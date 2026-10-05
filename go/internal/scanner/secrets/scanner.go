// Package secrets detects hardcoded secrets in source code via regex
// pattern matching, ported in-process from python/analyzers/secrets.py
// (TASK-115). Walks codePath recursively and emits one Finding per
// (pattern, file, line) match.
//
// This is now the SOLE secrets path — python/analyzers/secrets.py was
// removed once secrets/semgrep moved to native Go (TASK-115/116, see
// python/engine.py). The structure that follows still mirrors the original
// Python analyzer:
//   - 17 general patterns + ENV_SECRET (.env-only).
//   - Same SEC-<PATTERN_ID> finding IDs so dedup collapses any overlap
//     when --checks secrets is passed explicitly.
//   - Same skip-dirs / file-extension gate / .env name match.
//   - Same 1MB file-size cap and >500-char minified-JS-line skip.
//
// Evidence redaction DIVERGES from the removed Python analyzer on purpose:
// credential material is replaced at CAPTURE time with
// `[REDACTED len=N sha256:xxxxxxxx...]`, over the union of every pattern's
// value spans on the line — no prefix of a secret is ever emitted, and a
// neighbouring credential on the same line cannot ride along inside the
// evidence window. The old behaviour (first 20 raw chars + "...") leaked half
// of a 40-char token into every report, Jira ticket and PR comment. There is
// no live Python counterpart to stay in parity with: python/analyzers/
// secrets.py was deleted in TASK-115/116 and python/engine.py only prints a
// redirect notice when `secrets` is requested. See redact.go.
//
// Beyond parity, matches are filtered through isReferenceOrPlaceholder so a
// Secrets-Manager ARN / lookup key (a reference, not a credential) or a
// well-known placeholder (YOUR_TOKEN_HERE, example keys) is not reported —
// the two false-positive classes that used to need per-file:line .fendix-ignore
// suppressions.
//
// Regex notes: Go's RE2 doesn't support lookbehinds/lookaheads, so
// patterns that anchor token prefixes (ghp_, sk_live_, AKIA, etc.) in
// Python via (?<![A-Za-z0-9]) have the lookarounds stripped here and
// boundary characters validated manually post-match. See boundaryOK.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ErrCodePathMissing signals the codePath argument is empty or points
// nowhere. Callers errors.Is-check it and silently skip — matches the
// Python `if not root.exists(): return` early-out.
var ErrCodePathMissing = errors.New("secrets: code path does not exist")

const (
	// maxFileBytes mirrors python secrets.py _MAX_FILE_BYTES (1 MB).
	maxFileBytes = 1 << 20
	// evidenceMaxLen mirrors python _EVIDENCE_MAX_LEN.
	evidenceMaxLen = 120
	// minifiedLineLen mirrors python _is_minified (>500 chars in .js/.ts).
	minifiedLineLen = 500
	// fixText mirrors python finding `fix` field.
	fixText = "Remove the hardcoded credential. Store secrets in environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager). Rotate the exposed credential immediately."
)

// skipDirs mirrors python _SKIP_DIRS. Pruned in-place during the walk
// so we never descend into them.
var skipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, "vendor": {}, "__pycache__": {},
	".venv": {}, "venv": {}, "dist": {}, "build": {}, ".tox": {},
}

// scanExtensions mirrors python _SCAN_EXTENSIONS. Lower-case match on
// filepath.Ext.
var scanExtensions = map[string]struct{}{
	".py": {}, ".js": {}, ".ts": {}, ".jsx": {}, ".tsx": {}, ".go": {},
	".java": {}, ".rb": {}, ".php": {}, ".env": {}, ".cfg": {}, ".ini": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".json": {}, ".xml": {},
	".tf": {}, ".hcl": {}, ".sh": {}, ".bash": {}, ".zsh": {},
	".conf": {}, ".config": {},
}

// valueGroup selectors — which part of a match is credential material, for
// redaction (redact.go) and placeholder classification (placeholder.go).
const (
	// valueGroupAuto is the zero value, so an entry that wants it needs no
	// field at all: credential material is the LAST capturing group when the
	// pattern has one, else the whole match. Verified for every grouped
	// pattern in the registry — AWS_ACCESS_KEY(1) is the key,
	// AWS_SECRET_KEY(1) the 40-char value, GENERIC_API_KEY(1) the value,
	// HARDCODED_PASSWORD(1) the value, HARDCODED_SECRET_CONFIG(2) the value
	// (group 1 is the key NAME), ENV_SECRET(2) the value (group 1 the KEY).
	valueGroupAuto = 0
	// valueGroupNone: the match is a constant SIGNATURE, not credential
	// material. Keep it verbatim — redacting it destroys all triage signal
	// and leaks nothing.
	valueGroupNone = -1
	// valueGroupRestOfLine: the match is a HEADER and everything after it on
	// the same line is key material.
	valueGroupRestOfLine = -2
)

// pattern represents one detection rule. Regex is the body of the
// Python pattern with any (?<!...) / (?!...) stripped; leftBoundary
// and rightBoundary (when non-nil) match a single character that, if
// present immediately before or after the match, REJECTS the match.
//
// Severity values are pinned to the Python equivalents.
type pattern struct {
	id            string
	title         string
	regex         *regexp.Regexp
	severity      models.Severity
	cwe           string
	leftBoundary  *regexp.Regexp
	rightBoundary *regexp.Regexp
	// valueGroup selects which part of a match is credential material. Zero
	// (valueGroupAuto) for all but the three entries that say otherwise.
	valueGroup int
}

// CatalogRule is the public, non-sensitive contract metadata for one bundled
// secrets rule. It intentionally excludes the regular expression: publishing
// detection internals would make the documentation contract capable of
// changing scanner behaviour and could help evade a rule.
type CatalogRule struct {
	ID          string
	Title       string
	Severity    models.Severity
	Confidence  models.Confidence
	Category    string
	CWE         string
	Remediation string
}

// CatalogRules returns the executable secrets registry in scan order. The
// documentation contract generator consumes this projection so a rule cannot
// be added, removed, or reclassified without making the published catalog
// stale.
func CatalogRules() []CatalogRule {
	registry := make([]pattern, 0, len(patterns)+len(envPatterns))
	registry = append(registry, patterns...)
	registry = append(registry, envPatterns...)
	out := make([]CatalogRule, 0, len(registry))
	for _, p := range registry {
		out = append(out, CatalogRule{
			ID: p.id, Title: p.title, Severity: p.severity,
			Confidence: models.ConfidenceHigh, Category: "secrets", CWE: p.cwe,
			Remediation: fixText,
		})
	}
	return out
}

// boundaryAlnum matches a single [A-Za-z0-9] byte. Used as the default
// reject-on-touch set for most provider-token patterns.
var boundaryAlnum = regexp.MustCompile(`^[A-Za-z0-9]$`)

// boundaryUpperDigit matches [A-Z0-9] — used by AWS_ACCESS_KEY which
// in Python anchored on the uppercase alphanumeric set specifically.
var boundaryUpperDigit = regexp.MustCompile(`^[A-Z0-9]$`)

// boundaryAlnumDash matches [A-Za-z0-9-] — used by SLACK_TOKEN's right
// boundary (Python: (?![A-Za-z0-9-])) so a trailing hyphen also blocks.
var boundaryAlnumDash = regexp.MustCompile(`^[A-Za-z0-9-]$`)

// boundaryAlnumUnderDash matches [A-Za-z0-9_-] — GOOGLE_API_KEY right
// boundary and ANTHROPIC_API_KEY both sides.
var boundaryAlnumUnderDash = regexp.MustCompile(`^[A-Za-z0-9_-]$`)

// patterns is the registry in Python's order. Order matters for tests
// that index findings, but not for correctness — every match is
// reported with its own SEC-* id.
var patterns = []pattern{
	{
		id:            "AWS_ACCESS_KEY",
		title:         "AWS Access Key ID hardcoded",
		regex:         regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryUpperDigit,
		rightBoundary: boundaryUpperDigit,
	},
	{
		// Recognises both the canonical `aws_secret_access_key = "..."`
		// and the shorter `aws_secret = "..."` / `aws_secret_key = "..."`
		// variants. The 40-char value shape is what AWS issues — we
		// require it to limit FP risk on arbitrary base64 strings.
		// Track 4 heavy-eval surfaced the short-prefix variant as a
		// real-world miss on customer codebases.
		id:       "AWS_SECRET_KEY",
		title:    "AWS Secret Access Key hardcoded",
		regex:    regexp.MustCompile(`(?i)aws[_\-\s]*secret(?:[_\-\s]*(?:access[_\-\s]*)?key)?["\s]*[=:]["\s]*([A-Za-z0-9/+=]{40})`),
		severity: models.SeverityCritical,
		cwe:      "CWE-798",
	},
	{
		id:       "PRIVATE_KEY",
		title:    "Private key material hardcoded",
		regex:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		severity: models.SeverityCritical,
		cwe:      "CWE-321",
		// The pattern matches the ~27-char ARMOUR HEADER only, so the key
		// body is not part of the match — and in a JSON service-account file
		// the whole PEM lives on ONE line:
		//   "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN…"
		// Redacting just the match there would leave the actual key sitting
		// in the evidence window. Everything after the header on the same
		// line is therefore treated as key material. When that span is empty
		// (the header alone on its own line, the ordinary PEM-file shape) no
		// marker is emitted and evidence is unchanged.
		valueGroup: valueGroupRestOfLine,
	},
	{
		id:       "GENERIC_API_KEY",
		title:    "Hardcoded API key or token",
		regex:    regexp.MustCompile(`(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?key|auth[_\-]?token|client[_\-]?secret)\s*[=:]\s*["']([A-Za-z0-9\-_.+/]{20,})["']`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:       "HARDCODED_PASSWORD",
		title:    "Hardcoded password in source code",
		regex:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']`),
		severity: models.SeverityHigh,
		cwe:      "CWE-259",
	},
	{
		// Catches compound-suffix assignments through subscript or
		// attribute targets that the bare HARDCODED_PASSWORD regex
		// misses. Real-world examples (vflask, default Flask configs):
		//   app.config['SECRET_KEY_HMAC'] = 'secret'
		//   app.config["JWT_SECRET_KEY"] = "rotate-me"
		//   app.secret_key = 'F12Zr47j...'
		//   APP_SECRET = "..."
		// The keyword family is intentionally narrower than ENV_SECRET's
		// shotgun list — we anchor on tokens that strongly imply a
		// credential (secret_key, jwt_secret, hmac_key, app_secret, etc.)
		// to keep false-positive rate on non-credential variables low.
		// Minimum value length 4 to catch short placeholder secrets like
		// 'secret' / 'admin' / 'test' that the API-key regex's 20-char
		// floor rejects.
		id:    "HARDCODED_SECRET_CONFIG",
		title: "Hardcoded secret value in config-style assignment",
		regex: regexp.MustCompile(
			`(?i)(?:^|[.\[ \t])["']?(secret_key|api_secret|app_secret|jwt_secret|hmac_key|encryption_key|signing_key|csrf_secret|session_secret|cookie_secret)(?:[_\-]\w+)*["']?\s*\]?\s*[=:]\s*["']([^"'\n]{4,})["']`,
		),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:       "JWT_TOKEN",
		title:    "Hardcoded JWT token",
		regex:    regexp.MustCompile(`\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		// A JWT split across lines by implicit string concatenation —
		//
		//   JWT_TOKEN = (
		//       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
		//       "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
		//       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		//   )
		//
		// is invisible to the three-segment pattern above, because this
		// scanner is line-based and no single line holds all three segments.
		// That was a real miss: the accuracy corpus has exactly this shape and
		// scored it as detected only because a DUPLICATE emission from another
		// pattern happened to fall inside the scorer's ±6-line tolerance
		// window. Collapsing those duplicates removed the accident and exposed
		// the false negative.
		//
		// `eyJhbGciOi` is the base64 of `{"alg":"` — the opening of every JOSE
		// header. Anchoring on it (rather than on a generic `eyJ` prefix)
		// keeps this specific: it matches a JWT header segment and essentially
		// nothing else that appears in source.
		id:       "JWT_TOKEN_HEADER",
		title:    "Hardcoded JWT token",
		regex:    regexp.MustCompile(`\beyJhbGciOi[A-Za-z0-9\-_]{4,}`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
	{
		id:    "DB_CONNECTION_STRING",
		title: "Database connection string with credentials",
		// The capture group is around the PASSWORD segment only, so
		// redaction keeps the scheme, user and host readable for triage and
		// blanks just the credential. Adding a group cannot change RE2 match
		// extents, so detection behaviour is byte-identical to the ungrouped
		// form this replaced.
		regex:    regexp.MustCompile(`(?i)(?:mongodb|postgresql|postgres|mysql|mssql|redis|sqlite)://[^:@\s]+:([^@\s]+)@[^\s"']+`),
		severity: models.SeverityHigh,
		cwe:      "CWE-214",
	},
	{
		id:    "GITHUB_TOKEN",
		title: "GitHub token hardcoded",
		// Personal access (ghp_), OAuth (gho_), user-to-server (ghu_),
		// server-to-server (ghs_), refresh (ghr_).
		regex:         regexp.MustCompile(`gh[opusr]_[A-Za-z0-9]{36}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:            "STRIPE_LIVE_KEY",
		title:         "Stripe live secret key hardcoded",
		regex:         regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:    "SLACK_TOKEN",
		title: "Slack token hardcoded",
		// xoxa-/xoxb-/xoxp-/xoxr-/xoxs-.
		regex:         regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnumDash,
	},
	{
		id:            "GOOGLE_API_KEY",
		title:         "Google API key hardcoded",
		regex:         regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnumUnderDash,
	},
	{
		id:            "ANTHROPIC_API_KEY",
		title:         "Anthropic API key hardcoded",
		regex:         regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnumUnderDash,
		rightBoundary: boundaryAlnumUnderDash,
	},
	{
		id:    "OPENAI_API_KEY",
		title: "OpenAI API key hardcoded",
		// Legacy sk-<48 alnum>; project sk-proj-<...>; service-account sk-svcacct-<...>.
		// The body forbids `-` so the regex naturally cannot match
		// across the `sk-ant-` Anthropic prefix.
		regex:         regexp.MustCompile(`sk-(?:proj-|svcacct-)?[A-Za-z0-9]{32,}`),
		severity:      models.SeverityCritical,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:            "NPM_TOKEN",
		title:         "npm registry token hardcoded",
		regex:         regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		severity:      models.SeverityHigh,
		cwe:           "CWE-798",
		leftBoundary:  boundaryAlnum,
		rightBoundary: boundaryAlnum,
	},
	{
		id:    "GCP_SERVICE_ACCOUNT",
		title: "GCP service-account JSON key hardcoded",
		// Canonical signature line in Google's downloaded SA JSON files.
		regex:    regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		severity: models.SeverityCritical,
		cwe:      "CWE-798",
		// The match is the literal `"type": "service_account"` — a file-type
		// signature, not a credential. Redacting it would destroy the only
		// triage signal the finding carries and hide nothing.
		valueGroup: valueGroupNone,
	},
}

// envPatterns mirrors python _ENV_PATTERNS. Applied only to files where
// isEnvFile returns true — the unquoted KEY=value shape would produce
// false positives in regular source.
var envPatterns = []pattern{
	{
		id:    "ENV_SECRET",
		title: "Hardcoded credential in .env file",
		// KEY ends with a credential-y suffix; value is unquoted, ≥4
		// chars, not starting with whitespace/quote/#. The Python
		// regex is multiline-anchored via ^...$; in Go the (?m) flag
		// has the same effect, but we apply per-line so plain
		// anchors are fine.
		regex:    regexp.MustCompile(`^([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)S?(?:_[A-Z0-9_]+)?)\s*=\s*([^\s"'#][^\n#]{3,})\s*$`),
		severity: models.SeverityHigh,
		cwe:      "CWE-798",
	},
}

// Scan walks codePath, scans every eligible text file line-by-line for
// the secret patterns, and returns the resulting Findings. Behaviour
// matches python/analyzers/secrets.py except for cross-file ordering
// (Go walks in lexical order; the orchestrator's stable sort at step 6
// normalises this before ID assignment so the difference is invisible
// to downstream consumers).
//
// codePath must point at an existing directory; otherwise returns
// ErrCodePathMissing so the caller can silently skip. Walk errors on
// individual files are non-fatal — the file is skipped and the walk
// continues, matching the os.walk + try/except OSError pattern in Python.
//
// The context is checked between files; cancellation aborts the walk
// with ctx.Err().
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(ctx, codePath, nil)
}

// ScanWithAllowlist is Scan scoped to a diff-aware file allowlist. A nil
// allowlist scans every eligible file (full-scan parity with Scan). When
// set, only files whose absolute path is in the allowlist are read — the
// secrets half of `fendix scan --diff`. The directory walk and skip-dir
// pruning are unchanged; non-allowlisted files are skipped before scanFile
// opens them.
func ScanWithAllowlist(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, error) {
	if codePath == "" {
		return nil, ErrCodePathMissing
	}
	info, err := os.Stat(codePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCodePathMissing
		}
		return nil, fmt.Errorf("secrets: stat %q: %w", codePath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets: %q is not a directory", codePath)
	}

	absRoot, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("secrets: resolve %q: %w", codePath, err)
	}

	var findings []evidence.Evidence

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (the orchestrator also short-circuits) since this is exported.
	if allow.Empty() {
		return nil, nil
	}

	// Diff-aware fast path: when the allowlist names specific changed files,
	// scan exactly those — O(changed files) — instead of walking the whole
	// tree to filter it down to them. Parity with the walk below is preserved:
	// the same skipDirs prune (a committed vendor/ file stays skipped), the
	// file set stays a strict subset of the walk's (TraversesSymlink rejects
	// any file reached through a symlinked parent — which the walk never
	// descends and which could escape the repo root), and directories are
	// excluded via Lstat. (Empty allowlists already returned above.)
	if allow != nil {
		for _, path := range allow.AbsPaths() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if underSkipDir(absRoot, path) || gitdiff.TraversesSymlink(absRoot, path) {
				continue
			}
			info, err := os.Lstat(path)
			if err != nil || info.IsDir() {
				continue
			}
			fileFindings, err := scanFile(path, absRoot, fs.FileInfoToDirEntry(info))
			if err != nil {
				continue
			}
			findings = append(findings, fileFindings...)
		}
		return findings, nil
	}

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErrIn error) error {
		if walkErrIn != nil {
			// Permissions errors / vanished files — skip but keep walking.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if path == absRoot {
				return nil
			}
			if _, skip := skipDirs[d.Name()]; skip {
				return fs.SkipDir
			}
			return nil
		}

		// Diff-aware scoping: skip files outside the allowlist before any
		// read. A nil allowlist allows everything (full-scan default).
		if !allow.Allows(path) {
			return nil
		}

		fileFindings, err := scanFile(path, absRoot, d)
		if err != nil {
			// Per-file errors are non-fatal (matches Python's
			// try/except OSError: return).
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if walkErr != nil {
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			return findings, walkErr
		}
		return findings, fmt.Errorf("secrets: walk %q: %w", absRoot, walkErr)
	}
	return findings, nil
}

// scanFile reads one file, applies the pattern registry, and returns
// any findings it produces. The file is silently skipped if it isn't
// readable, exceeds maxFileBytes, or has an extension that's not in
// scanExtensions (unless it's a .env-style file).
// underSkipDir reports whether any directory component of abs (relative to
// root) is a pruned directory. The diff-aware fast path uses it to preserve
// parity with the walk, which prunes skipDirs subtrees (e.g. a committed
// vendor/ file the walk never reaches).
func underSkipDir(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, part := range parts[:len(parts)-1] { // dir components only, not the file
		if _, skip := skipDirs[part]; skip {
			return true
		}
	}
	return false
}

func scanFile(path, root string, d fs.DirEntry) ([]evidence.Evidence, error) {
	name := d.Name()
	envFile := isEnvFile(name)
	if !envFile {
		ext := strings.ToLower(filepath.Ext(name))
		if _, ok := scanExtensions[ext]; !ok {
			return nil, nil
		}
	}

	info, err := d.Info()
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileBytes {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)

	active := patterns
	if envFile {
		active = make([]pattern, 0, len(patterns)+len(envPatterns))
		active = append(active, patterns...)
		active = append(active, envPatterns...)
	}

	var out []evidence.Evidence
	isJSOrTS := strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts")
	text := string(data)
	lineno := 0
	// matches holds one FindAllStringSubmatchIndex row set per active
	// pattern for the CURRENT line. Reused across lines, and shared by the
	// redaction pre-pass and the emit loop so each regex runs exactly once
	// per line rather than once per consumer.
	matches := make([][][]int, len(active))
	for _, line := range splitLines(text) {
		lineno++
		if isJSOrTS && len(line) > minifiedLineLen {
			continue
		}
		matched := false
		for i := range active {
			matches[i] = active[i].regex.FindAllStringSubmatchIndex(line, -1)
			matched = matched || matches[i] != nil
		}
		if !matched {
			continue
		}

		// One redaction pass per line, over the union of EVERY pattern's
		// credential spans — not just the emitting pattern's own. Evidence is
		// a window over the SOURCE LINE, so a line carrying two credentials
		// would otherwise ship each one in the clear inside the other's
		// window. See redact.go for the full argument.
		//
		// INVARIANT from here down: `line` is used ONLY for offsets, pattern
		// matching and placeholder classification. The only string that may
		// reach an evidence.Evidence is `redacted`.
		spans := lineSecretSpans(line, active, matches)
		redacted, newSpans := redactSpans(line, spans)

		for i := range active {
			pat := &active[i]
			for _, sub := range matches[i] {
				if !boundaryOK(line, sub[0], sub[1], pat.leftBoundary, pat.rightBoundary) {
					continue
				}
				match := line[sub[0]:sub[1]]
				// B1/B2: drop matches that are references-not-credentials
				// (an ARN / Secrets-Manager lookup key) or well-known
				// placeholders (YOUR_TOKEN_HERE, example keys, changeme…).
				// These are the two false-positive classes that previously
				// had to be hand-suppressed per file:line in .fendix-ignore.
				// Unchanged: it still receives the FULL match.
				if isReferenceOrPlaceholder(line, match) {
					continue
				}
				vStart, vEnd, hasValue := secretValueSpan(pat, line, sub)
				value := ""
				if hasValue {
					value = line[vStart:vEnd]
				}
				aStart, aEnd := evidenceAnchor(sub[0], vStart, hasValue, spans, newSpans)
				safeEvidence := truncateEvidenceAround(redacted, aStart, aEnd)
				lineRef := fmt.Sprintf("%s:%d", rel, lineno)
				lineCopy := lineRef
				out = append(out, evidence.Evidence{
					ID:         "SEC-" + pat.id,
					RuleID:     "secrets/" + pat.id, // v0.22 native provenance
					Title:      pat.title,
					Severity:   pat.severity,
					Source:     models.SourceWhitebox,
					Category:   "secrets",
					Endpoint:   lineRef,
					Evidence:   safeEvidence,
					Fix:        fixText,
					References: []string{pat.cwe},
					Confidence: models.ConfidenceHigh,
					Line:       &lineCopy,
					// The SAFE identity the v2 fingerprint keys on: which
					// identifier this credential is bound to, and where it
					// lives. Never the credential, never a digest of it — see
					// models.SecretRef. lastAssignmentKey is reused rather
					// than re-derived so identity and the placeholder
					// classifier always agree on what the key is.
					Secret: &models.SecretRef{
						Identifier: secretIdentifier(line, vStart, hasValue),
						File:       rel,
					},
					// Deterministic fixture-credential classification. An
					// EVIDENCE ANNOTATION, not a filter — the finding is
					// emitted either way, at the same ID, severity and
					// endpoint, with full (redacted) evidence. The confidence
					// scorer turns it into one named negative delta. See
					// placeholder.go for why this is not folded into
					// isReferenceOrPlaceholder.
					Placeholder: classifyPlaceholder(line, vStart, value).isPlaceholder(),
					// Whether the match was anchored on the provider's own
					// token signature rather than on a surrounding assignment.
					// Bounds how far the fixture classification above is
					// allowed to de-escalate — see providerAnchoredRules.
					ProviderAnchored: isProviderAnchored(pat.id),
				})
			}
		}
	}
	return out, nil
}

// splitLines splits text on \n and \r\n line endings without including
// the terminator in each line. Mirrors python str.splitlines() closely
// enough for this scanner's purposes (we don't care about exotic
// terminators like U+2028 — secrets in those would also be exotic).
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	// Normalise \r\n → \n, then split on \n. Drop trailing empty if
	// the file ends in a newline so line numbers match Python's
	// splitlines (which also drops trailing empty).
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// boundaryOK returns false when the character immediately before
// (start-1) or after (end) the match satisfies the corresponding
// boundary regex — i.e. the lookaround would have rejected this match
// in the Python original. nil predicates short-circuit to true.
func boundaryOK(line string, start, end int, leftRE, rightRE *regexp.Regexp) bool {
	if leftRE != nil && start > 0 {
		if leftRE.MatchString(line[start-1 : start]) {
			return false
		}
	}
	if rightRE != nil && end < len(line) {
		if rightRE.MatchString(line[end : end+1]) {
			return false
		}
	}
	return true
}

// referencePrefixes are case-insensitive substrings whose presence in the
// matched value means it is a REFERENCE to a secret (a lookup key / ARN /
// resource id), not the secret value itself. The canonical case is an AWS
// Secrets Manager identifier — e.g.
//
//	secret_name = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"
//	secret_arn  = "arn:aws:secretsmanager:eu-central-1:123:secret:prod/db-AbCdEf"
//
// The real credential is fetched at runtime from the secrets manager; the
// literal in source is the address, not the password. These were previously
// hand-suppressed per file:line in .fendix-ignore (B1).
var referencePrefixes = []string{
	"arn:aws:secretsmanager:",
	"arn:aws:ssm:",
	"arn:aws:kms:",
	"rds!db-",      // RDS-managed master-secret name
	"rds!cluster-", // Aurora-managed master-secret name
	"projects/",    // GCP Secret Manager resource name: projects/*/secrets/*
}

// placeholderRE matches a VALUE that is UNAMBIGUOUSLY a templating marker, not
// a credential: YOUR_*_HERE, a single <...> or ${...} token, the bare words
// changeme / placeholder / redacted (case-insensitive), or a run of x's. It is
// anchored, so it's applied to the extracted assignment value, not the whole
// match line.
//
// Deliberately NARROW. It does NOT match the substring "example" / "sample" /
// "dummy": the engine intentionally still flags AWS's documented example keys
// (AKIAIOSFODNN7EXAMPLE, wJalrX…EXAMPLEKEY) and values like
// "ExampleFakeKeyForTesting" via the secrets module — "EXAMPLE" appears inside
// real leaked keys too, and over-suppressing on it produces false negatives.
// The two AWS example keys are handled separately by the textscan NegPattern.
//
// Those values ARE now de-escalated, just not here: classifyPlaceholder
// (placeholder.go) recognises them and sets Evidence.Placeholder, which costs
// the finding confidence while leaving it reported with full evidence. That is
// the treatment this comment says suppression could not give them — so keep
// this regex narrow and add nothing to it.
var placeholderRE = regexp.MustCompile(`(?i)^(?:your[_-][a-z0-9_-]*here|<[^>]+>|\$\{[^}]+\}|changeme|placeholder|redacted|x{6,})$`)

// quotedValueRE extracts the first single- or double-quoted string from a
// matched assignment (e.g. `password = "changeme"` → `changeme`). Many secret
// patterns match the whole `KEY = "value"` shape, so to classify the VALUE we
// have to pull it back out of the match.
var quotedValueRE = regexp.MustCompile(`["']([^"']*)["']`)

// isReferenceOrPlaceholder reports whether a regex-matched secret should NOT be
// reported because it is a reference-not-credential (an ARN / Secrets-Manager
// lookup key — referencePrefixes) or an unambiguous placeholder
// (placeholderRE). `match` is the full regex match (often `KEY = "value"`);
// the quoted value is extracted for the placeholder test, with a fallback to
// the whole match when there is no quoted segment.
func isReferenceOrPlaceholder(line, match string) bool {
	lowerMatch := strings.ToLower(match)
	lowerLine := strings.ToLower(line)
	for _, p := range referencePrefixes {
		if strings.Contains(lowerMatch, p) || strings.Contains(lowerLine, p) {
			return true
		}
	}
	value := match
	if m := quotedValueRE.FindStringSubmatch(match); m != nil {
		value = m[1]
	}
	return placeholderRE.MatchString(strings.TrimSpace(value))
}

// isEnvFile mirrors python _is_env_file: .env exactly, anything
// beginning with .env., or any file whose extension is .env.
func isEnvFile(name string) bool {
	if name == ".env" {
		return true
	}
	if strings.HasPrefix(name, ".env.") {
		return true
	}
	if filepath.Ext(name) == ".env" {
		return true
	}
	return false
}

// secretIdentifier returns the non-sensitive identifier a credential is bound
// to — the assignment key or config name to its left.
//
// Empty when the match has no binding identifier (a bare `-----BEGIN … KEY-----`
// block). That is reported honestly as "no identifier" rather than
// substituted with the line number, which would put location back into
// identity, or with a digest of the credential, which would persist a
// credential oracle. See models.SecretRef for the consequence.
func secretIdentifier(line string, valueStart int, hasValue bool) string {
	if !hasValue || valueStart <= 0 || valueStart > len(line) {
		return ""
	}
	prefix := line[:valueStart]
	// The binding is the assignment to the left of the STRING LITERAL the
	// value sits in — not of the nearest key, and not of the first quote on
	// the line.
	//
	// Nearest key: a connection string carries its own key:value shapes
	// inside the quoted value: `DATABASE_URL = "postgres://appuser:pw@host/db"`
	// makes `appuser` the nearest key, so the nearest-key search named the
	// finding after the database username. That is stable exactly until
	// someone rotates the credential, at which point a rotation — the correct
	// response to the finding — files it as a different vulnerability.
	//
	// First quote: cutting the line at its first quote instead named
	// `create(email="t@example.com", password="pw")` after `email`, an
	// unrelated argument. The identifier is part of the secret's identity, so
	// that made identity depend on whatever happened to precede the
	// credential on its line, and merged distinct credentials that shared a
	// preceding argument.
	//
	// So: find the literal that encloses the value (the value's own quotes, or
	// the connection string around it) and take the assignment immediately to
	// its left. lastAssignmentKey still runs on that prefix (a nested
	// `config["stripe_key"] =` gives `stripe_key`, not `config`), never on the
	// value's text.
	if open := enclosingQuote(prefix); open >= 0 {
		if outer := lastAssignmentKey(prefix[:open]); outer != "" {
			return outer
		}
	}
	return lastAssignmentKey(prefix)
}

// enclosingQuote returns the index of the quote that opens the string literal
// still open at the end of prefix, or -1 when prefix ends outside any literal.
// Single and double quotes are tracked separately (each closes only its own
// kind) and a backslash escapes the next byte inside a literal.
func enclosingQuote(prefix string) int {
	open := -1
	var quote byte
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case open >= 0 && c == '\\':
			i++
		case open >= 0 && c == quote:
			open = -1
		case open < 0 && (c == '"' || c == '\''):
			open, quote = i, c
		}
	}
	return open
}
