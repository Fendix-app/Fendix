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
//   - Same .env name match for ENV_SECRET.
//
// What it reads and how differs from the removed Python analyzer on purpose
// (R-010, D6'): every file that is text, not only those with a listed
// extension (textfiles.go); every line, however long, in overlapping windows,
// not skipping a .js/.ts line over 500 characters (stream.go); files up to
// streamMaxFileBytes in bounded memory, not 1 MB; and no directory pruned by
// its name alone (PrunedDir). What it still cannot read is recorded as lost
// evaluation (scope.Coverage), never skipped silently.
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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// ErrCodePathMissing signals the codePath argument is empty or points
// nowhere. Callers errors.Is-check it and silently skip — matches the
// Python `if not root.exists(): return` early-out.
var ErrCodePathMissing = errors.New("secrets: code path does not exist")

const (
	// defaultMaxFileBytes is the size above which a file is not read: 128 MiB.
	// A file is streamed in bounded memory, so the cap bounds time, not memory;
	// it is far above any source file and a generated data file in a repository
	// (GitHub refuses a push of one over 100 MiB). A file over it is lost
	// evaluation, named in the scan's detail.
	defaultMaxFileBytes = 128 << 20
	// evidenceMaxLen mirrors python _EVIDENCE_MAX_LEN.
	evidenceMaxLen = 120
	// fixText mirrors python finding `fix` field.
	fixText = "Remove the hardcoded credential. Store secrets in environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager). Rotate the exposed credential immediately."
)

// maxFileBytes is the cap on the bytes read from one file. It is a variable so
// a test can lower it; production code never assigns it.
var maxFileBytes int64 = defaultMaxFileBytes

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
	// valueSpans, when set, replaces valueGroup: it returns every credential
	// span the match covers, the match's own value first. A pattern needs it
	// when the regex capture cannot reach the end of the credential (a
	// connection-string password holding ; & ' " @ or a space, or a second
	// password property later in the same URL; see connectionStringSpans).
	// It never changes what matches, only what is redacted.
	valueSpans func(line string, sub []int) [][2]int
	// lineAnchored marks a pattern whose regex is anchored to the start of the
	// line (^). On a line longer than a window only the first window starts
	// at the line start, so the later windows skip it.
	lineAnchored bool
	// required, derived at start-up (prefilter.go), is a set of lower-cased
	// strings of which every match contains at least one; the pattern runs on a
	// line only when the line contains one.
	required []string
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
		//
		// Two shapes, one rule id (so no existing identity moves):
		//   1. URL userinfo: scheme://user:PASSWORD@host
		//   2. JDBC properties, which carry the password as a pair rather than
		//      as userinfo: jdbc:postgresql://h/app?user=u&password=PASSWORD,
		//      jdbc:sqlserver://h:1433;databaseName=a;password=PASSWORD
		// The value group of each is the password; the credential is the LAST
		// participating group, so redaction treats both the same. A value
		// STARTING with `$` is an interpolation (${DB_PASSWORD}) and does not
		// match; a `$` later in the value is part of the password, and the
		// whole value is the capture (a value class that excluded `$` anywhere
		// stopped at it and published the rest of the password).
		//
		// The capture marks where the password STARTS; it stops at the first
		// ; & ' " whitespace (or, for userinfo, @), which a password can
		// contain. Redaction therefore does not use the capture's end:
		// connectionStringSpans extends it to the end of the password
		// property (R-013), so no part of the password reaches evidence.
		regex:      regexp.MustCompile(`(?i)(?:mongodb|postgresql|postgres|mysql|mssql|redis|sqlite)://[^:@\s]+:([^@\s]+)@[^\s"']+|jdbc:[a-z0-9]+:(?://)?[^\s"'?;]+[?;][^\s"']*?\bpassword=([^&;\s"'$][^&;\s"']*)`),
		severity:   models.SeverityHigh,
		cwe:        "CWE-214",
		valueSpans: connectionStringSpans,
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
		regex:        regexp.MustCompile(`^([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)S?(?:_[A-Z0-9_]+)?)\s*=\s*([^\s"'#][^\n#]{3,})\s*$`),
		severity:     models.SeverityHigh,
		cwe:          "CWE-798",
		lineAnchored: true,
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
	findings, _, err := ScanCoverage(ctx, codePath, allow)
	return findings, err
}

// ScanCoverage is ScanWithAllowlist that also returns what the scan left
// unread (decision D6). A file the scanner reads (ReadsFile) that was over
// the size cap, could not be read, or was replaced between the walk and the
// read, and a directory it could not list, are lost evaluation: the caller
// records the scan a coverage gap naming them and keeps the findings. The
// only directory left unread is <root>/.git (PrunedDir), and it is not source.
func ScanCoverage(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, scope.Coverage, error) {
	var findings []evidence.Evidence
	var cov scope.Coverage
	err := scanTree(ctx, codePath, allow, func(out []emitted) {
		for _, e := range out {
			findings = append(findings, e.ev)
		}
	}, &cov)
	return findings, cov, err
}

// noteUnread files a file the walk did not (fully) read: too large or
// unreadable, both lost evaluation. A file proven binary is not text and is not recorded.
func noteUnread(cov *scope.Coverage, absRoot, path string, err error) {
	if cov == nil || err == nil || errors.Is(err, errBinary) {
		return
	}
	rel, rerr := filepath.Rel(absRoot, path)
	if rerr != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	switch {
	case errors.Is(err, errTooLarge):
		// Over the cap is lost evaluation, whatever the file looks like: a
		// banner or a layout is not evidence that nothing in it matters
		// (contract C6).
		cov.TooLarge(lostName(rel))
	case errors.Is(err, errTooManyFindings):
		// The file is not evaluated past its findings cap: lost, not skipped.
		cov.TooLarge(lostName(rel))
	default:
		cov.Unreadable(lostName(rel))
	}
}

// noteSymlink files a symbolic link the scan refused to follow (sre3-06). A
// link whose target is inside the scan root loses nothing: the walk reaches the
// target directly. A dangling link has nothing to read. A link to a file or
// directory outside the root is content that exists and was not read, so it is
// listed as declared out of scope (a symbolic link) instead of vanishing from a
// scan that says ok.
func noteSymlink(cov *scope.Coverage, absRoot, path string) {
	NoteRefusedSymlink(cov, absRoot, path, ReadsFile)
}

// NoteRefusedSymlink is noteSymlink for another scanner: reads says whether a
// file of this base name is one that scanner reads, so a link to a file it
// would never read is not a loss. A link to a directory always is.
func NoteRefusedSymlink(cov *scope.Coverage, absRoot, path string, reads func(base string) bool) {
	if cov == nil {
		return
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return
	}
	rel, err := filepath.Rel(absRoot, path)
	if err != nil {
		return
	}
	if rootReal, err := filepath.EvalSymlinks(absRoot); err == nil {
		if tr, err := filepath.Rel(rootReal, target); err == nil && tr != ".." && !strings.HasPrefix(tr, ".."+string(filepath.Separator)) {
			return
		}
	}
	if info, err := os.Stat(target); err != nil || (!info.IsDir() && !reads(filepath.Base(path))) {
		return
	}
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		cov.Symlink(SafeName(filepath.ToSlash(rel)) + "/")
		return
	}
	cov.Symlink(SafeName(filepath.ToSlash(rel)))
}

// emitted is one finding plus the redaction markers that identify the
// credential it reports (see Sighting). Only ScanSightings keeps the markers.
type emitted struct {
	ev      evidence.Evidence
	markers []string
}

// scanTree is the body of ScanWithAllowlist: it walks codePath (or reads the
// allowlist's files) and hands every file's findings to collect. On a walk
// error collect has already received the findings read so far.
//
// cov, when not nil, receives what the walk left unread (ScanCoverage).
func scanTree(ctx context.Context, codePath string, allow *gitdiff.Allowlist, collect func([]emitted), cov *scope.Coverage) error {
	return walkTree(ctx, codePath, allow, func(ctx context.Context, root *os.Root, path, rootDir string, d fs.DirEntry) error {
		emits, err := scanFile(ctx, root, path, rootDir, d)
		// What was read is kept even when the rest of the file was not.
		collect(emits)
		return err
	}, cov)
}

// fileVisitor reads one regular file the walk reached, through root. The error
// it returns says why the file was not read in full (errTooLarge, errBinary, an
// open or read error); the walk records it in the coverage.
type fileVisitor func(ctx context.Context, root *os.Root, path, rootDir string, d fs.DirEntry) error

// walkTree walks codePath (or visits the allowlist's files) and hands every
// regular file the scan reads to visit. It is the one walk both the scan and
// the credential search use, so they agree on what is in scope: the same
// pruned directories, the same symlink refusals, the same containment.
func walkTree(ctx context.Context, codePath string, allow *gitdiff.Allowlist, visit fileVisitor, cov *scope.Coverage) error {
	return walkTreeWith(ctx, codePath, allow, visit, cov, walkOptions{})
}

// walkOptions are the two things a walk's caller may change: which directories
// are pruned and which unreadable files count as lost.
type walkOptions struct {
	// prune says whether the directory at abs (rel under the root) is left
	// unread, why, and whether that is not worth listing. nil means PrunedDir.
	prune func(abs, rel string) (scope.Reason, bool)
	// reads says whether a file of this base name is one the walk must read.
	// nil means ReadsFile.
	reads func(base string) bool
}

// walkTreeWith is walkTree with its options.
func walkTreeWith(ctx context.Context, codePath string, allow *gitdiff.Allowlist, visit fileVisitor, cov *scope.Coverage, opts walkOptions) error {
	if opts.prune == nil {
		opts.prune = PrunedDir
	}
	if opts.reads == nil {
		opts.reads = ReadsFile
	}
	if codePath == "" {
		return ErrCodePathMissing
	}
	info, err := os.Stat(codePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrCodePathMissing
		}
		return fmt.Errorf("secrets: stat %q: %w", codePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("secrets: %q is not a directory", codePath)
	}

	absRoot, err := filepath.Abs(codePath)
	if err != nil {
		return fmt.Errorf("secrets: resolve %q: %w", codePath, err)
	}

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (the orchestrator also short-circuits) since this is exported.
	if allow.Empty() {
		return nil
	}

	// Every read goes through an os.Root opened on the scan root, so no path
	// the walk or the allowlist produces can resolve outside it, even if the
	// tree changes while the scan runs (R-003).
	root, err := os.OpenRoot(absRoot)
	if err != nil {
		return fmt.Errorf("secrets: open %q: %w", absRoot, err)
	}
	defer root.Close()

	// Diff-aware fast path: when the allowlist names specific changed files,
	// scan exactly those — O(changed files) — instead of walking the whole
	// tree to filter it down to them. Parity with the walk below is preserved:
	// the same pruned directories (a committed node_modules file stays
	// skipped), the file set stays a strict subset of the walk's
	// (TraversesSymlink rejects any file reached through a symlinked parent —
	// which the walk never descends and which could escape the repo root), and
	// anything that is not a regular file — a directory, a symlinked leaf, a
	// device — is excluded via Lstat, as the walk excludes it. (Empty
	// allowlists already returned above.)
	if allow != nil {
		noted := map[string]bool{}
		for _, path := range allow.AbsPaths() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if NotePrunedAncestor(cov, noted, absRoot, path) != "" || gitdiff.TraversesSymlink(absRoot, path) {
				continue
			}
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				noteSymlink(cov, absRoot, path)
				continue
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if err := visit(ctx, root, path, absRoot, fs.FileInfoToDirEntry(info)); err != nil {
				if errors.Is(err, errStopWalk) {
					return nil
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				noteUnread(cov, absRoot, path, err)
			}
		}
		return nil
	}

	// walkRoot, not filepath.WalkDir: a root that is itself a symlink is the
	// scope the user chose, and WalkDir would report it as one non-directory
	// entry and walk nothing (redteam-secrets-01).
	walkErr := walkRoot(absRoot, func(path string, d fs.DirEntry, walkErrIn error) error {
		if walkErrIn != nil {
			// Permissions errors / vanished files: skip and keep walking, but
			// a directory not listed, or a file of a kind the scanner reads,
			// is in scope and was not searched (security-01).
			if rel, rerr := filepath.Rel(absRoot, path); rerr == nil && rel != "." && cov != nil {
				switch {
				case d != nil && d.IsDir():
					cov.Unreadable(lostName(filepath.ToSlash(rel)) + "/")
				case opts.reads(filepath.Base(path)):
					cov.Unreadable(lostName(filepath.ToSlash(rel)))
				}
			}
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
			rel, rerr := filepath.Rel(absRoot, path)
			if rerr != nil {
				return nil
			}
			if reason, quiet := opts.prune(path, rel); reason != "" {
				if cov != nil && !quiet {
					cov.Exclude(reason, SafeName(filepath.ToSlash(rel))+"/")
				}
				return fs.SkipDir
			}
			return nil
		}

		// Regular files only (R-003). A symlink is never followed: one that
		// points outside the root would publish another file's contents
		// (a worker's environment, a mounted key) in this tree's evidence,
		// and one to /dev/zero would be read until memory runs out. One that
		// points inside the root loses nothing, because the walk reaches its
		// target directly; one that points outside is named (noteSymlink).
		// Devices, FIFOs and sockets are never source.
		// (WalkDir already does not descend a symlinked directory.)
		if d.Type()&fs.ModeSymlink != 0 {
			if allow.Allows(path) {
				NoteRefusedSymlink(cov, absRoot, path, opts.reads)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		// Diff-aware scoping: skip files outside the allowlist before any
		// read. A nil allowlist allows everything (full-scan default).
		if !allow.Allows(path) {
			return nil
		}

		if err := visit(ctx, root, path, absRoot, d); err != nil {
			if errors.Is(err, errStopWalk) {
				return fs.SkipAll
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Per-file errors are non-fatal (matches Python's
			// try/except OSError: return), and recorded as lost evaluation.
			noteUnread(cov, absRoot, path, err)
		}
		return nil
	})

	if walkErr != nil {
		if errors.Is(walkErr, context.Canceled) || errors.Is(walkErr, context.DeadlineExceeded) {
			return walkErr
		}
		return fmt.Errorf("secrets: walk %q: %w", absRoot, walkErr)
	}
	return nil
}

// walkRoot is filepath.WalkDir(root, fn) except that root itself is followed
// when it is a symbolic link. WalkDir Lstats its root, so a linked root is one
// non-directory entry and nothing under it is visited; the scan then recorded
// secrets ok over zero files. The link is resolved once, the resolved
// directory is walked, and every path is reported under root as the caller
// gave it, so the allowlist, the os.Root reads and the endpoints are unchanged.
// Links inside the tree are still never followed.
func walkRoot(root string, fn fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&fs.ModeSymlink == 0 {
		return filepath.WalkDir(root, fn)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve the root link %q: %w", root, err)
	}
	return filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		rel, rerr := filepath.Rel(resolved, path)
		if rerr != nil {
			return rerr
		}
		return fn(filepath.Join(root, rel), d, err)
	})
}

// SkipReason says why a full Scan of root would not read the file at path, or
// returns "" when it would. It applies the checks Scan applies: a pruned
// directory between root and the file, a binary file type, and a file over the
// size cap. A caller that re-tests a finding with Scan uses it to tell "no
// longer flagged" from "never looked at". An unreadable file returns "", so
// the caller's own inspection reports it.
func SkipReason(root, path string) string { return skipReason(root, path, true) }

// skipReason is SkipReason, with the size check optional.
func skipReason(root, path string, checkSize bool) string {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	if dir := prunedAncestor(absRoot, absPath); dir != "" {
		return fmt.Sprintf("it is under the skipped directory %q", dir)
	}
	name := filepath.Base(absPath)
	if !ReadsFile(name) {
		return fmt.Sprintf("files of the binary type %q are not read", strings.ToLower(filepath.Ext(name)))
	}
	if info, err := os.Lstat(absPath); err == nil {
		if info.Mode()&fs.ModeSymlink != 0 {
			return "it is a symbolic link, which the scanner never follows"
		}
		if !info.Mode().IsRegular() {
			return "it is not a regular file"
		}
		if checkSize && info.Size() > maxFileBytes {
			return fmt.Sprintf("it is larger than %d bytes", maxFileBytes)
		}
	}
	if gitdiff.TraversesSymlink(absRoot, absPath) {
		return "it is reached through a symbolic link, which the scanner never follows"
	}
	return ""
}

// errStopWalk is returned by a visitor that has its answer and wants the walk to
// end without recording anything as unread.
var errStopWalk = errors.New("stop the walk")

// relUnder is path relative to rootDir, or an error when it is outside it.
func relUnder(rootDir, path string) (string, error) {
	rel, err := filepath.Rel(rootDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("secrets: %q is outside the scan root", path)
	}
	return rel, nil
}

// errNotRegular, errChanged, errTooLarge and errBinary are why a file is not
// (fully) read. They are per-file conditions: the walk goes on.
var (
	errNotRegular = errors.New("not a regular file")
	errChanged    = errors.New("the file changed between the walk and the read")
	errTooLarge   = errors.New("larger than the read cap")
	// errBinary: the first bytes of a file of an unknown kind hold a NUL, which
	// proves it is not text. It is not lost evaluation and is not recorded.
	errBinary = errors.New("not a text file")
	// errTooManyFindings: one file reported maxFindingsPerFile findings, so the
	// rest of it was not read. The findings so far are kept.
	errTooManyFindings = errors.New("too many findings in one file")
	// wse1ErrSourceEncoding: a Python file whose declared source encoding is not
	// read as written (a codec that is not ASCII-transparent, a name no codec
	// answers to, a cookie only python -x reads), so what the scan read is not the
	// program CPython runs. The findings read in clear are kept, and the file is
	// lost evaluation under the existing "unreadable" reason (R5-01, R6-E2).
	wse1ErrSourceEncoding = errors.New("a Python file the scan cannot read as the program CPython runs")
)

// maxFindingsPerFile bounds the memory one file can cost: a file of nothing but
// credential-shaped lines would otherwise hold a finding per line. A file that
// reaches it is recorded as lost evaluation, not skipped.
var maxFindingsPerFile = 20000

// openRegularFile opens rel through root, which refuses any path that
// resolves outside the scan root. It returns only a regular file, and only the
// file the walk saw (walked, from Lstat): a path swapped for a link, a device
// or another file after the walk is refused.
func openRegularFile(root *os.Root, rel string, walked fs.FileInfo) (*os.File, error) {
	if testHookBeforeOpen != nil {
		testHookBeforeOpen(rel)
	}
	f, err := root.OpenFile(rel, openReadFlags, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	if walked != nil && !os.SameFile(walked, info) {
		f.Close()
		return nil, errChanged
	}
	// The size is not checked here: the caller has, and the read itself is
	// bounded by maxFileBytes whatever the file does after it was sized.
	return f, nil
}

// Test hooks, nil outside tests (qa-engine-06). They let a test change the
// tree at the exact points between the walk and the read, so each containment
// layer can be shown to be the one that refuses the change.
var (
	// testHookScanFile is called with the path of every entry that reaches
	// scanFile: only regular files ever should.
	testHookScanFile func(path string)
	// testHookBeforeOpen runs after the walk's Lstat and before the open.
	testHookBeforeOpen func(rel string)
	// testHookReadSource wraps the opened file before it is read.
	testHookReadSource func(io.Reader) io.Reader
)

// scanFile reads one regular file through root, in bounded memory, and
// applies the pattern registry. It returns the findings and an error that says
// why the file was not read in full: errTooLarge (the findings read before the
// cap are returned with it), errBinary, or an open or read error. The walk
// records them (D6). A file the scanner does not read by name returns nothing.
func scanFile(ctx context.Context, root *os.Root, path, rootDir string, d fs.DirEntry) ([]emitted, error) {
	if testHookScanFile != nil {
		testHookScanFile(path)
	}
	name := d.Name()
	if !ReadsFile(name) {
		return nil, nil
	}

	info, err := d.Info()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if info.Size() > maxFileBytes {
		return nil, errTooLarge
	}

	rel, err := relUnder(rootDir, path)
	if err != nil {
		return nil, err
	}
	f, err := openRegularFile(root, rel, info)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanOpenFile(ctx, f, name, filepath.ToSlash(rel))
}

// scanOpenFile streams an open file through the pattern registry. The read is
// bounded by maxFileBytes whatever the file does after it was sized: a file
// that keeps growing is cut one byte past the cap and is errTooLarge, with the
// findings of the bytes read.
func scanOpenFile(ctx context.Context, f io.Reader, name, rel string) ([]emitted, error) {
	src := f
	if testHookReadSource != nil {
		src = testHookReadSource(src)
	}
	lim := &io.LimitedReader{R: src, N: maxFileBytes + 1}
	r, py, err := textReaderPy(lim, name)
	if err != nil {
		return nil, err
	}
	out, err := scanReader(ctx, name, rel, r)
	if err == nil && lim.N <= 0 {
		err = errTooLarge
	}
	if err == nil && py.Lost() {
		// Read as written, and reported as far as that reads; but not the program
		// CPython runs, so the file is lost evaluation (R5-01, R6-E2).
		err = fmt.Errorf("%w: %s", wse1ErrSourceEncoding, wse1PyReason(py))
	}
	return out, err
}

// lineScanner applies the pattern registry to the windows of one file.
type lineScanner struct {
	active  []pattern
	matches [][][]int
	rel     string
	out     []emitted
	// carry holds the credential spans the earlier windows of the current line
	// found, in offsets of the line, so a window that sees only the tail of a
	// credential still redacts it (carry.go).
	carry     []carriedSpan
	carryLine int
}

// scanReader applies the pattern registry to a stream. rel is the
// slash-separated path findings are reported at. Each finding carries the
// markers that identify its credential: the marker of its own value and, when
// that value was merged with an overlapping span on the line, the marker the
// evidence shows.
func scanReader(ctx context.Context, name, rel string, r io.Reader) ([]emitted, error) {
	active := patterns
	if isEnvFile(name) {
		active = make([]pattern, 0, len(patterns)+len(envPatterns))
		active = append(active, patterns...)
		active = append(active, envPatterns...)
	}
	// matches holds one FindAllStringSubmatchIndex row set per active
	// pattern for the CURRENT line. Reused across lines, and shared by the
	// redaction pre-pass and the emit loop so each regex runs exactly once
	// per line rather than once per consumer.
	ls := &lineScanner{active: active, matches: make([][][]int, len(active)), rel: rel}
	n := 0
	err := streamLines(r, func(seg segment) error {
		if n++; n&0xff == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		ls.scan(seg)
		if len(ls.out) >= maxFindingsPerFile {
			return errTooManyFindings
		}
		return nil
	})
	return ls.out, err
}

// scan applies the registry to one window of one line.
func (ls *lineScanner) scan(seg segment) {
	line, lineno, rel := seg.text, seg.lineno, ls.rel
	active, matches := ls.active, ls.matches
	matched := false
	lower := strings.ToLower(line)
	ascii := isASCII(line)
	for i := range active {
		matches[i] = nil
		if !seg.first && active[i].lineAnchored {
			continue
		}
		if !active[i].mayMatch(lower, ascii) {
			continue
		}
		matches[i] = active[i].regex.FindAllStringSubmatchIndex(line, -1)
		matched = matched || matches[i] != nil
	}
	carriedIn := ls.carriedSpans(seg, line)
	if !matched {
		// Nothing to emit here, but a credential carried in from an earlier
		// window may reach through this one into the next.
		ls.updateCarry(seg, line, carriedIn, nil, 0)
		return
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
	spans := lineSecretSpans(line, active, matches, carriedIn...)
	redacted, newSpans := redactSpans(line, spans)
	ls.updateCarry(seg, line, carriedIn, spans, restOfLineEnd(line, active, matches))

	for i := range active {
		pat := &active[i]
		for _, sub := range matches[i] {
			if sub[0] < seg.ownStart || sub[0] >= seg.ownEnd {
				// Owned by the previous window (context here) or by the next,
				// which sees the whole match.
				continue
			}
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
			var markers []string
			if hasValue {
				markers = append(markers, redactionMarker(value))
				if m := mergedMarker(vStart, spans, newSpans, redacted); m != "" && m != markers[0] {
					markers = append(markers, m)
				}
			}
			lineRef := fmt.Sprintf("%s:%d", rel, lineno)
			lineCopy := lineRef
			ls.out = append(ls.out, emitted{markers: markers, ev: evidence.Evidence{
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
			}})
		}
	}
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
