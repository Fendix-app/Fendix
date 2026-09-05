// Package semgrep shells out to a host-installed semgrep binary,
// running fendix's bundled rule pack and mapping every match to a
// fendix Finding (TASK-116). Replaces the embedded
// python/analyzers/semgrep_runner.py path so the engine no longer
// requires Python at runtime for Semgrep checks.
//
// Behavioural parity with python/analyzers/semgrep_runner.py:
//   - SEC-<RULE_ID> finding IDs (uppercased, '-' and '.' → '_').
//   - Severity: rule metadata.fendix_severity wins; else map Semgrep's
//     ERROR/WARNING/INFO → HIGH/MEDIUM/LOW.
//   - Confidence: rule metadata.confidence; default MEDIUM.
//   - Category: rule metadata.category; default "code".
//   - References: rule metadata.cwe (string or list).
//   - Evidence: matched source lines, truncated at 200 chars + "...".
//   - 120s default timeout per invocation, mirroring Python.
//
// Distribution: rules are embedded into the binary via //go:embed
// and extracted to a per-process temp directory on first Scan call so
// the user's host semgrep can read them as files (semgrep --config
// requires a path on disk; it does not read stdin or in-memory rules).
// That directory is owned by the process, not by any one Scan; call
// Cleanup() on the way out (the CLI does, after the command tree
// returns) to remove it. Cleanup is refcounted, so it will not delete
// rules out from under a scan that is still running.
//
// Graceful absence: if semgrep is not on $PATH the package returns
// ErrSemgrepUnavailable and the orchestrator logs an "install
// semgrep for X% more checks" notice and continues — matches the
// existing posture for missing Python.
package semgrep

import (
	"bufio"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/gitdiff"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// ErrSemgrepUnavailable signals that no `semgrep` binary was found on
// $PATH. Callers errors.Is-check it and emit the install-hint log line
// without treating it as a scan failure.
var ErrSemgrepUnavailable = errors.New("semgrep: binary not found on PATH")

// ErrCodePathMissing signals codePath is empty or doesn't exist —
// silent-skip parity with the Python `if not code_path.exists(): return`.
var ErrCodePathMissing = errors.New("semgrep: code path does not exist")

// ErrTimeout is wrapped into the error returned when the semgrep process
// exceeds defaultTimeout, so the orchestrator can classify it as a timeout
// rather than a generic execution error.
var ErrTimeout = errors.New("semgrep: timed out")

// defaultTimeout matches python semgrep_runner.py (120s). Bounded
// per scan so a runaway rule can't hold the orchestrator hostage.
const defaultTimeout = 120 * time.Second

// evidenceMaxLen mirrors python truncate-at-200-chars + "..." behaviour.
const evidenceMaxLen = 200

// titleMaxLen mirrors python message.split("\n")[0][:120].
const titleMaxLen = 120

//go:embed rules/*.yaml
var embeddedRules embed.FS

// Extracted-rule-pack state. The directory is process-wide, not
// per-Scan: extraction is memoized so repeated scans reuse one copy,
// and semgrep reads --config off disk for the whole of its run. Removal
// therefore cannot be tied to any single Scan, so it is refcounted —
// every scan holds a reference for its duration, and Cleanup() either
// removes the dir immediately (no scans in flight) or marks it pending
// so the last scan to finish does the removal.
//
// All six fields are guarded by rulesMu.
var (
	rulesMu      sync.Mutex
	rulesOnce    sync.Once
	rulesDir     string
	rulesErr     error
	rulesRefs    int  // in-flight scans currently reading rulesDir
	rulesPending bool // Cleanup() was called while rulesRefs > 0
)

// LookPath wraps exec.LookPath and is var-not-func so tests can
// inject a fake binary location without touching $PATH.
var LookPath = exec.LookPath

// commandContext wraps exec.CommandContext for the same reason.
var commandContext = exec.CommandContext

// Scan runs the bundled fendix rule pack against codePath via the
// host's semgrep binary. Returns ErrSemgrepUnavailable when semgrep
// isn't installed; ErrCodePathMissing when codePath doesn't exist.
//
// Other failures (timeout, malformed JSON, non-success exit) return a
// wrapped error and an empty findings slice — the orchestrator logs +
// continues so a flaky semgrep run can't fail the whole scan.
//
// The provided ctx is honoured: cancellation kills the semgrep
// subprocess. A 120s deadline is layered onto ctx if ctx has no
// shorter deadline already.
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(ctx, codePath, nil)
}

// ScanWithAllowlist is Scan scoped to a diff-aware file allowlist. A nil
// allowlist scans the whole codePath (full-scan parity). When set, the
// changed files are passed to semgrep as `--include` path filters so the
// engine only analyses the diff — the semgrep half of `fendix scan --diff`.
//
// semgrep's --include takes a glob/path relative to the scan root; passing
// the exact relative path of each changed file restricts the run to those
// files. An empty (non-nil) allowlist scopes to zero files, so we return
// nothing rather than run semgrep with no --include — which would scan the
// WHOLE tree, the exact opposite of the diff intent (the historical footgun).
func ScanWithAllowlist(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, error) {
	if codePath == "" {
		return nil, ErrCodePathMissing
	}
	if info, err := os.Stat(codePath); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCodePathMissing
		}
		return nil, fmt.Errorf("semgrep: stat %q: %w", codePath, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("semgrep: %q is not a directory", codePath)
	}

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (not just in the orchestrator) because this function is exported and
	// callable directly; without it an empty allowlist scans everything.
	if allow.Empty() {
		return nil, nil
	}

	bin, err := LookPath("semgrep")
	if err != nil {
		return nil, ErrSemgrepUnavailable
	}

	// Hold a reference for the whole run: a concurrent Cleanup (process
	// shutdown) must not remove the --config dir while semgrep reads it.
	rules, release, err := acquireRules()
	if err != nil {
		return nil, fmt.Errorf("semgrep: extract rules: %w", err)
	}
	defer release()

	runCtx, cancel := contextWithDefaultTimeout(ctx, defaultTimeout)
	defer cancel()

	args := []string{
		"--config", rules,
		"--json",
		"--no-git-ignore",
		"--quiet",
	}
	// Diff scoping: one --include per changed file (relative to codePath).
	for _, rel := range allow.RelPaths(codePath) {
		args = append(args, "--include", rel)
	}
	args = append(args, codePath)

	cmd := commandContext(runCtx, bin, args...)
	stdout, err := cmd.Output()
	if err != nil {
		// Context errors (cancel/deadline) are always real failures —
		// surface them so the orchestrator can stop the scan.
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s", ErrTimeout, defaultTimeout)
		}
		if errors.Is(runCtx.Err(), context.Canceled) {
			return nil, runCtx.Err()
		}
		// If semgrep emitted parseable JSON we accept it regardless of
		// exit code. Semgrep returns 1 for "matches found" (success
		// case), and 2/5/7 for various rule-parse / engine errors —
		// in all cases the JSON envelope is well-formed and the
		// `results` field is meaningful (often empty when rules
		// failed to parse). Matches python semgrep_runner.py which
		// silently absorbs non-{0,1} exits as long as stdout parses.
		if findings, perr := parseAndMap(stdout, codePath); perr == nil && (len(findings) > 0 || isParseableEmpty(stdout)) {
			return findings, nil
		}
		// Truly broken: no parseable output AND non-zero exit.
		var exitErr *exec.ExitError
		stderr := ""
		if errors.As(err, &exitErr) {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
			if len(stderr) > 200 {
				stderr = stderr[:200] + "..."
			}
		}
		return nil, fmt.Errorf("semgrep: %w (stderr: %s)", err, stderr)
	}

	return parseAndMap(stdout, codePath)
}

// isParseableEmpty reports whether stdout decodes as a Semgrep JSON
// envelope, even one with zero results — this is how we distinguish
// "rule parse failure with valid JSON envelope" (treat as 0 findings)
// from "subprocess crashed before writing JSON" (real failure).
func isParseableEmpty(stdout []byte) bool {
	if len(stdout) == 0 {
		return false
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &probe); err != nil {
		return false
	}
	_, hasResults := probe["results"]
	return hasResults
}

// contextWithDefaultTimeout returns a context with the given timeout
// only when ctx itself has no earlier deadline; otherwise returns a
// no-op cancel + the original context.
func contextWithDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		if time.Until(dl) <= d {
			return ctx, func() {}
		}
	}
	return context.WithTimeout(ctx, d)
}

// semgrepResult mirrors the subset of the Semgrep JSON schema we use.
type semgrepResult struct {
	CheckID string         `json:"check_id"`
	Path    string         `json:"path"`
	Start   semgrepLineCol `json:"start"`
	Extra   semgrepExtra   `json:"extra"`
}

// semgrepMetavar is one metavariable binding. Only AbstractContent is decoded
// — the rest of semgrep's binding shape (byte offsets, propagated values) is
// location data, which identity must not read.
type semgrepMetavar struct {
	AbstractContent string `json:"abstract_content"`
}

type semgrepLineCol struct {
	Line int `json:"line"`
	Col  int `json:"col"`
}

type semgrepExtra struct {
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	Lines    string                 `json:"lines"`
	Metadata map[string]interface{} `json:"metadata"`
	// Metavars is what the rule actually CAPTURED — `$FUNC` -> "fetch_image".
	// It is the only structured thing distinguishing two matches of one rule
	// in one file, and semgrep has been sending it all along; we simply never
	// decoded it. Without it, five unprotected Flask routes were one finding.
	Metavars map[string]semgrepMetavar `json:"metavars"`
}

// semgrepOutput wraps a top-level Semgrep --json document.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

// parseAndMap decodes Semgrep's stdout JSON and converts each result
// into a fendix Finding. Empty or malformed stdout returns (nil, nil)
// so the orchestrator treats the scan as zero-findings rather than
// failed — matches python semgrep_runner.py which silently absorbs
// JSONDecodeError and returns an empty list. The Scan caller is
// responsible for surfacing real failures (timeout, ctx cancel,
// non-success exit with no parseable output).
func parseAndMap(stdout []byte, codeRoot string) ([]evidence.Evidence, error) {
	if len(stdout) == 0 {
		return nil, nil
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		return nil, nil
	}
	absRoot, err := filepath.Abs(codeRoot)
	if err != nil {
		absRoot = codeRoot
	}
	findings := make([]evidence.Evidence, 0, len(out.Results))
	for i := range out.Results {
		f, ok := mapResult(&out.Results[i], absRoot)
		if !ok {
			continue
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// mapResult converts one Semgrep result to a fendix Finding. Returns
// (zero, false) if the result lacks the minimal fields needed to be
// useful (no path or no rule id).
func mapResult(r *semgrepResult, absRoot string) (evidence.Evidence, bool) {
	if r.CheckID == "" || r.Path == "" {
		return evidence.Evidence{}, false
	}
	rel := r.Path
	if absPath, err := filepath.Abs(r.Path); err == nil {
		if rp, err := filepath.Rel(absRoot, absPath); err == nil && !strings.HasPrefix(rp, "..") {
			rel = rp
		}
	}
	rel = filepath.ToSlash(rel)
	endpoint := fmt.Sprintf("%s:%d", rel, r.Start.Line)
	endpointCopy := endpoint

	title := strings.TrimSpace(r.Extra.Message)
	if i := strings.IndexByte(title, '\n'); i >= 0 {
		title = title[:i]
	}
	if len(title) > titleMaxLen {
		title = title[:titleMaxLen]
	}
	if title == "" {
		title = "Semgrep finding"
	}

	// Semgrep OSS without a logged-in account replaces `extra.lines` with the
	// literal "requires login". That made every semgrep finding show that
	// phrase as its EVIDENCE — the field a user reads to decide whether the
	// finding is real — and left nothing to tell two matches of one rule in
	// one file apart, so five unprotected Flask routes shared one identity.
	//
	// The line is on disk, at a path and line number semgrep does send, so we
	// read it rather than depending on what semgrep chose to hand back.
	snippet := strings.TrimSpace(r.Extra.Lines)
	if snippet == "" || snippet == semgrepRedactedLines {
		snippet = readSourceLine(r.Path, r.Start.Line)
	}
	if len(snippet) > evidenceMaxLen {
		snippet = snippet[:evidenceMaxLen] + "..."
	}

	ruleID := normalizeCheckID(r.CheckID)
	id := "SEC-" + strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(ruleID), "-", "_"), ".", "_")

	return evidence.Evidence{
		ID:         id,
		Title:      title,
		Severity:   resolveSeverity(r),
		Source:     models.SourceWhitebox,
		SourceTier: models.TierSemgrepShim,
		Category:   resolveCategory(r),
		Endpoint:   endpoint,
		Evidence:   snippet,
		Fix:        strings.TrimSpace(r.Extra.Message),
		References: resolveCWE(r),
		Confidence: resolveConfidence(r),
		Line:       &endpointCopy,
		RuleID:     ruleID,
		// What the rule captured, when semgrep sends it. Absent from OSS
		// output, which is why the sink below carries the discriminator.
		Symbol: identifierMetavars(r.Extra.Metavars),
		// The matched construct, with string literals masked, as the finding's
		// vulnerable operation. This is what makes two matches of one rule in
		// one file two findings — see maskStringLiterals for why the masking
		// is a security boundary and not tidiness.
		Sink: maskStringLiterals(snippet),
	}, true
}

// semgrepRedactedLines is what semgrep OSS puts in `extra.lines` (and
// `extra.fingerprint`) instead of the matched source when no account is
// logged in. It is a sentinel, not source code.
const semgrepRedactedLines = "requires login"

// readSourceLine returns line n of a file, trimmed, or "" if it cannot be
// read. Best-effort by design: a missing or unreadable file leaves the finding
// with empty evidence, exactly as before, rather than failing the scan.
func readSourceLine(path string, n int) string {
	if path == "" || n <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxSourceLineLen)
	for i := 1; sc.Scan(); i++ {
		if i == n {
			return strings.TrimSpace(sc.Text())
		}
	}
	return ""
}

// maxSourceLineLen bounds a single recovered line, so a minified bundle cannot
// pull an unbounded string into a finding.
const maxSourceLineLen = 64 * 1024

// stringLiteral matches a single- or double-quoted literal, including an empty
// one. Escapes are not handled: over-masking a line is harmless here, since the
// result is a discriminator rather than something a reader parses.
var stringLiteral = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// maskStringLiterals replaces CREDENTIAL-SHAPED quoted literals in a line with
// `"…"`, leaving structural ones intact.
//
// A SECURITY BOUNDARY, not tidiness. The line recovered above is raw source,
// and a rule that matches a hardcoded credential matches the line the
// credential is on. This value becomes an identity input, and identity is
// persisted into `.fendix-ignore` files, baselines and GitHub Code Scanning —
// the wrong lifetime for a credential by a wide margin.
//
// TARGETED, though, and that half is equally load-bearing. Masking every
// literal removed the only thing telling five Flask routes apart: for a
// route-shaped rule the route path IS the identity, exactly as the endpoint is
// for a blackbox finding, and it is a string literal. Blanket masking traded a
// credential leak for a collision that hides four findings out of five.
//
// The line between them is credential SHAPE — see looksLikeCredential. A route
// path, a config key and a format string keep discriminating;
// `sk_live_51H8xQe…` and `xoxb-9999…` do not survive.
func maskStringLiterals(line string) string {
	return stringLiteral.ReplaceAllStringFunc(line, func(lit string) string {
		if looksLikeCredential(strings.Trim(lit, `"'`)) {
			return `"…"`
		}
		return lit
	})
}

// looksLikeCredential reports whether a string literal is shaped like a secret
// rather than like structure.
//
// The signal is the LONGEST UNBROKEN ALPHANUMERIC RUN, not length and not
// character variety. Both of those were tried and both were wrong:
// `/api/v1/organizations/members` is 29 characters and mixes lower-case,
// digits and separators, so length-plus-variety masked it and collapsed every
// long route into one identity.
//
// What actually separates the two is that human-written structure breaks into
// short words — `api`, `v1`, `organizations`, `members`, `database_url` — while
// a token is a single dense run: `51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs`,
// `aAaAaAaAaAaAaAaAaAaA`, a base64 blob. Sixteen characters without a
// separator is not a word anyone typed.
//
// Erring toward masking is correct where it is ambiguous — masking a
// structural literal costs one discriminator and risks a collision, while
// missing a credential persists it into ignore files, baselines and GitHub
// Code Scanning forever. This is NOT a secrets detector; scanner/secrets is,
// with real patterns. This only decides what may enter a fingerprint.
func looksLikeCredential(v string) bool {
	run := 0
	for _, r := range v {
		switch {
		// '/' is deliberately NOT a run character even though it is in the
		// base64 alphabet: it is also the path separator, and counting it
		// made `/api/v1/organizations/members` one 29-character run. Base64
		// survives the exclusion easily — '/' occurs about once every 64
		// characters there, so the runs between slashes stay far above the
		// threshold.
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+':
			run++
			if run >= credentialRunLen {
				return true
			}
		default:
			run = 0
		}
	}
	return false
}

// credentialRunLen is the unbroken alphanumeric run at which a literal is
// treated as token-shaped. Above the longest ordinary word or path segment,
// below every real key shape.
const credentialRunLen = 16

// rulesDirPrefix is the temp-directory prefix this scanner writes its rule
// files into. Shared with normalizeCheckID so the two can never drift: change
// it in one place and the id-stripping follows.
const rulesDirPrefix = "fendix-semgrep-rules-"

// rulesDirSegment matches the namespace segment semgrep derives from the
// temporary directory this scanner writes its rule files into.
var rulesDirSegment = regexp.MustCompile(`^.*?` + regexp.QuoteMeta(rulesDirPrefix) + `[^.]*\.`)

// normalizeCheckID strips the temporary rules directory out of a semgrep rule
// id, leaving the rule's own name.
//
// Semgrep namespaces a rule by the PATH it was loaded from, and this scanner
// writes its rules to os.MkdirTemp(…, "fendix-semgrep-rules-"). So every check
// id arrived as "tmp.fendix-semgrep-rules-1072928901.flask-route-no-auth-decorator",
// with a fresh number every run. Harmless while the id was only decoration;
// once it became an identity input it meant every semgrep finding got a new
// identity on every scan — RC-5 again, and worse, because it churned without
// the file changing at all.
//
// A rule id that never passed through our temp directory is returned
// unchanged: a registry rule's namespace is part of its real name.
func normalizeCheckID(checkID string) string {
	return rulesDirSegment.ReplaceAllString(checkID, "")
}

// metavarIdentifier matches a binding that is a plain identifier.
var metavarIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// identifierMetavars renders a rule's captured metavariables as a stable,
// ordered symbol — "$FUNC=fetch_image" — for the finding's identity.
//
// IDENTIFIERS ONLY, and that restriction is a security boundary rather than
// tidiness. A metavariable binds to whatever the rule matched, and a rule that
// matches a hardcoded credential binds one to the credential. Identity is
// persisted into ignore files, baselines and GitHub Code Scanning, so a
// binding that is a string literal or an expression must never reach it. A
// plain identifier — a function or variable name — cannot be a credential and
// is exactly the discriminator that separates two matches of one rule.
//
// Sorted by metavariable name so the value is order-independent; semgrep hands
// these back as a map.
func identifierMetavars(metavars map[string]semgrepMetavar) string {
	if len(metavars) == 0 {
		return ""
	}
	names := make([]string, 0, len(metavars))
	for name := range metavars {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		content := strings.TrimSpace(metavars[name].AbstractContent)
		if content == "" || len(content) > 128 || !metavarIdentifier.MatchString(content) {
			continue
		}
		parts = append(parts, name+"="+content)
	}
	return strings.Join(parts, ",")
}

// validFendixSeverities is the allowed set for the metadata.fendix_severity
// override field.
var validFendixSeverities = map[string]models.Severity{
	"CRITICAL": models.SeverityCritical,
	"HIGH":     models.SeverityHigh,
	"MEDIUM":   models.Severity("MEDIUM"),
	"LOW":      models.Severity("LOW"),
	"INFO":     models.Severity("INFO"),
}

// semgrepSeverityMap mirrors python _SEVERITY_MAP. Falls back to
// MEDIUM for unknown values, matching the Python default.
var semgrepSeverityMap = map[string]models.Severity{
	"ERROR":   models.SeverityHigh,
	"WARNING": models.Severity("MEDIUM"),
	"INFO":    models.Severity("LOW"),
}

func resolveSeverity(r *semgrepResult) models.Severity {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["fendix_severity"].(string); ok {
			if sev, ok := validFendixSeverities[strings.ToUpper(v)]; ok {
				return sev
			}
		}
	}
	if sev, ok := semgrepSeverityMap[strings.ToUpper(r.Extra.Severity)]; ok {
		return sev
	}
	return models.Severity("MEDIUM")
}

func resolveConfidence(r *semgrepResult) models.Confidence {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["confidence"].(string); ok {
			switch strings.ToUpper(v) {
			case "HIGH":
				return models.ConfidenceHigh
			case "MEDIUM":
				return models.Confidence("MEDIUM")
			case "LOW":
				return models.Confidence("LOW")
			}
		}
	}
	return models.Confidence("MEDIUM")
}

func resolveCategory(r *semgrepResult) string {
	if r.Extra.Metadata != nil {
		if v, ok := r.Extra.Metadata["category"].(string); ok && v != "" {
			return v
		}
	}
	return "code"
}

// resolveCWE accepts both string and []string shapes — Semgrep rule
// metadata supports either; Python coerces to a list either way.
func resolveCWE(r *semgrepResult) []string {
	if r.Extra.Metadata == nil {
		return nil
	}
	raw, ok := r.Extra.Metadata["cwe"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	return nil
}

// ensureRules extracts the embedded YAML rule files to a per-process
// temp directory on first call and returns its absolute path. Repeats
// of Scan within one process reuse the same directory — the rules are
// compiled into the binary so re-extraction would be wasted work.
//
// Callers that will hand the path to a subprocess must use acquireRules
// instead, so Cleanup can't remove the directory mid-run.
func ensureRules() (string, error) {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	return ensureRulesLocked()
}

// ensureRulesLocked is ensureRules with rulesMu already held.
func ensureRulesLocked() (string, error) {
	rulesOnce.Do(func() {
		dir, err := os.MkdirTemp("", rulesDirPrefix)
		if err != nil {
			rulesErr = err
			return
		}
		err = fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			data, err := embeddedRules.ReadFile(path)
			if err != nil {
				return err
			}
			out := filepath.Join(dir, filepath.Base(path))
			return os.WriteFile(out, data, 0o644)
		})
		if err != nil {
			// Don't strand a half-populated dir on a failed extraction.
			if rmErr := os.RemoveAll(dir); rmErr != nil {
				slog.Warn("semgrep: could not remove partially extracted rules dir", "dir", dir, "error", rmErr)
			}
			rulesErr = err
			return
		}
		rulesDir = dir
	})
	return rulesDir, rulesErr
}

// acquireRules extracts the rule pack (once per process) and registers
// the caller as an in-flight user of the directory. The returned release
// func must be called — via defer — when the caller no longer needs the
// path; it is idempotent, so a double release can't drive the refcount
// negative and let Cleanup delete rules another scan is still reading.
//
// Holding a reference defers Cleanup's removal, which is what makes
// shutdown safe while a semgrep subprocess still has the dir open as
// its --config.
func acquireRules() (string, func(), error) {
	rulesMu.Lock()
	defer rulesMu.Unlock()

	dir, err := ensureRulesLocked()
	if err != nil {
		return "", func() {}, err
	}
	rulesRefs++
	var once sync.Once
	return dir, func() { once.Do(releaseRules) }, nil
}

// releaseRules drops one in-flight reference and, if that was the last
// one and a Cleanup is pending, performs the deferred removal.
func releaseRules() {
	rulesMu.Lock()
	defer rulesMu.Unlock()

	if rulesRefs > 0 {
		rulesRefs--
	}
	if rulesRefs == 0 && rulesPending {
		if err := removeRulesLocked(); err != nil {
			// Nothing to return an error to on this path (the last scan
			// is unwinding), but never swallow it silently — a stale
			// temp dir is exactly the leak Cleanup exists to prevent.
			slog.Warn("semgrep: deferred rules cleanup failed", "error", err)
		}
	}
}

// Cleanup removes the temp directory holding the extracted rule pack.
//
// Call it once on the way out of a process that may have scanned: the
// fendix CLI does so after its command tree returns, and long-lived
// embedders (e.g. a webhook server) should call it on their shutdown
// path. Without it the extracted directory outlives the process and
// accumulates in $TMPDIR.
//
// Safe in every state: a no-op when nothing was extracted, and when
// scans are still in flight the removal is deferred until the last one
// finishes rather than yanking --config away from a running semgrep. A
// scan after a Cleanup re-extracts.
func Cleanup() error {
	rulesMu.Lock()
	defer rulesMu.Unlock()

	if rulesRefs > 0 {
		rulesPending = true
		return nil
	}
	return removeRulesLocked()
}

// removeRulesLocked deletes the extracted dir and re-arms the once so a
// later scan extracts a fresh copy. Caller must hold rulesMu.
func removeRulesLocked() error {
	rulesPending = false
	dir := rulesDir
	rulesOnce = sync.Once{}
	rulesDir = ""
	rulesErr = nil
	if dir == "" {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("semgrep: remove rules dir %q: %w", dir, err)
	}
	return nil
}

// resetRulesCacheForTesting removes the extracted rules dir and wipes
// the once-cache so a new extraction happens on the next call. Used by
// tests that need to assert extraction behaviour deterministically.
func resetRulesCacheForTesting() {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rulesRefs = 0
	if err := removeRulesLocked(); err != nil {
		slog.Warn("semgrep: test rules cleanup failed", "error", err)
	}
}
