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
	"syscall"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
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

// ErrFatal is wrapped into the error returned when semgrep ran but the run
// was fatal by Semgrep's own contract (see classifyRun): an exit other than 0
// or 1, a death by signal, or an error of level "error" in its JSON. The orchestrator records it
// failed/execution_error. Findings semgrep still reported are returned with it.
var ErrFatal = errors.New("semgrep: fatal error")

// ErrMalformedOutput is wrapped into the error returned when semgrep exited
// as if it succeeded but stdout is not a JSON results envelope. With --json a
// working semgrep always writes one, so zero findings cannot be assumed; the
// orchestrator records failed/malformed_output.
var ErrMalformedOutput = errors.New("semgrep: no JSON results envelope")

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
// Other failures return a wrapped error — ErrTimeout, ErrFatal (a fatal run
// by Semgrep's own contract; see classifyRun) or ErrMalformedOutput (no JSON
// results envelope) — and the orchestrator records semgrep failed and
// continues, so one broken analyzer cannot stop the scan, and is never
// mistaken for a clean run.
//
// The provided ctx is honoured: cancellation kills the semgrep
// subprocess. A 120s deadline is layered onto ctx if ctx has no
// shorter deadline already.
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(ctx, codePath, nil)
}

// Report is what one Semgrep run said about itself besides its findings.
type Report struct {
	// Incomplete counts the non-fatal, per-file problems Semgrep reported
	// (level "warn": a file that did not parse fully, a per-file or per-rule
	// timeout, a per-file memory limit), by Semgrep error type. The run is
	// still ok; findings in those files may be missing.
	Incomplete map[string]int
}

// Summary is the scanner-status detail for a clean run with per-file
// problems, or "" when there were none. Counts and Semgrep error types only:
// never a message, which can quote the scanned source.
func (r Report) Summary() string {
	if len(r.Incomplete) == 0 {
		return ""
	}
	types := make([]string, 0, len(r.Incomplete))
	total := 0
	for t, n := range r.Incomplete {
		types = append(types, t)
		total += n
	}
	sort.Strings(types)
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = fmt.Sprintf("%s %d", t, r.Incomplete[t])
	}
	return fmt.Sprintf("%d non-fatal per-file problem(s) reported by semgrep (%s); findings in those files may be incomplete",
		total, strings.Join(parts, ", "))
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
	findings, _, err := ScanWithReport(ctx, codePath, allow)
	return findings, err
}

// ScanWithReport is ScanWithAllowlist that also returns the run's Report.
// On ErrFatal it returns whatever findings semgrep still reported, so no
// evidence is lost while the run is recorded failed.
func ScanWithReport(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, Report, error) {
	none := Report{}
	if codePath == "" {
		return nil, none, ErrCodePathMissing
	}
	if info, err := os.Stat(codePath); err != nil {
		if os.IsNotExist(err) {
			return nil, none, ErrCodePathMissing
		}
		return nil, none, fmt.Errorf("semgrep: stat %q: %w", codePath, err)
	} else if !info.IsDir() {
		return nil, none, fmt.Errorf("semgrep: %q is not a directory", codePath)
	}

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (not just in the orchestrator) because this function is exported and
	// callable directly; without it an empty allowlist scans everything.
	if allow.Empty() {
		return nil, none, nil
	}

	// Diff scoping: one --include per changed file, relative to codePath.
	// An allowlist that cannot be expressed under codePath is an error, never
	// a filter that matches nothing. The orchestrator checks the scope first
	// and widens to a full scan instead; this guards direct callers.
	includes, err := allow.RelPaths(codePath)
	if err != nil {
		return nil, none, fmt.Errorf("semgrep: diff scope: %w", err)
	}

	bin, err := LookPath("semgrep")
	if err != nil {
		return nil, none, ErrSemgrepUnavailable
	}

	// Hold a reference for the whole run: a concurrent Cleanup (process
	// shutdown) must not remove the --config dir while semgrep reads it.
	rules, release, err := acquireRules()
	if err != nil {
		return nil, none, fmt.Errorf("semgrep: extract rules: %w", err)
	}
	defer release()

	runCtx, cancel := contextWithDefaultTimeout(ctx, defaultTimeout)
	defer cancel()

	args := []string{
		"--config", rules,
		"--json",
		"--no-git-ignore",
		"--quiet",
		// Without this, every run first asks semgrep.dev whether a newer
		// Semgrep exists. Fendix pins Semgrep itself and --quiet hides the
		// answer, so the check only adds outbound traffic, and with no route
		// out it is a wait: about 25 s on Semgrep 1.141.0 and 96 s on
		// 1.182.1, enough to push a mid-size tree past defaultTimeout and
		// record semgrep failed/timeout on an offline scan.
		"--disable-version-check",
	}
	for _, rel := range includes {
		args = append(args, "--include", rel)
	}
	args = append(args, codePath)

	cmd := commandContext(runCtx, bin, args...)
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, n: stderrKeep}
	stdout, err := cmd.Output()
	if err != nil {
		// Context errors (cancel/deadline) are always real failures —
		// surface them so the orchestrator can stop the scan.
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, none, fmt.Errorf("%w after %s", ErrTimeout, defaultTimeout)
		}
		if errors.Is(runCtx.Err(), context.Canceled) {
			return nil, none, runCtx.Err()
		}
	}
	status := exitStatus{code: 0}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, none, fmt.Errorf("semgrep: %w", err)
		}
		status = exitStatusOf(exitErr)
	}
	out, report, cerr := classifyRun(status, stdout, stderr.String())
	if out == nil {
		return nil, report, cerr
	}
	findings := mapResults(out, codePath)
	return findings, report, cerr
}

// stderrKeep bounds how much of semgrep's stderr is kept for an error
// message; only its tail is ever shown.
const stderrKeep = 64 * 1024

// limitedWriter keeps the first n bytes written to it and discards the rest,
// so a chatty semgrep cannot grow memory without bound.
type limitedWriter struct {
	w interface{ WriteString(string) (int, error) }
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		keep := p
		if len(keep) > l.n {
			keep = keep[:l.n]
		}
		_, _ = l.w.WriteString(string(keep))
		l.n -= len(keep)
	}
	return len(p), nil
}

// exitStatus is how the semgrep process ended: an exit code, or the signal
// that killed it (code -1).
type exitStatus struct {
	code   int
	signal string
}

// signalName names the signal that killed the process, "signal 9 (killed)".
func signalName(e *exec.ExitError) string {
	if ws, ok := e.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		sig := ws.Signal()
		return fmt.Sprintf("signal %d (%s)", int(sig), sig.String())
	}
	return "a signal"
}

func exitStatusOf(e *exec.ExitError) exitStatus {
	st := exitStatus{code: e.ExitCode()}
	if st.code == -1 {
		st.signal = signalName(e)
	}
	return st
}

// semgrepError is one entry of the envelope's "errors" list.
type semgrepError struct {
	Level   string          `json:"level"`
	Type    json.RawMessage `json:"type"`
	Message string          `json:"message"`
}

// typeName is the error's Semgrep type: a JSON string ("Timeout") or the
// first element of a constructor array (["PartialParsing", [...]]).
func (e semgrepError) typeName() string {
	var s string
	if json.Unmarshal(e.Type, &s) == nil && s != "" {
		return s
	}
	var parts []json.RawMessage
	if json.Unmarshal(e.Type, &parts) == nil && len(parts) > 0 && json.Unmarshal(parts[0], &s) == nil && s != "" {
		return s
	}
	return "unknown"
}

// Interfile-analysis errors Semgrep itself reports at level "error" yet does
// not fail the run on (output.py, is_special_interfile_analysis_error): the
// per-file results are still produced. They need --pro, which Fendix never
// passes; they are counted like any per-file problem rather than failing.
var nonBlockingErrorTypes = map[string]bool{
	"OutOfMemoryDuringInterfile": true,
	"TimeoutDuringInterfile":     true,
}

// classifyRun decides what a finished semgrep run means, from how the process
// ended and what it wrote. Semgrep 1.182.1's contract, read from its source
// (semgrep/error.py, output.py `_final_raise`, core_output.py) and exercised
// against the real binary (fixtures in testdata/runs):
//
//   - Fendix passes neither --error nor --strict, so a working run exits 0
//     whether or not it found anything. Exit 1 means findings under --error
//     and is accepted like 0 when it comes with an envelope.
//   - Per-file problems are level "warn" and leave the exit code at 0: a file
//     that does not fully parse (PartialParsing, Syntax error, Lexical error),
//     a per-file or per-rule Timeout, a per-file OutOfMemory. Their JSON
//     "code" can be 2 or 3 anyway, so "code" is never read: only "level".
//     Such a run is ok; the problems are counted in the Report.
//   - A fatal problem is level "error": an invalid or missing config (exit 7),
//     a rule that does not parse (exit 2, and other rules' results are still
//     printed), an engine killed or crashed mid-run, which includes out of
//     memory ("You are seeing this because the engine was killed", exit 2,
//     with a valid envelope and no results).
//   - Semgrep sets its exit code from the LAST error only, so an error-level
//     entry followed by per-file warnings exits 0 (observed: a rule parse
//     error plus syntax errors in three files). Any level "error" entry is
//     therefore fatal, whatever the exit code.
//
// So: a non-zero exit other than 1, a death by signal, exit 1 without an
// envelope, or any level "error" entry (bar the two interfile types above) is
// ErrFatal, named by the first error message or the tail of stderr; exit 0
// without a JSON results envelope is ErrMalformedOutput. The envelope, when
// there is one, is returned with the error so findings it carries are kept.
func classifyRun(status exitStatus, stdout []byte, stderr string) (*semgrepOutput, Report, error) {
	report := Report{}
	out, envErr := decodeEnvelope(stdout)
	var fatal *semgrepError
	if out != nil {
		for i := range out.Errors {
			e := out.Errors[i]
			typ := e.typeName()
			if strings.EqualFold(e.Level, "error") && !nonBlockingErrorTypes[typ] {
				if fatal == nil {
					fatal = &out.Errors[i]
				}
				continue
			}
			if strings.EqualFold(e.Level, "warn") || strings.EqualFold(e.Level, "warning") || nonBlockingErrorTypes[typ] {
				if report.Incomplete == nil {
					report.Incomplete = map[string]int{}
				}
				report.Incomplete[typ]++
			}
		}
	}

	// Exit 1 is "findings" only with an envelope; without one it is how
	// Semgrep's Python entrypoint exits on an exception (observed: a
	// semgrep-core it cannot exec).
	exitedClean := status.signal == "" && (status.code == 0 || (status.code == 1 && out != nil))
	switch {
	case !exitedClean:
		how := fmt.Sprintf("exited %d", status.code)
		if status.signal != "" {
			how = "was killed by " + status.signal
		}
		cause := firstNonEmpty(errorText(fatal), tailText(stderr), "no error message")
		if out == nil {
			return nil, report, fmt.Errorf("%w: semgrep %s and wrote no JSON results: %s", ErrFatal, how, cause)
		}
		return out, report, fmt.Errorf("%w: semgrep %s: %s", ErrFatal, how, cause)
	case out == nil:
		return nil, report, fmt.Errorf("%w: semgrep exited %d but stdout is %s (stderr: %s)",
			ErrMalformedOutput, status.code, envErr, firstNonEmpty(tailText(stderr), "empty"))
	case fatal != nil:
		return out, report, fmt.Errorf("%w: semgrep exited %d but reported a fatal error: %s", ErrFatal, status.code, errorText(fatal))
	}
	return out, report, nil
}

// decodeEnvelope returns the JSON results envelope, or nil and why not.
func decodeEnvelope(stdout []byte) (*semgrepOutput, string) {
	if len(strings.TrimSpace(string(stdout))) == 0 {
		return nil, "empty"
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &keys); err != nil {
		return nil, "not JSON"
	}
	if _, ok := keys["results"]; !ok {
		return nil, "JSON without a results list"
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		return nil, "JSON whose results or errors do not decode"
	}
	return &out, ""
}

// errorText is a Semgrep error on one line: its type and message, bounded
// (a FatalError message can carry a stack trace).
func errorText(e *semgrepError) string {
	if e == nil {
		return ""
	}
	msg := oneLine(e.Message)
	if msg == "" {
		return e.typeName()
	}
	return boundText(e.typeName() + ": " + msg)
}

// tailText is the last non-empty lines of stderr, bounded and on one line.
func tailText(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return boundText(oneLine(strings.Join(lines, " | ")))
}

// oneLine collapses whitespace and drops control characters.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// errorTextMax bounds an error message in a scanner-status detail.
const errorTextMax = 240

func boundText(s string) string {
	if len(s) > errorTextMax {
		return s[:errorTextMax] + "..."
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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
	Errors  []semgrepError  `json:"errors,omitempty"`
}

// mapResults converts every result of a decoded envelope to a Finding.
func mapResults(out *semgrepOutput, codeRoot string) []evidence.Evidence {
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
	return findings
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
