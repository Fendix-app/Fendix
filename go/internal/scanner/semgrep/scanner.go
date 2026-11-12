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
//   - A bounded stage (round 4, R-008; budget.go, plan.go): --jobs from the
//     cgroup CPU quota, --max-memory from the cgroup memory limit, a total
//     wall budget of DefaultWall (300 s) for every invocation together, a
//     large multi-language tree run as one invocation per language group, and
//     the files that timed out re-run alone with a larger per-file timeout.
//   - A 30 s bound per rule and file (ruleTimeoutSeconds); a rule that hits it
//     is reported in Run.Timeouts, not dropped silently.
//   - Installed packages, build output and vendored libraries are left out of a
//     run only on evidence read from the tree (decision D6', targets.go), and
//     every one left out is listed, never dropped silently.
//   - A `// nosemgrep` comment is honoured as Semgrep honours it, but the run
//     passes --disable-nosem and the engine applies the comment itself
//     (nosem.go), so every suppressed result is reported in Run.Suppressed.
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scope"
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

// defaultTimeout bounds the Semgrep stage (DefaultWall), so a runaway rule
// can't hold the orchestrator hostage. The stage executes every bundled pack,
// and the pack is growing from Python alone to Python, JavaScript/TypeScript,
// Java and Go, so it is 300 s; it was 120 s, mirroring python
// semgrep_runner.py. A stage that exceeds it fails: a single invocation keeps
// no Semgrep finding (Semgrep prints its JSON once, at the end), while a tree
// run as one invocation per language group loses only the groups that did not
// finish.
const defaultTimeout = DefaultWall

// ruleTimeoutSeconds is Semgrep's --timeout: how long one rule may run on one
// file before Semgrep gives up on that pair and moves on. Semgrep's default,
// 5 s, is short enough to cut a taint rule off on a large file; no bound at
// all would let one pathological file use up defaultTimeout and fail the
// whole run. At 30 s a slow pair costs only its own matches, and Semgrep
// reports it in its errors, which ScanRun surfaces as Run.Timeouts. Semgrep's
// --timeout-threshold (3 by default) still applies: after three rules time
// out on one file, it skips the remaining rules on that file.
var ruleTimeoutSeconds = 30

// SetRuleTimeoutForTesting sets the per-rule --timeout for the rest of a test
// and returns the function that restores it. Tests that need a real Semgrep
// rule timeout on a file of ordinary size use it; nothing else may.
func SetRuleTimeoutForTesting(seconds int) (restore func()) {
	prev := ruleTimeoutSeconds
	ruleTimeoutSeconds = seconds
	return func() { ruleTimeoutSeconds = prev }
}

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
// subprocess. A 300 s deadline is layered onto ctx if ctx has no
// shorter deadline already.
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	return ScanWithAllowlist(ctx, codePath, nil)
}

// RuleTimeout is one rule Semgrep gave up on for one file, after
// ruleTimeoutSeconds. The rule's matches in that file are missing from the
// run's findings.
type RuleTimeout struct {
	RuleID string // the bundled rule id, as a finding's RuleID
	Path   string // relative to the scan root, forward slashes
}

// RuleError is one error Semgrep reported about the rules themselves: a rule
// it could not load (invalid schema, a pattern that does not parse, an unknown
// language, a configuration file it rejected). A run with one did not run the
// whole pack, however clean its results look.
type RuleError struct {
	Type    string // Semgrep's error type, for example InvalidRuleSchemaError
	Message string
}

// Run is what one semgrep run produced.
type Run struct {
	Findings []evidence.Evidence
	// RuleErrors lists the rules Semgrep could not load. Semgrep exits
	// non-zero (7) for them, which classifyRun reports as ErrFatal, so
	// ScanRun returns this Run together with that error and the orchestrator
	// records the run failed: a broken pack is never mistaken for a pack
	// that found nothing. RuleErrors still names each rule error by type,
	// including one reported at a level other than "error", which
	// classifyRun alone would let pass.
	RuleErrors []RuleError
	// Timeouts lists the rules Semgrep stopped on a file. ScanRun returns
	// no error for them, since Findings holds everything else the run
	// found. The rule's matches in that file are missing, so the orchestrator
	// records the run failed (reason timeout, decision D1) and keeps Findings.
	Timeouts []RuleTimeout
	// ThresholdFiles are the files on which timeoutThreshold rules timed out:
	// Semgrep runs no other rule on such a file, and names none of them.
	ThresholdFiles []string
	// FixpointTimeouts lists the functions whose taint analysis Semgrep
	// stopped at its internal fixpoint budget (R-004). Semgrep reports them
	// only in its --time profile, never in `errors`; the taint rules named
	// lost their matches in that function.
	FixpointTimeouts []FixpointTimeout
	// FixpointUnreported is set when the run's --time profile carried no
	// fixpoint_timeouts list, so a taint rule that ran out of budget would be
	// silent: the run cannot show its taint analysis finished.
	FixpointUnreported bool
	// FileErrors lists the other per-file errors that cost rule evaluation
	// on a file (out of memory, stack overflow, an internal matching error,
	// too many matches, an interfile limit, and any type this engine does not
	// know): every entry of a type IsLossType reports, but a rule Timeout and
	// a fixpoint timeout.
	FileErrors []FileError
	// SkippedRules are rules Semgrep loaded and did not run (its
	// `skipped_rules`, for example a rule this Semgrep is too old for).
	SkippedRules []string
	// Coverage is what the run left unread (decision D6, targets.go): the
	// in-scope files too large, unreadable or not in Semgrep's paths.scanned,
	// which are lost evaluation, and the files and directories declared out
	// of scope, which the ok detail lists.
	Coverage scope.Coverage
	// ParseFailures lists the files Semgrep could not parse at all (decision
	// D1'): no rule ran on them. ScanRun also records each in Coverage as lost
	// evaluation, so the orchestrator names them from there.
	ParseFailures []ParseFailure
	// PartialParses lists the files Semgrep parsed only in part, with the lines
	// it skipped. A file whose skipped lines are few and reported leaves the run
	// ok (the detail names them); any other is recorded in Coverage as lost
	// evaluation.
	PartialParses []PartialParse
	// Suppressed lists the results a nosemgrep comment removed from Findings
	// (nosem.go). They are reported, never silent.
	Suppressed []Suppressed
	// Report counts the other non-fatal, per-file problems Semgrep reported.
	Report Report
	// Budget is the CPU, memory and wall budget the stage ran under.
	Budget Budget
	// Groups names the per-language invocations a split run made, in order;
	// empty for a run of one invocation.
	Groups []string
	// Retries is what the retry pass did with each file that lost evaluation
	// to time in pass 1: re-ran it alone (resolved or not) or did not.
	Retries []Retry
}

// FixpointTimeout is one function whose taint analysis Semgrep stopped at its
// internal fixpoint budget. That budget is wall-clock and not configurable, so
// the same file can lose its taint matches on a loaded worker and keep them on
// an idle one.
type FixpointTimeout struct {
	Path      string // relative to the scan root, forward slashes
	Line      int    // where the function starts
	Rules     int    // taint rules that lost it, from Semgrep's message; 0 when it does not say
	FirstRule string // the first of them, as a finding's RuleID; "" when it does not say
	// InErrors is set when Semgrep reported it as an entry of `errors`, where
	// it is also counted in Report.Incomplete, rather than in the profile.
	InErrors bool
}

// FileError is one per-file Semgrep error that cost rule evaluation on a file,
// other than a rule timeout (Run.Timeouts) or a fixpoint timeout.
type FileError struct {
	Type   string // Semgrep's error type, "Out of memory"
	RuleID string // the rule, when Semgrep names one
	Path   string // relative to the scan root, forward slashes
}

// IsTimeout reports whether the error is a timeout class (an interfile
// timeout), as opposed to a resource or engine failure.
func (e FileError) IsTimeout() bool { return IsTimeoutType(e.Type) }

// timeoutThreshold is Semgrep's --timeout-threshold, which ScanRun leaves at
// its default: after this many rules time out on one file, Semgrep skips the
// remaining rules on that file and reports only the timeouts.
const timeoutThreshold = 3

// TimeoutThreshold is timeoutThreshold, for the scanner-status detail.
func TimeoutThreshold() int { return timeoutThreshold }

// The per-file error types Semgrep writes, by what they cost (decisions D1 and
// D1'). Semgrep 1.182.1 spells them as semgrep_interfaces/semgrep_output_v1.py
// error_type's to_json does ("Out of memory", "Internal matching error", ...);
// the ATD constructor names (OutOfMemory, MatchingError, ...) are what some
// releases and this engine's own tables have used.
//
// A timeout class is failed/timeout (timeoutLossTypes). Every other type,
// including one this engine does not know and one that could not be decoded at
// all, is failed/execution_error: an out of memory, a stack overflow, an
// internal matching error, too many matches, a missing plugin, a fatal error, a
// warning of a kind not listed here. A type cannot be shown to have cost nothing
// unless it is listed as such, so the engine fails closed.
//
// D1' (round 4): a whole-file parse failure (parseFailureTypes: "Syntax error",
// "Lexical error", "Other syntax error", "AST builder error" and their
// constructor spellings) means Semgrep evaluated no rule on that file, whatever
// its exit code says, so it is lost evaluation and the files are named. The one
// parse type that is not is "PartialParsing" (partialParsingType): Semgrep
// parsed the file as far as it could and reports the spans it skipped, so the
// analysed scope is known. It stays ok only while those spans are reported and
// small (partialSkipOK); otherwise it is lost evaluation too.
var (
	partialParsingType = "PartialParsing"
	parseFailureTypes  = map[string]bool{
		"Syntax error":       true,
		"ParseError":         true,
		"Lexical error":      true,
		"LexicalError":       true,
		"Other syntax error": true,
		"OtherParseError":    true,
		"AST builder error":  true,
		"AstBuilderError":    true,
	}
	timeoutLossTypes = map[string]bool{
		"Timeout":                           true,
		"Fixpoint timeout":                  true,
		"FixpointTimeout":                   true,
		"Timeout during interfile analysis": true,
		"TimeoutDuringInterfile":            true,
	}
)

// IsLossType reports whether a Semgrep error type means evaluation was lost
// on a file: every type but "PartialParsing", which is lost only when its skipped
// spans are not reported or are not small (decision D1').
func IsLossType(typ string) bool { return typ != partialParsingType }

// IsParseFailureType reports whether a Semgrep error type is a whole-file parse
// failure (decision D1').
func IsParseFailureType(typ string) bool { return parseFailureTypes[typ] }

// IsTimeoutType reports whether a lost-evaluation type is a timeout class.
func IsTimeoutType(typ string) bool { return timeoutLossTypes[typ] }

// Report is what one Semgrep run said about itself besides its findings.
type Report struct {
	// Incomplete counts the non-fatal, per-file problems Semgrep reported
	// (any level but "error" and "info": a file that did not parse fully, a
	// per-file or per-rule timeout, a per-file memory limit), by Semgrep
	// error type; an entry that could not be decoded is counted under
	// "undecodable". Semgrep's own exit calls such a run successful. The
	// orchestrator does not (decision D1): every type but a parse problem is
	// lost evaluation and records the run failed. The decoded entries are
	// also in Run.Timeouts, Run.FixpointTimeouts and Run.FileErrors; a count
	// here beyond what they hold is an entry the decoders could not read,
	// which fails the run too (qa-engine-01).
	Incomplete map[string]int
	// Dropped names the options the run went without because the host
	// Semgrep predates the release that added them, "semgrep 1.45.0: dropped
	// --project-root (needs 1.111.0)", or "" when none were.
	Dropped string
	// DroppedDetection is the part of Dropped whose absence changes what is
	// scanned or matched (see optionalArgs), in the same form, or "" when
	// none of the dropped options does. The orchestrator records such a run
	// failed; the others leave it ok with Dropped in the detail.
	DroppedDetection string
	// DroppedWhy says what DroppedDetection costs, "files may be skipped:
	// ...", or "" when DroppedDetection is "".
	DroppedWhy string
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

// ScanWithAllowlist is ScanRun without the run's report: the findings alone.
func ScanWithAllowlist(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, error) {
	run, err := ScanRun(ctx, codePath, allow)
	return run.Findings, err
}

// ScanWithReport is ScanWithAllowlist that also returns the run's Report.
// On ErrFatal it returns whatever findings semgrep still reported, so no
// evidence is lost while the run is recorded failed.
func ScanWithReport(ctx context.Context, codePath string, allow *gitdiff.Allowlist) ([]evidence.Evidence, Report, error) {
	run, err := ScanRun(ctx, codePath, allow)
	return run.Findings, run.Report, err
}

// ScanRun is Scan scoped to a diff-aware file allowlist, returning the rules
// Semgrep timed out on and could not load beside the findings. A nil
// allowlist scans the whole codePath (full-scan parity). When set, the
// changed files are passed to semgrep as `--include` path filters so the
// engine only analyses the diff — the semgrep half of `fendix scan --diff`.
//
// semgrep's --include takes a glob/path relative to the scan root; passing
// the exact relative path of each changed file restricts the run to those
// files. An empty (non-nil) allowlist scopes to zero files, so we return
// nothing rather than run semgrep with no --include — which would scan the
// WHOLE tree, the exact opposite of the diff intent (the historical footgun).
func ScanRun(ctx context.Context, codePath string, allow *gitdiff.Allowlist) (Run, error) {
	return ScanRunWithOptions(ctx, codePath, allow, Options{})
}

// Options set the budget of one ScanRun. A zero value derives it from the
// host's limits and the environment (budget.go).
type Options struct {
	// Jobs is Semgrep's --jobs; 0 derives it from the CPU quota.
	Jobs int
	// MaxMemoryMiB is Semgrep's --max-memory; 0 derives it from the memory
	// limit, a negative value passes none.
	MaxMemoryMiB int
	// Wall is the stage's total wall budget; 0 uses DefaultWall.
	Wall time.Duration
	// SplitBytes is the in-scope source size from which a tree in several
	// languages runs one invocation per language; 0 uses DefaultSplitBytes, a
	// negative value never splits.
	SplitBytes int64
	// MaxRetryFiles bounds the retry pass; 0 uses DefaultMaxRetryFiles, a
	// negative value disables it.
	MaxRetryFiles int
}

// limitsFunc and getenv are how the budget reads the host; tests replace them.
var (
	limitsFunc = ReadLimits
	getenv     = os.Getenv
)

// resolveBudget derives the stage's budget: the host's limits and the
// environment, overridden by what opts sets.
func resolveBudget(ctx context.Context, opts Options) Budget {
	remaining := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		remaining = time.Until(dl)
	}
	b := DeriveBudget(limitsFunc(), remaining, getenv)
	if opts.Jobs > 0 {
		b.Jobs = opts.Jobs
		b.Overridden = append(b.Overridden, "options.jobs")
	}
	switch {
	case opts.MaxMemoryMiB > 0:
		b.MaxMemoryMiB = opts.MaxMemoryMiB
		b.Overridden = append(b.Overridden, "options.max-memory")
	case opts.MaxMemoryMiB < 0:
		b.MaxMemoryMiB = 0
		b.Overridden = append(b.Overridden, "options.max-memory=none")
	}
	if opts.Wall > 0 {
		b.Wall = stageWall(opts.Wall, remaining)
		b.Overridden = append(b.Overridden, "options.wall")
	}
	return b
}

// baseArgs are the flags every invocation of a stage takes, beside its
// --config, the options optionalArgs adds and its targets.
func baseArgs() []string {
	return []string{
		"--json",
		"--no-git-ignore",
		"--quiet",
		// Without this, every run first asks semgrep.dev whether a newer
		// Semgrep exists. Fendix pins Semgrep itself and --quiet hides the
		// answer, so the check only adds outbound traffic, and with no route
		// out it is a wait: about 25 s on Semgrep 1.141.0 and 96 s on
		// 1.182.1, enough to push a mid-size tree past the stage budget and
		// record semgrep failed/timeout on an offline scan.
		"--disable-version-check",
		// Semgrep reports a taint rule that ran out of its fixpoint budget on
		// a function only in the run's profile (time.fixpoint_timeouts), never
		// in `errors` (R-004). The defect at 07a1324 was that the engine never
		// read that profile; Semgrep 1.182.1 writes it with or without --time
		// (qa-engine-04). --time is passed so that a release which writes the
		// profile only on request writes it too; detection does not depend on
		// it, because a document without a fixpoint_timeouts list is
		// FixpointUnreported, which the orchestrator records as a gap.
		"--time",
		// The size cap every Go analyzer applies (decision D6), explicit so
		// that a Semgrep whose default differs skips exactly the files the
		// engine lists as too large. Every supported release has the option.
		"--max-target-bytes", strconv.Itoa(scope.MaxFileBytes),
		// A `// nosemgrep` comment is applied by the engine (nosem.go), which
		// reports what it suppressed; Semgrep itself must not drop the result
		// without a trace (redteam3-semgrep-01).
		"--disable-nosem",
	}
}

// ScanRunWithOptions is ScanRun with an explicit budget.
func ScanRunWithOptions(ctx context.Context, codePath string, allow *gitdiff.Allowlist, opts Options) (Run, error) {
	if codePath == "" {
		return Run{}, ErrCodePathMissing
	}
	if info, err := os.Stat(codePath); err != nil {
		if os.IsNotExist(err) {
			return Run{}, ErrCodePathMissing
		}
		return Run{}, fmt.Errorf("semgrep: stat %q: %w", codePath, err)
	} else if !info.IsDir() {
		return Run{}, fmt.Errorf("semgrep: %q is not a directory", codePath)
	}
	// A root that is itself a symbolic link is the scope the caller chose.
	// Semgrep does not follow a linked scanning root (it scanned nothing and
	// the run read ok), so it is given the directory the link resolves to.
	// The allowlist's paths are reduced to root-relative --include filters
	// against the root as the caller gave it, so they keep matching.
	target := resolveRootLink(codePath)

	// A diff that matched zero scannable files → nothing to do. Guard here too
	// (not just in the orchestrator) because this function is exported and
	// callable directly; without it an empty allowlist scans everything.
	if allow.Empty() {
		return Run{}, nil
	}

	// Diff scoping: one --include per changed file, relative to codePath.
	// An allowlist that cannot be expressed under codePath is an error, never
	// a filter that matches nothing. The orchestrator checks the scope first
	// and widens to a full scan instead; this guards direct callers.
	includes, err := allow.RelPaths(codePath)
	if err != nil {
		return Run{}, fmt.Errorf("semgrep: diff scope: %w", err)
	}

	bin, err := LookPath("semgrep")
	if err != nil {
		return Run{}, ErrSemgrepUnavailable
	}

	// Hold a reference for the whole run: a concurrent Cleanup (process
	// shutdown) must not remove the --config dir while semgrep reads it.
	rules, release, err := acquireRules()
	if err != nil {
		return Run{}, fmt.Errorf("semgrep: extract rules: %w", err)
	}
	defer release()

	// The version probe is bounded on its own (versionProbeTimeout) and does
	// not spend the run's deadline.
	version := semgrepVersionOf(ctx, bin)

	// Decision D6': what the run leaves out is decided from the tree before it
	// starts, so Semgrep is told to skip exactly those paths.
	targets := inScopeTargets(target, scopeAllowlist(allow, codePath, target))

	budget := resolveBudget(ctx, opts)
	slog.Info("semgrep: stage budget", "budget", budget.String())
	started := time.Now()
	end := started.Add(budget.Wall)
	if dl, ok := ctx.Deadline(); ok && dl.Before(end) {
		end = dl
	}
	st := &stage{
		bin:      bin,
		target:   target,
		base:     baseArgs(),
		version:  version,
		excludes: targets.Excludes,
		includes: includes,
		budget:   budget,
		end:      end,
	}

	// The plan: one invocation over every pack (a small tree, or one in a
	// single language), or one per language group (plan.go).
	splitBytes := opts.SplitBytes
	if splitBytes == 0 {
		splitBytes = splitBytesFromEnv(getenv)
	}
	var shards []shard
	groups, gerr := readPackGroups(rules)
	if gerr != nil {
		slog.Warn("semgrep: could not group the rule packs by language; running them as one invocation", "error", gerr)
	} else {
		shards = planShards(targets, groups, splitBytes)
	}

	if len(shards) > 0 {
		names := make([]string, len(shards))
		for i, sh := range shards {
			names[i] = fmt.Sprintf("%s(%s, %d KiB)", sh.name, filesNoun(len(sh.files)), sh.bytes>>10)
		}
		slog.Info("semgrep: the tree is run as one invocation per language group, cheapest first", "groups", strings.Join(names, ", "))
	}

	var results []invResult
	var unfinished []string
	if len(shards) == 0 {
		res := st.run(ctx, invocation{
			label:    "semgrep",
			configs:  []string{rules},
			timeout:  ruleTimeoutSeconds,
			jobs:     budget.Jobs,
			deadline: end,
		})
		switch {
		case res.ctxErr != nil:
			return Run{}, res.ctxErr
		case res.timedOut:
			return Run{}, fmt.Errorf("%w after %s", ErrTimeout, end.Sub(started).Round(time.Second))
		case res.startErr != nil:
			return Run{}, fmt.Errorf("semgrep: %w", res.startErr)
		}
		results = []invResult{res}
	} else {
		offsets := shardDeadlines(shards, end.Sub(started))
		for i, sh := range shards {
			deadline := minTime(end, started.Add(offsets[i]))
			if time.Until(deadline) < minShardWindow {
				unfinished = append(unfinished, fmt.Sprintf("%s %s", sh.name, filesNoun(len(sh.files))))
				continue
			}
			res := st.run(ctx, invocation{
				label:    sh.name,
				configs:  sh.configs,
				timeout:  ruleTimeoutSeconds,
				jobs:     budget.Jobs,
				deadline: deadline,
			})
			switch {
			case res.ctxErr != nil:
				return Run{}, res.ctxErr
			case res.timedOut:
				slog.Warn("semgrep: a language group did not finish within its share of the stage budget; its findings are lost",
					"group", sh.name, "files", len(sh.files), "elapsed", res.elapsed.Round(time.Second))
				unfinished = append(unfinished, fmt.Sprintf("%s %s", sh.name, filesNoun(len(sh.files))))
				continue
			case res.startErr != nil:
				return Run{}, fmt.Errorf("semgrep: %w", res.startErr)
			}
			results = append(results, res)
		}
	}

	// The extensions pass (decision D6', redteam4-d6-02, DE4-04): source files
	// Semgrep does not select by their extension (APP.JS, x.mts, a .vue
	// component) are named to it one by one with --scan-unknown-extensions,
	// with every pack, so they are evaluated like any other source file. A file
	// this pass does not report is lost evaluation (checkScanned), never an
	// exclusion by name.
	if len(targets.explicit) > 0 {
		// One invocation per language group, with only that group's packs: an
		// explicit file of an unselected extension is parsed as every language
		// of every rule it is run with, and a Python rule would report the
		// JavaScript file as a syntax error.
		byGroup := map[string][]string{}
		var order []string
		for _, rel := range targets.explicit {
			g := groupOfLanguage[languageOf(rel)]
			if _, seen := byGroup[g]; !seen {
				order = append(order, g)
			}
			byGroup[g] = append(byGroup[g], filepath.Join(target, filepath.FromSlash(rel)))
		}
		for _, g := range order {
			files := byGroup[g]
			configs := []string{rules}
			if gerr == nil {
				configs = nil
				for _, pg := range groups {
					if pg.name == g {
						configs = append(configs, pg.configs...)
					}
				}
				if len(configs) == 0 {
					configs = []string{rules}
				}
			}
			label := "extensions " + g
			if time.Until(end) < minShardWindow {
				unfinished = append(unfinished, label+" "+filesNoun(len(files)))
				continue
			}
			res := st.run(ctx, invocation{
				label:      label,
				configs:    configs,
				targets:    files,
				timeout:    ruleTimeoutSeconds,
				jobs:       budget.Jobs,
				deadline:   end,
				explicit:   true,
				unknownExt: true,
			})
			switch {
			case res.ctxErr != nil:
				return Run{}, res.ctxErr
			case res.timedOut:
				slog.Warn("semgrep: the extensions pass did not finish within the stage budget; its files are not evaluated",
					"group", g, "files", len(files), "elapsed", res.elapsed.Round(time.Second))
				unfinished = append(unfinished, label+" "+filesNoun(len(files)))
			case res.startErr != nil:
				return Run{}, fmt.Errorf("semgrep: %w", res.startErr)
			default:
				results = append(results, res)
			}
		}
	}

	// Classify each invocation as a run of its own, so a fatal one is named
	// and every document that did print is kept.
	var docs []*semgrepOutput
	var cerr error
	var report Report
	var firstStatus exitStatus
	var firstStderr string
	for i, res := range results {
		out, rep, err := classifyRun(res.status, res.stdout, res.stderr)
		if i == 0 {
			report, firstStatus, firstStderr = rep, res.status, res.stderr
		}
		if err != nil {
			if len(results) > 1 || len(shards) > 0 {
				err = fmt.Errorf("%s: %w", res.label, err)
			}
			if cerr == nil {
				cerr = err
			}
		}
		if out != nil {
			docs = append(docs, out)
		} else if len(shards) > 0 {
			slog.Warn("semgrep: a language group produced no results document; its files are not evaluated",
				"group", res.label, "error", err)
		}
	}
	if len(docs) == 0 {
		report.Dropped, report.DroppedDetection, report.DroppedWhy = st.note, st.lossyNote, st.why
		if cerr != nil && !version.known {
			if why := versionProbeProblem(bin); why != "" {
				cerr = fmt.Errorf("%w (semgrep --version could not be read: %s, so every option was passed)", cerr, why)
			}
		}
		if cerr == nil && len(unfinished) > 0 {
			cerr = &StageTimeoutError{Wall: end.Sub(started), Unfinished: unfinished}
		}
		return Run{Report: report, Budget: budget}, cerr
	}
	merged := mergeOutputs(docs)
	absTarget, aerr := filepath.Abs(target)
	if aerr != nil {
		absTarget = target
	}

	// The retry pass: files that lost evaluation to time, alone, with a
	// timeout scaled to their size, in what is left of the stage's wall budget.
	packsFor := func(rel string) []string {
		if len(shards) == 0 && semgrepSelects(rel) {
			return []string{rules}
		}
		var configs []string
		for _, g := range groups {
			if g.name == otherGroup || g.name == groupOfLanguage[languageOf(rel)] {
				configs = append(configs, g.configs...)
			}
		}
		if len(configs) == 0 {
			return []string{rules}
		}
		return configs
	}
	retries := st.retryPass(ctx, merged, absTarget, func(rel string) int64 { return targets.size[rel] }, packsFor, opts.MaxRetryFiles)

	// The report: classified again from the document as it now stands (a
	// resolved retry removed its pass-1 loss), with the first invocation's own
	// exit status when it is the only one.
	if len(results) == 1 && len(shards) == 0 {
		_, report, cerr = classifyDecoded(firstStatus, merged, "", firstStderr)
	} else {
		_, report, _ = classifyDecoded(exitStatus{}, merged, "", "")
	}
	report.Dropped = st.note
	report.DroppedDetection = st.lossyNote
	report.DroppedWhy = st.why
	if cerr != nil && !version.known {
		if why := versionProbeProblem(bin); why != "" {
			cerr = fmt.Errorf("%w (semgrep --version could not be read: %s, so every option was passed)", cerr, why)
		}
	}
	// A fatal run still returns its findings, rule errors and timeouts: the
	// orchestrator keeps the findings and records the run failed.
	run := runFromOutput(merged, target)
	run.Report = report
	run.Budget = budget
	run.Retries = retries
	for _, sh := range shards {
		run.Groups = append(run.Groups, sh.name)
	}
	if cerr == nil {
		// Decision D6: what the run was meant to evaluate, against what it
		// says it evaluated. A failed run is a gap already. A language group
		// that did not finish is not in paths.scanned, so its files are named
		// here as not evaluated.
		scanned, reported := scannedPaths(merged.Paths, absTarget)
		targets.checkScanned(scanned, reported)
		// Decision D1': a file Semgrep could not parse, or parsed only in part
		// with a large or unreported skip, was not evaluated.
		for _, pf := range run.ParseFailures {
			targets.Coverage.NotParsed(orUnknownPath(pf.Path))
		}
		for i := range run.PartialParses {
			pp := &run.PartialParses[i]
			if !pp.judge(absTarget) {
				pp.Lost = true
				targets.Coverage.NotParsed(orUnknownPath(pp.Path))
			}
		}
		run.Coverage = targets.Coverage
	}
	if len(unfinished) > 0 {
		timeout := &StageTimeoutError{Wall: end.Sub(started), Unfinished: unfinished}
		if cerr == nil {
			cerr = timeout
		} else {
			cerr = fmt.Errorf("%w; and %s", cerr, timeout.Error())
		}
	}
	return run, cerr
}

// orUnknownPath names a file whose error entry carried no path.
func orUnknownPath(p string) string {
	if p == "" {
		return "unknown file"
	}
	return p
}

// resolveRootLink is root, or the directory it resolves to when root itself
// is a symbolic link. Links below the root are not resolved.
func resolveRootLink(root string) string {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&fs.ModeSymlink == 0 {
		return root
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return root
	}
	return resolved
}

// scopeAllowlist re-roots the allowlist's paths from the root the caller gave
// to the directory Semgrep scanned, when the two differ (a linked root).
func scopeAllowlist(allow *gitdiff.Allowlist, given, target string) *gitdiff.Allowlist {
	if allow == nil || given == target {
		return allow
	}
	rel, err := allow.RelPaths(given)
	if err != nil {
		return gitdiff.NewAllowlist(target, nil)
	}
	return gitdiff.NewAllowlist(target, rel)
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
//
// Level and Message are kept raw: an entry whose message is of an unexpected
// type must still be read for its level, and never cost the results beside it.
type semgrepError struct {
	LevelRaw   json.RawMessage `json:"level"`
	Type       json.RawMessage `json:"type"`
	MessageRaw json.RawMessage `json:"message"`
}

// level is the error's level ("warn", "error"), or "" when it has none.
func (e semgrepError) level() string { return rawString(e.LevelRaw) }

// undecodableType is the Report.Incomplete key of an `errors` entry that
// could not be decoded at all.
const undecodableType = "undecodable"

// isInfoLevel reports whether an `errors` entry's level is one Semgrep uses
// for notes that do not concern a file's evaluation.
func isInfoLevel(level string) bool {
	return strings.EqualFold(level, "info") || strings.EqualFold(level, "debug")
}

// message is the error's message, or "" when it has none or it is not a string.
func (e semgrepError) message() string { return rawString(e.MessageRaw) }

// typeName is the error's Semgrep type (see errorTypeName).
func (e semgrepError) typeName() string { return errorTypeName(e.Type) }

// errorTypeName is a Semgrep error type: a JSON string ("Timeout") or the
// first element of a constructor array (["PartialParsing", [...]]), or
// "unknown" when it is neither. classifyRun and the decoders share it, so an
// entry is counted and decoded under the same type.
func errorTypeName(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return s
	}
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) == nil && len(parts) > 0 && json.Unmarshal(parts[0], &s) == nil && s != "" {
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
	out, envErr := decodeEnvelope(stdout)
	return classifyDecoded(status, out, envErr, stderr)
}

// classifyDecoded is classifyRun for a document already decoded (or not:
// out == nil, envErr saying why), so the stage can classify the merge of
// several invocations' documents, and a document a retry changed, the same way
// it classifies one.
func classifyDecoded(status exitStatus, out *semgrepOutput, envErr, stderr string) (*semgrepOutput, Report, error) {
	report := Report{}
	var fatal *semgrepError
	if out != nil {
		entries, undecodable := out.errorList()
		count := func(typ string, n int) {
			if n == 0 {
				return
			}
			if report.Incomplete == nil {
				report.Incomplete = map[string]int{}
			}
			report.Incomplete[typ] += n
		}
		// An entry that is not an object, or an `errors` that is not a list,
		// cannot be shown to have cost nothing (qa-engine-01).
		count(undecodableType, undecodable)
		for i := range entries {
			e := entries[i]
			typ := e.typeName()
			if strings.EqualFold(e.level(), "error") && !nonBlockingErrorTypes[typ] {
				if fatal == nil {
					fatal = &entries[i]
				}
				continue
			}
			// "info" is Semgrep's level for notes about the run, not about a
			// file's evaluation. Every other level, "warn" and also a missing
			// or unfamiliar one, is a per-file problem and counted.
			if isInfoLevel(e.level()) {
				continue
			}
			count(typ, 1)
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
	msg := oneLine(e.message())
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
	// DataflowTrace is a taint rule's source-to-sink trace, sent because Scan
	// passes --dataflow-traces — to a logged-in account only (ADR-011). Kept
	// raw: it is decoded only for a finding already reachable (see
	// taintChain), so a trace this decoder cannot read never fails the
	// document, and a trace on any other result is never read at all.
	DataflowTrace json.RawMessage `json:"dataflow_trace"`
}

// semgrepOutput wraps a top-level Semgrep --json document.
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
	// Errors is kept raw and decoded entry by entry (errorList, ruleTimeouts,
	// ruleErrors): an entry of an unexpected shape must cost that entry,
	// never the results.
	Errors json.RawMessage `json:"errors"`
	// Time is the --time profile, read only for its fixpoint_timeouts; nil
	// when the document has none.
	Time *semgrepTime `json:"time"`
	// SkippedRules is kept raw for the same reason as Errors.
	SkippedRules json.RawMessage `json:"skipped_rules"`
	// Paths is kept raw and read only for paths.scanned (scannedPaths).
	Paths json.RawMessage `json:"paths"`
}

// semgrepTime is the part of the --time profile ScanRun reads. Its decoder
// never fails: a profile of an unexpected shape leaves fixpoint unreported,
// which the orchestrator records as a gap, and never costs the results.
type semgrepTime struct {
	fixpoint    []json.RawMessage
	hasFixpoint bool
}

func (t *semgrepTime) UnmarshalJSON(data []byte) error {
	var raw struct {
		Fixpoint json.RawMessage `json:"fixpoint_timeouts"`
	}
	// Only a list is a report: null, an object or a string cannot show that
	// taint analysis finished.
	if json.Unmarshal(data, &raw) != nil || !strings.HasPrefix(strings.TrimSpace(string(raw.Fixpoint)), "[") {
		return nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw.Fixpoint, &entries) != nil {
		return nil
	}
	t.fixpoint, t.hasFixpoint = entries, true
	return nil
}

// errorList decodes the envelope's errors entry by entry, for classifyRun: an
// entry of an unexpected shape, or an `errors` that is not a list, costs that
// entry and never the results beside it. It also returns how many entries
// could not be decoded at all (an `errors` that is present and not a list
// counts as one), which classifyRun counts as lost evaluation.
func (o *semgrepOutput) errorList() ([]semgrepError, int) {
	entries, ok := errorEntries(o.Errors)
	if !ok {
		return nil, 1
	}
	list := make([]semgrepError, 0, len(entries))
	undecodable := 0
	for _, entry := range entries {
		var e semgrepError
		if json.Unmarshal(entry, &e) != nil {
			undecodable++
			continue
		}
		list = append(list, e)
	}
	return list, undecodable
}

// errorEntries splits the document's `errors` into its entries. An absent or
// null `errors` is no entries; one that is present and not a list is not ok.
func errorEntries(raw json.RawMessage) ([]json.RawMessage, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, true
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, false
	}
	return entries, true
}

// semgrepErrorDetail is one entry of the document's `errors`, read for the
// rule it names and the file it was about. Semgrep 1.141.0 reports a rule it
// stopped on a file at --timeout as
//
//	{"code": 2, "level": "warn", "type": "Timeout", "rule_id": "<id>",
//	 "message": "Timeout when running <id> on <path>:", "path": "<path>"}
//
// and still exits 0. Type is kept raw: other error types are ATD variants,
// encoded as an array whose first element is the tag.
//
// Every field is kept raw, so a field of an unexpected type (a rule_id that is
// an object, a path that is a number, a message that is a list) costs that
// field and never the entry: the entry still says what was lost
// (qa-engine-01).
type semgrepErrorDetail struct {
	Type     json.RawMessage `json:"type"`
	Level    json.RawMessage `json:"level"`
	RuleIDv  json.RawMessage `json:"rule_id"`
	PathV    json.RawMessage `json:"path"`
	Message  json.RawMessage `json:"message"`
	ShortMsg json.RawMessage `json:"short_msg"`
	LongMsg  json.RawMessage `json:"long_msg"`
}

// ruleID is the rule the entry names, "" when it names none or the field is
// not a string.
func (e semgrepErrorDetail) ruleID() string { return rawString(e.RuleIDv) }

// path is the file the entry is about, "" when it names none or the field is
// not a string.
func (e semgrepErrorDetail) path() string { return rawString(e.PathV) }

// perFile reports whether the entry is a per-file problem as classifyRun
// counts it: any level but "info"/"debug", and not a fatal "error" entry
// (which fails the run on its own).
func (e semgrepErrorDetail) perFile() bool {
	level := rawString(e.Level)
	if isInfoLevel(level) {
		return false
	}
	return !strings.EqualFold(level, "error") || nonBlockingErrorTypes[e.typeTag()]
}

// ruleErrorTypes are the error types that say Semgrep could not load a rule.
// The others in `errors` are about a scanned file (ParseError, LexicalError,
// PartialParsing, "Syntax error") or about a run limit (Timeout, OutOfMemory)
// and do not mean the pack did not run.
//
// Each type is listed under the constructor name and, where it differs, the
// spelling Semgrep 1.182.1 writes ("Rule parse error", "Invalid YAML",
// "Pattern parse error", "Incompatible rule").
var ruleErrorTypes = map[string]bool{
	"InvalidRuleSchemaError": true,
	"RuleParseError":         true,
	"Rule parse error":       true,
	"PatternParseError":      true,
	"Pattern parse error":    true,
	"UnknownLanguageError":   true,
	"InvalidYaml":            true,
	"Invalid YAML":           true,
	"IncompatibleRule":       true,
	"Incompatible rule":      true,
}

// typeTag is the error's type (errorTypeName): "unknown" when it is neither a
// string nor a variant array.
func (e semgrepErrorDetail) typeTag() string { return errorTypeName(e.Type) }

func rawString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// ruleError reports whether the error says a rule could not be loaded, with
// the message to show for it. Semgrep reports a configuration file it rejected
// as a SemgrepError "invalid configuration file found", after the specific
// InvalidRuleSchemaError.
func (e semgrepErrorDetail) ruleError() (RuleError, bool) {
	tag := e.typeTag()
	message := rawString(e.Message)
	switch {
	case ruleErrorTypes[tag]:
	case tag == "SemgrepError" && strings.Contains(strings.ToLower(message), "invalid configuration"):
	default:
		return RuleError{}, false
	}
	for _, m := range []string{rawString(e.ShortMsg), message, rawString(e.LongMsg)} {
		if m != "" {
			message = m
			break
		}
	}
	if len(message) > evidenceMaxLen {
		message = message[:evidenceMaxLen] + "..."
	}
	return RuleError{Type: tag, Message: message}, true
}

// isTimeout reports whether the error is a rule timing out on a file.
func (e semgrepErrorDetail) isTimeout() bool {
	return e.typeTag() == "Timeout"
}

// isFixpointTimeout reports whether the error is a taint fixpoint timeout,
// in either spelling.
func (e semgrepErrorDetail) isFixpointTimeout() bool {
	tag := e.typeTag()
	return tag == "Fixpoint timeout" || tag == "FixpointTimeout"
}

// parseAndMap decodes Semgrep's stdout JSON and converts each result
// into a fendix Finding. Empty or malformed stdout returns (nil, nil)
// so the caller treats it as zero-findings; ScanRun does not rely on this
// leniency, it classifies the run first (classifyRun) and only then maps.
func parseAndMap(stdout []byte, codeRoot string) ([]evidence.Evidence, error) {
	return parseRun(stdout, codeRoot).Findings, nil
}

// parseRun is parseAndMap with the run's rule timeouts and rule errors, each
// logged here, so a rule that lost its matches on a file is never silent.
func parseRun(stdout []byte, codeRoot string) Run {
	if len(stdout) == 0 {
		return Run{}
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		return Run{}
	}
	return runFromOutput(&out, codeRoot)
}

// runFromOutput maps a decoded envelope to a Run: its findings, the rules
// Semgrep timed out on and the rules it could not load, each logged.
func runFromOutput(out *semgrepOutput, codeRoot string) Run {
	absRoot, err := filepath.Abs(codeRoot)
	if err != nil {
		absRoot = codeRoot
	}
	kept, suppressed := splitSuppressed(out.Results, absRoot)
	view := *out
	view.Results = kept
	run := Run{Findings: mapResults(&view, codeRoot), Suppressed: suppressed}
	run.ParseFailures = parseFailures(out.Errors, absRoot)
	run.PartialParses = partialParses(out.Errors, absRoot)
	run.Timeouts = ruleTimeouts(out.Errors, absRoot)
	run.RuleErrors = ruleErrors(out.Errors)
	run.ThresholdFiles = thresholdFiles(run.Timeouts)
	run.FileErrors = fileErrors(out.Errors, absRoot)
	run.FixpointTimeouts = fixpointTimeouts(out, absRoot)
	run.FixpointUnreported = out.Time == nil || !out.Time.hasFixpoint
	run.SkippedRules = skippedRules(out.SkippedRules)
	return run
}

// thresholdFiles are the files with at least timeoutThreshold rule timeouts,
// in first-seen order.
func thresholdFiles(timeouts []RuleTimeout) []string {
	count := map[string]int{}
	var order []string
	for _, t := range timeouts {
		if count[t.Path] == 0 {
			order = append(order, t.Path)
		}
		count[t.Path]++
	}
	var out []string
	for _, p := range order {
		if count[p] >= timeoutThreshold {
			slog.Warn("semgrep: rules timed out on a file up to --timeout-threshold; no other rule ran on it",
				"path", p, "timeouts", count[p])
			out = append(out, p)
		}
	}
	return out
}

// fixpointEntry is one fixpoint timeout, from the profile or from `errors`.
// Its fields are read leniently (fixpointEntry.UnmarshalJSON), so a field of
// an unexpected type costs the field and never the entry.
type fixpointEntry struct {
	Message  json.RawMessage
	Path     string
	Location struct {
		Path  string
		Start struct{ Line int }
	}
}

func (f *fixpointEntry) UnmarshalJSON(data []byte) error {
	var raw struct {
		Message  json.RawMessage `json:"message"`
		Path     json.RawMessage `json:"path"`
		Location json.RawMessage `json:"location"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.Message, f.Path = raw.Message, rawString(raw.Path)
	var loc struct {
		Path  json.RawMessage `json:"path"`
		Start json.RawMessage `json:"start"`
	}
	if json.Unmarshal(raw.Location, &loc) == nil {
		f.Location.Path = rawString(loc.Path)
		var start struct {
			Line int `json:"line"`
		}
		if json.Unmarshal(loc.Start, &start) == nil {
			f.Location.Start.Line = start.Line
		}
	}
	return nil
}

// fixpointMessage is the tail Semgrep puts on a fixpoint timeout's message:
// "... at /w/routes/api.js:1:0 [rules: 2, first: rules.js-sqli-taint]".
var fixpointMessage = regexp.MustCompile(`\[rules: (\d+), first: ([^\]\s]+)\]`)

// fixpointTimeouts reads the profile's fixpoint_timeouts, and any "Fixpoint
// timeout" entry in `errors`, where a Semgrep could also put one.
func fixpointTimeouts(out *semgrepOutput, absRoot string) []FixpointTimeout {
	var raw []json.RawMessage
	if out.Time != nil {
		raw = append(raw, out.Time.fixpoint...)
	}
	fromProfile := len(raw)
	errs, _ := errorEntries(out.Errors)
	for _, e := range errs {
		var d semgrepErrorDetail
		if json.Unmarshal(e, &d) == nil && d.isFixpointTimeout() && d.perFile() {
			raw = append(raw, e)
		}
	}
	var list []FixpointTimeout
	for i, entry := range raw {
		var e fixpointEntry
		if json.Unmarshal(entry, &e) != nil {
			// Still a fixpoint timeout, just not one this decoder can place.
			list = append(list, FixpointTimeout{InErrors: i >= fromProfile})
			continue
		}
		f := FixpointTimeout{Line: e.Location.Start.Line, InErrors: i >= fromProfile}
		if p := firstNonEmpty(e.Location.Path, e.Path); p != "" {
			f.Path = relPath(p, absRoot)
		}
		if m := fixpointMessage.FindStringSubmatch(rawString(e.Message)); m != nil {
			f.Rules, _ = strconv.Atoi(m[1])
			f.FirstRule = normalizeCheckID(m[2])
		}
		slog.Warn("semgrep: taint analysis ran out of its fixpoint budget on a function; taint matches there are missing",
			"path", f.Path, "line", f.Line, "rules", f.Rules, "first_rule", f.FirstRule)
		list = append(list, f)
	}
	return list
}

// fileErrors decodes the `errors` entries whose type means a rule, or every
// rule, was not evaluated on a file, other than a rule Timeout (ruleTimeouts)
// and a fixpoint timeout (fixpointTimeouts).
func fileErrors(raw json.RawMessage, absRoot string) []FileError {
	entries, _ := errorEntries(raw)
	var out []FileError
	for _, entry := range entries {
		var e semgrepErrorDetail
		if json.Unmarshal(entry, &e) != nil || !e.perFile() {
			continue
		}
		typ := e.typeTag()
		if e.isTimeout() || e.isFixpointTimeout() || !IsLossType(typ) || IsParseFailureType(typ) || ruleErrorTypes[typ] {
			continue
		}
		fe := FileError{Type: typ, RuleID: normalizeCheckID(e.ruleID())}
		if p := e.path(); p != "" {
			fe.Path = relPath(p, absRoot)
		}
		slog.Warn("semgrep: a per-file error cost rule evaluation; matches there are missing",
			"type", fe.Type, "rule", fe.RuleID, "path", fe.Path)
		out = append(out, fe)
	}
	return out
}

// skippedRules reads the rule ids of the document's `skipped_rules`.
func skippedRules(raw json.RawMessage) []string {
	var entries []json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		var e struct {
			RuleID string `json:"rule_id"`
		}
		_ = json.Unmarshal(entry, &e)
		id := normalizeCheckID(e.RuleID)
		if id == "" {
			id = "unknown rule"
		}
		out = append(out, id)
	}
	if len(out) > 0 {
		slog.Warn("semgrep: rules were loaded and not run; their matches are missing", "rules", out)
	}
	return out
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

// ruleErrors decodes the entries of a document's `errors` that say a rule could
// not be loaded, and logs each one. An `errors` that is not a list, and an
// entry that does not decode, are skipped.
func ruleErrors(raw json.RawMessage) []RuleError {
	entries, _ := errorEntries(raw)
	var out []RuleError
	for _, entry := range entries {
		var e semgrepErrorDetail
		if json.Unmarshal(entry, &e) != nil {
			continue
		}
		re, ok := e.ruleError()
		if !ok {
			continue
		}
		slog.Warn("semgrep: a rule could not be loaded; its matches are missing", "type", re.Type, "message", re.Message)
		out = append(out, re)
	}
	return out
}

// ruleTimeouts decodes the Timeout entries of a document's `errors`, and
// logs each one. An `errors` that is not a list, and an entry that does not
// decode, are skipped: they only ever add timeouts to a run.
func ruleTimeouts(raw json.RawMessage, absRoot string) []RuleTimeout {
	entries, _ := errorEntries(raw)
	var out []RuleTimeout
	for _, entry := range entries {
		var e semgrepErrorDetail
		if json.Unmarshal(entry, &e) != nil || !e.isTimeout() || !e.perFile() {
			continue
		}
		t := RuleTimeout{RuleID: normalizeCheckID(e.ruleID())}
		if p := e.path(); p != "" {
			t.Path = relPath(p, absRoot)
		}
		slog.Warn("semgrep: rule timed out on a file; its matches there are missing",
			"rule", t.RuleID, "path", t.Path, "timeout_seconds", ruleTimeoutSeconds)
		out = append(out, t)
	}
	return out
}

// mapResult converts one Semgrep result to a fendix Finding. Returns
// (zero, false) if the result lacks the minimal fields needed to be
// useful (no path or no rule id).
func mapResult(r *semgrepResult, absRoot string) (evidence.Evidence, bool) {
	if r.CheckID == "" || r.Path == "" {
		return evidence.Evidence{}, false
	}
	rel := relPath(r.Path, absRoot)
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

	// What the rule captured, when semgrep sends it. Absent from OSS
	// output, which is why the sink below carries the discriminator.
	symbol := identifierMetavars(r.Extra.Metavars)
	// The matched construct, with string literals masked, as the finding's
	// vulnerable operation. This is what makes two matches of one rule in
	// one file two findings — see maskStringLiterals for why the masking
	// is a security boundary and not tidiness.
	sink := maskStringLiterals(snippet)
	if declaresTaintReachability(r.Extra.Metadata) {
		// A rule that asks for reachability (ADR-011) takes its identity
		// only from what every run has: the match's own line, and no
		// metavariables, which semgrep sends only to a logged-in account.
		// Its identity is then the same logged in or out, trace or no
		// trace, gate open or closed. No rule bundled before ADR-011 sets
		// the key, so no existing identity moves.
		symbol = ""
		sink = taintRuleSink(r)
	}

	ev := evidence.Evidence{
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
		Symbol:     symbol,
		Sink:       sink,
	}

	// A taint-mode rule's match, for a language that cleared its gate, is the
	// semgrep_taint tier (R-pf56); a dataflow trace, when semgrep sends one,
	// only adds detail to its chain. Every other result — every rule bundled
	// today — stays exactly the shim finding built above.
	if taintReachable(r, ruleID) {
		ev.SourceTier = models.TierSemgrepTaint
		ev.Reachable = true
		ev.TaintChain = taintChain(r.Extra.DataflowTrace, absRoot,
			models.TaintLink{File: rel, Line: r.Start.Line, Expr: sink})
	}
	return ev, true
}

// relPath renders a path semgrep reported relative to the scan root, with
// forward slashes, or as reported when it lies outside the root. Endpoint and
// every taint-chain link go through it, so they name a file the same way.
func relPath(path, absRoot string) string {
	rel := path
	if absPath, err := filepath.Abs(path); err == nil {
		if rp, err := filepath.Rel(absRoot, absPath); err == nil && !strings.HasPrefix(rp, "..") {
			rel = rp
		}
	}
	return filepath.ToSlash(rel)
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
			// Decision D6': no rule skips a file by its path (rulepaths.go).
			return os.WriteFile(out, stripPathExcludes(data), 0o644)
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
