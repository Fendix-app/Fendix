package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/npm"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/pip"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// scannerStatusList accumulates the per-scanner outcome for the dep-CVE,
// secrets, semgrep, and textscan passes (F-L7/F-L13/F-L14). It replaces
// the old fail-open behaviour where a scanner crash was logged at WARN
// and silently dropped: every failure is now recorded, surfaced in a
// scan-end summary, exposed in ScanMetadata, and (with
// --fail-on-scanner-error) able to force a non-zero exit.
type scannerStatusList []reporters.ScannerStatus

// ok records a clean run.
func (l *scannerStatusList) ok(name string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerOK})
}

// okDetail records a clean run that carries a note the reader should see
// (for example partial probe responses). The state is still ok.
func (l *scannerStatusList) okDetail(name, detail string) {
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerOK, Detail: truncateDetail(detail)})
}

// skip records an analyzer that did not run, with the closed reason that
// says why. A skip is never a failure; whether it is a coverage gap is
// decided by the reason's class (dependency_missing is, disabled is not).
func (l *scannerStatusList) skip(name string, reason reporters.ScannerReason, detail string) {
	if !reason.IsSkip() {
		panic("scannerStatusList.skip called with a non-skip reason: " + string(reason))
	}
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerSkipped, Reason: reason, Detail: truncateDetail(detail)})
}

// fail records an analyzer that started and did not deliver. The error text
// is truncated to keep the metadata payload bounded.
func (l *scannerStatusList) fail(name string, reason reporters.ScannerReason, err error) {
	l.failDetail(name, reason, truncateErr(err))
}

// failDetail is fail with a hand-written detail (no error value).
func (l *scannerStatusList) failDetail(name string, reason reporters.ScannerReason, detail string) {
	if !reason.IsFail() {
		panic("scannerStatusList.fail called with a non-fail reason: " + string(reason))
	}
	*l = append(*l, reporters.ScannerStatus{Name: name, State: reporters.ScannerFailed, Reason: reason, Detail: truncateDetail(detail)})
}

// set appends a fully-formed entry (used for python-engine children, whose
// state and reason arrive over the protocol and are validated there).
func (l *scannerStatusList) set(entry reporters.ScannerStatus) {
	entry.Detail = truncateDetail(entry.Detail)
	*l = append(*l, entry)
}

// markAttempts stamps the in-process retry count on the named entry.
func (l *scannerStatusList) markAttempts(name string, n int) {
	for i := range *l {
		if (*l)[i].Name == name {
			(*l)[i].Attempts = n
			return
		}
	}
}

// has reports whether an entry for name was recorded.
func (l scannerStatusList) has(name string) bool {
	for _, s := range l {
		if s.Name == name {
			return true
		}
	}
	return false
}

// sorted returns a copy in registry order. Names outside the registry keep
// their relative order after every registered name. Stable, so a scan
// renders identically on every run.
func (l scannerStatusList) sorted() scannerStatusList {
	out := make(scannerStatusList, len(l))
	copy(out, l)
	sort.SliceStable(out, func(i, j int) bool {
		ri, iok := registryRank[out[i].Name]
		rj, jok := registryRank[out[j].Name]
		switch {
		case iok && jok:
			return ri < rj
		case iok:
			return true
		default:
			return false
		}
	})
	return out
}

// hasFailure reports whether any recorded scanner ran and errored.
// Skipped scanners do not count.
func (l scannerStatusList) hasFailure() bool {
	for _, s := range l {
		if s.Failed() {
			return true
		}
	}
	return false
}

// failedNames returns the names of every scanner that errored, for the
// scan-end summary line.
func (l scannerStatusList) failedNames() []string {
	var out []string
	for _, s := range l {
		if s.Failed() {
			out = append(out, s.Name)
		}
	}
	return out
}

// truncateErr renders an error to a bounded single-line detail string.
func truncateErr(err error) string {
	if err == nil {
		return ""
	}
	return truncateDetail(err.Error())
}

// truncateDetail bounds a detail string the same way truncateErr does.
func truncateDetail(s string) string {
	const max = 240
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// classifyErr maps an analyzer error to a fail reason. semgrep.ErrTimeout
// (or a bare context deadline) is a timeout; everything else is typed via
// neterr.Classify against the typed transport errors pip/npm/govulncheck
// now produce (Task 7): a *neterr.LookupError or *neterr.StatusError
// wrapping a transient (429/5xx) status, or a subprocess sentinel, maps to
// network_error; a deadline or subprocess-timeout sentinel maps to
// timeout. Everything else stays execution_error — in particular a 4xx
// StatusError other than 429, which is never transient.
func classifyErr(err error) reporters.ScannerReason {
	if err == nil {
		return reporters.ReasonExecutionError
	}
	if errors.Is(err, semgrep.ErrTimeout) {
		return reporters.ReasonTimeout
	}
	if errors.Is(err, semgrep.ErrMalformedOutput) {
		return reporters.ReasonMalformedOutput
	}
	switch neterr.Classify(err) {
	case neterr.KindTimeout:
		return reporters.ReasonTimeout
	case neterr.KindNetwork:
		return reporters.ReasonNetworkError
	}
	return reporters.ReasonExecutionError
}

// recordSemgrepRun records a semgrep run that completed and keeps its
// findings. A run that stopped a rule on a file at its per-rule timeout is
// still ok, as it is by Semgrep's own contract and in v3.7.0 (R-pf90): the rule
// lost its matches in that file only. The detail names each such rule and
// file, so the gap is not invisible; the other per-file problems Semgrep
// reported are counted in it too. A run that did not load a rule, or that was
// killed (ErrFatal, which never reaches here), is failed.
func recordSemgrepRun(status *scannerStatusList, findings *[]evidence.Evidence, run semgrep.Run) {
	*findings = append(*findings, run.Findings...)
	// A rule Semgrep could not load means the pack did not run in full: the
	// run is failed, so a broken pack is neither read as a clean scan nor
	// allowed to stand in for the checks that cover for Semgrep (see
	// dropFallbackJSPatterns). Semgrep exits non-zero with a parseable
	// document in that case, and ScanRun accepts it.
	if len(run.RuleErrors) > 0 {
		noun := "rule errors"
		if len(run.RuleErrors) == 1 {
			noun = "rule error"
		}
		parts := make([]string, 0, len(run.RuleErrors))
		for _, e := range run.RuleErrors {
			parts = append(parts, e.Type+": "+e.Message)
		}
		detail := fmt.Sprintf("%d %s, rules not loaded: %s", len(parts), noun, strings.Join(parts, "; "))
		if len(run.Timeouts) > 0 {
			detail += fmt.Sprintf("; %d rule timeout(s) as well", len(run.Timeouts))
		}
		status.failDetail(AnalyzerSemgrep, reporters.ReasonExecutionError, detail)
		return
	}
	var parts []string
	if len(run.Timeouts) > 0 {
		pairs := make([]string, 0, len(run.Timeouts))
		for _, t := range run.Timeouts {
			rule, file := t.RuleID, t.Path
			if rule == "" {
				rule = "unknown rule"
			}
			if file == "" {
				file = "unknown file"
			}
			pairs = append(pairs, rule+" on "+file)
		}
		noun := "rule timeouts"
		if len(pairs) == 1 {
			noun = "rule timeout"
		}
		parts = append(parts, fmt.Sprintf("%d %s, matches missing: %s", len(pairs), noun, strings.Join(pairs, ", ")))
	}
	// Per-file problems Semgrep reports as non-fatal (a file that did not
	// fully parse, a per-file memory limit) leave the run ok, counted in the
	// detail so they are not invisible. A Timeout is already named above.
	other := run.Report
	if len(run.Timeouts) > 0 && other.Incomplete["Timeout"] > 0 {
		other.Incomplete = make(map[string]int, len(run.Report.Incomplete))
		for typ, n := range run.Report.Incomplete {
			if typ != "Timeout" {
				other.Incomplete[typ] = n
			}
		}
	}
	if summary := other.Summary(); summary != "" {
		parts = append(parts, summary)
	}
	if len(parts) == 0 {
		status.ok(AnalyzerSemgrep)
		return
	}
	status.okDetail(AnalyzerSemgrep, strings.Join(parts, "; "))
}

// recordDepScanResult records the outcome of a pip-style dep scan (one
// that returns an empty slice rather than a sentinel when no manifest is
// found) and appends any findings. Used by both the online and offline
// pip paths so they record status identically.
func (o *Orchestrator) recordDepScanResult(status *scannerStatusList, name, label string, findings *[]evidence.Evidence, scanFindings []evidence.Evidence, err error) {
	if len(scanFindings) > 0 {
		*findings = append(*findings, scanFindings...)
	}
	switch {
	case err == nil:
		slog.Info(label+" complete", "findings", len(scanFindings))
		status.ok(name)
	case errors.Is(err, pip.ErrNoManifests):
		slog.Debug(label + " found no manifests under code path")
		status.skip(name, reporters.ReasonNotApplicable, "no Python manifest under --code")
	default:
		slog.Warn(label+" failed", "error", err)
		status.fail(name, classifyErr(err), err)
	}
}

// recordNpmScanResult records the npm dep-scan outcome, preserving the
// existing sentinel handling (lockfile-missing advisory finding,
// no-lockfile silent skip). Shared by the online and offline npm paths.
// Returns the updated findings slice.
func (o *Orchestrator) recordNpmScanResult(status *scannerStatusList, findings *[]evidence.Evidence, npmFindings []evidence.Evidence, err error) []evidence.Evidence {
	if len(npmFindings) > 0 {
		*findings = append(*findings, npmFindings...)
	}
	switch {
	case err == nil:
		slog.Info("native npm deps scan complete", "findings", len(npmFindings))
		status.ok("npm")
	case errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent):
		// Single INFO finding — flag the gap without producing noise.
		// Surfaced by the Track 4 heavy-eval on Juice Shop / dvna / etc.
		slog.Info("npm deps scan: package.json present but lock file missing — emitting advisory finding")
		*findings = append(*findings, evidence.Evidence{
			ID:         "SEC-NPM_LOCKFILE_MISSING",
			RuleID:     "scanstatus/npm-lockfile-missing",
			Title:      "npm dep-CVE scan skipped — package-lock.json missing",
			Severity:   models.SeverityInfo,
			Source:     models.SourceWhitebox,
			Category:   "config",
			Endpoint:   filepath.Join(o.cfg.CodePath, "package.json"),
			Evidence:   "package.json was found at the scan root but no package-lock.json. Without the lock file, fendix's npm-audit scanner can't resolve transitive versions and skips the dep-CVE pass.",
			Fix:        "Run `npm install` (or `npm ci`) to materialise package-lock.json, then re-scan. For yarn or pnpm projects this scanner is currently silent; that gap is tracked separately. CWE-1395.",
			References: []string{"https://cwe.mitre.org/data/definitions/1395.html"},
			Confidence: models.ConfidenceHigh,
		})
		status.skip("npm", reporters.ReasonUnsupportedTarget, "package.json without package-lock.json")
	case errors.Is(err, npm.ErrNoLockfile):
		slog.Debug("no package-lock.json at code path, skipping native npm deps scan")
		status.skip("npm", reporters.ReasonNotApplicable, "no package.json under --code")
	default:
		slog.Warn("native npm deps scan failed", "error", err)
		status.fail("npm", classifyErr(err), err)
	}
	return *findings
}

// depScanners are the three dependency-CVE passes that the report's
// `checks_run` list has always summarised under the single coarse label
// "deps". Kept as one label for backward compatibility: consumers parse
// checks_run for that exact string.
var depScanners = map[string]bool{"govulncheck": true, "pip": true, "npm": true}

// codeScannerLabels returns the coarse `checks_run` labels for the code
// analysis passes that ACTUALLY completed, derived from the recorded
// per-scanner status rather than from the scan configuration.
//
// The list used to be hand-appended whenever a code path was configured,
// which meant a scan reported semgrep under "checks_run" while
// scanner_status simultaneously recorded it as skipped because the binary
// was missing — the same document asserting a check both ran and did not.
// A consumer cannot audit a release decision made from evidence that was
// never gathered, so only an `ok` pass earns its label here.
//
// Order is fixed (secrets, semgrep, deps) rather than derived from map or
// slice iteration, so two identical scans render byte-identical reports.
func codeScannerLabels(status scannerStatusList) []string {
	ran := make(map[string]bool, len(status))
	for _, s := range status {
		if s.State == reporters.ScannerOK {
			ran[s.Name] = true
		}
	}
	deps := false
	for name := range depScanners {
		if ran[name] {
			deps = true
			break
		}
	}

	var out []string
	if ran["secrets"] {
		out = append(out, "secrets")
	}
	if ran["semgrep"] {
		out = append(out, "semgrep")
	}
	if deps {
		out = append(out, "deps")
	}
	return out
}

// jsFallbackPrefix starts the rule ids of the Python engine's JavaScript
// pattern checks (SEC-JS_EVAL, SEC-JS_INNER_HTML, SEC-JS_DOCUMENT_WRITE,
// SEC-JS_SQL_TEMPLATE).
const jsFallbackPrefix = "SEC-JS_"

// semgrepRunSucceeded reports whether the run-level semgrep entry is ok. There
// is one status for the whole Semgrep run and none per pack; the JavaScript
// pack is always part of it.
func (l scannerStatusList) semgrepRunSucceeded() bool {
	for _, s := range l {
		if s.Name == AnalyzerSemgrep {
			return s.State == reporters.ScannerOK
		}
	}
	return false
}

// jsSemgrepPackBlocks reports whether Semgrep's JavaScript and TypeScript taint
// matches can block: both languages are in semgrep.ReachabilityLanguages
// (ADR-011). While they are not (ruling R-pf81: real-world precision is too low),
// every JS/TS Semgrep taint match is a plain warning, and the Python engine's
// JS_SQL_TEMPLATE pattern is the only JavaScript SQL finding that can block.
// Dropping it then would turn nine blocking corpus cases (express, nestjs and
// nextjs sqli direct, indirect and cross_file) into warnings.
func jsSemgrepPackBlocks() bool {
	return semgrep.ReachabilityLanguages["javascript"] && semgrep.ReachabilityLanguages["typescript"]
}

// dropFallbackJSPatterns removes the Python engine's JavaScript pattern
// findings (rule ids SEC-JS_*) when Semgrep's JavaScript pack has taken over:
// the Semgrep run succeeded AND its JS/TS taint findings can block
// (jsSemgrepPackBlocks). They are the fallback for a scan without Semgrep
// (--fast, or no binary), where nothing else reads JavaScript beyond textscan;
// once the pack answers they only repeat it, less precisely (D4). A Semgrep run
// that is skipped or failed, including one that could not load a rule, keeps
// them, and so does a run whose JS/TS taint gate is closed.
//
// evid is the Python engine's output only. A Semgrep finding's ID also starts
// with SEC-JS_ (js-cmdi-taint reports as SEC-JS_CMDI_TAINT), but its RuleID is
// the bundled rule's own, and Semgrep findings are never passed here.
func dropFallbackJSPatterns(evid []evidence.Evidence, status scannerStatusList) []evidence.Evidence {
	if !status.semgrepRunSucceeded() || !jsSemgrepPackBlocks() {
		return evid
	}
	kept := evid[:0:0]
	for _, e := range evid {
		id := e.RuleID
		if id == "" {
			id = e.ID
		}
		if strings.HasPrefix(id, jsFallbackPrefix) {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}
