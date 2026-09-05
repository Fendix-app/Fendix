package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"path/filepath"
	"sort"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"
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

// classifyErr maps an analyzer error to a fail reason. Task 7 extends it
// with transport typing; here only the two deterministic cases exist:
// a context deadline or the semgrep timeout sentinel is a timeout, and
// everything else is an execution error.
func classifyErr(err error) reporters.ScannerReason {
	if err == nil {
		return reporters.ReasonExecutionError
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, semgrep.ErrTimeout) {
		return reporters.ReasonTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return reporters.ReasonTimeout
	}
	return reporters.ReasonExecutionError
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
