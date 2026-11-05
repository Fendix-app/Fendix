package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/neterr"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/npm"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

func TestScannerStatusList_OkSkipFail(t *testing.T) {
	var l scannerStatusList
	l.ok("secrets")
	l.skip("govulncheck", reporters.ReasonNotApplicable, "offline mode")
	l.fail("pip", reporters.ReasonExecutionError, errors.New("osv.dev returned 503"))

	if len(l) != 3 {
		t.Fatalf("got %d statuses; want 3", len(l))
	}
	if l[0].State != reporters.ScannerOK || l[1].State != reporters.ScannerSkipped || l[2].State != reporters.ScannerFailed {
		t.Errorf("unexpected states: %+v", l)
	}
	if l[2].Detail != "osv.dev returned 503" {
		t.Errorf("fail detail = %q", l[2].Detail)
	}
}

func TestScannerStatusList_HasFailure(t *testing.T) {
	var clean scannerStatusList
	clean.ok("secrets")
	clean.skip("govulncheck", reporters.ReasonNotApplicable, "offline")
	if clean.hasFailure() {
		t.Error("hasFailure should be false when only ok/skip recorded")
	}

	var dirty scannerStatusList
	dirty.ok("secrets")
	dirty.fail("pip", reporters.ReasonExecutionError, errors.New("boom"))
	dirty.fail("npm", reporters.ReasonExecutionError, errors.New("kaboom"))
	if !dirty.hasFailure() {
		t.Error("hasFailure should be true when a scanner failed")
	}
	names := dirty.failedNames()
	if len(names) != 2 || names[0] != "pip" || names[1] != "npm" {
		t.Errorf("failedNames = %v; want [pip npm]", names)
	}
}

func TestTruncateErr_Bounded(t *testing.T) {
	if got := truncateErr(nil); got != "" {
		t.Errorf("truncateErr(nil) = %q; want empty", got)
	}
	long := make([]byte, 500)
	for i := range long {
		long[i] = 'x'
	}
	got := truncateErr(errors.New(string(long)))
	if len([]rune(got)) > 241 { // 240 chars + ellipsis rune
		t.Errorf("truncateErr did not bound length: %d", len([]rune(got)))
	}
}

// TestRecordDepScanResult_RecordsOkAndFail covers the shared pip-style
// recorder: success appends findings + records ok; error records fail.
func TestRecordDepScanResult_RecordsOkAndFail(t *testing.T) {
	o := &Orchestrator{cfg: &models.ScanConfig{}}

	var status scannerStatusList
	var findings []evidence.Evidence
	scanFindings := []evidence.Evidence{{ID: "X", Category: "deps"}}
	o.recordDepScanResult(&status, "pip", "native pypi deps scan", &findings, scanFindings, nil)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding appended, got %d", len(findings))
	}
	if len(status) != 1 || status[0].State != reporters.ScannerOK || status[0].Name != "pip" {
		t.Errorf("expected pip ok status, got %+v", status)
	}

	var status2 scannerStatusList
	var findings2 []evidence.Evidence
	o.recordDepScanResult(&status2, "pip", "native pypi deps scan", &findings2, nil, errors.New("network down"))
	if len(status2) != 1 || status2[0].State != reporters.ScannerFailed {
		t.Errorf("expected pip failed status, got %+v", status2)
	}
}

// TestRecordNpmScanResult_LockfileMissingIsSkip verifies the npm
// lockfile-missing sentinel records a SKIP (plus the advisory finding),
// not a failure.
func TestRecordNpmScanResult_LockfileMissingIsSkip(t *testing.T) {
	o := &Orchestrator{cfg: &models.ScanConfig{CodePath: "/tmp/x"}}
	var status scannerStatusList
	var findings []evidence.Evidence
	findings = o.recordNpmScanResult(&status, &findings, nil, npm.ErrLockfileMissingButPackageJsonPresent)
	if len(status) != 1 || status[0].State != reporters.ScannerSkipped || status[0].Reason != reporters.ReasonUnsupportedTarget {
		t.Errorf("expected npm skipped with unsupported_target reason, got %+v", status)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-NPM_LOCKFILE_MISSING" {
		t.Errorf("expected advisory finding, got %+v", findings)
	}
	if status.hasFailure() {
		t.Error("lockfile-missing must not count as a failure")
	}
}

func TestScannerStatusList_ReasonedRecording(t *testing.T) {
	var l scannerStatusList
	l.ok("secrets")
	l.skip("semgrep", reporters.ReasonDependencyMissing, "semgrep binary not installed")
	l.fail("pip", reporters.ReasonNetworkError, errors.New("post batch to https://api.osv.dev: connection reset"))
	l.failDetail("dast", reporters.ReasonNoEndpoints, "URL configured, discovery found zero endpoints")
	l.markAttempts("pip", 2)

	if got := l[1]; got.State != reporters.ScannerSkipped || got.Reason != reporters.ReasonDependencyMissing || got.Detail == "" {
		t.Fatalf("skip recorded wrong: %+v", got)
	}
	if got := l[2]; got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonNetworkError || got.Attempts != 2 {
		t.Fatalf("fail/attempts recorded wrong: %+v", got)
	}
	if !l.has("dast") || l.has("npm") {
		t.Fatal("has() must reflect recorded names")
	}
	if !l.hasFailure() {
		t.Fatal("a failed entry must still count as a failure for --fail-on-scanner-error")
	}
}

func TestScannerStatusList_SortedIsRegistryOrder(t *testing.T) {
	var l scannerStatusList
	l.ok("npm")
	l.ok("python-engine/deps")
	l.ok("dast")
	l.ok("python-engine")
	l.ok("secrets")
	l.ok("custom-plugin-thing") // not in the registry: stable, last
	got := l.sorted()
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	want := []string{"dast", "secrets", "npm", "python-engine", "python-engine/deps", "custom-plugin-thing"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("sorted names = %v, want %v", names, want)
	}
}

func TestClassifyErr_MinimalMapping(t *testing.T) {
	if got := classifyErr(context.DeadlineExceeded); got != reporters.ReasonTimeout {
		t.Errorf("deadline → %s, want timeout", got)
	}
	if got := classifyErr(errors.New("boom")); got != reporters.ReasonExecutionError {
		t.Errorf("plain error → %s, want execution_error", got)
	}
	if got := classifyErr(fmt.Errorf("wrap: %w", semgrep.ErrTimeout)); got != reporters.ReasonTimeout {
		t.Errorf("semgrep.ErrTimeout → %s, want timeout", got)
	}
	if got := classifyErr(&neterr.LookupError{Scanner: "pip", Failed: 1, Total: 1, Cause: &neterr.StatusError{Host: "h", Code: 503}}); got != reporters.ReasonNetworkError {
		t.Errorf("lookup 503 → %s, want network_error", got)
	}
	if got := classifyErr(&neterr.StatusError{Host: "h", Code: 404}); got != reporters.ReasonExecutionError {
		t.Errorf("404 → %s, want execution_error (never transient)", got)
	}
}

// A Semgrep run in which a rule hit its per-rule timeout delivered only part
// of its findings (R-pf59): the analyzer is recorded failed with reason
// timeout, as a pass cut short by Fendix's own budget is, so
// --fail-on-scanner-error and the coverage gates see it, and the findings it
// did produce are kept, as a partial dependency lookup keeps its own.
func TestSemgrepRunWithRuleTimeoutsFailsAndKeepsFindings(t *testing.T) {
	found := []evidence.Evidence{{ID: "SEC-PYTHON_EVAL_INJECTION", RuleID: "python-eval-injection"}}

	var clean scannerStatusList
	var cleanEvid []evidence.Evidence
	recordSemgrepRun(&clean, &cleanEvid, semgrep.Run{Findings: found})
	if len(clean) != 1 || clean[0] != (reporters.ScannerStatus{Name: AnalyzerSemgrep, State: reporters.ScannerOK}) {
		t.Errorf("run without timeouts = %+v; want a plain ok", clean)
	}
	if !reflect.DeepEqual(cleanEvid, found) {
		t.Errorf("findings = %+v; want %+v", cleanEvid, found)
	}

	for _, tc := range []struct {
		name     string
		timeouts []semgrep.RuleTimeout
		want     []string
	}{
		{"two", []semgrep.RuleTimeout{
			{RuleID: "js-sqli-taint", Path: "src/big.js"},
			{RuleID: "python-eval-injection", Path: "app/gen.py"},
		}, []string{"2 rule timeouts,", "js-sqli-taint on src/big.js", "python-eval-injection on app/gen.py"}},
		{"one", []semgrep.RuleTimeout{{RuleID: "js-sqli-taint", Path: "src/big.js"}},
			[]string{"1 rule timeout,", "js-sqli-taint on src/big.js"}},
		{"unnamed", []semgrep.RuleTimeout{{}}, []string{"1 rule timeout,", "unknown rule on unknown file"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var status scannerStatusList
			var evid []evidence.Evidence
			recordSemgrepRun(&status, &evid, semgrep.Run{Findings: found, Timeouts: tc.timeouts})
			if len(status) != 1 {
				t.Fatalf("entries = %+v; want one", status)
			}
			got := status[0]
			if got.Name != AnalyzerSemgrep || got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonTimeout {
				t.Errorf("entry = %+v; want semgrep, failed, timeout", got)
			}
			if !status.hasFailure() {
				t.Error("a rule timeout must count as a scanner failure for --fail-on-scanner-error")
			}
			for _, want := range append(tc.want, "matches missing") {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q lacks %q", got.Detail, want)
				}
			}
			if !reflect.DeepEqual(evid, found) {
				t.Errorf("findings = %+v; want the run's findings kept", evid)
			}
		})
	}
}

// A Semgrep run that could not load a rule pack is recorded failed (reason
// execution_error), whatever else the run produced: it did not run the pack, so
// the checks that stand in for it (D4) must stay on, and --fail-on-scanner-error
// must see it.
func TestSemgrepRunWithRuleErrorsFailsAndKeepsFindings(t *testing.T) {
	found := []evidence.Evidence{{ID: "SEC-PYTHON_EVAL_INJECTION", RuleID: "python-eval-injection"}}
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{
		Findings: found,
		RuleErrors: []semgrep.RuleError{
			{Type: "InvalidRuleSchemaError", Message: "Invalid rule schema: no pattern"},
			{Type: "SemgrepError", Message: "invalid configuration file found"},
		},
	})
	if len(status) != 1 {
		t.Fatalf("entries = %+v; want one", status)
	}
	got := status[0]
	if got.Name != AnalyzerSemgrep || got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Errorf("entry = %+v; want semgrep, failed, execution_error", got)
	}
	for _, want := range []string{"2 rule errors", "InvalidRuleSchemaError", "invalid configuration file found"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail %q lacks %q", got.Detail, want)
		}
	}
	if !status.hasFailure() {
		t.Error("a rule error must count as a scanner failure")
	}
	if !reflect.DeepEqual(evid, found) {
		t.Errorf("findings = %+v; want the run's findings kept", evid)
	}
}
