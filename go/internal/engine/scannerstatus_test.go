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

// A Semgrep run in which a rule hit its per-rule timeout is recorded failed,
// reason timeout (decision D1, R-007). This test used to require ok with a
// detail, as v3.7.0 and commit 3c929ec record it (ruling R-pf90); that is
// changed on purpose: the rule's matches in that file are missing, and an ok
// entry gave the scan coverage complete and a PASS while Semgrep knew it had
// given up (R-007, reproduced on a 2,719-line Spring controller). The detail
// names the counts and the first rules and files, and the findings the run did
// produce are kept.
func TestSemgrepRunWithRuleTimeoutsIsFailedWithDetailAndKeepsFindings(t *testing.T) {
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
		report   semgrep.Report
		want     []string
		notWant  []string
	}{
		{"two", []semgrep.RuleTimeout{
			{RuleID: "js-sqli-taint", Path: "src/big.js"},
			{RuleID: "python-eval-injection", Path: "app/gen.py"},
		}, semgrep.Report{Incomplete: map[string]int{"Timeout": 2}},
			[]string{"lost evaluation: 2 rule timeouts on 2 files;", "first: src/big.js (js-sqli-taint); app/gen.py (python-eval-injection)"},
			[]string{"non-fatal per-file"}},
		{"one", []semgrep.RuleTimeout{{RuleID: "js-sqli-taint", Path: "src/big.js"}},
			semgrep.Report{Incomplete: map[string]int{"Timeout": 1}},
			[]string{"lost evaluation: 1 rule timeout on 1 file;", "first: src/big.js (js-sqli-taint)"}, nil},
		{"unnamed", []semgrep.RuleTimeout{{}}, semgrep.Report{},
			[]string{"1 rule timeout on 1 file", "unknown file (unknown rule)"}, nil},
		// The other per-file problems of the run are still counted, once: a
		// Timeout is already named above.
		{"with other per-file problems", []semgrep.RuleTimeout{{RuleID: "js-sqli-taint", Path: "src/big.js"}},
			semgrep.Report{Incomplete: map[string]int{"Timeout": 1, "PartialParsing": 2}},
			[]string{"1 rule timeout on 1 file", "src/big.js (js-sqli-taint)", "PartialParsing 2"},
			[]string{"Timeout 1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var status scannerStatusList
			var evid []evidence.Evidence
			recordSemgrepRun(&status, &evid, semgrep.Run{Findings: found, Timeouts: tc.timeouts, Report: tc.report})
			if len(status) != 1 {
				t.Fatalf("entries = %+v; want one", status)
			}
			got := status[0]
			if got.Name != AnalyzerSemgrep || got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonTimeout {
				t.Errorf("entry = %+v; want semgrep, failed, timeout", got)
			}
			if !status.hasFailure() {
				t.Error("a rule timeout must count as a scanner failure")
			}
			for _, want := range tc.want {
				if !strings.Contains(got.Detail, want) {
					t.Errorf("detail %q lacks %q", got.Detail, want)
				}
			}
			for _, unwanted := range tc.notWant {
				if strings.Contains(got.Detail, unwanted) {
					t.Errorf("detail %q has %q", got.Detail, unwanted)
				}
			}
			if !reflect.DeepEqual(evid, found) {
				t.Errorf("findings = %+v; want the run's findings kept", evid)
			}
		})
	}
}

// Options dropped for an older host Semgrep whose absence does not change what
// is scanned or matched (semgrep.optionalArgs classifies each) are named in
// the detail of the run, which stays ok. This test used to use the
// --project-root note, which stayed ok too; going without --project-root
// changes which files the packs' path filters exclude, so it is now the failed
// case below (decision D1).
func TestSemgrepRunThatDroppedOptionsStaysOkAndNamesThem(t *testing.T) {
	const note = "semgrep 0.100.0: dropped --dataflow-traces (needs 0.107.0)"
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{Report: semgrep.Report{Dropped: note}})
	if len(status) != 1 {
		t.Fatalf("entries = %+v; want one", status)
	}
	got := status[0]
	if got.Name != AnalyzerSemgrep || got.State != reporters.ScannerOK || got.Reason != "" {
		t.Errorf("entry = %+v; want semgrep, ok, no reason", got)
	}
	if got.Detail != note {
		t.Errorf("detail = %q; want %q", got.Detail, note)
	}
	if status.hasFailure() {
		t.Error("dropped options alone must not count as a scanner failure")
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

// An option dropped for an older host Semgrep whose absence changes what is
// scanned (--project-root) makes the run failed, execution_error (D1).
func TestSemgrepRunThatDroppedADetectionOptionIsFailed(t *testing.T) {
	const note = "semgrep 1.45.0: dropped --project-root (needs 1.111.0)"
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{Report: semgrep.Report{Dropped: note, DroppedDetection: note}})
	if len(status) != 1 {
		t.Fatalf("entries = %+v; want one", status)
	}
	got := status[0]
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Errorf("entry = %+v; want semgrep, failed, execution_error", got)
	}
	if !strings.HasPrefix(got.Detail, note+"; files may be skipped") {
		t.Errorf("detail = %q; want it to start with %q", got.Detail, note)
	}
}

// Each loss class gets its reason: timeouts alone are timeout, anything else
// (or a mix) is execution_error.
func TestSemgrepLostEvaluationReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		run    semgrep.Run
		reason reporters.ScannerReason
		want   []string
	}{
		{"fixpoint", semgrep.Run{FixpointTimeouts: []semgrep.FixpointTimeout{{Path: "routes/api.js", Line: 1, Rules: 2, FirstRule: "js-sqli-taint"}}},
			reporters.ReasonTimeout, []string{"lost evaluation: 1 taint fixpoint timeout on 1 file; first: routes/api.js (taint fixpoint at line 1, 2 taint rules from js-sqli-taint)"}},
		{"threshold", semgrep.Run{
			Timeouts:       []semgrep.RuleTimeout{{RuleID: "a", Path: "Big.java"}, {RuleID: "b", Path: "Big.java"}, {RuleID: "c", Path: "Big.java"}},
			ThresholdFiles: []string{"Big.java"},
		}, reporters.ReasonTimeout, []string{"lost evaluation: 3 rule timeouts on 1 file, every other rule skipped on 1 file after 3 rule timeouts; first: Big.java (a, b, c)"}},
		{"interfile timeout", semgrep.Run{FileErrors: []semgrep.FileError{{Type: "Timeout during interfile analysis", Path: "a.java"}}},
			reporters.ReasonTimeout, []string{"1 per-file error (Timeout during interfile analysis 1)"}},
		{"out of memory", semgrep.Run{FileErrors: []semgrep.FileError{{Type: "Out of memory", Path: "gen.js"}}},
			reporters.ReasonExecutionError, []string{"lost evaluation: 1 per-file error (Out of memory 1); first: gen.js (Out of memory)"}},
		{"too many matches", semgrep.Run{FileErrors: []semgrep.FileError{{Type: "Too many matches", RuleID: "r", Path: "x.py"}}},
			reporters.ReasonExecutionError, []string{"x.py (Too many matches running r)"}},
		{"mixed", semgrep.Run{
			Timeouts:   []semgrep.RuleTimeout{{RuleID: "a", Path: "Big.java"}},
			FileErrors: []semgrep.FileError{{Type: "Stack overflow", Path: "deep.js"}},
		}, reporters.ReasonExecutionError, []string{"1 rule timeout on 1 file", "Stack overflow 1"}},
		{"skipped rules", semgrep.Run{SkippedRules: []string{"java-xss-taint"}},
			reporters.ReasonExecutionError, []string{"1 rule skipped by semgrep", "skipped rules (java-xss-taint)"}},
		{"fixpoint unreported", semgrep.Run{FixpointUnreported: true},
			reporters.ReasonExecutionError, []string{"semgrep reported no taint fixpoint timeouts list (--time)"}},
		{"timeout and fixpoint unreported", semgrep.Run{Timeouts: []semgrep.RuleTimeout{{RuleID: "a", Path: "b"}}, FixpointUnreported: true},
			reporters.ReasonExecutionError, []string{"1 rule timeout on 1 file", "no taint fixpoint timeouts list"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found := []evidence.Evidence{{RuleID: "kept"}}
			tc.run.Findings = found
			var status scannerStatusList
			var evid []evidence.Evidence
			recordSemgrepRun(&status, &evid, tc.run)
			got := status[0]
			if got.State != reporters.ScannerFailed || got.Reason != tc.reason {
				t.Errorf("entry = %+v; want failed/%s", got, tc.reason)
			}
			for _, w := range tc.want {
				if !strings.Contains(got.Detail, w) {
					t.Errorf("detail %q lacks %q", got.Detail, w)
				}
			}
			if !reflect.DeepEqual(evid, found) {
				t.Errorf("findings = %+v; want kept", evid)
			}
		})
	}
}

// A file that only partially parses, with few skipped lines reported, loses no
// evaluation Semgrep cannot name: ok with its count and the skipped lines.
// A whole-file parse failure (Syntax error) is lost evaluation (D1'): even
// beside partial parses the run is failed.
func TestSemgrepRunWithOnlyParseProblemsStaysOk(t *testing.T) {
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{
		Report:        semgrep.Report{Incomplete: map[string]int{"PartialParsing": 2}},
		PartialParses: []semgrep.PartialParse{{Path: "a.py", Spans: []semgrep.Span{{StartLine: 4, EndLine: 4}}, Reported: true, Skipped: 1, Total: 40}, {Path: "b.js", Spans: []semgrep.Span{{StartLine: 10, EndLine: 11}}, Reported: true, Skipped: 2, Total: 80}},
	})
	got := status[0]
	if got.State != reporters.ScannerOK || !strings.Contains(got.Detail, "PartialParsing 2") || strings.Contains(got.Detail, "lost evaluation") {
		t.Errorf("entry = %+v; want ok with the parse counts", got)
	}
	// The detail says what was skipped, in a segment a classifier can read.
	if !strings.Contains(got.Detail, "partial parse, 2 files with skipped lines: a.py 4, b.js 10-11") {
		t.Errorf("detail %q does not name the skipped lines", got.Detail)
	}

	status = nil
	recordSemgrepRun(&status, &evid, semgrep.Run{Report: semgrep.Report{Incomplete: map[string]int{"PartialParsing": 2, "Syntax error": 1}}})
	if got := status[0]; got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Errorf("entry = %+v; want failed/execution_error: a Syntax error is lost evaluation", got)
	}
}
