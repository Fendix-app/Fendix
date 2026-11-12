package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 for the semgrep entry: an in-scope file the run left unread
// (over the size cap, unreadable, or absent from Semgrep's paths.scanned) is
// lost evaluation, failed/execution_error naming the files, with the findings
// kept; a file declared out of scope (generated, a vendored or build
// directory, a pack test/fixture path) is listed in the ok detail.

func recordOne(t *testing.T, run semgrep.Run) (reporters.ScannerStatus, []evidence.Evidence) {
	t.Helper()
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, run)
	if len(status) != 1 {
		t.Fatalf("entries = %+v; want one", status)
	}
	return status[0], evid
}

func TestSemgrepInScopeFilesLeftUnreadAreAGap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mark  func(*scope.Coverage)
		wants []string
	}{
		{"too large", func(c *scope.Coverage) { c.TooLarge("src/app.js") }, []string{"over 1048576 bytes", "src/app.js"}},
		{"unreadable", func(c *scope.Coverage) { c.Unreadable("keys.py") }, []string{"unreadable", "keys.py"}},
		{"not in paths.scanned", func(c *scope.Coverage) { c.NotScanned("lib/ignored.js") }, []string{"not evaluated by semgrep", "lib/ignored.js"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := semgrep.Run{Findings: []evidence.Evidence{{ID: "SEC-X", RuleID: "js-sqli-taint", Endpoint: "app.js:9"}}}
			tc.mark(&run.Coverage)
			got, evid := recordOne(t, run)
			t.Logf("-> %s/%s: %s", got.State, got.Reason, got.Detail)
			if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
				t.Fatalf("entry = %+v; want failed/execution_error", got)
			}
			for _, w := range append(tc.wants, "lost evaluation: 1 in-scope file not read") {
				if !strings.Contains(got.Detail, w) {
					t.Errorf("detail %q lacks %q", got.Detail, w)
				}
			}
			if len(evid) != 1 {
				t.Errorf("findings = %+v; the rest of the run's findings are kept", evid)
			}
			cov := reporters.BuildCoverage([]reporters.ScannerStatus{got}, nil, false)
			if cov.ConfiguredComplete || !containsString(cov.Gaps, AnalyzerSemgrep) {
				t.Errorf("coverage %+v; want semgrep a gap", cov)
			}
		})
	}
}

// A size skip among rule timeouts keeps the reason execution_error: it is not
// a timeout class.
func TestSemgrepSizeSkipWithTimeoutsIsAnExecutionError(t *testing.T) {
	run := semgrep.Run{Timeouts: []semgrep.RuleTimeout{{RuleID: "a", Path: "A.java"}}}
	run.Coverage.TooLarge("big.js")
	got, _ := recordOne(t, run)
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Fatalf("entry = %+v; want failed/execution_error", got)
	}
	if !strings.Contains(got.Detail, "big.js") {
		t.Errorf("detail %q does not name big.js", got.Detail)
	}
}

func TestSemgrepDeclaredScopeIsListedInTheOkDetail(t *testing.T) {
	var run semgrep.Run
	run.Coverage.Exclude(scope.ReasonMinified, "public/app.min.js")
	run.Coverage.TestPath("tests/app.js")
	run.Coverage.Exclude(scope.ReasonNPMInstall, "node_modules/")
	got, _ := recordOne(t, run)
	const want = "declared out of scope, not scanned: minified 1 (public/app.min.js), test/fixture path 1 (tests/app.js), installed npm packages 1 (node_modules/)"
	if got.State != reporters.ScannerOK || got.Detail != want {
		t.Fatalf("entry = %+v; want ok with detail %q", got, want)
	}
}

// The ok detail is read by the backend and the frontend (decision D2): one cut
// by truncateDetail ends in "…" and reads as lost evaluation. However many
// files are declared, the detail stays within 240 bytes, keeps the parse
// summary whole, and never ends in "…" (contract C2).
func TestSemgrepOkDetailWithDeclaredScopeIsNeverCut(t *testing.T) {
	run := semgrep.Run{Report: semgrep.Report{Incomplete: map[string]int{"PartialParsing": 2}}}
	long := strings.Repeat("very/deeply/nested/directory/", 6)
	for i := 0; i < 40; i++ {
		run.Coverage.Exclude(scope.ReasonMinified, long+"bundle.min.js")
		run.Coverage.TestPath(long + "tests/a.test.js")
		run.Coverage.Exclude(scope.ReasonNPMInstall, long+"node_modules/")
	}
	got, _ := recordOne(t, run)
	t.Logf("detail (%d bytes): %s", len(got.Detail), got.Detail)
	if got.State != reporters.ScannerOK {
		t.Fatalf("entry = %+v; want ok", got)
	}
	if len(got.Detail) > 240 || strings.HasSuffix(got.Detail, "…") {
		t.Errorf("detail is %d bytes / cut: %q", len(got.Detail), got.Detail)
	}
	const summary = "2 non-fatal per-file problem(s) reported by semgrep (PartialParsing 2); findings in those files may be incomplete"
	if !strings.HasPrefix(got.Detail, summary) {
		t.Errorf("detail %q lost the parse summary", got.Detail)
	}
	if !strings.Contains(got.Detail, "minified 40") {
		t.Errorf("detail %q lost the declared counts", got.Detail)
	}
}

// qa-engine-01 / qa2-03, the last shapes: an `errors` entry that is not an
// object, and an `errors` that is not a list, cannot be shown to have cost
// nothing. Through ScanRun and recordSemgrepRun, the run is failed.
func TestUndecodableSemgrepErrorEntriesFailTheRun(t *testing.T) {
	for _, tc := range []struct{ name, errors string }{
		{"a string entry", `["a string entry"]`},
		{"a number entry beside a parse problem", `[7, {"code":3,"level":"warn","type":"Syntax error","path":"ROOT/a.js"}]`},
		{"an object instead of a list", `{"unexpected": "object"}`},
		{"a string instead of a list", `"oops"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"version":"1.182.1","results":[` + docFinding + `],"errors":` + tc.errors + `,"paths":{"scanned":[]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
			got := scanDocument(t, doc)
			t.Logf("-> %s/%s: %s", got.State, got.Reason, got.Detail)
			if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
				t.Fatalf("entry = %+v; want failed/execution_error", got)
			}
			if !strings.Contains(got.Detail, "could not be read (undecodable 1)") {
				t.Errorf("detail %q does not count the undecodable entry", got.Detail)
			}
		})
	}
	// An absent or null `errors` is no entries, not an undecodable one.
	for _, errs := range []string{`[]`, `null`} {
		doc := `{"version":"1.182.1","results":[],"errors":` + errs + `,"paths":{"scanned":[]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
		if got := scanDocument(t, doc); got.State != reporters.ScannerOK {
			t.Errorf("errors %s: entry = %+v; want ok", errs, got)
		}
	}
}
