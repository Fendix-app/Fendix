package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// Decision D1 (coverage outcome, R-004/R-007): a Semgrep run that did not
// evaluate every selected rule on every in-scope file is recorded semgrep
// failed, reason timeout for any timeout class and execution_error for
// everything else, with a detail that says what was lost. The findings the run
// did produce are kept. A file that only partially parses stays ok, with its
// count in the detail.
//
// These tests replay real Semgrep 1.182.1 output, recorded with the engine's
// own flags plus --time (semgrep/testdata/runs, see loss_test.go there), through
// semgrep.ScanRun and recordSemgrepRun, so the whole path from Semgrep's JSON to
// the scanner-status entry is under test.

// recordedRoot is the tree installRecordedSemgrep built for the stand-in.
var recordedRoot string

// semgrepRunsDir is the semgrep package's recorded runs.
func semgrepRunsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "scanner", "semgrep", "testdata", "runs")
}

// installRecordedSemgrep puts a stand-in semgrep on semgrep.LookPath that
// answers --version with version and every scan with the recorded stdout of
// fixture. A flag in reject is refused the way an old Semgrep refuses it.
func installRecordedSemgrep(t *testing.T, version, fixture string, reject ...string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo " + version + "; exit 0; fi\n" +
		"for a in \"$@\"; do\n  case \"$a\" in\n"
	for _, flag := range reject {
		script += "    " + flag + ") echo \"Error: No such option '" + flag + "'.\" 1>&2; exit 2;;\n"
	}
	// The recorded run was made on a tree under /fx/<name> or /t/<name>; the
	// stand-in answers with the same document rooted at this test's own tree,
	// which holds each file the run scanned (six lines each), so the engine can
	// read them the way it does a real tree (partial parses are judged by the
	// file's length).
	root := t.TempDir()
	recordedRoot = root
	raw, err := os.ReadFile(filepath.Join(semgrepRunsDir(t), fixture))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths struct {
			Scanned []string `json:"scanned"`
		} `json:"paths"`
	}
	_ = json.Unmarshal(raw, &doc)
	prefix := regexp.MustCompile(`^/(fx|t)/[^/]+`)
	for _, p := range doc.Paths.Scanned {
		rel := prefix.ReplaceAllString(p, "")
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(strings.Repeat("x = 1\n", 6)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rooted := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(rooted, []byte(regexp.MustCompile(`"/(fx|t)/[^/"]+`).ReplaceAllString(string(raw), `"`+root)), 0o644); err != nil {
		t.Fatal(err)
	}
	script += "  esac\ndone\ncat '" + rooted + "'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := semgrep.LookPath
	semgrep.LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return orig(name)
	}
	t.Cleanup(func() { semgrep.LookPath = orig })
}

// recordRecorded runs ScanRun against the stand-in and records the result the
// way the orchestrator does for a run that returned no error.
func recordRecorded(t *testing.T) (scannerStatusList, []evidence.Evidence, semgrep.Run) {
	t.Helper()
	run, err := semgrep.ScanRun(context.Background(), recordedRoot, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, run)
	if len(status) != 1 || status[0].Name != AnalyzerSemgrep {
		t.Fatalf("entries = %+v; want one semgrep entry", status)
	}
	return status, evid, run
}

func ruleIDs(evid []evidence.Evidence) []string {
	out := make([]string, 0, len(evid))
	for _, e := range evid {
		out = append(out, e.RuleID)
	}
	return out
}

func TestRecordedSemgrepRunThatLostEvaluationIsFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fixture  string
		reason   reporters.ScannerReason
		findings []string
		want     []string
	}{
		// java300 (a 2,719-line Spring controller) with --timeout 1: three
		// taint rules time out, Semgrep's --timeout-threshold of 3 is reached
		// and it runs no other rule on the file. No results at all.
		{"per-rule timeouts and the threshold", "threshold.json", reporters.ReasonTimeout, nil, []string{
			"lost evaluation:", "3 rule timeouts on 1 file", "every other rule skipped on 1 file after 3 rule timeouts",
			"ItemController.java (java-open_redirect-taint, java-sqli-taint, java-ssti-taint)",
		}},
		// An Express router of 1,000 inline handlers with an SSRF at the end:
		// the taint fixpoint of the one top-level function runs out of time,
		// Semgrep writes no `errors` entry and reports it only under --time.
		{"JS taint fixpoint timeout", "fixpoint-js.json", reporters.ReasonTimeout, nil, []string{
			"lost evaluation:", "1 taint fixpoint timeout on 1 file", "routes/api.js",
			"taint fixpoint at line 1, 2 taint rules from js-sqli-taint",
		}},
		// A gin main() with 400 inline closures and an SSRF at the end.
		{"Go taint fixpoint timeout", "fixpoint-go.json", reporters.ReasonTimeout, nil, []string{
			"lost evaluation:", "1 taint fixpoint timeout on 1 file", "main.go", "go-ssrf-taint",
		}},
		// The threshold case next to a small vulnerable route file and a file
		// that partially parses: the route file's finding is kept.
		{"loss next to findings", "timed-mixed.json", reporters.ReasonTimeout, []string{"js-ssrf-taint"}, []string{
			"3 rule timeouts on 1 file", "every other rule skipped on 1 file after 3 rule timeouts",
			// What does not fit the 240 bytes is counted, never cut (contract C2).
			"and 2 more (see report metadata)",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installRecordedSemgrep(t, "1.182.1", tc.fixture)
			status, evid, _ := recordRecorded(t)
			got := status[0]
			t.Logf("semgrep %s/%s: %s", got.State, got.Reason, got.Detail)
			if got.State != reporters.ScannerFailed || got.Reason != tc.reason {
				t.Fatalf("entry = %+v; want semgrep failed/%s: the run did not evaluate every rule on every file", got, tc.reason)
			}
			if !status.hasFailure() {
				t.Error("lost evaluation must count as a scanner failure (--fail-on-scanner-error)")
			}
			cov := reporters.BuildCoverage([]reporters.ScannerStatus(status), nil, false)
			if cov.ConfiguredComplete || !containsString(cov.Gaps, AnalyzerSemgrep) {
				t.Errorf("coverage = %+v; want semgrep a gap and configured_complete false", cov)
			}
			for _, w := range tc.want {
				if !strings.Contains(got.Detail, w) {
					t.Errorf("detail %q lacks %q", got.Detail, w)
				}
			}
			if ids := ruleIDs(evid); strings.Join(ids, ",") != strings.Join(tc.findings, ",") {
				t.Errorf("findings = %v; want %v kept", ids, tc.findings)
			}
		})
	}
}

// The complete lists behind a detail that did not fit are in the report's
// metadata: the partial parse that the detail above only counts is named there,
// with the lines Semgrep skipped.
func TestRecordedLossNextToAPartialParseNamesItInTheMetadata(t *testing.T) {
	installRecordedSemgrep(t, "1.182.1", "timed-mixed.json")
	_, _, run := recordRecorded(t)
	got := semgrepLimitations(run)
	want := "semgrep: partial parse, skipped lines: bad.py 2-3"
	found := false
	for _, e := range got {
		if e == want {
			found = true
		}
		if len(e) > 240 {
			t.Errorf("metadata entry is %d bytes: %q", len(e), e)
		}
	}
	if !found {
		t.Errorf("limitations %q lack %q", got, want)
	}
}

// A file that only partially parses loses no rule evaluation Semgrep can name:
// the run stays ok, with the count in the detail (D1), and a clean --time run
// is a plain ok.
func TestRecordedSemgrepRunWithoutLostEvaluationIsOk(t *testing.T) {
	installRecordedSemgrep(t, "1.182.1", "timed-syntax.json")
	status, evid, _ := recordRecorded(t)
	if got := status[0]; got.State != reporters.ScannerOK || !strings.Contains(got.Detail, "PartialParsing 1") {
		t.Errorf("entry = %+v; want ok with the PartialParsing count", got)
	}
	if ids := ruleIDs(evid); len(ids) != 1 || ids[0] != "js-ssrf-taint" {
		t.Errorf("findings = %v; want the js-ssrf-taint match", ids)
	}

	installRecordedSemgrep(t, "1.182.1", "timed-clean.json")
	status, _, _ = recordRecorded(t)
	if got := status[0]; got != (reporters.ScannerStatus{Name: AnalyzerSemgrep, State: reporters.ScannerOK}) {
		t.Errorf("entry = %+v; want a plain ok", got)
	}
}

// An old host Semgrep that does not know --project-root matches the packs'
// path filters against its own project root, the enclosing git work tree's
// root, so a scan under <gitroot>/fixtures/ can skip every file without an
// error. Going without it changes what is scanned: the run is failed
// (execution_error), not ok with a note.
func TestSemgrepRunWithoutProjectRootIsFailed(t *testing.T) {
	installRecordedSemgrep(t, "1.100.0", "timed-clean.json", "--project-root")
	status, evid, _ := recordRecorded(t)
	got := status[0]
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Fatalf("entry = %+v; want semgrep failed/execution_error", got)
	}
	for _, w := range []string{"semgrep 1.100.0: dropped --project-root (needs 1.111.0)", "files may be skipped"} {
		if !strings.Contains(got.Detail, w) {
			t.Errorf("detail %q lacks %q", got.Detail, w)
		}
	}
	if len(evid) != 1 {
		t.Errorf("findings = %v; want the run's one finding kept", ruleIDs(evid))
	}
}

// A --time document without time.fixpoint_timeouts cannot show that taint
// analysis finished; that is not a complete run (R-004).
func TestSemgrepRunThatCannotReportFixpointTimeoutsIsFailed(t *testing.T) {
	installRecordedSemgrep(t, "1.182.1", "timed-no-fixpoint-list.json")
	status, _, _ := recordRecorded(t)
	got := status[0]
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Fatalf("entry = %+v; want semgrep failed/execution_error", got)
	}
	if !strings.Contains(got.Detail, "taint fixpoint timeouts") {
		t.Errorf("detail %q does not say fixpoint timeouts could not be read", got.Detail)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
