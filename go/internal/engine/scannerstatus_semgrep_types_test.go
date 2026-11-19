package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// installSemgrepDocument puts a stand-in semgrep on semgrep.LookPath that
// answers --version with 1.182.1 and every scan with doc, in which ROOT is
// replaced by the scan root the test passes.
func installSemgrepDocument(t *testing.T, root, doc string) {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(out, []byte(strings.ReplaceAll(doc, "ROOT", root)), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "semgrep")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.182.1; exit 0; fi\ncat '" + out + "'\n"
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

// scanDocument runs ScanRun on a fresh root against doc and records it the way
// the orchestrator records a run that returned no error.
func scanDocument(t *testing.T, doc string) reporters.ScannerStatus {
	t.Helper()
	root := t.TempDir()
	installSemgrepDocument(t, root, doc)
	run, err := semgrep.ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, run)
	if len(status) != 1 {
		t.Fatalf("entries = %+v; want one", status)
	}
	return status[0]
}

const docFinding = `{"check_id":"tmp.fendix-semgrep-rules-1.js-ssrf-taint","path":"ROOT/routes.js","start":{"line":3,"col":1},"end":{"line":3,"col":9},"extra":{"message":"m","severity":"ERROR","lines":"requires login","metadata":{}}}`

func lossDocument(entry string) string {
	return `{"version":"1.182.1","results":[` + docFinding + `],"errors":[` + entry + `],"paths":{"scanned":[]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
}

// qa-engine-02: each per-file error type Semgrep can write, one entry in an
// otherwise clean run, through ScanRun and recordSemgrepRun. A type that loses
// evaluation makes the run failed (timeout for the timeout classes,
// execution_error for the others and for a type this engine does not know,
// and, since decision D1', for a whole-file parse failure). The finding is kept
// either way. The one type that can leave a run ok is PartialParsing, and only
// with few skipped lines (partial_parse_test.go).
func TestEachSemgrepErrorTypeRecordsItsOutcome(t *testing.T) {
	for _, tc := range []struct {
		typ    string
		state  reporters.ScannerStatusState
		reason reporters.ScannerReason
	}{
		{"Timeout", reporters.ScannerFailed, reporters.ReasonTimeout},
		{"Fixpoint timeout", reporters.ScannerFailed, reporters.ReasonTimeout},
		{"Timeout during interfile analysis", reporters.ScannerFailed, reporters.ReasonTimeout},
		{"TimeoutDuringInterfile", reporters.ScannerFailed, reporters.ReasonTimeout},
		{"Out of memory", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Stack overflow", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"OOM during interfile analysis", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"OutOfMemoryDuringInterfile", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Internal matching error", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Too many matches", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Missing plugin", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"SemgrepWarning", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Some error a later Semgrep adds", reporters.ScannerFailed, reporters.ReasonExecutionError},
		// D1' (round 4): a whole-file parse failure ran no rule on the file.
		{"Syntax error", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Lexical error", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"Other syntax error", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"AST builder error", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"ParseError", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"LexicalError", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"OtherParseError", reporters.ScannerFailed, reporters.ReasonExecutionError},
		{"AstBuilderError", reporters.ScannerFailed, reporters.ReasonExecutionError},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			typ, _ := json.Marshal(tc.typ)
			entry := fmt.Sprintf(`{"code":2,"level":"warn","type":%s,"rule_id":"tmp.fendix-semgrep-rules-1.js-sqli-taint","message":"m","path":"ROOT/big.js"}`, typ)
			got := scanDocument(t, lossDocument(entry))
			t.Logf("%s -> %s/%s: %s", tc.typ, got.State, got.Reason, got.Detail)
			if got.State != tc.state || got.Reason != tc.reason {
				t.Fatalf("entry = %+v; want %s/%s", got, tc.state, tc.reason)
			}
			if tc.state == reporters.ScannerFailed {
				if !strings.Contains(got.Detail, "lost evaluation") || !strings.Contains(got.Detail, "big.js") {
					t.Errorf("detail %q does not say evaluation was lost on big.js", got.Detail)
				}
			} else if !strings.Contains(got.Detail, tc.typ+" 1") || strings.Contains(got.Detail, "lost evaluation") {
				t.Errorf("detail %q; want the %s count and no lost evaluation", got.Detail, tc.typ)
			}
		})
	}
}

// qa-engine-01: a lost-evaluation entry whose fields are not of the expected
// types (a rule_id that is not a string, a message that is a list) must not
// make the run read a plain ok. Real Semgrep writes strings; this is the
// fail-closed guard against a shape this decoder has not seen.
func TestASemgrepLossEntryOfAnOddShapeIsNeverAPlainOk(t *testing.T) {
	for _, tc := range []struct {
		name   string
		entry  string
		reason reporters.ScannerReason
	}{
		{"timeout, rule_id an object", `{"code":2,"level":"warn","type":"Timeout","rule_id":{"id":"tmp.x.java-sqli-taint"},"message":"Timeout when running java-sqli-taint on ROOT/App.java:","path":"ROOT/App.java"}`, reporters.ReasonTimeout},
		{"out of memory, rule_id a number", `{"code":2,"level":"warn","type":"Out of memory","rule_id":7,"message":"oom","path":"ROOT/App.java"}`, reporters.ReasonExecutionError},
		{"stack overflow, path a number", `{"code":2,"level":"warn","type":"Stack overflow","path":7,"message":["x"]}`, reporters.ReasonExecutionError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scanDocument(t, lossDocument(tc.entry))
			t.Logf("-> %s/%s: %s", got.State, got.Reason, got.Detail)
			if got.State != reporters.ScannerFailed || got.Reason != tc.reason {
				t.Fatalf("entry = %+v; want failed/%s: Semgrep reported lost evaluation", got, tc.reason)
			}
			if !strings.Contains(got.Detail, "lost evaluation") {
				t.Errorf("detail %q does not say evaluation was lost", got.Detail)
			}
		})
	}
}

// The last guard of qa-engine-01: Semgrep counted a loss-type entry (the
// Report) that the decoders did not turn into a named loss. The run is failed,
// and the detail says entries could not be read.
func TestSemgrepLossEntriesThatCouldNotBeReadFailTheRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		run    semgrep.Run
		reason reporters.ScannerReason
		want   string
	}{
		{"out of memory", semgrep.Run{Report: semgrep.Report{Incomplete: map[string]int{"Out of memory": 1}}},
			reporters.ReasonExecutionError, "1 lost-evaluation entry semgrep reported could not be read (Out of memory 1)"},
		{"a timeout more than decoded", semgrep.Run{
			Timeouts: []semgrep.RuleTimeout{{RuleID: "a", Path: "A.java"}},
			Report:   semgrep.Report{Incomplete: map[string]int{"Timeout": 3}},
		}, reporters.ReasonTimeout, "2 lost-evaluation entries semgrep reported could not be read (Timeout 2)"},
		{"unknown type", semgrep.Run{Report: semgrep.Report{Incomplete: map[string]int{"unknown": 1, "PartialParsing": 1}}},
			reporters.ReasonExecutionError, "could not be read (unknown 1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var status scannerStatusList
			var evid []evidence.Evidence
			recordSemgrepRun(&status, &evid, tc.run)
			got := status[0]
			if got.State != reporters.ScannerFailed || got.Reason != tc.reason {
				t.Fatalf("entry = %+v; want failed/%s", got, tc.reason)
			}
			if !strings.Contains(got.Detail, tc.want) {
				t.Errorf("detail %q lacks %q", got.Detail, tc.want)
			}
		})
	}
	// Decoded entries that match the count are not counted twice.
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{
		FileErrors: []semgrep.FileError{{Type: "Out of memory", Path: "gen.js"}},
		Report:     semgrep.Report{Incomplete: map[string]int{"Out of memory": 1}},
	})
	if strings.Contains(status[0].Detail, "could not be read") {
		t.Errorf("detail %q; every entry was read", status[0].Detail)
	}
}

// A Semgrep older than 1.96.0 cannot be told to leave the scanned tree's
// .semgrepignore files and its own default ignore list alone; the run is a
// gap (redteam-semgrep-02, redteam2-semgrep-02), with the reason in the
// detail.
func TestSemgrepRunThatHonouredTheTreesSemgrepignoreIsFailed(t *testing.T) {
	const note = "semgrep 1.95.0: dropped --x-ignore-semgrepignore-files (needs 1.96.0)"
	const why = "files may be skipped: Semgrep's default ignore list and the tree's .semgrepignore files apply"
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, semgrep.Run{Report: semgrep.Report{Dropped: note, DroppedDetection: note, DroppedWhy: why}})
	got := status[0]
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError {
		t.Fatalf("entry = %+v; want failed/execution_error", got)
	}
	if !strings.HasPrefix(got.Detail, note+"; "+why) {
		t.Errorf("detail = %q; want it to start with %q", got.Detail, note+"; "+why)
	}
}

// Contract note for the Python engine: a child status line that arrives
// failed is recorded failed with its reason, and so is a gap in coverage; an
// invalid state/reason pair is failed/malformed_output, never ok.
func TestPythonEngineChildThatArrivesFailedIsAGap(t *testing.T) {
	for _, c := range []struct{ state, reason string }{
		{"failed", "timeout"}, {"failed", "execution_error"}, {"ok", "timeout"}, {"failed", ""},
	} {
		var status scannerStatusList
		recordPythonEngine(&status, SpawnResult{Outcome: SpawnOK, Checks: []CheckStatus{{Check: "injection", State: c.state, Reason: c.reason, Detail: "d"}}})
		var child reporters.ScannerStatus
		for _, s := range status {
			if s.Name == AnalyzerPythonInjection {
				child = s
			}
		}
		if child.State != reporters.ScannerFailed {
			t.Errorf("child %s/%s recorded %+v; want failed", c.state, c.reason, child)
		}
		cov := reporters.BuildCoverage([]reporters.ScannerStatus(status), nil, false)
		if cov.ConfiguredComplete || !containsString(cov.Gaps, AnalyzerPythonInjection) {
			t.Errorf("child %s/%s: coverage %+v; want %s a gap", c.state, c.reason, cov, AnalyzerPythonInjection)
		}
	}
}
