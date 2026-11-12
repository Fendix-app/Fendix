package semgrep

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Decision D1 turns on the type of each per-file entry Semgrep puts in
// `errors`: whether that file lost rule evaluation, and whether the loss is a
// timeout. These tests pin the classification of every error type Semgrep
// 1.182.1 can write (semgrep_interfaces/semgrep_output_v1.py, error_type), and
// of a type this engine does not know, through the decoder production uses
// (parseRun), so removing a type from timeoutLossTypes or executionLossTypes,
// or moving one between them, fails here (qa-engine-02).

type lossClassWant int

const (
	wantNoLoss lossClassWant = iota
	wantTimeoutLoss
	wantExecutionLoss
	// wantParseFailure is a whole-file parse failure (D1'): lost evaluation of
	// the execution class, listed in Run.ParseFailures.
	wantParseFailure
)

// semgrepErrorTypes is each error type Semgrep 1.182.1 can write for a file at
// level "warn", with the class it must have. The kind names (StackOverflow,
// OutOfMemoryDuringInterfile, ...) are the ATD constructor names some Semgrep
// releases and this engine's own tables have used; they classify the same.
var semgrepErrorTypes = []struct {
	typ  string
	want lossClassWant
}{
	// A rule, every remaining rule, or a taint function lost its matches on
	// the file at a time budget: failed/timeout.
	{"Timeout", wantTimeoutLoss},
	{"Fixpoint timeout", wantTimeoutLoss},
	{"Timeout during interfile analysis", wantTimeoutLoss},
	{"TimeoutDuringInterfile", wantTimeoutLoss},
	// Evaluation lost for any other reason: failed/execution_error.
	{"Out of memory", wantExecutionLoss},
	{"OutOfMemory", wantExecutionLoss},
	{"Stack overflow", wantExecutionLoss},
	{"StackOverflow", wantExecutionLoss},
	{"OOM during interfile analysis", wantExecutionLoss},
	{"OutOfMemoryDuringInterfile", wantExecutionLoss},
	{"Internal matching error", wantExecutionLoss},
	{"MatchingError", wantExecutionLoss},
	{"Too many matches", wantExecutionLoss},
	{"TooManyMatches", wantExecutionLoss},
	{"Missing plugin", wantExecutionLoss},
	{"Fatal error", wantExecutionLoss},
	// A type this engine does not know cannot be shown to have cost nothing.
	{"SemgrepWarning", wantExecutionLoss},
	{"Some error a later Semgrep adds", wantExecutionLoss},
	// The file was matched as far as it parsed and Semgrep reports the spans it
	// skipped (D1: ok, counted, the lines named). Whether it stays ok depends on
	// how much it skipped (parse_test.go).
	{"PartialParsing", wantNoLoss},
	// A whole-file parse failure ran no rule on the file (D1', round 4): lost
	// evaluation, decoded as a ParseFailure and not as a FileError.
	{"Syntax error", wantParseFailure},
	{"Lexical error", wantParseFailure},
	{"Other syntax error", wantParseFailure},
	{"AST builder error", wantParseFailure},
	{"ParseError", wantParseFailure},
	{"LexicalError", wantParseFailure},
	{"OtherParseError", wantParseFailure},
	{"AstBuilderError", wantParseFailure},
}

func TestEverySemgrepErrorTypeHasItsLossClass(t *testing.T) {
	root := t.TempDir()
	for _, tc := range semgrepErrorTypes {
		t.Run(tc.typ, func(t *testing.T) {
			if got := IsLossType(tc.typ); got != (tc.want != wantNoLoss) {
				t.Errorf("IsLossType(%q) = %v", tc.typ, got)
			}
			typ, _ := json.Marshal(tc.typ)
			if tc.typ == "PartialParsing" {
				// Semgrep writes this one as an ATD variant.
				typ = []byte(`["PartialParsing",[{"path":"` + root + `/a.js","start":{"line":1,"col":1},"end":{"line":1,"col":2}}]]`)
			}
			doc := fmt.Sprintf(`{"results":[],"errors":[{"code":2,"level":"warn","type":%s,"rule_id":"tmp.fendix-semgrep-rules-1234.js-sqli-taint","message":"m","path":"%s/a.js"}],"time":{"fixpoint_timeouts":[]}}`, typ, root)
			run := parseRun([]byte(doc), root)

			var loss, timeout bool
			switch {
			case len(run.Timeouts) == 1:
				loss, timeout = true, true
				if run.Timeouts[0].Path != "a.js" || run.Timeouts[0].RuleID != "js-sqli-taint" {
					t.Errorf("timeout = %+v; want js-sqli-taint on a.js", run.Timeouts[0])
				}
			case len(run.FixpointTimeouts) == 1:
				loss, timeout = true, true
			case len(run.FileErrors) == 1:
				loss, timeout = true, run.FileErrors[0].IsTimeout()
				if fe := run.FileErrors[0]; fe.Type != tc.typ || fe.Path != "a.js" || fe.RuleID != "js-sqli-taint" {
					t.Errorf("file error = %+v; want %s on a.js running js-sqli-taint", fe, tc.typ)
				}
			case len(run.ParseFailures) == 1:
				loss = true
				if pf := run.ParseFailures[0]; pf.Type != tc.typ || pf.Path != "a.js" {
					t.Errorf("parse failure = %+v; want %s on a.js", pf, tc.typ)
				}
			case len(run.Timeouts)+len(run.FixpointTimeouts)+len(run.FileErrors)+len(run.ParseFailures) > 1:
				t.Fatalf("one entry decoded more than once: %+v", run)
			}
			switch tc.want {
			case wantParseFailure:
				if !loss || timeout || len(run.ParseFailures) != 1 || len(run.FileErrors) != 0 {
					t.Errorf("%s: loss=%v timeout=%v parse failures %+v file errors %+v; want exactly one parse failure", tc.typ, loss, timeout, run.ParseFailures, run.FileErrors)
				}
			case wantNoLoss:
				if loss {
					t.Errorf("%s decoded as lost evaluation: %+v", tc.typ, run)
				}
			case wantTimeoutLoss:
				if !loss || !timeout {
					t.Errorf("%s: loss=%v timeout=%v; want a timeout-class loss", tc.typ, loss, timeout)
				}
			case wantExecutionLoss:
				if !loss || timeout {
					t.Errorf("%s: loss=%v timeout=%v; want an execution-class loss", tc.typ, loss, timeout)
				}
			}
		})
	}
}

// An entry Semgrep reports at level "info" is not about a file's evaluation
// (classifyRun does not count it either); only a known loss type is read at
// any level.
func TestAnInfoEntryOfAnUnknownTypeIsNotALoss(t *testing.T) {
	root := t.TempDir()
	run := parseRun([]byte(`{"results":[],"errors":[{"level":"info","type":"x","message":"y"}],"time":{"fixpoint_timeouts":[]}}`), root)
	if len(run.FileErrors) != 0 {
		t.Errorf("FileErrors = %+v; want none for an info entry", run.FileErrors)
	}
}

// qa-engine-01: an entry whose rule_id or path is not a string still says
// what was lost. It used to fail the strict decoder and vanish, while its type
// was counted (and filtered out of the ok summary as a loss type), so the run
// read a plain ok.
func TestALossEntryWithOddFieldsIsStillDecoded(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ name, entry string }{
		{"timeout, rule_id an object", `{"code":2,"level":"warn","type":"Timeout","rule_id":{"id":"x"},"message":"Timeout when running x","path":"` + root + `/App.java"}`},
		{"timeout, path a number", `{"code":2,"level":"warn","type":"Timeout","rule_id":"tmp.fendix-semgrep-rules-1234.java-sqli-taint","message":"m","path":7}`},
		{"out of memory, rule_id a number", `{"code":2,"level":"warn","type":"Out of memory","rule_id":7,"message":"oom","path":"` + root + `/App.java"}`},
		{"stack overflow, no path", `{"level":"warn","type":"Stack overflow","message":["not","a","string"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := parseRun([]byte(`{"results":[],"errors":[`+tc.entry+`],"time":{"fixpoint_timeouts":[]}}`), root)
			if n := len(run.Timeouts) + len(run.FileErrors); n != 1 {
				t.Fatalf("decoded %d losses from %s; want 1 (Timeouts %+v, FileErrors %+v)", n, tc.entry, run.Timeouts, run.FileErrors)
			}
		})
	}
}

// A profile whose fixpoint_timeouts is null, or not a list, cannot show that
// taint analysis finished: it is unreported, never "none".
func TestAFixpointListThatIsNotAListIsUnreported(t *testing.T) {
	for _, profile := range []string{`{"fixpoint_timeouts":null}`, `{"fixpoint_timeouts":{}}`, `{"fixpoint_timeouts":"x"}`, `{}`, `null`, `[]`} {
		run := parseRun([]byte(`{"results":[],"errors":[],"time":`+profile+`}`), t.TempDir())
		if !run.FixpointUnreported {
			t.Errorf("time %s: FixpointUnreported = false; want true", profile)
		}
	}
	if run := parseRun([]byte(`{"results":[],"errors":[],"time":{"fixpoint_timeouts":[]}}`), t.TempDir()); run.FixpointUnreported {
		t.Error("an empty fixpoint_timeouts list is a report of none, not unreported")
	}
}
