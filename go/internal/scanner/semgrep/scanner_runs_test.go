package semgrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Recorded runs (testdata/runs): real semgrep 1.182.1, the version
// python/requirements.lock pins, run inside the official image
// docker.io/fendixapp/fendix@sha256:ddf07e33… with the engine's own flags
// (--config <bundled rules> --json --no-git-ignore --quiet
// --disable-version-check <target>). Each <case>.json is that run's stdout,
// re-indented; the exit code it ended with is in the table below.
//
//	baseline             bundled rules, one matching file                   exit 0
//	syntax2              a file that does not parse, next to a match        exit 0, warn PartialParsing
//	timeout2             an expensive extra rule, --timeout 1                exit 0, warn Timeout (JSON code 2)
//	timeoutmixed         bundled rules plus that rule, --timeout 1           exit 0, warn Timeout, one match kept
//	badpattern           plus a rule whose pattern does not parse            exit 2, error Rule parse error, other results printed
//	ruleerror-then-warn  badpattern's rules on three unparsable files        exit 0 (!), error first, warn after
//	badschema            plus a rule without severity                        exit 7
//	badyaml              plus a file that is not YAML                        exit 7
//	missingcfg           --config pointing nowhere                           exit 7
//	oom                  ulimit -v 700000 on a 3000-file tree                exit 2, error "the engine was killed"
//	kill-KILL/kill-SEGV  SIGKILL/SIGSEGV to semgrep-core -json mid-run       exit 2, error "the engine was killed"
//	garbagecore.stderr   semgrep-core replaced by a non-executable file      exit 1, no stdout
//
// Semgrep itself exits non-zero only when its LAST error has level "error"
// (output.py _final_raise), which is why ruleerror-then-warn exits 0.

func recorded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "runs", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func TestClassifyRun_RecordedSemgrepRuns(t *testing.T) {
	cases := []struct {
		name       string
		exit       int
		wantErr    error // nil: ok
		wantInErr  string
		results    int
		incomplete map[string]int
	}{
		{"baseline", 0, nil, "", 1, nil},
		{"syntax2", 0, nil, "", 1, map[string]int{"PartialParsing": 1}},
		{"timeout2", 0, nil, "", 0, map[string]int{"Timeout": 1}},
		{"timeoutmixed", 0, nil, "", 1, map[string]int{"Timeout": 1}},
		{"badpattern", 2, ErrFatal, "exited 2: Rule parse error: Rule parse error in rule c.badpattern.x", 1, nil},
		{"ruleerror-then-warn", 0, ErrFatal, "exited 0 but reported a fatal error: Rule parse error", 1, map[string]int{"PartialParsing": 3}},
		{"badschema", 7, ErrFatal, "exited 7: InvalidRuleSchemaError", 0, nil},
		{"badyaml", 7, ErrFatal, "exited 7: SemgrepError: Invalid YAML file", 0, nil},
		{"missingcfg", 7, ErrFatal, "unable to find a config", 0, nil},
		{"oom", 2, ErrFatal, "You are seeing this because the engine was killed", 0, nil},
		{"kill-KILL", 2, ErrFatal, "the engine was killed", 0, nil},
		{"kill-SEGV", 2, ErrFatal, "the engine was killed", 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, report, err := classifyRun(exitStatus{code: tc.exit}, recorded(t, tc.name+".json"), "")
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("a run Semgrep itself treats as successful must be ok, got %v", err)
				}
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantInErr) {
					t.Errorf("err %q does not name the cause %q", err, tc.wantInErr)
				}
				if strings.ContainsAny(err.Error(), "\n\r") {
					t.Errorf("err must be one line: %q", err)
				}
			}
			if out == nil || len(out.Results) != tc.results {
				t.Fatalf("envelope results: got %v, want %d (findings Semgrep printed are kept)", out, tc.results)
			}
			if !reflect.DeepEqual(report.Incomplete, tc.incomplete) {
				t.Errorf("incomplete = %v, want %v", report.Incomplete, tc.incomplete)
			}
		})
	}
}

func TestClassifyRun_NoEnvelope(t *testing.T) {
	cases := []struct {
		name    string
		status  exitStatus
		stdout  string
		stderr  string
		wantErr error
		want    string
	}{
		// semgrep-core replaced by a file it cannot exec: Python traceback, exit 1.
		{"exit 1 without JSON is a failure, not findings", exitStatus{code: 1}, "", string(recorded(t, "garbagecore.stderr")),
			ErrFatal, "OSError: [Errno 8] Exec format error"},
		// An unreadable config: exit 2 and, with --quiet, no output at all.
		{"exit 2 with nothing written", exitStatus{code: 2}, "", "", ErrFatal, "exited 2 and wrote no JSON results: no error message"},
		{"killed by a signal", exitStatus{code: -1, signal: "signal 9 (killed)"}, "", "", ErrFatal, "was killed by signal 9 (killed)"},
		{"exit 0 with empty stdout", exitStatus{code: 0}, "", "", ErrMalformedOutput, "stdout is empty"},
		{"exit 0 with non-JSON stdout", exitStatus{code: 0}, "Usage: semgrep [OPTIONS]", "", ErrMalformedOutput, "stdout is not JSON"},
		{"exit 0 with JSON but no results", exitStatus{code: 0}, `{"errors":[]}`, "", ErrMalformedOutput, "JSON without a results list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := classifyRun(tc.status, []byte(tc.stdout), tc.stderr)
			if out != nil {
				t.Errorf("no envelope expected, got %+v", out)
			}
			if !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %v containing %q", err, tc.wantErr, tc.want)
			}
		})
	}
}

func TestClassifyRun_LevelNotCodeDecides(t *testing.T) {
	// A warn-level error with JSON code 2 (Semgrep's per-file Timeout) and an
	// info-level one: neither is fatal.
	ok := `{"results":[],"errors":[{"code":2,"level":"warn","type":"Timeout","message":"Timeout when running r on f"},{"code":0,"level":"info","type":"x","message":"y"}]}`
	if _, rep, err := classifyRun(exitStatus{code: 0}, []byte(ok), ""); err != nil || rep.Incomplete["Timeout"] != 1 {
		t.Fatalf("warn-level code-2 error must stay ok and be counted: err=%v report=%+v", err, rep)
	}
	// The interfile types Semgrep does not fail on, even at level error.
	interfile := `{"results":[],"errors":[{"code":2,"level":"error","type":"TimeoutDuringInterfile","message":"m"}]}`
	if _, rep, err := classifyRun(exitStatus{code: 0}, []byte(interfile), ""); err != nil || rep.Incomplete["TimeoutDuringInterfile"] != 1 {
		t.Fatalf("interfile errors are Semgrep-nonblocking: err=%v report=%+v", err, rep)
	}
	// Exit 1 with an envelope is Semgrep's "findings" code (--error).
	if _, _, err := classifyRun(exitStatus{code: 1}, recorded(t, "baseline.json"), ""); err != nil {
		t.Fatalf("exit 1 with an envelope is findings, got %v", err)
	}
}

func TestClassifyRun_ErrorTextIsBoundedAndOneLine(t *testing.T) {
	long := strings.Repeat("A very long fatal message line\n", 100)
	doc := `{"results":[],"errors":[{"code":2,"level":"error","type":"FatalError","message":` + jsonString(long) + `}]}`
	_, _, err := classifyRun(exitStatus{code: 2}, []byte(doc), "")
	if !errors.Is(err, ErrFatal) {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r") || len(err.Error()) > errorTextMax+120 {
		t.Fatalf("error text must be one bounded line, got %d bytes: %q", len(err.Error()), err)
	}
}

func jsonString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func TestReportSummary_CountsTypesNeverMessages(t *testing.T) {
	_, rep, err := classifyRun(exitStatus{code: 0}, recorded(t, "syntax2.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	got := rep.Summary()
	if got != "1 non-fatal per-file problem(s) reported by semgrep (PartialParsing 1); findings in those files may be incomplete" {
		t.Errorf("summary = %q", got)
	}
	// The PartialParsing message quotes the unparsed source; it must not reach
	// the scanner detail.
	if strings.Contains(got, "class class") || strings.Contains(got, "/t/syntax2") {
		t.Errorf("summary leaks the message or path: %q", got)
	}
	if (Report{}).Summary() != "" {
		t.Error("a run with no per-file problems has no summary")
	}
}

// Through the real subprocess path: a fake semgrep replays a recorded fatal
// envelope with its exit code, and one dies by a signal.
func TestScan_RecordedFatalRunIsAnError(t *testing.T) {
	installFakeSemgrep(t, string(recorded(t, "oom.json")), "", 2)
	_, _, err := ScanWithReport(context.Background(), t.TempDir(), nil)
	if !errors.Is(err, ErrFatal) || !strings.Contains(err.Error(), "the engine was killed") {
		t.Fatalf("an OOM-killed engine must be a fatal error, got %v", err)
	}

	installFakeSemgrep(t, string(recorded(t, "ruleerror-then-warn.json")), "", 0)
	got, _, err := ScanWithReport(context.Background(), t.TempDir(), nil)
	if !errors.Is(err, ErrFatal) {
		t.Fatalf("an error-level entry behind warnings (exit 0) must be fatal, got %v", err)
	}
	if len(got) != 1 {
		t.Errorf("the finding Semgrep still printed must be kept, got %d", len(got))
	}
}

func TestScan_SignalDeathIsNamed(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nkill -SEGV $$\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	origLook := LookPath
	LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return origLook(name)
	}
	t.Cleanup(func() { LookPath = origLook })
	_, _, err := ScanWithReport(context.Background(), t.TempDir(), nil)
	if !errors.Is(err, ErrFatal) || !strings.Contains(err.Error(), "was killed by signal") {
		t.Fatalf("a semgrep killed by SIGSEGV must be fatal and named, got %v", err)
	}
}

func TestScan_PerFileProblemsStayOkWithACount(t *testing.T) {
	installFakeSemgrep(t, string(recorded(t, "timeoutmixed.json")), "", 0)
	got, rep, err := ScanWithReport(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("a per-file timeout must not fail the analyzer: %v", err)
	}
	if len(got) != 1 || rep.Incomplete["Timeout"] != 1 {
		t.Fatalf("findings %d, report %+v; want 1 finding and one Timeout", len(got), rep)
	}
}
