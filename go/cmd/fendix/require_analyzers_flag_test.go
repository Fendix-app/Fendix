package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/cli"
)

// The composite Action passes `--require-analyzers <resolved>` and appends the
// caller's extra-args after it (scripts/action/scan.sh). These tests run that
// argv through the real CLI and prove extra-args cannot cancel the
// requirement: a repeated --require-analyzers only adds names (an empty one
// adds none), and a flag that disables a required analyzer exits 2.

type requireRun struct {
	code     int
	required []string
	gaps     []string
	strict   bool
	stderr   string
	semgrep  statusEntry
}

type statusEntry struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func runRequired(t *testing.T, args ...string) requireRun {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	root := newRootCmd()
	// Hermetic: no Python engine, no plugins, and --offline with no snapshot
	// so no dependency scanner reaches the network.
	base := []string{
		"scan", "--code", t.TempDir(), "--format", "json", "--output", out,
		"--python-engine=false", "--no-plugins", "--offline",
		"--offline-db", filepath.Join(t.TempDir(), "missing.json"),
	}
	root.SetArgs(append(base, args...))
	root.SetOut(new(strings.Builder))
	stderr := new(strings.Builder)
	root.SetErr(stderr)
	run := requireRun{}
	if err := root.Execute(); err != nil {
		var exitErr *cli.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("scan failed without an exit code: %v", err)
		}
		run.code = exitErr.Code
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the scan wrote no report: %v", err)
	}
	var rep struct {
		Metadata struct {
			ScannerStatus []statusEntry `json:"scanner_status"`
			Coverage      struct {
				Strict            bool     `json:"strict"`
				RequiredAnalyzers []string `json:"required_analyzers"`
				RequiredGaps      []string `json:"required_gaps"`
			} `json:"coverage"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("parsing report: %v", err)
	}
	run.required = rep.Metadata.Coverage.RequiredAnalyzers
	run.gaps = rep.Metadata.Coverage.RequiredGaps
	run.strict = rep.Metadata.Coverage.Strict
	run.stderr = stderr.String()
	for _, entry := range rep.Metadata.ScannerStatus {
		if entry.Name == "semgrep" {
			run.semgrep = entry
		}
	}
	return run
}

func TestRequireAnalyzers_ExtraArgsCannotCancelTheRequirement(t *testing.T) {
	cases := []struct {
		name      string
		extra     []string
		required  []string
		wantGaps  []string
		wantCode  int
		rationale string
	}{
		{"--fast disables the required semgrep", []string{"--fast"},
			[]string{"semgrep"}, []string{"semgrep"}, 2,
			"a required analyzer disabled by another flag is a contradiction"},
		{"an empty --require-analyzers adds nothing", []string{"--require-analyzers=", "--fast"},
			[]string{"semgrep"}, []string{"semgrep"}, 2,
			"pflag appends a repeated slice flag; an empty value appends no name"},
		{"a second list only adds names", []string{"--require-analyzers", "secrets", "--fast"},
			[]string{"semgrep", "secrets"}, []string{"semgrep"}, 2,
			"the Action's own list survives a caller's --require-analyzers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runRequired(t, append([]string{"--require-analyzers", "semgrep"}, tc.extra...)...)
			if got.code != tc.wantCode {
				t.Fatalf("exit %d, want %d (%s)", got.code, tc.wantCode, tc.rationale)
			}
			if !reflect.DeepEqual(got.required, tc.required) {
				t.Errorf("required_analyzers = %v, want %v (%s)", got.required, tc.required, tc.rationale)
			}
			if !reflect.DeepEqual(got.gaps, tc.wantGaps) {
				t.Errorf("required_gaps = %v, want %v", got.gaps, tc.wantGaps)
			}
			if !got.strict {
				t.Error("coverage.strict = false with a required analyzer")
			}
		})
	}
}

// Semgrep absent from PATH at scan time, after a preflight passed (the
// defence in depth the Action relies on): required, it is not delivered and
// the scan exits 2; not required, the same scan exits 0 and says coverage is
// incomplete without failing.
func TestRequireAnalyzers_UnavailableSemgrepExits2OnlyWhenRequired(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	got := runRequired(t, "--require-analyzers", "semgrep")
	if got.code != 2 || !reflect.DeepEqual(got.gaps, []string{"semgrep"}) {
		t.Fatalf("required semgrep missing from PATH: exit %d, gaps %v; want 2 and [semgrep]", got.code, got.gaps)
	}
	optional := runRequired(t)
	if optional.code != 0 || len(optional.gaps) != 0 || optional.strict {
		t.Fatalf("unrequired semgrep missing from PATH: exit %d, gaps %v, strict %v; want 0, none, false",
			optional.code, optional.gaps, optional.strict)
	}
}

// installRecordedSemgrep puts a semgrep on PATH that replays a recorded
// Semgrep 1.182.1 run (internal/scanner/semgrep/testdata/runs) with the exit
// code that run ended with.
func installRecordedSemgrep(t *testing.T, fixture string, exitCode int) {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "internal", "scanner", "semgrep", "testdata", "runs", fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat '" + path + "'\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "semgrep"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin:/bin")
}

// A Semgrep whose engine was killed mid-run (out of memory) still writes a
// well-formed envelope with no results. Until v3.6.5 that was recorded ok;
// it is failed now, and a required Semgrep makes the scan exit 2.
func TestRequireAnalyzers_FatalSemgrepRunIsNotOk(t *testing.T) {
	installRecordedSemgrep(t, "oom.json", 2)
	optional := runRequired(t)
	if optional.semgrep.State != "failed" || optional.semgrep.Reason != "execution_error" {
		t.Fatalf("semgrep = %+v, want failed/execution_error", optional.semgrep)
	}
	if !strings.Contains(optional.semgrep.Detail, "the engine was killed") {
		t.Errorf("detail must name the cause, got %q", optional.semgrep.Detail)
	}
	if optional.code != 0 {
		t.Errorf("not required: exit %d, want 0 (coverage incomplete, gate by the analyzers that ran)", optional.code)
	}

	required := runRequired(t, "--require-analyzers", "semgrep")
	if required.code != 2 || !reflect.DeepEqual(required.gaps, []string{"semgrep"}) {
		t.Fatalf("required semgrep that failed fatally: exit %d, gaps %v; want 2 and [semgrep]", required.code, required.gaps)
	}

	// Exit 0 with an error-level entry behind per-file warnings is fatal too.
	installRecordedSemgrep(t, "ruleerror-then-warn.json", 0)
	if got := runRequired(t, "--require-analyzers", "semgrep"); got.code != 2 || got.semgrep.State != "failed" {
		t.Fatalf("rule parse error then warnings: exit %d, semgrep %+v; want 2 and failed", got.code, got.semgrep)
	}

	// No envelope at all on exit 0.
	installRecordedSemgrep(t, "garbagecore.stderr", 0)
	if got := runRequired(t, "--require-analyzers", "semgrep"); got.code != 2 || got.semgrep.Reason != "malformed_output" {
		t.Fatalf("exit 0 without JSON: exit %d, semgrep %+v; want 2 and failed/malformed_output", got.code, got.semgrep)
	}
}

// Per-file problems are normal on real trees: a file that does not parse
// leaves Semgrep ok, required or not, with the count in its detail.
func TestRequireAnalyzers_PerFileProblemsKeepSemgrepOk(t *testing.T) {
	installRecordedSemgrep(t, "syntax2.json", 0)
	got := runRequired(t, "--require-analyzers", "semgrep")
	if got.code != 0 || got.semgrep.State != "ok" {
		t.Fatalf("per-file parse error: exit %d, semgrep %+v; want 0 and ok", got.code, got.semgrep)
	}
	if !strings.Contains(got.semgrep.Detail, "PartialParsing 1") {
		t.Errorf("the per-file problem must be counted in the detail, got %q", got.semgrep.Detail)
	}
}
