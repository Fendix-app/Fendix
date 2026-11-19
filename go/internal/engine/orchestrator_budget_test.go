package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// Round 4, R-008: the orchestrator hands the Semgrep stage its budget and
// records what the stage did, against a scripted stand-in for Semgrep (the
// real-Semgrep tests of the stage itself are in internal/scanner/semgrep).

// budgetSemgrep installs a stand-in semgrep: for a scan of a directory it
// prints pass.json, for a retry of one file (the last argument is a regular
// file) it prints retry.json, and it records every invocation's arguments in
// argv.log. It returns the directory those files live in.
func budgetSemgrep(t *testing.T) string {
	t.Helper()
	scen := t.TempDir()
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 1.182.1; exit 0; fi
echo "$*" >> "` + scen + `/argv.log"
for a in "$@"; do last=$a; done
if [ -f "$last" ]; then cat "` + scen + `/retry.json"; else cat "` + scen + `/pass.json"; fi
`
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
	return scen
}

// resolvedCodeDir is a code directory whose path has no symbolic link in it
// (macOS temp directories do), the form Semgrep's own paths take.
func resolvedCodeDir(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(writeCodeDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func budgetCfg(dir string, out string) *models.ScanConfig {
	return &models.ScanConfig{
		CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
		Offline: true, OfflineDBPath: filepath.Join(os.TempDir(), "missing-fendix-db.json"),
		NoPlugins: true, PythonEngine: false,
	}
}

func semgrepEntry(t *testing.T, rep reporters.JSONReport) reporters.ScannerStatus {
	t.Helper()
	for _, s := range rep.Metadata.ScannerStatus {
		if s.Name == AnalyzerSemgrep {
			return s
		}
	}
	t.Fatal("no semgrep entry in the report")
	return reporters.ScannerStatus{}
}

func TestOrchestratorHandsTheSemgrepStageItsBudget(t *testing.T) {
	scen := budgetSemgrep(t)
	real := resolvedCodeDir(t)
	dir := real
	doc := fmt.Sprintf(`{"results":[],"errors":[],"paths":{"scanned":[%q]},"time":{"fixpoint_timeouts":[]}}`, filepath.Join(real, "app.py"))
	if err := os.WriteFile(filepath.Join(scen, "pass.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := budgetCfg(dir, filepath.Join(t.TempDir(), "report.json"))
	cfg.SemgrepJobs = 3
	cfg.SemgrepMaxMemoryMiB = 700
	cfg.SemgrepWallBudget = 90 * time.Second
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(filepath.Join(scen, "argv.log"))
	if err != nil {
		t.Fatalf("semgrep was not run: %v", err)
	}
	argv := string(data)
	for _, want := range []string{"--jobs 3", "--max-memory 700"} {
		if !strings.Contains(argv, want) {
			t.Errorf("semgrep argv %q is missing %q: the config's budget must reach the stage", argv, want)
		}
	}
}

// A file that lost a rule to a timeout and finished when re-run alone is
// complete: the entry is ok, and the report still records the timeout it had,
// so the pass-1 loss is auditable and not silent.
func TestOrchestratorRecordsARetryThatResolvedATimeout(t *testing.T) {
	scen := budgetSemgrep(t)
	real := resolvedCodeDir(t)
	dir := real
	app := filepath.Join(real, "app.py")
	pass := fmt.Sprintf(`{"results":[],"errors":[{"code":2,"level":"warn","type":"Timeout","rule_id":"rules.python-eval","message":"Timeout when running rules.python-eval on %s:","path":%q}],"paths":{"scanned":[%q]},"time":{"fixpoint_timeouts":[]}}`, app, app, app)
	retry := fmt.Sprintf(`{"results":[],"errors":[],"paths":{"scanned":[%q]},"time":{"fixpoint_timeouts":[]}}`, app)
	for name, body := range map[string]string{"pass.json": pass, "retry.json": retry} {
		if err := os.WriteFile(filepath.Join(scen, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if code := NewOrchestrator(budgetCfg(dir, out), "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	rep := readReport(t, out)
	if got := semgrepEntry(t, rep); got.State != reporters.ScannerOK {
		t.Errorf("semgrep = %+v: the retry evaluated app.py in full, so the run is complete", got)
	}
	found := false
	for _, l := range rep.Metadata.Coverage.Limitations {
		if strings.Contains(l, "retried alone") && strings.Contains(l, "app.py") && strings.Contains(l, "resolved") {
			found = true
		}
	}
	if !found {
		t.Errorf("limitations = %q: a resolved retry must stay on the record", rep.Metadata.Coverage.Limitations)
	}
}

// A retry that does not finish leaves the file lost: the entry is failed, as it
// was before the retry existed.
func TestOrchestratorKeepsALossTheRetryCouldNotResolve(t *testing.T) {
	scen := budgetSemgrep(t)
	real := resolvedCodeDir(t)
	dir := real
	app := filepath.Join(real, "app.py")
	timeout := fmt.Sprintf(`{"code":2,"level":"warn","type":"Timeout","rule_id":"rules.python-eval","message":"Timeout when running rules.python-eval on %s:","path":%q}`, app, app)
	pass := fmt.Sprintf(`{"results":[],"errors":[%s],"paths":{"scanned":[%q]},"time":{"fixpoint_timeouts":[]}}`, timeout, app)
	retry := fmt.Sprintf(`{"results":[],"errors":[%s],"paths":{"scanned":[%q]},"time":{"fixpoint_timeouts":[]}}`, timeout, app)
	for name, body := range map[string]string{"pass.json": pass, "retry.json": retry} {
		if err := os.WriteFile(filepath.Join(scen, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	NewOrchestrator(budgetCfg(dir, out), "dev").Run(context.Background())
	rep := readReport(t, out)
	got := semgrepEntry(t, rep)
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonTimeout {
		t.Errorf("semgrep = %+v, want failed/timeout", got)
	}
	if !strings.Contains(got.Detail, "app.py") {
		t.Errorf("detail %q must name the file", got.Detail)
	}
}

func TestSemgrepBudgetNotesNameEveryRetry(t *testing.T) {
	if semgrepBudgetNotes(semgrep.Run{}) != nil {
		t.Error("a run with no retries has nothing to say")
	}
	notes := semgrepBudgetNotes(semgrep.Run{Retries: []semgrep.Retry{
		{Path: "a.js", Resolved: true, Timeout: 60},
		{Path: "b;c.js", Why: "timed out again"},
		{Path: "d.js", Why: "not retried: over the cap of 12 files"},
	}})
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"a.js (resolved", "still lost: timed out again", "d.js (still lost: not retried: over the cap of 12 files)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes %q are missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "b;c.js") {
		t.Errorf("a repository-controlled name must be sanitised (C1): %q", joined)
	}
	for _, n := range notes {
		if len(n) > 240 {
			t.Errorf("a note is over 240 bytes: %d", len(n))
		}
	}
}
