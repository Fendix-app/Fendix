package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// Round 6, WS-E2: R5-09 (RC-2c, decision D6, gate G2.8) and the R5-08 import
// goldens.
//
// A SARIF producer that says its run failed (executionSuccessful:false), or
// that raised error-level notifications, has not shown that it evaluated
// anything: an absent result is not evidence that a finding is gone. Today the
// import reads configured_complete and exits 0 (redteam5 sarif8 failed.sarif:
// "0 findings", complete). Under D6 the run adds an `import/<tool>` gap, the
// coverage is not complete, and `fendix import --fail-on` exits 2.

const wse2ImportDir = "testdata/r6import"

func wse2Import(t *testing.T, failOn string, files ...string) (int, map[string]any, *reporters.JSONReport) {
	t.Helper()
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = filepath.Join(wse2ImportDir, f)
	}
	cfg := importConfig(t, failOn, paths...)
	code := NewOrchestrator(cfg, "test").RunImport(context.Background())
	raw, err := os.ReadFile(cfg.OutputPath)
	if err != nil {
		t.Fatalf("no report written (exit %d): %v", code, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	rep, err := reporters.ParseJSONReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	return code, m, rep
}

func wse2ImportGap(rep *reporters.JSONReport, tool string) bool {
	c := rep.Metadata.Coverage
	return c != nil && slices.Contains(c.Gaps, "import/"+tool)
}

// D6 / R5-09: the failed producer run, and every neighbour that must read
// incomplete.
func TestRunImport_R5_09_FailedProducerRunReadsIncompleteAndFailOnExits2(t *testing.T) {
	for name, files := range map[string][]string{
		"executionSuccessful false + error notification":    {"failed.sarif"},
		"error notifications with executionSuccessful true": {"errnotif-success.sarif"},
		"one failed run among two files of the same tool":   {"ok.sarif", "failed.sarif"},
		// Review B3: every failure signal SARIF 2.1.0 defines for an invocation.
		"executionSuccessful false alone":               {"execfalse-only.sarif"},
		"toolConfigurationNotifications at level error": {"confnotif-error.sarif"},
		"two runs in one file, one failed":              {"tworuns-one-failed.sarif"},
		"two invocations in one run, one failed":        {"twoinvocations-one-failed.sarif"},
		"exitCode non-zero, no executionSuccessful":     {"exitcode-nonzero.sarif"},
		"exitSignalName set, no executionSuccessful":    {"exitsignal.sarif"},
	} {
		t.Run(name, func(t *testing.T) {
			// CRITICAL: no fixture result blocks at it, so the exit code
			// isolates the coverage reading from the finding decision.
			code, _, rep := wse2Import(t, "CRITICAL", files...)
			c := rep.Metadata.Coverage
			if c == nil {
				t.Fatal("no coverage block")
			}
			if c.ConfiguredComplete {
				t.Errorf("coverage reads configured_complete after a failed producer run (limitations: %v)", c.Limitations)
			}
			if !wse2ImportGap(rep, "codeql") {
				t.Errorf("coverage gaps %v lack import/codeql", c.Gaps)
			}
			if code != 2 {
				t.Errorf("fendix import --fail-on CRITICAL exited %d after a failed producer run, want 2", code)
			}
		})
	}
}

// Review B4: runs whose producer recorded success stay complete, with no gap
// and exit 0. Suppressed and disabled rules stay deferred with D19.
func TestRunImport_R5_09_SuccessfulRunsAreUnchanged(t *testing.T) {
	for name, file := range map[string]string{
		"executionSuccessful true, no notifications":     "ok.sarif",
		"executionSuccessful true, warning notification": "warnnotif-success.sarif",
	} {
		t.Run(name, func(t *testing.T) {
			code, _, rep := wse2Import(t, "CRITICAL", file)
			if c := rep.Metadata.Coverage; c == nil || !c.ConfiguredComplete {
				t.Errorf("a run its producer recorded as successful does not read configured_complete: %+v", c)
			}
			if wse2ImportGap(rep, "codeql") {
				t.Errorf("a run its producer did not mark failed got an import gap: %v", rep.Metadata.Coverage.Gaps)
			}
			if code != 0 {
				t.Errorf("exit %d, want 0 (no blocking finding, no failed run)", code)
			}
		})
	}
}

// OR-60: two producers in one file are judged separately. CodeQL's run
// succeeded and Semgrep's failed, so the gaps are exactly [import/semgrep]:
// one failed producer neither hides behind nor taints the other.
func TestRunImport_OR60_TwoProducersInOneFileGapOnlyTheFailedOne(t *testing.T) {
	code, _, rep := wse2Import(t, "CRITICAL", "two-producers-semgrep-failed.sarif")
	c := rep.Metadata.Coverage
	if c == nil || !slices.Equal(c.Gaps, []string{"import/semgrep"}) {
		var gaps []string
		if c != nil {
			gaps = c.Gaps
		}
		t.Errorf("gaps %v, want exactly [import/semgrep]", gaps)
	}
	if c != nil && c.ConfiguredComplete {
		t.Error("configured_complete with a failed Semgrep run")
	}
	if code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
}

// OR-60 control: exitCode 0 with no executionSuccessful is a successful run.
func TestRunImport_OR60_ExitCodeZeroIsASuccessfulRun(t *testing.T) {
	code, _, rep := wse2Import(t, "CRITICAL", "exitcode-zero.sarif")
	if c := rep.Metadata.Coverage; c == nil || !c.ConfiguredComplete || len(c.Gaps) != 0 {
		t.Errorf("exitCode 0 does not read complete with no gap: %+v", c)
	}
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
}

// OR-11: a SARIF without invocations is not a gap, because `invocations` is
// optional in SARIF 2.1.0. The producer recorded nothing either way; whether
// that can make a false complete is for the verifier to confirm (OR-11).
func TestRunImport_OR11_NoInvocationsIsNotAGap(t *testing.T) {
	code, _, rep := wse2Import(t, "CRITICAL", "noinvocations.sarif")
	if wse2ImportGap(rep, "codeql") {
		t.Errorf("no invocations produced an import gap: %v", rep.Metadata.Coverage.Gaps)
	}
	if code != 0 {
		t.Errorf("exit %d, want 0", code)
	}
}

// R5-09 on `fendix scan --import`: the scan path never consulted the run
// record at all (orchestrator.go:741-751).
func TestScanImport_R5_09_FailedProducerRunAddsTheGap(t *testing.T) {
	code := t.TempDir()
	if err := os.WriteFile(filepath.Join(code, "app.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath:          code,
		ImportPaths:       []string{filepath.Join(wse2ImportDir, "failed.sarif")},
		Format:            "json",
		OutputPath:        out,
		EnforceConfidence: true,
		Offline:           true,
	}
	NewOrchestrator(cfg, "test").Run(context.Background())
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	rep, err := reporters.ParseJSONReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !wse2ImportGap(rep, "codeql") {
		gaps := []string(nil)
		if rep.Metadata.Coverage != nil {
			gaps = rep.Metadata.Coverage.Gaps
		}
		t.Fatalf("scan --import of a failed producer run: gaps %v lack import/codeql", gaps)
	}
}

// wse2GoldenFailed names the goldens of a run its producer marked failed.
var wse2GoldenFailed = map[string]bool{
	"import_failed.json":            true,
	"import_errnotif_success.json":  true,
	"import_two_files_one_bad.json": true,
}

// R5-08 import goldens: the engine's own import reports for each producer
// record shape, written where python/tests/test_report_schema.py validates them
// against docs/schema.json with real JSON Schema. Wall-clock fields are
// normalized. Regenerate with UPDATE_GOLDEN=1 after reviewing the contract.
func TestRunImport_R6_ReportGoldens(t *testing.T) {
	goldenDir := filepath.Join("..", "..", "..", "python", "tests", "fixtures", "report_schema", "engine")
	for golden, files := range map[string][]string{
		"import_ok.json":                {"ok.sarif"},
		"import_failed.json":            {"failed.sarif"},
		"import_errnotif_success.json":  {"errnotif-success.sarif"},
		"import_no_invocations.json":    {"noinvocations.sarif"},
		"import_two_files_one_bad.json": {"ok.sarif", "failed.sarif"},
	} {
		t.Run(golden, func(t *testing.T) {
			_, m, _ := wse2Import(t, "", files...)
			meta := m["metadata"].(map[string]any)
			meta["started_at"] = "2026-11-14T00:00:00Z"
			meta["duration"] = "0s"
			meta["version"] = "golden"
			got, err := json.MarshalIndent(m, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join(goldenDir, golden)
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (UPDATE_GOLDEN=1 go test ./internal/engine -run TestRunImport_R6_ReportGoldens): %v", err)
			}
			// Review W1: a golden is a contract, so it must not pin the bug.
			// A golden of a failed producer run must itself read incomplete
			// with the import gap; these goldens change in Stage B.
			if wse2GoldenFailed[golden] {
				var g reporters.JSONReport
				if err := json.Unmarshal(want, &g); err != nil {
					t.Fatal(err)
				}
				if c := g.Metadata.Coverage; c == nil || c.ConfiguredComplete || !slices.Contains(c.Gaps, "import/codeql") {
					t.Errorf("golden %s pins a failed producer run as complete (coverage %+v); it must read incomplete with the import/codeql gap", golden, c)
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("import report %s changed; review the contract and regenerate with UPDATE_GOLDEN=1", golden)
			}
		})
	}
}

// OR-11: a failed producer run together with a finding that BLOCKs follows the
// engine's existing exit precedence (orchestrator.go Run, step 8): every
// coverage exit 2 (--fail-on-scanner-error, --fail-on-coverage-gap, a required
// analyzer not delivered, a hard discovery failure) is returned BEFORE the
// decision layer's exit 1. So the import exits 2, not 1: an incomplete run is
// reported as incomplete even when it also found something.
func TestRunImport_OR11_FailedRunWithABlockingFindingExits2(t *testing.T) {
	code, _, rep := wse2Import(t, "HIGH", "failed-with-blocking-finding.sarif")
	if rep.Decisions.Blocking == 0 {
		t.Fatalf("fixture error: no finding BLOCKs at --fail-on HIGH (decisions %+v)", rep.Decisions)
	}
	if code != 2 {
		t.Fatalf("failed producer run + a blocking finding exited %d; the coverage exit 2 takes precedence over the findings exit 1", code)
	}
}
