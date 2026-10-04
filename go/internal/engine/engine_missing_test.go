package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// vulnPyFixture is the canonical multi-step command-injection sample used in
// the Proven-Path demo. The native semgrep/secrets/textscan scanners can
// produce at least one finding on it, so it doubles as the regression guard
// for "missing Python engine must NOT silently fall back to Go-only output".
const vulnPyFixture = `import os
def handler(request):
    cmd = "ls " + request.args.get("dir")
    os.popen(cmd)               # multi-step taint -> command injection
    os.system("echo " + request.args.get("name"))   # command injection
`

// TestRun_PythonEngineMissing_IsFatal proves the fix for the silent-no-op bug:
// when the Python taint engine cannot be resolved AND SAST is requested
// (--code / --python-engine), the scan must HARD-FAIL (exit 2) with a loud,
// actionable error -- never exit 0 having quietly dropped the flagship SAST
// path down to whatever the native Go scanners happened to find.
//
// Before the fix: FENDIX_ENGINE at a bad path -> WARN, spawner falls back to
// "./python", subprocess chdir fails -> ERROR logged but exit 0 with the
// native findings presented as if SAST ran. This test catches that regression
// by asserting exit != 0 and that no report is emitted.
func TestRun_PythonEngineMissing_IsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.py"), []byte(vulnPyFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "report.json")

	// 1. Deliberately point FENDIX_ENGINE at a path with no engine.py.
	// extract.EnsureEngine returns its error before ever consulting the
	// embedded payload or the ./python fallback, so this is deterministic
	// whether or not the test binary embeds an engine.
	t.Setenv("FENDIX_ENGINE", filepath.Join(dir, "no-such-engine"))

	cfg := &models.ScanConfig{
		// 2. --code on the vuln.py fixture, SAST requested EXPLICITLY
		// (--python-engine by name). Only the explicit request is fatal on a
		// missing engine; the implicit --code auto-enable degrades (see
		// TestRun_PythonEngineMissing_ImplicitCode_IsNotFatal).
		CodePath:             dir,
		PythonEngine:         true,
		PythonEngineExplicit: true,
		Workers:              2,
		Timeout:              10,
		Format:               "json",
		OutputPath:           outputPath,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())

	// 3. The scan must exit non-zero.
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit when Python engine is missing and --python-engine requested, got exit %d", exitCode)
	}

	// 4. The resolution error must name the missing engine.
	if orch.engineErr == nil {
		t.Fatal("expected orchestrator to record a Python-engine resolution error")
	}
	if msg := orch.engineErr.Error(); !strings.Contains(msg, "Python taint engine not found") {
		t.Fatalf("error message must contain %q, got: %s", "Python taint engine not found", msg)
	}

	// 5. No report must be written -- we must NOT present native Go findings
	// as if the SAST taint engine ran. A fatal config error short-circuits
	// before rendering.
	if data, err := os.ReadFile(outputPath); err == nil {
		t.Fatalf("expected no report to be written on fatal engine error, but got %d bytes:\n%s", len(data), data)
	}
}

// TestRun_PythonEngineMissing_NonSAST_IsNotFatal guards the other half of the
// contract: a scan that does NOT request SAST (PythonEngine=false) must not be
// affected by a missing/unresolved Python engine. It stays a clean run.
func TestRun_PythonEngineMissing_NonSAST_IsNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.txt"), []byte("nothing to see"), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "report.json")

	// FENDIX_ENGINE deliberately bad, but PythonEngine is OFF, so the
	// orchestrator never resolves it and never WARNs about it.
	t.Setenv("FENDIX_ENGINE", filepath.Join(dir, "no-such-engine"))

	cfg := &models.ScanConfig{
		CodePath:     dir,
		PythonEngine: false, // secrets/semgrep/textscan only -- no SAST requested
		Fast:         true,  // keep it quick: secrets + textscan only
		Workers:      2,
		Timeout:      10,
		Format:       "json",
		OutputPath:   outputPath,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())

	if exitCode == 2 {
		t.Fatalf("a non-SAST scan must not hard-fail on a missing Python engine; got exit 2")
	}
	if orch.engineErr != nil {
		t.Fatalf("non-SAST scan must not even attempt engine resolution, but recorded error: %v", orch.engineErr)
	}
	if _, err := os.ReadFile(outputPath); err != nil {
		t.Fatalf("expected a report to be written for the non-SAST scan: %v", err)
	}
}

// TestRun_PythonEngineMissing_ImplicitCode_IsNotFatal guards the middle case:
// a `--code` scan auto-enables the Python engine (PythonEngine=true) but the
// user did NOT pass --python-engine by name (PythonEngineExplicit=false). When
// the engine can't be resolved, this must degrade to a native-Go-only scan —
// WARN + continue, report written, no exit 2 — NOT hard-fail. This is the
// regression the e2e refplugins smoke tests hit: a plugin/native-only --code
// scan on a CI runner with no python/ tree must still complete.
func TestRun_PythonEngineMissing_ImplicitCode_IsNotFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.py"), []byte(vulnPyFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "report.json")

	// Engine deliberately unresolvable, exactly as in the fatal test...
	t.Setenv("FENDIX_ENGINE", filepath.Join(dir, "no-such-engine"))

	cfg := &models.ScanConfig{
		// ...but SAST was only IMPLICITLY enabled by --code (Explicit=false).
		CodePath:             dir,
		PythonEngine:         true,
		PythonEngineExplicit: false,
		Fast:                 true, // keep it quick: skip semgrep/native SCA
		Workers:              2,
		Timeout:              10,
		Format:               "json",
		OutputPath:           outputPath,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())

	// Must NOT hard-fail (exit 2) — it degrades to the native-Go scanners.
	if exitCode == 2 {
		t.Fatalf("an implicit --code scan must not hard-fail on a missing Python engine; got exit 2")
	}
	// engineErr must be nil — the implicit path does not promote the missing
	// engine to a fatal error.
	if orch.engineErr != nil {
		t.Fatalf("implicit --code scan must not record a fatal engine error, got: %v", orch.engineErr)
	}
	// A report must be written — we still ran (native-Go) scanners.
	if _, err := os.ReadFile(outputPath); err != nil {
		t.Fatalf("expected a report to be written for the degraded implicit scan: %v", err)
	}
}
