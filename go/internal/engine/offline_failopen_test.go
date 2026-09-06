package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/offline"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// writeOfflineSnapshot writes a snapshot with one vulnerable PyPI flask
// advisory and returns its path.
func writeOfflineSnapshot(t *testing.T, dir string) string {
	t.Helper()
	snap := offline.FromOSVExport([]offline.Advisory{{
		ID:      "GHSA-flask-ssrf",
		Aliases: []string{"CVE-2026-1111"},
		Package: offline.PackageRef{Ecosystem: "PyPI", Name: "flask"},
		Ranges:  []offline.Range{{Introduced: "0.0.0", Fixed: "2.3.0"}},
		Summary: "Flask SSRF",
	}}, []string{"osv.dev"})
	path := filepath.Join(dir, "offline-db.json")
	if err := offline.Write(path, snap); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	return path
}

func readReport(t *testing.T, path string) reporters.JSONReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	return report
}

func statusFor(report reporters.JSONReport, name string) (reporters.ScannerStatus, bool) {
	for _, s := range report.Metadata.ScannerStatus {
		if s.Name == name {
			return s, true
		}
	}
	return reporters.ScannerStatus{}, false
}

// TestOrchestrator_OfflineRoutesPipThroughSnapshot verifies F-M4/F-H4:
// with --offline + a snapshot, the pip dep-CVE scanner finds the
// vulnerable pin from the snapshot (no network), govulncheck is recorded
// SKIPPED, and the finding lands in the report.
func TestOrchestrator_OfflineRoutesPipThroughSnapshot(t *testing.T) {
	dir := t.TempDir()
	codeDir := filepath.Join(dir, "code")
	if err := os.MkdirAll(codeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"), []byte("flask==2.2.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dbPath := writeOfflineSnapshot(t, dir)
	outPath := filepath.Join(dir, "report.json")

	cfg := &models.ScanConfig{
		CodePath:      codeDir,
		Workers:       1,
		Timeout:       10,
		Format:        "json",
		OutputPath:    outPath,
		Offline:       true,
		OfflineDBPath: dbPath,
	}
	orch := NewOrchestrator(cfg, "dev")
	if code := orch.Run(context.Background()); code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	report := readReport(t, outPath)

	// The flask CVE must be present, sourced from the offline snapshot.
	foundFlask := false
	for _, f := range report.Findings {
		if f.Category == "deps" && f.Title != "" && f.ID != "" {
			for _, r := range f.References {
				if r == "GHSA-flask-ssrf" || r == "CVE-2026-1111" {
					foundFlask = true
				}
			}
		}
	}
	if !foundFlask {
		t.Errorf("expected flask CVE from offline snapshot in findings; got %+v", report.Findings)
	}

	// govulncheck must be recorded SKIPPED in offline mode (needs vuln.go.dev).
	gv, ok := statusFor(report, "govulncheck")
	if !ok {
		t.Fatal("expected govulncheck status to be recorded")
	}
	if gv.State != reporters.ScannerSkipped {
		t.Errorf("govulncheck state = %q; want skipped", gv.State)
	}

	// pip must be recorded ok.
	if pipS, ok := statusFor(report, "pip"); !ok || pipS.State != reporters.ScannerOK {
		t.Errorf("pip status = %+v, ok=%v; want ok", pipS, ok)
	}
}

// TestOrchestrator_OfflineNoSnapshotSkipsDepScanners verifies that when
// --offline is set but no usable snapshot exists, the dep scanners are
// SKIPPED rather than silently hitting the network.
func TestOrchestrator_OfflineNoSnapshotSkipsDepScanners(t *testing.T) {
	dir := t.TempDir()
	codeDir := filepath.Join(dir, "code")
	if err := os.MkdirAll(codeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"), []byte("flask==2.2.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "report.json")

	cfg := &models.ScanConfig{
		CodePath:      codeDir,
		Workers:       1,
		Timeout:       10,
		Format:        "json",
		OutputPath:    outPath,
		Offline:       true,
		OfflineDBPath: filepath.Join(dir, "does-not-exist.json"),
	}
	orch := NewOrchestrator(cfg, "dev")
	if code := orch.Run(context.Background()); code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	report := readReport(t, outPath)
	for _, name := range []string{"govulncheck", "pip", "npm"} {
		s, ok := statusFor(report, name)
		if !ok {
			t.Errorf("expected %s status recorded", name)
			continue
		}
		if s.State != reporters.ScannerSkipped {
			t.Errorf("%s state = %q; want skipped (no snapshot, offline)", name, s.State)
		}
	}
	// No flask finding should appear — we did not reach the network.
	for _, f := range report.Findings {
		if f.Category == "deps" {
			t.Errorf("unexpected deps finding without snapshot: %+v", f)
		}
	}
}

// TestOrchestrator_FailOnScannerError verifies F-L7/F-L13: a scanner that
// runs and errors forces exit 2 when --fail-on-scanner-error is set, and a
// clean exit (0) when it is not. Pointing --code at a regular file (not a
// directory) makes validateCodePath reject it up front and record every
// code analyzer (secrets included) failed/input_error before any of them
// runs — deterministic and network-free.
func TestOrchestrator_FailOnScannerError(t *testing.T) {
	dir := t.TempDir()
	// A regular file as the code path: validateCodePath rejects it before
	// secrets (or any other code analyzer) ever runs, recording each one
	// failed/input_error (see TestOrchestrator_UnreadableCodePathIsInputErrorEverywhere).
	codeFile := filepath.Join(dir, "code.txt")
	if err := os.WriteFile(codeFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	// Without the flag: scanner failure is recorded but the run still
	// exits 0 (no findings at/above any threshold).
	cfgOff := &models.ScanConfig{
		CodePath:   codeFile,
		Workers:    1,
		Timeout:    10,
		Format:     "json",
		OutputPath: filepath.Join(dir, "report-off.json"),
	}
	if code := NewOrchestrator(cfgOff, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("without --fail-on-scanner-error: expected exit 0, got %d", code)
	}
	report := readReport(t, cfgOff.OutputPath)
	if s, ok := statusFor(report, "secrets"); !ok || s.State != reporters.ScannerFailed {
		t.Fatalf("expected secrets recorded failed, got %+v ok=%v", s, ok)
	}

	// With the flag: the same recorded failure forces exit 2.
	cfgOn := &models.ScanConfig{
		CodePath:           codeFile,
		Workers:            1,
		Timeout:            10,
		Format:             "json",
		OutputPath:         filepath.Join(dir, "report-on.json"),
		FailOnScannerError: true,
	}
	if code := NewOrchestrator(cfgOn, "dev").Run(context.Background()); code != 2 {
		t.Fatalf("with --fail-on-scanner-error: expected exit 2, got %d", code)
	}
}

// TestOrchestrator_IgnoreParseFailureExits2 verifies F-L14: an
// explicit-but-unparseable --ignore file is a hard error (exit 2).
func TestOrchestrator_IgnoreParseFailureExits2(t *testing.T) {
	dir := t.TempDir()
	codeDir := filepath.Join(dir, "code")
	if err := os.MkdirAll(codeDir, 0755); err != nil {
		t.Fatal(err)
	}
	// A code-only scan with no manifests still runs secrets/semgrep/textscan.
	if err := os.WriteFile(filepath.Join(codeDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Malformed YAML — a list where a mapping is expected.
	ignorePath := filepath.Join(dir, ".fendix-ignore")
	if err := os.WriteFile(ignorePath, []byte("ignore: [this is: not: valid: yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &models.ScanConfig{
		CodePath:   codeDir,
		Workers:    1,
		Timeout:    10,
		Format:     "json",
		OutputPath: filepath.Join(dir, "report.json"),
		IgnorePath: ignorePath,
	}
	orch := NewOrchestrator(cfg, "dev")
	if code := orch.Run(context.Background()); code != 2 {
		t.Fatalf("expected exit 2 for unparseable --ignore, got %d", code)
	}
}

// TestOrchestrator_SaveBaselineFailureExits2 verifies F-L14: a failed
// --save-baseline write is a hard error (exit 2).
func TestOrchestrator_SaveBaselineFailureExits2(t *testing.T) {
	dir := t.TempDir()
	codeDir := filepath.Join(dir, "code")
	if err := os.MkdirAll(codeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codeDir, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Point --save-baseline at a path whose parent is a regular file, so
	// the write must fail.
	notADir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notADir, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &models.ScanConfig{
		CodePath:         codeDir,
		Workers:          1,
		Timeout:          10,
		Format:           "json",
		OutputPath:       filepath.Join(dir, "report.json"),
		SaveBaselinePath: filepath.Join(notADir, "baseline.json"),
	}
	orch := NewOrchestrator(cfg, "dev")
	if code := orch.Run(context.Background()); code != 2 {
		t.Fatalf("expected exit 2 for failed --save-baseline, got %d", code)
	}
}
