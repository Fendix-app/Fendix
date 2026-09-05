package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// codeAnalyzers are the base entries every --code scan must record once.
var codeAnalyzers = []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm, AnalyzerPythonEngine, AnalyzerPlugins}

func writeCodeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nprint(os.environ.get('X'))\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func countByName(report reporters.JSONReport) map[string]int {
	counts := map[string]int{}
	for _, s := range report.Metadata.ScannerStatus {
		counts[s.Name]++
	}
	return counts
}

// TestOrchestrator_CodeAnalyzersRecordedExactlyOnce is the registry
// invariant (spec §10): whatever the flag combination, each base code
// analyzer appears exactly once, with a reason when not ok. Offline mode
// with no snapshot keeps the dependency scanners off the network.
func TestOrchestrator_CodeAnalyzersRecordedExactlyOnce(t *testing.T) {
	dir := writeCodeDir(t)
	for _, tc := range []struct {
		name string
		mut  func(cfg *models.ScanConfig)
	}{
		{"default", func(cfg *models.ScanConfig) {}},
		{"fast", func(cfg *models.ScanConfig) { cfg.Fast = true }},
		{"no-native-deps", func(cfg *models.ScanConfig) { cfg.NoNativeDeps = true }},
		{"no-plugins", func(cfg *models.ScanConfig) { cfg.NoPlugins = true }},
		{"python-engine-off", func(cfg *models.ScanConfig) { cfg.PythonEngine = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.json")
			cfg := &models.ScanConfig{
				CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
				Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"),
			}
			tc.mut(cfg)
			if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
				t.Fatalf("exit %d, want 0 (no strict flags set)", code)
			}
			counts := countByName(readReport(t, out))
			for _, name := range codeAnalyzers {
				if counts[name] != 1 {
					t.Errorf("%s recorded %d times, want exactly 1 (entries: %v)", name, counts[name], counts)
				}
			}
			for _, s := range readReport(t, out).Metadata.ScannerStatus {
				if s.State != reporters.ScannerOK && !s.Reason.Valid() {
					t.Errorf("%s is %s without a valid reason", s.Name, s.State)
				}
				if s.State == reporters.ScannerOK && s.Reason != "" {
					t.Errorf("%s is ok but carries reason %q", s.Name, s.Reason)
				}
			}
		})
	}
}

func TestOrchestrator_FastAndNoNativeDepsRecordDisabled(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: true}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	for _, name := range []string{AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
		s, ok := statusFor(report, name)
		if !ok || s.State != reporters.ScannerSkipped || s.Reason != reporters.ReasonDisabledByFlag {
			t.Errorf("%s under --fast = %+v, want skipped/disabled_by_flag", name, s)
		}
	}
}

func TestOrchestrator_PipNoManifestIsNotApplicable(t *testing.T) {
	dir := writeCodeDir(t) // has app.py, no requirements.txt
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	s, ok := statusFor(readReport(t, out), AnalyzerPip)
	if !ok || s.State != reporters.ScannerSkipped || s.Reason != reporters.ReasonNotApplicable {
		t.Fatalf("pip with no manifest = %+v, want skipped/not_applicable (was ok before the contract)", s)
	}
}

func TestOrchestrator_UnreadableCodePathIsInputErrorEverywhere(t *testing.T) {
	file := filepath.Join(t.TempDir(), "code.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: file, Workers: 1, Timeout: 5, Format: "json", OutputPath: out}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d, want 0: input_error changes recording, not the default exit", code)
	}
	report := readReport(t, out)
	for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
		s, ok := statusFor(report, name)
		if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonInputError {
			t.Errorf("%s = %+v, want failed/input_error", name, s)
		}
	}
}
