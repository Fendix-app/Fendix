package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/managedci"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// goModuleWithoutGoCommand writes a Go module and empties PATH, so the go
// command govulncheck loads packages through cannot run. It is the state a
// runner without a Go toolchain is in, and the same class of failure as a
// toolchain the engine cannot type-check: a Go module that went unscanned.
func goModuleWithoutGoCommand(t *testing.T) string {
	t.Helper()
	code := filepath.Join(t.TempDir(), "code")
	if err := os.MkdirAll(code, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.25\n",
		"main.go": "package main\n\nfunc main() {}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(code, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", t.TempDir())
	return code
}

// A govulncheck that could not run is a FAILED analyzer with a closed
// failure reason and the go command's own diagnosis — never not_applicable
// (x/vuln says "no go.mod file"), never ok-with-no-findings — and missing SCA
// coverage can never let a run pass: the local gates exit 2, and the managed
// evidence reports sca failed and unobserved, which the contract's release
// policy can only turn into INCOMPLETE (required_analyzer_failed).
func TestUnrunnableGovulncheckNeverPasses(t *testing.T) {
	cases := []struct {
		name     string
		cfg      func(*models.ScanConfig)
		wantExit int
	}{
		// The managed Action passes neither gate: the backend decides.
		{"managed evidence only", func(*models.ScanConfig) {}, 0},
		{"--require-analyzers govulncheck", func(c *models.ScanConfig) { c.RequiredAnalyzers = []string{AnalyzerGovulncheck} }, 2},
		{"--fail-on-coverage-gap", func(c *models.ScanConfig) { c.FailOnCoverageGap = true }, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := goModuleWithoutGoCommand(t)
			dir := t.TempDir()
			cfg := &models.ScanConfig{
				CodePath:            code,
				Workers:             1,
				Timeout:             10,
				Format:              "json",
				OutputPath:          filepath.Join(dir, "report.json"),
				NoPlugins:           true,
				EnforceConfidence:   true,
				DeescalateTests:     true,
				ManagedEvidencePath: filepath.Join(dir, "evidence.json"),
				ManagedContextPath:  writeContext(t, validContext),
			}
			tc.cfg(cfg)
			if got := NewOrchestrator(cfg, "v3.5.0").Run(context.Background()); got != tc.wantExit {
				t.Fatalf("exit = %d, want %d", got, tc.wantExit)
			}

			report := readReport(t, cfg.OutputPath)
			gv, ok := statusFor(report, AnalyzerGovulncheck)
			if !ok {
				t.Fatal("govulncheck has no scanner_status entry")
			}
			if gv.State != reporters.ScannerFailed || gv.Reason != reporters.ReasonExecutionError {
				t.Fatalf("govulncheck = %s/%s (%s), want failed/execution_error", gv.State, gv.Reason, gv.Detail)
			}
			if strings.Contains(gv.Detail, "no go.mod") || !strings.Contains(gv.Detail, "go command") {
				t.Errorf("detail %q must name the go command, not a missing go.mod", gv.Detail)
			}
			cov := report.Metadata.Coverage
			if cov == nil || cov.ConfiguredComplete || !slices.Contains(cov.Gaps, AnalyzerGovulncheck) {
				t.Errorf("coverage = %+v, want govulncheck recorded as a gap", cov)
			}

			raw, err := os.ReadFile(cfg.ManagedEvidencePath)
			if err != nil {
				t.Fatalf("read evidence: %v", err)
			}
			var submission managedci.Submission
			if err := json.Unmarshal(raw, &submission); err != nil {
				t.Fatalf("decode evidence: %v", err)
			}
			// The contract satisfies a required analyzer ONLY with status
			// completed AND presence in observed_analyzers.
			sca := analyzerByID(submission.Manifest.Analyzers, managedci.AnalyzerSCA)
			if sca == nil || sca.Status != "failed" || sca.ReasonCode != "execution_error" {
				t.Fatalf("sca analyzer = %+v, want failed/execution_error", sca)
			}
			if slices.Contains(submission.Manifest.Coverage.ObservedAnalyzers, managedci.AnalyzerSCA) {
				t.Errorf("sca is observed although govulncheck never loaded the module: %v", submission.Manifest.Coverage.ObservedAnalyzers)
			}
			gap := false
			for _, g := range submission.Manifest.Coverage.Gaps {
				gap = gap || g.AnalyzerID == managedci.AnalyzerSCA
			}
			if !gap {
				t.Errorf("no sca coverage gap in %+v", submission.Manifest.Coverage.Gaps)
			}
		})
	}
}
