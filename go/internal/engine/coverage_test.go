package engine

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"
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

// osvFlaky answers 503 to the first `failures` requests, then a clean
// "no vulns" batch/query response.
func osvFlaky(t *testing.T, failures int) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if int(n.Add(1)) <= failures {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/v1/querybatch") {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[]}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
}

func pipScanConfig(t *testing.T, srvURL string) (*models.ScanConfig, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	t.Setenv("HOME", t.TempDir()) // fresh OSV cache
	return &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: false}, out
}

func TestOrchestrator_TransientPipFailureIsRetriedOnce(t *testing.T) {
	srv := osvFlaky(t, 2) // first batch 503, serial fallback 503 → attempt 1 fails; attempt 2 clean
	defer srv.Close()
	saved := pip.OSVBaseURL
	pip.OSVBaseURL = srv.URL
	defer func() { pip.OSVBaseURL = saved }()
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()

	cfg, out := pipScanConfig(t, srv.URL)
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	s, _ := statusFor(readReport(t, out), AnalyzerPip)
	if s.State != reporters.ScannerOK || s.Attempts != 2 {
		t.Fatalf("pip = %+v, want ok with attempts 2", s)
	}
}

func TestOrchestrator_PersistentPipFailureRecordsSecondAttempt(t *testing.T) {
	srv := osvFlaky(t, 1000)
	defer srv.Close()
	saved := pip.OSVBaseURL
	pip.OSVBaseURL = srv.URL
	defer func() { pip.OSVBaseURL = saved }()
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()

	cfg, out := pipScanConfig(t, srv.URL)
	NewOrchestrator(cfg, "dev").Run(context.Background())
	s, _ := statusFor(readReport(t, out), AnalyzerPip)
	if s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonNetworkError || s.Attempts != 2 {
		t.Fatalf("pip = %+v, want failed/network_error with attempts 2", s)
	}
}

func TestRetryTransient_DeterministicFailuresAreNotRetried(t *testing.T) {
	calls := 0
	_, attempts, err := retryTransient(context.Background(), "pip", func() ([]evidence.Evidence, error) {
		calls++
		return nil, errors.New("pip: parse requirements: bad line")
	})
	if calls != 1 || attempts != 1 || err == nil {
		t.Fatalf("deterministic error must run once: calls=%d attempts=%d err=%v", calls, attempts, err)
	}
	calls = 0
	_, attempts, _ = retryTransient(context.Background(), "pip", func() ([]evidence.Evidence, error) {
		calls++
		return nil, &neterr.StatusError{Host: "h", Code: 404}
	})
	if calls != 1 || attempts != 1 {
		t.Fatalf("404 is not transient: calls=%d attempts=%d", calls, attempts)
	}
}

func TestRetryTransient_SecondAttemptFindingsReplaceFirst(t *testing.T) {
	savedDelay := retryDelay
	retryDelay = 0
	defer func() { retryDelay = savedDelay }()
	calls := 0
	findings, attempts, err := retryTransient(context.Background(), "npm", func() ([]evidence.Evidence, error) {
		calls++
		if calls == 1 {
			return []evidence.Evidence{{ID: "SEC-PARTIAL"}}, &neterr.LookupError{Scanner: "npm", Failed: 1, Total: 2, Cause: &neterr.StatusError{Host: "h", Code: 503}}
		}
		return []evidence.Evidence{{ID: "SEC-A"}, {ID: "SEC-B"}}, nil
	})
	if err != nil || attempts != 2 || len(findings) != 2 || findings[0].ID != "SEC-A" {
		t.Fatalf("second attempt must be authoritative: findings=%v attempts=%d err=%v", findings, attempts, err)
	}
}

func TestOrchestrator_CoverageBlockPresentAndSorted(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json")}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	cov := report.Metadata.Coverage
	if cov == nil || cov.ContractVersion != 1 || cov.Strict {
		t.Fatalf("coverage = %+v", cov)
	}
	if report.Metadata.PolicyVersion != decision.PolicyVersion {
		t.Fatalf("policy_version = %q, want %q", report.Metadata.PolicyVersion, decision.PolicyVersion)
	}
	// offline with no snapshot: pip and npm are dependency_missing → gaps.
	// semgrep joins them wherever the binary isn't on PATH (this repo's own
	// CI never installs it — see .github/workflows/ci.yml — so the check
	// is done by real LookPath rather than assuming either state).
	wantGaps := []string{"pip", "npm"}
	if _, err := exec.LookPath("semgrep"); err != nil {
		wantGaps = append([]string{"semgrep"}, wantGaps...)
	}
	if cov.ConfiguredComplete || !reflect.DeepEqual(cov.Gaps, wantGaps) {
		t.Fatalf("gaps = %v, configured_complete = %v", cov.Gaps, cov.ConfiguredComplete)
	}
	var names []string
	for _, s := range report.Metadata.ScannerStatus {
		names = append(names, s.Name)
	}
	want := []string{"dast", "spec", "active-probes", "secrets", "textscan", "semgrep", "govulncheck", "pip", "npm", "python-engine", "plugins"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("entries are not in registry order: %v", names)
	}
}

func TestOrchestrator_FailOnCoverageGapExits2(t *testing.T) {
	dir := writeCodeDir(t)
	mk := func(strict bool) *models.ScanConfig {
		return &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: filepath.Join(t.TempDir(), "r.json"),
			Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"), FailOnCoverageGap: strict}
	}
	if code := NewOrchestrator(mk(false), "dev").Run(context.Background()); code != 0 {
		t.Fatalf("without the flag: exit %d, want 0", code)
	}
	if code := NewOrchestrator(mk(true), "dev").Run(context.Background()); code != 2 {
		t.Fatalf("with --fail-on-coverage-gap and a dependency_missing gap: exit %d, want 2", code)
	}
}

func TestOrchestrator_RequireAnalyzersIsStricterThanConfiguredComplete(t *testing.T) {
	dir := writeCodeDir(t)
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: out, Fast: true, RequiredAnalyzers: []string{"semgrep"}}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 2 {
		t.Fatalf("--fast --require-analyzers semgrep: exit %d, want 2", code)
	}
	cov := readReport(t, out).Metadata.Coverage
	if !cov.Strict || !cov.ConfiguredComplete || !reflect.DeepEqual(cov.RequiredGaps, []string{"semgrep"}) {
		t.Fatalf("coverage = %+v: --fast is not an engine gap, but semgrep was required and not delivered", cov)
	}

	cfg2 := &models.ScanConfig{CodePath: dir, Workers: 1, Timeout: 5, Format: "json", OutputPath: filepath.Join(t.TempDir(), "r2.json"), Fast: true, RequiredAnalyzers: []string{"secrets"}}
	if code := NewOrchestrator(cfg2, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("required secrets ran: exit %d, want 0", code)
	}
}

func TestPrintCoverageSummary_ListsEveryEntryAndTheVerdictLines(t *testing.T) {
	var buf bytes.Buffer
	status := scannerStatusList{
		{Name: "secrets", State: reporters.ScannerOK},
		{Name: "semgrep", State: reporters.ScannerSkipped, Reason: reporters.ReasonDisabledByFlag, Detail: "--fast"},
		{Name: "pip", State: reporters.ScannerOK, Attempts: 2},
	}
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(status), []string{"semgrep"}, true)
	printCoverageSummary(&buf, status, cov, true)
	out := buf.String()
	for _, want := range []string{"secrets", "semgrep", "disabled", "disabled_by_flag", "coverage: complete", "required: not delivered (semgrep)", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
	if got := describeGaps(status, []string{"semgrep"}); !strings.Contains(got, "disabled by --fast") {
		t.Errorf("describeGaps must name the contradiction, got %q", got)
	}
}
