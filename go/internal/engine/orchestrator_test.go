package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// newVulnerableServer creates a mock API server with deliberate security issues
// for integration testing the full scan pipeline.
func newVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		// Missing security headers, password in response, no rate limiting
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Server", "nginx/1.21.3")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":1,"username":"admin","password":"hunter2","email":"admin@test.com"}]`)
	})

	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		// Origin-REFLECTING CORS with credentials — the exploitable shape, and
		// this fixture's only CRITICAL. It used to serve `ACAO: *` with
		// credentials, which reads as worse but is inert: the Fetch standard
		// forbids the wildcard under credentials mode `include`, so browsers
		// reject it and no cross-origin read occurs. That pair is now graded
		// MEDIUM as a configuration-only observation, which left this fixture
		// with nothing CRITICAL in it and silently stopped
		// TestOrchestrator_FailOnThreshold from exercising the gate it names.
		// Reflection is the shape that genuinely warrants CRITICAL.
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"api_key":"sk-live-1234567890abcdef","debug":true}`)
	})

	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		// Properly secured endpoint
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/api/v1/debug", func(w http.ResponseWriter, r *http.Request) {
		// Stack trace and internal IP
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"Traceback (most recent call last):\n  File \"app.py\"","server":"10.0.1.42"}`)
	})

	return httptest.NewServer(mux)
}

func TestOrchestrator_IntegrationScan(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: List users
  /api/v1/config:
    get:
      summary: Get config
  /api/v1/health:
    get:
      summary: Health check
  /api/v1/debug:
    get:
      summary: Debug info
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "json",
		OutputPath: outputPath,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// Read and parse output
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}

	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing report: %v", err)
	}

	// Verify findings exist
	if report.Total == 0 {
		t.Fatal("expected findings from vulnerable server, got 0")
	}

	// Check for expected finding types
	findingTitles := make(map[string]bool)
	for _, f := range report.Findings {
		findingTitles[f.Title] = true
	}

	expectedFindings := []string{
		"Password exposed in API response",
		"X-Powered-By header discloses technology",
		"Server version disclosed in header",
	}
	for _, title := range expectedFindings {
		if !findingTitles[title] {
			t.Errorf("missing expected finding: %s", title)
		}
	}

	// Verify sequential IDs
	for i, f := range report.Findings {
		expectedID := fmt.Sprintf("SEC-%03d", i+1)
		if f.ID != expectedID {
			t.Errorf("finding %d: expected ID %s, got %s", i, expectedID, f.ID)
		}
	}

	// Verify metadata
	if report.Metadata.Target != server.URL {
		t.Errorf("unexpected target: %s", report.Metadata.Target)
	}
}

func TestOrchestrator_HTMLOutput(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.html")
	os.WriteFile(specPath, []byte(spec), 0644)

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "html",
		OutputPath: outputPath,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading HTML report: %v", err)
	}

	html := string(data)
	if len(html) < 100 {
		t.Fatal("HTML report too short")
	}
}

func TestOrchestrator_FailOnThreshold(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	os.WriteFile(specPath, []byte(spec), 0644)

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "json",
		OutputPath: filepath.Join(dir, "report.json"),
		FailOn:     "CRITICAL",
		// A directly-constructed ScanConfig zero-values EnforceConfidence,
		// which is the LEGACY mapping — so without this the assertion below
		// would silently stop exercising the shipped gate. The findings the
		// vulnerable server produces are Source=blackbox on 200 responses (no
		// 4xx/static-asset penalty), so they are corroborated by the live
		// runtime observation and must still exit 1. If this goes to 0, the
		// corroboration predicate is wrong, not the test.
		EnforceConfidence: true,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())
	if exitCode != 1 {
		t.Fatalf("expected exit code 1 for --fail-on CRITICAL (credentialed origin reflection on /api/v1/config), got %d", exitCode)
	}
}

func TestOrchestrator_NoEndpoints(t *testing.T) {
	cfg := &models.ScanConfig{
		Timeout: 10,
		Workers: 1,
	}

	orch := NewOrchestrator(cfg, "dev")
	exitCode := orch.Run(context.Background())
	if exitCode != 2 {
		t.Fatalf("expected exit code 2 for no endpoints, got %d", exitCode)
	}
}

func TestOrchestrator_HybridScanWithMockEngine(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	// Write a mock Python engine that emits whitebox findings
	engineDir := t.TempDir()
	mockEngine := `import json, sys
sys.stdin.read()
findings = [
    {
        "id": "",
        "title": "Missing auth decorator on users endpoint",
        "severity": "HIGH",
        "source": "whitebox",
        "category": "auth",
        "endpoint": "routes/users.py:10",
        "evidence": "No @login_required on get_users()",
        "fix": "Add @login_required decorator",
        "references": ["CWE-862"],
        "confidence": "HIGH",
        "line": "routes/users.py:10"
    },
    {
        "id": "",
        "title": "Hardcoded API key",
        "severity": "CRITICAL",
        "source": "whitebox",
        "category": "secrets",
        "endpoint": "config/settings.py:5",
        "evidence": "API_KEY = 'sk-live-...'",
        "fix": "Use environment variable",
        "references": ["CWE-798"],
        "confidence": "HIGH",
        "line": "config/settings.py:5"
    }
]
for f in findings:
    print(json.dumps(f), flush=True)
print(json.dumps({"done": True, "total": len(findings)}), flush=True)
`
	os.WriteFile(filepath.Join(engineDir, "engine.py"), []byte(mockEngine), 0755)

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: List users
  /api/v1/config:
    get:
      summary: Get config
  /api/v1/health:
    get:
      summary: Health check
  /api/v1/debug:
    get:
      summary: Debug info
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.json")
	os.WriteFile(specPath, []byte(spec), 0644)

	cfg := &models.ScanConfig{
		URL:          server.URL,
		SpecPath:     specPath,
		CodePath:     engineDir, // triggers whitebox scan
		Workers:      2,
		Timeout:      10,
		DelayMs:      0,
		Format:       "json",
		OutputPath:   outputPath,
		PythonEngine: true, // TASK-118: opt back into Python whitebox path for this hybrid test
	}

	spawner := NewPythonSpawner("python3", engineDir)
	orch := NewOrchestratorWithSpawner(cfg, spawner)
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// Read and parse output
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}

	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing report: %v", err)
	}

	// Should have blackbox + whitebox findings
	if report.Total == 0 {
		t.Fatal("expected findings from hybrid scan, got 0")
	}

	// Check for whitebox findings
	hasWhiteboxFinding := false
	hasCorrelatedFinding := false
	for _, f := range report.Findings {
		if f.Source == models.SourceWhitebox {
			hasWhiteboxFinding = true
		}
		if f.Source == models.SourceCorrelated {
			hasCorrelatedFinding = true
		}
	}

	if !hasWhiteboxFinding && !hasCorrelatedFinding {
		t.Error("expected at least one whitebox or correlated finding from hybrid scan")
	}

	// Verify sequential IDs
	for i, f := range report.Findings {
		expectedID := fmt.Sprintf("SEC-%03d", i+1)
		if f.ID != expectedID {
			t.Errorf("finding %d: expected ID %s, got %s", i, expectedID, f.ID)
		}
	}
}

func TestOrchestrator_IgnoreRulesIntegration(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath := filepath.Join(dir, "report.json")
	os.WriteFile(specPath, []byte(spec), 0644)

	// Write ignore file that suppresses all headers findings
	ignoreContent := `
ignore:
  - category: headers
    reason: "Headers handled by reverse proxy"
`
	ignorePath := filepath.Join(dir, ".fendix-ignore")
	os.WriteFile(ignorePath, []byte(ignoreContent), 0644)

	cfg := &models.ScanConfig{
		URL:        server.URL,
		SpecPath:   specPath,
		Workers:    2,
		Timeout:    10,
		DelayMs:    0,
		Format:     "json",
		OutputPath: outputPath,
		IgnorePath: ignorePath,
	}

	orch := NewOrchestrator(cfg, "dev")
	orch.Run(context.Background())

	data, _ := os.ReadFile(outputPath)
	var report reporters.JSONReport
	json.Unmarshal(data, &report)

	for _, f := range report.Findings {
		if f.Category == "headers" {
			t.Errorf("headers findings should be suppressed by ignore rule, found: %s", f.Title)
		}
	}
}

func TestOrchestrator_BaselineDiffIntegration(t *testing.T) {
	server := newVulnerableServer()
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /api/v1/users:
    get:
      summary: test
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	outputPath1 := filepath.Join(dir, "report1.json")
	baselinePath := filepath.Join(dir, "baseline.json")

	os.WriteFile(specPath, []byte(spec), 0644)

	// First scan — save baseline
	cfg1 := &models.ScanConfig{
		URL:              server.URL,
		SpecPath:         specPath,
		Workers:          2,
		Timeout:          10,
		DelayMs:          0,
		Format:           "json",
		OutputPath:       outputPath1,
		SaveBaselinePath: baselinePath,
	}

	orch1 := NewOrchestrator(cfg1, "dev")
	orch1.Run(context.Background())

	// Verify baseline was saved
	if _, err := os.Stat(baselinePath); os.IsNotExist(err) {
		t.Fatal("baseline file was not created")
	}
	baselineData, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("reading baseline: %v", err)
	}
	var baseline []models.Finding
	if err := json.Unmarshal(baselineData, &baseline); err != nil {
		t.Fatalf("parsing baseline: %v", err)
	}
	if len(baseline) == 0 {
		t.Fatal("baseline file contained no findings")
	}

	// Second scan — diff against baseline (same server = same findings)
	outputPath2 := filepath.Join(dir, "report2.json")
	cfg2 := &models.ScanConfig{
		URL:          server.URL,
		SpecPath:     specPath,
		Workers:      2,
		Timeout:      10,
		DelayMs:      0,
		Format:       "json",
		OutputPath:   outputPath2,
		BaselinePath: baselinePath,
	}

	orch2 := NewOrchestrator(cfg2, "dev")
	orch2.Run(context.Background())

	data, _ := os.ReadFile(outputPath2)
	var report reporters.JSONReport
	json.Unmarshal(data, &report)

	// The exact finding set can vary slightly under the full package race suite
	// when scanner network probes contend for ephemeral ports. The integration
	// contract here is that the orchestrator wires baseline suppression in; the
	// exact key matching is covered by baseline_test.go.
	if report.Total >= len(baseline) {
		t.Errorf("expected baseline to suppress prior findings; got %d findings from baseline of %d", report.Total, len(baseline))
	}
}
