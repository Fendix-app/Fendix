package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/pip"
)

// TestOrchestrator_ContinuesAfterOSVOutage pins the orchestrator's
// continue-on-error contract: when OSV.dev is wholly unavailable,
// the dep-CVE scanner logs and continues; the rest of the scan
// (secrets in particular) still produces findings and the scan
// exits 0 with a non-empty report.
//
// This guards against a future refactor that accidentally bubbles
// dep-CVE errors up as fatal. The audit's #4 recommended addition
// (OSV fault injection) maps to this test: it exercises the
// `default: slog.Warn` branch at orchestrator.go around line 244
// and confirms it doesn't stop the scan.
func TestOrchestrator_ContinuesAfterOSVOutage(t *testing.T) {
	// OSV.dev returns 503 on every request — total outage.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer osvSrv.Close()
	restore := pip.SetOSVAPIBaseForTest(osvSrv.URL)
	defer restore()

	// Isolate the OSV cache to a tmpdir so a previous test run's
	// cached results can't satisfy this scan.
	t.Setenv("HOME", t.TempDir())

	// A code path that has both a requirements.txt (so pip.Scan
	// runs) AND a hardcoded secret (so secrets.Scan finds
	// something). The orchestrator must produce the secret finding
	// regardless of OSV.dev's state.
	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\nrequests==2.20.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(codeDir, "secret.py"), []byte(`
# A deliberately-leaked secret for fendix to find.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
`), 0o644); err != nil {
		t.Fatalf("write secret.py: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath:   codeDir,
		Workers:    2,
		Timeout:    10,
		Format:     "json",
		OutputPath: outputPath,
	}

	orch := NewOrchestrator(cfg, "test")
	exitCode := orch.Run(context.Background())
	if exitCode != 0 {
		t.Fatalf("orchestrator must exit 0 even with OSV outage; got %d", exitCode)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse report: %v", err)
	}

	// The hardcoded AWS_ACCESS_KEY must surface despite OSV being
	// down. If the orchestrator panicked or bailed on the pip
	// error, secrets.Scan would never run and Total would be 0.
	if report.Total == 0 {
		t.Fatal("scan returned no findings; orchestrator likely bailed on pip error instead of continuing")
	}
	var sawAWSKey bool
	for _, f := range report.Findings {
		if f.ID == "SEC-AWS_ACCESS_KEY" || // current ID shape
			(f.Category == "secrets" && f.Title != "" && contains(f.Title, "AWS")) {
			sawAWSKey = true
			break
		}
	}
	if !sawAWSKey {
		t.Errorf("expected an AWS-access-key finding from secrets.Scan despite OSV outage; got %d findings, none matching", report.Total)
		for i, f := range report.Findings {
			t.Logf("  [%d] %s — %s", i, f.ID, f.Title)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
