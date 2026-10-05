package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

func TestApplyBaselineDiff_NewFindings(t *testing.T) {
	dir := t.TempDir()

	// Create baseline with 2 findings
	baseline := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
		{ID: "SEC-002", Title: "CORS wildcard", Endpoint: "/api/config", Category: "cors"},
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	data, _ := json.Marshal(baseline)
	os.WriteFile(baselinePath, data, 0644)

	// Current scan has 3 findings — 2 old + 1 new
	current := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
		{ID: "SEC-002", Title: "CORS wildcard", Endpoint: "/api/config", Category: "cors"},
		{ID: "SEC-003", Title: "SQL injection", Endpoint: "/api/search", Category: "injection"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(result))
	}
	if result[0].Title != "SQL injection" {
		t.Errorf("expected 'SQL injection', got '%s'", result[0].Title)
	}
}

func TestApplyBaselineDiff_AllNew(t *testing.T) {
	dir := t.TempDir()

	baseline := []models.Finding{}
	baselinePath := filepath.Join(dir, "baseline.json")
	data, _ := json.Marshal(baseline)
	os.WriteFile(baselinePath, data, 0644)

	current := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1", Endpoint: "/a", Category: "headers"},
		{ID: "SEC-002", Title: "Finding 2", Endpoint: "/b", Category: "cors"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings (all new), got %d", len(result))
	}
}

func TestApplyBaselineDiff_AllKnown(t *testing.T) {
	dir := t.TempDir()

	baseline := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	data, _ := json.Marshal(baseline)
	os.WriteFile(baselinePath, data, 0644)

	current := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 0 {
		t.Fatalf("expected 0 new findings, got %d", len(result))
	}
}

func TestApplyBaselineDiff_JSONReportFormat(t *testing.T) {
	dir := t.TempDir()

	// Baseline in JSONReport format (as produced by --output)
	report := reporters.JSONReport{
		Findings: []models.Finding{
			{ID: "SEC-001", Title: "Old finding", Endpoint: "/api/old", Category: "headers"},
		},
		Total: 1,
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	data, _ := json.Marshal(report)
	os.WriteFile(baselinePath, data, 0644)

	current := []models.Finding{
		{ID: "SEC-001", Title: "Old finding", Endpoint: "/api/old", Category: "headers"},
		{ID: "SEC-002", Title: "New finding", Endpoint: "/api/new", Category: "cors"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(result))
	}
	if result[0].Title != "New finding" {
		t.Errorf("expected 'New finding', got '%s'", result[0].Title)
	}
}

func TestApplyBaselineDiff_MissingFile(t *testing.T) {
	current := []models.Finding{
		{ID: "SEC-001", Title: "Finding", Endpoint: "/a", Category: "headers"},
	}

	// Missing baseline file should return all findings
	result := ApplyBaselineDiff(current, "/nonexistent/baseline.json")
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (missing baseline = no diff), got %d", len(result))
	}
}

func TestApplyBaselineDiff_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	os.WriteFile(baselinePath, []byte("not json"), 0644)

	current := []models.Finding{
		{ID: "SEC-001", Title: "Finding", Endpoint: "/a", Category: "headers"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (invalid baseline = no diff), got %d", len(result))
	}
}

func TestApplyBaselineDiff_DifferentIDs(t *testing.T) {
	dir := t.TempDir()

	// Same finding but different IDs — should still match by title+endpoint+category
	baseline := []models.Finding{
		{ID: "SEC-005", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
	}
	baselinePath := filepath.Join(dir, "baseline.json")
	data, _ := json.Marshal(baseline)
	os.WriteFile(baselinePath, data, 0644)

	current := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"},
	}

	result := ApplyBaselineDiff(current, baselinePath)
	if len(result) != 0 {
		t.Fatalf("expected 0 findings (same finding different ID), got %d", len(result))
	}
}

func TestApplyBaselineDiffStrict_MissingIsFailOpen(t *testing.T) {
	current := []models.Finding{
		{Title: "Finding", Endpoint: "/a", Category: "headers"},
	}
	// A missing baseline is the legitimate first run: no error, all findings.
	result, err := ApplyBaselineDiffStrict(current, "/nonexistent/baseline.json")
	if err != nil {
		t.Fatalf("missing baseline must NOT error (fail-open first run), got %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (missing baseline = no diff), got %d", len(result))
	}
}

func TestApplyBaselineDiffStrict_CorruptIsFailClosed(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")
	os.WriteFile(baselinePath, []byte("not json"), 0644)

	current := []models.Finding{
		{Title: "Finding", Endpoint: "/a", Category: "headers"},
	}
	// A corrupt baseline is a misconfiguration: the strict variant must
	// surface an error so the orchestrator can exit 2 instead of silently
	// scanning without the diff.
	result, err := ApplyBaselineDiffStrict(current, baselinePath)
	if err == nil {
		t.Fatal("corrupt baseline must error (fail-closed), got nil")
	}
	if len(result) != 1 {
		t.Fatalf("on error, strict variant returns the original findings unchanged; got %d", len(result))
	}
}

func TestSaveBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	findings := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1", Severity: models.SeverityHigh, Endpoint: "/a", Category: "headers"},
		{ID: "SEC-002", Title: "Finding 2", Severity: models.SeverityMedium, Endpoint: "/b", Category: "cors"},
	}

	if err := SaveBaseline(findings, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading saved baseline: %v", err)
	}

	var loaded []models.Finding
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parsing saved baseline: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 findings in saved baseline, got %d", len(loaded))
	}
	if loaded[0].Title != "Finding 1" {
		t.Errorf("expected 'Finding 1', got '%s'", loaded[0].Title)
	}
}

func TestSaveBaseline_InvalidPath(t *testing.T) {
	err := SaveBaseline(nil, "/nonexistent/dir/baseline.json")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestFindingKey(t *testing.T) {
	f1 := models.Finding{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"}
	f2 := models.Finding{ID: "SEC-999", Title: "Missing HSTS", Endpoint: "/api/users", Category: "headers"}
	f3 := models.Finding{ID: "SEC-001", Title: "CORS issue", Endpoint: "/api/users", Category: "cors"}

	if findingKey(f1) != findingKey(f2) {
		t.Error("same title+endpoint+category should produce same key regardless of ID")
	}
	if findingKey(f1) == findingKey(f3) {
		t.Error("different title+category should produce different keys")
	}
}
