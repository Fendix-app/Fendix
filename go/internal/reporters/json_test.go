package reporters

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func sampleFindings() []models.Finding {
	return []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /api/users", Confidence: models.ConfidenceHigh, References: []string{"CWE-319"}},
		{ID: "SEC-002", Title: "CORS wildcard", Severity: models.SeverityCritical, Source: models.SourceBlackbox, Category: "cors", Endpoint: "GET /api/data", Confidence: models.ConfidenceHigh, References: []string{"CWE-942"}},
		{ID: "SEC-003", Title: "No rate limiting", Severity: models.SeverityMedium, Source: models.SourceBlackbox, Category: "headers", Endpoint: "POST /api/login", Confidence: models.ConfidenceMedium, References: []string{"CWE-770"}},
		{ID: "SEC-004", Title: "Server version", Severity: models.SeverityInfo, Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /api/health", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-005", Title: "Password in response", Severity: models.SeverityCritical, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "GET /api/users/1", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-006", Title: "Internal IP", Severity: models.SeverityLow, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "GET /api/debug", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
		{ID: "SEC-007", Title: "Token exposed", Severity: models.SeverityHigh, Source: models.SourceBlackbox, Category: "data_exposure", Endpoint: "POST /api/auth", Confidence: models.ConfidenceHigh, References: []string{"CWE-200"}},
	}
}

func TestRenderJSON_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "dev",
	}

	err := RenderJSON(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.Total != 7 {
		t.Errorf("expected total 7, got %d", report.Total)
	}
	if report.Summary.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", report.Summary.Critical)
	}
	if report.Summary.High != 1 {
		t.Errorf("expected 1 high, got %d", report.Summary.High)
	}
	if report.Summary.Medium != 2 {
		t.Errorf("expected 2 medium, got %d", report.Summary.Medium)
	}
	if report.Summary.Low != 1 {
		t.Errorf("expected 1 low, got %d", report.Summary.Low)
	}
	if report.Summary.Info != 1 {
		t.Errorf("expected 1 info, got %d", report.Summary.Info)
	}
	if report.Metadata.Target != "https://api.example.com" {
		t.Errorf("unexpected target: %s", report.Metadata.Target)
	}

	// Verify source counts
	if report.Sources.Blackbox != 7 {
		t.Errorf("expected 7 blackbox sources, got %d", report.Sources.Blackbox)
	}
}

func TestRenderJSON_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderJSON(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.Total != 0 {
		t.Errorf("expected total 0, got %d", report.Total)
	}
}

func TestRenderJSON_PrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderJSON(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	output := buf.String()
	if len(output) < 50 {
		t.Fatal("output too short to be pretty-printed")
	}
	if output[0] != '{' {
		t.Error("expected JSON object output")
	}
}

func TestCountSeverities(t *testing.T) {
	findings := sampleFindings()
	counts := CountSeverities(findings)

	if counts.Critical != 2 || counts.High != 1 || counts.Medium != 2 || counts.Low != 1 || counts.Info != 1 {
		t.Errorf("unexpected counts: %+v", counts)
	}
}

func TestCountSeverities_Empty(t *testing.T) {
	counts := CountSeverities(nil)
	if counts.Critical != 0 || counts.High != 0 || counts.Medium != 0 || counts.Low != 0 || counts.Info != 0 {
		t.Errorf("expected all zeros, got %+v", counts)
	}
}

func TestCountSources(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Source: models.SourceBlackbox},
		{ID: "SEC-002", Source: models.SourceBlackbox},
		{ID: "SEC-003", Source: models.SourceWhitebox},
		{ID: "SEC-004", Source: models.SourceCorrelated},
		{ID: "SEC-005", Source: models.SourceCorrelated},
		{ID: "SEC-006", Source: models.SourceCorrelated},
	}
	counts := CountSources(findings)
	if counts.Blackbox != 2 {
		t.Errorf("expected 2 blackbox, got %d", counts.Blackbox)
	}
	if counts.Whitebox != 1 {
		t.Errorf("expected 1 whitebox, got %d", counts.Whitebox)
	}
	if counts.Correlated != 3 {
		t.Errorf("expected 3 correlated, got %d", counts.Correlated)
	}
}

func TestCountSources_Empty(t *testing.T) {
	counts := CountSources(nil)
	if counts.Blackbox != 0 || counts.Whitebox != 0 || counts.Correlated != 0 {
		t.Errorf("expected all zeros, got %+v", counts)
	}
}

func TestRenderJSON_IncludesSourceCounts(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:         "https://api.example.com",
		Version:        "dev",
		Mode:           "hybrid",
		EndpointsCount: 15,
		ActiveProbes:   true,
		ChecksRun:      []string{"headers", "cors", "injection"},
	}
	findings := []models.Finding{
		{ID: "SEC-001", Source: models.SourceBlackbox, Severity: models.SeverityHigh, References: []string{}},
		{ID: "SEC-002", Source: models.SourceWhitebox, Severity: models.SeverityMedium, References: []string{}},
		{ID: "SEC-003", Source: models.SourceCorrelated, Severity: models.SeverityCritical, References: []string{}},
	}

	err := RenderJSON(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if report.Sources.Blackbox != 1 {
		t.Errorf("expected 1 blackbox, got %d", report.Sources.Blackbox)
	}
	if report.Sources.Whitebox != 1 {
		t.Errorf("expected 1 whitebox, got %d", report.Sources.Whitebox)
	}
	if report.Sources.Correlated != 1 {
		t.Errorf("expected 1 correlated, got %d", report.Sources.Correlated)
	}
	if report.Metadata.Mode != "hybrid" {
		t.Errorf("expected mode hybrid, got %s", report.Metadata.Mode)
	}
	if report.Metadata.EndpointsCount != 15 {
		t.Errorf("expected 15 endpoints, got %d", report.Metadata.EndpointsCount)
	}
	if report.Metadata.ActiveProbes != true {
		t.Error("expected active_probes true")
	}
	if len(report.Metadata.ChecksRun) != 3 {
		t.Errorf("expected 3 checks, got %d", len(report.Metadata.ChecksRun))
	}
}

// TestRenderJSON_DecisionSummary covers the v0.24 additive decision report:
// the top-level `decisions` block tallies statuses + HIGH-confidence, and
// per-finding status/confidence_score serialize.
func TestRenderJSON_DecisionSummary(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "a", Severity: models.SeverityHigh, Category: "x", Status: "BLOCK", ConfidenceScore: 80, ConfidenceBand: "HIGH"},
		{ID: "SEC-002", Title: "b", Severity: models.SeverityLow, Category: "y", Status: "INFO", ConfidenceScore: 45, ConfidenceBand: "MEDIUM"},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, findings, ScanMetadata{}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var rep JSONReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Decisions.Total != 2 || rep.Decisions.Blocking != 1 || rep.Decisions.Informational != 1 || rep.Decisions.Confirmed != 1 {
		t.Errorf("decision summary wrong: %+v", rep.Decisions)
	}
	if rep.Findings[0].Status != "BLOCK" || rep.Findings[0].ConfidenceScore != 80 {
		t.Errorf("per-finding decision fields not serialized: %+v", rep.Findings[0])
	}
}

// TestRenderJSON_NoDecisionFieldsByDefault confirms backward-compat: findings
// without decision fields omit them (omitempty), and Decisions has only Total.
func TestRenderJSON_NoDecisionFieldsByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []models.Finding{{ID: "SEC-001", Title: "a", Severity: models.SeverityLow, Category: "x"}}, ScanMetadata{}); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, absent := range []string{"\"status\"", "\"confidence_score\"", "\"confidence_band\""} {
		if bytes.Contains(buf.Bytes(), []byte(absent)) {
			t.Errorf("unstamped finding should omit %s: %s", absent, s)
		}
	}
}

// TestRenderJSON_StampsSchemaVersion covers both halves of the contract
// marker on a freshly written report: the key is physically in the bytes
// (a typed decode cannot tell an absent key from a zero, so the raw map is
// checked first), and it round-trips back through ParseJSONReport as 1.
//
// The expected value is pinned to the literal rather than to the
// SchemaVersion const on purpose — bumping the const is a contract change
// consumers have to be told about, so it fails here first. It did: 1 -> 2 for
// the fendix/v2 fingerprint algorithm, which invalidates every saved baseline
// and every `.fendix-ignore` fingerprint: rule written under v1.
func TestRenderJSON_StampsSchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	// SchemaVersion deliberately left unset by the caller: RenderJSON is
	// the stamper, so nothing upstream has to remember to set it.
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev", Mode: "blackbox"}

	if err := RenderJSON(&buf, sampleFindings(), meta); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	rawMeta, ok := raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata is not an object, got %T", raw["metadata"])
	}
	got, present := rawMeta["schema_version"]
	if !present {
		t.Fatalf("metadata.schema_version missing from rendered report: %v", rawMeta)
	}
	if got != float64(2) {
		t.Errorf("metadata.schema_version = %v, want 2", got)
	}

	report, err := ParseJSONReport(buf.Bytes())
	if err != nil {
		t.Fatalf("a freshly written report must parse: %v", err)
	}
	if report.Metadata.SchemaVersion != 2 {
		t.Errorf("round-tripped Metadata.SchemaVersion = %d, want 2", report.Metadata.SchemaVersion)
	}
}

// TestRenderJSON_RestampsSchemaVersionOnRerender is the `fendix report
// --input old.json --format json` path. The input predates the field and
// decodes to 0, but THIS build writes the output bytes, so the output
// carries THIS build's version rather than propagating the 0.
func TestRenderJSON_RestampsSchemaVersionOnRerender(t *testing.T) {
	stale := ScanMetadata{Target: "https://api.example.com", Version: "v0.4.1", Mode: "blackbox", SchemaVersion: 0}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, nil, stale); err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	report, err := ParseJSONReport(buf.Bytes())
	if err != nil {
		t.Fatalf("re-rendered report must parse: %v", err)
	}
	if report.Metadata.SchemaVersion != 2 {
		t.Errorf("Metadata.SchemaVersion = %d, want 1 — the writer stamps, it does not propagate", report.Metadata.SchemaVersion)
	}
	// The caller's copy must not be mutated: meta is passed by value.
	if stale.SchemaVersion != 0 {
		t.Errorf("caller's ScanMetadata was mutated: SchemaVersion = %d, want 0", stale.SchemaVersion)
	}
}
