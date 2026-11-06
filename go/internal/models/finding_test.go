package models

import (
	"encoding/json"
	"testing"
)

func TestFindingJSONSerialization(t *testing.T) {
	line := "src/config.py:14"
	f := Finding{
		ID:         "SEC-001",
		Title:      "Hardcoded API key detected",
		Severity:   SeverityCritical,
		Source:     SourceWhitebox,
		Category:   "secrets",
		Endpoint:   "src/config.py:14",
		Evidence:   "API_KEY = 'sk-live-abc...' [truncated]",
		Fix:        "Move to environment variable.",
		References: []string{"CWE-798"},
		Confidence: ConfidenceHigh,
		Line:       &line,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.ID != f.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, f.ID)
	}
	if decoded.Severity != f.Severity {
		t.Errorf("Severity = %q, want %q", decoded.Severity, f.Severity)
	}
	if decoded.Source != f.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, f.Source)
	}
	if decoded.Confidence != f.Confidence {
		t.Errorf("Confidence = %q, want %q", decoded.Confidence, f.Confidence)
	}
	if decoded.Line == nil || *decoded.Line != line {
		t.Errorf("Line = %v, want %q", decoded.Line, line)
	}
}

func TestFindingNullLine(t *testing.T) {
	f := Finding{
		ID:         "SEC-002",
		Title:      "Missing auth",
		Severity:   SeverityCritical,
		Source:     SourceBlackbox,
		Category:   "auth",
		Endpoint:   "GET /api/users",
		Evidence:   "200 without auth",
		Fix:        "Add auth",
		References: []string{"CWE-306"},
		Confidence: ConfidenceHigh,
		Line:       nil,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Verify null serialization
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal to map failed: %v", err)
	}
	if raw["line"] != nil {
		t.Errorf("line should be null, got %v", raw["line"])
	}
}

func TestFindingJSONFieldNames(t *testing.T) {
	f := Finding{
		ID:         "SEC-001",
		Title:      "test",
		Severity:   SeverityHigh,
		Source:     SourceBlackbox,
		Category:   "test",
		Endpoint:   "test",
		Evidence:   "test",
		Fix:        "test",
		References: []string{},
		Confidence: ConfidenceHigh,
		Line:       nil,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify all expected JSON field names exist
	expectedFields := []string{
		"id", "title", "severity", "source", "category",
		"endpoint", "evidence", "fix", "references", "confidence", "line",
	}
	for _, field := range expectedFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing JSON field %q", field)
		}
	}
}

// ADR-011: the Semgrep taint tier ranks with native_go, and both Semgrep tiers
// are Semgrep-sourced — the predicate every "never for a Semgrep finding" rule
// (deterministic detection, tool identity, Proven Path) reads.
func TestSemgrepTaintTier(t *testing.T) {
	if got := TierSemgrepTaint.TrustRank(); got != 2 || got != TierNativeGo.TrustRank() {
		t.Errorf("semgrep_taint TrustRank = %d, want 2 (native_go's)", got)
	}
	for tier, want := range map[SourceTier]bool{
		TierSemgrepShim: true, TierSemgrepTaint: true,
		TierNativeGo: false, TierTreeSitter: false, "": false,
	} {
		if got := tier.IsSemgrep(); got != want {
			t.Errorf("%q.IsSemgrep() = %v, want %v", tier, got, want)
		}
	}
}
