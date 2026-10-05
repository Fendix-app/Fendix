package verifycmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestRunCorrelatedFindingWithoutBothInputsIsUnknownWithExplanation asserts
// that verify on a correlated finding given only --url (no --code) returns
// status=unknown AND a Reason that names correlated findings and what's
// missing. C4 gave correlated findings a real two-sided verify; the honest
// unknown now fires only when an input for one half is absent (here --code),
// not unconditionally. Sprint-03 trust intent preserved: never a bare unknown.
func TestRunCorrelatedFindingWithoutBothInputsIsUnknownWithExplanation(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-CORR-001",
		Title:    "Correlated finding for verify scope test",
		Source:   models.SourceCorrelated,
		Endpoint: "GET /api/something",
		Category: "auth",
	}})

	r, err := Run(context.Background(), "SEC-CORR-001", Options{
		BaselinePath: baseline,
		URL:          "http://localhost:1", // no --code → cannot re-test the whitebox half
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Errorf("want %v; got %v (reason=%q)", StatusUnknown, r.Status, r.Reason)
	}
	if !strings.Contains(strings.ToLower(r.Reason), "correlat") {
		t.Errorf("Reason should mention 'correlated' findings: %q", r.Reason)
	}
	// The reason must tell the user what to do: supply both inputs, or re-scan.
	if !strings.Contains(strings.ToLower(r.Reason), "--code") ||
		!strings.Contains(strings.ToLower(r.Reason), "re-scan") {
		t.Errorf("Reason should name the missing input and the re-scan path: %q", r.Reason)
	}
}

// TestRunUnknownShapeNamesSourceAndCategory confirms the new Reason
// string echoes back the finding's source/category, so the user knows
// exactly why their finding wasn't supported.
func TestRunUnknownShapeNamesSourceAndCategory(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-WEIRD-001",
		Title:    "Active probe with no endpoint",
		Source:   models.Source("active-probe-shape"), // an unknown source string
		Category: "injection",
		// No Endpoint — won't match isURLFinding/isFileFinding/isDepFinding
	}})

	r, err := Run(context.Background(), "SEC-WEIRD-001", Options{
		BaselinePath: baseline,
		URL:          "http://localhost:1",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Fatalf("want %v; got %v", StatusUnknown, r.Status)
	}
	if !strings.Contains(r.Reason, "active-probe-shape") {
		t.Errorf("Reason should echo the finding's source: %q", r.Reason)
	}
	if !strings.Contains(r.Reason, "injection") {
		t.Errorf("Reason should echo the finding's category: %q", r.Reason)
	}
}

// TestRenderJSONIncludesAllFields confirms the JSON output shape is
// stable: status, reason, original, latency_ms, verified_at all present.
func TestRenderJSONIncludesAllFields(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-JSON-001",
		Title:    "JSON shape test finding",
		Source:   models.SourceCorrelated,
		Endpoint: "GET /api/x",
		Category: "auth",
	}})
	r, err := Run(context.Background(), "SEC-JSON-001", Options{
		BaselinePath: baseline,
		URL:          "http://localhost:1",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Round-trip via JSON to confirm the documented field set is honoured.
	var buf strings.Builder
	if err := Render(&buf, r, true); err != nil {
		t.Fatalf("Render JSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &got); err != nil {
		t.Fatalf("decode rendered JSON: %v", err)
	}
	for _, key := range []string{"finding_id", "status", "verified_at", "latency_ms"} {
		if _, ok := got[key]; !ok {
			t.Errorf("expected key %q in rendered JSON; got %v", key, got)
		}
	}
	// Reason should be present for unknown-status results.
	if _, ok := got["reason"]; !ok {
		t.Errorf("expected key %q in rendered JSON for unknown-status result; got %v", "reason", got)
	}
	// Original should be present (the finding existed in baseline).
	if _, ok := got["original"]; !ok {
		t.Errorf("expected key %q in rendered JSON; got %v", "original", got)
	}
}
