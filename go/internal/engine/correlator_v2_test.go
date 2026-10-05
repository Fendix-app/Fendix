package engine

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// sampleFindingSets returns fresh finding slices each call (no shared backing
// arrays / pointers) so the two correlation pipelines under test can't alias.
func sampleFindingSets() [][]models.Finding {
	return [][]models.Finding{
		// pass-through only (no whitebox)
		{
			{Source: models.SourceBlackbox, Category: "headers", Title: "Missing CSP", Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh},
		},
		// a BB+WB injection pair that exercises the merge path
		{
			{Source: models.SourceBlackbox, Category: "injection", Title: "SQL injection", Endpoint: "/api/users", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: "param id"},
			{Source: models.SourceWhitebox, Category: "injection", Title: "SQL injection", Endpoint: "/api/users", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium, Reachable: true, Evidence: "cursor.execute"},
		},
		// mixed pass-through + unmatched whitebox
		{
			{Source: models.SourceBlackbox, Category: "headers", Title: "Missing HSTS", Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh},
			{Source: models.SourceWhitebox, Category: "secrets", Title: "Hardcoded key", Endpoint: "config.py:3", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh},
		},
	}
}

// TestCorrelateEvidence_RenderIdenticalToLegacy is the E3 contract lock: the
// rendered projection of Correlation V2 must equal the legacy Correlate()
// output for every input — so routing the orchestrator through the Evidence
// layer cannot change the public findings.
func TestCorrelateEvidence_RenderIdenticalToLegacy(t *testing.T) {
	for i := range sampleFindingSets() {
		want := Correlate(sampleFindingSets()[i])
		got := evidence.ToFindings(CorrelateEvidence(evidence.FromFindings(sampleFindingSets()[i])))
		if !reflect.DeepEqual(want, got) {
			t.Errorf("set %d: CorrelateEvidence render differs from legacy Correlate\n want=%+v\n got =%+v", i, want, got)
		}
	}
}

// TestCorrelateEvidence_PreservesPassThroughProvenance confirms provenance the
// Finding can't carry survives correlation for an unchanged pass-through.
func TestCorrelateEvidence_PreservesPassThroughProvenance(t *testing.T) {
	in := []evidence.Evidence{{
		Source: models.SourceBlackbox, Category: "headers", Title: "Missing CSP",
		Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh,
		RuleID: "dast.headers.csp", Payload: "GET /", Response: "200 OK",
		Metadata: map[string]string{"check": "headers"},
	}}
	out := CorrelateEvidence(in)
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if out[0].RuleID != "dast.headers.csp" || out[0].Payload != "GET /" || out[0].Response != "200 OK" {
		t.Errorf("pass-through provenance not preserved: %+v", out[0])
	}
	if out[0].Metadata["check"] != "headers" {
		t.Errorf("metadata not preserved: %+v", out[0].Metadata)
	}
}

// TestCorrelateEvidenceMarksUnconfirmedWhiteboxFindings locks the SINGLE
// producer of Evidence.UnconfirmedByLiveScan.
//
// The "[Unconfirmed by live scan]" prose is written by correlateWithMarks and
// published as part of the `evidence` string; the flag is its machine-readable
// counterpart, and the decision layer gates on the flag, never on the prose.
// The two must therefore be produced together at every site — a hybrid scan
// where the flag is dropped reports "unconfirmed" and fails the build on the
// same finding, which is the exact incoherence FIX-08 removes.
func TestCorrelateEvidenceMarksUnconfirmedWhiteboxFindings(t *testing.T) {
	in := []evidence.Evidence{
		// A blackbox finding, so correlation actually runs.
		{Source: models.SourceBlackbox, Category: "headers", Title: "Missing CSP", Endpoint: "/", Severity: models.SeverityMedium, Confidence: models.ConfidenceHigh},
		// A whitebox URL-endpoint finding with no blackbox counterpart.
		{Source: models.SourceWhitebox, Category: "injection", Title: "SQL injection", Endpoint: "/api/v1/orders", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: "cursor.execute"},
		// A whitebox file:line finding — a live HTTP scan cannot confirm or
		// deny a hardcoded secret at a source location, so it gets neither the
		// suffix (TASK-092) nor the marker.
		{Source: models.SourceWhitebox, Category: "secrets", Title: "Hardcoded key", Endpoint: "config.py:3", Severity: models.SeverityHigh, Confidence: models.ConfidenceHigh, Evidence: `key = "..."`},
	}

	want := map[string]bool{
		"Missing CSP":   false,
		"SQL injection": true,
		"Hardcoded key": false,
	}
	var seen int
	for _, e := range CorrelateEvidence(in) {
		expect, ok := want[e.Title]
		if !ok {
			t.Fatalf("unexpected finding %q in correlator output", e.Title)
		}
		seen++
		if e.UnconfirmedByLiveScan != expect {
			t.Errorf("%q UnconfirmedByLiveScan = %v, want %v", e.Title, e.UnconfirmedByLiveScan, expect)
		}
		// The marker and the prose must agree — they are two views of one fact.
		if got := strings.Contains(e.Evidence, "[Unconfirmed by live scan]"); got != expect {
			t.Errorf("%q evidence-suffix presence = %v, want %v (marker and prose drifted)", e.Title, got, expect)
		}
	}
	if seen != len(want) {
		t.Fatalf("expected %d findings out of correlation, got %d", len(want), seen)
	}

	// And the marker is invisible in the public shape: the rendered projection
	// is still byte-identical to what legacy Correlate produces.
	legacy := Correlate(evidence.ToFindings(in))
	if got := evidence.ToFindings(CorrelateEvidence(in)); !reflect.DeepEqual(legacy, got) {
		t.Errorf("marking changed the rendered output\n want=%+v\n got =%+v", legacy, got)
	}
}
