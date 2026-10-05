package reporters

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/confidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// scoredFinding is a BLOCK carrying the score breakdown in both published
// forms, the way stampDecisions leaves a real finding.
func scoredFinding() models.Finding {
	return models.Finding{
		ID: "SEC-001", Title: "Vulnerable dependency", Category: "deps",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Status: "BLOCK", DecisionReason: "severity at or above the --fail-on threshold",
		DecisionPolicy: "enforced", ConfidenceScore: 75, ConfidenceBand: "HIGH",
		ConfidenceReasons: []string{
			"+35 base: a scanner produced this finding",
			"+10 static (SAST) evidence present",
			"+30 deterministic detection: a high-confidence pattern match in production (non-test) code",
		},
		ConfidenceBreakdown: []confidence.Reason{
			{Delta: 35, Code: confidence.CodeBaseDetection, Text: "base: a scanner produced this finding"},
			{Delta: 10, Code: confidence.CodeStaticEvidence, Text: "static (SAST) evidence present"},
			{Delta: 30, Code: confidence.CodeDeterministicDetection, Text: "deterministic detection: a high-confidence pattern match in production (non-test) code"},
		},
	}
}

// TestSARIFCarriesConfidenceBreakdown: the structured breakdown is how a SARIF
// consumer learns WHICH rules moved the score, without parsing a presentation
// string. Its absence was the P1 parity gap — native JSON had the reasons and
// SARIF had only the final number.
func TestSARIFCarriesConfidenceBreakdown(t *testing.T) {
	res := renderOneResult(t, scoredFinding())
	props := res["properties"].(map[string]interface{})

	raw, ok := props["confidence_breakdown"].([]interface{})
	if !ok {
		t.Fatalf("properties.confidence_breakdown missing — SARIF cannot explain the score\n%v", props)
	}
	if len(raw) != 3 {
		t.Fatalf("want 3 breakdown entries, got %d", len(raw))
	}
	first := raw[0].(map[string]interface{})
	if first["code"] != confidence.CodeBaseDetection {
		t.Errorf("entry 0 code = %v, want %q", first["code"], confidence.CodeBaseDetection)
	}
	if first["delta"].(float64) != 35 {
		t.Errorf("entry 0 delta = %v, want 35", first["delta"])
	}
	if first["text"] == "" {
		t.Error("entry 0 has no text")
	}

	// The deltas must reconstruct the published score, or the two numbers in
	// the same result disagree.
	sum := 0.0
	for _, e := range raw {
		sum += e.(map[string]interface{})["delta"].(float64)
	}
	if int(sum) != 75 {
		t.Errorf("breakdown deltas sum to %v, but confidence_score is 75", sum)
	}
}

// TestSARIFCarriesConfidenceReasons keeps the human-readable breakdown too.
// Parity means a SARIF reader sees what a native-JSON reader sees; dropping
// the prose would make the two reports describe the same score differently.
func TestSARIFCarriesConfidenceReasons(t *testing.T) {
	res := renderOneResult(t, scoredFinding())
	props := res["properties"].(map[string]interface{})
	reasons, ok := props["confidence_reasons"].([]interface{})
	if !ok {
		t.Fatalf("properties.confidence_reasons missing\n%v", props)
	}
	if len(reasons) != 3 {
		t.Fatalf("want 3 reasons, got %d", len(reasons))
	}
}

// TestSARIFOmitsBreakdownWhenUnscored: a finding from a report produced before
// the decision pass existed must render byte-identically to how it always has.
// Emitting an empty array instead of omitting the key would change every
// archived report's re-render.
func TestSARIFOmitsBreakdownWhenUnscored(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		ID: "SEC-001", Title: "x", Category: "headers",
		Severity: models.SeverityLow, Evidence: "e",
	})
	props, ok := res["properties"].(map[string]interface{})
	if !ok {
		return // no properties at all is also fine
	}
	if _, present := props["confidence_breakdown"]; present {
		t.Error("confidence_breakdown emitted for an unscored finding")
	}
	if _, present := props["confidence_reasons"]; present {
		t.Error("confidence_reasons emitted for an unscored finding")
	}
}
