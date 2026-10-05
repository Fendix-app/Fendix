package reporters

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// A relaxed-policy BLOCK and an evidence-backed BLOCK must NOT produce
// indistinguishable SARIF. Without this a consumer reading the report cannot
// verify Fendix's central claim, because "BLOCK" would mean either "we proved
// it" or "the gate was switched off" with nothing to tell them apart.
func TestRelaxedPolicyBlockIsIdentifiableInSarif(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:          "Missing authentication on endpoint",
		Category:       "auth_bypass",
		Severity:       models.SeverityCritical,
		Source:         models.SourceBlackbox,
		Endpoint:       "GET /status",
		Status:         "BLOCK",
		DecisionReason: "severity at or above the --fail-on threshold (relaxed policy: --enforce-confidence=false)",
		DecisionPolicy: "relaxed",
		PolicyOverride: true,
	})

	dec := decisionBlock(t, res)
	if dec["policy"] != "relaxed" {
		t.Errorf("decision.policy = %v, want %q", dec["policy"], "relaxed")
	}
	if dec["policy_override"] != true {
		t.Errorf("decision.policy_override = %v, want true", dec["policy_override"])
	}
	if sigs, present := dec["independent_signals"]; present {
		t.Errorf("independent_signals = %v on a finding nothing corroborated; the override marker "+
			"is the only thing distinguishing this BLOCK", sigs)
	}
}

// The shipped policy must not stamp either key, so their PRESENCE is the
// signal. An always-present "policy_override": false would be noise on every
// normal result.
func TestEnforcedPolicyBlockCarriesNoOverrideMarker(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:              "Potential SSRF",
		Category:           "injection",
		Severity:           models.SeverityHigh,
		Source:             models.SourceWhitebox,
		Endpoint:           "app/views.py:674",
		Status:             "BLOCK",
		DecisionReason:     "severity at or above the --fail-on threshold; corroborated by: reachable taint path",
		DecisionPolicy:     "enforced",
		IndependentSignals: []string{"reachable taint path"},
		Reachable:          true,
	})

	dec := decisionBlock(t, res)
	if v, present := dec["policy_override"]; present {
		t.Errorf("decision.policy_override = %v is present on an evidence-backed BLOCK; want omitted", v)
	}
	if dec["policy"] != "enforced" {
		t.Errorf("decision.policy = %v, want %q", dec["policy"], "enforced")
	}
}
