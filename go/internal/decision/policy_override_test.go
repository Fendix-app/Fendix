package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// bareBlackbox is the RC-1 shape: a scanner-assigned CRITICAL with nothing
// corroborating it. Under the shipped policy it warns. Under the legacy policy
// it blocks — on severity alone.
func bareBlackbox() evidence.Evidence {
	return evidence.Evidence{
		Title: "Missing authentication on endpoint", Category: "auth_bypass",
		Endpoint: "GET /status", Severity: models.SeverityCritical,
		Source: models.SourceBlackbox, Confidence: models.ConfidenceMedium,
	}
}

// A BLOCK produced by the relaxed/legacy policy is NOT an evidence-backed
// decision, and the Decision must say so. Without this a consumer cannot
// distinguish "Fendix proved this" from "the operator turned the gate off",
// and Fendix's central product claim becomes unverifiable from the output.
func TestLegacyPolicyBlockIsMarkedAsAnOverride(t *testing.T) {
	d := DecideWithOptions(bareBlackbox(), "HIGH", Options{}) // EnforceConfidence=false

	if d.Status != StatusBlock {
		t.Fatalf("Status = %q, want BLOCK — the legacy mapping must still block on severity", d.Status)
	}
	if !d.PolicyOverride {
		t.Error("PolicyOverride = false on a legacy-policy BLOCK — an unconfirmed finding gated " +
			"the build and nothing in the decision records that the gate was relaxed")
	}
	if d.Policy != PolicyRelaxed {
		t.Errorf("Policy = %q, want %q", d.Policy, PolicyRelaxed)
	}
	if d.Corroboration.Any() {
		t.Errorf("Corroboration = %+v, want empty — this shape has no supporting evidence at all, "+
			"which is exactly why the override marker matters", d.Corroboration)
	}
}

// The shipped policy must NOT carry the override marker, so the two are
// distinguishable in every consumer.
func TestEnforcedPolicyIsNotMarkedAsAnOverride(t *testing.T) {
	confirmed := evidence.Evidence{
		Title: "SSRF", Category: "injection", Endpoint: "app/views.py:674",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter,
		Reachable: true,
	}
	d := DecideWithOptions(confirmed, "HIGH", Options{EnforceConfidence: true})

	if d.Status != StatusBlock {
		t.Fatalf("Status = %q, want BLOCK", d.Status)
	}
	if d.PolicyOverride {
		t.Error("PolicyOverride = true under the shipped policy — an evidence-backed BLOCK must " +
			"never be labelled an override")
	}
	if d.Policy != PolicyEnforced {
		t.Errorf("Policy = %q, want %q", d.Policy, PolicyEnforced)
	}
}

// A legacy-policy decision that would ALSO have blocked under the shipped
// policy is not an override in any meaningful sense: the relaxation changed
// nothing. Marking it would cry wolf and teach readers to ignore the flag.
func TestLegacyPolicyIsNotAnOverrideWhenEvidenceWouldHaveBlockedAnyway(t *testing.T) {
	confirmed := evidence.Evidence{
		Title: "SSRF", Category: "injection", Endpoint: "app/views.py:674",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter,
		Reachable: true,
	}
	d := DecideWithOptions(confirmed, "HIGH", Options{}) // relaxed

	if d.Status != StatusBlock {
		t.Fatalf("Status = %q, want BLOCK", d.Status)
	}
	if d.PolicyOverride {
		t.Error("PolicyOverride = true, but this finding is independently corroborated and would " +
			"have blocked under the shipped policy too — the relaxation changed nothing")
	}
}

// A relaxed-policy run that produces no BLOCK at all has nothing to override.
func TestNonBlockingDecisionsAreNeverOverrides(t *testing.T) {
	low := evidence.Evidence{
		Title: "informational", Category: "headers", Endpoint: "GET /",
		Severity: models.SeverityLow, Source: models.SourceBlackbox,
	}
	for _, opts := range []Options{{}, {EnforceConfidence: true}} {
		d := DecideWithOptions(low, "HIGH", opts)
		if d.PolicyOverride {
			t.Errorf("opts=%+v: PolicyOverride = true on a %s decision", opts, d.Status)
		}
	}
}
