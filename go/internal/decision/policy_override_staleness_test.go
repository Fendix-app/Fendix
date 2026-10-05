package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// PolicyOverride's contract, from its own doc comment: true ONLY when the
// relaxed policy produced a BLOCK the shipped policy would not have produced.
//
// decide() sets it in the relaxed BLOCK arm. But DecideWithOptions then runs
// applyApplicabilityGate and the test-fixture de-escalation, either of which
// can move Status off BLOCK — and nothing re-evaluated the flag. So a relaxed
// run exported WARN and INFO findings carrying policy_override=true.
//
// That breaks the one question the flag exists to answer: "which BLOCKs exist
// only because someone turned the evidence requirement off?" A consumer
// filtering on it got non-blocking findings back.
//
// Found by the release-validation pass against the real binary:
//
//	SEC-033 deps    relaxed=WARN  override=true   (applicability gate)
//	SEC-045 secrets relaxed=INFO  override=true   (test-fixture de-escalation)

// TestPolicyOverrideClearedWhenApplicabilityGateDemotes: the SCA route off BLOCK.
func TestPolicyOverrideClearedWhenApplicabilityGateDemotes(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps",
		Confidence: models.ConfidenceHigh, ComponentNotImported: true,
	}
	d := DecideWithOptions(ev, "HIGH", Options{}) // relaxed
	if d.Status == StatusBlock {
		t.Fatalf("precondition: expected the applicability gate to demote, got BLOCK")
	}
	if d.PolicyOverride {
		t.Errorf("status %s carries policy_override=true — the flag claims a relaxed BLOCK that does not exist", d.Status)
	}
}

// TestPolicyOverrideClearedWhenTestFixtureDeescalates: the secrets route off BLOCK.
func TestPolicyOverrideClearedWhenTestFixtureDeescalates(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets",
		Confidence: models.ConfidenceHigh, InTest: true, Placeholder: true,
	}
	d := DecideWithOptions(ev, "HIGH", Options{DeescalateTests: true}) // relaxed + de-escalation
	if d.Status == StatusBlock {
		t.Fatalf("precondition: expected the fixture de-escalation to demote, got BLOCK")
	}
	if d.PolicyOverride {
		t.Errorf("status %s carries policy_override=true", d.Status)
	}
}

// TestPolicyOverrideSurvivesOnAGenuineRelaxedBlock is the other half, and the
// one that matters: clearing the stale flag must not clear the real one.
func TestPolicyOverrideSurvivesOnAGenuineRelaxedBlock(t *testing.T) {
	// Placeholder-shaped credential in PRODUCTION code: scores LOW, so the
	// shipped policy holds it at WARN and the relaxed policy blocks it. This is
	// the exact shape the real binary produced as SEC-001.
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets",
		Confidence: models.ConfidenceHigh, Placeholder: true,
	}
	relaxed := DecideWithOptions(ev, "HIGH", Options{})
	if relaxed.Status != StatusBlock {
		t.Fatalf("precondition: relaxed should BLOCK, got %s (%s)", relaxed.Status, relaxed.Reason)
	}
	if !relaxed.PolicyOverride {
		t.Error("a genuine relaxed BLOCK lost its policy_override flag")
	}
	enforced := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if enforced.Status == StatusBlock {
		t.Fatalf("precondition: enforced should hold this, got BLOCK")
	}
	if enforced.PolicyOverride {
		t.Error("an enforced verdict must never be marked as an override")
	}
}

// TestPolicyOverrideImpliesBlock is the invariant in general form, swept over
// the shapes that reach a demotion.
func TestPolicyOverrideImpliesBlock(t *testing.T) {
	cases := []evidence.Evidence{
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps", ComponentNotImported: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets", InTest: true, Placeholder: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityCritical, Source: models.SourceWhitebox, Category: "secrets", InTest: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets", Placeholder: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "auth", Confidence: models.ConfidenceMedium},
		{Severity: models.SeverityLow, Source: models.SourceBlackbox},
	}
	for _, opts := range []Options{{}, {DeescalateTests: true}, {EnforceConfidence: true}, {EnforceConfidence: true, DeescalateTests: true}} {
		for _, ev := range cases {
			d := DecideWithOptions(ev, "HIGH", opts)
			if d.PolicyOverride && d.Status != StatusBlock {
				t.Errorf("opts %+v ev %+v: policy_override=true on status %s", opts, ev, d.Status)
			}
		}
	}
}
