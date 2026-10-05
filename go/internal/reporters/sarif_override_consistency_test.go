package reporters

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The export-time structural invariant: policy_override may only appear on a
// BLOCK.
//
// This is deliberately NOT a second copy of the decision logic — it never asks
// whether the finding SHOULD be an override, which is the decision layer's job
// and stays there. It asserts one structural relationship between two fields
// of the same result: "override implies BLOCK". A malformed pair is dropped
// rather than published, because a consumer auditing relaxed-policy blocks
// cannot tell a stale flag from a real one and would act on both.
//
// The decision layer's settleOverride already prevents the pair from being
// produced. This is the belt to that braces: it also covers a finding that
// reached the reporter from somewhere else — a re-render of an archived report
// written before the fix, which is the case that actually matters, since those
// documents exist and will be re-rendered.

func TestSARIFDropsPolicyOverrideOnNonBlock(t *testing.T) {
	for _, status := range []string{"WARN", "INFO"} {
		f := models.Finding{
			ID: "SEC-001", Title: "x", Category: "deps", Severity: models.SeverityHigh,
			Status: status, DecisionReason: "held at WARN", DecisionPolicy: "relaxed",
			PolicyOverride: true, ConfidenceScore: 45, ConfidenceBand: "MEDIUM",
		}
		dec := decisionBlock(t, renderOneResult(t, f))
		if v, present := dec["policy_override"]; present && v == true {
			t.Errorf("status %s exported policy_override=true — a non-blocking finding "+
				"claims a relaxed BLOCK that does not exist", status)
		}
	}
}

func TestSARIFKeepsPolicyOverrideOnBlock(t *testing.T) {
	f := models.Finding{
		ID: "SEC-001", Title: "x", Category: "secrets", Severity: models.SeverityHigh,
		Status: "BLOCK", DecisionReason: "severity at or above the --fail-on threshold (relaxed policy)",
		DecisionPolicy: "relaxed", PolicyOverride: true, ConfidenceScore: 25, ConfidenceBand: "LOW",
	}
	dec := decisionBlock(t, renderOneResult(t, f))
	if dec["policy_override"] != true {
		t.Errorf("a genuine relaxed BLOCK lost its override flag: %v", dec)
	}
	if dec["policy"] != "relaxed" {
		t.Errorf("policy = %v, want relaxed", dec["policy"])
	}
}

// The policy STRING is untouched by the guard. "this report came from a
// relaxed run" stays true of a demoted finding — it is only the "…and it
// blocked because of that" claim that does not.
func TestSARIFKeepsRelaxedPolicyLabelOnNonBlock(t *testing.T) {
	f := models.Finding{
		ID: "SEC-001", Title: "x", Category: "deps", Severity: models.SeverityHigh,
		Status: "WARN", DecisionReason: "held at WARN", DecisionPolicy: "relaxed",
		PolicyOverride: true, ConfidenceScore: 45, ConfidenceBand: "MEDIUM",
	}
	dec := decisionBlock(t, renderOneResult(t, f))
	if dec["policy"] != "relaxed" {
		t.Errorf("policy label lost: %v", dec)
	}
}

// TestSARIFBlockLiteralMatchesDecisionPackage locks the restated "BLOCK"
// literal to its source of truth.
//
// The reporter must not import the decision package in production code, so the
// literal is restated there. A restated constant that nothing checks is a
// latent bug: rename decision.StatusBlock and the guard above silently stops
// matching, letting every override through again. The TEST may import the
// decision package freely — it creates no production dependency.
func TestSARIFBlockLiteralMatchesDecisionPackage(t *testing.T) {
	if decisionStatusBlock != string(decision.StatusBlock) {
		t.Fatalf("reporters.decisionStatusBlock = %q but decision.StatusBlock = %q — "+
			"the override guard is comparing against a status that no longer exists",
			decisionStatusBlock, decision.StatusBlock)
	}
}
