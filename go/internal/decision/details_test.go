package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/confidence"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// codesOf collects the structured reason codes on a decision's score
// breakdown, so a test can assert on the machine-readable form rather than on
// the wording of a sentence.
func codesOf(d Decision) map[string]bool {
	out := map[string]bool{}
	for _, r := range d.Score.Details {
		out[r.Code] = true
	}
	return out
}

// TestGateDemotionIsMachineReadable: when the confidence gate holds a
// threshold-crossing finding at WARN it appends an explanation to the
// breakdown. That explanation is the ANSWER to "why was blocking withheld",
// so it has to survive as a code, not only as prose.
func TestGateDemotionIsMachineReadable(t *testing.T) {
	// HIGH severity, whitebox, nothing corroborating: the "no signal at all"
	// arm holds it at WARN.
	ev := evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "auth"}
	d := DecideWithOptions(ev, "HIGH", enforced)
	if d.Status != StatusWarn {
		t.Fatalf("precondition: want WARN, got %s (%s)", d.Status, d.Reason)
	}
	if !codesOf(d)[confidence.CodeHeldUncorroborated] {
		t.Errorf("no %q code in breakdown: %+v", confidence.CodeHeldUncorroborated, d.Score.Details)
	}
}

// TestApplicabilityDeescalationIsMachineReadable: the SCA "affected component
// not imported" hold is the de-escalation most worth keying off downstream —
// it is the difference between "vulnerable package present" and "vulnerable
// code path reachable".
func TestApplicabilityDeescalationIsMachineReadable(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Category: "deps", ComponentNotImported: true, Confidence: models.ConfidenceHigh,
	}
	d := DecideWithOptions(ev, "HIGH", enforced)
	if d.Status != StatusWarn {
		t.Fatalf("precondition: want WARN, got %s (%s)", d.Status, d.Reason)
	}
	if !codesOf(d)[confidence.CodeNotApplicableComponentAbsent] {
		t.Errorf("no %q code in breakdown: %+v", confidence.CodeNotApplicableComponentAbsent, d.Score.Details)
	}
}

// TestDecisionDetailsStayAlignedWithReasons extends the confidence layer's
// anti-drift lock across the decision layer's own appends. appendReason and
// its structured twin must move together or the two published breakdowns
// describe different scores.
func TestDecisionDetailsStayAlignedWithReasons(t *testing.T) {
	cases := []evidence.Evidence{
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "auth"},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps", ComponentNotImported: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets", InTest: true, Placeholder: true, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityCritical, Source: models.SourceWhitebox, Category: "secrets", Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityLow, Source: models.SourceBlackbox},
	}
	for _, ev := range cases {
		for _, opts := range []Options{enforced, {EnforceConfidence: true, DeescalateTests: true}, {}} {
			d := DecideWithOptions(ev, "HIGH", opts)
			if len(d.Score.Details) != len(d.Score.Reasons) {
				t.Errorf("length mismatch %d vs %d for %+v opts %+v\n%v",
					len(d.Score.Details), len(d.Score.Reasons), ev, opts, d.Score.Reasons)
			}
			sum := 0
			for _, r := range d.Score.Details {
				sum += r.Delta
			}
			if sum != d.Score.Value {
				t.Errorf("detail deltas sum %d != Value %d for %+v", sum, d.Score.Value, ev)
			}
		}
	}
}
