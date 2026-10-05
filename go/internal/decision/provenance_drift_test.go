package decision

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestDecisionProvenanceSurvivesTheFindingProjection is the DRIFT GUARD for the
// decision layer, mirroring the confidence package's guard for the scorer.
//
// confidence.Score is not the only consumer of Evidence-internal state:
// DecideWithOptions reads Evidence.InTest, which models.Finding has no field
// for. If that field stops surviving the project → restore round trip, the
// test-fixture de-escalation silently stops firing in production — exactly the
// failure mode that left DecideWithOptions dead code in the first place.
func TestDecisionProvenanceSurvivesTheFindingProjection(t *testing.T) {
	ev := evidence.Evidence{
		Title:    "Hardcoded API key",
		Category: "secrets",
		Endpoint: "app/tests/test_client.py:12",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		InTest:   true,
	}
	opts := Options{DeescalateTests: true}

	want := DecideWithOptions(ev, "", opts)
	if want.Status != StatusInfo {
		t.Fatalf("baseline: Status = %q, want INFO (test setup is wrong)", want.Status)
	}

	ix := evidence.NewProvenanceIndex([]evidence.Evidence{ev})
	restored := ix.Restore(evidence.FromFindings(evidence.ToFindings([]evidence.Evidence{ev})))
	got := DecideWithOptions(restored[0], "", opts)

	if got.Status != want.Status {
		t.Errorf("decision differs across the Finding projection: got %q, want %q — an\n"+
			"Evidence-internal field the decision layer reads is missing from\n"+
			"evidence.ScoringProvenance", got.Status, want.Status)
	}
}

// TestProvenanceIndexDerivesInTestFromEndpoint documents that a producer does
// not have to set InTest by hand: the index derives it from the endpoint, which
// is how Python-emitted findings (whose `in_test` wire field is dropped by the
// models.Finding unmarshal) still get classified.
func TestProvenanceIndexDerivesInTestFromEndpoint(t *testing.T) {
	ev := evidence.Evidence{
		Title:    "Hardcoded API key",
		Category: "secrets",
		Endpoint: "app/tests/test_client.py:12",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		// InTest deliberately NOT set — the index must derive it.
	}
	ix := evidence.NewProvenanceIndex([]evidence.Evidence{ev})
	restored := ix.Restore(evidence.FromFindings(evidence.ToFindings([]evidence.Evidence{ev})))
	if !restored[0].InTest {
		t.Fatal("index did not derive InTest from a test-path endpoint")
	}
	if d := DecideWithOptions(restored[0], "", Options{DeescalateTests: true}); d.Status != StatusInfo {
		t.Errorf("Status = %q, want INFO", d.Status)
	}
}

// TestDeescalationIsExplainedInTheScoreReasons enforces the explainability
// contract: a finding demoted to INFO must say why in the published reason
// breakdown, and the added line must not perturb the score/reason arithmetic.
func TestDeescalationIsExplainedInTheScoreReasons(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh,
		Endpoint: "app/tests/test_views.py:42",
		Category: "injection",
		Source:   models.SourceWhitebox,
		InTest:   true,
	}
	plain := DecideWithOptions(ev, "", Options{DeescalateTests: false})
	demoted := DecideWithOptions(ev, "", Options{DeescalateTests: true})

	if demoted.Score.Value != plain.Score.Value {
		t.Errorf("de-escalation changed the confidence SCORE (%d → %d); it must only change STATUS",
			plain.Score.Value, demoted.Score.Value)
	}
	joined := strings.Join(demoted.Score.Reasons, "\n")
	if !strings.Contains(joined, "test/fixture code") {
		t.Errorf("no reason line explains the de-escalation:\n%s", joined)
	}
	if !strings.Contains(joined, "+0 ") {
		t.Errorf("the de-escalation reason must carry an explicit +0 delta so reasons still\n"+
			"reconcile with the score:\n%s", joined)
	}
	if len(demoted.Score.Reasons) != len(plain.Score.Reasons)+1 {
		t.Errorf("expected exactly one extra reason line, got %d vs %d",
			len(demoted.Score.Reasons), len(plain.Score.Reasons))
	}
}

// TestDeescalationDoesNotAliasTheSharedReasonSlice guards a subtle aliasing
// bug: Decide builds Score.Reasons, and appending in place could mutate a slice
// another Decision shares, making output depend on evaluation order.
func TestDeescalationDoesNotAliasTheSharedReasonSlice(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh,
		Endpoint: "app/tests/test_views.py:42",
		Category: "injection",
		Source:   models.SourceWhitebox,
		InTest:   true,
	}
	evs := []evidence.Evidence{ev, ev}
	ds := DecideAllWithOptions(evs, "", Options{DeescalateTests: true})
	if len(ds[0].Score.Reasons) != len(ds[1].Score.Reasons) {
		t.Fatalf("identical evidence produced different reason counts: %d vs %d",
			len(ds[0].Score.Reasons), len(ds[1].Score.Reasons))
	}
	for i := range ds[0].Score.Reasons {
		if ds[0].Score.Reasons[i] != ds[1].Score.Reasons[i] {
			t.Fatalf("reason %d differs between identical decisions: %q vs %q",
				i, ds[0].Score.Reasons[i], ds[1].Score.Reasons[i])
		}
	}
}

// TestUnconfirmedMarkerSurvivesTheFindingProjection is the same drift guard for
// FIX-08's marker. UnconfirmedByLiveScan is set by the correlator, read by the
// decision layer, and has NO field on models.Finding and NO endpoint-derived
// fallback — so if it stops surviving the project → restore round trip, the
// "never BLOCK on unconfirmed-only evidence" rule is silently dead on every
// hybrid scan, which is the only scan shape that produces the marker at all.
func TestUnconfirmedMarkerSurvivesTheFindingProjection(t *testing.T) {
	ev := evidence.Evidence{
		Title:                 "SQL injection",
		Category:              "injection",
		Endpoint:              "/api/v1/orders",
		Severity:              models.SeverityCritical,
		Source:                models.SourceWhitebox,
		Confidence:            models.ConfidenceMedium,
		Evidence:              "cursor.execute(...) [Unconfirmed by live scan]",
		UnconfirmedByLiveScan: true,
	}
	opts := Options{EnforceConfidence: true}

	want := DecideWithOptions(ev, "HIGH", opts)
	if want.Status != StatusWarn {
		t.Fatalf("baseline: Status = %q, want WARN (test setup is wrong)", want.Status)
	}

	ix := evidence.NewProvenanceIndex([]evidence.Evidence{ev})
	restored := ix.Restore(evidence.FromFindings(evidence.ToFindings([]evidence.Evidence{ev})))
	got := DecideWithOptions(restored[0], "HIGH", opts)

	if got.Status != want.Status {
		t.Errorf("decision differs across the Finding projection: got %q, want %q —\n"+
			"UnconfirmedByLiveScan is missing from evidence.ScoringProvenance",
			got.Status, want.Status)
	}
}
