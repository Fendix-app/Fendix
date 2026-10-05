package confidence

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// detailCases exercises every arm that appends a reason line, so the
// Details/Reasons invariants below are checked against the full rule surface
// rather than one convenient shape.
func detailCases() []evidence.Evidence {
	return []evidence.Evidence{
		{Source: models.SourceBlackbox},
		{Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim},
		{Source: models.SourceCorrelated, RouteConfirmed: true, Reachable: true, ProvenPath: true,
			SourceTier: models.TierTreeSitter, Payload: "p", Response: "r"},
		{Source: models.SourceBlackbox, ResponseContext: "4xx"},
		{Source: models.SourceBlackbox, DirectObservation: true},
		{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, Placeholder: true},
		{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, Category: "deps", ComponentNotImported: true},
		{Source: models.SourceImported, Confidence: models.ConfidenceHigh},
		{Source: models.SourceImported, Confidence: models.ConfidenceLow},
		{Source: models.SourceBlackbox, CrossToolCorroborated: true, CorroboratingTools: []string{"semgrep"}},
		{Source: models.SourceBlackbox, ResponseContext: "static-asset",
			Lineage: []evidence.Evidence{{Source: models.SourceBlackbox, Category: "headers"}}},
	}
}

// TestDetailsParallelReasons is the anti-drift lock. Details is the
// machine-readable form of the SAME breakdown Reasons renders, so the two must
// stay index-for-index aligned: a rule that appends to one and forgets the
// other would let SARIF and the native text report describe different scores.
func TestDetailsParallelReasons(t *testing.T) {
	for _, ev := range detailCases() {
		r := Score(ev)
		if len(r.Details) != len(r.Reasons) {
			t.Fatalf("Details/Reasons length mismatch: %d vs %d for %+v\n%v",
				len(r.Details), len(r.Reasons), ev, r.Reasons)
		}
		for i, d := range r.Details {
			if d.Code == "" {
				t.Errorf("Details[%d] has no Code (text %q)", i, d.Text)
			}
			// Reasons[i] is the rendered form: an optional signed-delta
			// prefix followed by the detail's own text. Suffix-matching
			// covers both the prefixed rules and the delta-free lineage line.
			if !strings.HasSuffix(r.Reasons[i], d.Text) {
				t.Errorf("Reasons[%d] = %q does not end with Details[%d].Text = %q",
					i, r.Reasons[i], i, d.Text)
			}
		}
	}
}

// TestDetailDeltasSumToValue mirrors TestReasonsSumToValue on the structured
// form. It is the reason SARIF may consume Details INSTEAD of parsing the
// presentation strings: the deltas reconstruct the score without a parser.
func TestDetailDeltasSumToValue(t *testing.T) {
	for _, ev := range detailCases() {
		r := Score(ev)
		sum := 0
		for _, d := range r.Details {
			sum += d.Delta
		}
		if sum != r.Value {
			t.Errorf("detail deltas sum %d != Value %d for %+v\n%+v", sum, r.Value, ev, r.Details)
		}
	}
}

// TestDetailCodesAreStable pins the codes a consumer keys off. They are a
// published contract: renaming one silently breaks every downstream rule that
// matched on it, which is exactly the fragility the structured form exists to
// remove.
func TestDetailCodesAreStable(t *testing.T) {
	ev := evidence.Evidence{
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		Category: "deps", ComponentNotImported: true,
	}
	got := map[string]int{}
	for _, d := range Score(ev).Details {
		got[d.Code] = d.Delta
	}
	want := map[string]int{
		"base_detection":          35,
		"static_evidence":         10,
		"deterministic_detection": 30,
		"component_not_imported":  -10,
	}
	for code, delta := range want {
		if got[code] != delta {
			t.Errorf("code %q: got delta %d, want %d (all: %v)", code, got[code], delta, got)
		}
	}
}
