package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Regression gate for an order-dependence an adversarial audit surfaced.
//
// Deduplicate seeded a group's endpoint set from the FIRST member's Endpoint
// only, and adopted a new primary just on a STRICT findingLess. Two members
// tying on every ordering key (Endpoint, Evidence, Fix, Line) but carrying
// different AffectedEndpoints therefore handed the group whichever list
// happened to arrive first. Because the scoring-provenance fold walks
// AffectedEndpoints, that leaked all the way into published, gate-visible
// fields — confidence_score, confidence_band and (once B3 landed) status.
//
// Deduplicate now folds every member's AffectedEndpoints into the group set,
// so the result is a function of the finding SET (F-L6), not the sequence.

func tiedMember(affected []string) evidence.Evidence {
	e := secretEvidence("tests/test_auth.py:1")
	e.AffectedEndpoints = affected
	return e
}

func TestDedupFoldsEveryMembersAffectedEndpoints(t *testing.T) {
	a := tiedMember([]string{"tests/test_auth.py:1"})
	b := tiedMember([]string{"tests/test_auth.py:1", "src/app.py:9"})

	forward := Deduplicate(evidence.ToFindings([]evidence.Evidence{a, b}))
	reverse := Deduplicate(evidence.ToFindings([]evidence.Evidence{b, a}))

	if len(forward) != 1 || len(reverse) != 1 {
		t.Fatalf("expected one deduped finding, got %d / %d", len(forward), len(reverse))
	}
	got, want := strings.Join(forward[0].AffectedEndpoints, ","), strings.Join(reverse[0].AffectedEndpoints, ",")
	if got != want {
		t.Errorf("AffectedEndpoints depends on arrival order:\n forward=%v\n reverse=%v", forward[0].AffectedEndpoints, reverse[0].AffectedEndpoints)
	}
	// The union, not whichever list arrived first.
	if len(forward[0].AffectedEndpoints) != 2 {
		t.Errorf("expected the union of both members' endpoints, got %v", forward[0].AffectedEndpoints)
	}
}

// TestTiedDedupVerdictIsOrderIndependent is the end-to-end consequence: the
// published status/score/reasons must not flip with input order.
func TestTiedDedupVerdictIsOrderIndependent(t *testing.T) {
	a := tiedMember([]string{"tests/test_auth.py:1"})
	b := tiedMember([]string{"tests/test_auth.py:1", "src/app.py:9"})
	opts := decision.Options{DeescalateTests: true}

	fwd := finalize([]evidence.Evidence{a, b}, "", opts)
	rev := finalize([]evidence.Evidence{b, a}, "", opts)

	if len(fwd) != len(rev) {
		t.Fatalf("finding count differs by order: %d vs %d", len(fwd), len(rev))
	}
	for i := range fwd {
		if fwd[i].Status != rev[i].Status {
			t.Errorf("finding %d status flips with input order: %q vs %q", i, fwd[i].Status, rev[i].Status)
		}
		if fwd[i].ConfidenceScore != rev[i].ConfidenceScore {
			t.Errorf("finding %d score flips with input order: %d vs %d", i, fwd[i].ConfidenceScore, rev[i].ConfidenceScore)
		}
		if strings.Join(fwd[i].ConfidenceReasons, "|") != strings.Join(rev[i].ConfidenceReasons, "|") {
			t.Errorf("finding %d reasons flip with input order:\n f=%v\n r=%v", i, fwd[i].ConfidenceReasons, rev[i].ConfidenceReasons)
		}
	}
	// A group spanning test AND production code must not earn the exemption,
	// whichever member arrived first.
	if fwd[0].Status != string(decision.StatusWarn) {
		t.Errorf("mixed test+production group Status = %q, want WARN", fwd[0].Status)
	}
}

// An empty Endpoint must not leak "" into a group's AffectedEndpoints.
func TestDedupDropsEmptyEndpoints(t *testing.T) {
	a := secretEvidence("")
	b := secretEvidence("src/app.py:9")

	for _, in := range [][]evidence.Evidence{{a, b}, {b, a}} {
		out := Deduplicate(evidence.ToFindings(in))
		for _, ep := range out[0].AffectedEndpoints {
			if ep == "" {
				t.Fatalf("empty endpoint leaked into AffectedEndpoints: %#v", out[0].AffectedEndpoints)
			}
		}
	}
}

var _ = models.Finding{}

// TestGatedDedupVerdictIsOrderIndependent extends the same lock over the
// enforcement path. FIX-08's BLOCK reason is built by joining
// decision.corroborations(), so a map or a set in that list would show up here
// as a reason string that flips with worker arrival order — while every
// existing determinism test, which runs with failOn "", would stay green.
func TestGatedDedupVerdictIsOrderIndependent(t *testing.T) {
	a := tiedMember([]string{"tests/test_auth.py:1"})
	b := tiedMember([]string{"tests/test_auth.py:1", "src/app.py:9"})
	// Every corroborating signal on, so the joined reason has something to
	// reorder.
	for _, e := range []*evidence.Evidence{&a, &b} {
		e.Source = models.SourceCorrelated
		e.RouteConfirmed = true
		e.Reachable = true
		e.ProvenPath = true
	}
	opts := decision.Options{DeescalateTests: true, EnforceConfidence: true}

	fwd := finalize([]evidence.Evidence{a, b}, "HIGH", opts)
	rev := finalize([]evidence.Evidence{b, a}, "HIGH", opts)

	if len(fwd) != len(rev) {
		t.Fatalf("finding count differs by order: %d vs %d", len(fwd), len(rev))
	}
	for i := range fwd {
		if fwd[i].Status != rev[i].Status {
			t.Errorf("finding %d status flips with input order: %q vs %q", i, fwd[i].Status, rev[i].Status)
		}
		if strings.Join(fwd[i].ConfidenceReasons, "|") != strings.Join(rev[i].ConfidenceReasons, "|") {
			t.Errorf("finding %d reasons flip with input order:\n f=%v\n r=%v", i, fwd[i].ConfidenceReasons, rev[i].ConfidenceReasons)
		}
	}
	// Premise guard: a corroborated group spanning production code must still
	// gate, or this test is comparing two WARNs and proving nothing.
	if fwd[0].Status != string(decision.StatusBlock) {
		t.Fatalf("corroborated group Status = %q, want BLOCK — this test's premise no longer holds", fwd[0].Status)
	}
}
