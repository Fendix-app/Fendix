package engine

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// RC-3. Deduplicate accumulates endpoints, references, Confidence and Source
// order-invariantly, then takes EVERY other field from whichever member wins
// findingLess (endpoint, then evidence, then fix, then line — lexicographic).
//
// Reachable, ProvenPath, RouteConfirmed, TaintChain, Route and SourceTier live
// in the render block, so evidence.ProvenanceIndex cannot reach them — it
// carries the Evidence-INTERNAL half by construction. They rode along with the
// lexicographic minimum, so a confirmed occurrence whose endpoint sorted later
// than an unconfirmed one had its proof silently deleted.
//
// decision.corroborate reads exactly those fields, so this could demote a
// genuinely confirmed finding to WARN.
func TestDedupPreservesConfirmedEvidenceAgainstUnknownDuplicate(t *testing.T) {
	confirmed := models.Finding{
		Title:          "Potential SSRF — dynamic URL passed to HTTP client",
		Category:       "injection",
		Severity:       models.SeverityHigh,
		Source:         models.SourceWhitebox,
		Endpoint:       "z/views.py:674", // sorts AFTER the unconfirmed one
		Reachable:      true,
		ProvenPath:     true,
		RouteConfirmed: true,
		SourceTier:     models.TierTreeSitter,
		TaintChain: []models.TaintLink{
			{File: "z/views.py", Line: 652, Expr: "request.query_params.get('url')"},
			{File: "z/views.py", Line: 674, Expr: "requests.get(image_url)"},
		},
		Route: &models.Route{Method: "GET", Pattern: "/proxy", Handler: "views.image_proxy"},
		Line:  linePtr("z/views.py:674"),
	}
	unknown := models.Finding{
		Title:      "Potential SSRF — dynamic URL passed to HTTP client",
		Category:   "injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Endpoint:   "a/util.py:10", // sorts FIRST → wins findingLess
		SourceTier: models.TierSemgrepShim,
		Line:       linePtr("a/util.py:10"),
	}

	for _, tc := range []struct {
		name string
		in   []models.Finding
	}{
		{"confirmed first", []models.Finding{confirmed, unknown}},
		{"unknown first", []models.Finding{unknown, confirmed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Deduplicate(append([]models.Finding(nil), tc.in...))
			if len(out) != 1 {
				t.Fatalf("got %d findings, want 1 merged group", len(out))
			}
			g := out[0]
			if !g.Reachable {
				t.Error("Reachable = false — a proved taint path was erased by an unconfirmed duplicate")
			}
			if !g.ProvenPath {
				t.Error("ProvenPath = false — proof erased")
			}
			if !g.RouteConfirmed {
				t.Error("RouteConfirmed = false — proof erased")
			}
			if len(g.TaintChain) != 2 {
				t.Errorf("TaintChain has %d links, want 2 — the chain was dropped with the losing member",
					len(g.TaintChain))
			}
			if g.Route == nil {
				t.Error("Route = nil — the bound route was dropped with the losing member")
			}
			if g.SourceTier != models.TierTreeSitter {
				t.Errorf("SourceTier = %q, want the most-trusted tier in the group", g.SourceTier)
			}
		})
	}
}

// The fold must PRESERVE evidence, never manufacture it: a group in which
// nobody proved reachability must not come out reachable.
func TestDedupDoesNotManufactureEvidence(t *testing.T) {
	a := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "a"}
	b := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "b"}

	out := Deduplicate([]models.Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	g := out[0]
	if g.Reachable || g.ProvenPath || g.RouteConfirmed {
		t.Errorf("dedup manufactured evidence: reachable=%v provenPath=%v routeConfirmed=%v",
			g.Reachable, g.ProvenPath, g.RouteConfirmed)
	}
	if len(g.TaintChain) != 0 || g.Route != nil {
		t.Errorf("dedup manufactured a chain/route: chain=%v route=%v", g.TaintChain, g.Route)
	}
}

// F-L6: the merged result must be a pure function of the member SET. With three
// members carrying different proofs, every permutation must produce the same
// merged finding — otherwise worker-pool arrival order changes the published
// confidence score and decision status.
func TestDedupProofUnionIsOrderIndependent(t *testing.T) {
	mk := func(ep string, reachable, proven bool, tier models.SourceTier, chain int) models.Finding {
		f := models.Finding{
			Title: "T", Category: "injection", Severity: models.SeverityHigh,
			Endpoint: ep, Reachable: reachable, ProvenPath: proven, SourceTier: tier,
		}
		for i := 0; i < chain; i++ {
			f.TaintChain = append(f.TaintChain, models.TaintLink{File: ep, Line: i})
		}
		return f
	}
	a := mk("a", false, false, models.TierSemgrepShim, 0)
	b := mk("m", true, false, models.TierNativeGo, 2)
	c := mk("z", false, true, models.TierTreeSitter, 0)

	perms := [][]models.Finding{
		{a, b, c}, {a, c, b}, {b, a, c}, {b, c, a}, {c, a, b}, {c, b, a},
	}
	var want models.Finding
	for i, p := range perms {
		out := Deduplicate(append([]models.Finding(nil), p...))
		if len(out) != 1 {
			t.Fatalf("permutation %d: got %d findings, want 1", i, len(out))
		}
		got := out[0]
		if i == 0 {
			want = got
			if !got.Reachable || !got.ProvenPath || got.SourceTier != models.TierTreeSitter ||
				len(got.TaintChain) != 2 {
				t.Fatalf("baseline permutation did not union the proofs: %+v", got)
			}
			continue
		}
		if got.Reachable != want.Reachable || got.ProvenPath != want.ProvenPath ||
			got.RouteConfirmed != want.RouteConfirmed || got.SourceTier != want.SourceTier ||
			len(got.TaintChain) != len(want.TaintChain) || got.Endpoint != want.Endpoint {
			t.Errorf("permutation %d diverged:\n got=%+v\nwant=%+v", i, got, want)
		}
	}
}
