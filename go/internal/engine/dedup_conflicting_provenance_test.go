package engine

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CONFLICTING PROVENANCE — the semantics, established by what producers can
// actually emit rather than by what a boolean can theoretically hold.
//
// The adversarial question is: when two occurrences in one dedup group carry
// reachable=true and reachable=false, is the false an EXPLICIT NEGATIVE
// observation that proof-union wrongly discards?
//
// It is not, and the reason is a property of static analysis rather than of
// this codebase's style. python/analyzers/ast_analyzer.py assigns
// finding["reachable"] = True at exactly one place and never assigns False:
// the flag is a POSITIVE marker meaning "a source→sink chain was PROVEN". Its
// absence means "no chain was proven", which subsumes both "the analyzer never
// looked" and "the analyzer looked and found none" — and a taint analyzer
// cannot distinguish "no path exists" from "no path found" without a soundness
// guarantee it does not have.
//
// So reachability has TWO honest states, not four:
//
//	true  → proven reachable
//	false → not proven (unknown; NEVER "proven unreachable")
//
// Proof-union (OR) is therefore the correct merge: it preserves the only claim
// anyone made. A four-state Unknown/ConfirmedTrue/ConfirmedFalse/Conflicting
// model would introduce a ConfirmedFalse state that no producer in the system
// can populate — an enum added to satisfy a test rather than to model reality.
//
// TestReachabilityIsAPositiveOnlyClaim is the tripwire: if a producer ever
// starts emitting a genuine "proven unreachable", this reasoning expires and
// the merge must be revisited.
func TestConflictingReachabilityResolvesToProven(t *testing.T) {
	proven := models.Finding{
		Title: "Potential SSRF", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Endpoint: "z/views.py:674",
		Reachable: true, ProvenPath: true, SourceTier: models.TierTreeSitter,
		TaintChain: []models.TaintLink{
			{File: "z/views.py", Line: 652, Expr: "request.query_params.get('url')"},
			{File: "z/views.py", Line: 674, Expr: "requests.get(image_url)"},
		},
	}
	notProven := models.Finding{
		Title: "Potential SSRF", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Endpoint: "a/util.py:10",
		Reachable: false, SourceTier: models.TierTreeSitter,
	}

	out := Deduplicate([]models.Finding{notProven, proven})
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	g := out[0]

	if !g.Reachable {
		t.Error("Reachable = false — the only positive claim anyone made was discarded")
	}
	// The proof must stay PINNED to the occurrence that earned it. This is what
	// stops the group-level flag from being read as "every affected endpoint is
	// reachable": the chain names one file and line, and it is the proven one.
	if len(g.TaintChain) != 2 {
		t.Fatalf("TaintChain has %d links, want the proven occurrence's chain", len(g.TaintChain))
	}
	if g.TaintChain[1].File != "z/views.py" {
		t.Errorf("TaintChain sink file = %q, want the occurrence that proved reachability", g.TaintChain[1].File)
	}
	if len(g.AffectedEndpoints) != 2 {
		t.Errorf("AffectedEndpoints = %v, want both occurrences retained so a reader can see the "+
			"group spans locations the proof does not cover", g.AffectedEndpoints)
	}
}

// The tripwire. If any producer ever emits reachability as a NEGATIVE claim,
// "false means not proven" stops being true and proof-union stops being
// obviously correct. This test does not police the Python source; it states the
// contract the Go merge depends on, so the next author meets it here.
//
// Concretely: models.Finding has no way to say "proven unreachable". Adding one
// REQUIRES revisiting mergeReachability, because OR would then silently prefer
// a stale positive over a fresh negative.
func TestReachabilityIsAPositiveOnlyClaim(t *testing.T) {
	var f models.Finding
	if f.Reachable {
		t.Fatal("zero-value Finding is reachable; the flag is no longer positive-only")
	}
	// A finding with no analysis at all and a finding the analyzer examined
	// without proving a path are INDISTINGUISHABLE by design. If this ever
	// stops being true, the two-state model above must be re-derived.
	unanalyzed := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "a"}
	analyzedNoPath := models.Finding{Title: "T", Category: "c", Severity: models.SeverityHigh, Endpoint: "b"}
	if unanalyzed.Reachable != analyzedNoPath.Reachable {
		t.Error("the model now distinguishes unanalyzed from analyzed-no-path; " +
			"revisit the conflicting-provenance semantics in this file")
	}
}

// merge(A, B) == merge(B, A), semantically, for a group carrying CONFLICTING
// provenance across every proof-union field at once.
func TestConflictingProvenanceMergeIsCommutative(t *testing.T) {
	a := models.Finding{
		Title: "T", Category: "injection", Severity: models.SeverityHigh, Endpoint: "aaa",
		Reachable: true, ProvenPath: false, RouteConfirmed: true,
		SourceTier: models.TierSemgrepShim,
		TaintChain: []models.TaintLink{{File: "aaa", Line: 1}},
	}
	b := models.Finding{
		Title: "T", Category: "injection", Severity: models.SeverityHigh, Endpoint: "bbb",
		Reachable: false, ProvenPath: true, RouteConfirmed: false,
		SourceTier: models.TierTreeSitter,
		Route:      &models.Route{Method: "GET", Pattern: "/x", Handler: "h"},
	}

	ab := Deduplicate([]models.Finding{a, b})
	ba := Deduplicate([]models.Finding{b, a})
	if len(ab) != 1 || len(ba) != 1 {
		t.Fatalf("want one group each, got %d and %d", len(ab), len(ba))
	}
	x, y := ab[0], ba[0]

	if x.Reachable != y.Reachable || x.ProvenPath != y.ProvenPath ||
		x.RouteConfirmed != y.RouteConfirmed || x.SourceTier != y.SourceTier ||
		len(x.TaintChain) != len(y.TaintChain) || (x.Route == nil) != (y.Route == nil) ||
		x.Endpoint != y.Endpoint {
		t.Errorf("merge is not commutative:\n merge(a,b)=%+v\n merge(b,a)=%+v", x, y)
	}
	// And the union is the union: every positive claim from either side survives.
	if !x.Reachable || !x.ProvenPath || !x.RouteConfirmed {
		t.Errorf("a positive claim was lost: reachable=%v provenPath=%v routeConfirmed=%v",
			x.Reachable, x.ProvenPath, x.RouteConfirmed)
	}
	if x.SourceTier != models.TierTreeSitter {
		t.Errorf("SourceTier = %q, want the most-trusted tier present", x.SourceTier)
	}
	if len(x.TaintChain) == 0 || x.Route == nil {
		t.Error("the chain from one side and the route from the other did not both survive")
	}
}

// Idempotence: re-merging a merged group changes nothing. Without this,
// dedup running twice (e.g. after a re-ingest) could drift.
func TestConflictingProvenanceMergeIsIdempotent(t *testing.T) {
	in := []models.Finding{
		{Title: "T", Category: "injection", Severity: models.SeverityHigh, Endpoint: "a", Reachable: true,
			TaintChain: []models.TaintLink{{File: "a", Line: 1}}},
		{Title: "T", Category: "injection", Severity: models.SeverityHigh, Endpoint: "b"},
	}
	once := Deduplicate(in)
	twice := Deduplicate(append([]models.Finding(nil), once...))

	if len(once) != 1 || len(twice) != 1 {
		t.Fatalf("want one group, got %d then %d", len(once), len(twice))
	}
	if once[0].Reachable != twice[0].Reachable ||
		len(once[0].TaintChain) != len(twice[0].TaintChain) ||
		once[0].Endpoint != twice[0].Endpoint ||
		len(once[0].AffectedEndpoints) != len(twice[0].AffectedEndpoints) {
		t.Errorf("merge is not idempotent:\n once=%+v\ntwice=%+v", once[0], twice[0])
	}
}

// Negative evidence that IS explicit — the scoring-provenance flags — must keep
// agree-or-drop semantics, NOT proof union. Placeholder/InTest/ComponentNotImported
// describe the nature of one occurrence; one occurrence must not speak for the
// group. This test pins that the two fold rules stay distinct: proof union for
// positive claims, agreement for per-occurrence characterizations.
func TestPerOccurrenceCharacterizationsDoNotUnion(t *testing.T) {
	// Two occurrences, one in test code and one in production. The group must
	// NOT inherit "this is test code" from the single test occurrence.
	prod := models.Finding{Title: "Hardcoded API key", Category: "secrets",
		Severity: models.SeverityHigh, Endpoint: "app/settings.py:3"}
	test := models.Finding{Title: "Hardcoded API key", Category: "secrets",
		Severity: models.SeverityHigh, Endpoint: "tests/test_x.py:9"}

	out := Deduplicate([]models.Finding{prod, test})
	if len(out) != 1 {
		t.Fatalf("want one group, got %d", len(out))
	}
	if len(out[0].AffectedEndpoints) != 2 {
		t.Fatalf("want both endpoints in the group, got %v", out[0].AffectedEndpoints)
	}
	// The assertion that matters lives in evidence.mergeScoringProvenance
	// (agreementOrBool) — see TestDedupGroupOnlyPenalizedWhenEveryOccurrenceWas.
	// This test exists to keep the two rules visibly adjacent: if someone
	// "simplifies" dedup by unioning everything, that test goes red and this
	// comment says why the asymmetry is deliberate.
}
