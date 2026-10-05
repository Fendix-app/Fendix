package engine

import (
	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// CorrelateEvidence is the v0.22 Correlation Service V2: it correlates
// black-box and white-box Evidence and returns correlated Evidence.
//
// SAFETY INVARIANT: the rendered projection of the result
// (evidence.ToFindings(CorrelateEvidence(evs))) is byte-identical to the
// legacy Correlate(evidence.ToFindings(evs)) — guaranteed because the merge
// logic IS the proven Correlate(), run on the projected findings, with the
// result lifted back through the lossless adapter. The correlator_v2 test
// locks this equality.
//
// On top of identical render output, it does what a Finding pipeline can't:
//   - preserves the per-evidence provenance (RuleID/Payload/Response/
//     DetectedAt/Metadata/Lineage) that models.Finding has no field for, for
//     findings that pass through correlation unchanged; and
//   - records Lineage on merged (correlated) results, so the BB+WB inputs are
//     no longer lost after mergeFindings.
//
// Because the provenance/lineage live only on the returned Evidence (the
// orchestrator immediately projects back to Finding for the rest of the
// pipeline in v0.22), they cannot affect the public output — they are
// groundwork for the v0.23 confidence engine.
func CorrelateEvidence(evs []evidence.Evidence) []evidence.Evidence {
	// correlateWithMarks, not Correlate: the parallel slice is the only way to
	// learn WHICH outputs the correlator suffixed with "[Unconfirmed by live
	// scan]". FromFindings below cannot recover it — the marker is not a
	// Finding field — and re-deriving it by string-matching the evidence text
	// would make a published prose string load-bearing.
	correlated, unconfirmed := correlateWithMarks(evidence.ToFindings(evs))
	out := evidence.FromFindings(correlated)

	// Index inputs by a render-stable identity so a pass-through output can
	// reclaim the provenance the Finding round-trip dropped. (Fingerprints
	// aren't assigned until after correlation, so we key on content.)
	type idKey struct{ source, category, endpoint, title string }
	inByKey := make(map[idKey]evidence.Evidence, len(evs))
	for _, e := range evs {
		inByKey[idKey{string(e.Source), e.Category, e.Endpoint, e.Title}] = e
	}

	for i := range out {
		o := &out[i]
		// Stamp the correlator's own verdict FIRST, before the pass-through
		// branch's `continue` can skip it. An unconfirmed whitebox finding
		// still matches its input on the idKey below (the branch mutates only
		// the evidence text and Confidence, neither of which is part of the
		// key), so it takes the pass-through path — where the OR-restore below
		// preserves this mark rather than clobbering it with the input's zero.
		o.UnconfirmedByLiveScan = unconfirmed[i]
		if src, ok := inByKey[idKey{string(o.Source), o.Category, o.Endpoint, o.Title}]; ok {
			// Unchanged pass-through: restore its provenance verbatim.
			o.RuleID = src.RuleID
			o.Payload = src.Payload
			o.Response = src.Response
			o.DetectedAt = src.DetectedAt
			o.Metadata = src.Metadata
			o.Lineage = src.Lineage
			// ResponseContext is provenance too (the B4 de-escalation tag).
			// Omitting it here silently discarded the tag for every finding
			// that merely passed THROUGH correlation, which is most of them
			// on a hybrid scan — the 4xx/static-asset penalty then couldn't
			// fire even once the scorer was given the Evidence.
			o.ResponseContext = src.ResponseContext
			// The same trap, six more times. DirectObservation (the scorer's
			// deterministic-read bonus), UnconfirmedByLiveScan (the decision
			// layer's needs-corroboration marker), Placeholder (the
			// fixture-credential de-escalation), ComponentNotImported (the
			// dep-applicability de-escalation) and the AuthExpectation pair
			// (the RC-2 auth-confirmation signals) are all producer-set, and none
			// of them has the endpoint-derived fallback that lets InTest
			// survive being omitted here. Dropping one would leave its rule
			// working on a pure-DAST or pure-SAST scan and silently dead on
			// every hybrid (--url + --code) scan, because the orchestrator
			// builds the ProvenanceIndex AFTER correlation.
			o.DirectObservation = src.DirectObservation
			o.Placeholder = src.Placeholder
			o.ComponentNotImported = src.ComponentNotImported
			// Six now. AuthExpectation / AuthExpectationSource (RC-2) are the
			// same shape: set by the auth check from the spec-derived endpoint
			// inventory, with no endpoint-derived fallback — nothing downstream
			// can re-observe "the specification required auth here". Dropped
			// here, the decision layer's "contradicted authentication
			// requirement" signal would work on a pure-DAST scan and be
			// silently dead on every --url + --code scan.
			o.AuthExpectation = src.AuthExpectation
			o.AuthExpectationSource = src.AuthExpectationSource
			// Seven. Applicability is a fact about the SCANNED TREE observed by
			// the import grep; nothing downstream can re-observe it, and the
			// decision layer now reads it directly.
			o.Applicability = src.Applicability
			// UnconfirmedByLiveScan is OR-ed rather than assigned because THIS
			// function is also a producer for it — the correlator is what
			// discovers that a whitebox finding had no live match. A plain
			// assignment would clobber a mark set earlier in this same loop
			// with the input's zero value.
			o.UnconfirmedByLiveScan = o.UnconfirmedByLiveScan || src.UnconfirmedByLiveScan
			continue
		}
		// Merged/transformed (typically Source=correlated): record the inputs
		// whose endpoint contributed, as lineage. Best-effort and internal —
		// it never affects the rendered Finding.
		o.Lineage = lineageFor(*o, evs)
	}
	return out
}

// lineageFor returns the input evidence whose endpoint matches the (possibly
// merged) output's endpoint set — the constituents of a correlated result.
func lineageFor(out evidence.Evidence, inputs []evidence.Evidence) []evidence.Evidence {
	eps := map[string]bool{out.Endpoint: true}
	for _, e := range out.AffectedEndpoints {
		eps[e] = true
	}
	var lin []evidence.Evidence
	for _, in := range inputs {
		if in.Endpoint != "" && eps[in.Endpoint] {
			lin = append(lin, in)
		}
	}
	return lin
}
