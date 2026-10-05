package evidence

import (
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ── Carrying scoring provenance across the Evidence → Finding projection ────
//
// ToFinding is deliberately lossy: models.Finding is the FROZEN public shape,
// so the Evidence-internal provenance (probe payload/response, the B4 HTTP
// response context, correlation lineage) has nowhere to go. That is correct
// for the report — but the confidence scorer reads exactly those fields, and
// the orchestrator scores at the very END of finalization, long after the
// projection. The result was three rules (payload-validated +10, HTTP-context
// -15, the lineage reason line) that could never fire in production.
//
// ProvenanceIndex closes that gap WITHOUT touching the public shape: capture
// the internal half keyed by the finding's render-stable identity before the
// projection, then re-attach it to the Evidence the scorer sees. Nothing here
// is ever serialized.

// ScoringProvenance is the Evidence-internal half that the scoring layer
// (confidence.Score and decision.Decide*) reads but models.Finding has no
// field for.
//
// INVARIANT: every Evidence-internal field the confidence scorer or the
// decision layer reads must appear here. Two tests in the confidence package
// guard it together, and both are needed:
//
//   - TestScoringProvenanceSurvivesTheFindingProjection scores a populated
//     Evidence, then scores it again after a projection + restore round trip,
//     and fails if the two disagree. It catches a field that is READ by the
//     scorer but not CARRIED here.
//   - TestScoringProvenanceCoversEveryScoredField reflects over this struct and
//     requires every field to be exercised by one of those fixtures. It catches
//     the hole the first test cannot see on its own: a hand-built fixture only
//     covers the fields it happens to populate, so a new field added to Evidence
//     and to this struct — but to no fixture — would otherwise ship green and
//     dead, which is exactly how payload-validated / ResponseContext / lineage
//     became dead code.
type ScoringProvenance struct {
	// Payload / Response are the active-probe request and its reply; the
	// scorer awards payloadValidated only when BOTH are present.
	Payload  string
	Response string
	// ResponseContext is the B4 de-escalation tag ("4xx" / "static-asset").
	ResponseContext string
	// Lineage is the constituent evidence a correlated result merged from;
	// it renders the "evidence chain" reason line (0 points, but part of the
	// explainability contract).
	Lineage []Evidence
	// InTest is the B3 test/fixture-code flag the decision layer reads to
	// de-escalate WARN → INFO. It merges with the same "agree or drop"
	// rule as the rest, which is what stops one test occurrence in a dedup
	// group from de-escalating a production occurrence.
	InTest bool
	// DirectObservation (the confidence scorer's directObservation bonus),
	// UnconfirmedByLiveScan (the decision layer's "needs corroboration to
	// block" marker), Placeholder (the scorer's placeholderPenalty) and
	// ComponentNotImported (the scorer's componentNotImported penalty) are the
	// producer-set flags that joined InTest. All of them merge with the same
	// "agree or drop" rule, so a dedup group earns a bonus only when EVERY
	// occurrence earned it and is de-escalated only when EVERY occurrence
	// deserved it.
	//
	// CRITICAL, and the reason they are grouped and commented together: unlike
	// InTest, NONE of them has an endpoint-derived fallback in
	// NewProvenanceIndex. InTest is a pure function of the endpoint, so a
	// missed hop self-heals; these are known only to their producer, so a
	// missed hop is permanent and silent.
	DirectObservation     bool
	UnconfirmedByLiveScan bool
	Placeholder           bool
	ComponentNotImported  bool
	// ProviderAnchored joins them, with one difference recorded at the merge
	// site: it folds by UNION, not agree-or-drop, because it withholds a
	// de-escalation rather than granting a bonus.
	ProviderAnchored bool
	// CrossToolCorroborated + CorroboratingTools are the outputs of strong
	// cross-tool correlation (engine.CorrelateCrossTool): an INDEPENDENT
	// tool reported the same normalized CWE at the same normalized location.
	// The decision layer counts the flag as a corroborating signal and the
	// scorer awards crossToolCorroborated, so like the four flags above they
	// must survive the Finding projection.
	//
	// UNLIKE the four flags above, these two fold by PROOF UNION rather than
	// agree-or-drop (see mergeScoringProvenance): corroboration is a fact
	// about the logical vulnerability backed by an explicit tool-identity
	// record, so an uncorroborated duplicate occurrence in the dedup group
	// must not erase it — while occurrences with no record contribute
	// nothing, so dedup can never manufacture it. Correlation establishes
	// trust; everything after correlation only preserves it.
	CrossToolCorroborated bool
	CorroboratingTools    []string
	// AuthExpectation / AuthExpectationSource are the RC-2 fields: what a
	// source of truth declared about authentication for this endpoint. Like
	// the producer-set flags above they have NO endpoint-derived fallback —
	// only the spec parse knows them — so a missed hop here is permanent and
	// silent, which is why they are carried explicitly.
	//
	// They fold by agree-or-drop: two endpoints in one dedup group that
	// disagree about whether auth was expected collapse to Unknown. That is
	// the conservative reading (the group no longer supports either claim)
	// and keeps the fold commutative.
	AuthExpectation       models.AuthExpectation
	AuthExpectationSource string
	// Applicability is the three-state dependency-applicability verdict. It
	// supersedes ComponentNotImported (kept alongside for one release) and, like
	// it, is observed by the scanner walking the source tree — nothing
	// downstream of the projection can re-observe it.
	Applicability models.Applicability
}

// ProvenanceIndex maps a render-stable finding identity to the scoring
// provenance of the Evidence it was projected from. Build it immediately
// before the projection; consume it with Restore immediately before scoring.
type ProvenanceIndex map[string]ScoringProvenance

// identityKey is the render-stable identity of a finding: the same
// (Category, Endpoint, Title) triple models.Fingerprint hashes. It is stable
// across every finalization step that runs between the projection and
// scoring — escalation and consistency touch Severity only, dedup keeps one
// group member verbatim, sort/ID-assignment/ignore/baseline reorder or drop
// but never rewrite these three fields.
//
// NUL separators keep the encoding injective (no field may contain NUL).
func identityKey(category, endpoint, title string) string {
	return category + "\x00" + endpoint + "\x00" + title
}

// NewProvenanceIndex indexes the scoring provenance of evs.
//
// Two Evidence sharing one identity are merged with agreementOr — see
// mergeScoringProvenance for why that is both deterministic and conservative.
func NewProvenanceIndex(evs []Evidence) ProvenanceIndex {
	ix := make(ProvenanceIndex, len(evs))
	for _, e := range evs {
		k := identityKey(e.Category, e.Endpoint, e.Title)
		p := ScoringProvenance{
			Payload:         e.Payload,
			Response:        e.Response,
			ResponseContext: e.ResponseContext,
			Lineage:         e.Lineage,
			// Derive the test-context flag from the endpoint when the producer
			// did not set it. Deriving HERE (rather than in each scanner) gives
			// one classification point for every engine — including the Python
			// bridge, whose `in_test` wire field is dropped by the
			// models.Finding unmarshal — and keeps the rule a pure function of
			// the endpoint, so it stays reproducible.
			InTest: e.InTest || models.IsTestPath(e.Endpoint),
			// No `|| derive(...)` clause for the four below, on purpose:
			// nothing on a projected Finding can reconstruct them, so an
			// invented fallback would be a guess rather than a recovery.
			// ComponentNotImported in particular is a fact about the SCANNED
			// TREE, which nothing downstream of the scanner can re-observe.
			DirectObservation:     e.DirectObservation,
			UnconfirmedByLiveScan: e.UnconfirmedByLiveScan,
			Placeholder:           e.Placeholder,
			ProviderAnchored:      e.ProviderAnchored,
			ComponentNotImported:  e.ComponentNotImported,
			CrossToolCorroborated: e.CrossToolCorroborated,
			CorroboratingTools:    e.CorroboratingTools,
			AuthExpectation:       e.AuthExpectation,
			AuthExpectationSource: e.AuthExpectationSource,
			Applicability:         e.Applicability,
		}
		if prev, ok := ix[k]; ok {
			p = mergeScoringProvenance(prev, p)
		}
		ix[k] = p
	}
	return ix
}

// Restore returns a copy of evs with each element's scoring provenance
// re-attached from the index. Fields already set on the input are never
// overwritten, so restoring Evidence that never lost its provenance is a
// no-op.
//
// A finding that dedup collapsed carries the whole group in
// AffectedEndpoints; its provenance is the merge over every endpoint in the
// group, so a de-escalation tag only survives when EVERY occurrence carried
// it. That is the same "only ever observed on a 4xx" rule the CORS scanner
// applies per-endpoint, extended across the dedup merge.
//
// An identity that is not in the index contributes the zero provenance, which
// is exactly what an absent entry means — so a miss degrades to today's
// behaviour (score off the projected fields alone) rather than guessing.
func (ix ProvenanceIndex) Restore(evs []Evidence) []Evidence {
	if evs == nil {
		return nil
	}
	out := make([]Evidence, len(evs))
	copy(out, evs)
	if len(ix) == 0 {
		return out
	}
	for i := range out {
		p := ix.lookup(out[i])
		if out[i].Payload == "" {
			out[i].Payload = p.Payload
		}
		if out[i].Response == "" {
			out[i].Response = p.Response
		}
		if out[i].ResponseContext == "" {
			out[i].ResponseContext = p.ResponseContext
		}
		if len(out[i].Lineage) == 0 {
			out[i].Lineage = p.Lineage
		}
		if !out[i].InTest {
			out[i].InTest = p.InTest
		}
		if !out[i].DirectObservation {
			out[i].DirectObservation = p.DirectObservation
		}
		if !out[i].UnconfirmedByLiveScan {
			out[i].UnconfirmedByLiveScan = p.UnconfirmedByLiveScan
		}
		if !out[i].Placeholder {
			out[i].Placeholder = p.Placeholder
		}
		if !out[i].ProviderAnchored {
			out[i].ProviderAnchored = p.ProviderAnchored
		}
		if !out[i].ComponentNotImported {
			out[i].ComponentNotImported = p.ComponentNotImported
		}
		if !out[i].CrossToolCorroborated {
			out[i].CrossToolCorroborated = p.CrossToolCorroborated
		}
		if len(out[i].CorroboratingTools) == 0 {
			out[i].CorroboratingTools = p.CorroboratingTools
		}
		if out[i].AuthExpectation == models.AuthExpectationUnknown {
			out[i].AuthExpectation = p.AuthExpectation
		}
		if out[i].AuthExpectationSource == "" {
			out[i].AuthExpectationSource = p.AuthExpectationSource
		}
		if out[i].Applicability == models.ApplicabilityUnknown {
			out[i].Applicability = p.Applicability
		}
	}
	return out
}

// lookup resolves the provenance for one finding-shaped Evidence, merging
// across its dedup group when it has one.
func (ix ProvenanceIndex) lookup(e Evidence) ScoringProvenance {
	if len(e.AffectedEndpoints) == 0 {
		return ix[identityKey(e.Category, e.Endpoint, e.Title)]
	}
	// mergeScoringProvenance is commutative, associative and idempotent, so
	// the fold is independent of the (already sorted) endpoint order — and of
	// whether AffectedEndpoints repeats the primary Endpoint.
	merged := ix[identityKey(e.Category, e.Endpoint, e.Title)]
	for _, ep := range e.AffectedEndpoints {
		if ep == e.Endpoint {
			continue
		}
		merged = mergeScoringProvenance(merged, ix[identityKey(e.Category, ep, e.Title)])
	}
	return merged
}

// mergeScoringProvenance folds two provenances for the same finding identity.
//
// The rule is "agree or drop": a field survives only when both sides carry
// the identical value, otherwise it collapses to zero. That makes the merge a
// commutative/associative/idempotent meet — the result is a pure function of
// the member SET, not of worker-pool arrival order (the same F-L6
// determinism property dedup enforces) — and it is the conservative reading:
// a bonus is awarded only when every occurrence earned it, and a
// de-escalation applies only when every occurrence was de-escalated.
//
// ONE DELIBERATE EXCEPTION: the cross-tool corroboration pair folds by
// PROOF UNION, not agreement. The other flags describe the nature of each
// occurrence ("this match is in test code", "this value is fixture-shaped"),
// where one occurrence must not speak for the group. Corroboration is
// different in kind: it is a positive fact about the LOGICAL VULNERABILITY,
// established once by engine.CorrelateCrossTool's strong predicate and
// carried with its proof — the independent tool identities in
// CorroboratingTools. An uncorroborated duplicate occurrence joining the
// group does not negate that proof, so agreement-folding it away would erase
// a valid independent-engine confirmation (the exact regression
// engine.TestCorroborationSurvivesUncorroboratedDuplicate pins).
//
// The union CANNOT manufacture trust: only CorrelateCrossTool ever writes a
// tool into CorroboratingTools, so the union of records from occurrences
// that were never stamped is empty, and the merged flag is derived from the
// union — corroborated iff at least one validated tool-identity record
// survives. Correlation establishes trust; this fold (and dedup around it)
// only preserves it. Sorted-set union keeps the fold commutative,
// associative and idempotent, so F-L6 determinism holds.
func mergeScoringProvenance(a, b ScoringProvenance) ScoringProvenance {
	tools := unionSorted(a.CorroboratingTools, b.CorroboratingTools)
	return ScoringProvenance{
		Payload:         agreementOr(a.Payload, b.Payload),
		Response:        agreementOr(a.Response, b.Response),
		ResponseContext: agreementOr(a.ResponseContext, b.ResponseContext),
		Lineage:         agreementOrLineage(a.Lineage, b.Lineage),
		InTest:          agreementOrBool(a.InTest, b.InTest),

		DirectObservation:     agreementOrBool(a.DirectObservation, b.DirectObservation),
		UnconfirmedByLiveScan: agreementOrBool(a.UnconfirmedByLiveScan, b.UnconfirmedByLiveScan),
		Placeholder:           agreementOrBool(a.Placeholder, b.Placeholder),
		ComponentNotImported:  agreementOrBool(a.ComponentNotImported, b.ComponentNotImported),
		// UNION, deliberately breaking the agree-or-drop rule its neighbours
		// follow. Those flags grant a bonus or a de-escalation, so requiring
		// every occurrence to agree is the conservative direction. This one
		// WITHHOLDS a de-escalation, so the conservative direction is the
		// opposite: if any occurrence in the group carries a provider's
		// signature, the group keeps its full weight.
		ProviderAnchored: a.ProviderAnchored || b.ProviderAnchored,
		// Derived from the surviving proof, never from the bare flags: a
		// true flag with no tool record (which no producer emits) does not
		// survive the merge — corroboration without its proof is not
		// corroboration.
		CrossToolCorroborated: len(tools) > 0,
		CorroboratingTools:    tools,
		AuthExpectation: models.AuthExpectation(
			agreementOr(string(a.AuthExpectation), string(b.AuthExpectation))),
		AuthExpectationSource: agreementOr(a.AuthExpectationSource, b.AuthExpectationSource),
		// Agree-or-drop: two dependency findings in one group that disagree
		// about applicability collapse to Unknown, which is the conservative
		// reading — the group no longer supports either claim.
		Applicability: models.Applicability(
			agreementOr(string(a.Applicability), string(b.Applicability))),
	}
}

// unionSorted returns the sorted, deduped union of two tool-identity lists;
// nil when both are empty. Commutative, associative, idempotent.
func unionSorted(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	set := make(map[string]bool, len(a)+len(b))
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func agreementOr(a, b string) string {
	if a == b {
		return a
	}
	return ""
}

// agreementOrBool is agreementOr for a flag: the value survives only when both
// sides agree, which for a bool is exactly logical AND (true+true→true;
// false+false→false; a disagreement collapses to false). Commutative,
// associative and idempotent, so folding it over a dedup group is independent
// of member order — and it is the conservative reading: a group earns the
// test-fixture de-escalation only when EVERY occurrence in it is test code.
func agreementOrBool(a, b bool) bool {
	return a && b
}

func agreementOrLineage(a, b []Evidence) []Evidence {
	if lineageKey(a) == lineageKey(b) {
		return a
	}
	return nil
}

// lineageKey renders a lineage into a comparable string using exactly the
// fields lineageTrace reports plus the identity triple, so two lineages
// compare equal iff they produce the same reason line for the same inputs.
func lineageKey(l []Evidence) string {
	if len(l) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, e := range l {
		sb.WriteString(string(e.Source))
		sb.WriteByte(0)
		sb.WriteString(e.Category)
		sb.WriteByte(0)
		sb.WriteString(e.Endpoint)
		sb.WriteByte(0)
		sb.WriteString(e.Title)
		sb.WriteByte('\n')
	}
	return sb.String()
}
