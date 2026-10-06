// Package evidence is the v0.22 domain layer in Fendix's
// Engine → Evidence → Finding → Decision architecture.
//
// An Evidence is everything an analysis engine observed about a potential
// issue. It is a SUPERSET of the rendered models.Finding: it carries every
// field a Finding renders, plus richer provenance the public Finding JSON
// does not expose — the exact rule/check id, the raw probe payload and
// response (DAST), a detection timestamp, free-form metadata, and, for
// correlated results, the lineage of the inputs that merged.
//
// Findings are PROJECTED from Evidence via ToFinding. The reporters still
// marshal models.Finding, so the public JSON/SARIF/HTML contract is
// unchanged — that invariant is the whole point of v0.22, and it is enforced
// by the round-trip identity tests in this package plus the output-snapshot
// and schema regression suites.
//
// The "render block" below MUST stay field-for-field in sync with
// models.Finding; the adapter tests fail loudly if it drifts.
package evidence

import (
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Evidence is the domain object produced by engines and consumed by the
// correlation service and (eventually) the decision layer.
type Evidence struct {
	// --- Render block: projected 1:1 onto models.Finding ------------------
	// Field names match models.Finding EXACTLY (including Evidence — yes, an
	// Evidence field on the Evidence type), so a scanner migrates from
	// building models.Finding{...} to evidence.Evidence{...} by swapping the
	// type name and nothing else. Keep in lockstep with models.Finding.
	ID          string
	Fingerprint string
	// FingerprintV1 is the retired identity, carried alongside Fingerprint
	// purely so downstream consumers can bridge the v1→v2 re-key.
	FingerprintV1     string
	Title             string
	Severity          models.Severity
	Source            models.Source
	Category          string
	Endpoint          string
	AffectedEndpoints []string
	// Occurrences mirrors models.Finding.Occurrences: the per-occurrence
	// identities of a grouped finding, carried so a Finding→Evidence→Finding
	// round trip cannot drop them.
	Occurrences    []models.Occurrence
	Evidence       string // the human-readable snippet (== models.Finding.Evidence)
	Fix            string
	References     []string
	Confidence     models.Confidence
	Line           *string
	TaintChain     []models.TaintLink
	Reachable      bool
	SourceTier     models.SourceTier
	Route          *models.Route
	RouteConfirmed bool
	ProvenPath     bool
	// v0.24 decision-report fields (render block; project 1:1 onto Finding).
	Status            string
	ConfidenceScore   int
	ConfidenceBand    string
	ConfidenceReasons []string
	// ConfidenceBreakdown is the machine-readable twin of ConfidenceReasons
	// and is projected 1:1 exactly as it is. The two are ONE breakdown in two
	// forms; carrying only the strings through the adapter would let the
	// structured form vanish at the Evidence→Finding boundary while the prose
	// survived, which is the specific asymmetry the parity work removed.
	ConfidenceBreakdown []models.ConfidenceReason

	// RuleID is the precise rule/check identity (e.g. a semgrep rule id, a
	// DAST check name, or a CVE for an advisory) — finer-grained than
	// Category.
	//
	// PROJECTED, as of the v2 fingerprint. It used to live in the
	// internal-only block below, and dropping it was the root cause of RC-5:
	// by the time the orchestrator stamped a fingerprint, the only identity
	// material left on the Finding was Category|Endpoint|Title, and Endpoint
	// for a whitebox finding is "path:line". Identity had nothing semantic to
	// hold on to, so it held on to the line number.
	RuleID string
	// Dependency / Secret are the per-family semantic identities the v2
	// fingerprint keys on. Both are projected for the same reason as RuleID:
	// identity must be built from structure the model carries, never
	// reconstructed by parsing a rendered Title.
	Dependency *models.DependencyRef
	Secret     *models.SecretRef
	// Sink is the normalized vulnerable operation — see models.Finding.Sink.
	Sink string
	// Symbol is the enclosing function — see models.Finding.Symbol.
	Symbol string

	// --- v0.22 provenance: INTERNAL ONLY, never serialized into Finding ---
	// ToFinding drops every field below. Anything here that confidence.Score
	// reads must also be carried by ScoringProvenance (provenance.go),
	// otherwise the rule that reads it is dead for any caller downstream of
	// the projection — see the comment at the top of provenance.go.
	// Payload is the request/probe Fendix sent (DAST); empty for static evidence.
	Payload string
	// Response is a bounded excerpt of what the target returned (DAST).
	Response string
	// DetectedAt is when in the scan this evidence was observed.
	DetectedAt time.Time
	// Lineage holds the constituent evidence that merged into this one
	// (populated by the correlation service for Source=correlated results),
	// so the BB+WB inputs are no longer lost after a merge.
	Lineage []Evidence
	// Metadata is free-form structural context (scanner version, etc.).
	Metadata map[string]string
	// ResponseContext tags DAST evidence with de-escalation context (B4):
	// "4xx" (the finding fired on an auth-gated / client-error response) or
	// "static-asset" (a static file, not an API route). The confidence
	// scorer applies a penalty; evidence is preserved (Rule 3). INTERNAL —
	// never projected onto Finding, so the public JSON/SARIF contract is
	// unchanged.
	ResponseContext string
	// InTest marks evidence whose sink lives in test / fixture code (B3).
	// The decision layer de-escalates such a finding from WARN to INFO when
	// the scan policy asks for it (ScanConfig.DeescalateTests) — evidence is
	// preserved, never suppressed (Rule 3), and a BLOCK at/above --fail-on is
	// never downgraded.
	//
	// Producers may set this directly; NewProvenanceIndex otherwise derives it
	// from the endpoint via models.IsTestPath, so every engine (native Go and
	// the Python bridge alike) gets the same classification without an IPC
	// change. INTERNAL — never projected onto Finding.
	InTest bool
	// DirectObservation marks evidence whose claim is a DETERMINISTIC READ of a
	// single live response: a header present or absent, a cookie attribute
	// present or absent, a literal CORS header value. Such a claim carries no
	// inference about exploitability, reachability or intent — it is what the
	// wire said. Set by the emitting scanner (headers.go, cors.go,
	// cookie_flags.go); the confidence scorer awards directObservation for it.
	//
	// Unlike InTest there is NO derivable fallback — NewProvenanceIndex
	// re-derives InTest from the endpoint via models.IsTestPath, and nothing on
	// models.Finding can re-derive this — so it MUST be carried by
	// ScoringProvenance AND restored by engine.CorrelateEvidence, or the rule is
	// permanently dead. INTERNAL — never projected onto Finding.
	DirectObservation bool
	// UnconfirmedByLiveScan marks evidence the correlator could not confirm
	// against the live scan: correlation actually ran (both a blackbox and a
	// whitebox slice existed), the whitebox endpoint is URL-shaped, and no
	// blackbox match was found. It is the machine-readable counterpart of the
	// "[Unconfirmed by live scan]" prose suffix the correlator already writes
	// into the evidence text, and the decision layer reads it to hold such a
	// finding at WARN.
	//
	// Deliberately NOT named `Confirmed`: the zero value would then assert
	// "unconfirmed" for every producer that never runs through the correlator
	// (every code-only scan), inverting the meaning of the default. Like
	// DirectObservation it has no endpoint-derivable fallback. INTERNAL — never
	// projected onto Finding.
	UnconfirmedByLiveScan bool
	// Placeholder marks credential evidence whose value matched the
	// deterministic fixture heuristics in scanner/secrets: a
	// FAKE_/TEST_/DUMMY_/MOCK_/EXAMPLE_/PLACEHOLDER_/SAMPLE_ variable name, a
	// placeholder word inside the value, a dominant-character or long-run
	// value, or an implausibly short value. The confidence scorer applies
	// placeholderPenalty; the finding is still reported with full evidence
	// (Rule 3) — this is de-escalation, never suppression.
	//
	// Like the two above it CANNOT be re-derived from the endpoint, so it must
	// be carried explicitly by ScoringProvenance AND restored by
	// engine.CorrelateEvidence. INTERNAL — never projected onto Finding.
	Placeholder bool
	// ProviderAnchored marks credential evidence whose VALUE carries a known
	// provider's signature — an AKIA… access-key id, a ghp_/gho_/ghu_/ghs_
	// GitHub token, sk_live_…, xox[abprs]-…, AIza… — rather than merely being
	// a high-entropy string a generic rule matched.
	//
	// It exists to bound fixture de-escalation. The placeholder heuristics
	// include a signal read off the variable NAME (FAKE_/TEST_/DUMMY_…), and a
	// name is chosen by whoever wrote the line — it is evidence about their
	// intent, never about the credential. `TEST_STRIPE_KEY = "sk_live_…"` is a
	// live key with a misleading label, and letting the label alone push it
	// below WARN would suppress exactly the leak that matters most.
	//
	// So this flag does not de-escalate anything. It VETOES a de-escalation
	// that other signals would otherwise have earned, which is why it merges
	// by union rather than agreement: one provider-anchored occurrence in a
	// dedup group is enough to withhold the drop for the whole group.
	//
	// Like the flags above it cannot be re-derived from the endpoint, so it
	// must be carried by ScoringProvenance and restored. INTERNAL — never
	// projected onto Finding.
	ProviderAnchored bool
	// ComponentNotImported marks dependency evidence whose advisory is scoped
	// to a specific importable sub-component — a Django advisory that only
	// touches django.contrib.gis, say — that the scanned tree never imports.
	// The vulnerable package IS installed, so this is a weaker inference than
	// the HTTP-context de-escalation: it says the reachable surface is
	// smaller, not that the finding is wrong. The confidence scorer applies
	// componentNotImported (-10) and the finding is PRESERVED in full with its
	// evidence text (Rule 3), never suppressed.
	//
	// Set by scanner/deps/applicability, which is the only thing that can know
	// it — like the three flags above it has NO endpoint-derived fallback, so
	// it must be carried by ScoringProvenance AND restored by
	// engine.CorrelateEvidence. INTERNAL — never projected onto Finding.
	ComponentNotImported bool
	// Applicability is the three-state dependency-applicability verdict
	// (unknown / applicable / evidence_against). It SUPERSEDES
	// ComponentNotImported, whose false conflated "the component is imported"
	// with "we never evaluated this".
	//
	// ComponentNotImported is retained for one release as a derived alias so an
	// out-of-tree producer that still sets it keeps working; ApplicabilityOf
	// resolves the pair. Set by scanner/deps/applicability, which is the only
	// thing that can know it — like the flags above it has NO endpoint-derived
	// fallback and must be carried by ScoringProvenance.
	Applicability models.Applicability
	// AuthExpectation is what a source of truth DECLARED about authentication
	// for this endpoint, and AuthExpectationSource names that source
	// ("openapi", "static-route", "differential"). They are what let the
	// decision layer treat a contradicted requirement as INDEPENDENT
	// corroboration — the spec says protected, the wire says open, and those
	// are two observations that could have agreed — while an unauthenticated
	// 200 on an endpoint of unknown expectation stays observational.
	//
	// Unknown ("") is a real third state, not a default standing in for
	// Public: see models.AuthExpectation.
	//
	// Like DirectObservation these have NO endpoint-derived fallback — nothing
	// on a projected Finding can reconstruct them — so they must be carried by
	// ScoringProvenance and restored before scoring, or the rule is dead.
	AuthExpectation       models.AuthExpectation
	AuthExpectationSource string
	// Weakness is the normalized CWE identity of the claim ("CWE-89", …),
	// the machine-readable input to cross-tool correlation. Producers:
	// sarifimport extracts it from SARIF rule taxa/tags; StampWeakness
	// derives it for native evidence from exact CWE-NNN reference tokens.
	// The correlator reads ONLY this field — never free-form References —
	// so weakness matching cannot drift with reference prose. INTERNAL —
	// never projected onto Finding.
	Weakness []string
	// ToolID is the normalized identity of the effective engine that
	// produced this evidence ("fendix", "semgrep", "codeql", …), used to
	// decide independence during cross-tool correlation. Set by sarifimport
	// for imports; derived for native evidence by engine.CorrelateCrossTool
	// (fendix, except the semgrep shim tier which is "semgrep" so an
	// imported semgrep SARIF is correctly NOT independent of it). SARIF
	// filename is never identity. INTERNAL — never projected onto Finding.
	ToolID string
	// CrossToolCorroborated marks evidence that STRONG cross-tool
	// correlation confirmed: an independent tool reported the same
	// normalized CWE at the same normalized location (see
	// engine.CorrelateCrossTool for the exact predicate). It is the ONLY
	// signal by which imported evidence may strengthen a decision — the
	// decision layer counts it as a corroborating signal and the confidence
	// scorer awards crossToolCorroborated. Like the producer-set flags
	// above it has NO fallback and must be carried by ScoringProvenance.
	// INTERNAL — never projected onto Finding.
	CrossToolCorroborated bool
	// CorroboratingTools names the independent tools behind
	// CrossToolCorroborated (sorted, deduped), for the explainability line.
	// INTERNAL — never projected onto Finding.
	CorroboratingTools []string
	// LineEnd is the last line of the finding's source region when the
	// producer knows a RANGE (SARIF region endLine). 0 means "no range" —
	// only the rendered Line (start) is known. Cross-tool correlation
	// prefers overlapping ranges over raw line proximity when BOTH sides
	// carry one. INTERNAL — never projected onto Finding.
	LineEnd int
}

// ApplicabilityOf resolves the effective applicability verdict for ev, honouring
// the deprecated ComponentNotImported alias.
//
// The alias resolves to EvidenceAgainst and NEVER to Applicable: a producer
// that only knows the old bool can assert "no affected component is imported"
// but cannot assert the converse — its false has always meant "either imported
// or never checked". Reading it as Applicable would manufacture a claim the
// producer never made, which is the exact conflation the enum exists to end.
func ApplicabilityOf(ev Evidence) models.Applicability {
	if ev.Applicability != models.ApplicabilityUnknown {
		return ev.Applicability
	}
	if ev.ComponentNotImported {
		return models.ApplicabilityEvidenceAgainst
	}
	return models.ApplicabilityUnknown
}

// FromFinding lifts a models.Finding into Evidence, copying the render block
// verbatim and leaving the new provenance zero. This is the migration
// boundary: a scanner not yet emitting Evidence can have its Finding lifted
// losslessly so it flows through the Evidence pipeline unchanged.
func FromFinding(f models.Finding) Evidence {
	return Evidence{
		ID:                  f.ID,
		Fingerprint:         f.Fingerprint,
		FingerprintV1:       f.FingerprintV1,
		Title:               f.Title,
		Severity:            f.Severity,
		Source:              f.Source,
		Category:            f.Category,
		Endpoint:            f.Endpoint,
		AffectedEndpoints:   f.AffectedEndpoints,
		Occurrences:         f.Occurrences,
		Evidence:            f.Evidence,
		Fix:                 f.Fix,
		References:          f.References,
		Confidence:          f.Confidence,
		Line:                f.Line,
		TaintChain:          f.TaintChain,
		Reachable:           f.Reachable,
		SourceTier:          f.SourceTier,
		Route:               f.Route,
		RouteConfirmed:      f.RouteConfirmed,
		ProvenPath:          f.ProvenPath,
		Status:              f.Status,
		ConfidenceScore:     f.ConfidenceScore,
		ConfidenceBand:      f.ConfidenceBand,
		ConfidenceReasons:   f.ConfidenceReasons,
		ConfidenceBreakdown: f.ConfidenceBreakdown,
		RuleID:              f.RuleID,
		Dependency:          f.Dependency,
		Secret:              f.Secret,
		Sink:                f.Sink,
		Symbol:              f.Symbol,
	}
}

// ToFinding projects Evidence back to the public models.Finding shape. This
// is the ONLY representation the reporters see, so it MUST reproduce the
// Finding exactly — the round-trip tests assert FromFinding∘ToFinding is the
// identity on every Finding field (and therefore on the marshaled JSON).
func (e Evidence) ToFinding() models.Finding {
	return models.Finding{
		ID:                  e.ID,
		Fingerprint:         e.Fingerprint,
		FingerprintV1:       e.FingerprintV1,
		Title:               e.Title,
		Severity:            e.Severity,
		Source:              e.Source,
		Category:            e.Category,
		Endpoint:            e.Endpoint,
		AffectedEndpoints:   e.AffectedEndpoints,
		Occurrences:         e.Occurrences,
		Evidence:            e.Evidence,
		Fix:                 e.Fix,
		References:          e.References,
		Confidence:          e.Confidence,
		Line:                e.Line,
		TaintChain:          e.TaintChain,
		Reachable:           e.Reachable,
		SourceTier:          e.SourceTier,
		Route:               e.Route,
		RouteConfirmed:      e.RouteConfirmed,
		ProvenPath:          e.ProvenPath,
		Status:              e.Status,
		ConfidenceScore:     e.ConfidenceScore,
		ConfidenceBand:      e.ConfidenceBand,
		ConfidenceReasons:   e.ConfidenceReasons,
		ConfidenceBreakdown: e.ConfidenceBreakdown,
		RuleID:              e.RuleID,
		Dependency:          e.Dependency,
		Secret:              e.Secret,
		Sink:                e.Sink,
		Symbol:              e.Symbol,
	}
}

// FromFindings / ToFindings are slice helpers for the pipeline boundary.
func FromFindings(fs []models.Finding) []Evidence {
	if fs == nil {
		return nil
	}
	out := make([]Evidence, len(fs))
	for i, f := range fs {
		out[i] = FromFinding(f)
	}
	return out
}

// ToFindings projects a slice of Evidence to Findings for the reporters.
func ToFindings(es []Evidence) []models.Finding {
	if es == nil {
		return nil
	}
	out := make([]models.Finding, len(es))
	for i, e := range es {
		out[i] = e.ToFinding()
	}
	return out
}
