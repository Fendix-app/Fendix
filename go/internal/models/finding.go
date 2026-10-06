// Package models defines the core data types shared across Fendix.
// Finding, Severity, Confidence, and Source are the primary types
// used by both Go and Python engines via the IPC contract.
package models

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents how certain we are about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Source indicates which engine produced the finding.
type Source string

const (
	SourceBlackbox   Source = "blackbox"
	SourceWhitebox   Source = "whitebox"
	SourceCorrelated Source = "correlated"
	// SourceImported marks a finding ingested from another scanner's SARIF
	// report (`fendix import` / `scan --import`). Imported findings carry an
	// empty SourceTier on purpose — the correlator scores unknown tiers most
	// conservatively, so external evidence can never masquerade as a native
	// high-trust analyzer. They are fenced out of the blackbox↔whitebox
	// correlator entirely; the only way an import strengthens another finding
	// is the strong-corroboration path in engine.CorrelateCrossTool.
	SourceImported Source = "imported"
)

// SourceTier records WHICH analysis engine tier produced a whitebox
// finding (Proven Path v1 / roadmap "Tier provenance enforcement"). The
// correlator weights tiers differently when escalating confidence: a
// CRITICAL driven by a Tier-3 semgrep regex that never cleared the
// F1≥0.95 gate must not escalate to CRITICAL via correlation. Preserved
// end-to-end through NDJSON IPC → correlator → ScanFinding → UI so the
// F1 gate can't be silently bypassed by the correlation moat.
//
// Empty for blackbox findings (no code tier produced them) and for
// pre-existing findings emitted before the field existed — treat empty
// as "unknown tier", which the correlator scores most conservatively.
type SourceTier string

const (
	// TierNativeGo: in-binary Go analysis (textscan today; gosast later).
	TierNativeGo SourceTier = "native_go"
	// TierTreeSitter: the Python/tree-sitter sidecar (the AST taint
	// analyzer that emits taint chains — the highest-trust SAST tier).
	TierTreeSitter SourceTier = "tree_sitter_sidecar"
	// TierSemgrepShim: shelled-out semgrep (breadth, lowest trust until a
	// rule pack clears the F1 gate).
	TierSemgrepShim SourceTier = "semgrep_shim"
)

// TrustRank orders the analysis tiers by how much the engine trusts them.
// Higher wins. Used to pick the representative when two engines report the
// SAME sink at the same location, so the surviving finding is the one from the
// most trustworthy analyzer rather than whichever happened to run first.
//
// The ordering mirrors the correlator's escalation gate (TASK-125): the
// tree-sitter taint analyzer proves a dataflow path, native Go rules are
// in-binary and line-exact, and the semgrep shim buys breadth at the cost of
// precision until its rule pack clears the F1 gate. An empty tier ("unknown",
// e.g. the SCA scanners) sorts above only semgrep — it is not a low-precision
// regex pass, it simply predates the field.
func (t SourceTier) TrustRank() int {
	switch t {
	case TierTreeSitter:
		return 3
	case TierNativeGo:
		return 2
	case "": // unknown / pre-field (SCA and legacy emitters)
		return 1
	case TierSemgrepShim:
		return 0
	default:
		return 1
	}
}

// AuthExpectation is what Fendix ESTABLISHED about whether an endpoint is
// supposed to require authentication — independently of what it actually did
// when probed.
//
// The zero value is UNKNOWN and that is load-bearing. A target scanned with no
// spec and no static route analysis has no expectation, and "we never
// established one" must never render as "this endpoint is declared public".
// Collapsing unknown into public would silently suppress real bypasses;
// collapsing it into required would flag every public endpoint as CRITICAL,
// which is the RC-2 defect. It is its own state, and the decision layer treats
// it as evidence in neither direction.
type AuthExpectation string

const (
	// AuthExpectationUnknown — never evaluated. NOT a claim in either direction.
	AuthExpectationUnknown AuthExpectation = ""
	// AuthExpectationPublic — a source of truth declares anonymous access
	// intentional (OpenAPI `security: []` or `security: [{}]`).
	AuthExpectationPublic AuthExpectation = "public"
	// AuthExpectationRequired — a source of truth declares authentication
	// required: an operation-level `security` requirement, or an inherited
	// global one the operation does not override.
	AuthExpectationRequired AuthExpectation = "required"
)

// Applicability is what Fendix established about whether a vulnerable
// dependency's AFFECTED COMPONENT is actually used by the scanned project — as
// distinct from whether the vulnerable VERSION is installed, which is what the
// finding itself asserts.
//
// Three states, and exactly three, because three is what the analyzer can
// actually produce (scanner/deps/applicability.resolve):
//
//	Unknown         the advisory names no importable component, or the import
//	                grep overran its budget and failed open. NOT a claim.
//	Applicable      at least one affected component IS imported by the tree.
//	EvidenceAgainst no affected component is imported anywhere in the tree.
//
// The previous model was a single bool, ComponentNotImported, whose false
// conflated "the component IS imported" with "we never evaluated this" — two
// states that must drive different decisions.
//
// DELIBERATELY NOT a fourth "ConfirmedNonApplicable" state. The backing
// evidence is a static import grep, and dynamic import forms
// (importlib.import_module, plugin registries, reflection) mean absence of an
// import is EVIDENCE against applicability, never proof of it. Naming the state
// after what it is — evidence — keeps that honest at every call site.
//
// Symmetrically, Applicable means "the component is imported", not "the
// vulnerable function is reached": Fendix does not build a dependency call
// graph. It is evidence FOR applicability, which is why it restores normal
// policy rather than escalating beyond it.
type Applicability string

const (
	// ApplicabilityUnknown — not evaluated, or evaluation was incomplete.
	ApplicabilityUnknown Applicability = ""
	// ApplicabilityApplicable — an affected component is imported.
	ApplicabilityApplicable Applicability = "applicable"
	// ApplicabilityEvidenceAgainst — no affected component is imported.
	ApplicabilityEvidenceAgainst Applicability = "evidence_against"
)

// Route binds a finding to the HTTP route that reaches its sink (Proven
// Path v1). Populated by the Python route extractor for whitebox findings
// whose enclosing function is a registered Django/Flask/FastAPI handler;
// the correlator uses it to bind a blackbox endpoint to the exact handler
// + taint chain instead of fuzzy path matching. Empty when no route could
// be bound (e.g. a finding in a helper not directly wired to a URL).
type Route struct {
	Method  string `json:"method,omitempty"`  // GET, POST, … ("" = any/unknown)
	Pattern string `json:"pattern,omitempty"` // URL pattern, e.g. /users/<id>
	Handler string `json:"handler,omitempty"` // handler symbol, e.g. views.get_user
	File    string `json:"file,omitempty"`    // file the route is declared in
	Line    int    `json:"line,omitempty"`    // line of the route declaration
}

// TaintLink is one step in a dataflow chain from a source (e.g.
// request.args.get) to a sink (e.g. cursor.execute). The Python AST
// analyzer records these chains for SQLi, SSRF, and open-redirect
// findings (TASK-114) so the correlator and reporters can prove
// "this is reachable" rather than "this looks dangerous."
type TaintLink struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Expr string `json:"expr"`
}

// DependencyRef is the semantic identity of the package a dependency finding
// is about: which ecosystem, which package, which manifest declared it.
//
// It exists because that identity used to live only in the rendered Title
// ("Vulnerable dependency: requests==2.28.0 (CVE-…)"), which made the
// dependency's identity a substring of a human-readable string. Version is
// carried for reporting but is deliberately NOT an identity input — a package
// bumped from one vulnerable version to another is the same unresolved
// vulnerability, and churning its fingerprint would file it as "fixed, plus a
// new one" on every patch release.
type DependencyRef struct {
	Ecosystem string `json:"ecosystem,omitempty"` // PyPI, npm, Go, …
	Package   string `json:"package,omitempty"`
	Version   string `json:"version,omitempty"`
	Manifest  string `json:"manifest,omitempty"` // requirements.txt, package-lock.json, …
}

// SecretRef is the SAFE identity of a committed credential: which
// non-sensitive identifier it was bound to and which file it lives in.
//
// Identifier is the assignment key or config name the credential sits behind
// — AWS_SECRET_ACCESS_KEY, stripe_api_key, the JSON/YAML path. It is
// deliberately NOT the credential, and deliberately NOT a digest of the
// credential.
//
// A digest was the obvious alternative and is rejected on purpose. The
// redaction marker already published in evidence is an unsalted, 4-byte
// truncated SHA-256 — the redact.go doc says outright that a low-entropy
// value is "trivially recoverable from it by dictionary". Evidence is one
// report; a fingerprint is forever: it is committed into .fendix-ignore
// files, saved into baselines, and uploaded to GitHub Code Scanning, where it
// would stand as a permanent, greppable oracle for the credential's value.
// Long-lived identity is exactly the wrong place to persist a reversible
// function of a secret. The identifier distinguishes two credentials in one
// file just as well and carries no credential material.
//
// The residual trade-off, documented rather than hidden: when a pattern
// matches material with no binding identifier (a bare `-----BEGIN … KEY-----`
// block), Identifier is empty and two such blocks in one file share an
// identity — reported as one "private key material in this file" record.
// Merging two key blocks is a reporting imprecision; persisting a credential
// oracle would be a security defect.
type SecretRef struct {
	Identifier string `json:"identifier,omitempty"`
	File       string `json:"file,omitempty"`
}

// ConfidenceReason is one scoring rule's contribution to a confidence score.
// confidence.Reason is an alias of this type; it is declared HERE because it
// has to sit on Finding, and the confidence package imports models — so the
// dependency can only point one way.
type ConfidenceReason struct {
	Delta int    `json:"delta"`
	Code  string `json:"code"`
	Text  string `json:"text"`
}

// Occurrence is one security occurrence inside a (possibly grouped) finding:
// where it is, and its own fendix/v2 fingerprint. The fingerprint is computed
// from that occurrence alone, before any grouping, so it is independent of
// which other occurrences share its presentation group and of how their
// paths sort.
type Occurrence struct {
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint"`
}

// Finding represents a single security finding produced by either engine.
// This struct is the shared data contract between Go and Python.
//
// AffectedEndpoints is populated by the orchestrator's deduplication pass
// (TASK-088) when N findings of the same (Title, Category, Severity)
// collapse into one. The slice contains every affected endpoint including
// the primary one in `Endpoint`. When the finding represents a single
// occurrence, AffectedEndpoints is nil (omitted from JSON via omitempty).
//
// TaintChain and Reachable are populated by the white-box AST analyzer
// when it can prove an intra-function dataflow path from a request-input
// source to a dangerous sink (TASK-114). The correlator promotes a
// blackbox+whitebox match to Source=correlated AND Reachable=true when
// the whitebox half carries a chain — that's the "DAST + SAST agree
// AND we can show the path" case worth a build-failing exit code.
type Finding struct {
	ID string `json:"id"`
	// Fingerprint is the fendix/v2 semantic, run-stable identity for the
	// finding: SHA-256 over labelled identity components, truncated to 20
	// bytes. Unlike ID (a positional SEC-NNN reassigned every run) it excludes
	// line/column coordinates and presentation text, so .fendix-ignore rules and
	// baselines keep matching across line shifts and rewording. The containing
	// file/manifest or HTTP method+path remains part of identity. Stamped
	// centrally in the orchestrator before ID assignment.
	Fingerprint string `json:"fingerprint,omitempty"`
	// FingerprintV1 is the RETIRED sha1(Category|Endpoint|Title) identity for
	// this same finding, published purely as a migration bridge.
	//
	// It is not an identity and nothing may key on it: v1 moved whenever a
	// line was inserted above a finding, which is the defect v2 exists to fix.
	// Its only job is to let a consumer that tracked this finding under v1
	// recognise it after the re-key, instead of reading the transition as
	// "the old finding vanished and a new one appeared" — which is how the
	// hosted backend ended up with two Issues, and two SEC ids, for one
	// vulnerability.
	//
	// Computed here rather than downstream so the mapping is produced by the
	// side that owns both algorithms and cannot drift from either.
	FingerprintV1 string `json:"fingerprint_v1,omitempty"`
	// RuleID is the precise rule/check that fired (e.g. "python.ssrf.taint",
	// "secrets/aws-access-key", or a CVE id for a dependency advisory). It is
	// the single most stable identity input a finding has: unlike Title it is
	// not prose, and unlike Endpoint it does not move when the code does.
	//
	// It has always existed on evidence.Evidence; it was dropped by
	// ToFinding, which is precisely why fingerprinting had nothing semantic
	// left to hash and fell back on Category|Endpoint|Title.
	RuleID string `json:"rule_id,omitempty"`
	// Dependency is the package identity behind a `deps` finding. Nil for
	// every other family.
	Dependency *DependencyRef `json:"dependency,omitempty"`
	// Secret is the safe identity of a committed credential behind a
	// `secrets` finding. Nil for every other family. Never holds credential
	// material — see SecretRef.
	Secret *SecretRef `json:"secret,omitempty"`
	// Sink is the normalized vulnerable OPERATION a code finding is about —
	// "requests.get(url)", "cursor.execute(q)", "open(name)". It is the
	// operation's identity, and it is what separates two vulnerabilities of
	// the same rule in the same symbol.
	//
	// Carried explicitly rather than read off the end of TaintChain, because a
	// chainless finding has no chain to read and would otherwise fall back to
	// its evidence text. Those are different strings, so the fallback made
	// identity move the moment an analyzer learned to PROVE a flow it had only
	// observed — turning an evidence improvement into a new vulnerability. The
	// analyzer knows the sink either way; this is where it says so.
	Sink string `json:"sink,omitempty"`
	// Symbol is the enclosing function or method a code finding sits in.
	//
	// Distinct from Route.Handler on purpose. A Route is bound only when the
	// analyzer PROVED a taint chain and the enclosing function is a registered
	// handler, so route availability tracks how much was proven rather than
	// tracking the code. Identity must not inherit that dependency: the
	// symbol is the same symbol whether or not the flow was proven, and
	// keying on Route.Handler made a finding change identity the moment its
	// chain became provable.
	Symbol            string   `json:"symbol,omitempty"`
	Title             string   `json:"title"`
	Severity          Severity `json:"severity"`
	Source            Source   `json:"source"`
	Category          string   `json:"category"`
	Endpoint          string   `json:"endpoint"`
	AffectedEndpoints []string `json:"affected_endpoints,omitempty"`
	// Occurrences lists every distinct security occurrence this finding
	// presents: one entry per (endpoint, occurrence fingerprint). A finding is
	// a PRESENTATION group; an occurrence is the unit of security identity.
	// Baselines, `.fendix-ignore` rules and lifecycle tracking act on
	// occurrences, never on the group, so a new occurrence that joins an old
	// group can never inherit the group's suppression or disposition. The
	// finding's own Fingerprint is the primary occurrence's fingerprint and
	// always appears here. Emitted for every scanned finding; absent only on
	// reports produced before this field existed.
	Occurrences []Occurrence `json:"occurrences,omitempty"`
	Evidence    string       `json:"evidence"`
	Fix         string       `json:"fix"`
	References  []string     `json:"references"`
	Confidence  Confidence   `json:"confidence"`
	Line        *string      `json:"line"`
	TaintChain  []TaintLink  `json:"taint_chain,omitempty"`
	Reachable   bool         `json:"reachable,omitempty"`
	// SourceTier records the analysis engine tier (Proven Path v1). Empty
	// for blackbox / pre-field findings. See SourceTier doc.
	SourceTier SourceTier `json:"source_tier,omitempty"`
	// Route binds the finding to its HTTP route (Proven Path v1). Empty
	// when unbound. A non-empty Route + a TaintChain is the v1 "proof":
	// route → handler → source→sink taint path.
	Route *Route `json:"route,omitempty"`
	// RouteConfirmed is set by the correlator when a blackbox endpoint was
	// matched to this finding's Route.Pattern (the highest-priority match
	// strategy). It means the live scan actually hit the route the taint
	// chain reaches — not merely a fuzzy URL overlap.
	RouteConfirmed bool `json:"route_confirmed,omitempty"`
	// ProvenPath is the Proven Path v1 signal: set ONLY when RouteConfirmed
	// AND Reachable are both true (and the source tier cleared the F1 gate).
	// It marks the "DAST hit + SAST taint path + the exact route that reaches
	// it" case and forces the finding to CRITICAL. Never set from
	// RouteConfirmed alone.
	ProvenPath bool `json:"proven_path,omitempty"`

	// --- v0.24 Decision Reports (additive, omitempty) -------------------
	// These surface the internal Decision + Confidence Engine in the public
	// report. Stamped once by the orchestrator from the finalized finding
	// set; absent (and byte-identical to pre-v0.24) when a reporter is
	// called without the orchestrator's decision pass.
	//
	// Status is the decision verdict: BLOCK / WARN / INFO.
	Status string `json:"status,omitempty"`
	// ConfidenceScore is the deterministic 0–100 confidence score (v0.23).
	ConfidenceScore int `json:"confidence_score,omitempty"`
	// ConfidenceBand is the score-derived HIGH/MEDIUM/LOW band. It is
	// intentionally distinct from the existing `confidence` enum (which
	// scanners/correlation set): `confidence` is unchanged for backward
	// compat; `confidence_band` is the v0.23 scorer's bucket and may equal it.
	ConfidenceBand string `json:"confidence_band,omitempty"`
	// ConfidenceReasons is the plain-text, per-rule breakdown of the score
	// (the "no black boxes" contract).
	ConfidenceReasons []string `json:"confidence_reasons,omitempty"`

	// ConfidenceBreakdown is ConfidenceReasons in machine-readable form,
	// index-for-index aligned with it: one entry per scoring rule that fired,
	// carrying a stable Code and the signed Delta it contributed.
	//
	// It exists so a consumer — the SARIF export above all — can key off a
	// rule identity instead of parsing a presentation string whose wording is
	// free to change. The deltas sum to ConfidenceScore, so the score is
	// reconstructable without a parser.
	ConfidenceBreakdown []ConfidenceReason `json:"confidence_breakdown,omitempty"`
	// DecisionReason is the plain-text justification for Status, verbatim from
	// decision.Decision.Reason.
	DecisionReason string `json:"decision_reason,omitempty"`
	// DecisionPolicy names which policy produced Status: "enforced" (the
	// shipped evidence-gated policy) or "relaxed" (the legacy severity-only
	// mapping restored by --enforce-confidence=false).
	DecisionPolicy string `json:"decision_policy,omitempty"`
	// PolicyOverride is true only when the relaxed policy produced a BLOCK the
	// shipped policy would NOT have produced — i.e. an unconfirmed finding
	// gated the build because the operator switched the evidence requirement
	// off.
	//
	// omitempty is deliberate: the marker's PRESENCE is the signal. Publishing
	// "policy_override": false on every normal result would be noise, and noise
	// is how a genuine override goes unnoticed.
	PolicyOverride bool `json:"policy_override,omitempty"`
	// IndependentSignals / SelfEvidentSignals are the two corroboration classes
	// behind Status (decision.corroborate). Only Independent may lift a band to
	// BLOCK; both are published so a reader can reconstruct the verdict without
	// re-running the engine.
	//
	// STAMPED, NOT PROJECTED — same reasoning as the corroboration pair below:
	// engine.stampDecisions writes them from the post-Restore evidence, so they
	// reflect the merged group rather than whichever duplicate won findingLess.
	IndependentSignals []string `json:"independent_signals,omitempty"`
	SelfEvidentSignals []string `json:"self_evident_signals,omitempty"`
	// AuthExpectation is what a source of truth declared about authentication
	// for this endpoint (unknown / public / required). Published because the
	// DECISION depends on it: a "contradicted authentication requirement" is an
	// independent corroborating signal, and an auditable decision cannot cite a
	// field the report withholds. Empty (unknown) is omitted, which is the
	// honest encoding — see the type doc.
	AuthExpectation AuthExpectation `json:"auth_expectation,omitempty"`
	// Applicability is the dependency-applicability verdict. Published for the
	// same reason as AuthExpectation: the decision policy reads it, and an
	// auditable verdict cannot cite a field the report withholds. Unknown is
	// omitted, which is the honest encoding of "not evaluated".
	Applicability Applicability `json:"applicability,omitempty"`

	// --- Cross-tool corroboration (SARIF import) ------------------------
	// CrossToolCorroborated / CorroboratingTools publish the verdict of
	// engine.CorrelateCrossTool: an INDEPENDENT tool reported the same
	// normalized weakness at the same normalized location. Both omitempty,
	// so a report with no corroboration is byte-identical to one produced
	// before these fields existed. Their additive introduction did not require
	// a schema-version bump.
	//
	// STAMPED, NOT PROJECTED. evidence.ToFinding deliberately does NOT carry
	// them; engine.stampDecisions writes them from the post-Restore evidence
	// so the published value is the PROOF-UNION over the dedup group rather
	// than whichever duplicate happened to win findingLess and become the
	// group primary. Projecting them through the render block would silently
	// reintroduce the erasure the proof-union fold exists to prevent — on a
	// public surface. TestPublicCorroborationSurvivesUncorroboratedDuplicate
	// locks this.
	CrossToolCorroborated bool     `json:"cross_tool_corroborated,omitempty"`
	CorroboratingTools    []string `json:"corroborating_tools,omitempty"`
}

// SeverityRank returns a numeric rank for severity comparison.
// Higher values indicate more severe findings.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
