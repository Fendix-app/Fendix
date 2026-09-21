package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// SARIF 2.1.0 structures — see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

const (
	// sarifLegacyFingerprintKey is the scheme a report that announces NO
	// algorithm was produced under. Every engine build before v3.0.0 omitted
	// `metadata.fingerprint_algorithm` and hashed sha1(Category|Endpoint|Title),
	// so absent means v1 — never "this build's algorithm".
	sarifLegacyFingerprintKey = "fendix/v1"

	// sarifAutomationID is the category a run with no declared mode is grouped
	// under, and the prefix every moded category is built from. Keep it
	// STABLE: changing it re-partitions every alert in every repo that has
	// already ingested a Fendix SARIF, which makes it an effectively one-way
	// door.
	sarifAutomationID = "fendix/scan"

	// sarifMaxLogicalLocations caps how many endpoints one result lists as
	// SARIF locations.
	//
	// A rate-limit sweep over a large API deduplicates into ONE finding whose
	// AffectedEndpoints holds every operation it covered — ~883 on a real
	// target — and each of those became a logicalLocation. That is expressive
	// and unusable: no consumer renders 883 locations legibly, and every
	// consumer pays to parse them.
	//
	// The cap governs the LOCATION LIST only, which exists for a human to
	// navigate. The full set moves to result.properties.affected_endpoints
	// with an explicit count and a truncation marker, so nothing is lost and a
	// truncated result can never be mistaken for a complete one (working rule
	// 3: de-escalate evidence, never delete it).
	sarifMaxLogicalLocations = 10
)

// SARIFLog is the top-level SARIF 2.1.0 object.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool SARIFTool `json:"tool"`
	// AutomationDetails identifies this analysis (SARIF §3.14.3 →
	// runAutomationDetails §3.17). It belongs on the RUN object — a sibling of
	// tool/results/invocations — not on tool, driver, result or invocation.
	// GitHub Code Scanning reads the id as the analysis "category": two tools
	// uploading SARIF for the same commit without distinct ids overwrite each
	// other's alerts, so a multi-tool repo silently loses whichever analysis
	// uploaded first.
	AutomationDetails *SARIFRunAutomationDetails `json:"automationDetails,omitempty"`
	Results           []SARIFResult              `json:"results"`
	Invocations       []SARIFInvocation          `json:"invocations,omitempty"`
	// Properties is the run-level property bag (SARIF §3.14.29). Carries the
	// coverage contract ("fendix/coverage") and, on hosted re-renders, the
	// backend's verdict ("fendix/release"). Additive; omitted when empty.
	Properties map[string]any `json:"properties,omitempty"`
}

// SARIFRunAutomationDetails identifies a run (SARIF §3.17). Only `id` is
// emitted: guid/correlationGuid would have to be stable across runs to be
// worth anything to a consumer, and the engine has no such identifier yet.
type SARIFRunAutomationDetails struct {
	ID string `json:"id"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool identity and rules.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule defines a rule (one per unique finding type).
type SARIFRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription SARIFMessage    `json:"shortDescription"`
	Help             SARIFMessage    `json:"help"`
	HelpURI          string          `json:"helpUri,omitempty"`
	DefaultConfig    SARIFRuleConfig `json:"defaultConfiguration"`
	Properties       SARIFProperties `json:"properties,omitempty"`
}

// SARIFRuleConfig sets the default severity level for a rule.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFMessage holds a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
	// CodeFlows renders a finding's taint chain as a step-through path
	// (Proven Path v1). GitHub Code Scanning renders these as an
	// expandable source→sink walk in the alert UI — the "screenshot that
	// sells" proof. Empty for findings without a proven chain.
	CodeFlows []SARIFCodeFlow `json:"codeFlows,omitempty"`
	// PartialFingerprints carries the run-stable identity of the finding
	// (SARIF §3.27.16). Consumers use it to recognise the SAME alert across
	// runs even when file/line drifts, so a re-ordered scan does not
	// close-and-reopen every GitHub alert. Key form is "name/version", per the
	// spec's own "stableResultHash/v1" example.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	// Rank is SARIF's own per-result priority (§3.27.16): 0.0 lowest, 100.0
	// highest. It carries EFFECTIVE RISK — intrinsic severity tempered by how
	// confident Fendix is in this particular instance — which is the one of
	// the four concepts that is genuinely per-result and has no home on the
	// rule. Using the standard field means nothing non-standard is invented
	// for consumers to special-case.
	Rank       *float64               `json:"rank,omitempty"`
	Properties *SARIFResultProperties `json:"properties,omitempty"`
}

// SARIFResultProperties carries fendix-specific provenance on a result so
// SARIF consumers (and our own re-ingestion) can see the detection tier and
// route binding that back the Proven Path claim.
type SARIFResultProperties struct {
	SourceTier   string `json:"source_tier,omitempty"`
	Reachable    bool   `json:"reachable,omitempty"`
	RouteMethod  string `json:"route_method,omitempty"`
	RoutePattern string `json:"route_pattern,omitempty"`
	RouteHandler string `json:"route_handler,omitempty"`
	// v0.24 decision-report fields.
	Status          string `json:"status,omitempty"`
	ConfidenceScore int    `json:"confidence_score,omitempty"`
	ConfidenceBand  string `json:"confidence_band,omitempty"`
	// ConfidenceReasons / ConfidenceBreakdown are the score's justification,
	// in the two forms the native JSON report publishes. Both travel, because
	// parity means a SARIF reader sees what a native-JSON reader sees.
	//
	// ConfidenceBreakdown is the one a CONSUMER should key off: stable Code,
	// signed Delta, and the deltas reconstruct ConfidenceScore with no parser.
	// ConfidenceReasons is the human wording, carried for readers, and no
	// automated decision should depend on parsing it.
	//
	// Both omitempty: a finding from a report produced before the decision
	// pass has neither, and must re-render byte-identically to how it always
	// has.
	ConfidenceReasons   []string                  `json:"confidence_reasons,omitempty"`
	ConfidenceBreakdown []models.ConfidenceReason `json:"confidence_breakdown,omitempty"`
	// IntrinsicSeverity / EffectiveRisk publish the two severity concepts that
	// used to be indistinguishable in the report. IntrinsicSeverity is the
	// finding's own severity — how bad this kind of issue is when real, the
	// same axis the rule's security-severity scores. EffectiveRisk is that
	// severity after Fendix's confidence in THIS instance is applied, and is
	// the band form of SARIFResult.Rank.
	//
	// Published side by side on purpose: the gap between them is the whole
	// point. A HIGH rule firing on a LOW-confidence placeholder reads
	// intrinsic_severity=HIGH, effective_risk=LOW, and a consumer can act on
	// the difference instead of inferring it.
	IntrinsicSeverity string `json:"intrinsic_severity,omitempty"`
	EffectiveRisk     string `json:"effective_risk,omitempty"`
	// AffectedEndpointCount / AffectedEndpoints / LocationsTruncated carry the
	// FULL accounting when the location list was capped at
	// sarifMaxLogicalLocations. The locations a reader navigates are a sample;
	// these are the record. All three are omitempty, so a result inside the
	// cap is byte-identical to one produced before the cap existed.
	AffectedEndpointCount int      `json:"affected_endpoint_count,omitempty"`
	AffectedEndpoints     []string `json:"affected_endpoints,omitempty"`
	LocationsTruncated    bool     `json:"locations_truncated,omitempty"`
	// Evidence is the raw finding evidence, moved here when result.message.text
	// became a human description (FIX-13.4). Kept verbatim — working rule 3:
	// evidence is DE-ESCALATED, never deleted. For a finding with a real
	// file:line it is ALSO mirrored into region.snippet.text; the duplication
	// is intentional so a consumer reading either place sees the same string.
	Evidence string `json:"evidence,omitempty"`
	// CorroboratingTools names the INDEPENDENT tools that reported the same
	// normalized weakness at the same location. Emitted so corroboration
	// provenance survives re-export into GitHub code scanning rather than
	// being lost at the boundary — a consumer can see that two engines
	// agreed, not merely that fendix scored the finding highly.
	CorroboratingTools []string `json:"corroborating_tools,omitempty"`
	// Decision is the machine-readable justification for Status. Pointer +
	// omitempty so a report produced without the decision pass stays
	// byte-identical to one produced before this field existed.
	Decision *SARIFDecision `json:"decision,omitempty"`
}

// SARIFDecision is the auditable justification for one finding's verdict: what
// the decision was, why, which signals supported it and in which class, and the
// evidence flags behind them.
//
// It exists so a consumer can answer "why exactly did this BLOCK my build?"
// from the exported result alone. Before it, a reader could see status,
// confidence_score, confidence_band and source_tier and still not reconstruct
// the verdict.
type SARIFDecision struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Policy is "enforced" or "relaxed"; PolicyOverride marks a BLOCK that
	// exists ONLY because --enforce-confidence=false switched the evidence
	// requirement off. Together they are what stop an operator-relaxed gate
	// from being indistinguishable from an evidence-backed one.
	Policy             string   `json:"policy,omitempty"`
	PolicyOverride     bool     `json:"policy_override,omitempty"`
	IndependentSignals []string `json:"independent_signals,omitempty"`
	SelfEvidentSignals []string `json:"self_evident_signals,omitempty"`
	// Evidence is a MAP, not a struct, and that is load-bearing — see
	// decisionProperties.
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

// decisionStatusBlock is decision.StatusBlock's value, restated here rather
// than imported: reporters must not depend on the decision package (it would
// invite exactly the logic duplication the decision block exists to avoid).
// The two are locked together by TestSARIFBlockLiteralMatchesDecisionPackage.
const decisionStatusBlock = "BLOCK"

// decisionProperties renders the machine-readable justification for a finding's
// verdict, or nil when no decision pass ran.
//
// THE EVIDENCE SUB-OBJECT IS A MAP ON PURPOSE. A struct field is either true or
// false, and this contract requires a third state: a key that is ABSENT means
// "not evaluated", never "evaluated and found false". Rendering unknown as
// false is the single most misleading thing this exporter could do, because a
// consumer cannot then distinguish a check that cleared from a check that never
// ran — and "unknown treated as false" is the defect class this whole change
// exists to remove. `omitempty` on a bool would collapse false into absent,
// which is the same error wearing a different hat: it would make a genuinely
// evaluated `false` unrepresentable.
//
// Only facts Fendix actually established are emitted.
func decisionProperties(f models.Finding) *SARIFDecision {
	if f.Status == "" {
		return nil // no decision pass ran; emit nothing rather than a hollow block
	}

	evi := map[string]interface{}{}
	if f.Reachable {
		evi["reachable"] = true
		// Only meaningful once reachability was evaluated: a chain either was
		// or was not established. With no reachability analysis at all, both
		// keys stay absent.
		evi["flow_established"] = len(f.TaintChain) > 0
	}
	if len(f.TaintChain) > 0 {
		evi["source_controlled"] = true
		evi["sink_detected"] = true
	}
	if f.RouteConfirmed {
		evi["route_confirmed"] = true
	}
	if f.AuthExpectation != models.AuthExpectationUnknown {
		evi["auth_expectation"] = string(f.AuthExpectation)
	}
	if f.Applicability != models.ApplicabilityUnknown {
		evi["applicability"] = string(f.Applicability)
	}
	if f.CrossToolCorroborated {
		evi["cross_tool_corroborated"] = true
	}

	out := &SARIFDecision{
		Status: f.Status,
		Reason: NeutralizeText(f.DecisionReason),
		Policy: NeutralizeText(f.DecisionPolicy),
		// STRUCTURAL INVARIANT, not a second decision.
		//
		// policy_override means "this BLOCK exists only because the evidence
		// requirement was switched off". On a non-BLOCK there is no such
		// BLOCK, so the claim is unpublishable regardless of how the field got
		// set. This never asks whether the finding SHOULD be an override —
		// that is decision.decide's call and stays there — it only refuses to
		// emit a self-contradictory pair.
		//
		// decision.settleOverride stops the pair being produced in the first
		// place. This guard covers the input that layer cannot reach: an
		// ARCHIVED report written before that fix, re-rendered later. Those
		// documents exist, so the reporter has to be safe against them.
		//
		// The `policy` label is deliberately NOT cleared: "this came from a
		// relaxed run" stays true of a demoted finding.
		PolicyOverride:     f.PolicyOverride && f.Status == string(decisionStatusBlock),
		IndependentSignals: neutralizeTags(f.IndependentSignals),
		SelfEvidentSignals: neutralizeTags(f.SelfEvidentSignals),
	}
	if len(evi) > 0 {
		out.Evidence = evi
	}
	return out
}

// SARIFCodeFlow groups one or more threadFlows (SARIF §3.36). A taint chain
// is a single thread of execution, so we emit exactly one threadFlow per
// code flow.
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

// SARIFThreadFlow is an ordered sequence of locations along one execution
// thread (SARIF §3.37) — here, source → intermediate hops → sink.
type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

// SARIFThreadFlowLocation wraps one location in a threadFlow (SARIF §3.38).
type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
}

// SARIFLocation describes where a finding was detected.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
	// Message labels a location within a threadFlow step (the taint
	// expression at that hop). Omitted for ordinary result locations.
	Message *SARIFMessage `json:"message,omitempty"`
}

// SARIFPhysicalLocation points to a file and line.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file by URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion describes a line range in a file.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
	// Snippet is the source text at StartLine (SARIF §3.30.13). This is where
	// a SAST finding's code line belongs — result.message.text is for the
	// human description, not for raw source.
	//
	// StartLine deliberately has no omitempty and the `lineNum > 0` gate that
	// builds a region is deliberately not relaxed: SARIF requires
	// region.startLine >= 1, so a region must never exist without a real line
	// number, and `{"startLine": 0, "snippet": …}` must stay unreachable.
	Snippet *SARIFArtifactContent `json:"snippet,omitempty"`
}

// SARIFArtifactContent carries literal artifact text (SARIF §3.3).
type SARIFArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// SARIFLogicalLocation describes a logical location (endpoint, function).
type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFInvocation captures metadata about the scan run.
//
// executionSuccessful is false (F-L13) when any required scanner errored,
// derived from ScanMetadata.ScannerStatus. A false value tells SARIF
// consumers (GitHub Code Scanning, sarif-multitool) that the analysis was
// degraded — results may be incomplete — rather than presenting a partial
// scan as a clean pass. Per-scanner failures are itemised in
// toolExecutionNotifications.
type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	CommandLine                string              `json:"commandLine,omitempty"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification is a tool-execution notification (SARIF §3.58). Used
// to itemise scanner failures behind a false executionSuccessful.
type SARIFNotification struct {
	Level   string       `json:"level,omitempty"`
	Message SARIFMessage `json:"message"`
}

// SARIFProperties holds custom key-value pairs.
type SARIFProperties struct {
	Category   string   `json:"category,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	// SecuritySeverity is the GitHub Code Scanning ranking score, derived ONLY
	// from the rule's severity (see sarifSecuritySeverity). The hyphenated
	// JSON name is GitHub's, not ours — do not rename it. Appended at the end
	// of the struct on purpose: encoding/json emits fields in declaration
	// order, so appending leaves every pre-existing key where it was.
	SecuritySeverity string `json:"security-severity,omitempty"`
	// SeverityModel names WHICH of the four severity concepts SecuritySeverity
	// expresses, so a consumer never has to guess. Always "intrinsic": the
	// score describes how bad this KIND of issue is when it is real.
	//
	// It cannot express effective risk, because security-severity is a
	// RULE-level property shared by every result under the rule, and the
	// results under one rule legitimately differ in confidence. Ranking the
	// rule down to match its weakest instance would hide the next instance
	// that IS real. Effective risk is per-result and lives on the result — see
	// SARIFResult.Rank.
	SeverityModel string `json:"severity_model,omitempty"`
}

// taintChainToCodeFlow converts a finding's taint chain into a SARIF
// codeFlow with one threadFlow whose locations are the source→sink steps,
// each carrying the expression as its location message. Returns nil for an
// empty chain so the codeFlows field is omitted (omitempty) on findings
// without a proven path.
func taintChainToCodeFlow(chain []models.TaintLink) *SARIFCodeFlow {
	if len(chain) == 0 {
		return nil
	}
	locs := make([]SARIFThreadFlowLocation, 0, len(chain))
	for _, link := range chain {
		loc := SARIFLocation{
			PhysicalLocation: &SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: normalizeArtifactURI(link.File)},
			},
		}
		if link.Line > 0 {
			loc.PhysicalLocation.Region = &SARIFRegion{StartLine: link.Line}
		}
		// The expression text is untrusted source; neutralize control/bidi
		// chars before embedding it as the step message.
		tfl := SARIFThreadFlowLocation{Location: loc}
		tfl.Location.Message = &SARIFMessage{Text: NeutralizeText(link.Expr)}
		locs = append(locs, tfl)
	}
	return &SARIFCodeFlow{ThreadFlows: []SARIFThreadFlow{{Locations: locs}}}
}

// sarifResultProperties stamps fendix provenance (detection tier, reachable
// flag, route binding) into a result's properties. Returns nil when there's
// nothing to record so the field stays omitted.
func sarifResultProperties(f models.Finding) *SARIFResultProperties {
	// Evidence counts toward "there is something to record". Dropping it from
	// this guard would silently delete the evidence of every plain blackbox
	// finding — no tier, no route, no decision stamp — which is precisely the
	// working-rule-3 violation FIX-13.4 exists to avoid.
	evidence := NeutralizeText(f.Evidence)
	if f.SourceTier == "" && !f.Reachable && f.Route == nil && f.Status == "" && f.ConfidenceScore == 0 &&
		evidence == "" && len(f.CorroboratingTools) == 0 {
		return nil
	}
	p := &SARIFResultProperties{
		SourceTier:          string(f.SourceTier),
		Reachable:           f.Reachable,
		Status:              f.Status,
		ConfidenceScore:     f.ConfidenceScore,
		ConfidenceBand:      f.ConfidenceBand,
		ConfidenceReasons:   neutralizeAll(f.ConfidenceReasons),
		ConfidenceBreakdown: neutralizeBreakdown(f.ConfidenceBreakdown),
		IntrinsicSeverity:   string(f.Severity),
		EffectiveRisk:       effectiveRiskBand(f),
		Evidence:            evidence,
		CorroboratingTools:  f.CorroboratingTools,
	}
	if f.Route != nil {
		p.RouteMethod = f.Route.Method
		p.RoutePattern = f.Route.Pattern
		p.RouteHandler = f.Route.Handler
	}
	// The guard above already returns early on f.Status == "", so any finding
	// reaching here with a decision gets its justification; one without a
	// decision pass gets nil and the key is omitted entirely.
	p.Decision = decisionProperties(f)
	return p
}

// ruleKeyFor returns a stable, human-readable rule ID for a finding's
// check type. Two findings with the same (category, title) share a rule ID;
// the per-finding identifier (Finding.ID, e.g. "SEC-042") stays in the
// SARIF result, not on the rule.
//
// Format: "fendix.<category>.<title-slug>" — opaque to consumers but stable
// across runs so that suppression baselines and PR-grouping tools (GitHub
// Code Scanning, sarif-multitool) treat repeat findings as one rule.
func ruleKeyFor(f models.Finding) string {
	// Neutralize first: the category is embedded verbatim in the rule ID
	// (consumers group/suppress by it), so a zero-width or control char
	// must not leak through even though slug() sanitizes the other half.
	cat := strings.ToLower(strings.TrimSpace(NeutralizeText(f.Category)))
	if cat == "" {
		cat = "uncategorized"
	}
	// RuleID names the check itself. Prefer it over the title for the same
	// reason the v2 fingerprint does: a title is presentation, and titles now
	// follow the evidence a finding holds. Keying rules on the title meant one
	// check's results scattered across two rules the moment a taint chain was
	// proven and "Potential SSRF" became "SSRF" — a rule split caused purely
	// by wording, on the surface GitHub groups and suppresses by.
	if ruleSlug := slug(NeutralizeText(f.RuleID)); ruleSlug != "" {
		return "fendix." + cat + "." + ruleSlug
	}
	// Findings from before RuleID was projected, and emitters that never set
	// one, keep the original category+title key so their existing GitHub
	// alerts and suppressions are undisturbed.
	titleSlug := slug(f.Title)
	if titleSlug == "" {
		titleSlug = "unnamed"
	}
	return "fendix." + cat + "." + titleSlug
}

// slug lowercases a string and collapses any run of non-[a-z0-9] characters
// to a single '-'. Used for rule IDs derived from finding titles.
func slug(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := true // suppress leading dash
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := b.String()
	return strings.TrimRight(out, "-")
}

// sarifLevel maps Fendix severity to SARIF level.
func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// sarifSecuritySeverity maps a Fendix severity to the GitHub Code Scanning
// `security-severity` rule property — a CVSS-style 0.0–10.0 score emitted as a
// STRING (CodeQL's convention, and what GitHub's own documented examples use).
// Without it GitHub buckets every Fendix alert as "medium" regardless of its
// level. GitHub's thresholds are >=9.0 critical, >=7.0 high, >=4.0 medium,
// >0.0 low; the constants below land exactly one per bucket.
//
// Working rule 8: this is a pure function of SEVERITY. It must never read
// f.Confidence, f.ConfidenceScore or f.ConfidenceBand. Confidence is an
// independently scored axis, and the rule this property hangs off is SHARED by
// findings whose confidence differs (SARIFProperties.Confidence is already
// first-wins across them), so a confidence-derived score would be neither
// meaningful nor order-independent. Taking models.Severity and nothing else
// makes that violation impossible to write by accident.
func sarifSecuritySeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "9.5"
	case models.SeverityHigh:
		return "8.0"
	case models.SeverityMedium:
		return "5.5"
	case models.SeverityLow:
		return "3.0"
	default: // INFO, and any unrecognised/empty value — mirrors sarifLevel
		return "1.0"
	}
}

// --- the four severity concepts -----------------------------------------
//
// A Fendix finding carries four things a reader routinely conflates:
//
//	intrinsic severity  how bad this KIND of issue is when it is real
//	confidence          how sure Fendix is that THIS instance is real
//	effective risk      the two combined — how much this alert deserves now
//	decision            what Fendix DID (BLOCK / WARN / INFO)
//
// SARIF has a natural home for three of them: security-severity on the rule
// (intrinsic), rank on the result (effective risk), level on the result
// (decision). Confidence has none, so it is published as an explicit result
// property alongside the other three rather than being folded into one of
// them. RC-7 was the consequence of folding: a synthetic FAKE_API_KEY scored
// 25 in the LOW band and held at WARN was published under a rule ranked High,
// with nothing in the result to say Fendix disagreed.

// effectiveRisk is intrinsic severity tempered by confidence, on SARIF's
// 0.0–100.0 rank scale (§3.27.16, 0.0 lowest priority).
//
// An UNSTAMPED finding — no decision pass, no confidence score — is NOT
// tempered. Absent confidence is "never assessed", not "assessed as low", and
// quietly down-ranking every finding from a producer that does not score would
// bury real issues behind a missing field.
func effectiveRisk(f models.Finding) float64 {
	base := map[models.Severity]float64{
		models.SeverityCritical: 100,
		models.SeverityHigh:     80,
		models.SeverityMedium:   55,
		models.SeverityLow:      30,
	}[f.Severity]
	if base == 0 {
		base = 10 // INFO, and any unrecognised or empty severity
	}
	switch f.ConfidenceBand {
	case "HIGH":
		return base
	case "MEDIUM":
		return base * 0.7
	case "LOW":
		return base * 0.35
	default:
		return base
	}
}

// effectiveRiskBand is the human-readable form of effectiveRisk, bucketed on
// the same boundaries GitHub uses for security-severity so the two numbers are
// read on one scale.
func effectiveRiskBand(f models.Finding) string {
	if f.ConfidenceBand == "" && f.Status == "" {
		return "" // never assessed — say nothing rather than guess
	}
	switch r := effectiveRisk(f); {
	case r >= 90:
		return "CRITICAL"
	case r >= 70:
		return "HIGH"
	case r >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// assessmentIsDowngraded reports whether Fendix ranks this instance materially
// below the rule it fired under.
//
// It exists because GitHub renders security-severity, not rank, and
// security-severity is necessarily the rule's intrinsic score. The gap has to
// reach the one field a human actually reads, which is the message.
func assessmentIsDowngraded(f models.Finding) bool {
	band := effectiveRiskBand(f)
	if band == "" {
		return false
	}
	rank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	return rank[band] < rank[string(f.Severity)]
}

// sarifLevelForStatus drives the SARIF level (and thus the GitHub annotation
// color) from the v0.24 decision verdict: BLOCK→error, WARN→warning,
// INFO→note. When no decision is stamped (status==""), it falls back to the
// severity-based level so output is byte-identical to pre-v0.24. This is the
// intended v0.24 behavioral change: a HIGH finding BELOW the --fail-on
// threshold is WARN→warning (not error), so annotations reflect "what blocks".
func sarifLevelForStatus(status string, sev models.Severity) string {
	switch status {
	case "BLOCK":
		return "error"
	case "WARN":
		return "warning"
	case "INFO":
		return "note"
	default:
		return sarifLevel(sev)
	}
}

// fingerprintKeyFor names the algorithm that PRODUCED the fingerprints in a
// report — read from the report, never from this build's constant.
//
// `fendix report --input` re-renders an ARCHIVED report: the findings and their
// fingerprints come out of the file, and this build's algorithm says nothing
// about how they were computed. Keying them off the constant published a v1
// value under `fendix/v2`, so a v2 consumer would match it against real v2
// identities — the wrong namespace, silently. That is the "one key, two
// meanings" hazard the key was versioned to prevent, arriving from the other
// direction.
//
// An absent announcement means v1, which is load-bearing: every engine build
// before v3.0.0 omitted the field, so every archived report is a v1 report.
func fingerprintKeyFor(meta ScanMetadata) string {
	if meta.FingerprintAlgorithm != "" {
		return meta.FingerprintAlgorithm
	}
	return sarifLegacyFingerprintKey
}

// automationIDFor is the analysis category GitHub Code Scanning partitions
// alerts by (SARIF §3.17.3 runAutomationDetails; GitHub reads it as the
// "category" of an upload).
//
// It must separate analyses that cover DIFFERENT ground, because an upload
// carrying no findings for a category means "everything in this category is
// fixed". A single constant put a code-only scan and a live DAST scan of the
// same repository in one bucket, so whichever ran last cleared the other's
// alerts — a scheduled whitebox job silently closing every finding a nightly
// blackbox scan had opened, and the reverse.
//
// It must equally NOT separate two runs of the same analysis, or GitHub can
// never match this run's alerts to the last one's and nothing is ever marked
// fixed. So it is derived from the scan MODE and from nothing else: not the
// engine version (an upgrade must not re-partition), not the duration or
// endpoint count (those vary run to run by design), and never a timestamp or
// UUID — an id made unique per run is the same defect wearing the opposite
// mask.
//
// An empty mode keeps the original constant, so reports that predate the mode
// field — and `fendix report --input` replays of them — stay in the bucket
// their alerts already live in.
func automationIDFor(mode string) string {
	switch mode {
	case "whitebox", "blackbox", "hybrid", "import":
		return sarifAutomationID + "/" + mode
	default:
		return sarifAutomationID
	}
}

// sarifHelpURI extracts the first useful reference URL for a rule.
// CWE IDs are mapped to their MITRE page.
func sarifHelpURI(refs []string) string {
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
			return ref
		}
		if strings.HasPrefix(ref, "CWE-") {
			return "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(ref, "CWE-") + ".html"
		}
	}
	return ""
}

// uriSchemeRE matches a leading URI scheme ("javascript:", "http://",
// "file:", "data:", …). Per RFC 3986 a scheme is an ASCII letter
// followed by letters/digits/'+'/'-'/'.' and a ':'. We strip it so an
// artifactLocation.uri can never carry an executable or absolute-URL
// scheme into a SARIF viewer.
var uriSchemeRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)

// normalizeArtifactURI sanitizes a file path destined for a SARIF
// artifactLocation.uri. SARIF consumers (GitHub Code Scanning, IDEs)
// resolve these against the project root, so a value carrying a scheme
// ("javascript:alert(1)"), an absolute path, or ".." traversal can be
// abused. We coerce the value into a safe relative path:
//
//   - control/bidi characters are stripped (NeutralizeText);
//   - any leading URI scheme is removed;
//   - the path is split on '/', and "", ".", and ".." segments are
//     dropped (so "../../etc/passwd" → "etc/passwd" and "/abs" → "abs");
//   - backslashes are treated as separators too (Windows-style paths).
//
// The result is always a relative path with no scheme and no traversal.
func normalizeArtifactURI(uri string) string {
	uri = NeutralizeText(uri)
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	// Drop a leading scheme ("javascript:", "http://", "file:", …).
	uri = uriSchemeRE.ReplaceAllString(uri, "")
	// Normalise Windows separators so traversal segments can't slip
	// through as "..\..".
	uri = strings.ReplaceAll(uri, "\\", "/")

	segs := strings.Split(uri, "/")
	clean := make([]string, 0, len(segs))
	for _, seg := range segs {
		switch seg {
		case "", ".", "..":
			// Drop empty (collapses "//" and leading "/"), current-dir,
			// and parent-dir traversal segments.
			continue
		default:
			clean = append(clean, seg)
		}
	}
	return strings.Join(clean, "/")
}

// bareURISchemes are the scheme tokens a URL collapses to once a trailing
// line suffix is stripped off it. `line: "https:8080"` parses as path
// "https" + line 8080 under parseLine's rule (a legal all-digit suffix), and
// reports rendered before FIX-02 may already carry a bare "https" in the
// field. Neither is a file.
var bareURISchemes = map[string]bool{
	"http": true, "https": true, "ftp": true, "ftps": true,
	"file": true, "data": true, "ws": true, "wss": true, "javascript": true,
}

// looksLikeURLPath reports whether a path parsed out of Finding.Line is
// really a URL — or the bare scheme fragment left over from one — in which
// case it must NOT become an artifactLocation.uri.
//
// The predicate is deliberately NARROW, and deliberately not uriSchemeRE
// (which matches any RFC 3986 scheme prefix): uriSchemeRE also matches the
// "C:" of `C:\src\app.go`, so reusing it here would route every Windows
// whitebox finding into the endpoint branch. Only a literal "://" or an
// exact bare-scheme token counts.
func looksLikeURLPath(p string) bool {
	if strings.Contains(p, "://") {
		return true
	}
	return bareURISchemes[strings.ToLower(strings.TrimSpace(p))]
}

// neutralizeTags strips control/bidi characters from each reference tag.
// References feed both helpUri (already scheme-filtered) and the SARIF
// rule's properties.tags array; the tags are free text and must not
// carry invisible or reordering characters into a SARIF viewer. Returns
// nil for an empty/nil input so the omitempty JSON tag still drops the
// field.
func neutralizeTags(refs []string) []string {
	if len(refs) == 0 {
		return refs
	}
	out := make([]string, len(refs))
	for i, ref := range refs {
		out[i] = NeutralizeText(ref)
	}
	return out
}

// parseLine splits a Finding.Line value into a file path and a line number.
//
// Only a TRAILING ":<digits>" run is a line suffix. Everything else — no
// colon at all, a colon followed by anything non-numeric, a colon at the very
// end — returns the string WHOLE with line 0. That narrow rule is the entire
// fix (FIX-02): the previous implementation split on EVERY ":" and read the
// last segment as the line number, which mangled the URLs that legitimately
// arrive in this field.
//
// They arrive from python/analyzers/spec_parser.py, which stamps
// `"line": self.spec_path` at eight sites (126/194/217/240/274/298/340/380),
// and spec_path may itself be an https:// URL — spec_parser.py:404 fetches a
// spec over https on purpose. Pre-fix:
//
//	"https://api.example.com/openapi.json"
//	  → Split → ["https", "//api.example.com/openapi.json"]
//	  → Sscanf fails → filePath "https", line 0
//
//	"https://host:8080/api/x"
//	  → Split → ["https", "//host", "8080/api/x"]
//	  → Sscanf reads 8080 → filePath "https://host", line 8080
//
// The second is the worse of the two: normalizeArtifactURI then strips the
// scheme, so the emitter published artifactLocation.uri "host" carrying a
// FABRICATED startLine 8080 — a plausible-looking line in a file that does
// not exist. Both now come back whole with line 0, and RenderSARIF routes
// them to a logical location instead (see looksLikeURLPath).
//
// Parity anchor: this is precisely what the Python side already asserts about
// the same field. python/tests/test_ast_analyzer.py::TestFindingStructure::
// test_line_field_format does `f["line"].rsplit(":", 1)` and requires
// `parts[1].isdigit()`. Do not diverge from it.
//
// NOT fixed here, deliberately: "file:line:col" ("src/app.py:42:10") still
// yields path "src/app.py:42" + line 10, exactly as the old splitter did. No
// producer in the tree emits that shape, so reproducing the behaviour is
// cheaper than guessing at a new one.
func parseLine(line *string) (string, int) {
	if line == nil || *line == "" {
		return "", 0
	}
	s := *line
	i := strings.LastIndexByte(s, ':')
	if i < 0 || i == len(s)-1 {
		// No colon, or a trailing colon with nothing behind it. An empty
		// suffix is not a digit run — `"".isdigit()` is False on the Python
		// side too, so the colon stays part of the path.
		return s, 0
	}
	suffix := s[i+1:]
	for _, r := range suffix {
		if r < '0' || r > '9' {
			return s, 0
		}
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		// All digits, but too many of them to fit an int. A whole path is a
		// better answer than a silently truncated line number.
		return s, 0
	}
	return s[:i], n
}

// buildResultMessage composes result.message.text: the rule name (the finding
// title) plus the location it fired at.
//
// Pre-fix this field carried raw f.Evidence. For a SAST finding that is a line
// of SOURCE CODE — "with open(path, 'w', ...) as f:" — which reads as
// gibberish as a GitHub PR annotation and duplicates the snippet sitting right
// beside it. The evidence is not dropped (working rule 3): it moves to
// region.snippet.text when there is a real file:line, and is kept verbatim in
// result.properties.evidence in every case.
//
// locCtx is produced by the same branch that produced result.locations, so the
// message and the locations can never disagree about where the finding is. Its
// components are already neutralized where they are built, so this does not
// re-neutralize it.
func buildResultMessage(f models.Finding, locCtx string) string {
	title := strings.TrimSpace(NeutralizeText(f.Title))
	if title == "" {
		// ruleKeyFor never returns "" — it falls back to
		// "fendix.uncategorized.unnamed". That guarantees a non-empty message,
		// which the pre-fix emitter did not: an evidence-less finding produced
		// message.text "", and GitHub rejects that.
		title = ruleKeyFor(f)
	}
	if locCtx != "" {
		title = title + " at " + locCtx
	}
	// State the scale explicitly for a sweep-style finding. "(+882 more)"
	// inside locCtx names a remainder; a reader triaging wants the total.
	if n := len(f.AffectedEndpoints); n > sarifMaxLogicalLocations {
		title = fmt.Sprintf("%s — %d operations affected", title, n)
	}
	// GitHub ranks alerts by the RULE's security-severity, which is
	// necessarily the intrinsic score — so when Fendix's own assessment of
	// this instance is lower, the message is the only field a human reads that
	// can say so. Without it the FAKE_API_KEY case reads as a High alert with
	// no hint that Fendix scored it 25.
	//
	// Only emitted when the two genuinely disagree. A caveat on every alert is
	// a caveat on none.
	if assessmentIsDowngraded(f) {
		title = fmt.Sprintf("%s — %s confidence (%d/100): effective risk %s, below this rule's %s severity",
			title, f.ConfidenceBand, f.ConfidenceScore, effectiveRiskBand(f), f.Severity)
	}
	return title
}

// RenderSARIF writes a SARIF 2.1.0 report to the writer.
//
// Rules are deduplicated by check identity (category + title) rather than per
// finding (TASK-083). Pre-fix, 160 findings produced 160 unique rule IDs like
// SEC-001..SEC-160; tools that group results by ruleId (GitHub Code Scanning,
// `sarif-multitool merge`) scattered identical issues across many "rules".
// After the fix, "Missing CSP header" reported on 21 endpoints is one rule
// referenced 21 times — which is what SARIF semantics expect.
func RenderSARIF(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	// Strip bidi/zero-width/control characters from the coverage/verdict
	// metadata before anything below reads it. Under `fendix report
	// --input`, ScannerStatus and Coverage arrive verbatim from an
	// arbitrary parsed JSON report — exactly as untrusted as the finding
	// fields neutralized below, and exactly what html.go and pdf.go
	// already do before rendering their own coverage table / appendix.
	meta = NeutralizeCoverageMetadata(meta)

	// A rule is shared by every finding of the same check (category+title), and
	// those findings may legitimately carry DIFFERENT severities: the engine's
	// dedupKey (internal/engine/dedup.go) is severity|category|title, so
	// Deduplicate deliberately KEEPS a same-check pair at two severities as two
	// findings, and orchestrator step 5.6 enforceConsistency (LOW confidence
	// caps severity at MEDIUM, MEDIUM at HIGH) plus escalateNonCorrelatedReachable
	// actively create that split. So take the MAX, and take it in a pre-pass:
	//
	//   - first-wins was not deterministic in any useful sense. The orchestrator
	//     sorts by Endpoint → Category → Title and never by severity, so the
	//     surviving rule severity was whichever finding had the lexicographically
	//     smallest endpoint — and `fendix report --input` accepts an arbitrarily
	//     ordered findings array, so it varied by producer too.
	//   - max is the fail-loud choice. security-severity has no per-result
	//     equivalent in SARIF; one value serves every alert under the rule, and
	//     under-ranking a CRITICAL is strictly worse than over-ranking a LOW.
	//
	// Ties: models.SeverityRank returns 0 for both INFO and any unrecognised or
	// empty severity, so a rank-0 tie keeps the first-seen value — but sarifLevel
	// and sarifSecuritySeverity map INFO and "" to the same outputs ("note" /
	// "1.0"), so the emitted JSON is order-independent regardless.
	// Resolved once per report: the algorithm is a property of the run that
	// produced these fingerprints, not of any one finding.
	fingerprintKey := fingerprintKeyFor(meta)

	ruleSeverity := make(map[string]models.Severity, len(findings))
	for _, f := range findings {
		key := ruleKeyFor(f)
		if cur, ok := ruleSeverity[key]; !ok || models.SeverityRank(f.Severity) > models.SeverityRank(cur) {
			ruleSeverity[key] = f.Severity
		}
	}

	// Build deduplicated rules list keyed by stable check identity.
	ruleMap := make(map[string]int) // stable ruleKey -> index in rules
	var rules []SARIFRule

	for _, f := range findings {
		key := ruleKeyFor(f)
		if _, exists := ruleMap[key]; exists {
			continue
		}
		idx := len(rules)
		ruleMap[key] = idx

		// Strip control/bidi from human-facing rule fields. helpUri is
		// left to sarifHelpURI, which already restricts it to http/https.
		ruleName := NeutralizeText(f.Title)
		rule := SARIFRule{
			ID:               key,
			Name:             ruleName,
			ShortDescription: SARIFMessage{Text: ruleName},
			Help:             SARIFMessage{Text: NeutralizeText(f.Fix)},
			HelpURI:          sarifHelpURI(f.References),
			DefaultConfig:    SARIFRuleConfig{Level: sarifLevel(ruleSeverity[key])},
			Properties: SARIFProperties{
				Category:         NeutralizeText(f.Category),
				Tags:             neutralizeTags(f.References),
				Confidence:       string(f.Confidence),
				SecuritySeverity: sarifSecuritySeverity(ruleSeverity[key]),
				SeverityModel:    "intrinsic",
			},
		}
		rules = append(rules, rule)
	}

	// Build results — each finding references its check's shared rule, not a per-instance one.
	results := make([]SARIFResult, 0, len(findings))
	for _, f := range findings {
		key := ruleKeyFor(f)
		result := SARIFResult{
			RuleID:    key,
			RuleIndex: ruleMap[key],
			// v0.24: per-result level follows the decision verdict (BLOCK→error,
			// WARN→warning, INFO→note); falls back to severity when unstamped.
			Level: sarifLevelForStatus(f.Status, f.Severity),
			// Message is assigned after the location block: it names the
			// location the finding fired at, so it cannot be composed until
			// that branch has run.
		}

		// Build locations from either line (whitebox) or endpoint(s) (blackbox).
		// Per SARIF spec, multiple locations on a single result mean "this
		// finding applies to all of these places" — exactly the semantics we
		// want for deduplicated findings (TASK-088).
		//
		// FIX-02: the branch is chosen on the PARSED path, not merely on
		// `f.Line` being non-empty. A `line` that is really a URL names no
		// artifact, so it belongs with the endpoints — and the logicalLocation
		// branch below already renders that correctly, which is why the fix is
		// to stop feeding it a bogus physicalLocation rather than to rewrite
		// it. The URL test has to run BEFORE normalizeArtifactURI, because
		// normalizeArtifactURI is what deletes the scheme and hides the
		// URL-ness.
		var locCtx string
		// truncatedEndpoints is non-nil only when the location list was
		// capped; it carries the FULL set so the property block below can
		// record what the locations no longer show.
		var truncatedEndpoints []string
		filePath, lineNum := parseLine(f.Line) // handles nil / "" itself
		artifactURI := ""
		if filePath != "" && !looksLikeURLPath(filePath) {
			// Coerce the artifact URI into a safe relative path: no
			// scheme (javascript:/http://), no leading slash, no "..".
			artifactURI = normalizeArtifactURI(filePath)
		}
		if artifactURI != "" {
			loc := SARIFLocation{
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: artifactURI},
				},
			}
			locCtx = artifactURI
			if lineNum > 0 {
				reg := &SARIFRegion{StartLine: lineNum}
				// FIX-13.4: the code line belongs here, not in the message.
				// Reuse f.Evidence rather than re-reading the source file —
				// Evidence is already the sanitized string (SanitizeFindings
				// redacts auth values; the secrets scanner truncates a matched
				// secret before it ever becomes Evidence), and re-reading would
				// bypass both and put raw credentials into a blob the GitHub
				// App uploads.
				if ev := NeutralizeText(f.Evidence); ev != "" {
					reg.Snippet = &SARIFArtifactContent{Text: ev}
				}
				loc.PhysicalLocation.Region = reg
				locCtx = fmt.Sprintf("%s:%d", artifactURI, lineNum)
			}
			result.Locations = []SARIFLocation{loc}
		} else {
			// Use AffectedEndpoints when present (deduped finding); otherwise
			// fall back to the singleton Endpoint. Either way produces one
			// SARIFLocation per endpoint with kind=endpoint.
			endpoints := f.AffectedEndpoints
			if len(endpoints) == 0 && f.Endpoint != "" {
				endpoints = []string{f.Endpoint}
			}
			// A URL-shaped `line` on a finding with no endpoint at all is
			// still a location. De-escalate it to a logical one rather than
			// dropping it — working rule 3: evidence is de-escalated, never
			// deleted.
			if len(endpoints) == 0 && filePath != "" && looksLikeURLPath(filePath) {
				endpoints = []string{filePath}
			}
			if len(endpoints) > 0 {
				// Cap the navigable list; the full set is recorded in
				// properties below. See sarifMaxLogicalLocations.
				shown := endpoints
				truncated := false
				if len(shown) > sarifMaxLogicalLocations {
					shown = shown[:sarifMaxLogicalLocations]
					truncated = true
				}
				locs := make([]SARIFLocation, 0, len(shown))
				for _, ep := range shown {
					locs = append(locs, SARIFLocation{
						LogicalLocations: []SARIFLogicalLocation{{
							// Endpoint string is an untrusted logical
							// location name — strip control/bidi chars.
							Name: NeutralizeText(ep),
							Kind: "endpoint",
						}},
					})
				}
				result.Locations = locs
				locCtx = NeutralizeText(endpoints[0])
				if len(endpoints) > 1 {
					locCtx = fmt.Sprintf("%s (+%d more)", locCtx, len(endpoints)-1)
				}
				if truncated {
					// Recorded here, stamped after the property block below —
					// sarifResultProperties REPLACES result.Properties, so
					// writing it now would be silently overwritten.
					truncatedEndpoints = endpoints
				}
			}
		}
		result.Message = SARIFMessage{Text: buildResultMessage(f, locCtx)}
		// Effective risk on SARIF's own per-result priority field. Stamped
		// only for a finding that was actually assessed — see effectiveRiskBand
		// on why an unassessed finding is not silently down-ranked.
		if effectiveRiskBand(f) != "" {
			rank := effectiveRisk(f)
			result.Rank = &rank
		}

		// Proven Path v1: render the taint chain as a codeFlow so GitHub
		// shows the source→sink step-through, and stamp provenance
		// (source_tier, reachable, route binding) into result properties.
		if cf := taintChainToCodeFlow(f.TaintChain); cf != nil {
			result.CodeFlows = []SARIFCodeFlow{*cf}
		}
		if props := sarifResultProperties(f); props != nil {
			result.Properties = props
		}
		// A truncated result must never read as a complete one. The count, the
		// full endpoint set and an explicit marker go on after the property
		// block, which replaces result.Properties wholesale.
		if len(truncatedEndpoints) > 0 {
			if result.Properties == nil {
				result.Properties = &SARIFResultProperties{}
			}
			result.Properties.AffectedEndpointCount = len(truncatedEndpoints)
			result.Properties.AffectedEndpoints = neutralizeAll(truncatedEndpoints)
			result.Properties.LocationsTruncated = true
		}

		// FIX-13.1 / DECISIONS.md D4: emit the key only when a real
		// engine-scheme fingerprint is present. Never invent one, never emit an
		// empty value — omitempty keeps a pre-fingerprint report byte-identical.
		// NeutralizeText is not decorative here: under `fendix report --input`
		// this value comes from an operator-supplied JSON file, i.e. it is
		// untrusted like every other field in this loop.
		if fp := strings.TrimSpace(NeutralizeText(f.Fingerprint)); fp != "" {
			result.PartialFingerprints = map[string]string{fingerprintKey: fp}
		}

		results = append(results, result)
	}

	// F-L13 / spec §5.6: executionSuccessful() picks one of three modes
	// (default CLI, strict CLI, hosted export) from meta alone, and every
	// non-ok ScannerStatus entry becomes its own toolExecutionNotification —
	// a degraded or incomplete scan must not present as a clean pass to
	// SARIF consumers.
	invocation := SARIFInvocation{ExecutionSuccessful: executionSuccessful(meta)}
	for _, s := range meta.ScannerStatus {
		if s.State == ScannerOK {
			continue
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{
			Level:   notificationLevel(s),
			Message: SARIFMessage{Text: notificationText(s)},
		})
	}
	if meta.Coverage != nil && meta.Coverage.Strict {
		byName := map[string]ScannerStatus{}
		for _, s := range meta.ScannerStatus {
			byName[s.Name] = s
		}
		for _, name := range meta.Coverage.RequiredGaps {
			// s is the zero value when the required name has no matching
			// scanner_status entry at all (BuildCoverage supports that: an
			// operator can require an analyzer the report never mentions).
			// Its Reason is then "", so the parenthetical is omitted rather
			// than rendered as a dangling "()".
			s := byName[name]
			text := fmt.Sprintf("required analyzer %s not delivered: %s", name, s.Class())
			if s.Reason != "" {
				text += fmt.Sprintf(" (%s)", s.Reason)
			}
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{Level: "error", Message: SARIFMessage{Text: NeutralizeText(text)}})
		}
	}
	if meta.CoverageState == "incomplete" {
		text := "Required coverage incomplete"
		if names := hostedIncompleteGapNames(meta); len(names) > 0 {
			text += ": " + strings.Join(names, ", ")
		}
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, SARIFNotification{
			Level: "warning",
			// names can originate from ScannerStatus.Name or
			// meta.Coverage.Gaps, both operator-controlled under
			// `fendix report --input`, so the whole message is neutralized
			// like every other notification text in this function.
			Message: SARIFMessage{Text: NeutralizeText(text)},
		})
	}

	var runProps map[string]any
	if meta.Coverage != nil || len(meta.ScannerStatus) > 0 {
		runProps = map[string]any{"fendix/coverage": map[string]any{"coverage": meta.Coverage, "scanner_status": meta.ScannerStatus}}
	}
	if meta.ReleaseDecision != "" || meta.CoverageState != "" {
		if runProps == nil {
			runProps = map[string]any{}
		}
		rel := map[string]any{"release_decision": meta.ReleaseDecision, "coverage_state": meta.CoverageState, "decision_policy_version": meta.DecisionPolicyVersion}
		if len(meta.DecisionRationale) > 0 {
			rel["decision_rationale"] = meta.DecisionRationale
		}
		runProps["fendix/release"] = rel
	}

	log := SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Fendix",
						Version:        meta.Version,
						InformationURI: "https://github.com/Fendix-app/Fendix",
						Rules:          rules,
					},
				},
				// Emitted unconditionally, zero-findings runs included: GitHub
				// needs the category on a clean run too, otherwise the "no
				// alerts" upload cannot clear the previous run's alerts for it.
				AutomationDetails: &SARIFRunAutomationDetails{ID: automationIDFor(meta.Mode)},
				Results:           results,
				Invocations:       []SARIFInvocation{invocation},
				Properties:        runProps,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF report: %w", err)
	}
	return nil
}

// neutralizeAll strips control/bidi characters from every entry of an
// untrusted string slice. Endpoint names reach the report from crawled targets
// and spec files, so they are neutralized wherever they are emitted — the
// property copy is no different from the logicalLocation copy.
// neutralizeBreakdown sanitizes the free TEXT of each breakdown entry and
// leaves Code and Delta untouched. Codes are a closed set this engine emits
// and deltas are integers, so neither can carry the control/bidi characters
// NeutralizeText exists to strip — and a code must survive byte-exact or the
// consumer matching on it silently stops matching.
func neutralizeBreakdown(in []models.ConfidenceReason) []models.ConfidenceReason {
	if len(in) == 0 {
		return nil
	}
	out := make([]models.ConfidenceReason, len(in))
	for i, r := range in {
		out[i] = models.ConfidenceReason{Delta: r.Delta, Code: r.Code, Text: NeutralizeText(r.Text)}
	}
	return out
}

func neutralizeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = NeutralizeText(s)
	}
	return out
}

// executionSuccessful implements the three modes of spec §5.6, decided from
// the input alone so a re-render is faithful:
//  1. hosted export (coverage_state present): false iff incomplete —
//     regardless of any unrelated scanner failure, since the hosted
//     release_decision is the verdict that matters here;
//  2. strict CLI run: false iff Coverage.StrictOK() is false (a failed
//     entry is already an engine gap, so configured_complete already
//     covers it — no separate failure check needed);
//  3. default CLI run: false iff an analyzer failed — unchanged behaviour.
func executionSuccessful(meta ScanMetadata) bool {
	if meta.CoverageState != "" {
		return meta.CoverageState != "incomplete"
	}
	if meta.Coverage != nil && meta.Coverage.Strict {
		return meta.Coverage.StrictOK()
	}
	for _, s := range meta.ScannerStatus {
		if s.Failed() {
			return false
		}
	}
	return true
}

// notificationLevel maps a lifecycle class to a SARIF notification level:
// a failure is an error, an unavailable dependency or an unclassifiable
// entry is a warning, an intentional or structural skip is a note.
func notificationLevel(s ScannerStatus) string {
	switch s.Class() {
	case ClassFailed:
		return "error"
	case ClassUnavailable, ClassUnknown:
		return "warning"
	}
	return "note"
}

// notificationText renders "<name>: <class> (<reason>): <detail>". Detail
// is neutralized because under `fendix report --input` it is operator
// supplied.
func notificationText(s ScannerStatus) string {
	text := s.Name + ": " + s.Class()
	if s.Reason != "" {
		text += " (" + string(s.Reason) + ")"
	}
	if s.Detail != "" {
		text += ": " + s.Detail
	}
	return NeutralizeText(text)
}

// hostedIncompleteGapNames names the analyzers behind a hosted
// coverage_state=incomplete verdict, in order of preference:
//  1. the backend's own rationale (spec §6.2 rationale v2 shape,
//     "missing_coverage[].scanner"), decoded best-effort — any other
//     shape, or no rationale at all, simply falls through; never an
//     error, never a panic;
//  2. else the engine's own Coverage.Gaps, when non-empty;
//  3. else any local ScannerStatus entry that is a gap or unclassifiable.
//
// The result is deduplicated preserving order, and may be empty when
// nothing can be named.
func hostedIncompleteGapNames(meta ScanMetadata) []string {
	var names []string
	if len(meta.DecisionRationale) > 0 {
		var rationale struct {
			MissingCoverage []struct {
				Scanner string `json:"scanner"`
			} `json:"missing_coverage"`
		}
		if err := json.Unmarshal(meta.DecisionRationale, &rationale); err == nil {
			for _, m := range rationale.MissingCoverage {
				names = append(names, m.Scanner)
			}
		}
	}
	if len(names) == 0 && meta.Coverage != nil && len(meta.Coverage.Gaps) > 0 {
		names = append(names, meta.Coverage.Gaps...)
	}
	if len(names) == 0 {
		for _, s := range meta.ScannerStatus {
			if s.IsGap() || s.Class() == ClassUnknown {
				names = append(names, s.Name)
			}
		}
	}
	return dedupeStrings(names)
}

// dedupeStrings drops empty entries and repeats, preserving first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
