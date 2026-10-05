// Package confidence is the v0.23 Confidence Engine: a DETERMINISTIC,
// rule-based, fully explainable scorer that turns an evidence.Evidence into a
// 0–100 confidence score plus a plain-text reason for every contribution.
//
// There is NO AI in this path (Constitution Rule 8). Every point comes from a
// fixed, documented rule keyed off the provenance v0.22 threaded onto Evidence
// (source engine, runtime confirmation, reachability, cross-engine agreement,
// payload validation, analyzer tier, correlation lineage). The same Evidence
// always yields the same score and the same reasons — auditable, reproducible.
//
// v0.23 is INTERNAL: the score attaches to the internal decision.Decision and
// does NOT change the public report (the existing models.Confidence enum,
// severity, and JSON/SARIF/HTML are untouched). v0.24 surfaces it.
package confidence

import (
	"fmt"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Rule deltas. Exposed as consts so the scoring policy is auditable at a
// glance and a future release can tune it without spelunking the logic.
//
// NOTE on payloadValidated — CORRECTED, and the correction matters for how the
// rest of the table reads.
//
// The previous note said the rule was dead because "every active-probe scanner
// sets Payload, none sets Response". BOTH halves were wrong: every `Payload:`
// site in internal/scanner populated a ProbeRecord (the probe audit log), never
// an ev.Evidence, so production evidence carried NEITHER field. The rule was
// doubly dead, and nothing in the type system said so.
//
// As of the RC-1 decision-integrity change the confirmed active-probe checks
// (error-based SQLi, time-based blind SQLi, command injection, CRLF, reflected
// XSS, open redirect) set both fields on the Evidence they emit, so the +10
// fires in production and the DAST-only ceiling before directObservation is 55.
//
// This matters beyond the score: decision.corroborate counts "payload-validated
// probe" as an INDEPENDENT corroborating signal, and it is what active-probe
// findings gate on now that the tautological "live runtime observation" signal
// is gone. A scanner that records only what it SENT confirms nothing.
const (
	base               = 35  // a scanner flagged this at all
	staticEvidence     = 10  // SAST (whitebox/correlated) saw it in source
	runtimeEvidence    = 10  // DAST (blackbox/correlated) observed it live
	crossEngineAgree   = 25  // DAST and SAST independently flagged the same issue
	routeConfirmed     = 10  // a live request confirmed the vulnerable route
	reachableTaint     = 10  // AST proved a source→sink taint path
	provenPathBonus    = 5   // confirmed route AND reachable taint chain
	payloadValidated   = 10  // an active probe payload elicited a confirming response
	directObservation  = 30  // the claim is a deterministic read of a live response (header/cookie/CORS value present or absent)
	deterministicDetn  = 30  // the claim is a deterministic pattern match in production (non-test, non-fixture) source
	tierTreeSitterBump = 5   // highest-trust analyzer tier
	tierSemgrepPenalty = -5  // lowest-trust analyzer tier (regex breadth)
	httpContextPenalty = -15 // B4: finding fired on a 4xx / static-asset context
	placeholderPenalty = -20 // the credential value matches deterministic fixture heuristics
	// FIX-14. Lighter than httpContextPenalty on purpose: that rule fires when
	// a finding was observed in a context that makes it PROBABLY inapplicable
	// (an auth-gated 4xx, a static asset), whereas "the advisory's component is
	// never imported" is a weaker inference — the vulnerable dependency IS
	// installed, and reflective import forms (importlib.import_module) are a
	// documented false-negative of the grep that backs it.
	componentNotImported = -10

	// ── SARIF import (Source=imported) ─────────────────────────────────────
	// External tool output is INPUT EVIDENCE, not fendix verification, so the
	// deltas are calibrated to land each precision tier in the band the
	// import design promised: high-precision → 35+10+25 = 70, exactly
	// bandHigh (blocks alone at/above --fail-on); medium → 45, MEDIUM band
	// (blocks only with a corroborating signal); low → 35, LOW band (warns).
	importedEvidence      = 10  // an external scanner reported this via SARIF import
	importedHighPrecision = 25  // the source tool declares high precision / error level
	importedLowPrecision  = -10 // the source tool declares low precision / note level
	// crossToolCorroborated fires only on the STRONG predicate in
	// engine.CorrelateCrossTool: a genuinely independent tool reported the
	// same normalized CWE at the same normalized location. Deliberately
	// smaller than crossEngineAgree (+25): DAST+SAST agreement inside fendix
	// proves two different OBSERVATION MODES agree, while cross-tool
	// agreement proves two implementations of (often) the same mode agree.
	// The decision-layer corroboration signal, not this delta, is what lifts
	// a MEDIUM-band finding to BLOCK.
	crossToolCorroborated = 15

	// Band thresholds on the 0–100 score.
	bandHigh   = 70
	bandMedium = 40
)

// Result is the deterministic confidence verdict for one piece of Evidence.
type Result struct {
	// Value is the clamped 0–100 score.
	Value int
	// Band is the coarse bucket derived from Value (HIGH/MEDIUM/LOW).
	Band models.Confidence
	// Reasons is the plain-text breakdown — one line per rule that fired,
	// in deterministic order. This is the "no black boxes" contract.
	Reasons []string
	// Details is the SAME breakdown in machine-readable form, index-for-index
	// aligned with Reasons. It exists so a consumer — SARIF above all — can key
	// off a stable Code and a signed Delta instead of parsing a presentation
	// string whose wording is free to change.
	//
	// Reasons is NOT derived from Details and Details is NOT derived from
	// Reasons: both are appended by the same rule at the same moment, which is
	// what keeps them aligned. TestDetailsParallelReasons locks the alignment.
	Details []Reason
}

// Reason is one scoring rule's contribution to a confidence score.
//
// Aliased to models.ConfidenceReason rather than declared here: the type has
// to sit on models.Finding (the published report shape) and models cannot
// import this package without a cycle. An ALIAS, not a defined type, so the
// two names are the same type and no conversion is ever needed.
type Reason = models.ConfidenceReason

// Score computes the confidence Result for ev. Pure and deterministic.
//
// CALLER CONTRACT: several rules here (payload-validated, the B4
// ResponseContext de-escalation, the lineage reason line) read fields that
// exist ONLY on evidence.Evidence — models.Finding has no home for them. So
// scoring an Evidence rebuilt from a projected Finding silently skips those
// rules. Anything downstream of the Evidence→Finding projection must run its
// input through evidence.ProvenanceIndex.Restore first; the orchestrator does
// this in stampDecisions, and
// TestScoringProvenanceSurvivesTheFindingProjection guards it.
func Score(ev evidence.Evidence) Result {
	score := base
	const baseWhy = "base: a scanner produced this finding"
	reasons := []string{fmt.Sprintf("+%d %s", base, baseWhy)}
	details := []Reason{{Delta: base, Code: CodeBaseDetection, Text: baseWhy}}

	// add records ONE rule firing, in both forms, from a single call. Keeping
	// the two appends in one place is the whole anti-drift mechanism: there is
	// no way to add a scoring rule that lands in the text report but not in the
	// structured one.
	add := func(delta int, code, why string) {
		score += delta
		sign := "+"
		if delta < 0 {
			sign = "" // negative already carries its sign
		}
		reasons = append(reasons, fmt.Sprintf("%s%d %s", sign, delta, why))
		details = append(details, Reason{Delta: delta, Code: code, Text: why})
	}

	hasStatic := ev.Source == models.SourceWhitebox || ev.Source == models.SourceCorrelated
	hasRuntime := ev.Source == models.SourceBlackbox || ev.Source == models.SourceCorrelated
	if hasStatic {
		add(staticEvidence, CodeStaticEvidence, "static (SAST) evidence present")
	}
	if hasRuntime {
		add(runtimeEvidence, CodeRuntimeEvidence, "runtime (DAST) observation present")
	}
	if ev.Source == models.SourceCorrelated {
		add(crossEngineAgree, CodeCrossEngineAgreement, "cross-engine agreement: DAST and SAST independently flagged this")
	}
	if ev.Source == models.SourceImported {
		add(importedEvidence, CodeImportedEvidence, "imported: an external scanner reported this finding (SARIF import)")
		// The tool's self-declared precision (mapped onto the Confidence
		// enum by sarifimport) sets the standalone band. It is the tool's
		// claim about its own rule — never a fendix verification signal, and
		// never a corroborator for any OTHER finding.
		switch ev.Confidence {
		case models.ConfidenceHigh:
			add(importedHighPrecision, CodeImportedHighPrecision, "the source tool declares high precision for this rule")
		case models.ConfidenceLow:
			add(importedLowPrecision, CodeImportedLowPrecision, "the source tool declares low precision for this rule")
		}
	}
	if ev.RouteConfirmed {
		add(routeConfirmed, CodeRouteConfirmed, "live request confirmed the vulnerable route")
	}
	if ev.Reachable {
		add(reachableTaint, CodeReachableTaintPath, "AST proved a reachable source→sink taint path")
	}
	if ev.ProvenPath {
		add(provenPathBonus, CodeProvenPath, "proven path: confirmed route AND reachable taint chain")
	}
	if ev.Payload != "" && ev.Response != "" {
		add(payloadValidated, CodePayloadValidated, "active probe payload elicited a confirming response")
	}
	// A deterministic read of a live response — a header present or absent, a
	// cookie attribute present or absent, a literal CORS header value — is
	// near-certain: there is no inference step between the bytes on the wire
	// and the claim. Gated on hasRuntime because the concept is DAST-only; a
	// static analyzer can never make this observation, and the gate stops a
	// future SAST emitter from claiming the bonus.
	//
	// The delta is 30, not 25. At +25 a clean direct observation lands on
	// exactly bandHigh (35+10+25 == 70) with zero margin, and correlation can
	// never lift these categories higher — engine.categoryMap covers only
	// secrets/injection/auth, so a headers/cookie/cors finding is never
	// SourceCorrelated. Any future negative delta would then drop every one of
	// them out of HIGH in a single step. At +30 a clean observation sits at 75,
	// and one carrying the B4 context penalty lands at 60 — still MEDIUM, which
	// is precisely the de-escalation the 4xx / static-asset FP classes need.
	if hasRuntime && ev.DirectObservation {
		add(directObservation, CodeDirectObservation, "direct observation: the finding is a deterministic read of a live response")
	}
	if HasDeterministicDetection(ev) {
		add(deterministicDetn, CodeDeterministicDetection, "deterministic detection: a high-confidence pattern match in production (non-test) code")
	}
	switch ev.SourceTier {
	case models.TierTreeSitter:
		add(tierTreeSitterBump, CodeTierTreeSitter, "high-trust analyzer tier (tree-sitter taint)")
	case models.TierSemgrepShim:
		add(tierSemgrepPenalty, CodeTierSemgrep, "lower-trust analyzer tier (semgrep regex breadth)")
	}

	// Strong cross-tool corroboration (engine.CorrelateCrossTool): an
	// INDEPENDENT tool reported the same normalized CWE at the same
	// normalized location. This is the only channel by which imported
	// evidence strengthens a score — title/category/fingerprint coincidence
	// never reaches here.
	if ev.CrossToolCorroborated {
		why := "independent cross-tool corroboration: another engine reported the same weakness at the same location"
		if len(ev.CorroboratingTools) > 0 {
			why = "independent cross-tool corroboration: " + strings.Join(ev.CorroboratingTools, ", ") +
				" reported the same weakness at the same location"
		}
		add(crossToolCorroborated, CodeCrossToolCorroborated, why)
	}

	// B4: de-escalate (not suppress) DAST findings that fired on a 4xx
	// (auth-gated/client-error) response or a static-asset endpoint. Evidence
	// is preserved (Rule 3); only the confidence score drops.
	switch ev.ResponseContext {
	case "4xx":
		add(httpContextPenalty, CodeHTTPContext4xx, "finding fired on a 4xx (auth-gated/client-error) response")
	case "static-asset":
		add(httpContextPenalty, CodeHTTPContextStaticAsset, "finding fired on a static-asset endpoint, not an API route")
	}

	// De-escalate (never suppress) a credential finding whose value is shaped
	// like a fixture. The classification itself is computed deterministically
	// in scanner/secrets and carried on the Evidence, so nothing here is
	// heuristic at scoring time (Rule 8) and the finding is still reported in
	// full with its evidence intact (Rule 3).
	if ev.Placeholder {
		add(placeholderPenalty, CodeFixtureShapedValue, "credential value matches deterministic placeholder heuristics (fixture-shaped)")
	}

	// De-escalate (never suppress) a dependency finding whose advisory is
	// scoped to an importable sub-component the scanned tree never imports.
	// The grep behind the flag is deterministic and runs in the scanner
	// (Rule 8); the finding keeps its id, severity, endpoint and full evidence
	// text (Rule 3) — only the confidence drops, which is what stops a
	// smaller-surface vulnerability from gating a build at the same weight as
	// one on a code path the project actually uses.
	if ev.ComponentNotImported {
		add(componentNotImported, CodeComponentNotImported, "the advisory's affected component is not imported by the scanned code")
	}

	// Evidence-chain tracing: a correlated score is only as trustworthy as
	// the inputs that merged into it, so surface them.
	if trace := lineageTrace(ev); trace != "" {
		// Delta 0: lineage explains where the score came from, it does not
		// move it. Its rendered line carries no signed prefix, which is why
		// the alignment test suffix-matches rather than comparing equality.
		reasons = append(reasons, trace)
		details = append(details, Reason{Code: CodeEvidenceLineage, Text: trace})
	}

	// Keep the "no black boxes" contract exact: when corroboration pushes the
	// raw sum over the ceiling, record the cap so the reasons sum to Value.
	if score > 100 {
		const capWhy = "capped at 100 (corroboration ceiling)"
		over := score - 100
		reasons = append(reasons, fmt.Sprintf("-%d %s", over, capWhy))
		details = append(details, Reason{Delta: -over, Code: CodeCorroborationCeiling, Text: capWhy})
	}
	score = clamp(score, 0, 100)
	return Result{Value: score, Band: bandFor(score), Reasons: reasons, Details: details}
}

// HasDeterministicDetection reports whether ev earns the deterministicDetn
// delta: the static-analysis mirror of DirectObservation.
//
// A pattern analyzer that reads a credential, a vulnerable pinned version or a
// dangerous construct out of source text and asserts models.ConfidenceHigh has
// made the same KIND of claim a missing-header check makes — the finding IS the
// read, with no inference between the bytes in the file and the claim. Without
// it a whitebox secrets finding scores 35 base + 10 static = 45 and can never
// leave the MEDIUM band on its own, because payloadValidated cannot fire (no
// producer sets Evidence.Response) and correlation needs a live target. Once
// band membership gates enforcement, that would stop a code-only scan of REAL
// hardcoded credentials from failing the build — a security regression, which
// is why this delta exists.
//
// Exported so the decision layer can count the same signal as corroboration
// without re-deriving — and then drifting from — the predicate.
//
// The four conjuncts, each doing real work:
//
//   - hasStatic: the mirror of DirectObservation's hasRuntime gate. A live
//     probe cannot make a source-text pattern match.
//   - ConfidenceHigh: the emitting check's own claim that this is a literal
//     match rather than a graded guess. It is the same predicate the DAST side
//     uses, so one rule reads across both halves of the engine.
//   - not TierSemgrepShim: that tier buys breadth at the cost of precision and
//     has not cleared the F1 gate (see models.SourceTier.TrustRank and
//     tierSemgrepPenalty). Letting regex breadth band HIGH on its own would
//     hand the gate exactly the false positives band-gating exists to stop.
//   - not InTest, not Placeholder: 31 of the 35 catalogued instances in
//     tasks/FP_CORPUS.md are test fixtures, and a value the placeholder
//     classifier recognises is deterministic evidence that the match is NOT a
//     real credential. Both directly negate "deterministic detection of a real
//     defect", so they gate the bonus rather than merely being penalised
//     afterwards — a fixture-shaped credential must land in LOW, not in the
//     MEDIUM band where one corroborator could still block a build.
//
// Reachable / proven-path findings are deliberately NOT excluded. A proven
// source→sink chain is the most deterministic thing a static analyzer can
// produce; excluding it would leave a CRITICAL proven-path SQLi in MEDIUM with
// no corroborator on a code-only scan, which is the same regression this delta
// was added to prevent.
func HasDeterministicDetection(ev evidence.Evidence) bool {
	hasStatic := ev.Source == models.SourceWhitebox || ev.Source == models.SourceCorrelated
	return hasStatic &&
		ev.Confidence == models.ConfidenceHigh &&
		ev.SourceTier != models.TierSemgrepShim &&
		!ev.InTest &&
		!ev.Placeholder
}

// lineageTrace renders ev.Lineage (the BB+WB inputs that merged during
// correlation) into a single plain-text chain line. Empty when there's no
// lineage (non-correlated evidence).
func lineageTrace(ev evidence.Evidence) string {
	if len(ev.Lineage) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ev.Lineage))
	for _, in := range ev.Lineage {
		src := string(in.Source)
		if src == "" {
			src = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", src, in.Category))
	}
	return "evidence chain: merged from " + strings.Join(parts, " + ")
}

func bandFor(score int) models.Confidence {
	switch {
	case score >= bandHigh:
		return models.ConfidenceHigh
	case score >= bandMedium:
		return models.ConfidenceMedium
	default:
		return models.ConfidenceLow
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
