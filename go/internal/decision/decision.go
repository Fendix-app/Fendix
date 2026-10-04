// Package decision is the Decision layer in Fendix's
// Engine → Evidence → Finding → Decision architecture.
//
// A Decision is the verdict for a piece of Evidence: should this finding BLOCK
// the build, merely WARN, be INFO, or be IGNOREd. Since v0.24 this layer is NOT
// parallel bookkeeping — it IS the product: orchestrator.Run stamps every
// finding's published `status` from stampDecisions and then returns
// decision.ExitCode(decisions) as the process exit code. The legacy checkFailOn
// helper no longer exists anywhere in the module; the comments that still name
// it mark the behaviour this package must reproduce, not live code.
//
// Two entry points, deliberately:
//
//   - Decide / DecideAll take no Options and implement the LEGACY,
//     severity-only mapping (block iff severity >= --fail-on). Production does
//     not take this path any more. It is retained because it is the oracle
//     TestExitCodeMatchesLegacyCheckFailOn locks, and that lock is what makes
//     `--enforce-confidence=false` a byte-for-byte-compatible escape hatch
//     rather than a promise.
//   - DecideWithOptions / DecideAllWithOptions take the scan policy and are
//     what the orchestrator calls. Under Options.EnforceConfidence (the CLI
//     default) a finding at or above --fail-on BLOCKs only when the
//     deterministic confidence band supports the claim; under
//     Options.DeescalateTests an uncorroborated finding in test/fixture code is
//     held at WARN.
//
// Neither policy ever drops a finding, edits its evidence text or changes its
// confidence score (Rule 3 / Rule 8): the only things that move are
// Decision.Status, Decision.Reason and one appended 0-point Score.Reasons line
// explaining the move.
package decision

import (
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/confidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Policy names which decision policy produced a verdict.
//
// It is published because a BLOCK means two different things under the two
// policies, and a consumer that cannot tell them apart cannot verify Fendix's
// central claim — that a normal BLOCK is an auditable, evidence-backed
// decision rather than a severe scanner observation.
type Policy string

const (
	// PolicyEnforced is the shipped policy: a finding at or above --fail-on
	// blocks only when the confidence band supports it AND something
	// corroborates the claim.
	PolicyEnforced Policy = "enforced"
	// PolicyRelaxed is the legacy severity-only mapping, restored by
	// --enforce-confidence=false. Corroboration is ignored entirely.
	PolicyRelaxed Policy = "relaxed"
)

// Status is the verdict for one piece of evidence.
type Status string

const (
	// StatusBlock — fails the build (exit 1). Matches "at/above --fail-on".
	StatusBlock Status = "BLOCK"
	// StatusWarn — surfaced prominently but non-blocking (MEDIUM+ below threshold).
	StatusWarn Status = "WARN"
	// StatusInfo — informational (LOW / INFO severity).
	StatusInfo Status = "INFO"
	// StatusIgnore — suppressed (e.g. by a .fendix-ignore rule). Reserved;
	// suppression happens upstream today, so Decide does not emit it yet.
	StatusIgnore Status = "IGNORE"
)

// Decision is the internal verdict plus its justification.
type Decision struct {
	Status     Status
	Confidence models.Confidence
	Reason     string
	// Score is the deterministic confidence score (0–100) + plain-text reason
	// breakdown for this decision. Stamped onto the finding as
	// confidence_score / confidence_band / confidence_reasons.
	Score confidence.Result
	// Evidence is the supporting evidence this verdict was derived from.
	Evidence evidence.Evidence
	// Corroboration is the partitioned signal set behind Status. Exported so
	// the orchestrator can stamp it onto the finding without re-deriving — and
	// therefore drifting from — the predicate the gate actually used.
	Corroboration corroboration
	// Policy names which policy produced this verdict (enforced / relaxed).
	Policy Policy
	// PolicyOverride is true ONLY when the relaxed policy produced a BLOCK that
	// the shipped policy would NOT have produced. That is the precise condition
	// worth flagging: an unconfirmed finding gated a build because the operator
	// turned the evidence requirement off.
	//
	// Deliberately NOT "the relaxed policy was in effect". A relaxed run whose
	// findings are all independently corroborated would block identically under
	// either policy; marking those would cry wolf and teach readers to ignore
	// the flag, which is worse than not having it.
	PolicyOverride bool

	// aboveThreshold records that this finding's severity met --fail-on,
	// independent of what the confidence policy then did with it. It is the
	// floor DecideWithOptions uses to keep a threshold-crossing finding from
	// sinking all the way to INFO after a demotion. Unexported on purpose:
	// nothing serializes Decision, and it is policy bookkeeping, not a verdict.
	aboveThreshold bool
}

// Decide computes the Decision for one piece of evidence under the given
// --fail-on threshold (the raw flag value; "" = no threshold), using the
// LEGACY severity-only mapping: block iff failOn is a valid severity (rank > 0)
// and the evidence's severity rank is at or above it. Identical to the
// pre-v1.2.2 checkFailOn.
//
// This is the frozen compatibility oracle, not the production path — see the
// package doc. Production calls DecideWithOptions; passing a zero Options there
// reproduces exactly this mapping, which is the --enforce-confidence=false
// contract.
func Decide(ev evidence.Evidence, failOn string) Decision {
	return decide(ev, failOn, Options{})
}

// decide is the shared body. opts.EnforceConfidence changes ONLY the
// at-or-above-threshold arm; the WARN (actionable, below threshold) and INFO
// (informational) arms are byte-identical in both modes, so a finding that
// never met --fail-on is unaffected by the confidence policy.
func decide(ev evidence.Evidence, failOn string, opts Options) Decision {
	threshold := 0
	if failOn != "" {
		threshold = models.SeverityRank(models.Severity(failOn))
	}
	rank := models.SeverityRank(ev.Severity)

	d := Decision{
		Confidence: ev.Confidence,
		Score:      confidence.Score(ev),
		Evidence:   ev,
		// Computed once here so the gate, the reason string and the exported
		// justification all read the SAME partition. Deriving it a second time
		// downstream is how an exporter drifts from the policy it claims to
		// describe.
		Corroboration: corroborate(ev),
	}
	d.aboveThreshold = threshold > 0 && rank >= threshold
	d.Policy = PolicyRelaxed
	if opts.EnforceConfidence {
		d.Policy = PolicyEnforced
	}
	switch {
	case d.aboveThreshold:
		if opts.EnforceConfidence {
			applyConfidenceGate(&d, ev)
		} else {
			d.Status = StatusBlock
			d.Reason = "severity at or above the --fail-on threshold"
			// Would the SHIPPED policy have blocked this too? Run the same gate
			// on a throwaway copy and compare. If it would have warned, this
			// BLOCK exists only because the evidence requirement was switched
			// off, and that fact has to travel with the finding all the way to
			// SARIF — otherwise an operator-relaxed gate is indistinguishable
			// from an evidence-backed one.
			//
			// Cheap and exact: applyConfidenceGate is a pure function of the
			// score and the corroboration, both already computed above.
			shadow := d
			applyConfidenceGate(&shadow, ev)
			d.PolicyOverride = shadow.Status != StatusBlock
			if d.PolicyOverride {
				d.Reason += " (relaxed policy: --enforce-confidence=false; the shipped policy " +
					"would have held this at " + string(shadow.Status) + " — " + shadow.Reason + ")"
			}
		}
	case rank >= models.SeverityRank(models.SeverityMedium):
		d.Status = StatusWarn
		d.Reason = "actionable finding below the --fail-on threshold"
	default:
		d.Status = StatusInfo
		d.Reason = "informational finding"
	}
	return d
}

// applyConfidenceGate is FIX-08, tightened by RC-1: a finding whose severity met
// --fail-on BLOCKs only when the deterministic confidence band supports the
// claim AND something actually corroborates it.
//
// The rule table, in evaluation order:
//
//	marked unconfirmed-by-live-scan, no independent signal → WARN
//	band LOW                                               → WARN
//	NO signal of any class                                 → WARN   ← RC-1
//	band MEDIUM, no INDEPENDENT signal                     → WARN
//	otherwise                                              → BLOCK
//
// RC-1 CHANGE, and the shape of it matters. The old table's third arm read
// "band MEDIUM, no corroborating signal → WARN", and the signal list counted
// "live runtime observation" — true for every Source ∈ {blackbox, correlated}.
// So a bare DAST finding (35 base + 10 runtime = 45, MEDIUM) supplied its own
// required signal and any scanner-assigned CRITICAL blocked the build.
//
// The fix is NOT "self-evident signals can never block". That was tried and it
// broke the case deterministicDetn exists for: a hardcoded credential in
// production source, found by a deterministic pattern match on a code-only scan,
// where no second observation is even possible. The difference is whether the
// observation ESTABLISHES the claim:
//
//   - secrets: the observation ("this regex matched a credential in non-test
//     source") substantially IS the claim. Self-evident, and sufficient at HIGH.
//   - auth_bypass: the observation ("HTTP 200 with no Authorization header") is
//     NOT the claim ("authentication was bypassed"). It is missing the premise
//     "authentication was expected here", which nothing supplied. It now scores
//     no signal at all and is held at WARN — and Task 3/4 of the plan gives it a
//     real independent signal when a spec declares the requirement.
//
// So the tautology is deleted, self-evident signals still count at HIGH, and a
// MEDIUM band still requires something independent.
//
// The unconfirmed arm runs FIRST and is band-independent: the correlator set
// that marker because a live scan ran and did NOT confirm this finding, which
// is a direct contradiction of the claim rather than merely weak support for
// it. Reporting "[Unconfirmed by live scan]" in the evidence text and failing
// the build on the same finding is the specific incoherence FIX-08 exists to
// remove, so no band alone lifts it — only an actual independent signal does.
//
// Every WARN arm appends one 0-point line to the score breakdown. It must be
// 0-point and carry an explicit "+0 " prefix: confidence_reasons is published
// alongside confidence_score and the two have to reconcile (Rule 8 —
// engine.assertReasonsSumToScore and confidence.TestReasonsSumToValue both
// parse the leading signed delta). The score itself never moves; a demotion is
// an ENFORCEMENT decision, not a re-scoring of the evidence.
func applyConfidenceGate(d *Decision, ev evidence.Evidence) {
	c := d.Corroboration
	sigs := c.Independent

	hold := func(code, reason string) {
		d.Status = StatusWarn
		d.Reason = reason
		appendDecisionReason(&d.Score, code, "+0 held at WARN: "+reason)
	}

	switch {
	case ev.UnconfirmedByLiveScan && len(sigs) == 0:
		hold(confidence.CodeHeldUnconfirmedByLiveScan,
			"severity at or above the --fail-on threshold but the finding is unconfirmed "+
				"by live scan and uncorroborated — needs independent corroboration to block")
	case d.Score.Band == models.ConfidenceLow:
		hold(confidence.CodeHeldConfidenceLow,
			"severity above threshold but confidence LOW — needs corroboration to block")
	case !c.Any():
		// RC-1's core arm. Reaching a band without ANY signal means the score
		// came from source/tier deltas alone — i.e. from what kind of scanner
		// ran, not from anything it established. A scanner-assigned severity
		// constant must not gate a build on its own.
		hold(confidence.CodeHeldUncorroborated,
			"severity above threshold but nothing corroborates the claim — "+
				"needs corroboration to block")
	case d.Score.Band == models.ConfidenceMedium && len(sigs) == 0:
		// A MEDIUM band supported only by self-evident signals: the observation
		// was clean, but nothing independent of it agrees. Held at WARN.
		hold(confidence.CodeHeldMediumNoIndependent,
			"severity above threshold but confidence MEDIUM with no corroborating signal — "+
				"needs corroboration to block")
	default:
		d.Status = StatusBlock
		d.Reason = "severity at or above the --fail-on threshold; corroborated by: " +
			strings.Join(append(append([]string(nil), sigs...), c.SelfEvident...), ", ")
	}
}

// corroboration partitions the signals supporting a claim into two classes.
//
// INDEPENDENT signals come from an observation DISTINCT from the one that
// produced the claim: another engine agreed, a taint path was proved, a route
// was confirmed live, a probe payload elicited a predicted response, an external
// tool reported the same weakness at the same location. These are the only
// signals that may lift a band to BLOCK.
//
// SELF-EVIDENT signals restate the observation that produced the claim: a
// deterministic read of a live response, a deterministic pattern match in
// production source. They are strong — they carry the largest confidence deltas
// in the scorer (+30 each) — but they are not CONFIRMATION, because there is no
// second observation that could have disagreed. They are published so a reader
// sees the full support, and they never substitute for an independent signal.
//
// RC-1, REMOVED IN THIS CHANGE: "live runtime observation", which fired for
// every Source ∈ {blackbox, correlated}. It was a restatement of a field the
// report already exports, so every blackbox finding corroborated ITSELF: a
// bare DAST finding sits at 35 base + 10 runtime = 45 (MEDIUM band), the
// tautology supplied the one required signal, and any scanner-assigned CRITICAL
// then blocked the build. Severity is a constant in the scanner; that made
// "BLOCK" a function of a constant.
//
// The prior comment defended the signal on the grounds that removing it would
// strip every active-probe DAST finding (injection, XSS, SSRF, GraphQL) of its
// only corroborator. That was TRUE, and the reason is recorded in confidence.go:
// payloadValidated requires Payload AND Response, and no production producer set
// Response, so the honest signal for those scanners was dead code. The fix is to
// make that signal real (the active-probe checks now record a bounded response
// excerpt), not to keep a tautology standing in for it.
//
// confidence.HasDeterministicDetection is the static mirror of DirectObservation
// and is called rather than re-derived, so the classification cannot drift from
// the delta that pays for it.
//
// Both slices are built by a FIXED sequence of ifs, never a map or a set: they
// are joined into Decision.Reason and exported into SARIF, so their order must
// be a pure function of the evidence (Rule 8). Each is nil when nothing fires,
// so `len(...) == 0` is the single predicate everywhere.
type corroboration struct {
	Independent []string
	SelfEvident []string
}

// Any reports whether any signal at all fired, in either class.
func (c corroboration) Any() bool {
	return len(c.Independent) > 0 || len(c.SelfEvident) > 0
}

func corroborate(ev evidence.Evidence) corroboration {
	var c corroboration

	if ev.Source == models.SourceCorrelated {
		c.Independent = append(c.Independent, "cross-engine agreement")
	}
	if ev.RouteConfirmed {
		c.Independent = append(c.Independent, "confirmed route")
	}
	if ev.Reachable {
		c.Independent = append(c.Independent, "reachable taint path")
	}
	if ev.ProvenPath {
		c.Independent = append(c.Independent, "proven path")
	}
	// Payload AND Response — mirrors confidence.payloadValidated exactly. The
	// pair is the differential: "we sent something" is not evidence, "the
	// target answered the way the check predicted" is.
	if ev.Payload != "" && ev.Response != "" {
		c.Independent = append(c.Independent, "payload-validated probe")
	}
	// Strong cross-tool corroboration only — stamped exclusively by
	// engine.CorrelateCrossTool when an INDEPENDENT tool reported the same
	// normalized CWE at the same normalized location. An imported finding that
	// merely shares a title, category, fingerprint, or file with this one never
	// sets the flag, so it can never satisfy this arm.
	if ev.CrossToolCorroborated {
		c.Independent = append(c.Independent, "independent cross-tool corroboration")
	}
	// A live unauthenticated success that contradicts a DECLARED requirement is
	// two observations disagreeing: the specification says protected, the wire
	// says open. The declaration comes from a source entirely separate from the
	// probe that produced the claim, which is what makes it independent — and
	// it is the premise the auth_bypass claim was missing (RC-2).
	//
	// Unknown and Public contribute NOTHING. Unknown is not evidence in either
	// direction, and Public is evidence AGAINST the claim, which the scanner
	// already reflects by emitting the finding at INFO.
	if ev.AuthExpectation == models.AuthExpectationRequired {
		c.Independent = append(c.Independent, "contradicted authentication requirement")
	}

	if ev.DirectObservation {
		c.SelfEvident = append(c.SelfEvident, "direct observation of a live response")
	}
	if confidence.HasDeterministicDetection(ev) {
		c.SelfEvident = append(c.SelfEvident, "deterministic detection in production code")
	}
	// An imported finding whose SOURCE TOOL declares the rule high-precision.
	// Self-evident, not independent: it is one engine's own claim about its own
	// rule, and nothing has agreed with it — cross-tool agreement is a separate
	// signal that only engine.CorrelateCrossTool may stamp.
	//
	// It must be classified rather than omitted. The SARIF-import design
	// (docs/superpowers/specs/2026-08-25-sarif-import-design.md) calibrated the
	// import deltas so a high-precision rule lands at exactly bandHigh (35 base
	// + 10 imported + 25 high-precision = 70) and gates on its own, while medium
	// lands at 45 and low at 35. Leaving it unclassified would silently revoke
	// that contract via the "no signal of any class" arm, turning an intentional
	// design decision into an accident of taxonomy.
	if ev.Source == models.SourceImported && ev.Confidence == models.ConfidenceHigh {
		c.SelfEvident = append(c.SelfEvident, "imported high-precision rule")
	}
	return c
}

// applyApplicabilityGate holds a dependency finding at WARN when Fendix has
// credible evidence that the advisory's affected component is unused.
//
// WHY THIS IS A DECISION ARM AND NOT A CONFIDENCE DELTA. Before this, the only
// consequence of non-applicability was componentNotImported (-10) on the score.
// That produced the right answer for the django case by arithmetic accident —
// 75 - 10 = 65 happens to cross the HIGH→MEDIUM boundary — and the wrong answer
// for any dependency finding whose score sat higher, e.g. one an independent
// tool also reported (+15 crossToolCorroborated). A ten-point nudge is not a
// policy; it is a coincidence that holds until the numbers move.
//
// The finding is fully PRESERVED (Rule 3): same id, severity, CVE identity and
// evidence text, and the score is untouched. Only enforcement moves, and one
// 0-point line records why.
//
// SCOPE. Deliberately restricted to category "deps". Applicability is a
// statement about a vulnerable dependency's affected component; it has no
// meaning for an injection or auth finding, and a stray value on one must not
// silence it.
//
// CONSERVATISM. ApplicabilityEvidenceAgainst is backed by a static import grep,
// which dynamic import forms can defeat. That is exactly why it de-escalates to
// WARN — visible, actionable, non-gating — rather than suppressing, and why
// Options.BlockOnInapplicable exists for teams whose policy is "no vulnerable
// version ships, applicable or not".
func applyApplicabilityGate(d *Decision, ev evidence.Evidence, opts Options) {
	// Applies to any THRESHOLD-CROSSING dependency finding, not only one the
	// confidence gate left at BLOCK.
	//
	// Scoping it to BLOCK alone was not enough: for the common django shape the
	// band arm fires first (65 → MEDIUM, no independent signal) and the finding
	// lands at WARN with a reason that never mentions applicability. The outcome
	// is right but the explanation is an accident — "confidence MEDIUM with no
	// corroborating signal" is true and useless, and it stops being true the
	// moment the score moves. Applicability is the durable, actionable fact, so
	// it becomes the stated reason whenever it applies.
	if !d.aboveThreshold || opts.BlockOnInapplicable {
		return
	}
	if d.Status != StatusBlock && d.Status != StatusWarn {
		return
	}
	if !strings.EqualFold(ev.Category, "deps") {
		return
	}
	if evidence.ApplicabilityOf(ev) != models.ApplicabilityEvidenceAgainst {
		return
	}
	const reason = "the vulnerable package is installed but Fendix found no import of the " +
		"advisory's affected component, so the vulnerable code path is not applicable to this " +
		"project on the available evidence — finding preserved, held at WARN " +
		"(override with --block-on-inapplicable)"
	d.Status = StatusWarn
	d.Reason = "severity at or above the --fail-on threshold, but " + reason
	appendDecisionReason(&d.Score, confidence.CodeNotApplicableComponentAbsent, "+0 held at WARN: "+reason)
}

// appendDecisionReason appends ONE enforcement line to the score breakdown, in
// both published forms at once — the rendered text and its machine-readable
// twin. Doing both from a single call is what stops a future demotion from
// landing in confidence_reasons but not in confidence_breakdown.
//
// `line` is the fully rendered text, INCLUDING its "+0 " prefix; the structured
// Text is that line with the prefix stripped, so Reasons[i] always ends with
// Details[i].Text and the alignment tests hold. Delta is 0 by construction: a
// demotion is an ENFORCEMENT decision, not a re-scoring of the evidence, and
// the published reasons must still sum to ConfidenceScore (Rule 8).
//
// Both slices are COPIED before appending. Copying is not optional:
// confidence.Score builds them once per call, and appending in place could
// write into a backing array another Decision shares, making the published
// output depend on evaluation order
// (TestDeescalationDoesNotAliasTheSharedReasonSlice guards this).
func appendDecisionReason(score *confidence.Result, code, line string) {
	score.Reasons = append(append([]string(nil), score.Reasons...), line)
	score.Details = append(append([]confidence.Reason(nil), score.Details...),
		confidence.Reason{Code: code, Text: strings.TrimPrefix(line, "+0 ")})
}

// Options tunes the decision policy.
//
// ZERO-VALUE POLARITY MATTERS. Both fields default to false = legacy, while
// both CLI flags default to true. A directly-constructed Options{} — which is
// what most engine tests build — therefore opts OUT of the shipped policy. That
// is exactly the shape that let DeescalateTests ship as dead code (see the
// header comment on internal/engine/deescalate_tests_wiring_test.go): the unit
// tests passed, the docs described the behaviour, and no config field turned it
// on. If you add a field here, add a wiring test that drives it from
// models.ScanConfig, not just from a literal.
type Options struct {
	// DeescalateTests drops findings in test / fixture code (evidence
	// preserved — Rule 3): WARN → INFO, and an UNCORROBORATED BLOCK → WARN.
	// A test-code finding with an independent signal — for example, a proved
	// reachable path beyond the original pattern match — still BLOCKs. A
	// provider-shaped token is not itself live validation. Overridable so a
	// team that DOES want to gate on every test-code finding can turn it off
	// with --deescalate-tests=false. (B3 / FIX-09.)
	DeescalateTests bool

	// EnforceConfidence gates the --fail-on threshold on the deterministic
	// confidence band: at or above the threshold, a finding BLOCKs only when
	// its band and evidence support the claim (HIGH needs an independent or
	// self-evident signal; MEDIUM needs an independent signal; LOW never), and
	// a finding the correlator marked
	// unconfirmed-by-live-scan never blocks on its own. Evidence is never
	// suppressed — only enforcement moves. (FIX-08.)
	//
	// The CLI default is true (--enforce-confidence). Setting it false
	// restores the legacy severity-only mapping BYTE-FOR-BYTE; it does not
	// also disable the test-fixture rule, which is gated on DeescalateTests.
	EnforceConfidence bool

	// BlockOnInapplicable makes a dependency finding gate the build even when
	// Fendix has credible evidence the vulnerable component is unused.
	//
	// Default false: evidence of non-applicability holds such a finding at WARN
	// (the finding, its severity, its CVE identity and its full evidence text
	// are all preserved — this is de-escalation, never suppression). A team with
	// a policy of "no vulnerable version ships, applicable or not" — common
	// under regulatory constraints where the SBOM is what is audited, not the
	// call graph — sets this to restore blocking.
	//
	// It is an explicit policy choice, not a confidence knob, which is why it
	// lives here rather than as another delta in the scorer.
	BlockOnInapplicable bool
}

// testFixtureReason is the 0-point explainability line appended to the score
// breakdown when the test-fixture WARN → INFO de-escalation fires. It carries
// an explicit "+0" so the published reasons still sum to ConfidenceScore — the
// de-escalation changes the decision STATUS, never the score (the same
// zero-delta convention confidence.lineageTrace uses).
const testFixtureReason = "+0 de-escalated to INFO: finding is in test/fixture code " +
	"(rule: test-fixture; evidence preserved)"

// testFixtureBlockReason is the same line for FIX-09's BLOCK → WARN arm. Kept
// separate so the report distinguishes "this was never going to gate anything"
// from "this crossed your --fail-on threshold and we held it at WARN".
const testFixtureBlockReason = "+0 de-escalated to WARN: finding is in test/fixture code " +
	"with no corroborating signal (rule: test-fixture; evidence preserved)"

// testFixtureCorroboratedReason is the line for the further WARN → INFO step
// taken when the test PATH and the fixture-shaped VALUE agree. Distinct from
// the two above so a reader can tell "held at WARN because it is in a test"
// from "dropped to INFO because two independent signals said it is not a real
// credential".
const testFixtureCorroboratedReason = "+0 de-escalated to INFO: credential is in test/fixture " +
	"code AND its value is fixture-shaped — two independent signals " +
	"(rule: test-fixture-corroborated; evidence preserved)"

// fixtureCorroborated reports whether two INDEPENDENT signals agree that a
// credential finding is not a live secret:
//
//   - InTest — where the value lives, derived from the file path.
//   - Placeholder — what the value looks like, derived from the bytes.
//
// Independence is the whole point. The two are produced by different inputs, so
// their agreement is genuine corroboration rather than one observation counted
// twice — the same standard the blocking gate applies, used here to weaken a
// claim instead of to strengthen one.
//
// ProviderAnchored VETOES it. The placeholder heuristics include a signal read
// off the variable NAME, and a name is chosen by whoever wrote the line: it
// records their intent, not the nature of the value. `TEST_STRIPE_KEY =
// "sk_live_…"` is a live key with a misleading label, and a label must never be
// allowed to push a provider-signed credential below WARN. A generic rule's
// match carries no such signature, which is exactly the case this de-escalation
// is for.
func fixtureCorroborated(ev evidence.Evidence) bool {
	return ev.InTest && ev.Placeholder && !ev.ProviderAnchored
}

// DecideWithOptions is the production entry point: decide() under the scan
// policy, plus the test-fixture de-escalation.
//
// The test-fixture rule (B3, extended by FIX-09) reads:
//
//   - BLOCK + no corroborating signal → WARN. 31 of the 35 catalogued false
//     positives in tasks/FP_CORPUS.md are test fixtures, and before FIX-09 the
//     rule only demoted WARN → INFO — so the project's single largest FP class
//     was structurally exempt from its own mitigation whenever a team set
//     --fail-on. A test-code finding with a surviving independent signal still
//     BLOCKs, which keeps this de-escalation evidence-aware rather than path
//     suppression (Rule 3).
//   - WARN + below --fail-on → INFO. The original v1.1 rule, unchanged.
//
// The arms are mutually exclusive by construction (a switch on the status
// decide() produced), so exactly ONE 0-point reason line is ever appended —
// TestDeescalationIsExplainedInTheScoreReasons locks that arithmetic.
//
// THE FLOOR: a finding whose severity met --fail-on is never reported below
// WARN. Without it, a threshold-crossing test-code finding could be demoted
// BLOCK → WARN here (or WARN by the confidence gate) and then demoted again
// WARN → INFO by the second arm, burying it at the same level as a
// below-threshold LOW. d.aboveThreshold is the guard.
//
// CALLER CONTRACT: the de-escalation keys off ev.InTest, which is
// Evidence-internal and therefore does NOT survive the Evidence→Finding
// projection. Callers downstream of that projection MUST run their input
// through evidence.ProvenanceIndex.Restore first; the orchestrator does this in
// stampDecisions. Deliberately there is no fall back to re-deriving the flag
// from ev.Endpoint here: for a deduplicated finding the primary endpoint is
// only one member of the group, so path-matching it directly would let a single
// test occurrence de-escalate a group that also contains production
// occurrences. The index's "agree or drop" fold is the only correct source.
func DecideWithOptions(ev evidence.Evidence, failOn string, opts Options) Decision {
	d := decide(ev, failOn, opts)
	applyApplicabilityGate(&d, ev, opts)
	if !opts.DeescalateTests || !ev.InTest {
		return settleOverride(d)
	}
	switch d.Status {
	case StatusBlock:
		// A finding in test code with an independent signal still gates the
		// build; the signal must establish something beyond the original
		// pattern match.
		//
		// RC-1: reads the INDEPENDENT class only. Not a behaviour change for
		// this arm — confidence.HasDeterministicDetection is gated on !InTest,
		// so the only self-evident signal reachable here is DirectObservation,
		// which no secrets/fixture producer sets. Keeping it on the independent
		// class is the conservative reading and matches the gate above.
		if len(d.Corroboration.Independent) == 0 {
			d.Status = StatusWarn
			d.Reason = "de-escalated to WARN: finding is in test/fixture code with no corroborating " +
				"signal beyond the pattern match (rule: test-fixture; evidence preserved; " +
				"--fail-on threshold was met)"
			appendDecisionReason(&d.Score, confidence.CodeDeescalatedTestFixtureThreshold, testFixtureBlockReason)
		}
	case StatusWarn:
		if !d.aboveThreshold {
			d.Status = StatusInfo
			d.Reason = "de-escalated to INFO: finding is in test/fixture code (rule: test-fixture; evidence preserved)"
			// Surface the de-escalation in the published breakdown too. Without
			// this the report shows a finding silently demoted to INFO with
			// nothing in confidence_reasons explaining why.
			appendDecisionReason(&d.Score, confidence.CodeDeescalatedTestFixture, testFixtureReason)
		}
	}

	// The fixture-corroborated exception to the WARN floor.
	//
	// Placed AFTER the switch, and gated on the resulting status rather than on
	// which arm produced it, because a fixture credential can arrive at WARN by
	// two different routes: the confidence gate demoting a threshold-crosser
	// whose band is LOW, or the test-fixture arm above holding a BLOCK. Both
	// describe the same finding, so both must reach the same verdict — keying
	// this off one arm would make the outcome depend on which demotion happened
	// to fire first, which is exactly the kind of order-dependence this package
	// works to avoid.
	//
	// The floor (see TestThresholdCrossingFindingNeverSinksBelowWarn) exists so
	// stacked demotions cannot bury a finding that crossed the team's --fail-on
	// threshold. That concern does not apply here: two INDEPENDENT deterministic
	// signals — the path the value sits on, and the bytes of the value itself —
	// agree the string is not a credential at all. Their agreement is
	// corroboration, applied in the de-escalating direction, which is the same
	// standard the blocking gate applies in the escalating one.
	//
	// Independent corroboration VETOES the drop, exactly as it does for the
	// BLOCK arm: if anything beyond the pattern match supports the claim, the
	// fixture signals are no longer the whole story.
	//
	// Nothing is suppressed. The finding keeps its id, intrinsic severity,
	// endpoint and full redacted evidence; only Status and Reason move, plus one
	// 0-point line in the published breakdown.
	if d.Status == StatusWarn && len(d.Corroboration.Independent) == 0 && fixtureCorroborated(ev) {
		d.Status = StatusInfo
		d.Reason = "de-escalated to INFO: credential is in test/fixture code AND its value " +
			"matches the deterministic fixture heuristics — two independent signals agree " +
			"it is not a live credential (rule: test-fixture-corroborated; evidence preserved)"
		appendDecisionReason(&d.Score, confidence.CodeDeescalatedTestFixtureCorroborated, testFixtureCorroboratedReason)
	}
	return settleOverride(d)
}

// settleOverride is the LAST word on PolicyOverride, and it exists because the
// flag was being set too early to stay true.
//
// decide() computes it in the relaxed BLOCK arm — correctly, at that moment.
// But applyApplicabilityGate and the test-fixture de-escalation both run
// afterwards and can move Status off BLOCK, and neither re-evaluated the flag.
// A relaxed run therefore exported WARN and INFO findings carrying
// policy_override=true, which breaks the single question the flag exists to
// answer: "which BLOCKs exist only because the evidence requirement was turned
// off?" Filtering on it returned findings that block nothing.
//
// So the flag is settled once, here, after every arm has had its say. This is
// NOT a re-derivation of the override decision — decide() still owns that, and
// this never turns the flag ON. It only withdraws a claim that a later
// demotion made untrue, which is why a genuine relaxed BLOCK is untouched.
//
// Status, severity and score are unaffected: a demotion already happened and
// is already explained in the reason breakdown. Only the stale claim clears.
func settleOverride(d Decision) Decision {
	if d.Status != StatusBlock {
		d.PolicyOverride = false
	}
	return d
}

// DecideAll maps a slice of evidence to decisions under one threshold, using
// the legacy zero-Options mapping (no confidence gate, no test-fixture
// de-escalation). See the package doc: this is the compatibility oracle, not
// the production path.
func DecideAll(evs []evidence.Evidence, failOn string) []Decision {
	return DecideAllWithOptions(evs, failOn, Options{})
}

// DecideAllWithOptions maps a slice of evidence to decisions under one
// threshold and one policy. This is the production entry point the
// orchestrator uses; DecideAll is the zero-Options convenience wrapper kept
// for callers that predate the policy.
func DecideAllWithOptions(evs []evidence.Evidence, failOn string, opts Options) []Decision {
	if evs == nil {
		return nil
	}
	out := make([]Decision, len(evs))
	for i, ev := range evs {
		out[i] = DecideWithOptions(ev, failOn, opts)
	}
	return out
}

// ExitCode reproduces checkFailOn's exit semantics from a set of decisions:
// 1 if any decision BLOCKs, else 0. orchestrator.Run returns this directly, so
// it is the process exit code — under the default policy a finding the
// confidence gate held at WARN no longer contributes a 1.
func ExitCode(decisions []Decision) int {
	for _, d := range decisions {
		if d.Status == StatusBlock {
			return 1
		}
	}
	return 0
}
