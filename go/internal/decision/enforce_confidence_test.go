package decision

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// FIX-08: --fail-on alone no longer decides the exit code. A finding at or
// above the threshold BLOCKs only when the deterministic confidence band
// supports the claim. These tests pin the rule table, the escape hatch, and the
// determinism of the corroboration list.
//
// Every band below is DERIVED from confidence.Score, never from
// models.Confidence — the two are different things and a row that sets only the
// enum proves nothing. The comment on each row shows the arithmetic so a future
// delta change makes the intent (not just the number) reviewable.

// enforced is the shipped policy; legacy is what --enforce-confidence=false
// restores. DeescalateTests is off in both so these rows isolate FIX-08.
var (
	enforced = Options{EnforceConfidence: true}
	legacy   = Options{}
)

// TestDecideEnforcedRuleTable is the FIX-08 rule table. Each row also asserts
// the SAME input under the legacy policy, so the flag is provably the only
// difference — a row that behaved identically in both modes would be testing
// nothing.
func TestDecideEnforcedRuleTable(t *testing.T) {
	cases := []struct {
		name        string
		ev          evidence.Evidence
		want        Status
		wantLegacy  Status
		reasonHas   string
		reasonExact string
	}{
		{
			// 35 base + 10 static + 10 runtime + 25 cross-engine = 80 → HIGH.
			// RC-1: the reason now NAMES what corroborated it rather than
			// asserting "confidence HIGH". Two engines agreeing is the signal;
			// the band is the arithmetic consequence, not the justification.
			name:       "HIGH band blocks and names its corroborator",
			ev:         evidence.Evidence{Severity: models.SeverityCritical, Source: models.SourceCorrelated},
			want:       StatusBlock,
			wantLegacy: StatusBlock,
			reasonHas:  "corroborated by: cross-engine agreement",
		},
		{
			// 35 + 10 static + 30 deterministic detection = 75 → HIGH.
			// This is the D1 row: a REAL hardcoded credential in production
			// code must still fail the build on a code-only scan.
			name: "production pattern match bands HIGH and blocks",
			ev: evidence.Evidence{
				Severity:   models.SeverityHigh,
				Source:     models.SourceWhitebox,
				Confidence: models.ConfidenceHigh,
			},
			want:       StatusBlock,
			wantLegacy: StatusBlock,
			reasonHas:  "deterministic detection in production code",
		},
		{
			// 35 + 10 static = 45 → MEDIUM, and nothing corroborates it.
			name:       "MEDIUM band with no corroborating signal warns",
			ev:         evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceWhitebox},
			want:       StatusWarn,
			wantLegacy: StatusBlock,
			reasonHas:  "needs corroboration to block",
		},
		{
			// 35 + 10 static + 10 reachable = 55 → MEDIUM, corroborated.
			name:       "MEDIUM band with a reachable taint path blocks",
			ev:         evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Reachable: true},
			want:       StatusBlock,
			wantLegacy: StatusBlock,
			reasonHas:  "corroborated by: reachable taint path",
		},
		{
			// 35 + 10 runtime = 45 → MEDIUM. THE RC-1 ROW, inverted from what
			// it asserted before. A bare blackbox finding used to supply its
			// own corroborator ("live runtime observation", true for every
			// Source=blackbox), so any scanner-assigned CRITICAL blocked the
			// build on nothing but a severity constant. It now warns.
			//
			// This does NOT destroy the active-scan gate: an active probe that
			// elicited a confirming response earns "payload-validated probe"
			// (see the row below), and a deterministic response read earns the
			// self-evident signal. What is gone is gating on the mere fact that
			// a DAST scanner ran.
			name:       "MEDIUM band blackbox no longer blocks on source alone",
			ev:         evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceBlackbox},
			want:       StatusWarn,
			wantLegacy: StatusBlock,
			reasonHas:  "nothing corroborates the claim",
		},
		{
			// 35 + 10 runtime + 10 payload-validated = 55 → MEDIUM, and the
			// probe differential is INDEPENDENT, so the active-scan gate holds
			// for a probe that actually confirmed something.
			name: "MEDIUM band blackbox blocks on a payload-validated probe",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh,
				Source:   models.SourceBlackbox,
				Payload:  "' OR 1=1--",
				Response: "SQL syntax error near ''",
			},
			want:       StatusBlock,
			wantLegacy: StatusBlock,
			reasonHas:  "corroborated by: payload-validated probe",
		},
		{
			// 35 + 10 runtime - 15 4xx context = 30 → LOW.
			name: "LOW band never blocks",
			ev: evidence.Evidence{
				Severity:        models.SeverityHigh,
				Source:          models.SourceBlackbox,
				ResponseContext: "4xx",
			},
			want:        StatusWarn,
			wantLegacy:  StatusBlock,
			reasonExact: "severity above threshold but confidence LOW — needs corroboration to block",
		},
		{
			// 35 base only (no source) → LOW.
			name:        "sourceless evidence bands LOW and warns",
			ev:          evidence.Evidence{Severity: models.SeverityHigh},
			want:        StatusWarn,
			wantLegacy:  StatusBlock,
			reasonExact: "severity above threshold but confidence LOW — needs corroboration to block",
		},
		{
			// 35 + 10 static = 45 → MEDIUM. InTest gates the deterministic
			// detection delta off, so the fixture match cannot band HIGH.
			name: "test-code pattern match stays MEDIUM and uncorroborated",
			ev: evidence.Evidence{
				Severity:   models.SeverityHigh,
				Source:     models.SourceWhitebox,
				Confidence: models.ConfidenceHigh,
				InTest:     true,
			},
			want:       StatusWarn,
			wantLegacy: StatusBlock,
			reasonHas:  "needs corroboration to block",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideWithOptions(tc.ev, "HIGH", enforced)
			if got.Status != tc.want {
				t.Errorf("Status = %q, want %q (score %d, band %s, reason %q)",
					got.Status, tc.want, got.Score.Value, got.Score.Band, got.Reason)
			}
			if tc.reasonExact != "" && got.Reason != tc.reasonExact {
				t.Errorf("Reason = %q, want exactly %q", got.Reason, tc.reasonExact)
			}
			if tc.reasonHas != "" && !strings.Contains(got.Reason, tc.reasonHas) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tc.reasonHas)
			}
			if legacyGot := DecideWithOptions(tc.ev, "HIGH", legacy).Status; legacyGot != tc.wantLegacy {
				t.Errorf("legacy policy Status = %q, want %q — the flag must be the only difference",
					legacyGot, tc.wantLegacy)
			}
			// Rule 3: enforcement moved, nothing else. The score is the
			// evidence's, not the gate's.
			if got.Score.Value != DecideWithOptions(tc.ev, "HIGH", legacy).Score.Value {
				t.Errorf("the confidence gate changed the SCORE; it may only change STATUS")
			}
		})
	}
}

// TestEnforcedDecisionsNameTheSignalsThatJustifiedTheBlock is the
// explainability half of the DoD: a BLOCK must say what corroborated it, so a
// reader can tell a HIGH-band claim from a MEDIUM-band-plus-one-signal claim.
func TestEnforcedDecisionsNameTheSignalsThatJustifiedTheBlock(t *testing.T) {
	ev := evidence.Evidence{
		Severity:       models.SeverityCritical,
		Source:         models.SourceCorrelated,
		RouteConfirmed: true,
		Reachable:      true,
		ProvenPath:     true,
	}
	d := DecideWithOptions(ev, "HIGH", enforced)
	if d.Status != StatusBlock {
		t.Fatalf("Status = %q, want BLOCK", d.Status)
	}
	// RC-1: "live runtime observation" is no longer among them — it named the
	// scanner, not the evidence.
	for _, want := range []string{
		"cross-engine agreement",
		"confirmed route", "reachable taint path", "proven path",
	} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("BLOCK reason does not name %q: %q", want, d.Reason)
		}
	}
	if strings.Contains(d.Reason, "live runtime observation") {
		t.Errorf("BLOCK reason still names the removed tautological signal: %q", d.Reason)
	}
}

// TestEnforceConfidenceOffIsByteForByteLegacy is the escape-hatch contract:
// with the flag off, every Status, Reason and exit code is what the pre-FIX-08
// severity-only mapping produced — including for evidence carrying the new
// signals, which must be ignored entirely in this mode.
func TestEnforceConfidenceOffIsByteForByteLegacy(t *testing.T) {
	off := Options{EnforceConfidence: false, DeescalateTests: false}

	// The exit-code cross-product, against the independent legacy oracle.
	for _, set := range sevSets() {
		for _, fo := range failOns {
			evs := make([]evidence.Evidence, len(set))
			for i, sev := range set {
				evs[i] = ev(sev)
			}
			got := ExitCode(DecideAllWithOptions(evs, fo, off))
			if want := legacyCheckFailOn(set, fo); got != want {
				t.Errorf("set=%v failOn=%q: ExitCode=%d, legacy checkFailOn=%d", set, fo, got, want)
			}
		}
	}

	// Per-decision Status AND Reason identity, over evidence that varies every
	// field the new gate reads. Decide() is the frozen legacy implementation,
	// so it is the oracle.
	variants := []evidence.Evidence{
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox},
		{Severity: models.SeverityHigh, Source: models.SourceBlackbox},
		{Severity: models.SeverityHigh, Source: models.SourceCorrelated},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Reachable: true},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, RouteConfirmed: true},
		{Severity: models.SeverityHigh, Source: models.SourceWhitebox, UnconfirmedByLiveScan: true},
		{Severity: models.SeverityHigh, Source: models.SourceBlackbox, ResponseContext: "4xx"},
		{Severity: models.SeverityCritical, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh},
		{Severity: models.SeverityMedium, Source: models.SourceWhitebox},
		{Severity: models.SeverityLow, Source: models.SourceWhitebox},
	}
	for _, fo := range failOns {
		for _, v := range variants {
			want := Decide(v, fo)
			got := DecideWithOptions(v, fo, off)
			if got.Status != want.Status || got.Reason != want.Reason {
				t.Errorf("failOn=%q ev=%+v: got %q/%q, want the legacy %q/%q",
					fo, v, got.Status, got.Reason, want.Status, want.Reason)
			}
			if len(got.Score.Reasons) != len(want.Score.Reasons) {
				t.Errorf("failOn=%q ev=%+v: the disabled gate still appended a reason line: %v",
					fo, v, got.Score.Reasons)
			}
		}
	}
}

// TestUnconfirmedEvidenceNeverBlocksUnderDefaultPolicy is FIX-08 item 3: the
// correlator's "[Unconfirmed by live scan]" claim and a BLOCK verdict on the
// same finding are contradictory, and the contradiction is what the marker
// exists to stop. The arm is band-independent — CRITICAL severity does not lift
// it — but it IS corroboration-dependent, so this is de-escalation, not
// suppression.
func TestUnconfirmedEvidenceNeverBlocksUnderDefaultPolicy(t *testing.T) {
	// Shaped like what correlator.correlateWithMarks actually emits: the
	// unconfirmed branch forces Confidence to MEDIUM.
	unconfirmed := evidence.Evidence{
		Title:                 "SQL injection",
		Category:              "injection",
		Endpoint:              "/api/v1/orders",
		Severity:              models.SeverityCritical,
		Source:                models.SourceWhitebox,
		Confidence:            models.ConfidenceMedium,
		Evidence:              "cursor.execute(...) [Unconfirmed by live scan]",
		UnconfirmedByLiveScan: true,
	}

	d := DecideWithOptions(unconfirmed, "CRITICAL", enforced)
	if d.Status != StatusWarn {
		t.Errorf("unconfirmed finding Status = %q, want WARN (score %d, band %s)",
			d.Status, d.Score.Value, d.Score.Band)
	}
	if !strings.Contains(d.Reason, "unconfirmed by live scan") {
		t.Errorf("reason should name the unconfirmed marker: %q", d.Reason)
	}
	if d.Evidence.Evidence == "" {
		t.Error("evidence text was dropped; the marker de-escalates, it never suppresses (Rule 3)")
	}

	// Corroborated: the live scan not matching it no longer stands alone.
	corroborated := unconfirmed
	corroborated.Reachable = true
	if got := DecideWithOptions(corroborated, "CRITICAL", enforced); got.Status != StatusBlock {
		t.Errorf("corroborated unconfirmed finding Status = %q, want BLOCK", got.Status)
	}

	// Escape hatch: the legacy mapping ignores the marker entirely.
	if got := DecideWithOptions(unconfirmed, "CRITICAL", legacy); got.Status != StatusBlock {
		t.Errorf("with --enforce-confidence=false Status = %q, want the legacy BLOCK", got.Status)
	}
}

// TestCorroborationsAreDeterministicAndOrdered is the Rule 8 lock. The list is
// joined into Decision.Reason, which is published as part of the decision
// output and compared verbatim by the order-independence tests in
// internal/engine — so any map or set in here would surface as flaky output.
func TestCorroborationsAreDeterministicAndOrdered(t *testing.T) {
	full := evidence.Evidence{
		Severity:       models.SeverityHigh,
		Source:         models.SourceCorrelated,
		Confidence:     models.ConfidenceHigh,
		RouteConfirmed: true,
		Reachable:      true,
		ProvenPath:     true,
		Payload:        "' OR 1=1--",
		Response:       "500 Internal Server Error",

		DirectObservation: true,
	}
	// RC-1: "live runtime observation" is gone — it restated Source and made
	// every blackbox finding corroborate itself. The remaining signals are
	// partitioned: independent (a second observation that could have
	// disagreed) vs self-evident (the claim IS the observation).
	wantIndependent := []string{
		"cross-engine agreement",
		"confirmed route",
		"reachable taint path",
		"proven path",
		"payload-validated probe",
	}
	wantSelfEvident := []string{
		"direct observation of a live response",
		"deterministic detection in production code",
	}
	got := corroborate(full)
	if strings.Join(got.Independent, "|") != strings.Join(wantIndependent, "|") {
		t.Errorf("Independent = %v, want %v", got.Independent, wantIndependent)
	}
	if strings.Join(got.SelfEvident, "|") != strings.Join(wantSelfEvident, "|") {
		t.Errorf("SelfEvident = %v, want %v", got.SelfEvident, wantSelfEvident)
	}
	for i := 0; i < 1000; i++ {
		c := corroborate(full)
		if strings.Join(c.Independent, "|") != strings.Join(wantIndependent, "|") ||
			strings.Join(c.SelfEvident, "|") != strings.Join(wantSelfEvident, "|") {
			t.Fatalf("corroborate is not deterministic (iteration %d): %+v", i, c)
		}
	}
	none := corroborate(evidence.Evidence{Severity: models.SeverityHigh})
	if none.Independent != nil || none.SelfEvident != nil {
		t.Errorf("corroborate with no signals = %+v, want both nil so len()==0 is the single predicate", none)
	}
	if none.Any() {
		t.Error("Any() = true with no signals")
	}
}

// TestObservationConceptsAreClassified supersedes the DECISIONS.md D7 lock.
//
// D7 held that decision's wide Source-keyed predicate ("live runtime
// observation") and the narrow evidence.DirectObservation field were two
// DIFFERENT corroborating signals and that both must count. RC-1 overturns the
// first half: the wide predicate was a restatement of Source, so it corroborated
// nothing and made every blackbox finding self-corroborating. The narrow field
// survives — reclassified as SELF-EVIDENT, because a deterministic read of a
// response is the claim itself, not a second observation of it.
func TestObservationConceptsAreClassified(t *testing.T) {
	// The narrow field (a header/cookie/CORS read) is self-evident, not independent.
	direct := evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceBlackbox, DirectObservation: true}
	c := corroborate(direct)
	if !contains(c.SelfEvident, "direct observation of a live response") {
		t.Error("evidence.DirectObservation is not classified as a self-evident signal")
	}
	if len(c.Independent) != 0 {
		t.Errorf("Independent = %v, want empty — a deterministic read confirms nothing beyond itself", c.Independent)
	}

	// The static mirror is likewise self-evident.
	det := evidence.Evidence{Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh}
	if !contains(corroborate(det).SelfEvident, "deterministic detection in production code") {
		t.Error("the deterministic-detection signal is not classified as self-evident")
	}
}

// TestActiveProbeNeedsAResponseToCorroborate pins the contract Task 2 of the
// decision-integrity plan implements.
//
// An active probe that only records what it SENT has produced no differential:
// "we sent a payload" is not evidence. The pair (Payload, Response) is — the
// target answered the way the check predicted. This mirrors
// confidence.payloadValidated exactly.
func TestActiveProbeNeedsAResponseToCorroborate(t *testing.T) {
	sentOnly := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceBlackbox, Payload: "' OR 1=1--",
	}
	if len(corroborate(sentOnly).Independent) != 0 {
		t.Error("a probe that recorded only its payload corroborated something; it has no differential")
	}

	confirmed := sentOnly
	confirmed.Response = "SQL syntax error near ''"
	if !contains(corroborate(confirmed).Independent, "payload-validated probe") {
		t.Error("a probe whose payload elicited a confirming response is not independently corroborated")
	}
}

// TestActiveProbeScannersCanStillGateABuild is the COVERAGE half of RC-1.
//
// Removing "live runtime observation" is only safe because the honest
// replacement — payload-validated probe — is real. Before Task 2 it was not:
// every `Payload:` site in internal/scanner populated a ProbeRecord (the audit
// log), never an ev.Evidence, so production findings carried NEITHER Payload
// nor Response and payloadValidated was doubly dead.
//
// This asserts the shape a confirmed active probe emits NOW. If a scanner
// regresses to recording only what it sent, this goes red and the active-scan
// gate is gone — which is exactly what it is here to catch.
func TestActiveProbeScannersCanStillGateABuild(t *testing.T) {
	probe := evidence.Evidence{
		Title: "SQL Injection (MySQL, error-based)", Category: "injection", Endpoint: "GET /search",
		Severity: models.SeverityHigh, Source: models.SourceBlackbox,
		Confidence: models.ConfidenceHigh,
		Payload:    "' OR 1=1--",
		Response:   "You have an error in your SQL syntax near '''",
	}
	d := DecideWithOptions(probe, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — a confirmed active probe must gate (score %d, band %s, reason %q)",
			d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
	if !contains(corroborate(probe).Independent, "payload-validated probe") {
		t.Error("a confirmed active probe is not independently corroborated")
	}

	// The same probe WITHOUT a recorded response is not a differential and
	// must not gate. This is the pre-Task-2 production shape.
	sentOnly := probe
	sentOnly.Response = ""
	if got := DecideWithOptions(sentOnly, "HIGH", Options{EnforceConfidence: true}); got.Status == StatusBlock {
		t.Error("a probe that recorded only what it sent gated a build; it confirmed nothing")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestTestFixtureBlockDemotionRequiresNoCorroboration is FIX-09 item 1: the
// demotion is conditional on the absence of corroboration, which is what makes
// it a de-escalation rather than a path-based exemption (Rule 3 forbids the
// latter outright).
func TestTestFixtureBlockDemotionRequiresNoCorroboration(t *testing.T) {
	ev := evidence.Evidence{
		Title:      "Hardcoded API key or token",
		Category:   "secrets",
		Endpoint:   "app/tests/test_client.py:12",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
		Evidence:   `api_key = "sk-live-abc..."`,
		InTest:     true,
	}
	on := Options{DeescalateTests: true}
	off := Options{DeescalateTests: false}

	held := DecideWithOptions(ev, "HIGH", on)
	if held.Status != StatusWarn {
		t.Errorf("Status = %q, want WARN", held.Status)
	}
	if !strings.Contains(held.Reason, "test/fixture code") || !strings.Contains(held.Reason, "corroborating") {
		t.Errorf("reason must name the rule and the missing corroboration: %q", held.Reason)
	}
	if held.Evidence.Evidence == "" {
		t.Error("evidence text was dropped (Rule 3)")
	}

	plain := DecideWithOptions(ev, "HIGH", off)
	if plain.Status != StatusBlock {
		t.Errorf("with --deescalate-tests=false Status = %q, want BLOCK", plain.Status)
	}
	if held.Score.Value != plain.Score.Value {
		t.Errorf("the de-escalation changed the SCORE (%d → %d); it must only change STATUS",
			plain.Score.Value, held.Score.Value)
	}
	if len(held.Score.Reasons) != len(plain.Score.Reasons)+1 {
		t.Errorf("expected exactly one extra reason line, got %d vs %d",
			len(held.Score.Reasons), len(plain.Score.Reasons))
	}
	last := held.Score.Reasons[len(held.Score.Reasons)-1]
	if !strings.HasPrefix(last, "+0 ") {
		t.Errorf("the de-escalation line must carry an explicit +0 delta so reasons still\n"+
			"reconcile with the score: %q", last)
	}

	// An independently supported credential finding in a fixture can still be
	// a leak. Reachable stands in for "some signal beyond the pattern match"
	// here; provider-shaped syntax alone is not live validation.
	corroborated := ev
	corroborated.Reachable = true
	if got := DecideWithOptions(corroborated, "HIGH", on); got.Status != StatusBlock {
		t.Errorf("corroborated test-code finding Status = %q, want BLOCK", got.Status)
	}
}

// TestThresholdCrossingFindingNeverSinksBelowWarn locks the floor. Two
// independent demotions now exist (the confidence gate and the test-fixture
// rule), and letting them cascade would bury a finding that DID cross the
// team's --fail-on threshold at the same level as a below-threshold LOW.
//
// ONE EXCEPTION, added deliberately and tested separately below: a credential
// that is BOTH in test code AND fixture-shaped may reach INFO. The floor exists
// to stop a REAL finding being buried by stacked demotions; that concern does
// not apply when two independent deterministic signals — the path it lives on
// and the bytes of the value — agree the string is not a credential at all. The
// exception is bounded by ProviderAnchored, so anything carrying a provider's
// own token signature keeps the floor no matter how it is named.
//
// The fixture below therefore sets Placeholder WITHOUT InTest for the floor
// cases, so it still exercises the stacked-demotion cascade the floor guards.
func TestThresholdCrossingFindingNeverSinksBelowWarn(t *testing.T) {
	// Placeholder alone: 35 base + 10 static - 20 placeholder = 25 → LOW band,
	// so the confidence gate demotes it. The worst case for the cascade that
	// does NOT meet the fixture-corroborated exception.
	//
	// ProviderAnchored keeps the fixture-corroborated exception vetoed, so both
	// demotions (confidence gate AND test-fixture) still stack exactly as they
	// did before the exception existed — which is what the floor is here to
	// catch. A misleadingly-named live provider key is also the case where the
	// floor matters most.
	ev := evidence.Evidence{
		Title:            "Stripe live secret key hardcoded",
		Category:         "secrets",
		Endpoint:         "app/tests/test_client.py:12",
		Severity:         models.SeverityHigh,
		Source:           models.SourceWhitebox,
		Confidence:       models.ConfidenceHigh,
		InTest:           true,
		Placeholder:      true,
		ProviderAnchored: true,
	}
	for _, enforce := range []bool{true, false} {
		for _, deescalate := range []bool{true, false} {
			opts := Options{EnforceConfidence: enforce, DeescalateTests: deescalate}
			d := DecideWithOptions(ev, "HIGH", opts)
			if d.Status == StatusInfo {
				t.Errorf("enforce=%v deescalate=%v: a finding at or above --fail-on was reported INFO",
					enforce, deescalate)
			}
			if d.Status != StatusBlock && d.Status != StatusWarn {
				t.Errorf("enforce=%v deescalate=%v: unexpected Status %q", enforce, deescalate, d.Status)
			}
		}
	}

	// Below the threshold the original WARN → INFO rule is untouched.
	below := ev
	below.Severity = models.SeverityMedium
	if d := DecideWithOptions(below, "HIGH", Options{EnforceConfidence: true, DeescalateTests: true}); d.Status != StatusInfo {
		t.Errorf("below-threshold test finding Status = %q, want INFO (the v1.1 rule must still fire)", d.Status)
	}
}

// --- the fixture-corroborated exception to the WARN floor ----------------
//
// A credential that is BOTH in test code AND fixture-shaped carries two
// INDEPENDENT deterministic signals that it is not a live secret: the path it
// sits on, and the bytes of the value. Their agreement is corroboration used to
// weaken a claim, which is the same standard the blocking gate applies to
// strengthen one.

func fixtureSecret() evidence.Evidence {
	return evidence.Evidence{
		Title:       "Hardcoded API key or token",
		Category:    "secrets",
		Endpoint:    "app/tests/test_client.py:12",
		Severity:    models.SeverityHigh,
		Source:      models.SourceWhitebox,
		Confidence:  models.ConfidenceHigh,
		InTest:      true,
		Placeholder: true,
	}
}

func TestFixtureCorroboratedCredentialReachesInfo(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	d := DecideWithOptions(fixtureSecret(), "HIGH", opts)

	if d.Status != StatusInfo {
		t.Fatalf("a fixture-shaped credential in test code should reach INFO, got %q (%s)",
			d.Status, d.Reason)
	}
	// The drop must be explained in BOTH places a reader might look.
	if !strings.Contains(d.Reason, "two independent signals") {
		t.Errorf("the decision reason must name the two signals: %q", d.Reason)
	}
	var found bool
	for _, r := range d.Score.Reasons {
		if strings.Contains(r, "test-fixture-corroborated") {
			found = true
			if !strings.HasPrefix(r, "+0 ") {
				t.Errorf("the de-escalation must carry an explicit +0 delta: %q", r)
			}
		}
	}
	if !found {
		t.Errorf("the confidence breakdown must record the de-escalation: %v", d.Score.Reasons)
	}
}

// The veto. A provider's own token signature is evidence about the VALUE; a
// variable name is evidence about its author's intent. `TEST_STRIPE_KEY =
// "sk_live_..."` is a live key with a misleading label and must keep its floor.
func TestProviderAnchoredCredentialKeepsTheWarnFloor(t *testing.T) {
	ev := fixtureSecret()
	ev.ProviderAnchored = true

	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	d := DecideWithOptions(ev, "HIGH", opts)

	if d.Status == StatusInfo {
		t.Fatalf("a provider-anchored credential must not be de-escalated to INFO by its NAME (%s)", d.Reason)
	}
	if d.Status != StatusWarn {
		t.Errorf("expected the existing WARN floor, got %q", d.Status)
	}
}

// Each signal ALONE is an observation, not corroboration. Neither may reach
// INFO on its own, or the exception would be one signal wearing two hats.
func TestOneTestContextSignalIsNotEnoughForInfo(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	pathOnly := fixtureSecret()
	pathOnly.Placeholder = false // in tests, but the value looks real
	if d := DecideWithOptions(pathOnly, "HIGH", opts); d.Status == StatusInfo {
		t.Errorf("a real-looking credential in a test file must not reach INFO: %s", d.Reason)
	}

	valueOnly := fixtureSecret()
	valueOnly.InTest = false // fixture-shaped, but in production code
	valueOnly.Endpoint = "app/settings.py:12"
	if d := DecideWithOptions(valueOnly, "HIGH", opts); d.Status == StatusInfo {
		t.Errorf("a fixture-shaped value in production code must not reach INFO: %s", d.Reason)
	}
}

// Independent corroboration vetoes the drop. Once something beyond the pattern
// match supports the claim, the two fixture signals are no longer the whole
// story, so the finding keeps the WARN floor.
//
// It stays WARN rather than returning to BLOCK because a fixture-shaped value
// scores in the LOW band (35 base + 10 static + 10 reachable - 20 placeholder =
// 35), and a LOW-band finding never blocks — that is the confidence gate's rule,
// not this de-escalation's, and it is asserted here so the interaction between
// the two is pinned rather than assumed.
func TestCorroboratedFixtureCredentialDoesNotSinkToInfo(t *testing.T) {
	ev := fixtureSecret()
	ev.Reachable = true // any independent signal

	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	d := DecideWithOptions(ev, "HIGH", opts)
	if d.Status == StatusInfo {
		t.Errorf("independent corroboration must veto the fixture de-escalation: %s", d.Reason)
	}
	if d.Status != StatusWarn {
		t.Errorf("expected the WARN floor, got %q (%s)", d.Status, d.Reason)
	}
}

// Nothing is deleted to achieve the drop — the whole point of preferring
// de-escalation over suppression.
func TestFixtureDeescalationPreservesTheEvidence(t *testing.T) {
	ev := fixtureSecret()
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	d := DecideWithOptions(ev, "HIGH", opts)

	if d.Evidence.Title != ev.Title || d.Evidence.Category != ev.Category {
		t.Error("the finding's identity fields must survive de-escalation")
	}
	if d.Evidence.Severity != models.SeverityHigh {
		t.Errorf("intrinsic severity must not be rewritten by a decision: %s", d.Evidence.Severity)
	}
	plain := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Score.Value != plain.Score.Value {
		t.Errorf("the de-escalation changed the SCORE (%d → %d); it must only change STATUS",
			plain.Score.Value, d.Score.Value)
	}
}
