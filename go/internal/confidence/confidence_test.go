package confidence

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestScoreDeterministic(t *testing.T) {
	ev := evidence.Evidence{Source: models.SourceCorrelated, Reachable: true, RouteConfirmed: true}
	a := Score(ev)
	b := Score(ev)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Score is not deterministic:\n a=%+v\n b=%+v", a, b)
	}
}

func TestScoreBlackboxOnlyIsModest(t *testing.T) {
	// A blackbox-only finding that is NOT a direct observation — an inference
	// about policy strength (Weak-CSP), or a read the scanner itself cannot
	// disambiguate (SameSite): base(35) + runtime(10) = 45 → MEDIUM. Findings
	// that ARE deterministic reads earn directObservation on top and reach the
	// HIGH band.
	got := Score(evidence.Evidence{Source: models.SourceBlackbox})
	if got.Value != base+runtimeEvidence {
		t.Errorf("blackbox-only Value = %d, want %d", got.Value, base+runtimeEvidence)
	}
	if got.Band != models.ConfidenceMedium {
		t.Errorf("blackbox-only Band = %q, want MEDIUM", got.Band)
	}
}

func TestScoreCorrelatedProvenPathIsHigh(t *testing.T) {
	ev := evidence.Evidence{
		Source:         models.SourceCorrelated,
		RouteConfirmed: true,
		Reachable:      true,
		ProvenPath:     true,
		SourceTier:     models.TierTreeSitter,
		Payload:        "id=1' OR '1'='1",
		Response:       "HTTP 500 SQL syntax error",
	}
	got := Score(ev)
	// 35+10+10+25+10+10+5+10+5 = 120, clamped to 100.
	if got.Value != 100 {
		t.Errorf("fully-corroborated Value = %d, want 100 (clamped)", got.Value)
	}
	if got.Band != models.ConfidenceHigh {
		t.Errorf("Band = %q, want HIGH", got.Band)
	}
	joined := strings.Join(got.Reasons, "\n")
	for _, want := range []string{"cross-engine agreement", "reachable", "live request", "active probe"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reasons missing %q:\n%s", want, joined)
		}
	}
}

func TestSemgrepTierPenalty(t *testing.T) {
	withTier := Score(evidence.Evidence{Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim})
	noTier := Score(evidence.Evidence{Source: models.SourceWhitebox})
	if withTier.Value != noTier.Value+tierSemgrepPenalty {
		t.Errorf("semgrep penalty not applied: withTier=%d noTier=%d", withTier.Value, noTier.Value)
	}
	if !strings.Contains(strings.Join(withTier.Reasons, "\n"), "lower-trust") {
		t.Error("semgrep penalty reason missing")
	}
}

func TestBandThresholds(t *testing.T) {
	cases := []struct {
		score int
		want  models.Confidence
	}{
		{100, models.ConfidenceHigh},
		{70, models.ConfidenceHigh},
		{69, models.ConfidenceMedium},
		{40, models.ConfidenceMedium},
		{39, models.ConfidenceLow},
		{0, models.ConfidenceLow},
	}
	for _, c := range cases {
		if got := bandFor(c.score); got != c.want {
			t.Errorf("bandFor(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestEveryRuleAddsAReason(t *testing.T) {
	// A reason line per contribution + the base line. The "no black boxes"
	// contract: the score must be fully accounted for by the reasons.
	got := Score(evidence.Evidence{Source: models.SourceCorrelated, Reachable: true})
	if len(got.Reasons) < 4 { // base + static + runtime + cross + reachable
		t.Errorf("expected a reason per contribution, got %d: %v", len(got.Reasons), got.Reasons)
	}
	if !strings.HasPrefix(got.Reasons[0], "+35 base") {
		t.Errorf("first reason should be the base: %q", got.Reasons[0])
	}
}

func TestLineageTrace(t *testing.T) {
	ev := evidence.Evidence{
		Source: models.SourceCorrelated,
		Lineage: []evidence.Evidence{
			{Source: models.SourceBlackbox, Category: "injection"},
			{Source: models.SourceWhitebox, Category: "injection"},
		},
	}
	got := Score(ev)
	joined := strings.Join(got.Reasons, "\n")
	if !strings.Contains(joined, "evidence chain") || !strings.Contains(joined, "blackbox(injection)") {
		t.Errorf("lineage trace missing from reasons:\n%s", joined)
	}
}

func TestClamp(t *testing.T) {
	if clamp(-5, 0, 100) != 0 || clamp(150, 0, 100) != 100 || clamp(50, 0, 100) != 50 {
		t.Error("clamp boundaries wrong")
	}
}

func BenchmarkScore(b *testing.B) {
	ev := evidence.Evidence{Source: models.SourceCorrelated, Reachable: true, RouteConfirmed: true, ProvenPath: true, SourceTier: models.TierTreeSitter}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Score(ev)
	}
}

// TestReasonsSumToValue is the "no black boxes" contract: the signed deltas in
// Reasons must reconstruct Value exactly, including the corroboration cap.
func TestReasonsSumToValue(t *testing.T) {
	cases := []evidence.Evidence{
		{Source: models.SourceBlackbox},
		{Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim},
		{Source: models.SourceCorrelated, RouteConfirmed: true, Reachable: true, ProvenPath: true, SourceTier: models.TierTreeSitter, Payload: "p", Response: "r"},
		// The B4 de-escalation deltas are negative — the sum must still land
		// exactly on Value.
		{Source: models.SourceBlackbox, ResponseContext: "4xx"},
		{Source: models.SourceBlackbox, Payload: "p", Response: "r", ResponseContext: "static-asset",
			Lineage: []evidence.Evidence{{Source: models.SourceBlackbox, Category: "headers"}}},
		// A direct observation, on its own and with the B4 penalty on top.
		{Source: models.SourceBlackbox, DirectObservation: true},
		{Source: models.SourceBlackbox, DirectObservation: true, ResponseContext: "4xx"},
		// The placeholder de-escalation is negative and must reconcile too.
		{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, Placeholder: true},
		// So must the dep-applicability one, which stacks on top of the
		// deterministic-detection bonus rather than cancelling it.
		{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, Category: "deps", ComponentNotImported: true},
	}
	for _, ev := range cases {
		r := Score(ev)
		sum := 0
		for _, reason := range r.Reasons {
			var n int
			// each reason starts with a signed int like "+35 ..." / "-20 ..."
			if _, err := fmt.Sscanf(reason, "%d", &n); err == nil {
				sum += n
			}
		}
		if sum != r.Value {
			t.Errorf("reasons sum %d != Value %d for %+v\n%v", sum, r.Value, ev, r.Reasons)
		}
	}
}

// TestScore4xxContextPenalty / TestScoreStaticAssetPenalty are the B4 gates:
// a DAST finding that fired on a 4xx (auth-gated/client-error) response or a
// static-asset endpoint gets a confidence PENALTY (de-escalation, evidence
// preserved) rather than emit-time suppression.
func TestScore4xxContextPenalty(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceBlackbox}
	ctx4xx := evidence.Evidence{Source: models.SourceBlackbox, ResponseContext: "4xx"}
	if Score(ctx4xx).Value >= Score(base).Value {
		t.Errorf("4xx context should lower confidence: base=%d 4xx=%d",
			Score(base).Value, Score(ctx4xx).Value)
	}
	found := false
	for _, r := range Score(ctx4xx).Reasons {
		if strings.Contains(r, "4xx") {
			found = true
		}
	}
	if !found {
		t.Error("expected a 4xx-context reason line")
	}
}

// provenanceFixture is one Evidence shape the two drift guards below share,
// with its score pinned so a silent retune of the rule deltas cannot slip past.
type provenanceFixture struct {
	name      string
	ev        evidence.Evidence
	wantValue int
}

// provenanceDriftFixtures must, BETWEEN THEM, populate every field of
// evidence.ScoringProvenance — TestScoringProvenanceCoversEveryScoredField
// enforces exactly that. Adding a field to Evidence + ScoringProvenance and
// forgetting to exercise it here is the hole that left payload-validated,
// ResponseContext and lineage dead in production with a green suite.
func provenanceDriftFixtures() []provenanceFixture {
	return []provenanceFixture{
		{
			// A DAST header finding on a static asset whose credential-shaped
			// value looked like a fixture: exercises Payload, Response,
			// ResponseContext, Lineage, DirectObservation and Placeholder in
			// one shot.
			name: "blackbox direct observation, fixture-shaped, on a static asset",
			ev: evidence.Evidence{
				Title:    "Missing Content-Security-Policy header",
				Category: "headers",
				Endpoint: "GET /assets/app.js",
				Severity: models.SeverityMedium,
				Source:   models.SourceBlackbox,
				// every Evidence-internal field the scorer reads:
				Payload:           "GET /assets/app.js",
				Response:          "HTTP/1.1 200 OK",
				ResponseContext:   "static-asset",
				Lineage:           []evidence.Evidence{{Source: models.SourceBlackbox, Category: "headers"}},
				DirectObservation: true,
				Placeholder:       true,
			},
			// 35 base + 10 runtime + 10 payload + 30 direct - 20 placeholder
			// - 15 context.
			wantValue: base + runtimeEvidence + payloadValidated + directObservation +
				placeholderPenalty + httpContextPenalty,
		},
		{
			// A SAST finding whose producer marked it as test code even though
			// the ENDPOINT is a production path — so models.IsTestPath cannot
			// re-derive the flag and the round trip depends on
			// ScoringProvenance.InTest alone. UnconfirmedByLiveScan rides along
			// here: the confidence scorer does not read it (it is a
			// decision-layer signal, guarded by
			// decision.TestDecisionProvenanceSurvivesTheFindingProjection), but
			// it still has to be CARRIED, and the coverage guard below is what
			// says so.
			name: "whitebox pattern match its producer marked as test code",
			ev: evidence.Evidence{
				Title:                 "Hardcoded API key or token",
				Category:              "secrets",
				Endpoint:              "src/app.py:42",
				Severity:              models.SeverityHigh,
				Source:                models.SourceWhitebox,
				Confidence:            models.ConfidenceHigh,
				InTest:                true,
				UnconfirmedByLiveScan: true,
			},
			// 35 base + 10 static.
			wantValue: base + staticEvidence,
		},
		{
			// A provider-signed credential (an sk_live_… match) sitting in a
			// test file under a misleading TEST_ name. ProviderAnchored is a
			// decision-layer signal the scorer does not read — it VETOES the
			// fixture de-escalation in decision.fixtureCorroborated — but like
			// InTest and AuthExpectation it is unobservable downstream of the
			// projection, so it has to be CARRIED. This fixture is what the
			// coverage guard below reads to prove the hop exists.
			//
			// Placeholder is set alongside it deliberately: the veto only means
			// anything when the fixture heuristics DID fire, which is exactly
			// the `TEST_STRIPE_KEY = "sk_live_…"` shape.
			name: "provider-anchored credential in test code under a fixture-shaped name",
			ev: evidence.Evidence{
				Title:            "Stripe live secret key hardcoded",
				Category:         "secrets",
				Endpoint:         "tests/test_billing.py:12",
				Severity:         models.SeverityCritical,
				Source:           models.SourceWhitebox,
				Confidence:       models.ConfidenceHigh,
				InTest:           true,
				Placeholder:      true,
				ProviderAnchored: true,
			},
			// 35 base + 10 static - 20 placeholder. InTest gates the
			// deterministic-detection bonus off; ProviderAnchored carries no
			// score delta of its own by design.
			wantValue: base + staticEvidence + placeholderPenalty,
		},
		{
			// A live auth finding on an endpoint the OpenAPI spec declares
			// protected. AuthExpectation / AuthExpectationSource are stamped by
			// the auth check from the spec-derived endpoint inventory and are
			// unobservable downstream of the projection — nothing on a
			// models.Finding can reconstruct "the spec required auth here".
			//
			// The scorer does not read them (they are decision-layer signals,
			// like UnconfirmedByLiveScan above), but they must be CARRIED, and
			// the coverage guard below is what enforces that. If they were
			// dropped, the decision layer's "contradicted authentication
			// requirement" arm would be dead on every real scan while its unit
			// tests stayed green — the exact failure mode this fixture set
			// exists to prevent.
			name: "live auth finding on a spec-declared protected endpoint",
			ev: evidence.Evidence{
				Title:                 "Authentication requirement bypassed",
				Category:              "auth_bypass",
				Endpoint:              "GET /api/users",
				Severity:              models.SeverityCritical,
				Source:                models.SourceBlackbox,
				Confidence:            models.ConfidenceHigh,
				AuthExpectation:       models.AuthExpectationRequired,
				AuthExpectationSource: "openapi",
			},
			// 35 base + 10 runtime. The auth-expectation fields carry no
			// confidence delta — they change the DECISION, not the score.
			wantValue: base + runtimeEvidence,
		},
		{
			// A dependency finding whose advisory is scoped to an importable
			// sub-component the scanned tree never imports. It gets its own
			// fixture rather than riding on one of the above because the flag
			// is meaningless outside the deps category, and because this is
			// the shape whose SURVIVAL matters: the fact is observed by the
			// scanner walking the source tree, and nothing downstream of the
			// projection can re-observe it.
			name: "dependency advisory whose affected component is never imported",
			ev: evidence.Evidence{
				Title:                "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
				Category:             "deps",
				Endpoint:             "requirements.txt",
				Severity:             models.SeverityHigh,
				Source:               models.SourceWhitebox,
				Confidence:           models.ConfidenceHigh,
				ComponentNotImported: true,
				// The three-state verdict that supersedes the bool. Both are set
				// here because the scanner keeps them in lockstep for one
				// release, and BOTH must survive the projection: the bool feeds
				// the scorer's -10 delta, the enum feeds the decision layer's
				// applicability gate.
				Applicability: models.ApplicabilityEvidenceAgainst,
			},
			// 35 base + 10 static + 30 deterministic detection - 10 component.
			wantValue: base + staticEvidence + deterministicDetn + componentNotImported,
		},
		{
			// A SARIF-imported finding that CorrelateCrossTool strongly
			// corroborated (an independent tool reported the same normalized
			// CWE at the same location). CrossToolCorroborated and
			// CorroboratingTools are stamped BEFORE the Finding projection
			// and are observable by nothing downstream of it — the exact
			// shape whose survival ScoringProvenance exists to guarantee. If
			// they were dropped, the decision layer's cross-tool
			// corroboration arm would be dead on every real scan while its
			// unit tests stayed green.
			name: "imported finding with strong cross-tool corroboration",
			ev: evidence.Evidence{
				Title:                 "SQL Injection",
				Category:              "injection",
				Endpoint:              "app/views.py:102",
				Severity:              models.SeverityHigh,
				Source:                models.SourceImported,
				Confidence:            models.ConfidenceMedium,
				CrossToolCorroborated: true,
				CorroboratingTools:    []string{"fendix"},
			},
			// 35 base + 10 imported + 15 cross-tool corroboration.
			wantValue: base + importedEvidence + crossToolCorroborated,
		},
	}
}

// TestScoringProvenanceSurvivesTheFindingProjection is the DRIFT GUARD for the
// wiring fix. Score is a pure function of Evidence, but the orchestrator can
// only hand it Evidence rebuilt from the projected models.Finding — a lossy
// shape — plus whatever evidence.ProvenanceIndex carries across that boundary.
//
// So: score the real Evidence, then score the same Evidence after a
// project → restore round trip, and require an identical Result. Every rule
// that reads an Evidence-internal field is covered by construction. Add a new
// scored internal field to evidence.Evidence without adding it to
// ScoringProvenance and this test goes red — which is exactly how the
// payload-validated / HTTP-context / lineage rules became dead code.
func TestScoringProvenanceSurvivesTheFindingProjection(t *testing.T) {
	for _, fx := range provenanceDriftFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			want := Score(fx.ev)
			// Pinned so the guard fails loudly if the deltas are retuned
			// without revisiting this contract.
			if want.Value != fx.wantValue {
				t.Fatalf("unexpected baseline Value %d, want %d — retune this fixture with the rule deltas",
					want.Value, fx.wantValue)
			}

			ix := evidence.NewProvenanceIndex([]evidence.Evidence{fx.ev})
			restored := ix.Restore(evidence.FromFindings(evidence.ToFindings([]evidence.Evidence{fx.ev})))
			got := Score(restored[0])

			if !reflect.DeepEqual(got, want) {
				t.Errorf("score differs across the Finding projection — an Evidence-internal\n"+
					"field the scorer reads is missing from evidence.ScoringProvenance.\n got=%+v\nwant=%+v", got, want)
			}
		})
	}
}

// TestScoringProvenanceCoversEveryScoredField is the guard that
// evidence/provenance.go's INVARIANT comment has always named — and which,
// until now, existed nowhere in the repo, so the invariant it promised was
// never actually enforced.
//
// The round-trip guard above is only as good as its fixtures: a field that no
// fixture sets is never exercised, so a new internal field can be added to
// Evidence AND to ScoringProvenance, be dropped by NewProvenanceIndex, and
// still leave the suite green. This one reflects over ScoringProvenance and
// requires every field to be non-zero on at least one fixture, which turns
// "someone remembered" into "the build says so".
//
// A field the scorer does not read (UnconfirmedByLiveScan today) still has to
// appear: the point is that the next author consciously decides where it is
// covered rather than discovering later that it was nowhere.
func TestScoringProvenanceCoversEveryScoredField(t *testing.T) {
	fixtures := provenanceDriftFixtures()
	pt := reflect.TypeOf(evidence.ScoringProvenance{})
	for i := 0; i < pt.NumField(); i++ {
		name := pt.Field(i).Name
		covered := false
		for _, fx := range fixtures {
			fv := reflect.ValueOf(fx.ev).FieldByName(name)
			if !fv.IsValid() {
				t.Fatalf("evidence.ScoringProvenance.%s has no same-named field on evidence.Evidence —\n"+
					"the two must stay name-for-name so Restore can be a mechanical copy", name)
			}
			if !fv.IsZero() {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("evidence.ScoringProvenance.%s is not exercised by any fixture in\n"+
				"provenanceDriftFixtures — add it to one, or the projection guard cannot\n"+
				"see whether the field survives the round trip", name)
		}
	}
}

func TestScoreStaticAssetPenalty(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceBlackbox}
	stat := evidence.Evidence{Source: models.SourceBlackbox, ResponseContext: "static-asset"}
	if Score(stat).Value >= Score(base).Value {
		t.Errorf("static-asset context should lower confidence: base=%d static=%d",
			Score(base).Value, Score(stat).Value)
	}
}

// TestDirectObservationReachesTheHighBand is the FIX-07 headline. Before it, a
// single-engine DAST finding was arithmetically stuck in MEDIUM: the ceiling
// was 35 base + 10 runtime = 45 (payloadValidated cannot fire — nothing in the
// module produces Evidence.Response), bandHigh is 70, and headers/cookie/cors
// are outside engine.categoryMap so correlation can never lift them either.
// "Confirmed" was therefore a synonym for "correlated", and a scan with no code
// path could not produce one.
func TestDirectObservationReachesTheHighBand(t *testing.T) {
	got := Score(evidence.Evidence{Source: models.SourceBlackbox, DirectObservation: true})

	if want := base + runtimeEvidence + directObservation; got.Value != want {
		t.Errorf("direct-observation Value = %d, want %d", got.Value, want)
	}
	if got.Band != models.ConfidenceHigh {
		t.Errorf("Band = %q, want HIGH — a deterministic read of a live response must be able\n"+
			"to reach HIGH without correlation", got.Band)
	}
	// Margin, not just membership: at +25 the score would land on exactly 70,
	// and any later negative delta would de-band every header/cookie/cors
	// finding in one step (DECISIONS.md D5).
	if got.Value <= bandHigh {
		t.Errorf("Value = %d sits on the bandHigh boundary (%d) with no margin", got.Value, bandHigh)
	}
	if !strings.Contains(strings.Join(got.Reasons, "\n"), "direct observation") {
		t.Errorf("no direct-observation reason line: %v", got.Reasons)
	}
}

// TestDirectObservationRequiresRuntimeEvidence guards the hasRuntime gate. The
// bonus is a claim about reading a live RESPONSE, so a static emitter must not
// be able to claim it — and internal/engine's payload-validation wiring test
// pins an exact score that depends on this gate holding.
func TestDirectObservationRequiresRuntimeEvidence(t *testing.T) {
	got := Score(evidence.Evidence{Source: models.SourceWhitebox, DirectObservation: true})
	if want := base + staticEvidence; got.Value != want {
		t.Errorf("whitebox DirectObservation Value = %d, want %d — the bonus is DAST-only",
			got.Value, want)
	}
	if strings.Contains(strings.Join(got.Reasons, "\n"), "direct observation") {
		t.Errorf("a static finding claimed the direct-observation bonus: %v", got.Reasons)
	}
}

// TestDeterministicDetectionLetsAProductionPatternMatchBandHigh is the SAST
// mirror, and the reason a code-only scan of real hardcoded credentials still
// fails a build once band membership gates enforcement (DECISIONS.md D1). A
// secrets finding is Source=whitebox with no SourceTier, so without this delta
// it scores 35 + 10 = 45 forever — MEDIUM, with no corroborator available on a
// scan that has no live target.
func TestDeterministicDetectionLetsAProductionPatternMatchBandHigh(t *testing.T) {
	secret := evidence.Evidence{
		Title:      "Hardcoded API key or token",
		Category:   "secrets",
		Endpoint:   "src/config.py:9",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
	}

	got := Score(secret)
	if want := base + staticEvidence + deterministicDetn; got.Value != want {
		t.Errorf("production secrets Value = %d, want %d", got.Value, want)
	}
	if got.Band != models.ConfidenceHigh {
		t.Errorf("Band = %q, want HIGH — a real credential in production code must be able to\n"+
			"band HIGH on a code-only scan", got.Band)
	}
	if !strings.Contains(strings.Join(got.Reasons, "\n"), "deterministic detection") {
		t.Errorf("no deterministic-detection reason line: %v", got.Reasons)
	}

	// Every conjunct of the predicate must be able to withhold the delta on its
	// own — each is load-bearing for a different false-positive class.
	demotions := []struct {
		name string
		mut  func(*evidence.Evidence)
	}{
		{"test/fixture code (FP_CORPUS P1: 31 of 35 catalogued instances)", func(e *evidence.Evidence) { e.InTest = true }},
		{"fixture-shaped credential value", func(e *evidence.Evidence) { e.Placeholder = true }},
		{"semgrep-shim tier (breadth before precision)", func(e *evidence.Evidence) { e.SourceTier = models.TierSemgrepShim }},
		{"the analyzer did not assert HIGH confidence", func(e *evidence.Evidence) { e.Confidence = models.ConfidenceMedium }},
		{"blackbox source (the DAST mirror is directObservation)", func(e *evidence.Evidence) { e.Source = models.SourceBlackbox }},
	}
	for _, d := range demotions {
		t.Run(d.name, func(t *testing.T) {
			ev := secret
			d.mut(&ev)
			r := Score(ev)
			if strings.Contains(strings.Join(r.Reasons, "\n"), "deterministic detection") {
				t.Errorf("the delta still fired: %v", r.Reasons)
			}
			if r.Band == models.ConfidenceHigh {
				t.Errorf("Band = HIGH (%d); this shape must not band HIGH on its own", r.Value)
			}
		})
	}
}

// TestFixtureShapedCredentialLandsInLow pins the FIX-09 end state the
// deterministic-detection gate exists to make reachable: a placeholder value
// must fall clear of MEDIUM, not merely one notch inside it. Sitting in MEDIUM
// would leave it one corroborating signal away from blocking a build.
func TestFixtureShapedCredentialLandsInLow(t *testing.T) {
	got := Score(evidence.Evidence{
		Title:       "Hardcoded API key or token",
		Category:    "secrets",
		Endpoint:    "src/config.py:9",
		Source:      models.SourceWhitebox,
		Confidence:  models.ConfidenceHigh,
		Placeholder: true,
	})
	if want := base + staticEvidence + placeholderPenalty; got.Value != want {
		t.Errorf("placeholder Value = %d, want %d", got.Value, want)
	}
	if got.Band != models.ConfidenceLow {
		t.Errorf("Band = %q, want LOW", got.Band)
	}
}

// TestScoreComponentNotImportedPenalty is the FIX-14 gate. A dependency
// finding whose advisory only touches a sub-component the scanned tree never
// imports is REAL — the vulnerable package is installed — but its reachable
// surface is smaller, so it should not gate a build at the same weight as one
// on a code path the project actually uses.
//
// Rule 3 is the whole shape of this: the finding is de-escalated, never
// dropped. Detection, id, severity, endpoint and evidence text all stay; only
// the score moves.
func TestScoreComponentNotImportedPenalty(t *testing.T) {
	dep := evidence.Evidence{
		Title:      "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category:   "deps",
		Endpoint:   "requirements.txt",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
	}
	full := Score(dep)

	notImported := dep
	notImported.ComponentNotImported = true
	got := Score(notImported)

	if got.Value >= full.Value {
		t.Errorf("Value = %d; want strictly below the un-annotated %d", got.Value, full.Value)
	}
	if want := full.Value + componentNotImported; got.Value != want {
		t.Errorf("Value = %d; want %d (exactly one delta applied)", got.Value, want)
	}
	if !strings.Contains(strings.Join(got.Reasons, "\n"),
		"the advisory's affected component is not imported by the scanned code") {
		t.Errorf("no component-not-imported reason line: %v", got.Reasons)
	}
	// The observable effect is the band flip: a dependency finding is
	// whitebox + ConfidenceHigh with no analyzer tier, so it earns
	// deterministicDetn and sits at 75 = HIGH. The penalty moves it to 65 =
	// MEDIUM, where --fail-on's band gate no longer treats it as
	// self-corroborating.
	if full.Band != models.ConfidenceHigh {
		t.Fatalf("baseline dep band = %q (%d); this test's premise is that it starts HIGH",
			full.Band, full.Value)
	}
	if got.Band != models.ConfidenceMedium {
		t.Errorf("Band = %q (%d); want MEDIUM", got.Band, got.Value)
	}
	// De-escalation, not suppression: the delta must NOT withhold the
	// deterministic-detection bonus the way Placeholder does. The dependency
	// really is installed and really is vulnerable.
	if !strings.Contains(strings.Join(got.Reasons, "\n"), "deterministic detection") {
		t.Errorf("the component penalty suppressed the detection bonus; it should only subtract: %v", got.Reasons)
	}
}

// TestFPCorpusBandCalibration is the FP-corpus recalibration, expressed as a Go
// table because the benchmark labels cannot carry it: benchmark.MatchFinding
// splits an endpoint on its last ":" and returns false without one, and a DAST
// endpoint is "GET /admin" — no colon — so every header/cookie/cors finding
// buckets as Unknown there. The class names below are the
// benchmark.FPClass constants the taxonomy in BENCHMARKS.md §5 promises.
//
// Note on the 4xx row: tasks/FP_CORPUS.md's P2 instances are all 404s on
// /.env.local, and headers.go / cors.go / cookie_flags.go now skip 404/410/5xx
// outright, while httpResponseContext only tags 401/403/405/406/429. The
// residual 4xx class is auth-gated responses, so that is what is calibrated
// here rather than the file's 2026-05-11 table.
func TestFPCorpusBandCalibration(t *testing.T) {
	cases := []struct {
		name      string
		fpClass   string // benchmark.FPClass, or "" for a confirmed-TP class
		ev        evidence.Evidence
		wantValue int
		wantBand  models.Confidence
	}{
		{
			name:      "confirmed TP: missing X-Content-Type-Options on a live API route",
			fpClass:   "", // FP_CORPUS P4 — tracked as a known-mostly-TP class
			ev:        evidence.Evidence{Source: models.SourceBlackbox, DirectObservation: true},
			wantValue: base + runtimeEvidence + directObservation,
			wantBand:  models.ConfidenceHigh,
		},
		{
			name:      "known FP: the same read on an auth-gated response",
			fpClass:   "http-4xx-context", // benchmark.FPHTTP4xxContext
			ev:        evidence.Evidence{Source: models.SourceBlackbox, DirectObservation: true, ResponseContext: "4xx"},
			wantValue: base + runtimeEvidence + directObservation + httpContextPenalty,
			wantBand:  models.ConfidenceMedium,
		},
		{
			name:      "known FP: the same read on a CDN-served static asset",
			fpClass:   "static-asset-context", // benchmark.FPStaticAssetCtx
			ev:        evidence.Evidence{Source: models.SourceBlackbox, DirectObservation: true, ResponseContext: "static-asset"},
			wantValue: base + runtimeEvidence + directObservation + httpContextPenalty,
			wantBand:  models.ConfidenceMedium,
		},
		{
			name:      "unchanged: a DAST finding that is an inference, not a read (Weak-CSP / SameSite)",
			fpClass:   "",
			ev:        evidence.Evidence{Source: models.SourceBlackbox},
			wantValue: base + runtimeEvidence,
			wantBand:  models.ConfidenceMedium,
		},
		{
			name:      "unchanged: an inference-shaped DAST finding on a 4xx",
			fpClass:   "http-4xx-context",
			ev:        evidence.Evidence{Source: models.SourceBlackbox, ResponseContext: "4xx"},
			wantValue: base + runtimeEvidence + httpContextPenalty,
			wantBand:  models.ConfidenceLow,
		},
		{
			name:    "known FP: a secrets match in test/fixture code",
			fpClass: "test-fixture", // benchmark.FPTestFixture — FP_CORPUS P1, 31 of 35
			ev: evidence.Evidence{
				Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, InTest: true,
			},
			wantValue: base + staticEvidence,
			wantBand:  models.ConfidenceMedium,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Score(c.ev)
			if got.Value != c.wantValue {
				t.Errorf("Value = %d, want %d (fp_class %q)", got.Value, c.wantValue, c.fpClass)
			}
			if got.Band != c.wantBand {
				t.Errorf("Band = %q, want %q (fp_class %q)", got.Band, c.wantBand, c.fpClass)
			}
			// The FP rows carry the load: a known-FP class reaching HIGH is the
			// regression this calibration exists to catch.
			if c.fpClass != "" && got.Band == models.ConfidenceHigh {
				t.Errorf("known-FP class %q banded HIGH at %d — de-escalation failed", c.fpClass, got.Value)
			}
		})
	}
}
