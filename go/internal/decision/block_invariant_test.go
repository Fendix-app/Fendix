package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// blockCapableCategories is every category that can currently reach CRITICAL or
// HIGH severity, i.e. every category that can meet a --fail-on threshold.
//
// Deliberately an explicit list rather than something derived: adding a category
// to the engine must be a conscious decision to bring it under this invariant,
// not something that happens silently.
var blockCapableCategories = []string{
	"auth_bypass", "auth", "injection", "secrets", "cors", "deps",
	"idor", "xss", "ssrf", "rate_limiting", "headers", "cookie", "iac",
	"redirect", "graphql", "exposure", "configleak",
}

// THE INVARIANT. No evidence may reach BLOCK without at least one corroborating
// signal, and no MEDIUM-band evidence may reach BLOCK without an INDEPENDENT
// one. Severity alone — which is a constant chosen by the scanner — must never
// be sufficient.
//
// This is the property the whole decision-integrity change exists to establish,
// so it is asserted across the full cross product rather than on hand-picked
// shapes. Any failure here is a real hole in the policy, not a test to relax.
func TestNoBlockWithoutCorroboration(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh,
		models.SeverityMedium, models.SeverityLow, models.SeverityInfo,
	}
	sources := []models.Source{
		models.SourceBlackbox, models.SourceWhitebox,
		models.SourceCorrelated, models.SourceImported,
	}
	confidences := []models.Confidence{
		models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow,
	}
	tiers := []models.SourceTier{
		"", models.TierNativeGo, models.TierTreeSitter, models.TierSemgrepShim,
	}
	failOns := []string{"", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	checked := 0
	for _, cat := range blockCapableCategories {
		for _, sev := range severities {
			for _, src := range sources {
				for _, conf := range confidences {
					for _, tier := range tiers {
						for _, failOn := range failOns {
							ev := evidence.Evidence{
								Title:      "synthetic " + cat,
								Category:   cat,
								Severity:   sev,
								Source:     src,
								Confidence: conf,
								SourceTier: tier,
								Endpoint:   "GET /synthetic",
							}
							d := DecideWithOptions(ev, failOn, opts)
							checked++
							if d.Status != StatusBlock {
								continue
							}
							if !d.Corroboration.Any() {
								t.Errorf("BLOCK with NO corroborating signal at all: "+
									"category=%s severity=%s source=%s confidence=%s tier=%q failOn=%s "+
									"score=%d band=%s reason=%q",
									cat, sev, src, conf, tier, failOn,
									d.Score.Value, d.Score.Band, d.Reason)
							}
							if d.Score.Band == models.ConfidenceMedium &&
								len(d.Corroboration.Independent) == 0 {
								t.Errorf("MEDIUM-band BLOCK with no INDEPENDENT signal: "+
									"category=%s severity=%s source=%s confidence=%s tier=%q failOn=%s "+
									"score=%d self_evident=%v reason=%q",
									cat, sev, src, conf, tier, failOn,
									d.Score.Value, d.Corroboration.SelfEvident, d.Reason)
							}
						}
					}
				}
			}
		}
	}
	t.Logf("checked %d evidence shapes", checked)
}

// The converse guard. A gate nobody can trip is not a fix, it is a removal —
// so at least one realistic shape per confirmation mechanism must still BLOCK.
// If Task 1's narrowing had gone too far, this is what would have caught it.
func TestConfirmedFindingsStillBlock(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	cases := map[string]evidence.Evidence{
		"reachable taint path": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter, Reachable: true,
		},
		"cross-engine agreement": {
			Category: "secrets", Severity: models.SeverityHigh, Source: models.SourceCorrelated,
			Confidence: models.ConfidenceHigh,
		},
		"contradicted auth requirement": {
			Category: "auth_bypass", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, AuthExpectation: models.AuthExpectationRequired,
		},
		"payload-validated probe": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh,
			Payload:    "' OR 1=1--", Response: "You have an error in your SQL syntax",
		},
		"cross-tool corroboration": {
			Category: "injection", Severity: models.SeverityHigh, Source: models.SourceImported,
			Confidence:            models.ConfidenceHigh,
			CrossToolCorroborated: true, CorroboratingTools: []string{"codeql"},
		},
		// The code-only-scan case deterministicDetn exists for: a REAL
		// hardcoded credential in production source, where no second
		// observation is possible even in principle.
		"deterministic detection in production source": {
			Category: "secrets", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierNativeGo,
		},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			ev.Title, ev.Endpoint = name, "GET /x"
			d := DecideWithOptions(ev, "HIGH", opts)
			if d.Status != StatusBlock {
				t.Errorf("Status = %q, want BLOCK (score=%d band=%s independent=%v self_evident=%v reason=%q)",
					d.Status, d.Score.Value, d.Score.Band,
					d.Corroboration.Independent, d.Corroboration.SelfEvident, d.Reason)
			}
		})
	}
}

// Every BLOCK must be EXPLAINABLE: the reason must name what corroborated it,
// so the exported justification is never an empty assertion.
func TestEveryBlockNamesItsCorroboration(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	shapes := []evidence.Evidence{
		{Category: "injection", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Confidence: models.ConfidenceHigh, SourceTier: models.TierTreeSitter, Reachable: true},
		{Category: "auth_bypass", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, AuthExpectation: models.AuthExpectationRequired},
		{Category: "cors", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Confidence: models.ConfidenceHigh, DirectObservation: true},
	}
	for _, ev := range shapes {
		ev.Title, ev.Endpoint = "shape "+ev.Category, "GET /x"
		d := DecideWithOptions(ev, "HIGH", opts)
		if d.Status != StatusBlock {
			continue
		}
		if d.Reason == "" {
			t.Errorf("%s: BLOCK with an empty reason", ev.Category)
		}
		if !d.Corroboration.Any() {
			t.Errorf("%s: BLOCK whose reason cites nothing", ev.Category)
		}
	}
}

// Determinism: the same evidence must always yield the same verdict, reason,
// score and signal lists. A map iteration or a time-dependent rule anywhere in
// this path would surface here.
func TestDecisionIsDeterministic(t *testing.T) {
	ev := evidence.Evidence{
		Title: "determinism probe", Category: "injection", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		SourceTier: models.TierTreeSitter, Reachable: true, ProvenPath: true,
		RouteConfirmed: true, Endpoint: "app/x.py:1",
	}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	first := DecideWithOptions(ev, "HIGH", opts)
	for i := 0; i < 200; i++ {
		got := DecideWithOptions(ev, "HIGH", opts)
		if got.Status != first.Status || got.Reason != first.Reason ||
			got.Score.Value != first.Score.Value || got.Score.Band != first.Score.Band {
			t.Fatalf("iteration %d diverged on verdict:\n got=%+v\nwant=%+v", i, got, first)
		}
		if len(got.Corroboration.Independent) != len(first.Corroboration.Independent) ||
			len(got.Corroboration.SelfEvident) != len(first.Corroboration.SelfEvident) {
			t.Fatalf("iteration %d diverged on signals: %+v vs %+v",
				i, got.Corroboration, first.Corroboration)
		}
		for j := range got.Corroboration.Independent {
			if got.Corroboration.Independent[j] != first.Corroboration.Independent[j] {
				t.Fatalf("iteration %d: signal order changed at %d", i, j)
			}
		}
	}
}

// The escape hatch must remain byte-for-byte legacy: with EnforceConfidence
// off, corroboration is ignored entirely and severity alone decides. Teams
// pinned to the old policy must be able to keep it.
func TestLegacyPolicyIgnoresCorroborationEntirely(t *testing.T) {
	bare := evidence.Evidence{
		Title: "bare blackbox", Category: "auth_bypass", Endpoint: "GET /status",
		Severity: models.SeverityCritical, Source: models.SourceBlackbox,
		Confidence: models.ConfidenceMedium,
	}
	if got := DecideWithOptions(bare, "HIGH", Options{EnforceConfidence: true}); got.Status != StatusWarn {
		t.Errorf("shipped policy Status = %q, want WARN", got.Status)
	}
	if got := DecideWithOptions(bare, "HIGH", Options{}); got.Status != StatusBlock {
		t.Errorf("legacy policy Status = %q, want BLOCK — --enforce-confidence=false must restore it", got.Status)
	}
}

// ── Extended dimensions: applicability and policy override ──────────────────
//
// The base matrix above predates both. Each adds a dimension along which a
// BLOCK can now be produced or withheld, so each needs its own invariant or the
// property test would silently stop covering the whole decision surface.

// No dependency finding may BLOCK under the shipped policy when Fendix has
// credible evidence its vulnerable component is unused — at ANY band, from ANY
// source, at ANY severity. This is the §5 case generalised: the previous
// behaviour produced the right answer only where the band boundary happened to
// fall.
func TestNoDependencyBlockAgainstNonApplicabilityEvidence(t *testing.T) {
	severities := []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium}
	sources := []models.Source{
		models.SourceBlackbox, models.SourceWhitebox,
		models.SourceCorrelated, models.SourceImported,
	}
	confidences := []models.Confidence{models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow}
	opts := Options{EnforceConfidence: true, DeescalateTests: true}

	checked := 0
	for _, sev := range severities {
		for _, src := range sources {
			for _, conf := range confidences {
				for _, corroborated := range []bool{false, true} {
					for _, failOn := range []string{"MEDIUM", "HIGH", "CRITICAL"} {
						ev := evidence.Evidence{
							Title:    "Vulnerable dependency: pkg==1.0.0 (CVE-0000-0000)",
							Category: "deps", Endpoint: "requirements.txt",
							Severity: sev, Source: src, Confidence: conf,
							Applicability: models.ApplicabilityEvidenceAgainst,
						}
						if corroborated {
							ev.CrossToolCorroborated = true
							ev.CorroboratingTools = []string{"osv-scanner"}
						}
						d := DecideWithOptions(ev, failOn, opts)
						checked++
						if d.Status == StatusBlock {
							t.Errorf("dependency BLOCK against non-applicability evidence: "+
								"severity=%s source=%s confidence=%s corroborated=%v failOn=%s "+
								"score=%d band=%s reason=%q",
								sev, src, conf, corroborated, failOn,
								d.Score.Value, d.Score.Band, d.Reason)
						}
					}
				}
			}
		}
	}
	t.Logf("checked %d dependency shapes carrying non-applicability evidence", checked)
}

// UNKNOWN IS NOT FALSE. A dependency whose applicability was never evaluated
// must follow normal policy — the absence of an evaluation is not evidence that
// the component is unused, and treating it as such would silence real risk on
// every advisory the catalog does not cover.
func TestUnknownApplicabilityIsNotTreatedAsEvidenceAgainst(t *testing.T) {
	opts := Options{EnforceConfidence: true, DeescalateTests: true}
	unknown := evidence.Evidence{
		Title: "Vulnerable dependency: pkg==1.0.0", Category: "deps",
		Endpoint: "requirements.txt", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
	}
	against := unknown
	against.Applicability = models.ApplicabilityEvidenceAgainst

	du := DecideWithOptions(unknown, "HIGH", opts)
	da := DecideWithOptions(against, "HIGH", opts)
	if du.Status == da.Status {
		t.Errorf("unevaluated and evidence-against produced the SAME verdict (%s) — the two "+
			"states are not distinguished by the policy", du.Status)
	}
	if du.Status != StatusBlock {
		t.Errorf("unevaluated applicability Status = %q, want BLOCK (normal policy)", du.Status)
	}
}

// EXPLICIT NEGATIVE IS NOT UNKNOWN. Applicable (the component IS imported) must
// behave differently from Unknown too — otherwise the positive verdict the old
// bool could not express would still be doing nothing.
func TestApplicableIsDistinguishableFromUnknown(t *testing.T) {
	for _, a := range []models.Applicability{
		models.ApplicabilityUnknown,
		models.ApplicabilityApplicable,
		models.ApplicabilityEvidenceAgainst,
	} {
		ev := evidence.Evidence{
			Title: "Vulnerable dependency: pkg==1.0.0", Category: "deps",
			Endpoint: "requirements.txt", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
			Applicability: a,
		}
		d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true, DeescalateTests: true})
		want := StatusBlock
		if a == models.ApplicabilityEvidenceAgainst {
			want = StatusWarn
		}
		if d.Status != want {
			t.Errorf("applicability=%q Status = %q, want %q (reason=%q)", a, d.Status, want, d.Reason)
		}
	}
}

// EVERY relaxed-policy BLOCK that the shipped policy would have withheld must
// carry the override marker. Swept across the same matrix, because an override
// that is invisible for one category is invisible where it matters.
func TestEveryRelaxedOnlyBlockIsMarkedAsAnOverride(t *testing.T) {
	severities := []models.Severity{models.SeverityCritical, models.SeverityHigh}
	sources := []models.Source{models.SourceBlackbox, models.SourceWhitebox, models.SourceImported}
	confidences := []models.Confidence{models.ConfidenceHigh, models.ConfidenceMedium, models.ConfidenceLow}

	relaxed := Options{DeescalateTests: true}
	shipped := Options{EnforceConfidence: true, DeescalateTests: true}

	checked, overrides := 0, 0
	for _, cat := range blockCapableCategories {
		for _, sev := range severities {
			for _, src := range sources {
				for _, conf := range confidences {
					ev := evidence.Evidence{
						Title: "synthetic " + cat, Category: cat, Endpoint: "GET /x",
						Severity: sev, Source: src, Confidence: conf,
					}
					dr := DecideWithOptions(ev, "HIGH", relaxed)
					ds := DecideWithOptions(ev, "HIGH", shipped)
					checked++
					if dr.Status != StatusBlock {
						continue
					}
					if ds.Status != StatusBlock && !dr.PolicyOverride {
						t.Errorf("relaxed-only BLOCK is NOT marked as an override: "+
							"category=%s severity=%s source=%s confidence=%s (shipped=%s)",
							cat, sev, src, conf, ds.Status)
					}
					if ds.Status == StatusBlock && dr.PolicyOverride {
						t.Errorf("BLOCK marked as an override although the shipped policy "+
							"would also have blocked: category=%s severity=%s source=%s confidence=%s",
							cat, sev, src, conf)
					}
					if dr.PolicyOverride {
						overrides++
					}
				}
			}
		}
	}
	t.Logf("checked %d shapes under both policies; %d were relaxed-only BLOCKs", checked, overrides)
	if overrides == 0 {
		t.Error("no relaxed-only BLOCK was produced at all — the override marker is untested")
	}
}
