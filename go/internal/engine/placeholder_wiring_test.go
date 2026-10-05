package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// This is the wiring gate for Evidence.Placeholder, and it is deliberately
// built the awkward way.
//
// CorrelateEvidence is `FromFindings(Correlate(ToFindings(evs)))` — a round
// trip that ZEROES every Evidence-internal field — followed by an explicit
// allow-list restore. InTest survives being absent from that list only because
// NewProvenanceIndex re-derives it from the endpoint via models.IsTestPath.
// Placeholder has no such derivation: it is known only to its producer, so a
// missed hop is permanent and silent. The orchestrator runs correlation ONLY
// when hasWhitebox && hasBlackbox (orchestrator.go:539) and builds the
// provenance index AFTER it, so a code-only `--code` scan looks perfectly
// healthy while adding a `--target` destroys the flag.
//
// Hence: drive the REAL secrets scanner (hand-setting the flag would pass even
// with the producer broken), and push the result through the HYBRID order
// rather than through `finalize`, which skips CorrelateEvidence entirely.
//
// The two fixture credentials carry DIFFERENT titles on purpose. Deduplicate
// groups on Severity|Category|Title, so two findings sharing a title collapse
// into one group whose provenance is the agreementOrBool merge — which folds a
// placeholder and a non-placeholder to false, correctly but uselessly for this
// test.
func secretsEvidenceFor(t *testing.T) (fixture, real evidence.Evidence) {
	t.Helper()
	dir := t.TempDir()
	body := `FAKE_API_KEY = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"` + "\n" +
		`GITHUB_TOKEN = "ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	evs, err := secrets.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("secrets.Scan: %v", err)
	}
	var gotFixture, gotReal *evidence.Evidence
	for i := range evs {
		switch {
		case strings.HasSuffix(evs[i].Endpoint, "cfg.py:1"):
			gotFixture = &evs[i]
		case strings.HasSuffix(evs[i].Endpoint, "cfg.py:2"):
			gotReal = &evs[i]
		}
	}
	if gotFixture == nil || gotReal == nil {
		t.Fatalf("test premise broken: expected a finding on each line; got %d findings", len(evs))
	}
	if !gotFixture.Placeholder {
		t.Fatal("test premise broken: the producer did not classify line 1 as a placeholder")
	}
	if gotReal.Placeholder {
		t.Fatal("test premise broken: the producer classified line 2 as a placeholder")
	}
	return *gotFixture, *gotReal
}

// assertPlaceholderDeescalation is the shared verdict: the fixture-shaped
// credential is still reported, lands in a strictly lower confidence band than
// its real-shaped twin, publishes the penalty as a signed reason line, and
// both findings still reconcile reasons-to-score.
//
// It asserts on the BAND and on the presence of the -20 line rather than on an
// exact score gap. The observable gap is wider than the penalty itself —
// HasDeterministicDetection excludes a placeholder, so the fixture also
// forfeits the deterministic-detection bonus — and pinning that arithmetic here
// would couple this test to another delta's value.
func assertPlaceholderDeescalation(t *testing.T, fixtureF, realF models.Finding) {
	t.Helper()

	if realF.ConfidenceBand != string(models.ConfidenceHigh) {
		t.Errorf("real-shaped credential band = %q; want HIGH (score %d, %v)",
			realF.ConfidenceBand, realF.ConfidenceScore, realF.ConfidenceReasons)
	}
	if fixtureF.ConfidenceBand != string(models.ConfidenceLow) {
		t.Errorf("fixture-shaped credential band = %q; want LOW (score %d, %v)",
			fixtureF.ConfidenceBand, fixtureF.ConfidenceScore, fixtureF.ConfidenceReasons)
	}
	if fixtureF.ConfidenceScore >= realF.ConfidenceScore {
		t.Errorf("fixture score %d is not below the real one %d — the flag was lost somewhere in the pipeline",
			fixtureF.ConfidenceScore, realF.ConfidenceScore)
	}

	if !hasReasonWithPrefix(fixtureF, "-20 ") {
		t.Errorf("no -20 placeholder reason on the fixture finding: %v", fixtureF.ConfidenceReasons)
	}
	if hasReasonWithPrefix(realF, "-20 ") {
		t.Errorf("the real-shaped credential was penalised as a placeholder: %v", realF.ConfidenceReasons)
	}

	// Severity is NOT a function of confidence — de-escalation is a
	// confidence claim, not a severity rewrite (Rule 3).
	if fixtureF.Severity != models.SeverityHigh {
		t.Errorf("fixture severity = %q; want HIGH — the penalty must not rewrite severity", fixtureF.Severity)
	}

	assertReasonsSumToScore(t, fixtureF)
	assertReasonsSumToScore(t, realF)
}

func hasReasonWithPrefix(f models.Finding, prefix string) bool {
	for _, r := range f.ConfidenceReasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

// splitSecretsFindings picks the two cfg.py findings out of a finalized set.
func splitSecretsFindings(t *testing.T, out []models.Finding) (fixture, real models.Finding) {
	t.Helper()
	var gotFixture, gotReal *models.Finding
	for i := range out {
		switch {
		case strings.HasSuffix(out[i].Endpoint, "cfg.py:1"):
			gotFixture = &out[i]
		case strings.HasSuffix(out[i].Endpoint, "cfg.py:2"):
			gotReal = &out[i]
		}
	}
	if gotFixture == nil || gotReal == nil {
		t.Fatalf("a secrets finding was dropped during finalization (Rule 3 violation):\n%+v", out)
	}
	return *gotFixture, *gotReal
}

// TestPlaceholderPenaltyReachesTheFindingThroughTheHybridPipeline is the test
// that goes red if CorrelateEvidence stops restoring Placeholder. It
// reproduces the orchestrator's hybrid sequence — correlate FIRST, index
// SECOND.
func TestPlaceholderPenaltyReachesTheFindingThroughTheHybridPipeline(t *testing.T) {
	fixture, real := secretsEvidenceFor(t)

	// A synthetic blackbox observation, present only so that
	// hasWhitebox && hasBlackbox holds and correlation actually runs. It has
	// no whitebox counterpart, so it passes straight through the correlator.
	probe := evidence.Evidence{
		Title:    "Missing security header: Content-Security-Policy",
		Category: "headers",
		Endpoint: "https://example.test/",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
	}

	evid := []evidence.Evidence{fixture, real, probe}
	if !hasWhitebox(evidence.ToFindings(evid)) || !hasBlackbox(evidence.ToFindings(evid)) {
		t.Fatal("test premise broken: the input is not a hybrid scan, so correlation would be skipped")
	}
	evid = CorrelateEvidence(evid)

	out := finalizeIndexed(evid, evidence.NewProvenanceIndex(evid), "", decision.Options{})
	if len(out) != 3 {
		t.Fatalf("finding count = %d; want 3 — de-escalation must never drop a finding:\n%+v", len(out), out)
	}
	fixtureF, realF := splitSecretsFindings(t, out)
	assertPlaceholderDeescalation(t, fixtureF, realF)
}

// TestPlaceholderSurvivesTheCodeOnlyPipelineToo is the negative control: the
// code-only path reaches the same verdict by a different route (the provenance
// index alone, no correlation). Deleting the correlator's restore leaves THIS
// test green and the hybrid one red — which is precisely the asymmetry that let
// the same trap swallow InTest unnoticed.
func TestPlaceholderSurvivesTheCodeOnlyPipelineToo(t *testing.T) {
	fixture, real := secretsEvidenceFor(t)

	out := finalize([]evidence.Evidence{fixture, real}, "", decision.Options{})
	if len(out) != 2 {
		t.Fatalf("finding count = %d; want 2:\n%+v", len(out), out)
	}
	fixtureF, realF := splitSecretsFindings(t, out)
	assertPlaceholderDeescalation(t, fixtureF, realF)
}
