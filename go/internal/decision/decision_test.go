package decision

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func ev(sev models.Severity) evidence.Evidence {
	return evidence.Evidence{Severity: sev, Confidence: models.ConfidenceHigh}
}

// legacyCheckFailOn replicates orchestrator.checkFailOn EXACTLY so the test
// is an independent oracle for the Decision-layer exit code.
func legacyCheckFailOn(sevs []models.Severity, failOn string) int {
	if failOn == "" {
		return 0
	}
	threshold := models.SeverityRank(models.Severity(failOn))
	if threshold == 0 {
		return 0
	}
	for _, s := range sevs {
		if models.SeverityRank(s) >= threshold {
			return 1
		}
	}
	return 0
}

// sevSets / failOns are the exit-code cross-product shared by the legacy lock
// and the --enforce-confidence=false contract test.
func sevSets() [][]models.Severity {
	return [][]models.Severity{
		{},
		{models.SeverityInfo},
		{models.SeverityLow},
		{models.SeverityMedium},
		{models.SeverityHigh},
		{models.SeverityCritical},
		{models.SeverityLow, models.SeverityMedium},
		{models.SeverityInfo, models.SeverityHigh},
		{models.SeverityMedium, models.SeverityCritical},
	}
}

var failOns = []string{"", "MEDIUM", "HIGH", "CRITICAL", "INFO", "garbage"}

// TestExitCodeMatchesLegacyCheckFailOn is the v0.22 contract lock, and since
// v1.2.2 it guards the --enforce-confidence=false ESCAPE HATCH specifically:
// Decide / DecideAll are the frozen legacy severity-only mapping, and for every
// (findings, fail-on) combination ExitCode(DecideAll(...)) must still equal the
// legacy checkFailOn result.
//
// Production no longer takes this path — the orchestrator calls
// DecideAllWithOptions with the shipped policy — so this test alone no longer
// proves the CLI's exit code. TestDecideEnforcedRuleTable and
// TestEnforceConfidenceOffIsByteForByteLegacy cover the two live policies; note
// in particular that ev() leaves Source empty, so every case here scores 35
// (band LOW) and would collapse to WARN if enforcement were applied to it.
func TestExitCodeMatchesLegacyCheckFailOn(t *testing.T) {
	for _, set := range sevSets() {
		for _, fo := range failOns {
			evs := make([]evidence.Evidence, len(set))
			for i, s := range set {
				evs[i] = ev(s)
			}
			got := ExitCode(DecideAll(evs, fo))
			want := legacyCheckFailOn(set, fo)
			if got != want {
				t.Errorf("set=%v failOn=%q: ExitCode=%d, legacy checkFailOn=%d", set, fo, got, want)
			}
		}
	}
}

// TestDecideStatus is the LEGACY (severity-only) status table: what Decide
// returns with no Options, i.e. what --enforce-confidence=false restores. The
// enforced table that production actually ships lives in
// TestDecideEnforcedRuleTable.
func TestDecideStatus(t *testing.T) {
	cases := []struct {
		sev    models.Severity
		failOn string
		want   Status
	}{
		{models.SeverityCritical, "HIGH", StatusBlock},
		{models.SeverityHigh, "HIGH", StatusBlock},
		{models.SeverityMedium, "HIGH", StatusWarn}, // below threshold but actionable
		{models.SeverityMedium, "", StatusWarn},     // no threshold → never block
		{models.SeverityCritical, "", StatusWarn},   // no threshold → not BLOCK even if critical
		{models.SeverityLow, "HIGH", StatusInfo},
		{models.SeverityInfo, "CRITICAL", StatusInfo},
		{models.SeverityCritical, "garbage", StatusWarn}, // invalid threshold → no block
	}
	for _, c := range cases {
		got := Decide(ev(c.sev), c.failOn).Status
		if got != c.want {
			t.Errorf("Decide(%s, %q).Status = %s, want %s", c.sev, c.failOn, got, c.want)
		}
	}
}

func TestDecideCarriesEvidenceAndConfidence(t *testing.T) {
	e := evidence.Evidence{Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium, Title: "x"}
	d := Decide(e, "HIGH")
	if d.Confidence != models.ConfidenceMedium {
		t.Errorf("confidence not carried: %v", d.Confidence)
	}
	if d.Evidence.Title != "x" {
		t.Errorf("supporting evidence not carried")
	}
	if d.Reason == "" {
		t.Error("decision should carry a reason")
	}
}

func TestDecideAllNil(t *testing.T) {
	if DecideAll(nil, "HIGH") != nil {
		t.Error("DecideAll(nil) should be nil")
	}
}

func TestDecidePopulatesConfidenceScore(t *testing.T) {
	// v0.23: every decision carries a deterministic score + reasons.
	d := Decide(evidence.Evidence{Source: models.SourceCorrelated, Reachable: true}, "HIGH")
	if d.Score.Value <= 0 {
		t.Errorf("decision has no confidence score: %+v", d.Score)
	}
	if len(d.Score.Reasons) == 0 {
		t.Error("decision score has no plain-text reasons (no black boxes)")
	}
}

// TestDecideDeescalatesTestFixtureToInfo is the B3 (test-fixture) gate: a
// finding in test/fixture code de-escalates to INFO (evidence preserved,
// Rule 3), config-overridable so a team that DOES want to gate on test-code
// findings can turn it off.
// InTest is set explicitly here, not derived from Endpoint: the flag is the
// conservatively-merged output of evidence.ProvenanceIndex (which folds a
// dedup group with "agree or drop"), and re-deriving it from the primary
// endpoint inside Decide would defeat that merge. See the CALLER CONTRACT on
// DecideWithOptions.
func TestDecideDeescalatesTestFixtureToInfo(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh,
		Endpoint: "app/tests/test_views.py:42",
		Category: "injection",
		InTest:   true,
	}
	// Without a --fail-on threshold this HIGH finding is WARN; in a test path
	// it drops to INFO with an explanatory reason (evidence preserved).
	d := DecideWithOptions(ev, "", Options{DeescalateTests: true})
	if d.Status != StatusInfo {
		t.Errorf("test-fixture finding Status = %q, want INFO", d.Status)
	}
	if !strings.Contains(d.Reason, "test") {
		t.Errorf("reason should explain the de-escalation: %q", d.Reason)
	}
	// Disabling the rule keeps it WARN.
	d2 := DecideWithOptions(ev, "", Options{DeescalateTests: false})
	if d2.Status != StatusWarn {
		t.Errorf("with de-escalation off, Status = %q, want WARN", d2.Status)
	}
	// A non-test HIGH finding is unaffected even with de-escalation on.
	prod := evidence.Evidence{Severity: models.SeverityHigh, Endpoint: "app/views.py:10", Category: "injection"}
	if got := DecideWithOptions(prod, "", Options{DeescalateTests: true}); got.Status != StatusWarn {
		t.Errorf("non-test finding Status = %q, want WARN (unaffected)", got.Status)
	}
	// FIX-09 (v1.2.2) INVERTED the old assertion here. Before, a BLOCK at/above
	// --fail-on was never downgraded by the test-path rule; that made the
	// project's largest FP class (31/35 of tasks/FP_CORPUS.md) structurally
	// exempt from its own mitigation for exactly the teams that set a
	// threshold. Now an UNCORROBORATED test-code BLOCK is held at WARN...
	held := DecideWithOptions(ev, "HIGH", Options{DeescalateTests: true})
	if held.Status != StatusWarn {
		t.Errorf("uncorroborated test-fixture BLOCK Status = %q, want WARN", held.Status)
	}
	if !strings.Contains(held.Reason, "test/fixture code") || !strings.Contains(held.Reason, "corroborating") {
		t.Errorf("reason should name both the test-fixture rule and the missing corroboration: %q", held.Reason)
	}
	// ...while a CORROBORATED one still gates the build. That is what keeps
	// this a de-escalation rather than path suppression (Rule 3): an
	// independent signal beyond the pattern match can establish a real leak.
	corroborated := ev
	corroborated.Reachable = true
	if got := DecideWithOptions(corroborated, "HIGH", Options{DeescalateTests: true}); got.Status != StatusBlock {
		t.Errorf("corroborated test-fixture finding Status = %q, want BLOCK", got.Status)
	}
}
