package engine

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TASK-092: orchestrator step 5.6 must downgrade severity for findings whose
// confidence is below their severity rank (per scoring formula's implicit cap).
func TestEnforceConsistency_DowngradesLowConfidenceHighSeverity(t *testing.T) {
	in := []models.Finding{
		{ID: "SEC-001", Title: "A", Severity: models.SeverityCritical, Confidence: models.ConfidenceLow},
		{ID: "SEC-002", Title: "B", Severity: models.SeverityHigh, Confidence: models.ConfidenceMedium},
		{ID: "SEC-003", Title: "C", Severity: models.SeverityCritical, Confidence: models.ConfidenceMedium},
		{ID: "SEC-004", Title: "D", Severity: models.SeverityCritical, Confidence: models.ConfidenceHigh},
	}

	out := enforceConsistency(in)

	if got := out[0].Severity; got != models.SeverityMedium {
		t.Errorf("LOW conf + CRITICAL sev: want MEDIUM, got %s", got)
	}
	if got := out[1].Severity; got != models.SeverityHigh {
		t.Errorf("MEDIUM conf + HIGH sev: want HIGH unchanged, got %s", got)
	}
	if got := out[2].Severity; got != models.SeverityHigh {
		t.Errorf("MEDIUM conf + CRITICAL sev: want HIGH downgrade, got %s", got)
	}
	if got := out[3].Severity; got != models.SeverityCritical {
		t.Errorf("HIGH conf + CRITICAL sev: want CRITICAL unchanged, got %s", got)
	}
}

func TestEnforceConsistency_EmptyInput(t *testing.T) {
	out := enforceConsistency(nil)
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
	out = enforceConsistency([]models.Finding{})
	if len(out) != 0 {
		t.Errorf("expected 0 findings, got %d", len(out))
	}
}

// TASK-125: pure-whitebox findings with reachable=true should get one
// severity-level bump, mirroring the correlator's existing bump for
// the correlated-reachable case.
func TestEscalateNonCorrelatedReachable_BumpsWhitebox(t *testing.T) {
	in := []models.Finding{
		{ID: "SEC-001", Title: "Reachable XSS", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Reachable: true},
		{ID: "SEC-002", Title: "Reachable SQLi", Severity: models.SeverityMedium,
			Source: models.SourceWhitebox, Reachable: true},
		{ID: "SEC-003", Title: "Not reachable", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Reachable: false},
	}
	out := escalateNonCorrelatedReachable(in)

	if got := out[0].Severity; got != models.SeverityCritical {
		t.Errorf("reachable HIGH should escalate to CRITICAL, got %s", got)
	}
	if got := out[1].Severity; got != models.SeverityHigh {
		t.Errorf("reachable MEDIUM should escalate to HIGH, got %s", got)
	}
	if got := out[2].Severity; got != models.SeverityHigh {
		t.Errorf("non-reachable HIGH should stay HIGH, got %s", got)
	}
}

func TestEscalateNonCorrelatedReachable_SkipsCorrelated(t *testing.T) {
	// The correlator already applied the bump for correlated-reachable
	// findings in mergeFindings. Applying again would double-bump and
	// blow past the confidence cap.
	in := []models.Finding{
		{ID: "SEC-001", Title: "Correlated reachable", Severity: models.SeverityHigh,
			Source: models.SourceCorrelated, Reachable: true},
	}
	out := escalateNonCorrelatedReachable(in)
	if got := out[0].Severity; got != models.SeverityHigh {
		t.Errorf("correlated reachable should be untouched here, got %s", got)
	}
}

func TestEscalateNonCorrelatedReachable_SaturatesAtCritical(t *testing.T) {
	// Already CRITICAL → stays CRITICAL (escalateSeverity is idempotent
	// at the top of the scale).
	in := []models.Finding{
		{ID: "SEC-001", Title: "Already CRITICAL", Severity: models.SeverityCritical,
			Source: models.SourceWhitebox, Reachable: true},
	}
	out := escalateNonCorrelatedReachable(in)
	if got := out[0].Severity; got != models.SeverityCritical {
		t.Errorf("CRITICAL should stay CRITICAL, got %s", got)
	}
}

func TestEscalateNonCorrelatedReachable_EmptyInput(t *testing.T) {
	out := escalateNonCorrelatedReachable(nil)
	if len(out) != 0 {
		t.Errorf("nil input: expected 0, got %d", len(out))
	}
	out = escalateNonCorrelatedReachable([]models.Finding{})
	if len(out) != 0 {
		t.Errorf("empty input: expected 0, got %d", len(out))
	}
}
