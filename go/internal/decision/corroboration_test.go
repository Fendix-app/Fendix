package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// A blackbox finding whose ONLY support is "a live probe produced it" must not
// reach BLOCK. "The scan ran" is a restatement of Source, not an observation
// independent of the claim — see RC-1 in the design spec.
func TestBlackboxSourceAloneIsNotIndependentCorroboration(t *testing.T) {
	ev := evidence.Evidence{
		Title:      "Missing authentication on endpoint",
		Category:   "auth_bypass",
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Endpoint:   "GET /status",
		Confidence: models.ConfidenceMedium,
	}

	c := corroborate(ev)
	if len(c.Independent) != 0 {
		t.Errorf("Independent = %v, want empty — a bare blackbox source corroborates nothing", c.Independent)
	}

	d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusWarn {
		t.Errorf("Status = %q, want WARN (score %d, band %s, reason %q)",
			d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
}

// A proven source→sink chain IS independent of the pattern match that found the
// sink, so it still blocks. This is the coverage half of the invariant.
func TestReachableTaintPathRemainsIndependentCorroboration(t *testing.T) {
	ev := evidence.Evidence{
		Title:      "Potential SSRF — dynamic URL passed to HTTP client",
		Category:   "injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Endpoint:   "app/views.py:674",
		Confidence: models.ConfidenceHigh,
		SourceTier: models.TierTreeSitter,
		Reachable:  true,
	}

	c := corroborate(ev)
	if !containsSignal(c.Independent, "reachable taint path") {
		t.Errorf("Independent = %v, want it to contain %q", c.Independent, "reachable taint path")
	}

	d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusBlock {
		t.Errorf("Status = %q, want BLOCK — a reachable taint path must still gate", d.Status)
	}
}

// A deterministic read of a live response is self-evident, not independent: the
// claim IS the observation. It keeps paying its confidence delta and is still
// exported, but it cannot lift a MEDIUM band on its own.
func TestDirectObservationIsSelfEvidentNotIndependent(t *testing.T) {
	ev := evidence.Evidence{
		Title:             "CORS wildcard origin with credentials allowed",
		Category:          "cors",
		Severity:          models.SeverityCritical,
		Source:            models.SourceBlackbox,
		Endpoint:          "POST /api/auth/refresh/",
		Confidence:        models.ConfidenceHigh,
		DirectObservation: true,
	}

	c := corroborate(ev)
	if !containsSignal(c.SelfEvident, "direct observation of a live response") {
		t.Errorf("SelfEvident = %v, want it to contain the direct-observation signal", c.SelfEvident)
	}
	if containsSignal(c.Independent, "direct observation of a live response") {
		t.Errorf("Independent = %v, must not contain the direct-observation signal", c.Independent)
	}
}

func containsSignal(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
