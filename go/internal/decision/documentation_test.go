package decision

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func docEvidence() evidence.Evidence {
	return evidence.Evidence{
		Title: "Stripe live secret key hardcoded", Category: "secrets", Endpoint: "docs/guide.md:12",
		Severity: models.SeverityCritical, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		InDoc: true,
	}
}

var docOptions = []Options{
	{EnforceConfidence: true},
	{EnforceConfidence: true, DeescalateTests: true},
	{EnforceConfidence: true, DeescalateTests: false},
}

// RC-10b: how a credential in documentation is decided, under every option.
func TestDocumentationCredentialDecisions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*evidence.Evidence)
		want   Status
	}{
		{"real-format, not provable: WARN", func(e *evidence.Evidence) {}, StatusWarn},
		{"provable offline: BLOCK", func(e *evidence.Evidence) { e.OfflineProvable = true }, StatusBlock},
		{"synthetic value: INFO", func(e *evidence.Evidence) { e.SyntheticValue, e.Placeholder = true, true }, StatusInfo},
		{"synthetic value, provider-anchored: still INFO (the value is the evidence)", func(e *evidence.Evidence) {
			e.SyntheticValue, e.Placeholder, e.ProviderAnchored = true, true, true
		}, StatusInfo},
		{"synthetic flag but provable offline: BLOCK, the INFO step never applies to a provable value", func(e *evidence.Evidence) {
			e.SyntheticValue, e.OfflineProvable = true, true
		}, StatusBlock},
		{"synthetic with an independent signal: the INFO step is vetoed", func(e *evidence.Evidence) {
			e.SyntheticValue, e.Placeholder, e.Reachable = true, true, true
		}, StatusWarn},
		{"not documentation: a synthetic value alone is WARN", func(e *evidence.Evidence) {
			e.InDoc = false
			e.SyntheticValue, e.Placeholder = true, true
		}, StatusWarn},
		{"not documentation: a real value BLOCKs", func(e *evidence.Evidence) { e.InDoc = false }, StatusBlock},
		{"another category is not read", func(e *evidence.Evidence) {
			e.Category = "injection"
			e.SyntheticValue = true
		}, StatusBlock},
	}
	for _, c := range cases {
		for _, opts := range docOptions {
			t.Run(c.name, func(t *testing.T) {
				ev := docEvidence()
				c.mutate(&ev)
				d := DecideWithOptions(ev, "HIGH", opts)
				if d.Status != c.want {
					t.Errorf("deescalate=%v: status %s, want %s (%s)", opts.DeescalateTests, d.Status, c.want, d.Reason)
				}
			})
		}
	}
}

// Nothing is suppressed: the demotion is explained in the reason and the
// evidence's identity is untouched.
func TestDocumentationDemotionIsExplained(t *testing.T) {
	ev := docEvidence()
	ev.SyntheticValue, ev.Placeholder = true, true
	d := DecideWithOptions(ev, "HIGH", Options{EnforceConfidence: true})
	if d.Status != StatusInfo || d.Reason != documentationSyntheticReason {
		t.Fatalf("status %s reason %q", d.Status, d.Reason)
	}
	if d.PolicyOverride {
		t.Error("a demotion cannot be a policy override")
	}
}

// With the confidence gate off (--enforce-confidence=false) the legacy
// severity-only mapping is restored byte for byte: the documentation arm does
// not apply to it.
func TestDocumentationArmDoesNotChangeTheLegacyMapping(t *testing.T) {
	ev := docEvidence()
	ev.SyntheticValue, ev.Placeholder = true, true
	if got := DecideWithOptions(ev, "HIGH", Options{}).Status; got != StatusBlock {
		t.Errorf("legacy mapping changed: %s, want BLOCK", got)
	}
}
