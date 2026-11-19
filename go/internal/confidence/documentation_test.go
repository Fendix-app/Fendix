package confidence

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func docCredential() evidence.Evidence {
	return evidence.Evidence{
		Title: "Stripe live secret key hardcoded", Category: "secrets", Endpoint: "README.md:7",
		Severity: models.SeverityCritical, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		InDoc: true,
	}
}

// RC-10b: a credential read out of documentation earns no deterministic
// detection weight unless it is provable offline.
func TestHasDeterministicDetectionDocumentation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*evidence.Evidence)
		want   bool
	}{
		{"documentation credential, not provable", func(e *evidence.Evidence) {}, false},
		{"documentation credential, provable offline", func(e *evidence.Evidence) { e.OfflineProvable = true }, true},
		{"the same finding outside documentation", func(e *evidence.Evidence) { e.InDoc = false }, true},
		{"not a secret: documentation does not matter", func(e *evidence.Evidence) { e.Category = "injection" }, true},
		{"documentation with a synthetic value", func(e *evidence.Evidence) { e.SyntheticValue, e.Placeholder = true, true }, false},
		{"documentation in test code", func(e *evidence.Evidence) { e.InTest = true }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := docCredential()
			c.mutate(&ev)
			if got := HasDeterministicDetection(ev); got != c.want {
				t.Errorf("HasDeterministicDetection = %v, want %v", got, c.want)
			}
			// The scorer and the predicate never disagree: the +30 is present
			// exactly when the predicate says so.
			has := false
			for _, d := range Score(ev).Details {
				if d.Code == CodeDeterministicDetection {
					has = true
				}
			}
			if has != c.want {
				t.Errorf("Score carries the deterministic-detection delta = %v, predicate %v", has, c.want)
			}
		})
	}
}
