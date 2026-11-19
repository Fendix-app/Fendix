package engine

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CL-1 / B-3: the correlator rebuilds evidence from an allow-list of what a
// producer knew, and a flag it drops is dropped silently. NotDocumentation is
// what the secrets scanner knows from the first line of the file, so it must
// cross the correlator, or a hybrid scan scores a shell script named INSTALL as
// documentation while a code-only scan does not.
func TestCorrelatorKeepsNotDocumentation(t *testing.T) {
	in := []evidence.Evidence{{
		Title: "Hardcoded password in source code", Category: "secrets", Endpoint: "INSTALL:3",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		NotDocumentation: true,
	}}
	out := CorrelateEvidence(in)
	if len(out) != 1 {
		t.Fatalf("got %d evidence, want 1", len(out))
	}
	if !out[0].NotDocumentation {
		t.Error("CorrelateEvidence dropped NotDocumentation")
	}
}
