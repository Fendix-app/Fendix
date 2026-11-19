package evidence

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func classEv(endpoint string, mutate func(*Evidence)) Evidence {
	e := Evidence{
		Title: "Hardcoded password in source code", Category: "secrets", Endpoint: endpoint,
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

// C1-1: the class is read from the provenance by the occurrence's identity, so
// occurrences that differ in a flag only the producer knows have different
// classes, and a group of agreeing occurrences has their class.
func TestOccurrenceClass(t *testing.T) {
	plain := classEv("src/a.py:2", nil)
	placeholder := classEv("src/b.py:2", func(e *Evidence) { e.Placeholder = true })
	synthetic := classEv("src/c.py:2", func(e *Evidence) { e.Placeholder, e.SyntheticValue = true, true })
	provable := classEv("docs/d.md:2", func(e *Evidence) { e.OfflineProvable = true })
	anchored := classEv("src/e.py:2", func(e *Evidence) { e.Placeholder, e.ProviderAnchored = true, true })
	notImported := classEv("src/f.py:2", func(e *Evidence) { e.Applicability = models.ApplicabilityEvidenceAgainst })
	all := []Evidence{plain, placeholder, synthetic, provable, anchored, notImported}
	ix := NewProvenanceIndex(all)
	classes := map[string]string{}
	for _, e := range all {
		c := ix.OccurrenceClass(e.ToFinding())
		if prev, dup := classes[c]; dup {
			t.Errorf("%s and %s share the class %q", prev, e.Endpoint, c)
		}
		classes[c] = e.Endpoint
	}
	if got := ix.OccurrenceClass(plain.ToFinding()); got != "" {
		t.Errorf("an occurrence with no producer flag has class %q, want empty", got)
	}

	// A group of occurrences that agree has their class.
	a := classEv("src/g1.py:2", func(e *Evidence) { e.Placeholder, e.SyntheticValue = true, true })
	b := classEv("src/g2.py:2", func(e *Evidence) { e.Placeholder, e.SyntheticValue = true, true })
	ixg := NewProvenanceIndex([]Evidence{a, b})
	group := a.ToFinding()
	group.AffectedEndpoints = []string{"src/g1.py:2", "src/g2.py:2"}
	if g, m := ixg.OccurrenceClass(group), ixg.OccurrenceClass(a.ToFinding()); g != m {
		t.Errorf("a group's class %q is not its members' %q", g, m)
	}

	// Blackbox findings have none: one observation of one URL.
	bb := Evidence{Title: "Missing CSP", Category: "headers", Endpoint: "GET /", Source: models.SourceBlackbox, DirectObservation: true}
	if got := NewProvenanceIndex([]Evidence{bb}).OccurrenceClass(bb.ToFinding()); got != "" {
		t.Errorf("a blackbox finding has class %q, want empty", got)
	}
	// An occurrence the index does not know has the empty class (today's behaviour).
	if got := ix.OccurrenceClass(classEv("src/unknown.py:2", nil).ToFinding()); got != "" {
		t.Errorf("unknown occurrence class %q, want empty", got)
	}
}
