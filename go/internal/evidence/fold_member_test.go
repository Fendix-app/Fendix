package evidence

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CL2-2 / R3-SEC-B1: what a provider member folded into a representative
// contributes to the representative's provenance.

func foldEv(rule, title string, mutate func(*Evidence)) Evidence {
	e := Evidence{
		RuleID: rule, Title: title, Category: "secrets", Endpoint: "src/a.py:1",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func TestFoldMemberGradesTheFoldedFindingOnItsBestMember(t *testing.T) {
	generic := foldEv("secrets/HARDCODED_PASSWORD", "Hardcoded password", func(e *Evidence) { e.Placeholder, e.SyntheticValue = true, true })
	realToken := foldEv("secrets/SLACK_TOKEN", "Slack token hardcoded", func(e *Evidence) { e.ProviderAnchored = true })
	sampleToken := foldEv("secrets/SLACK_TOKEN", "Slack token hardcoded", func(e *Evidence) {
		e.ProviderAnchored, e.Placeholder, e.SyntheticValue = true, true, true
	})

	t.Run("a real provider token clears the generic value's judgement", func(t *testing.T) {
		ix := NewProvenanceIndex([]Evidence{generic, realToken})
		ix.FoldMember(generic.ToFinding(), realToken.ToFinding())
		p := ix.lookup(generic)
		if p.Placeholder || p.SyntheticValue || !p.ProviderAnchored {
			t.Errorf("representative provenance after the fold: %+v", p)
		}
	})
	t.Run("a sample provider token leaves the judgement", func(t *testing.T) {
		ix := NewProvenanceIndex([]Evidence{generic, sampleToken})
		ix.FoldMember(generic.ToFinding(), sampleToken.ToFinding())
		p := ix.lookup(generic)
		if !p.Placeholder || !p.SyntheticValue {
			t.Errorf("a sample token must not clear the representative's judgement: %+v", p)
		}
	})
	t.Run("a real generic member clears a sample provider representative (F-B1)", func(t *testing.T) {
		realGeneric := foldEv("secrets/HARDCODED_PASSWORD", "Hardcoded password", nil)
		ix := NewProvenanceIndex([]Evidence{sampleToken, realGeneric})
		ix.FoldMember(sampleToken.ToFinding(), realGeneric.ToFinding())
		p := ix.lookup(sampleToken)
		if p.Placeholder || p.SyntheticValue {
			t.Errorf("a real value folded into a sample representative must keep the folded finding real: %+v", p)
		}
	})
	t.Run("two samples stay samples", func(t *testing.T) {
		ix := NewProvenanceIndex([]Evidence{generic, sampleToken})
		ix.FoldMember(sampleToken.ToFinding(), generic.ToFinding())
		p := ix.lookup(sampleToken)
		if !p.Placeholder || !p.SyntheticValue {
			t.Errorf("a sample member must not raise a sample representative: %+v", p)
		}
	})
	t.Run("ProviderAnchored is a union", func(t *testing.T) {
		plain := foldEv("secrets/HARDCODED_PASSWORD", "Hardcoded password", nil)
		other := foldEv("secrets/GENERIC_API_KEY", "Hardcoded API key", nil)
		ix := NewProvenanceIndex([]Evidence{plain, other})
		ix.FoldMember(plain.ToFinding(), other.ToFinding())
		if ix.lookup(plain).ProviderAnchored {
			t.Error("two generic findings made a representative provider-anchored")
		}
		ix2 := NewProvenanceIndex([]Evidence{plain, realToken})
		ix2.FoldMember(plain.ToFinding(), realToken.ToFinding())
		if !ix2.lookup(plain).ProviderAnchored {
			t.Error("a provider member did not mark the representative provider-anchored")
		}
	})
	t.Run("it never adds a judgement", func(t *testing.T) {
		clean := foldEv("secrets/HARDCODED_PASSWORD", "Hardcoded password", nil)
		ix := NewProvenanceIndex([]Evidence{clean, sampleToken})
		ix.FoldMember(clean.ToFinding(), sampleToken.ToFinding())
		if p := ix.lookup(clean); p.Placeholder || p.SyntheticValue {
			t.Errorf("a sample provider token made a clean representative a sample: %+v", p)
		}
	})
	t.Run("an offline-provable provider token is kept", func(t *testing.T) {
		prov := foldEv("secrets/GITHUB_TOKEN", "GitHub token hardcoded", func(e *Evidence) { e.ProviderAnchored, e.OfflineProvable = true, true })
		ix := NewProvenanceIndex([]Evidence{generic, prov})
		ix.FoldMember(generic.ToFinding(), prov.ToFinding())
		if p := ix.lookup(generic); !p.OfflineProvable {
			t.Errorf("provable lost in the fold: %+v", p)
		}
	})
	t.Run("an unknown member or representative changes nothing", func(t *testing.T) {
		ix := NewProvenanceIndex([]Evidence{generic})
		ix.FoldMember(generic.ToFinding(), realToken.ToFinding())
		ix.FoldMember(realToken.ToFinding(), generic.ToFinding())
		if p := ix.lookup(generic); !p.Placeholder || p.ProviderAnchored {
			t.Errorf("unknown member changed the index: %+v", p)
		}
	})
}
