package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Fendix runs several static engines over one tree. When two of them recognise
// the same construct, Deduplicate's (Title, Category, Severity) key keeps them
// apart forever because the titles differ — so the user sees one vulnerability
// two or three times. Measured on fastapi 0.110.0, one `SECRET_KEY = "..."`
// line produced THREE findings at two different severities; on the accuracy
// corpus the same double-report cascaded into a phantom false positive that
// held the synthetic F1 at 0.987, under its 0.990 CI floor.

func wbAt(cat, endpoint, title string, sev models.Severity, tier models.SourceTier) models.Finding {
	return models.Finding{
		Title: title, Category: cat, Endpoint: endpoint, Severity: sev,
		Source: models.SourceWhitebox, SourceTier: tier,
		Confidence: models.ConfidenceHigh, Evidence: "e:" + title, Fix: "f:" + title,
	}
}

func collapseTitles(fs []models.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Title
	}
	return out
}

// TestCollapseKeepsHighestTrustTier is the core case: two engines, one sink.
func TestCollapseKeepsHighestTrustTier(t *testing.T) {
	in := []models.Finding{
		wbAt("injection", "cmdi.py:17", "subprocess with shell=True (semgrep wording)", models.SeverityCritical, models.TierSemgrepShim),
		wbAt("injection", "cmdi.py:17", "subprocess called with shell=True", models.SeverityCritical, models.TierTreeSitter),
	}
	got := CollapseDuplicateLocations(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(got), collapseTitles(got))
	}
	if got[0].SourceTier != models.TierTreeSitter {
		t.Errorf("kept tier %q, want the higher-trust tree_sitter", got[0].SourceTier)
	}
}

// TestCollapseDoesNotLetLowTrustEscalateSeverity guards the SourceTier
// contract: semgrep must not raise a finding's severity through the back door,
// which is exactly what mergeFindings' tier gate exists to prevent.
func TestCollapseDoesNotLetLowTrustEscalateSeverity(t *testing.T) {
	in := []models.Finding{
		wbAt("secrets", "a.py:12", "Hardcoded secret (semgrep)", models.SeverityCritical, models.TierSemgrepShim),
		wbAt("secrets", "a.py:12", "Hardcoded API key or token", models.SeverityHigh, models.TierNativeGo),
	}
	got := CollapseDuplicateLocations(in)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH — the semgrep CRITICAL must not survive as an escalation",
			got[0].Severity)
	}
}

// TestCollapsePreservesDistinctSameTierRules is the regression gate for the
// over-collapse this fix originally caused: a Dockerfile legitimately earns
// BOTH "no USER directive" and "pins to :latest" from the same engine. They
// are separately actionable and must both survive. (Caught by the
// output-format snapshot suite.)
func TestCollapsePreservesDistinctSameTierRules(t *testing.T) {
	in := []models.Finding{
		wbAt("iac", "Dockerfile:1", "Dockerfile doesn't drop privileges (no USER directive in file)", models.SeverityMedium, models.TierNativeGo),
		wbAt("iac", "Dockerfile:1", "Dockerfile pins to :latest (or no tag at all)", models.SeverityMedium, models.TierNativeGo),
	}
	got := CollapseDuplicateLocations(in)
	if len(got) != 2 {
		t.Fatalf("same-tier findings at one location are DISTINCT rules; got %d: %v", len(got), collapseTitles(got))
	}
}

func TestCollapseLeavesBlackboxAndCorrelatedAlone(t *testing.T) {
	bb1 := models.Finding{Title: "Missing CSP", Category: "headers", Endpoint: "GET /a", Source: models.SourceBlackbox}
	bb2 := models.Finding{Title: "Missing HSTS", Category: "headers", Endpoint: "GET /a", Source: models.SourceBlackbox}
	co1 := models.Finding{Title: "SQLi", Category: "injection", Endpoint: "GET /b", Source: models.SourceCorrelated, SourceTier: models.TierTreeSitter}
	co2 := models.Finding{Title: "SQLi (semgrep)", Category: "injection", Endpoint: "GET /b", Source: models.SourceCorrelated, SourceTier: models.TierSemgrepShim}
	got := CollapseDuplicateLocations([]models.Finding{bb1, bb2, co1, co2})
	if len(got) != 4 {
		t.Errorf("blackbox/correlated findings must pass through untouched, got %d: %v", len(got), collapseTitles(got))
	}
}

func TestCollapseDifferentLocationsAndCategoriesUntouched(t *testing.T) {
	in := []models.Finding{
		wbAt("injection", "a.py:1", "X", models.SeverityHigh, models.TierTreeSitter),
		wbAt("injection", "a.py:2", "Y", models.SeverityHigh, models.TierSemgrepShim), // different line
		wbAt("secrets", "a.py:1", "Z", models.SeverityHigh, models.TierSemgrepShim),   // different category
	}
	if got := CollapseDuplicateLocations(in); len(got) != 3 {
		t.Errorf("expected all 3 preserved, got %d: %v", len(got), collapseTitles(got))
	}
}

// TestCollapseUnionsReferences — a dropped duplicate's CWE mapping must not be
// lost, or collapsing would silently reduce the report's coverage.
func TestCollapseUnionsReferences(t *testing.T) {
	a := wbAt("injection", "a.py:1", "keep", models.SeverityHigh, models.TierTreeSitter)
	a.References = []string{"CWE-78"}
	b := wbAt("injection", "a.py:1", "drop", models.SeverityHigh, models.TierSemgrepShim)
	b.References = []string{"CWE-77", "OWASP-A03"}
	got := CollapseDuplicateLocations([]models.Finding{a, b})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	joined := strings.Join(got[0].References, ",")
	for _, want := range []string{"CWE-78", "CWE-77", "OWASP-A03"} {
		if !strings.Contains(joined, want) {
			t.Errorf("reference %q lost in the collapse: %v", want, got[0].References)
		}
	}
}

// TestCollapseIsOrderIndependent locks F-L6 for the new pass.
func TestCollapseIsOrderIndependent(t *testing.T) {
	a := wbAt("injection", "a.py:1", "semgrep wording", models.SeverityCritical, models.TierSemgrepShim)
	b := wbAt("injection", "a.py:1", "tree-sitter wording", models.SeverityCritical, models.TierTreeSitter)
	c := wbAt("injection", "a.py:1", "native wording", models.SeverityCritical, models.TierNativeGo)
	for _, in := range [][]models.Finding{{a, b, c}, {c, b, a}, {b, a, c}, {c, a, b}} {
		got := CollapseDuplicateLocations(in)
		if len(got) != 1 || got[0].SourceTier != models.TierTreeSitter {
			t.Errorf("order %v produced %d findings, tier %q — want 1 / tree_sitter",
				collapseTitles(in), len(got), got[0].SourceTier)
		}
	}
}

func TestCollapseEmptyAndSingle(t *testing.T) {
	if got := CollapseDuplicateLocations(nil); got != nil {
		t.Errorf("nil in, want nil out, got %v", got)
	}
	one := []models.Finding{wbAt("injection", "a.py:1", "X", models.SeverityHigh, models.TierTreeSitter)}
	if got := CollapseDuplicateLocations(one); len(got) != 1 {
		t.Errorf("single finding must pass through, got %d", len(got))
	}
}

func TestTrustRankOrdering(t *testing.T) {
	if !(models.TierTreeSitter.TrustRank() > models.TierNativeGo.TrustRank() &&
		models.TierNativeGo.TrustRank() > models.SourceTier("").TrustRank() &&
		models.SourceTier("").TrustRank() > models.TierSemgrepShim.TrustRank()) {
		t.Error("trust order must be tree_sitter > native_go > unknown > semgrep_shim")
	}
}
