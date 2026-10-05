package engine

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestCorrelate_OrderInvariants pins the properties of Correlate that
// MUST hold regardless of input order. The complete output is NOT
// order-invariant — when a whitebox finding has multiple valid
// blackbox candidates, "first match wins" picks an order-dependent
// pair. But the *aggregate* shape is invariant, and that's what this
// test enforces.
//
// Properties asserted (per permutation):
//
//	(1) The TOTAL output count is the same.
//	(2) The number of correlated findings is the same — i.e. the
//	    pairing count doesn't depend on input order.
//	(3) The SET of whitebox findings that ended up correlated (vs.
//	    left uncorrelated with "[Unconfirmed by live scan]") is the
//	    same. The specific blackbox each one paired with is allowed
//	    to vary across permutations.
//	(4) The SET of blackbox findings that ended up uncorrelated is
//	    the same.
//
// Failure mode this catches: any future refactor that introduces
// non-determinism into the pairing eligibility (e.g. by changing
// `taken` to a non-set semantics, or by making categoryMap iteration
// affect outcomes), where the *which-paired-with-whom* might be
// permitted to drift but the COUNT must not.
func TestCorrelate_OrderInvariants(t *testing.T) {
	// Hand-crafted corpus designed to exercise all three match
	// kinds (exact / suffix / fuzzy):
	//
	//   - WB src/routes/users.py ⟷ BB GET /api/v1/users (fuzzy via
	//     "users" segment)
	//   - WB src/routes/orders.py ⟷ BB GET /api/v1/orders (fuzzy)
	//   - WB /pet/findByStatus    ⟷ BB GET /api/v3/pet/findByStatus
	//     (suffix)
	//   - WB src/auth/login.py    — no matching BB → stays unmerged
	//   - BB GET /api/v1/healthz  — no matching WB → stays unmerged
	corpus := []models.Finding{
		bb("auth_bypass", "GET /api/v1/users", "200 without auth", "T1"),
		bb("injection", "GET /api/v1/orders?id=1", "sleep(5) succeeded", "T2"),
		bb("auth_bypass", "GET /api/v3/pet/findByStatus", "200 without auth", "T3"),
		bb("data_exposure", "GET /api/v1/healthz", "stack trace", "T4"),

		wb("auth", "src/routes/users.py:42", "missing @login_required", "T1w"),
		wb("injection", "src/routes/orders.py:80", "raw SQL", "T2w"),
		wb("auth", "/pet/findByStatus", "no auth check", "T3w"),
		wb("secrets", "src/auth/login.py:14", "hardcoded key", "T5w"),
	}

	// Reference run.
	ref := Correlate(append([]models.Finding(nil), corpus...))
	refSummary := correlateSummary(ref)
	if refSummary.correlated == 0 {
		t.Fatalf("setup error: expected at least one correlation in reference run; got summary=%+v", refSummary)
	}

	rng := rand.New(rand.NewSource(20260516))
	const trials = 100
	for trial := 0; trial < trials; trial++ {
		perm := append([]models.Finding(nil), corpus...)
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })

		got := Correlate(perm)
		gotSummary := correlateSummary(got)

		if gotSummary.total != refSummary.total {
			t.Errorf("trial %d: total count = %d, want %d (order should not change total output count)",
				trial, gotSummary.total, refSummary.total)
		}
		if gotSummary.correlated != refSummary.correlated {
			t.Errorf("trial %d: correlated count = %d, want %d (order should not change pairing count)",
				trial, gotSummary.correlated, refSummary.correlated)
		}
		if !sameSet(gotSummary.unmergedWB, refSummary.unmergedWB) {
			t.Errorf("trial %d: unmerged whitebox titles differ.\n  ref: %v\n  got: %v",
				trial, refSummary.unmergedWB, gotSummary.unmergedWB)
		}
		if !sameSet(gotSummary.unmergedBB, refSummary.unmergedBB) {
			t.Errorf("trial %d: unmerged blackbox titles differ.\n  ref: %v\n  got: %v",
				trial, refSummary.unmergedBB, gotSummary.unmergedBB)
		}
	}
}

// TestCorrelate_NoBlackboxLeavesWhiteboxUnconfirmedSuffix is the
// complementary contract test: when there's nothing to correlate
// against, whitebox URL findings get the "[Unconfirmed by live scan]"
// evidence suffix and confidence=MEDIUM, while file-path findings
// pass through untouched. Pin it explicitly so a future refactor
// that drops the isURLEndpoint check doesn't go unnoticed.
func TestCorrelate_NoBlackboxLeavesWhiteboxUnconfirmedSuffix(t *testing.T) {
	// Both findings come in at confidence HIGH so we can observe the
	// downgrade-to-MEDIUM behaviour explicitly (the wb() helper's
	// default of MEDIUM would make the URL-finding's downgrade
	// invisible).
	urlIn := wb("auth", "/pet/findByStatus", "no auth check", "url-only")
	urlIn.Confidence = models.ConfidenceHigh
	fileIn := wb("secrets", "src/config.py:14", "hardcoded key", "file-only")
	fileIn.Confidence = models.ConfidenceHigh
	corpus := []models.Finding{urlIn, fileIn}

	got := Correlate(corpus)
	if len(got) != 2 {
		t.Fatalf("expected 2 outputs, got %d", len(got))
	}
	var urlF, fileF *models.Finding
	for i := range got {
		switch got[i].Title {
		case "url-only":
			urlF = &got[i]
		case "file-only":
			fileF = &got[i]
		}
	}
	if urlF == nil || fileF == nil {
		t.Fatalf("missing one of the expected findings: %+v", got)
	}
	// URL-anchored: downgraded to MEDIUM and suffixed.
	if urlF.Confidence != models.ConfidenceMedium {
		t.Errorf("URL whitebox confidence = %v, want MEDIUM (downgraded because no blackbox match)", urlF.Confidence)
	}
	if !hasSubstr(urlF.Evidence, "Unconfirmed by live scan") {
		t.Errorf("URL whitebox should have [Unconfirmed by live scan] suffix; got evidence %q", urlF.Evidence)
	}
	// File-anchored: passes through untouched (confidence stays
	// HIGH; no suffix).
	if fileF.Confidence != models.ConfidenceHigh {
		t.Errorf("file-anchored whitebox confidence = %v, want HIGH (live scan can't confirm or refute a file-anchored finding)", fileF.Confidence)
	}
	if hasSubstr(fileF.Evidence, "Unconfirmed by live scan") {
		t.Errorf("file-anchored whitebox should NOT get the [Unconfirmed by live scan] suffix; got evidence %q", fileF.Evidence)
	}
}

// TestCorrelate_IdempotentOnAlreadyCorrelated pins that re-running
// Correlate on its own output doesn't escalate severity or change
// counts. Findings with Source=SourceCorrelated are pass-through.
func TestCorrelate_IdempotentOnAlreadyCorrelated(t *testing.T) {
	corpus := []models.Finding{
		bb("auth_bypass", "GET /api/v1/users", "200 without auth", "T1"),
		wb("auth", "src/routes/users.py:42", "missing @login_required", "T1w"),
	}
	once := Correlate(corpus)
	twice := Correlate(append([]models.Finding(nil), once...))

	if len(once) != len(twice) {
		t.Fatalf("idempotency broken: 1× → %d findings, 2× → %d findings", len(once), len(twice))
	}
	a := correlateSummary(once)
	b := correlateSummary(twice)
	if a.correlated != b.correlated {
		t.Errorf("correlated count drifted under re-correlation: %d → %d", a.correlated, b.correlated)
	}

	// Severity must NOT escalate a second time.
	for _, f := range once {
		if f.Source != models.SourceCorrelated {
			continue
		}
		for _, g := range twice {
			if g.Title == f.Title && g.Endpoint == f.Endpoint && g.Severity != f.Severity {
				t.Errorf("severity escalated on re-correlation for %q: %s → %s",
					f.Title, f.Severity, g.Severity)
			}
		}
	}
}

// --- helpers ---

func bb(cat, endpoint, evidence, title string) models.Finding {
	return models.Finding{
		Title:      title,
		Severity:   models.SeverityHigh,
		Source:     models.SourceBlackbox,
		Category:   cat,
		Endpoint:   endpoint,
		Evidence:   evidence,
		References: []string{"CWE-XX"},
		Confidence: models.ConfidenceHigh,
	}
}

func wb(cat, endpoint, evidence, title string) models.Finding {
	return models.Finding{
		Title:      title,
		Severity:   models.SeverityMedium,
		Source:     models.SourceWhitebox,
		Category:   cat,
		Endpoint:   endpoint,
		Evidence:   evidence,
		References: []string{"CWE-XX"},
		Confidence: models.ConfidenceMedium,
	}
}

type correlateSummaryShape struct {
	total      int
	correlated int
	unmergedWB []string // sorted titles
	unmergedBB []string // sorted titles
}

func correlateSummary(findings []models.Finding) correlateSummaryShape {
	out := correlateSummaryShape{total: len(findings)}
	for _, f := range findings {
		switch f.Source {
		case models.SourceCorrelated:
			out.correlated++
		case models.SourceBlackbox:
			out.unmergedBB = append(out.unmergedBB, f.Title)
		case models.SourceWhitebox:
			out.unmergedWB = append(out.unmergedWB, f.Title)
		}
	}
	sort.Strings(out.unmergedWB)
	sort.Strings(out.unmergedBB)
	return out
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasSubstr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
