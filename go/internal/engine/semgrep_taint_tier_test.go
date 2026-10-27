package engine

import (
	"reflect"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The semgrep_taint tier (ADR-011) in the engine's tier-aware steps. While
// semgrep.ReachabilityLanguages is empty no producer emits it; these tests pin
// what the tier means once a language is enabled.

// TrustRank 2 ties the taint tier with native_go (textscan). Escalation runs
// before the collapse, so a proven Semgrep taint finding declared at the same
// severity as textscan's finding on the same line arrives one level higher and
// is the one kept, with its chain. Against the shim it wins on rank.
func TestCollapseKeepsTheProvenSemgrepTaintFinding(t *testing.T) {
	chain := []models.TaintLink{
		{File: "app.js", Line: 7, Expr: "req.query.name"},
		{File: "app.js", Line: 9, Expr: "db.query(sql)"},
	}
	taint := wbAt("injection", "app.js:9", "SQL injection: request input reaches db.query()",
		models.SeverityHigh, models.TierSemgrepTaint)
	taint.Reachable, taint.TaintChain = true, chain

	for name, other := range map[string]models.Finding{
		"textscan (native_go)": wbAt("injection", "app.js:9", "SQL built by string concatenation",
			models.SeverityHigh, models.TierNativeGo),
		"semgrep shim": wbAt("injection", "app.js:9", "SQL built by string concatenation (semgrep)",
			models.SeverityHigh, models.TierSemgrepShim),
	} {
		t.Run(name, func(t *testing.T) {
			// The orchestrator's order: escalate reachable findings, then collapse.
			in := escalateNonCorrelatedReachable([]models.Finding{other, taint})
			out := CollapseDuplicateLocations(in)
			if len(out) != 1 {
				t.Fatalf("got %d findings %v, want the two collapsed into one", len(out), collapseTitles(out))
			}
			if out[0].SourceTier != models.TierSemgrepTaint || !reflect.DeepEqual(out[0].TaintChain, chain) {
				t.Errorf("kept %q (tier %s, chain %v); want the semgrep_taint finding with its chain",
					out[0].Title, out[0].SourceTier, out[0].TaintChain)
			}
		})
	}
}

// Fendix's own Semgrep taint pass and an imported Semgrep SARIF are one
// engine: neither may corroborate the other as an independent tool.
func TestNoIndependence_FendixSemgrepTaintVsImportedSemgrep(t *testing.T) {
	native := nativeSQLi("app/views.py:100", "100")
	native.SourceTier = models.TierSemgrepTaint
	imported := importedSQLi("semgrep", "app/views.py:101", "101")

	if got := ClassifyCrossTool(native, imported); got == MatchStrong {
		t.Fatal("fendix's semgrep taint tier and an imported semgrep SARIF are the same effective engine — not independent")
	}
}

// A Proven Path is never granted to a Semgrep tier: managed-ci/v2's
// consistency rule proven_path_requires_route_and_taint rejects proven_path
// with analyzer_implementation semgrep. The taint tier's reachability still
// takes the correlator's reachable escalation, as it takes the non-correlated
// one; the shim never carries reachability.
func TestProvenPathNeverFromASemgrepTier(t *testing.T) {
	for tier, wantSeverity := range map[models.SourceTier]models.Severity{
		models.TierSemgrepShim:  models.SeverityMedium, // LOW → MEDIUM (correlation only)
		models.TierSemgrepTaint: models.SeverityHigh,   // LOW → MEDIUM → HIGH (correlation + reachable)
	} {
		t.Run(string(tier), func(t *testing.T) {
			wb := routeWB("injection", &models.Route{Method: "GET", Pattern: "/users/{id}", Handler: "get_user"}, true)
			wb.SourceTier = tier
			wb.Severity = models.SeverityLow
			bb := routeBB("injection", "GET /users/42")
			bb.Severity = models.SeverityLow

			result := Correlate([]models.Finding{bb, wb})
			if len(result) != 1 || !result[0].RouteConfirmed {
				t.Fatalf("precondition: want one route-confirmed correlated finding, got %+v", result)
			}
			if result[0].ProvenPath {
				t.Error("ProvenPath = true for a Semgrep tier")
			}
			if result[0].Severity != wantSeverity {
				t.Errorf("Severity = %s, want %s", result[0].Severity, wantSeverity)
			}
		})
	}
}

// R-pf56 / Global Constraint: a correlated semgrep_taint finding takes the
// correlator's reachable escalation on top of the correlation bump, as a
// non-correlated one takes escalateNonCorrelatedReachable's. The shim never
// carries Reachable and gets the correlation bump only. Semgrep findings bind
// no Route, so this is the path a real one correlates through.
func TestCorrelatedSemgrepTaintTakesTheReachableEscalation(t *testing.T) {
	for tier, want := range map[models.SourceTier]models.Severity{
		models.TierSemgrepShim:  models.SeverityHigh,     // MEDIUM → HIGH (correlation)
		models.TierSemgrepTaint: models.SeverityCritical, // MEDIUM → HIGH → CRITICAL (correlation + reachable)
	} {
		t.Run(string(tier), func(t *testing.T) {
			bb := models.Finding{
				Title: "SQL injection confirmed by live scan", Severity: models.SeverityMedium,
				Source: models.SourceBlackbox, Category: "injection", Endpoint: "http://example.com/users",
				Evidence: "500 on payload", References: []string{"CWE-89"}, Confidence: models.ConfidenceHigh,
			}
			wb := models.Finding{
				Title: "SQL injection: request input reaches db.query()", Severity: models.SeverityMedium,
				Source: models.SourceWhitebox, Category: "injection", Endpoint: "routes/users.js:9",
				Evidence: "db.query(sql)", References: []string{"CWE-89"}, Confidence: models.ConfidenceHigh,
				Line: linePtr("routes/users.js:9"), SourceTier: tier,
			}
			if tier == models.TierSemgrepTaint {
				wb.Reachable = true
				wb.TaintChain = []models.TaintLink{{File: "routes/users.js", Line: 9, Expr: "db.query(sql)"}}
			}

			result := Correlate([]models.Finding{bb, wb})
			if len(result) != 1 || result[0].Source != models.SourceCorrelated {
				t.Fatalf("precondition: want one correlated finding, got %+v", result)
			}
			if result[0].Severity != want {
				t.Errorf("Severity = %s, want %s", result[0].Severity, want)
			}
			if result[0].ProvenPath {
				t.Error("ProvenPath = true for a Semgrep tier")
			}
			if result[0].Reachable != (tier == models.TierSemgrepTaint) {
				t.Errorf("Reachable = %v, want it carried from the whitebox half", result[0].Reachable)
			}
		})
	}
}
