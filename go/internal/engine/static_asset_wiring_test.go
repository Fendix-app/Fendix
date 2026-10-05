package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// These tests are the regression gate for the B4 "static-asset context is dead"
// defect. internal/confidence carried a `case "static-asset"` penalty branch and
// the benchmark taxonomy carried an FPStaticAssetCtx class, but no scanner ever
// produced that tag — the only producer, httpResponseContext, returned "4xx" or
// "". Static assets were instead HARD-SUPPRESSED in the rate-limit check, which
// is the opposite of Rule 3 (preserve evidence, de-escalate).
//
// The gate deliberately drives the REAL scanner check rather than hand-building
// Evidence with the tag pre-set: hand-setting it would have passed before the
// fix too. What was broken was the producer, so the producer is what the test
// exercises.

// headerFindingsFor runs the real header check against a loopback server that
// returns 200 with no security headers, at the given path.
func headerFindingsFor(t *testing.T, path string) []evidence.Evidence {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	ep := scanner.Endpoint{Method: "GET", Path: path, FullURL: server.URL + path}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := scanner.CheckHeaders(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatalf("no header findings produced for %q — test premise broken", path)
	}
	return findings
}

// TestStaticAssetPenaltyReachesTheFindingThroughTheRealPipeline is THE test
// that fails before the fix. It runs the production header check on a static
// path, then the production finalization + decision stamping, and requires the
// -15 static-asset penalty and its reason line to land on the emitted finding.
//
// Pre-fix, CheckHeaders left ResponseContext empty for a static asset, so the
// scores below were identical and the reason line never appeared.
func TestStaticAssetPenaltyReachesTheFindingThroughTheRealPipeline(t *testing.T) {
	staticEv := headerFindingsFor(t, "/assets/app.js")
	apiEv := headerFindingsFor(t, "/api/v1/users")

	staticF := finalize(staticEv, "", decision.Options{})
	apiF := finalize(apiEv, "", decision.Options{})

	if len(staticF) == 0 || len(apiF) == 0 {
		t.Fatalf("findings lost in finalization: static=%d api=%d", len(staticF), len(apiF))
	}

	// Rule 3: the finding survives. Suppressing it would have been the easy
	// (and wrong) fix.
	if len(staticF) != len(apiF) {
		t.Errorf("static-asset findings were dropped rather than de-escalated: %d vs %d on an API route",
			len(staticF), len(apiF))
	}

	if staticF[0].ConfidenceScore >= apiF[0].ConfidenceScore {
		t.Errorf("static-asset finding scored %d, want lower than the API-route %d — the B4\n"+
			"static-asset penalty did not reach the finding through the real pipeline",
			staticF[0].ConfidenceScore, apiF[0].ConfidenceScore)
	}
	if got, want := apiF[0].ConfidenceScore-staticF[0].ConfidenceScore, 15; got != want {
		t.Errorf("penalty was %d points, want %d", got, want)
	}

	joined := strings.Join(staticF[0].ConfidenceReasons, "\n")
	if !strings.Contains(joined, "static-asset") {
		t.Errorf("no static-asset reason line on the finding — the de-escalation must be\n"+
			"explainable in the published breakdown:\n%s", joined)
	}
	// Explainability: the reasons must still reconcile with the score.
	assertReasonsSumToScore(t, staticF[0])
	assertReasonsSumToScore(t, apiF[0])
}

// TestAPIRouteGetsNoStaticAssetPenalty is the negative control — a normal API
// endpoint must be untouched.
func TestAPIRouteGetsNoStaticAssetPenalty(t *testing.T) {
	apiF := finalize(headerFindingsFor(t, "/api/v1/users"), "", decision.Options{})

	joined := strings.Join(apiF[0].ConfidenceReasons, "\n")
	if strings.Contains(joined, "static-asset") {
		t.Errorf("API-route finding carried a static-asset penalty:\n%s", joined)
	}
}

// TestStaticAssetContextMixedDedupGroupUsesConservativeMerge locks the merge
// rule for the new tag. A header finding on a static asset and the identical
// finding on an API route share (Title, Category, Severity), so dedup collapses
// them into one. The de-escalation must NOT survive that merge — the API-route
// occurrence never earned it.
func TestStaticAssetContextMixedDedupGroupUsesConservativeMerge(t *testing.T) {
	mixed := append(headerFindingsFor(t, "/assets/app.js"), headerFindingsFor(t, "/api/v1/users")...)
	allStatic := append(headerFindingsFor(t, "/assets/app.js"), headerFindingsFor(t, "/static/site.css")...)

	mixedF := finalize(mixed, "", decision.Options{})
	staticF := finalize(allStatic, "", decision.Options{})

	if len(mixedF) == 0 || len(staticF) == 0 {
		t.Fatal("findings lost in finalization")
	}
	if len(mixedF[0].AffectedEndpoints) != 2 {
		t.Fatalf("expected the two occurrences to dedup, got AffectedEndpoints=%v",
			mixedF[0].AffectedEndpoints)
	}

	if strings.Contains(strings.Join(mixedF[0].ConfidenceReasons, "\n"), "static-asset") {
		t.Errorf("mixed static+API dedup group kept the static-asset penalty — an API-route\n"+
			"occurrence must not inherit it: %v", mixedF[0].ConfidenceReasons)
	}
	if !strings.Contains(strings.Join(staticF[0].ConfidenceReasons, "\n"), "static-asset") {
		t.Errorf("all-static dedup group LOST the penalty; the conservative merge must still\n"+
			"apply it when every occurrence earned it: %v", staticF[0].ConfidenceReasons)
	}
	if mixedF[0].ConfidenceScore-staticF[0].ConfidenceScore != 15 {
		t.Errorf("expected the all-static group to score 15 lower than the mixed group, got %d vs %d",
			staticF[0].ConfidenceScore, mixedF[0].ConfidenceScore)
	}
}

// TestStaticAssetContextIsOrderIndependent locks F-L6 for the new tag.
func TestStaticAssetContextIsOrderIndependent(t *testing.T) {
	a := headerFindingsFor(t, "/assets/app.js")
	b := headerFindingsFor(t, "/api/v1/users")

	forward := finalize(append(append([]evidence.Evidence{}, a...), b...), "", decision.Options{})
	reverse := finalize(append(append([]evidence.Evidence{}, b...), a...), "", decision.Options{})

	if len(forward) != len(reverse) {
		t.Fatalf("finding count differs by input order: %d vs %d", len(forward), len(reverse))
	}
	for i := range forward {
		if forward[i].ConfidenceScore != reverse[i].ConfidenceScore {
			t.Errorf("finding %d (%s) score differs by input order: %d vs %d",
				i, forward[i].Title, forward[i].ConfidenceScore, reverse[i].ConfidenceScore)
		}
		if strings.Join(forward[i].ConfidenceReasons, "|") != strings.Join(reverse[i].ConfidenceReasons, "|") {
			t.Errorf("finding %d (%s) reasons differ by input order:\n f=%v\n r=%v",
				i, forward[i].Title, forward[i].ConfidenceReasons, reverse[i].ConfidenceReasons)
		}
	}
}

// assertReasonsSumToScore enforces the scorer's "no black boxes" contract: every
// published reason carries an explicit signed delta and they must add up to
// ConfidenceScore. Lines without a leading delta (the lineage trace) contribute
// zero and are skipped.
func assertReasonsSumToScore(t *testing.T, f models.Finding) {
	t.Helper()
	sum := 0
	for _, r := range f.ConfidenceReasons {
		var n int
		if _, err := fmtSscanDelta(r, &n); err != nil {
			continue // a 0-point explanatory line (e.g. the evidence chain)
		}
		sum += n
	}
	if sum != f.ConfidenceScore {
		t.Errorf("reasons do not reconcile with the score for %q: sum=%d score=%d\n%v",
			f.Title, sum, f.ConfidenceScore, f.ConfidenceReasons)
	}
}

// fmtSscanDelta parses the leading signed integer of a reason line
// ("+10 static (SAST) evidence present" → 10, "-15 ..." → -15).
func fmtSscanDelta(reason string, out *int) (int, error) {
	head, _, _ := strings.Cut(reason, " ")
	if head == "" {
		return 0, errNoDelta
	}
	neg := false
	switch head[0] {
	case '+':
		head = head[1:]
	case '-':
		neg = true
		head = head[1:]
	default:
		return 0, errNoDelta
	}
	if head == "" {
		return 0, errNoDelta
	}
	n := 0
	for _, c := range head {
		if c < '0' || c > '9' {
			return 0, errNoDelta
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	*out = n
	return 1, nil
}

type noDeltaError struct{}

func (noDeltaError) Error() string { return "reason line carries no signed delta" }

var errNoDelta = noDeltaError{}
