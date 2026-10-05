package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// A blackbox identity is category + rule + normalized endpoint. The blackbox
// scanners emitted no RuleID, so with the rule empty every check in one
// category at one endpoint collapsed into a single identity: eleven header
// checks on `GET /api/data` measured as ONE record, which means suppressing
// "missing CSP" silently suppressed "missing HSTS" and every sibling with it.
//
// That is the worst class of identity failure — a collision HIDES findings,
// where a split merely duplicates them — so it is asserted at the emitters,
// where the fix lives, rather than left to the generated corpus, which
// populates the identity fields itself and so can never catch an emitter that
// populates nothing.

// bareServer answers 200 with no security headers, so every header, CORS and
// cookie check has something to report.
func bareServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func assertDistinctRuleIdentities(t *testing.T, found []ev.Evidence) {
	t.Helper()
	if len(found) == 0 {
		t.Fatal("the check produced no findings — the fixture is not exercising it")
	}

	byRule := map[string][]string{}
	for _, e := range found {
		if e.RuleID == "" {
			t.Errorf("no RuleID on %q — identity falls back to category+endpoint, "+
				"which every sibling check shares", e.Title)
			continue
		}
		byRule[e.RuleID] = append(byRule[e.RuleID], e.Title)
	}

	// Distinct checks must get distinct rules; the same check reported twice
	// legitimately shares one.
	for rule, titles := range byRule {
		seen := map[string]bool{}
		for _, ti := range titles {
			seen[ti] = true
		}
		if len(seen) > 1 {
			t.Errorf("rule %q covers %d different checks: %v", rule, len(seen), titles)
		}
	}

	// And the property that actually matters: no two distinct checks at one
	// endpoint may share a fingerprint.
	byFP := map[string]map[string]bool{}
	for _, e := range found {
		fp := models.Fingerprint(e.ToFinding())
		if byFP[fp] == nil {
			byFP[fp] = map[string]bool{}
		}
		byFP[fp][e.Title] = true
	}
	for fp, titles := range byFP {
		if len(titles) > 1 {
			names := make([]string, 0, len(titles))
			for ti := range titles {
				names = append(names, ti)
			}
			t.Errorf("COLLISION: fingerprint %s covers %d checks: %v", fp[:12], len(titles), names)
		}
	}
}

func TestHeaderChecksHaveDistinctRuleIdentities(t *testing.T) {
	srv := bareServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
	})
	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: srv.URL + "/api/data"}
	found := headersCheck{}.Run(t.Context(), NewCheckContext(&models.ScanConfig{URL: srv.URL}), ep)
	assertDistinctRuleIdentities(t, found)
}

func TestCookieChecksHaveDistinctRuleIdentities(t *testing.T) {
	srv := bareServer(t, func(w http.ResponseWriter, r *http.Request) {
		// One cookie missing every attribute: Secure, HttpOnly and SameSite
		// are three separate checks and must be three identities.
		w.Header().Add("Set-Cookie", "sessionid=abc123; Path=/")
		w.WriteHeader(http.StatusOK)
	})
	ep := Endpoint{Method: "GET", Path: "/login", FullURL: srv.URL + "/login"}
	found := cookieFlagsCheck{}.Run(t.Context(), NewCheckContext(&models.ScanConfig{URL: srv.URL}), ep)
	assertDistinctRuleIdentities(t, found)
}

func TestCORSChecksHaveDistinctRuleIdentities(t *testing.T) {
	srv := bareServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.WriteHeader(http.StatusOK)
	})
	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: srv.URL + "/api/data"}
	found := corsCheck{}.Run(t.Context(), NewCheckContext(&models.ScanConfig{URL: srv.URL}), ep)
	assertDistinctRuleIdentities(t, found)
}

// The headline case stated directly, so a regression names itself.
func TestTwoHeaderChecksAtOneEndpointAreTwoRecords(t *testing.T) {
	srv := bareServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: srv.URL + "/api/data"}
	found := headersCheck{}.Run(t.Context(), NewCheckContext(&models.ScanConfig{URL: srv.URL}), ep)

	fps := map[string]bool{}
	for _, e := range found {
		fps[models.Fingerprint(e.ToFinding())] = true
	}
	if len(fps) != len(found) {
		t.Errorf("%d header findings collapsed into %d identities", len(found), len(fps))
	}
	t.Logf("%d header findings, %d distinct identities", len(found), len(fps))
}
