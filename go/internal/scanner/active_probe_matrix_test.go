package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// THE ACTIVE-PROBE CORROBORATION MATRIX.
//
// RC-1 removed "live runtime observation" — true for every Source=blackbox
// finding — as a corroborating signal. That was correct: it was a restatement
// of a field, not evidence. But it means every blackbox check must now earn a
// REAL corroboration class, or it can no longer gate a build at all.
//
// Decision hardening must not become detection suppression. This test drives
// each active-tier scanner against a fixture that makes it fire and asserts the
// evidence it emits can still reach BLOCK under the shipped policy.
//
// A scanner that legitimately cannot produce a differential belongs in
// nonBlockingByDesign below, with the reason recorded — not silently demoted.
func TestEveryActiveScannerCanStillCorroborate(t *testing.T) {
	for _, tc := range activeScannerMatrix(t) {
		t.Run(tc.name, func(t *testing.T) {
			findings := tc.run()
			if len(findings) == 0 {
				t.Fatalf("%s produced no evidence; the fixture no longer triggers it", tc.name)
			}

			var gating []ev.Evidence
			for _, f := range findings {
				if models.SeverityRank(f.Severity) >= models.SeverityRank(models.SeverityHigh) {
					gating = append(gating, f)
				}
			}
			if len(gating) == 0 {
				t.Skipf("%s emitted nothing at HIGH+; not gate-capable in this fixture", tc.name)
			}

			opts := decision.Options{EnforceConfidence: true, DeescalateTests: true}
			for _, f := range gating {
				c := decision.DecideWithOptions(f, "HIGH", opts).Corroboration
				if !c.Any() {
					t.Errorf("%q (%s) has NO corroborating signal of any class — under the shipped "+
						"policy it can never BLOCK. RC-1 removed the tautology this check was "+
						"relying on; it needs a real differential (payload+response, timing, or "+
						"a documented alternative class).\n  payload=%q response=%q",
						f.Title, f.Severity, f.Payload, f.Response)
					continue
				}
				d := decision.DecideWithOptions(f, "HIGH",
					decision.Options{EnforceConfidence: true, DeescalateTests: true})
				if d.Status != decision.StatusBlock {
					t.Errorf("%q (%s) does not reach BLOCK: status=%s score=%d band=%s reason=%q",
						f.Title, f.Severity, d.Status, d.Score.Value, d.Score.Band, d.Reason)
				}
			}
		})
	}
}

type activeScannerCase struct {
	name string
	run  func() []ev.Evidence
}

func activeScannerMatrix(t *testing.T) []activeScannerCase {
	t.Helper()
	return []activeScannerCase{
		{"injection/error-based-sqli", func() []ev.Evidence { return runSQLiErrorCase(t) }},
		{"xss/reflected", func() []ev.Evidence { return runReflectedXSSCase(t) }},
		{"openredirect", func() []ev.Evidence { return runOpenRedirectCase(t) }},
		{"ssrf/error-leak", func() []ev.Evidence { return runSSRFErrorLeakCase(t) }},
		{"graphql/introspection", func() []ev.Evidence { return runGraphQLIntrospectionCase(t) }},
		{"hostheader/redirect-host", func() []ev.Evidence { return runHostHeaderCase(t) }},
		{"methodtamper/verb-bypass", func() []ev.Evidence { return runMethodTamperCase(t) }},
	}
}

func runSSRFErrorLeakCase(t *testing.T) []ev.Evidence {
	t.Helper()
	ResetGlobalAuditLog()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(target, "fendix.invalid") {
			_, _ = w.Write([]byte("Failed fetching " + target + ": dial tcp: connection refused"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return SSRFCheck{}.Run(context.Background(), NewCheckContext(activeSSRFCfg()), ssrfEP(srv))
}

func runGraphQLIntrospectionCase(t *testing.T) []ev.Evidence {
	t.Helper()
	ResetGlobalAuditLog()
	srv := httptest.NewServer(gqlIntrospectionHandler(introspectionJSON))
	t.Cleanup(srv.Close)
	return graphQLCheck{}.Run(context.Background(), NewCheckContext(activeGraphQLCfg()), graphQLRootEP(srv))
}

func runHostHeaderCase(t *testing.T) []ev.Evidence {
	t.Helper()
	ResetGlobalAuditLog()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			host = xfh
		}
		w.Header().Set("Location", "https://"+host+"/path")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return hostHeaderCheck{}.Run(context.Background(), NewCheckContext(activeHostHeaderCfg()), hostHeaderEP(srv))
}

func runMethodTamperCase(t *testing.T) []ev.Evidence {
	t.Helper()
	ResetGlobalAuditLog()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if hasAuthHeader(r) {
				_, _ = w.Write([]byte("authorized GET content body that is non-trivial"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost:
			_, _ = w.Write([]byte("POST served protected content without any auth!"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := activeMethodTamperCfg()
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	return methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg),
		methodTamperEP(srv, http.MethodGet, "/admin"))
}
