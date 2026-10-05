package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeProbeCase drives ONE production active-probe check against a fixture
// target that makes it fire. These go through the real entry points — no
// hand-built Evidence — so the test observes what the scanner actually emits.
type activeProbeCase struct {
	name string
	run  func() []ev.Evidence
}

func activeProbeCases(t *testing.T) []activeProbeCase {
	t.Helper()
	return []activeProbeCase{
		{name: "error-based SQLi", run: func() []ev.Evidence { return runSQLiErrorCase(t) }},
		{name: "reflected XSS", run: func() []ev.Evidence { return runReflectedXSSCase(t) }},
		{name: "open redirect", run: func() []ev.Evidence { return runOpenRedirectCase(t) }},
	}
}

// activeCfg builds the minimum config the active tier requires. AllowPrivate is
// on because every fixture is an httptest server on loopback, which the SSRF
// egress guard blocks by default.
func activeCfg(target string) *models.ScanConfig {
	return &models.ScanConfig{
		URL:          target,
		EnableActive: true,
		AllowPrivate: true,
	}
}

func runSQLiErrorCase(t *testing.T) []ev.Evidence {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A MySQL error signature — matches sqliErrorPatterns[0].
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>You have an error in your SQL syntax near '''</body></html>"))
	}))
	t.Cleanup(srv.Close)

	ep := Endpoint{Method: "GET", Path: "/search", FullURL: srv.URL + "/search", Params: []string{"q"}}
	return CheckInjection(context.Background(), activeCfg(srv.URL), ep)
}

func runReflectedXSSCase(t *testing.T) []ev.Evidence {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo every query value back RAW into an HTML body — the un-encoded
		// reflection the XSS check looks for.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>"))
		for _, vs := range r.URL.Query() {
			for _, v := range vs {
				_, _ = w.Write([]byte(v))
			}
		}
		_, _ = w.Write([]byte("</body></html>"))
	}))
	t.Cleanup(srv.Close)

	cfg := activeCfg(srv.URL)
	ep := Endpoint{Method: "GET", Path: "/echo", FullURL: srv.URL + "/echo", Params: []string{"q"}}
	return reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
}

func runOpenRedirectCase(t *testing.T) []ev.Evidence {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect verbatim to whatever was supplied — the off-origin 3xx the
		// check confirms against its sentinel host.
		for _, param := range redirectParams {
			if dest := r.URL.Query().Get(param); dest != "" {
				w.Header().Set("Location", dest)
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	cfg := activeCfg(srv.URL)
	ep := Endpoint{Method: "GET", Path: "/go", FullURL: srv.URL + "/go"}
	return openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
}
