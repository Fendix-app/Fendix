package scanner

// These tests scan loopback httptest servers, so each config sets
// AllowPrivate: true — exactly what a real scan auto-applies when the --url
// target resolves to a private/loopback host (see allowPrivate /
// netguard.TargetIsPrivate).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestIsStaticAssetPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// The extension families the B4 static-asset context covers.
		{"/assets/app.js", true},
		{"/static/site.css", true},
		{"/img/logo.png", true},
		{"/img/hero.jpg", true},
		{"/img/hero.jpeg", true},
		{"/img/spinner.gif", true},
		{"/icons/menu.svg", true},
		{"/favicon.ico", true},
		{"/fonts/inter.woff", true},
		{"/fonts/inter.woff2", true},
		{"/assets/app.js.map", true},
		{"/robots.txt", true},
		{"/sitemap.xml", true},
		{"/.DS_Store", true},

		// API routes must never be classified as static — a false positive here
		// silently de-escalates real findings.
		{"/api/v1/users", false},
		{"/api/v1/users/42", false},
		{"/", false},
		{"/login", false},
		{"/health", false},

		// Regression gate: GENERATED-content routes. These extensions used to
		// be in the regex, which made the rate-limit check skip exactly the
		// expensive export endpoints CWE-770 is about, and de-escalated their
		// header findings. A generated .pdf/.zip is an API route, not a CDN
		// asset.
		{"/api/v1/reports/export.pdf", false},
		{"/api/invoices/2024.zip", false},
		{"/api/backup.tar.gz", false},
		{"/api/v1/module.wasm", false},
		// An extension appearing mid-path is not a static asset; the regex is
		// anchored at the end for exactly this reason.
		{"/api/css/settings", false},
		{"/api/app.js/callback", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := isStaticAssetPath(tc.path); got != tc.want {
				t.Errorf("isStaticAssetPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestResponseContextForPrecedence locks the ordering contract: an auth-gated
// status wins over the static-asset classification, so the pre-existing "4xx"
// behaviour is bit-for-bit unchanged.
func TestResponseContextForPrecedence(t *testing.T) {
	tests := []struct {
		name   string
		status int
		path   string
		want   string
	}{
		{"api route, 200", 200, "/api/users", ""},
		{"api route, 401", 401, "/api/users", "4xx"},
		{"static asset, 200", 200, "/assets/app.js", "static-asset"},
		{"static asset, 401 → 4xx wins", 401, "/assets/app.js", "4xx"},
		{"static asset, 403 → 4xx wins", 403, "/favicon.ico", "4xx"},
		{"api route, 301 (not a de-escalation context)", 301, "/api/users", ""},
		{"static asset, 429 → 4xx wins", 429, "/static/site.css", "4xx"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseContextFor(tc.status, tc.path); got != tc.want {
				t.Errorf("responseContextFor(%d, %q) = %q, want %q", tc.status, tc.path, got, tc.want)
			}
		})
	}
}

// TestCheckHeadersTagsStaticAssetContext is the scanner half of the B4
// static-asset fix. Before it, no producer ever emitted "static-asset", so the
// confidence scorer's branch for it was unreachable.
//
// The header IS genuinely absent on this response — that observation is real,
// so the finding must survive (Rule 3). Only its confidence context changes.
func TestCheckHeadersTagsStaticAssetContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/assets/app.js", FullURL: server.URL + "/assets/app.js"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("no header findings on a static asset — evidence must be preserved, not suppressed")
	}
	for _, f := range findings {
		if f.ResponseContext != "static-asset" {
			t.Errorf("finding %q ResponseContext = %q, want \"static-asset\"", f.Title, f.ResponseContext)
		}
	}
}

// TestCheckHeadersDoesNotTagAPIRoute — the tag must be targeted.
func TestCheckHeadersDoesNotTagAPIRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/v1/users", FullURL: server.URL + "/api/v1/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckHeaders(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("expected header findings on a bare 200 response")
	}
	for _, f := range findings {
		if f.ResponseContext != "" {
			t.Errorf("API-route finding %q was tagged %q; it must carry no de-escalation context",
				f.Title, f.ResponseContext)
		}
	}
}

// TestCheckHeadersStillTagsFourXX guards the pre-existing behaviour: the 4xx
// context must keep working, and must win over static-asset when both apply.
func TestCheckHeadersStillTagsFourXX(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"api route", "/api/v1/admin"},
		{"static asset (4xx takes precedence)", "/assets/admin.js"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()

			ep := Endpoint{Method: "GET", Path: tc.path, FullURL: server.URL + tc.path}
			cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

			findings := CheckHeaders(context.Background(), cfg, ep)
			if len(findings) == 0 {
				t.Fatal("expected header findings on a 401 response (4.11: 401s are not skipped)")
			}
			for _, f := range findings {
				if f.ResponseContext != "4xx" {
					t.Errorf("finding %q ResponseContext = %q, want \"4xx\"", f.Title, f.ResponseContext)
				}
			}
		})
	}
}

// TestCheckCORSTagsStaticAssetContext covers the CORS half. A permissive CORS
// policy on a CDN-served asset is a real observation, just a weaker one than
// the same policy on an API route.
func TestCheckCORSTagsStaticAssetContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/assets/app.js", FullURL: server.URL + "/assets/app.js"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("no CORS findings on a static asset — evidence must be preserved, not suppressed")
	}
	for _, f := range findings {
		if f.ResponseContext != "static-asset" {
			t.Errorf("finding %q ResponseContext = %q, want \"static-asset\"", f.Title, f.ResponseContext)
		}
	}
}

// TestCheckCORSDoesNotTagAPIRoute — targeted, same as headers.
func TestCheckCORSDoesNotTagAPIRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) == 0 {
		t.Fatal("expected a CORS finding for wildcard+credentials")
	}
	for _, f := range findings {
		if f.ResponseContext != "" {
			t.Errorf("API-route CORS finding was tagged %q; it must carry no context", f.ResponseContext)
		}
	}
}

// TestRateLimitStillSkipsStaticAssets documents the deliberate asymmetry with
// headers/CORS. Rate limiting on a CDN/static-middleware-served file is not an
// app-layer control, so there is no security observation to preserve — this is
// the "no signal → skip" side of the rule, not a suppressed finding. Fendix
// de-escalates evidence; it does not manufacture evidence in order to
// de-escalate it.
func TestRateLimitStillSkipsStaticAssets(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/favicon.ico", FullURL: server.URL + "/favicon.ico"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	if findings := CheckRateLimit(context.Background(), cfg, ep); len(findings) != 0 {
		t.Errorf("expected no rate-limit findings on a static asset, got %d", len(findings))
	}
	if hits != 0 {
		t.Errorf("static-asset skip should cost zero requests, sent %d", hits)
	}
}

// TestCheckCookieFlagsPreservesAuthGatedEvidence is the regression gate for a
// suppression the audit surfaced: cookie-flags returned nil for ANY status
// >= 400, so a login endpoint answering 401 while issuing a session cookie
// without HttpOnly produced no finding at all. That is arguably the most
// security-relevant Set-Cookie a scan can observe, and it was discarded.
//
// It is now preserved and de-escalated via the shared B4 context, matching the
// header and CORS checks.
func TestCheckCookieFlagsPreservesAuthGatedEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abcdef0123456789abcdef; Path=/")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	ep := Endpoint{Method: "POST", Path: "/api/login", FullURL: server.URL + "/api/login"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := cookieFlagsCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
	if len(findings) == 0 {
		t.Fatal("no cookie findings on a 401 that issued a session cookie — the evidence " +
			"must be preserved and de-escalated, not suppressed")
	}
	for _, f := range findings {
		if f.ResponseContext != "4xx" {
			t.Errorf("finding %q ResponseContext = %q, want \"4xx\"", f.Title, f.ResponseContext)
		}
	}
}

// A genuine no-signal response is still skipped outright.
func TestCheckCookieFlagsStillSkipsMissingAndServerError(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone, http.StatusInternalServerError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "session=abcdef0123456789abcdef; Path=/")
			w.WriteHeader(code)
		}))
		ep := Endpoint{Method: "GET", Path: "/gone", FullURL: server.URL + "/gone"}
		cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
		if f := (cookieFlagsCheck{}).Run(context.Background(), NewCheckContext(cfg), ep); len(f) != 0 {
			t.Errorf("status %d should be skipped (framework noise), got %d findings", code, len(f))
		}
		server.Close()
	}
}

// A normal 2xx API route carries no de-escalation context.
func TestCheckCookieFlagsUntaggedOnAPIRoute(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abcdef0123456789abcdef; Path=/")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/me", FullURL: server.URL + "/api/me"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := cookieFlagsCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)
	if len(findings) == 0 {
		t.Fatal("expected cookie findings on a 200 session cookie")
	}
	for _, f := range findings {
		if f.ResponseContext != "" {
			t.Errorf("API-route cookie finding tagged %q; want no context", f.ResponseContext)
		}
	}
}
