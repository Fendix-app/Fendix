package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestCheckRateLimit_NoLimiting(t *testing.T) {
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for no rate limiting, got %d", len(findings))
	}
	// An ordinary authenticated-style list read. The observation is real and
	// still reported, but an unlimited GET /api/users is a capacity fact, not
	// the credential-stuffing precondition an unlimited login is — so it is
	// INFO. This is what stops a 700-endpoint scan from emitting one giant WARN
	// that implies equal urgency everywhere.
	if findings[0].Severity != models.SeverityInfo {
		t.Errorf("expected INFO severity for an ordinary GET, got %s", findings[0].Severity)
	}
	// Phase 5.4 deliberate change: the title is now scoped to the bounded
	// burst ("...within N requests") instead of the absolute "No rate
	// limiting detected", which over-claimed (the burst can't disprove a
	// per-minute/hour limiter).
	if !strings.HasPrefix(findings[0].Title, "No rate limiting observed within ") {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	if int(reqCount.Load()) != rateLimitProbeCount {
		t.Errorf("expected %d requests sent, got %d", rateLimitProbeCount, reqCount.Load())
	}
}

// TASK-123 / FP corpus pattern P3: static-file paths don't warrant a
// "no rate limiting" finding — they're served by CDNs / static-file
// middleware, not the API layer. Also avoids the cost of N probe
// requests against an asset.
func TestCheckRateLimit_SkipsStaticFile(t *testing.T) {
	cases := []string{
		"/.DS_Store",
		"/favicon.ico",
		"/robots.txt",
		"/static/app.bundle.js",
		"/assets/style.css",
		"/img/logo.png",
		"/fonts/Inter.woff2",
		"/source.map",
		"/sitemap.xml",
		"/security.txt",
	}
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	for _, path := range cases {
		reqCount.Store(0)
		ep := Endpoint{Method: "GET", Path: path, FullURL: server.URL + path}
		findings := CheckRateLimit(context.Background(), cfg, ep)
		if len(findings) != 0 {
			t.Errorf("%s: expected 0 findings (static file), got %d", path, len(findings))
		}
		if reqCount.Load() != 0 {
			t.Errorf("%s: expected 0 requests sent (early-skip), got %d", path, reqCount.Load())
		}
	}
}

func TestCheckRateLimit_ApiPathStillScanned(t *testing.T) {
	// Negative control — an API path with the same shape but a non-
	// static extension still triggers the full check.
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount.Add(1)
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("api path should still emit finding, got %d", len(findings))
	}
	if reqCount.Load() != int32(rateLimitProbeCount) {
		t.Errorf("api path should send all probes, got %d", reqCount.Load())
	}
}

func TestCheckRateLimit_Returns429(t *testing.T) {
	var reqCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := reqCount.Add(1)
		if count > 5 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when 429 returned, got %d", len(findings))
	}
}

func TestCheckRateLimit_HasRateLimitHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "99")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when rate limit headers present, got %d", len(findings))
	}
}

func TestCheckRateLimit_RetryAfterHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when Retry-After present, got %d", len(findings))
	}
}

// 5.4 / 5.7 — the finding must be honest about scope: it can only
// observe absence of limiting WITHIN N requests, not prove absence of
// slower per-minute/hour limiters. Title + evidence reflect "within N
// requests" and Confidence stays Medium.
func TestRateLimit_FindingIsScopedAndMedium(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Title, "within") {
		t.Errorf("title should be scoped to N requests, got %q", f.Title)
	}
	if !strings.Contains(strings.ToLower(f.Evidence), "slower") &&
		!strings.Contains(strings.ToLower(f.Evidence), "per-minute") &&
		!strings.Contains(strings.ToLower(f.Evidence), "cannot") {
		t.Errorf("evidence should note the scope limitation, got %q", f.Evidence)
	}
	if f.Confidence != models.ConfidenceMedium {
		t.Errorf("confidence = %s, want MEDIUM", f.Confidence)
	}
}

// 5.5 — dedicated category. The finding and the Check.Category() method
// must both report "rate_limiting", not the old "headers".
func TestRateLimit_CategoryIsRateLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Category != "rate_limiting" {
		t.Errorf("finding category = %q, want rate_limiting", findings[0].Category)
	}
	if got := (rateLimitCheck{}).Category(); got != "rate_limiting" {
		t.Errorf("rateLimitCheck{}.Category() = %q, want rate_limiting", got)
	}
}

// 5.6 — budget/error interaction. When most probe requests fail (server
// closes the connection without responding), too few complete to draw a
// conclusion → no finding (inconclusive), NOT a false "unprotected".
func TestRateLimit_InconclusiveWhenProbesFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack and drop the connection so client.Do returns an error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/flaky", FullURL: server.URL + "/api/flaky"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("too few completed probes → inconclusive, expected 0 findings, got %d", len(findings))
	}
}

func TestCheckRateLimit_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ep := Endpoint{Method: "GET", Path: "/api/test", FullURL: server.URL + "/api/test"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckRateLimit(ctx, cfg, ep)
	if findings != nil {
		t.Fatalf("expected nil findings on cancelled context, got %d", len(findings))
	}
}
