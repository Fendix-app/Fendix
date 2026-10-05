package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ---------------------------------------------------------------------------
// matchesConfigLeakPath — pure unit table
// ---------------------------------------------------------------------------

func TestMatchesConfigLeakPath(t *testing.T) {
	cases := []struct {
		path     string
		wantHit  bool
		wantPath string
		wantSub  string // substring expected in title
	}{
		{"/.env", true, "/.env", "Environment configuration"},
		{"/.env.local", true, "/.env.local", "Environment configuration"},
		{"/.env.production", true, "/.env.production", "Environment configuration"},
		{"/.htaccess", true, "/.htaccess", "Apache .htaccess"},
		{"/.htpasswd", true, "/.htpasswd", ".htpasswd credentials"},
		{"/web.config", true, "/web.config", "IIS web.config"},
		{"/.npmrc", true, "/.npmrc", "npm authentication"},
		{"/.DS_Store", true, "/.DS_Store", "macOS"},
		// Prefix matches for directory-style leaks (leading "/" stripped only
		// for the internal prefix comparison; we return the cleaned path
		// unchanged, leading slash and all).
		{"/.git/HEAD", true, "/.git/HEAD", "Git repository internals"},
		{"/.git/config", true, "/.git/config", "Git repository internals"},
		{"/.aws/credentials", true, "/.aws/credentials", "AWS credentials directory"},
		{"/.ssh/id_rsa", true, "/.ssh/id_rsa", "SSH key directory"},
		// Bare (no leading slash) directory prefix still matches
		{".git/HEAD", true, ".git/HEAD", "Git repository internals"},
		// Method prefix normalization preserves the leading "/"
		{"GET /.env", true, "/.env", "Environment configuration"},
		{"POST /.git/HEAD", true, "/.git/HEAD", "Git repository internals"},
		// Query string + fragment stripping
		{"/.env?ref=main", true, "/.env", "Environment"},
		{"/.env#fragment", true, "/.env", "Environment"},
		// Negatives
		{"/api/users", false, "", ""},
		{"/", false, "", ""},
		{"", false, "", ""},
		{"/.envrc.example", false, "", ""}, // not a known basename
		{"/env", false, "", ""},            // missing leading dot
		{"/git/config", false, "", ""},     // missing leading dot on directory prefix
	}
	for _, c := range cases {
		gotPath, gotTitle, gotHit := matchesConfigLeakPath(c.path)
		if gotHit != c.wantHit {
			t.Errorf("matchesConfigLeakPath(%q) hit=%v; want %v", c.path, gotHit, c.wantHit)
			continue
		}
		if !c.wantHit {
			continue
		}
		if gotPath != c.wantPath {
			t.Errorf("matchesConfigLeakPath(%q) path=%q; want %q", c.path, gotPath, c.wantPath)
		}
		if !strings.Contains(gotTitle, c.wantSub) {
			t.Errorf("matchesConfigLeakPath(%q) title=%q; want substring %q", c.path, gotTitle, c.wantSub)
		}
	}
}

// ---------------------------------------------------------------------------
// CheckConfigLeak — integration against httptest
// ---------------------------------------------------------------------------

// serveConfigLeak returns an httptest server that serves `body` with
// `status` for any of the listed paths, 404 for everything else.
func serveConfigLeak(t *testing.T, leakPaths map[string]string, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range leakPaths {
		body := body
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckConfigLeak_FiresOn200(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/.env": "DB_PASSWORD=hunter2\nAPI_KEY=sk-live-xyz\n",
	}, http.StatusOK)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: srv.URL + "/.env"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity = %q; want CRITICAL", f.Severity)
	}
	if f.Category != "data_exposure" {
		t.Errorf("category = %q; want data_exposure", f.Category)
	}
	// 4.15: the served-file body is no longer captured into evidence —
	// the 200 + path is the proof. Evidence must NOT contain any
	// secret-shaped substring from the served body, and must say the
	// body was not captured.
	for _, secret := range []string{"hunter2", "sk-live-xyz", "DB_PASSWORD", "API_KEY"} {
		if strings.Contains(f.Evidence, secret) {
			t.Errorf("evidence leaks served-file content %q: %q", secret, f.Evidence)
		}
	}
	if !strings.Contains(f.Evidence, "not captured") {
		t.Errorf("evidence should note body was not captured: %q", f.Evidence)
	}
}

func TestCheckConfigLeak_SkipsOn404(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/.env": "DB_PASSWORD=hunter2",
	}, http.StatusNotFound)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: srv.URL + "/.env"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("got %d findings on 404; want 0 (server isn't serving the file)", len(findings))
	}
}

func TestCheckConfigLeak_SkipsOn500(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/.env": "internal error",
	}, http.StatusInternalServerError)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: srv.URL + "/.env"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("got %d findings on 500; want 0", len(findings))
	}
}

func TestCheckConfigLeak_SkipsUnmatchedPaths(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/api/users": `[{"id":1,"name":"Alice"}]`,
	}, http.StatusOK)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: srv.URL + "/api/users"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("got %d findings on non-config path; want 0", len(findings))
	}
}

func TestCheckConfigLeak_FiresOnGitInternals(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/.git/HEAD": "ref: refs/heads/main\n",
	}, http.StatusOK)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.git/HEAD", FullURL: srv.URL + "/.git/HEAD"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1 for git internals", len(findings))
	}
	if !strings.Contains(findings[0].Title, "Git repository") {
		t.Errorf("title doesn't mention Git: %q", findings[0].Title)
	}
}

// TestCheckConfigLeak_SkipsSPAHTMLFallback reproduces the v0.20 Juice Shop
// false positive: an SPA / catch-all server answers 200 with index.html for
// EVERY unknown path, including /.env. A status-only check fired a phantom
// CRITICAL; the body (HTML) proves it is a framework fallback, not a leak.
func TestCheckConfigLeak_SkipsSPAHTMLFallback(t *testing.T) {
	srv := serveConfigLeak(t, map[string]string{
		"/.env": "<!DOCTYPE html><html><head><title>App</title></head><body>SPA</body></html>",
	}, http.StatusOK)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: srv.URL + "/.env"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("got %d findings; want 0 — an HTML 200 is an SPA catch-all, not a real .env leak", len(findings))
	}
}

// TestCheckConfigLeak_SkipsExplicitHTMLContentType covers the header path:
// even when the body isn't obviously HTML, a text/html Content-Type marks
// the response as a framework fallback.
func TestCheckConfigLeak_SkipsExplicitHTMLContentType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("app shell"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.git/HEAD", FullURL: srv.URL + "/.git/HEAD"}

	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("got %d findings; want 0 — text/html Content-Type means SPA fallback", len(findings))
	}
}

func TestCheckConfigLeak_HandlesEmptyURL(t *testing.T) {
	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: ""}
	findings := CheckConfigLeak(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings on empty URL; got %d", len(findings))
	}
}

// ctx-cancel test omitted: http.Client.Timeout + httptest.Server's
// goroutine model means a `select {}` handler reliably leaks under
// -race and runs the suite past its 120s budget. ctx propagation is
// already covered by Go's stdlib http tests; we trust it here.

// ---------------------------------------------------------------------------
// 4.15: body-sample redaction was removed — the body is no longer
// captured into evidence at all (see TestCheckConfigLeak_FiresOn200,
// which asserts no served-file substring leaks into the finding).
// The former TestSanitizeConfigLeakEvidence_* tests are gone with the
// function they covered.
// ---------------------------------------------------------------------------
