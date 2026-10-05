package verifycmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

func writeBaseline(t *testing.T, dir string, findings []models.Finding) string {
	t.Helper()
	report := reporters.JSONReport{
		Metadata: reporters.ScanMetadata{
			Version: "test",
			Mode:    "blackbox",
		},
		Total:    len(findings),
		Findings: findings,
	}
	data, err := json.Marshal(&report)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ─── baseline / dispatch ────────────────────────────────────────────

func TestRun_NotFoundInBaseline(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{
		{ID: "SEC-001", Title: "Other finding"},
	})
	r, err := Run(context.Background(), "SEC-999", Options{BaselinePath: baseline, URL: "http://localhost:1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusNotFound {
		t.Errorf("want %v; got %v (reason=%q)", StatusNotFound, r.Status, r.Reason)
	}
	if r.Original != nil {
		t.Errorf("Original should be nil when not-found; got %+v", r.Original)
	}
}

func TestRun_MissingBaselinePath(t *testing.T) {
	_, err := Run(context.Background(), "SEC-001", Options{})
	if err == nil {
		t.Fatal("expected error for missing baseline")
	}
}

// ─── URL-anchored ───────────────────────────────────────────────────

func TestVerifyURL_MissingCSPStillPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-001",
		Title:    "Missing Content-Security-Policy header",
		Endpoint: "GET /",
		Category: "headers",
	}})
	r, err := Run(context.Background(), "SEC-001", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Errorf("want still-present; got %v (reason=%q)", r.Status, r.Reason)
	}
}

func TestVerifyURL_MissingCSPResolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-001",
		Title:    "Missing Content-Security-Policy header",
		Endpoint: "GET /",
		Category: "headers",
	}})
	r, err := Run(context.Background(), "SEC-001", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusResolved {
		t.Errorf("want resolved; got %v (reason=%q)", r.Status, r.Reason)
	}
}

func TestVerifyURL_PermissiveCORSStillPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-002",
		Title:    "CORS allows any origin",
		Endpoint: "GET /api",
		Category: "cors",
	}})
	r, err := Run(context.Background(), "SEC-002", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Errorf("want still-present; got %v (reason=%q)", r.Status, r.Reason)
	}
}

func TestVerifyURL_MissingAuthStillPresent(t *testing.T) {
	// The /metrics-style FP scenario: endpoint returns 200 to unauth.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("# HELP python_gc_objects ...\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-009",
		Title:    "Missing authentication on endpoint",
		Endpoint: "GET /metrics",
		Category: "auth_bypass",
	}})
	r, err := Run(context.Background(), "SEC-009", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Errorf("want still-present; got %v (reason=%q)", r.Status, r.Reason)
	}
}

func TestVerifyURL_MissingAuthResolvedWhenGated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-009",
		Title:    "Missing authentication on endpoint",
		Endpoint: "GET /admin",
		Category: "auth_bypass",
	}})
	r, err := Run(context.Background(), "SEC-009", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusResolved {
		t.Errorf("want resolved; got %v (reason=%q)", r.Status, r.Reason)
	}
}

func TestVerifyURL_PassesAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-001",
		Title:    "Missing Content-Security-Policy header",
		Endpoint: "GET /api/v1/",
		Category: "headers",
	}})
	_, err := Run(context.Background(), "SEC-001", Options{
		BaselinePath: baseline,
		URL:          srv.URL,
		Auth:         "Bearer test-token-xyz",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if gotAuth != "Bearer test-token-xyz" {
		t.Errorf("Authorization header not forwarded: got %q", gotAuth)
	}
}

func TestVerifyURL_UnreachableHostIsUnknown(t *testing.T) {
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-001",
		Title:    "Missing Content-Security-Policy header",
		Endpoint: "GET /",
		Category: "headers",
	}})
	r, err := Run(context.Background(), "SEC-001", Options{
		BaselinePath: baseline,
		URL:          "http://127.0.0.1:1", // closed port
		Timeout:      500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Errorf("want unknown; got %v (reason=%q)", r.Status, r.Reason)
	}
}

// ─── shape predicates ───────────────────────────────────────────────

func TestIsURLFinding(t *testing.T) {
	cases := []struct {
		ep   string
		want bool
	}{
		{"GET /admin", true},
		{"POST /api/login", true},
		{"https://api.example.com/x", true},
		{"path/to/file.py:42", false},
		{"requirements.txt", false},
		{"", false},
	}
	for _, c := range cases {
		got := isURLFinding(&models.Finding{Endpoint: c.ep})
		if got != c.want {
			t.Errorf("isURLFinding(%q) = %v; want %v", c.ep, got, c.want)
		}
	}
}

func TestIsFileFinding(t *testing.T) {
	cases := []struct {
		ep   string
		want bool
	}{
		{"path/to/file.py:42", true},
		{"foo.js:1", true},
		{".env.Production", true},
		{".env.bak", true},
		{"GET /admin", false},
		{"https://x.com/y", false},
		{"requirements.txt", false}, // dep finding, handled separately
	}
	for _, c := range cases {
		got := isFileFinding(&models.Finding{Endpoint: c.ep})
		if got != c.want {
			t.Errorf("isFileFinding(%q) = %v; want %v", c.ep, got, c.want)
		}
	}
}

func TestSplitMethodPath(t *testing.T) {
	m, p := splitMethodPath("POST /api/login")
	if m != "POST" || p != "/api/login" {
		t.Errorf("got %q %q", m, p)
	}
	m, p = splitMethodPath("https://x.com/a/b")
	if m != "GET" || p != "/a/b" {
		t.Errorf("absolute URL not split: got %q %q", m, p)
	}
	m, p = splitMethodPath("/path-only")
	if m != "GET" || p != "/path-only" {
		t.Errorf("bare path not handled: got %q %q", m, p)
	}
}
