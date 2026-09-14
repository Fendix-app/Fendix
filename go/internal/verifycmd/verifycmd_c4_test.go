package verifycmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// writeFile writes content to <root>/<rel>, creating parent dirs.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// C4 (v1.1): verify coverage for correlated + active-probe findings.
//
// Before C4 both shapes returned a bare StatusUnknown "not supported". C4
// gives each a real re-test:
//
//   - Correlated: a correlated finding fuses a blackbox URL match with a
//     whitebox file/taint match. Missing source returns unknown because the
//     checkout may be incomplete. Gated-route behavior remains a legacy
//     heuristic, not governed resolution evidence.
//
//   - Active-probe: a blackbox injection/xss/ssrf/... finding produced by an
//     active-tier check. Re-issuing the actual attack payload needs explicit
//     consent (opts.EnableActive), mirroring the original scan's
//     --enable-active gate. Without consent we still give a useful reachability
//     answer: a now-gated endpoint (401/403/404/410) is resolved; a still-open
//     one is reported still-present with a note that a full re-probe needs
//     consent. With consent we re-hit the endpoint and look for the check's
//     signal.

// --- Correlated -----------------------------------------------------------

func TestVerifyCorrelated_BothHalvesHold_StillPresent(t *testing.T) {
	// Blackbox half: the route still answers 200 (reachable). Whitebox half:
	// the tainted file still exists. Correlation holds → still-present.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	code := t.TempDir()
	writeFile(t, code, "app/views.py", "import requests\ndef f(u):\n    return requests.get(u)\n")

	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:                "SEC-CORR-1",
		Title:             "Correlated SSRF — DAST hit + SAST taint path",
		Source:            models.SourceCorrelated,
		Category:          "ssrf",
		Endpoint:          "GET /api/fetch",
		Reachable:         true,
		Route:             &models.Route{Pattern: "/api/fetch"},
		TaintChain:        []models.TaintLink{{Line: 3, Expr: "requests.get(u)"}},
		AffectedEndpoints: []string{"app/views.py:3"},
	}})

	r, err := Run(context.Background(), "SEC-CORR-1", Options{
		BaselinePath: baseline, URL: srv.URL, CodePath: code,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Fatalf("both halves hold → want still-present; got %v (%q)", r.Status, r.Reason)
	}
	if !strings.Contains(strings.ToLower(r.Reason), "correlat") {
		t.Errorf("reason should explain the correlation verdict: %q", r.Reason)
	}
}

func TestVerifyCorrelated_WhiteboxFileGone_Unknown(t *testing.T) {
	// Missing source may mean an incomplete checkout, not a fix.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	code := t.TempDir() // empty — app/views.py does not exist

	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:                "SEC-CORR-2",
		Title:             "Correlated SSRF — DAST hit + SAST taint path",
		Source:            models.SourceCorrelated,
		Category:          "ssrf",
		Endpoint:          "GET /api/fetch",
		Route:             &models.Route{Pattern: "/api/fetch"},
		AffectedEndpoints: []string{"app/views.py:3"},
	}})

	r, err := Run(context.Background(), "SEC-CORR-2", Options{
		BaselinePath: baseline, URL: srv.URL, CodePath: code,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Fatalf("whitebox file gone → want unknown; got %v (%q)", r.Status, r.Reason)
	}
}

func TestVerifyCorrelated_BlackboxGated_Resolved(t *testing.T) {
	// The route now returns 403 (gated) → the DAST half no longer reproduces
	// → correlation broken → resolved, even though the file still exists.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	dir := t.TempDir()
	code := t.TempDir()
	writeFile(t, code, "app/views.py", "x=1\n")

	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:                "SEC-CORR-3",
		Title:             "Correlated SSRF — DAST hit + SAST taint path",
		Source:            models.SourceCorrelated,
		Category:          "ssrf",
		Endpoint:          "GET /api/fetch",
		AffectedEndpoints: []string{"app/views.py:3"},
	}})

	r, err := Run(context.Background(), "SEC-CORR-3", Options{
		BaselinePath: baseline, URL: srv.URL, CodePath: code,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusResolved {
		t.Fatalf("blackbox gated → want resolved; got %v (%q)", r.Status, r.Reason)
	}
}

func TestVerifyCorrelated_NoInputsIsUnknown(t *testing.T) {
	// A correlated finding needs BOTH --url and --code to re-test both halves.
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-CORR-4",
		Title:    "Correlated finding",
		Source:   models.SourceCorrelated,
		Category: "ssrf",
		Endpoint: "GET /api/fetch",
	}})
	r, err := Run(context.Background(), "SEC-CORR-4", Options{
		BaselinePath: baseline, URL: "http://localhost:1", // no --code
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusUnknown {
		t.Fatalf("missing --code → want unknown; got %v", r.Status)
	}
	if !strings.Contains(strings.ToLower(r.Reason), "--code") {
		t.Errorf("reason should name the missing input: %q", r.Reason)
	}
}

// --- Active-probe ---------------------------------------------------------

func TestVerifyActiveProbe_NoConsent_GatedIsResolved(t *testing.T) {
	// An active-probe injection finding whose endpoint now returns 401 →
	// resolved without needing a re-probe (reachability alone answers it).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-ACT-1",
		Title:    "SQL injection (active probe)",
		Source:   models.SourceBlackbox,
		Category: "injection",
		Endpoint: "GET /api/item?id=1",
		Evidence: "active probe: payload ' OR '1'='1 changed the response",
	}})

	r, err := Run(context.Background(), "SEC-ACT-1", Options{
		BaselinePath: baseline, URL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusResolved {
		t.Fatalf("gated active-probe endpoint → want resolved; got %v (%q)", r.Status, r.Reason)
	}
}

func TestVerifyActiveProbe_NoConsent_OpenIsStillPresentWithNote(t *testing.T) {
	// Endpoint still open, no consent to re-probe → still-present, but the
	// reason must say a full re-probe needs --enable-active consent so the
	// verdict isn't mistaken for a confirmed re-exploit.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-ACT-2",
		Title:    "Reflected XSS (active probe)",
		Source:   models.SourceBlackbox,
		Category: "xss",
		Endpoint: "GET /search?q=x",
		Evidence: "active probe: reflected <script> payload",
	}})

	r, err := Run(context.Background(), "SEC-ACT-2", Options{
		BaselinePath: baseline, URL: srv.URL,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Fatalf("open active-probe endpoint w/o consent → want still-present; got %v (%q)", r.Status, r.Reason)
	}
	if !strings.Contains(strings.ToLower(r.Reason), "enable-active") {
		t.Errorf("reason must flag that a full re-probe needs consent: %q", r.Reason)
	}
}

func TestVerifyActiveProbe_Consent_ReprobesEndpoint(t *testing.T) {
	// With EnableActive consent, verify actually re-hits the endpoint; when the
	// reflected signal is gone (endpoint sanitizes now) → resolved.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("clean response, no reflection"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:       "SEC-ACT-3",
		Title:    "Reflected XSS (active probe)",
		Source:   models.SourceBlackbox,
		Category: "xss",
		Endpoint: "GET /search?q=x",
		Evidence: "active probe: reflected <script>alert(1)</script>",
	}})

	r, err := Run(context.Background(), "SEC-ACT-3", Options{
		BaselinePath: baseline, URL: srv.URL, EnableActive: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hits == 0 {
		t.Fatal("consent given but endpoint was never re-probed")
	}
	if r.Status != StatusResolved {
		t.Fatalf("re-probe found no reflection → want resolved; got %v (%q)", r.Status, r.Reason)
	}
}

func TestIsActiveProbeFinding(t *testing.T) {
	cases := []struct {
		f    models.Finding
		want bool
	}{
		{models.Finding{Category: "injection", Source: models.SourceBlackbox, Evidence: "active probe: x"}, true},
		{models.Finding{Category: "xss", Source: models.SourceBlackbox, Evidence: "active probe payload reflected"}, true},
		{models.Finding{Category: "headers", Source: models.SourceBlackbox, Evidence: "CSP missing"}, false},
		{models.Finding{Category: "injection", Source: models.SourceWhitebox, Evidence: "taint chain"}, false},
	}
	for i, c := range cases {
		if got := isActiveProbeFinding(&c.f); got != c.want {
			t.Errorf("case %d: isActiveProbeFinding = %v, want %v", i, got, c.want)
		}
	}
}
