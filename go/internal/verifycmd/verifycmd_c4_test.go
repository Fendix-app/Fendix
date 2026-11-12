package verifycmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
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
	// Changed 2026-11-12 (contract C5.6): this was "resolved". A correlated SSRF's
	// DAST half comes from an active probe, and a gated route (403) is a
	// reachability change, not proof the probe's finding was fixed, so the
	// result is unknown. The test keeps its name so the history reads.
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
	if r.Status != StatusUnknown || !strings.Contains(r.Reason, "not proof of remediation") {
		t.Fatalf("blackbox gated on an active-probe half → want unknown; got %v (%q)", r.Status, r.Reason)
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

// Decision 2026-11-12 (amendment 1, contract C5.6): an active-probe finding is
// never resolved by verify. 401/403/404/410 say the route changed, not that it
// was fixed, and a response without the signal says one request did not carry
// it. Only a reproduced marker is a result (still-present); everything else is
// unknown with a reason naming what was observed.

func activeBaseline(t *testing.T, id, category, endpoint, evidence string) string {
	t.Helper()
	return writeBaseline(t, t.TempDir(), []models.Finding{{
		ID: id, Title: "Injection (active probe)", Source: models.SourceBlackbox,
		Category: category, Endpoint: endpoint, Evidence: evidence,
	}})
}

func TestVerifyActiveProbe_GatedStatusIsNeverResolved(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone} {
		for _, consent := range []bool{false, true} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
			baseline := activeBaseline(t, "SEC-ACT-1", "injection", "GET /api/item?id=1", "active probe: payload ' OR '1'='1 changed the response")
			r, err := Run(context.Background(), "SEC-ACT-1", Options{BaselinePath: baseline, URL: srv.URL, EnableActive: consent})
			srv.Close()
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if r.Status != StatusUnknown {
				t.Fatalf("HTTP %d (consent=%v) -> %v (%q), want unknown: a gated status is not proof of remediation", code, consent, r.Status, r.Reason)
			}
			if !strings.Contains(r.Reason, "not proof of remediation") || !strings.Contains(r.Reason, strconv.Itoa(code)) {
				t.Errorf("reason must name what was observed: %q", r.Reason)
			}
		}
	}
}

func TestVerifyActiveProbe_RateLimitAndTemporaryFailureAreUnknown(t *testing.T) {
	for _, code := range []int{429, 502, 503, 504} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		baseline := activeBaseline(t, "SEC-ACT-1", "injection", "GET /api/item?id=1", "active probe: payload x")
		r, err := Run(context.Background(), "SEC-ACT-1", Options{BaselinePath: baseline, URL: srv.URL, EnableActive: true})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusUnknown || !strings.Contains(r.Reason, "proves nothing") {
			t.Fatalf("HTTP %d -> %v (%q), want unknown", code, r.Status, r.Reason)
		}
	}
}

func TestVerifyActiveProbe_NoResponseIsUnknown(t *testing.T) {
	// A target that never answers (stall) and one that resets: nothing was
	// evaluated, so nothing is concluded.
	release := make(chan struct{})
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer stall.Close()
	defer close(release)
	reset := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _ := w.(http.Hijacker).Hijack()
		c.Close()
	}))
	defer reset.Close()
	for name, base := range map[string]string{"stall": stall.URL, "reset": reset.URL} {
		baseline := activeBaseline(t, "SEC-ACT-1", "injection", "GET /api/item?id=1", "active probe: payload x")
		r, err := Run(context.Background(), "SEC-ACT-1", Options{BaselinePath: baseline, URL: base, EnableActive: true, Timeout: 200 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusUnknown || !strings.Contains(r.Reason, "not evaluated") {
			t.Fatalf("%s -> %v (%q), want unknown", name, r.Status, r.Reason)
		}
	}
}

func TestVerifyActiveProbe_NoConsent_OpenIsUnknownWithNote(t *testing.T) {
	// Endpoint still open, no consent to re-probe: a reachability observation,
	// not a re-test, and not an assertion that the finding is still present.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	baseline := activeBaseline(t, "SEC-ACT-2", "xss", "GET /search?q=x", "active probe: reflected <script> payload")
	r, err := Run(context.Background(), "SEC-ACT-2", Options{BaselinePath: baseline, URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusUnknown {
		t.Fatalf("open endpoint w/o consent -> %v (%q), want unknown", r.Status, r.Reason)
	}
	if !strings.Contains(strings.ToLower(r.Reason), "enable-active") || !strings.Contains(r.Reason, "reachability") {
		t.Errorf("reason must say it is a reachability observation and that a re-probe needs consent: %q", r.Reason)
	}
}

func TestVerifyActiveProbe_Consent_NoSignalIsUnknownNotResolved(t *testing.T) {
	// With consent verify re-hits the endpoint. A clean response is one
	// response: it does not prove the vulnerability is gone.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("clean response, no reflection"))
	}))
	defer srv.Close()
	baseline := activeBaseline(t, "SEC-ACT-3", "xss", "GET /search?q=x", "active probe: reflected <script>alert(1)</script>")
	r, err := Run(context.Background(), "SEC-ACT-3", Options{BaselinePath: baseline, URL: srv.URL, EnableActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if hits == 0 {
		t.Fatal("consent given but endpoint was never re-probed")
	}
	if r.Status != StatusUnknown || r.Status == StatusResolved {
		t.Fatalf("re-probe found no reflection -> %v (%q), want unknown, never resolved", r.Status, r.Reason)
	}
}

func TestVerifyActiveProbe_Consent_ReproducedSignalIsStillPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><script>alert(1)</script></html>"))
	}))
	defer srv.Close()
	baseline := activeBaseline(t, "SEC-ACT-4", "xss", "GET /search?q=x", "active probe: reflected <script>alert(1)</script>")
	r, err := Run(context.Background(), "SEC-ACT-4", Options{BaselinePath: baseline, URL: srv.URL, EnableActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusStillPresent {
		t.Fatalf("reproduced marker -> %v (%q), want still-present", r.Status, r.Reason)
	}
}

func TestVerifyActiveProbe_AllCheckCategoriesAreRecognised(t *testing.T) {
	// The categories the checks actually stamp, not only the hyphenated spellings.
	for _, cat := range []string{"injection", "ssrf", "redirect", "host_header", "method_tamper", "graphql", "open-redirect", "host-header", "method-tamper"} {
		f := models.Finding{Source: models.SourceBlackbox, Category: cat, Evidence: "active probe: payload x"}
		if !isActiveProbeFinding(&f) {
			t.Errorf("category %q is not recognised as an active-probe finding", cat)
		}
	}
}

func TestVerifyCorrelated_ActiveProbeHalfGatedIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	code := t.TempDir()
	writeFile(t, code, "app/views.py", "def f(u):\n    return u\n")
	baseline := writeBaseline(t, t.TempDir(), []models.Finding{{
		ID: "SEC-CORR-ACT", Title: "SQL injection", Source: models.SourceCorrelated, Category: "injection",
		Endpoint: "GET /api/item?id=1", AffectedEndpoints: []string{"app/views.py:2"}, Evidence: "active probe: payload ' OR 1=1",
	}})
	r, err := Run(context.Background(), "SEC-CORR-ACT", Options{BaselinePath: baseline, URL: srv.URL, CodePath: code})
	if err != nil {
		t.Fatal(err)
	}
	if r.Status == StatusResolved {
		t.Fatalf("a correlated active-probe finding must not resolve on a gated status: %v (%q)", r.Status, r.Reason)
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
		// The category decides. These evidence texts carry neither "active probe"
		// nor "payload" (the open-redirect and host-header checks word it
		// differently); they used to fall into the generic fallback, where a 404
		// reads as "presumed gated or removed" and the finding as resolved.
		{models.Finding{Category: "redirect", Source: models.SourceBlackbox, Evidence: "Open redirect confirmed: Location points at the canary host"}, true},
		{models.Finding{Category: "host_header", Source: models.SourceBlackbox, Evidence: "Location host follows the Host header"}, true},
	}
	for i, c := range cases {
		if got := isActiveProbeFinding(&c.f); got != c.want {
			t.Errorf("case %d: isActiveProbeFinding = %v, want %v", i, got, c.want)
		}
	}
}
