package scanner

// Integration tests for the active reflected-XSS check (CWE-79). They drive
// reflectedXSSCheck.Run against loopback httptest servers, so every cfg sets
// AllowPrivate: true — the same relaxation a real scan auto-applies when --url
// resolves to a private/loopback host (see allowPrivate / netguard).
//
// XSS is the highest-FP-risk active check, so the negative tests are
// load-bearing: TestXSS_JSONContentTypeSuppressed (the Content-Type gate) and
// TestXSS_EncodedReflectionSuppressed (the encoded-vs-raw distinction) are the
// two controls that prevent the dominant reflected-XSS false positives. They
// MUST stay green.

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeXSSCfg returns the standard active-scan config for these tests.
func activeXSSCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// xssEP builds an Endpoint declaring a single query param "q", so
// targetsForEndpoint yields exactly one (q, query) target — one canary probe.
func xssEP(server *httptest.Server) Endpoint {
	return Endpoint{
		Method:  "GET",
		Path:    "/search",
		FullURL: server.URL + "/search",
		Params:  []string{"q"},
	}
}

// TestXSS_RawHTMLReflection: handler reflects the raw ?q= value verbatim into a
// text/html body → 1 finding, High severity, High confidence, CWE-79.
func TestXSS_RawHTMLReflection(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Results for: " + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 XSS finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for raw reflection, got %s", f.Confidence)
	}
	if f.Category != "injection" {
		t.Errorf("expected category=injection, got %q", f.Category)
	}
	if !hasRef(f, "CWE-79") {
		t.Errorf("expected CWE-79 reference, got %v", f.References)
	}
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected blackbox source, got %s", f.Source)
	}
}

// TestXSS_ScriptContext: payload echoed inside a <script> block in text/html →
// still raw-survival → High.
func TestXSS_ScriptContext(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><script>var term = '" + q + "';</script></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 XSS finding for script-context reflection, got %d: %+v", len(findings), findings)
	}
	if findings[0].Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for raw script-context reflection, got %s", findings[0].Confidence)
	}
}

// TestXSS_JSONContentTypeSuppressed (LOAD-BEARING): handler reflects the payload
// verbatim but sets Content-Type application/json → 0 findings. Proves the
// Content-Type gate — reflected markup in JSON is not parsed as HTML by the
// browser, so it is not XSS.
func TestXSS_JSONContentTypeSuppressed(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Reflect the payload verbatim — the ONLY reason this must not flag is
		// the non-HTML Content-Type.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"query": "` + q + `"}`))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: application/json reflection must produce 0 findings (Content-Type gate), got %d: %+v", len(findings), findings)
	}
}

// TestXSS_EncodedReflectionSuppressed (LOAD-BEARING): handler html-entity-encodes
// the reflection in text/html → 0 findings. Proves the encoded-vs-raw control:
// &lt;svg/onload=...&gt; is safe because the browser renders it as text.
func TestXSS_EncodedReflectionSuppressed(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		// Proper output-encoding: the marker reflects, but every HTML
		// metacharacter is entity-encoded.
		_, _ = w.Write([]byte("<html><body>Results for: " + html.EscapeString(q) + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: HTML-entity-encoded reflection must produce 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestXSS_MarkerOnlyNoMetacharsNoFinding: handler reflects ONLY the marker
// (strips the HTML metacharacters) → 0 findings. Mere reflection without the
// surviving brackets is not XSS.
func TestXSS_MarkerOnlyNoMetacharsNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		// Strip everything that isn't alphanumeric — leaves the fendixXSS<hex>
		// marker intact but removes <, >, /, " entirely.
		var b strings.Builder
		for _, c := range q {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
				b.WriteRune(c)
			}
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + b.String() + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when only the marker reflects (no metacharacters), got %d: %+v", len(findings), findings)
	}
}

// TestXSS_4xxSkipped: handler 404s and echoes the query → 0 findings. HTML
// error pages that echo the query string are a self-reflection FP.
func TestXSS_4xxSkipped(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><body>Not found: " + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a 4xx response echoing the query, got %d: %+v", len(findings), findings)
	}
}

// TestXSS_NotActiveNoFinding: EnableActive=false → 0 findings, even against a
// blatantly vulnerable handler.
func TestXSS_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>" + q + "</body></html>"))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when EnableActive=false, got %d: %+v", len(findings), findings)
	}
}

// TestXSS_NoReflection: static text/html body with no echo → 0 findings.
func TestXSS_NoReflection(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Welcome to the search page.</body></html>"))
	}))
	defer server.Close()

	cfg := activeXSSCfg()
	findings := reflectedXSSCheck{}.Run(context.Background(), NewCheckContext(cfg), xssEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when nothing is reflected, got %d: %+v", len(findings), findings)
	}
}
