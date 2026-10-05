package scanner

// Integration tests for the active HTTP method-tampering check (CWE-650/693/285).
// They drive methodTamperCheck.Run against loopback httptest servers, so every
// cfg sets AllowPrivate:true (the netguard egress guard would otherwise block the
// dial to the 127.0.0.1 test server — same paradox as the SSRF / host-header /
// graphql tests).
//
// LOAD-BEARING negative tests that MUST stay green:
//   - TestMethodTamper_HEADEmptyBodyNoFinding: a 2xx on HEAD with an empty body
//     is the EXPECTED HEAD contract, NOT a verb-bypass.
//   - TestMethodTamper_PublicEndpointNoBypassProbe: a public 200→200 verb flip
//     (no auth configured, no gate signal) is NOT a bypass.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeMethodTamperCfg returns the standard active-scan config for these tests.
// AllowPrivate:true is mandatory so the egress guard does not block the dial to
// the loopback httptest server.
func activeMethodTamperCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// methodTamperEP builds an Endpoint at the given path with the given canonical
// method.
func methodTamperEP(server *httptest.Server, method, path string) Endpoint {
	return Endpoint{Method: method, Path: path, FullURL: server.URL + path}
}

// findMethodTamperFinding returns the first finding whose Title contains the
// given substring (case-insensitive).
func findMethodTamperFinding(findings []ev.Evidence, titleContains string) (ev.Evidence, bool) {
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), strings.ToLower(titleContains)) {
			return f, true
		}
	}
	return ev.Evidence{}, false
}

// hasAuthHeader reports whether the request carries an Authorization header (the
// auth-bypass tests gate the canonical verb on this header).
func hasAuthHeader(r *http.Request) bool {
	return r.Header.Get("Authorization") != ""
}

// TestMethodTamper_VerbBypass: server gates GET WITHOUT auth (401) but returns
// 200 for POST WITHOUT auth → HIGH verb-based access-control bypass listing POST.
func TestMethodTamper_VerbBypass(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Canonical verb is gated unless authed.
			if hasAuthHeader(r) {
				_, _ = w.Write([]byte("authorized GET content body that is non-trivial"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost:
			// The auth filter does not cover POST — leaks protected content.
			_, _ = w.Write([]byte("POST served protected content without any auth!"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	ep := methodTamperEP(server, http.MethodGet, "/admin")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	f, ok := findMethodTamperFinding(findings, "bypass")
	if !ok {
		t.Fatalf("expected a verb-based access-control bypass finding, got %+v", findings)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Category != "method_tamper" {
		t.Errorf("expected category=method_tamper, got %q", f.Category)
	}
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected source=blackbox, got %q", f.Source)
	}
	if !strings.Contains(strings.ToUpper(f.Evidence), "POST") {
		t.Errorf("expected evidence to list the bypassing verb POST, got %q", f.Evidence)
	}
	if !hasRef(f, "CWE-285") {
		t.Errorf("expected CWE-285 reference, got %v", f.References)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected High confidence for a clean 401→200 flip, got %s", f.Confidence)
	}
}

// TestMethodTamper_TRACEEnabled: server 200s on TRACE echoing the request →
// MEDIUM XST (CWE-693).
func TestMethodTamper_TRACEEnabled(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodTrace:
			// Echo the request line + headers back (the XST signature).
			w.Header().Set("Content-Type", "message/http")
			_, _ = w.Write([]byte("TRACE " + r.URL.Path + " HTTP/1.1\r\nHost: " + r.Host + "\r\n"))
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost:
			// Canonical GET (and other safe verbs) are a normal public page; only
			// TRACE is dangerous-enabled so the XST signal is isolated.
			_, _ = w.Write([]byte("hello"))
		default:
			// PUT / DELETE are properly rejected.
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	ep := methodTamperEP(server, http.MethodGet, "/")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	// TRACE/XST is folded into the single dangerous-method finding (CWE-693).
	f, ok := findMethodTamperFinding(findings, "dangerous method")
	if !ok {
		t.Fatalf("expected a dangerous-method (TRACE/XST) finding, got %+v", findings)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for TRACE/XST, got %s", f.Severity)
	}
	if !hasRef(f, "CWE-693") {
		t.Errorf("expected CWE-693 reference for TRACE/XST, got %v", f.References)
	}
	if !strings.Contains(strings.ToUpper(f.Evidence), "TRACE") {
		t.Errorf("expected evidence to mention TRACE, got %q", f.Evidence)
	}
}

// TestMethodTamper_PUTAccepted: server 200/201s on PUT → MEDIUM dangerous-method
// (CWE-650).
func TestMethodTamper_PUTAccepted(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusCreated) // 201 — accepted
			_, _ = w.Write([]byte("created"))
			return
		}
		// Canonical GET is a normal public page.
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	ep := methodTamperEP(server, http.MethodGet, "/files/report")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	f, ok := findMethodTamperFinding(findings, "dangerous method")
	if !ok {
		t.Fatalf("expected a dangerous-method finding, got %+v", findings)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for PUT accepted, got %s", f.Severity)
	}
	if !hasRef(f, "CWE-650") {
		t.Errorf("expected CWE-650 reference, got %v", f.References)
	}
	if !strings.Contains(strings.ToUpper(f.Evidence), "PUT") {
		t.Errorf("expected evidence to list PUT, got %q", f.Evidence)
	}
}

// TestMethodTamper_HEADEmptyBodyNoFinding: server gates GET (401 no auth) but
// HEAD returns 200 with an EMPTY body → NO bypass finding. LOAD-BEARING: an
// empty 2xx HEAD is the expected HEAD contract, not a verb-bypass.
func TestMethodTamper_HEADEmptyBodyNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if hasAuthHeader(r) {
				_, _ = w.Write([]byte("authorized content"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodHead:
			// 200 with no body and no data-bearing headers (Content-Length 0).
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	ep := methodTamperEP(server, http.MethodGet, "/admin")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if _, ok := findMethodTamperFinding(findings, "bypass"); ok {
		t.Fatalf("LOAD-BEARING: an empty-body HEAD 2xx must NOT be a verb-bypass; got %+v", findings)
	}
}

// TestMethodTamper_PublicEndpointNoBypassProbe: cfg.Auth==nil, canonical GET is a
// public 200, alternate verbs are also 200 → NO bypass finding. LOAD-BEARING
// trigger gate: a public 200→200 verb flip is not a bypass. (Dangerous-method
// probes may still run; we assert no BYPASS finding specifically.)
func TestMethodTamper_PublicEndpointNoBypassProbe(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every safe/representative verb is public 200 with a body; PUT/DELETE/
		// TRACE are NOT accepted (so no dangerous-method noise either).
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions:
			_, _ = w.Write([]byte("public page content for everyone"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg() // Auth == nil
	ep := methodTamperEP(server, http.MethodGet, "/")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if _, ok := findMethodTamperFinding(findings, "bypass"); ok {
		t.Fatalf("LOAD-BEARING: a public 200→200 verb flip (no auth, no gate signal) must NOT be a bypass; got %+v", findings)
	}
}

// TestMethodTamper_MultipleVerbsOneFinding: two verbs (POST and PUT) both bypass
// the GET gate → exactly ONE bypass finding listing BOTH verbs (deduped).
func TestMethodTamper_MultipleVerbsOneFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if hasAuthHeader(r) {
				_, _ = w.Write([]byte("authorized content non-trivial body"))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost, http.MethodPut:
			// Both alternate verbs leak protected content without auth.
			_, _ = w.Write([]byte("leaked protected content via alternate verb"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	ep := methodTamperEP(server, http.MethodGet, "/admin")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	var bypass []ev.Evidence
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "bypass") {
			bypass = append(bypass, f)
		}
	}
	if len(bypass) != 1 {
		t.Fatalf("expected exactly 1 bypass finding listing both verbs, got %d: %+v", len(bypass), bypass)
	}
	ev := strings.ToUpper(bypass[0].Evidence)
	if !strings.Contains(ev, "POST") || !strings.Contains(ev, "PUT") {
		t.Errorf("expected the single bypass finding to list BOTH POST and PUT, got %q", bypass[0].Evidence)
	}
}

// TestMethodTamper_NotActiveNoFinding: EnableActive:false → 0 findings (the check
// is TierActive and gated).
func TestMethodTamper_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("content"))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	ep := methodTamperEP(server, http.MethodGet, "/admin")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if len(findings) != 0 {
		t.Fatalf("EnableActive:false must yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestMethodTamper_AllMethodsProperlyGated: server 401/403/405s every verb
// WITHOUT auth → 0 bypass findings (the auth filter covers every verb).
func TestMethodTamper_AllMethodsProperlyGated(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasAuthHeader(r) {
			_, _ = w.Write([]byte("authorized"))
			return
		}
		// Every verb without auth is gated. TRACE/PUT/DELETE also rejected, so no
		// dangerous-method findings either.
		switch r.Method {
		case http.MethodPut, http.MethodDelete, http.MethodTrace:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	cfg := activeMethodTamperCfg()
	cfg.Auth = &models.AuthContext{Type: models.AuthTypeBearer, Header: "Authorization", Value: "Bearer realtoken"}
	ep := methodTamperEP(server, http.MethodGet, "/admin")
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if _, ok := findMethodTamperFinding(findings, "bypass"); ok {
		t.Fatalf("expected 0 bypass findings when every verb is gated, got %+v", findings)
	}
}

// TestMethodTamper_SPACatchAllNoFinding is the regression for the final-review
// blocker: a catch-all server (SPA host / reverse proxy try_files / API-gateway
// default route) returns 200 + the same shell for EVERY verb. PUT/DELETE
// returning 2xx there is NOT a real write-acceptance — it's the default page.
// The dangerous-method probe must compare against the canonical baseline and
// suppress when status+body match (catch-all), mirroring the bypass path's
// discipline. Was a false MEDIUM "dangerous method enabled".
func TestMethodTamper_SPACatchAllNoFinding(t *testing.T) {
	const shell = "<!doctype html><html><body>app shell</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Catch-all: 200 + identical shell for every method (incl. PUT/DELETE/TRACE).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(shell))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: server.URL + "/"}
	ResetGlobalAuditLog()
	findings := methodTamperCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "dangerous") {
			t.Errorf("SPA catch-all (200 for every verb, same body) wrongly flagged dangerous method: %q / %q", f.Title, f.Evidence)
		}
	}
}
