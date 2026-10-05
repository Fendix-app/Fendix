package scanner

// Integration tests for the active host-header injection check (CWE-644/601).
// They drive hostHeaderCheck.Run against loopback httptest servers, so every
// cfg sets AllowPrivate: true (the netguard egress guard would otherwise block
// the dial to the 127.0.0.1 test server — same paradox as the SSRF tests).
//
// LOAD-BEARING negative tests that MUST stay green:
//   - TestHostHeader_BareEchoNotInURLPositionNoFinding: a bare-text echo of the
//     sentinel that is NOT in a URL-host position is NOT a finding (the anchored
//     //sentinel / scheme://sentinel regex must require the URL prefix).
//   - TestHostHeader_BaselineAlreadyRedirectsToSentinelNoFinding: a server whose
//     UNPOISONED baseline already 302s to the sentinel host yields NO finding
//     (baseline-diff guard — the reflection is not attacker-controlled).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeHostHeaderCfg returns the standard active-scan config for these tests.
// AllowPrivate:true is mandatory so the egress guard does not block the dial to
// the loopback httptest server.
func activeHostHeaderCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// hostHeaderEP builds a parameterless Endpoint — host-header injection is a
// per-endpoint (active-lite) check; the attack surface is the request line and
// the Host-family headers, not query/body params.
func hostHeaderEP(server *httptest.Server) Endpoint {
	return Endpoint{
		Method:  "GET",
		Path:    "/",
		FullURL: server.URL + "/",
	}
}

// poisonedHost reports whether ANY Host-family vector on the request carries the
// sentinel. req.Host holds the override of the Host header (Go special-cases it).
func poisonedHost(r *http.Request) bool {
	if strings.Contains(r.Host, hostHeaderSentinel) {
		return true
	}
	for _, h := range []string{"X-Forwarded-Host", "X-Forwarded-Server", "Forwarded"} {
		if strings.Contains(r.Header.Get(h), hostHeaderSentinel) {
			return true
		}
	}
	return false
}

// TestHostHeader_RedirectHostReflected: the handler 302s with a Location whose
// host is built from the (poisoned) Host header → HIGH/High finding, redirect
// shape. The unpoisoned baseline redirects to its OWN host, so the baseline-diff
// guard is satisfied.
func TestHostHeader_RedirectHostReflected(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			host = xfh
		}
		// Build an absolute redirect from the (attacker-controlled) host.
		w.Header().Set("Location", "https://"+host+"/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 host-header finding (redirect), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for redirect-host reflection, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for redirect-host reflection, got %s", f.Confidence)
	}
	if f.Category != "host_header" {
		t.Errorf("expected category=host_header, got %q", f.Category)
	}
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected blackbox source, got %s", f.Source)
	}
	if !hasRef(f, "CWE-644") {
		t.Errorf("expected CWE-644 reference, got %v", f.References)
	}
	if !hasRef(f, "CWE-601") {
		t.Errorf("expected CWE-601 reference, got %v", f.References)
	}
}

// TestHostHeader_ResetContextBodyLink: the handler returns 200 with an absolute
// password-reset link built from the poisoned host → HIGH (reset context).
func TestHostHeader_ResetContextBodyLink(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if poisonedHost(r) {
			host := r.Host
			if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
				host = xfh
			}
			_, _ = fmt.Fprintf(w, `<a href="https://%s/reset?token=x">reset your password</a>`, host)
			return
		}
		_, _ = w.Write([]byte("<p>welcome</p>"))
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 host-header finding (reset link), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for reset-context absolute link, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for reset-context absolute link, got %s", f.Confidence)
	}
	if f.Category != "host_header" {
		t.Errorf("expected category=host_header, got %q", f.Category)
	}
	if !hasRef(f, "CWE-644") {
		t.Errorf("expected CWE-644 reference, got %v", f.References)
	}
}

// TestHostHeader_GenericAbsoluteLink: the body reflects the sentinel in a URL
// position (//sentinel/foo) but with NO reset/password/verify context → MEDIUM.
func TestHostHeader_GenericAbsoluteLink(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if poisonedHost(r) {
			host := r.Host
			if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
				host = xfh
			}
			// Scheme-relative URL position, no reset/password/verify context.
			_, _ = fmt.Fprintf(w, `<p>see the latest at //%s/foo for details</p>`, host)
			return
		}
		_, _ = w.Write([]byte("<p>welcome</p>"))
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 host-header finding (generic link), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for generic absolute link, got %s", f.Severity)
	}
	if f.Category != "host_header" {
		t.Errorf("expected category=host_header, got %q", f.Category)
	}
}

// TestHostHeader_BareEchoNotInURLPositionNoFinding (LOAD-BEARING): the handler
// echoes the sentinel as PLAIN TEXT, not in a URL-host position (not preceded by
// // or a scheme://). The anchored regex must NOT match a bare echo → NO finding.
func TestHostHeader_BareEchoNotInURLPositionNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		if poisonedHost(r) {
			// Bare echo of the sentinel as a search term — NOT in a URL position.
			_, _ = fmt.Fprintf(w, `<p>you requested %s as a search term</p>`, hostHeaderSentinel)
			return
		}
		_, _ = w.Write([]byte("<p>welcome</p>"))
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: bare echo not in URL-host position must NOT fire, got %d: %+v", len(findings), findings)
	}
}

// TestHostHeader_BaselineAlreadyRedirectsToSentinelNoFinding (LOAD-BEARING): the
// UNPOISONED baseline ALREADY 302s to the sentinel host (unrelated to the
// attacker), and the poisoned probe does the same. The baseline-diff guard must
// suppress the finding → NO finding.
func TestHostHeader_BaselineAlreadyRedirectsToSentinelNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect to the sentinel host regardless of the request's Host —
		// a server that does this for unrelated reasons must not FP.
		w.Header().Set("Location", "https://"+hostHeaderSentinel+"/always")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: baseline already redirecting to sentinel must NOT fire (baseline-diff), got %d: %+v", len(findings), findings)
	}
}

// TestHostHeader_OneFindingPerShape: the sentinel is reflected into the redirect
// host via BOTH Host AND X-Forwarded-Host. The check must dedup the redirect
// shape → exactly 1 finding, not 2.
func TestHostHeader_OneFindingPerShape(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build the redirect host from whichever Host-family vector is poisoned.
		host := r.Host
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			host = xfh
		}
		w.Header().Set("Location", "https://"+host+"/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 redirect finding (deduped across Host + X-Forwarded-Host), got %d: %+v", len(findings), findings)
	}
}

// TestHostHeader_NotActiveNoFinding: EnableActive=false → the check is a no-op.
func TestHostHeader_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+r.Host+"/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when EnableActive=false, got %d: %+v", len(findings), findings)
	}
}

// TestHostHeader_404Skipped: a baseline 404 is not a feature → the check skips
// the endpoint and emits no findings even though the handler reflects the host.
func TestHostHeader_404Skipped(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the host into a redirect Location but answer 404 — not a feature.
		w.Header().Set("Location", "https://"+r.Host+"/path")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := activeHostHeaderCfg()
	findings := hostHeaderCheck{}.Run(context.Background(), NewCheckContext(cfg), hostHeaderEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when baseline is 404, got %d: %+v", len(findings), findings)
	}
}
