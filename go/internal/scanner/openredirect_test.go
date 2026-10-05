package scanner

// Integration tests for the active open-redirect check (CWE-601). They drive
// openRedirectCheck.Run against loopback httptest servers, so every cfg sets
// AllowPrivate: true — the same relaxation a real scan auto-applies when --url
// resolves to a private/loopback host (see allowPrivate / netguard).
//
// The load-bearing FP control is host comparison via url.Hostname() on the
// backslash-normalized Location, never a substring match on the raw header.
// TestOpenRedirect_SubstringHostNoFinding is the regression guard for that.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

const redirectSentinel = "fendix-redirect.example"

// activeRedirectCfg returns the standard active-scan config for these tests.
func activeRedirectCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// epFor builds an Endpoint that declares no params; targetsForEndpoint is not
// what open-redirect uses (it iterates its own redirectParams list), so the
// only thing that matters is FullURL/Method/Path pointing at the test server.
func epFor(server *httptest.Server) Endpoint {
	return Endpoint{Method: "GET", Path: "/login", FullURL: server.URL + "/login"}
}

// reflectingRedirectServer 302s to whatever the named query param contains.
// It echoes the raw value as Location (no normalization on the server side) so
// the check sees exactly what was injected.
func reflectingRedirectServer(t *testing.T, param string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if v == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", v)
		w.WriteHeader(http.StatusFound)
	}))
}

func TestOpenRedirect_ReflectingLocation(t *testing.T) {
	ResetGlobalAuditLog()
	// 302s to whatever ?next= contains. The scheme-relative //sentinel payload
	// reflects as Location: //fendix-redirect.example → exact host match.
	server := reflectingRedirectServer(t, "next")
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 open-redirect finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for exact-host match, got %s", f.Confidence)
	}
	if !hasRef(f, "CWE-601") {
		t.Errorf("expected CWE-601 reference, got %v", f.References)
	}
	if f.Category != "redirect" {
		t.Errorf("expected category=redirect, got %q", f.Category)
	}
}

func TestOpenRedirect_SchemeRelative(t *testing.T) {
	ResetGlobalAuditLog()
	// Handler always emits the scheme-relative form regardless of input — proves
	// //host parses to Hostname()==sentinel and fires.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("url") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "//"+redirectSentinel+"/path")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) == 0 {
		t.Fatalf("expected a finding for scheme-relative //host redirect, got none")
	}
}

func TestOpenRedirect_BackslashBypass(t *testing.T) {
	ResetGlobalAuditLog()
	// Handler emits the /\ form for the first probed param. url.Parse on the raw
	// value yields a path-only URL (empty host); only after replacing \ with /
	// does it parse to //sentinel. This asserts the normalization step is
	// applied. Keys on "next" (the first redirectParam) so confirmation lands
	// inside the per-endpoint probe budget.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", `/\`+redirectSentinel+"/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) == 0 {
		t.Fatalf("expected a finding for backslash-bypass /\\host redirect (normalization not applied?), got none")
	}
}

func TestOpenRedirect_SuffixBypass(t *testing.T) {
	ResetGlobalAuditLog()
	// Always redirects to the subdomain-style bypass host
	// trusted.com.fendix-redirect.example → Hostname() ENDS WITH "."+sentinel.
	// A dedicated handler (not the reflecting one) is required because the
	// per-param short-circuit would otherwise confirm on the exact-host payload
	// first; here every payload yields the suffix host, so the finding is the
	// MEDIUM-confidence suffix bypass.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "https://trusted.com."+redirectSentinel+"/welcome")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) == 0 {
		t.Fatalf("expected a finding for suffix-bypass redirect, got none")
	}
	var sawSuffix bool
	for _, f := range findings {
		if f.Confidence == models.ConfidenceMedium && f.Severity == models.SeverityMedium {
			sawSuffix = true
		}
	}
	if !sawSuffix {
		t.Errorf("expected a MEDIUM-confidence suffix-bypass finding, got %+v", findings)
	}
}

func TestOpenRedirect_JavascriptScheme(t *testing.T) {
	ResetGlobalAuditLog()
	// Always redirects to javascript:alert(1)//sentinel. The dangerous scheme
	// is itself the confirmation (no legitimate server emits a javascript:
	// Location), elevating the finding to HIGH severity / HIGH confidence.
	// A dedicated handler is required so the dangerous-scheme Location is what
	// confirms rather than the exact-host payload short-circuiting first.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("next") == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "javascript:alert(1)//"+redirectSentinel)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) == 0 {
		t.Fatalf("expected a finding for javascript: scheme redirect, got none")
	}
	var sawHigh bool
	for _, f := range findings {
		if f.Severity == models.SeverityHigh && f.Confidence == models.ConfidenceHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Errorf("expected a HIGH/HIGH dangerous-scheme finding, got %+v", findings)
	}
}

func TestOpenRedirect_SubstringHostNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	// LOAD-BEARING FP GUARD: the server redirects to its OWN host
	// (https://victim.test/login?next=<payload>), so the sentinel appears only
	// in the query string. Hostname() is victim.test, not the sentinel, so a
	// correct host-equality check must NOT fire. A naive substring match WOULD.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "https://victim.test/login?next="+url.QueryEscape(next))
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) != 0 {
		t.Fatalf("FP GUARD FAILED: sentinel only in query of own-host redirect must NOT fire, got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirect_200BodyEchoNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	// 200 with the payload echoed in the body but NO Location header → no
	// redirect, no finding. Reflection in body is not an open redirect.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("you asked to go to " + r.URL.Query().Get("next")))
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) != 0 {
		t.Fatalf("expected no finding for 200 body-echo (no Location), got %d: %+v", len(findings), findings)
	}
}

func TestOpenRedirect_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := reflectingRedirectServer(t, "next")
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := openRedirectCheck{}.Run(context.Background(), NewCheckContext(cfg), epFor(server))
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when EnableActive=false, got %d", len(findings))
	}
}

func TestOpenRedirect_BudgetRespected(t *testing.T) {
	ResetGlobalAuditLog()
	// A server that never redirects (always 200) so no finding short-circuits
	// the loop; with MaxProbesPerEndpoint=2 the check must stop after 2 probes.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := activeRedirectCfg()
	cfg.MaxProbesPerEndpoint = 2
	cc := NewCheckContext(cfg)
	ep := epFor(server)
	openRedirectCheck{}.Run(context.Background(), cc, ep)

	if got := cc.Audit.Count(ep.FullURL); got > 2 {
		t.Errorf("budget not respected: recorded %d probes, want <= 2", got)
	}
}
