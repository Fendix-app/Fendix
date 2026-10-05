package scanner

// These tests scan loopback httptest servers. The SSRF egress guard
// (internal/netguard) refuses loopback/private addresses by default, so each
// config sets AllowPrivate: true — exactly what a real scan auto-applies when
// the --url target resolves to a private/loopback host (see allowPrivate /
// netguard.TargetIsPrivate).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestCheckCORS_WildcardWithCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard+credentials, got %d", len(findings))
	}
	// Configuration-only observation, NOT a demonstrated exploit. The Fetch
	// standard forbids ACAO:* under credentials mode `include`, so browsers
	// reject the pair and no authenticated cross-origin read happens. MEDIUM
	// keeps it below --fail-on HIGH, i.e. non-blocking.
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity (invalid config, exploitation not demonstrated), got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS wildcard origin combined with credentials (invalid configuration)" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
	// The wording must say exploitation was not demonstrated, so a reader
	// cannot mistake the pair for a proven credentialed read.
	if !strings.Contains(findings[0].Evidence, "NOT demonstrated") {
		t.Errorf("evidence must state exploitation was not demonstrated, got: %s", findings[0].Evidence)
	}
}

// A configuration-only wildcard+credentials observation must never outrank a
// DEMONSTRATED credentialed reflection. Both signals fire here (wildcard+creds
// on the preflight, reflection+creds on the simple request); the exploitable
// one has to win, or the de-escalation above would have bought quiet at the
// cost of hiding the finding that matters.
func TestCORS_WildcardCredsNeverMasksDemonstratedReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(200)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 origin finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Title != "CORS reflects arbitrary origin with credentials" {
		t.Fatalf("demonstrated reflection was masked by the config-only wildcard finding: %s", findings[0].Title)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL for demonstrated credentialed reflection, got %s", findings[0].Severity)
	}
}

// Fixture 5 — reflection on an endpoint a source of truth DECLARES public.
// The reflection is still real and still reported; what changes is the impact
// claim, because the readable response is not authenticated data. CRITICAL
// there would be asserting account takeover against a public body.
func TestCORS_ReflectedCredsOnDeclaredPublicEndpointIsNotCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{
		Method:          "GET",
		Path:            "/api/status",
		FullURL:         server.URL + "/api/status",
		AuthExpectation: models.AuthExpectationPublic,
	}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 origin finding, got %d: %+v", len(findings), findings)
	}
	// Preserved, not deleted: still reported, still reflection, just not
	// account-takeover grade.
	if findings[0].RuleID != "cors/reflects-origin-with-credentials" {
		t.Fatalf("the reflection finding must be preserved, got rule %s", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH on a declared-public endpoint, got %s", findings[0].Severity)
	}
	if findings[0].AuthExpectation != models.AuthExpectationPublic {
		t.Errorf("the declaration that drove the de-escalation must be serialized, got %q", findings[0].AuthExpectation)
	}
}

// The asymmetry that keeps the de-escalation honest: absence of a declaration
// is NOT evidence that a response is harmless. An endpoint discovered by
// crawling carries AuthExpectationUnknown and must keep the full severity.
func TestCORS_UnknownAuthExpectationStaysCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	// No AuthExpectation set — exactly what crawl/brute-force discovery leaves.
	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 origin finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("unknown auth expectation must not be read as public; expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestCheckCORS_WildcardWithoutCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/public", FullURL: server.URL + "/api/public"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard ACAO, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestCheckCORS_ReflectedOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for reflected origin, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestCheckCORS_NonStandardMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, TRACE, PURGE")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for non-standard methods, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
}

func TestCheckCORS_NoCORSHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/safe", FullURL: server.URL + "/api/safe"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for no CORS headers, got %d", len(findings))
	}
}

// TASK-123 / FP corpus pattern P2: CORS misconfig findings on a 404
// page are unreachable — the path doesn't serve a feature. Skip.
func TestCheckCORS_SkipsOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set a wildcard ACAO that *would* fire a CRITICAL finding — but
		// the 404 status should gate it out.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(404)
	}))
	defer server.Close()
	ep := Endpoint{Method: "GET", Path: "/.env.local", FullURL: server.URL + "/.env.local"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 CORS findings on 404, got %d: %+v", len(findings), findings)
	}
}

func TestCheckCORS_ProperConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/secure", FullURL: server.URL + "/api/secure"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for proper CORS config, got %d", len(findings))
	}
}

func TestCheckCORS_MultipleIssues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, TRACE")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/bad", FullURL: server.URL + "/api/bad"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (wildcard + non-standard method), got %d", len(findings))
	}
}

// Phase 4a / 4.1 — suffix bypass: the server reflects an origin derived from
// the target host as a subdomain of the attacker domain
// (https://<targetHost>.evil.example.com). Exact-match reflection of the bare
// evilOrigin would miss this whole class. ACAO equals the probe origin exactly.
func TestCORS_SuffixBypassReflected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		// Reflect ONLY the suffix-bypass probe origin, not the bare evil origin.
		if strings.HasSuffix(origin, ".evil.example.com") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for suffix-bypass reflection, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

// Phase 4a / 4.2 — a reflected arbitrary origin WITH credentials is
// account-takeover grade → CRITICAL, not HIGH.
func TestCORS_ReflectedOriginWithCredentialsIsCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for credentialed reflection, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin with credentials" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

// Phase 4a / 4.3 — some servers reflect Origin only on the actual
// (simple) request, not the preflight. The simple-request probe must catch it.
func TestCORS_SimpleRequestReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect ONLY on the real method (GET); emit nothing on OPTIONS.
		if r.Method == http.MethodOptions {
			w.WriteHeader(200)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for simple-request reflection, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

// Phase 4a / 4.3 dedup — the SAME reflecting misconfig present on BOTH
// preflight and simple request must produce ONE finding, not two.
func TestCORS_ReflectionNotDoubleReported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduped reflection finding, got %d: %+v", len(findings), findings)
	}
}

// Phase 4a / 4.4 — sandboxed iframes / data-URIs send Origin: null. A server
// that reflects "null" is exploitable. HIGH without creds, CRITICAL with creds.
func TestCORS_NullOriginAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for null-origin acceptance, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS accepts null origin" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestCORS_NullOriginWithCredentialsIsCritical(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for credentialed null-origin, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", findings[0].Severity)
	}
}

// Phase 4a / 4.5 — status-gate narrowing. A 401 that still reflects the evil
// origin is a real misconfig: the CORS headers are independent of the probe's
// auth outcome. Only 404 (and 5xx) should gate evaluation out.
func TestCORS_EvaluatedOn401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(401)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/private", FullURL: server.URL + "/api/private"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 reflection finding on 401, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

// Phase 4a / 4.5 — 404 must still gate CORS evaluation out (regression guard
// for the existing TestCheckCORS_SkipsOn404 narrowing).
func TestCORS_StillSkipsOn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/missing", FullURL: server.URL + "/missing"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404, got %d: %+v", len(findings), findings)
	}
}

// Phase 4a precedence regression — wildcard-no-creds and reflected-origin are
// DISTINCT misconfigs that can co-occur across different probes/methods. A
// server may return ACAO: * on the OPTIONS preflight while reflecting the
// arbitrary probe origin on the GET (simple) request. wildcard-no-creds (MEDIUM)
// must NOT subsume the reflected-origin finding (HIGH) — that hides the
// higher-severity issue. The single emitted origin finding must be the HIGH
// reflection, not the MEDIUM wildcard.
func TestCORS_WildcardOnPreflightReflectedOnGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// Preflight: wildcard, no credentials → MEDIUM signal.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(200)
			return
		}
		// Simple request: reflect the attacker probe origin → HIGH signal.
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 origin finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity (reflected origin must not be suppressed by wildcard MEDIUM), got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin" {
		t.Errorf("unexpected title (wildcard MEDIUM hid the HIGH reflection): %s", findings[0].Title)
	}
}

// Phase 4a precedence regression — same co-occurrence as above, but the GET
// reflection carries Access-Control-Allow-Credentials: true. This is an
// account-takeover-grade CRITICAL finding that must never be hidden behind the
// MEDIUM wildcard-no-creds finding.
func TestCORS_WildcardPreflightReflectedCredsOnGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// Preflight: wildcard, no credentials → MEDIUM signal.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(200)
			return
		}
		// Simple request: reflect with credentials → CRITICAL signal.
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/users", FullURL: server.URL + "/api/users"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 origin finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity (credentialed reflection must not be suppressed by wildcard MEDIUM), got %s", findings[0].Severity)
	}
	if findings[0].Title != "CORS reflects arbitrary origin with credentials" {
		t.Errorf("unexpected title (wildcard MEDIUM hid the CRITICAL reflection): %s", findings[0].Title)
	}
}

// Phase 4a / 4.6 — Access-Control-Allow-Methods: * is a wildcard methods
// misconfig the non-standard-method loop ignores today.
func TestCORS_WildcardMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example.com")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}

	findings := CheckCORS(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for wildcard methods, got %d: %+v", len(findings), findings)
	}
	if findings[0].Title != "CORS allows all methods (wildcard)" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

// TestCORS_DirectObservationOnOriginFindingsOnly mirrors the headers predicate.
// ACAO/ACAC are read literally and reflection is exact case-insensitive
// equality to the probe origin, so the origin findings are direct observations.
// The method-policy findings are not: an ACAM token list is read literally too,
// but those findings grade EXPLOITABILITY rather than certainty, which is why
// both already carry ConfidenceMedium.
func TestCORS_DirectObservationOnOriginFindingsOnly(t *testing.T) {
	t.Run("origin findings", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin := r.Header.Get("Origin"); origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.WriteHeader(200)
		}))
		defer server.Close()

		ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
		findings := CheckCORS(context.Background(), &models.ScanConfig{Timeout: 10, AllowPrivate: true}, ep)
		if len(findings) == 0 {
			t.Fatal("no CORS findings for a reflecting server — test premise broken")
		}
		for _, f := range findings {
			if !strings.HasPrefix(f.Title, "CORS reflects") && !strings.HasPrefix(f.Title, "CORS wildcard") &&
				!strings.HasPrefix(f.Title, "CORS accepts") && !strings.HasPrefix(f.Title, "CORS allows any") {
				continue // a method-policy finding; covered by the subtest below
			}
			if !f.DirectObservation {
				t.Errorf("%q is not marked DirectObservation; ACAO/ACAC are literal reads", f.Title)
			}
		}
	})

	t.Run("method-policy findings are graded, not read", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Methods", "*")
			w.WriteHeader(200)
		}))
		defer server.Close()

		ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
		findings := CheckCORS(context.Background(), &models.ScanConfig{Timeout: 10, AllowPrivate: true}, ep)

		var found bool
		for _, f := range findings {
			if f.Title != "CORS allows all methods (wildcard)" {
				continue
			}
			found = true
			if f.DirectObservation {
				t.Error("the method-policy finding claimed the direct-observation bonus; it is graded\n" +
					"on exploitability, which is why it carries ConfidenceMedium")
			}
		}
		if !found {
			t.Fatalf("no wildcard-methods finding: %v", findings)
		}
	})
}
