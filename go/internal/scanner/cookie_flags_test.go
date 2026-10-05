package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// cookieFindingTitles collects finding titles for assertions.
func cookieFindingTitles(fs []ev.Evidence) map[string]ev.Evidence {
	m := make(map[string]ev.Evidence, len(fs))
	for _, f := range fs {
		m[f.Title] = f
	}
	return m
}

// hasRef reports whether a finding's References slice contains want.
func hasRef(f ev.Evidence, want string) bool {
	for _, r := range f.References {
		if r == want {
			return true
		}
	}
	return false
}

// runCookieCheck builds a CheckContext for a test server and runs the check.
// For TLS servers the test client (srv.Client) is wired in so the cert is
// trusted; that client is not SSRF-guarded, which is fine for unit testing the
// cookie classification logic.
func runCookieCheck(t *testing.T, srv *httptest.Server, tls bool) []ev.Evidence {
	t.Helper()
	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true}
	cc := NewCheckContext(cfg)
	if tls {
		cc.Client = srv.Client()
	}
	ep := Endpoint{Method: "GET", Path: "/", FullURL: srv.URL + "/"}
	return cookieFlagsCheck{}.Run(context.Background(), cc, ep)
}

func TestCookieFlags_SessionCookieNoFlagsHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings (HttpOnly, Secure, SameSite), got %d: %v", len(findings), findings)
	}

	var httpOnly, secure, sameSite *ev.Evidence
	for i := range findings {
		f := findings[i]
		if f.Category != "cookie" {
			t.Errorf("expected category cookie, got %q for %q", f.Category, f.Title)
		}
		if f.Source != models.SourceBlackbox {
			t.Errorf("expected source blackbox, got %q for %q", f.Source, f.Title)
		}
		switch {
		case hasRef(f, "CWE-1004"):
			httpOnly = &findings[i]
		case hasRef(f, "CWE-614"):
			secure = &findings[i]
		case hasRef(f, "CWE-1275"):
			sameSite = &findings[i]
		}
	}

	if httpOnly == nil {
		t.Fatal("missing HttpOnly finding (CWE-1004)")
	}
	if httpOnly.Severity != models.SeverityMedium {
		t.Errorf("HttpOnly severity: got %s want MEDIUM", httpOnly.Severity)
	}
	if httpOnly.Confidence != models.ConfidenceHigh {
		t.Errorf("HttpOnly confidence: got %s want HIGH", httpOnly.Confidence)
	}

	if secure == nil {
		t.Fatal("missing Secure finding (CWE-614)")
	}
	if secure.Severity != models.SeverityMedium {
		t.Errorf("Secure severity: got %s want MEDIUM", secure.Severity)
	}
	if secure.Confidence != models.ConfidenceHigh {
		t.Errorf("Secure confidence: got %s want HIGH", secure.Confidence)
	}

	if sameSite == nil {
		t.Fatal("missing SameSite finding (CWE-1275)")
	}
	if sameSite.Severity != models.SeverityLow {
		t.Errorf("SameSite severity: got %s want LOW", sameSite.Severity)
	}
	if sameSite.Confidence != models.ConfidenceMedium {
		t.Errorf("SameSite confidence: got %s want MEDIUM", sameSite.Confidence)
	}

	// Endpoint label should be "METHOD PATH".
	if httpOnly.Endpoint != "GET /" {
		t.Errorf("endpoint label: got %q want %q", httpOnly.Endpoint, "GET /")
	}
}

func TestCookieFlags_PlainHTTPSuppressesSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, false)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (Secure suppressed on http), got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if hasRef(f, "CWE-614") {
			t.Errorf("Secure finding should be suppressed on plain http, got %q", f.Title)
		}
	}
}

func TestCookieFlags_HardenedCookie(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; HttpOnly; Secure; SameSite=Strict")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for fully hardened cookie, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_AnalyticsIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Long value, no flags, but on the ignore-list — must not flag.
		w.Header().Set("Set-Cookie", "_ga=GA1.2.long.value.123456789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for analytics cookie (ignore-list wins), got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_DeletionCookieIgnored(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=; Max-Age=-1")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for deletion cookie, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_SameSiteNoneWithoutSecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SameSite=None without Secure over https → SameSite finding escalates
		// to MEDIUM. (HttpOnly + Secure findings also fire here.)
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; SameSite=None")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	var sameSite *ev.Evidence
	for i := range findings {
		if hasRef(findings[i], "CWE-1275") {
			sameSite = &findings[i]
		}
	}
	if sameSite == nil {
		t.Fatalf("missing SameSite finding; got %v", findings)
	}
	if sameSite.Severity != models.SeverityMedium {
		t.Errorf("SameSite=None+!Secure severity: got %s want MEDIUM (escalated)", sameSite.Severity)
	}
}

func TestCookieFlags_4xxSkipped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(404)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on 404 response, got %d: %v", len(findings), findings)
	}
}

func TestCookieFlags_DuplicateFlagOneFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Two Set-Cookie for the same name, both hardened on Secure+SameSite
		// but missing HttpOnly. Exactly ONE HttpOnly finding for that name.
		w.Header().Add("Set-Cookie", "sessionid=abc123def456ghi789; Secure; SameSite=Strict")
		w.Header().Add("Set-Cookie", "sessionid=zzz987yyy654xxx321; Secure; SameSite=Strict")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	httpOnlyCount := 0
	for _, f := range findings {
		if hasRef(f, "CWE-1004") {
			httpOnlyCount++
		}
	}
	if httpOnlyCount != 1 {
		t.Fatalf("expected exactly 1 HttpOnly finding for duplicate cookie name, got %d: %v", httpOnlyCount, findings)
	}
}

// sanity: ensure evidence mentions the cookie name + flag (helps triage).
func TestCookieFlags_EvidenceNamesCookie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, false)
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "sessionid") {
			t.Errorf("evidence should name the cookie: %q", f.Evidence)
		}
	}
	titles := cookieFindingTitles(findings)
	if len(titles) == 0 {
		t.Fatal("expected at least one finding")
	}
}

// TestCookieFlags_DirectObservationOnBooleanReadsOnly locks the same predicate
// the header and CORS checks use. HttpOnly and Secure are plain boolean reads
// of the parsed Set-Cookie. SameSite is not: net/http parses an ABSENT
// attribute to http.SameSite(0) and an unrecognized one to
// SameSiteDefaultMode, so the scanner cannot tell the two apart and the claim
// is an inference — which is why that finding already carries ConfidenceMedium.
func TestCookieFlags_DirectObservationOnBooleanReadsOnly(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	for _, f := range findings {
		want := !hasRef(f, "CWE-1275") // everything except the SameSite finding
		if f.DirectObservation != want {
			t.Errorf("%q DirectObservation = %v, want %v", f.Title, f.DirectObservation, want)
		}
		// The predicate must stay readable as "direct observation iff the check
		// asserts ConfidenceHigh from a literal read".
		if f.DirectObservation != (f.Confidence == models.ConfidenceHigh) {
			t.Errorf("%q breaks the file's predicate: DirectObservation=%v Confidence=%s",
				f.Title, f.DirectObservation, f.Confidence)
		}
	}
}

// csrfHTTPOnlyTitle is the title the CSRF-class HttpOnly finding must carry.
// Pinned in the test rather than exported from the scanner so a drive-by
// re-wording has to be a deliberate, visible edit: models.Fingerprint and
// dedupKey both hash Title, so changing it churns every committed
// .fendix-ignore fingerprint rule and --baseline entry for the finding.
const csrfHTTPOnlyTitle = "CSRF cookie readable by JavaScript (no HttpOnly) — " +
	"expected for double-submit patterns (Django/Rails AJAX); verify this is intentional"

// TestCookieFlags_CSRFClassificationBeatsTheSessionSubstring is the load-bearing
// unit for FIX-11. "csrftoken" contains "token", which is in cookieSessionList,
// so consulting the session list first silently reproduces the exact mislabel
// this change fixes — and every higher-level test would still pass, because the
// finding count is unchanged either way.
func TestCookieFlags_CSRFClassificationBeatsTheSessionSubstring(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  cookieClass
	}{
		{"csrftoken", "kx9QpL2mZ4vR8nT6", cookieClassCSRF},  // Django; also contains "token"
		{"XSRF-TOKEN", "kx9QpL2mZ4vR8nT6", cookieClassCSRF}, // Angular / Laravel
		{"_csrf", "kx9QpL2mZ4vR8nT6", cookieClassCSRF},      // Express / Rails
		{"sessionid", "kx9QpL2mZ4vR8nT6", cookieClassSession},
		{"PHPSESSID", "kx9QpL2mZ4vR8nT6", cookieClassSession},
		{"auth_token", "short", cookieClassSession},
		{"jwt", "short", cookieClassSession},
		{"_ga", "GA1.2.long.value.123456789", cookieClassNone}, // ignore-list wins over length
		{"locale", "en-GB", cookieClassNone},
		{"page", "12345", cookieClassNone}, // small integer, not credential-shaped
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyCookie(&http.Cookie{Name: c.name, Value: c.value}); got != c.want {
				t.Errorf("classifyCookie(%q) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestCookieFlags_CSRFTokenIsNotASessionFinding is the user-visible half: a
// Django csrftoken without HttpOnly must not be reported as a session-credential
// defect. Rule 3 — the observation is preserved and de-escalated, never dropped.
func TestCookieFlags_CSRFTokenIsNotASessionFinding(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "csrftoken=kx9QpL2mZ4vR8nT6bW1cY3hJ5dG7fA0s; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	titles := cookieFindingTitles(findings)

	if _, ok := titles["Session cookie missing HttpOnly flag"]; ok {
		t.Error("a CSRF double-submit token was reported as a session cookie missing HttpOnly")
	}

	csrf, ok := titles[csrfHTTPOnlyTitle]
	if !ok {
		t.Fatalf("no CSRF HttpOnly finding — the observation must be de-escalated, not\n"+
			"suppressed (Rule 3). Got: %v", findings)
	}
	if csrf.Severity != models.SeverityInfo {
		t.Errorf("severity = %s, want INFO — a readable CSRF token is the expected configuration",
			csrf.Severity)
	}
	if csrf.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence = %s, want HIGH — it is still a literal read of the response",
			csrf.Confidence)
	}
	if !csrf.DirectObservation {
		t.Error("the CSRF finding is the same boolean read as the session one and must keep\n" +
			"DirectObservation")
	}
	if csrf.Category != "cookie" {
		t.Errorf("category = %q, want cookie", csrf.Category)
	}
	if !hasRef(csrf, "CWE-1004") {
		t.Errorf("CWE-1004 dropped; the finding stays in the same reference family so a\n"+
			"consumer filtering on it still sees the observation: %v", csrf.References)
	}
	if !strings.Contains(csrf.Evidence, "csrftoken") {
		t.Errorf("evidence should name the cookie: %q", csrf.Evidence)
	}
	// benchmarks/targets/dvwa-known.json matches its expected cookie finding by
	// the substring "HttpOnly" in the TITLE. Losing it would degrade a gated
	// benchmark from inside the passing band — worse than a hard failure.
	if !strings.Contains(csrf.Title, "HttpOnly") {
		t.Errorf("the CSRF title must still contain the substring %q: %q", "HttpOnly", csrf.Title)
	}
	// Finding count is a 1-for-1 swap, which keeps the corpus TP/FP arithmetic
	// stable: HttpOnly(INFO) + Secure + SameSite.
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (HttpOnly, Secure, SameSite), got %d: %v", len(findings), findings)
	}
}

// TestCookieFlags_CSRFCookieStillReportsSecureAndSameSite locks the required
// NON-change. A CSRF token has to be readable by script; it does NOT have to
// travel in the clear, and SameSite=None on one is genuinely CSRF-permissive.
// Both branches stay reachable and byte-identical to the session path.
func TestCookieFlags_CSRFCookieStillReportsSecureAndSameSite(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "csrftoken=kx9QpL2mZ4vR8nT6bW1cY3hJ5dG7fA0s; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var secure, sameSite *ev.Evidence
	findings := runCookieCheck(t, srv, true)
	for i := range findings {
		switch {
		case hasRef(findings[i], "CWE-614"):
			secure = &findings[i]
		case hasRef(findings[i], "CWE-1275"):
			sameSite = &findings[i]
		}
	}

	if secure == nil {
		t.Fatalf("missing Secure finding for a CSRF cookie over HTTPS: %v", findings)
	}
	if secure.Title != "Session cookie missing Secure flag" || secure.Severity != models.SeverityMedium ||
		secure.Confidence != models.ConfidenceHigh {
		t.Errorf("Secure finding changed: %q / %s / %s", secure.Title, secure.Severity, secure.Confidence)
	}

	if sameSite == nil {
		t.Fatalf("missing SameSite finding for a CSRF cookie: %v", findings)
	}
	if sameSite.Title != "Session cookie missing or weak SameSite attribute" ||
		sameSite.Severity != models.SeverityLow || sameSite.Confidence != models.ConfidenceMedium {
		t.Errorf("SameSite finding changed: %q / %s / %s", sameSite.Title, sameSite.Severity, sameSite.Confidence)
	}
}

// TestCookieFlags_SessionCookieUnaffectedByCSRFSplit is the regression guard for
// everything the split must NOT touch.
func TestCookieFlags_SessionCookieUnaffectedByCSRFSplit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	findings := runCookieCheck(t, srv, true)
	titles := cookieFindingTitles(findings)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %v", len(findings), findings)
	}
	httpOnly, ok := titles["Session cookie missing HttpOnly flag"]
	if !ok {
		t.Fatalf("a session cookie lost its HttpOnly finding: %v", findings)
	}
	if httpOnly.Severity != models.SeverityMedium || !httpOnly.DirectObservation {
		t.Errorf("session HttpOnly finding changed: %s / DirectObservation=%v",
			httpOnly.Severity, httpOnly.DirectObservation)
	}
	if _, ok := titles[csrfHTTPOnlyTitle]; ok {
		t.Error("a session cookie was reported as a CSRF double-submit token")
	}
}

// TestCookieFlags_SessionAndCSRFCookiesAreSeparateFindings — a host that sets
// both now produces two HttpOnly-class findings where it produced one, because
// they are genuinely different claims with different severities. Named
// explicitly because it also means two dedup groups downstream.
func TestCookieFlags_SessionAndCSRFCookiesAreSeparateFindings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sessionid=abc123def456ghi789; Secure; SameSite=Lax")
		w.Header().Add("Set-Cookie", "csrftoken=kx9QpL2mZ4vR8nT6bW1c; Secure; SameSite=Lax")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	titles := cookieFindingTitles(runCookieCheck(t, srv, true))
	if _, ok := titles["Session cookie missing HttpOnly flag"]; !ok {
		t.Error("session HttpOnly finding missing")
	}
	if _, ok := titles[csrfHTTPOnlyTitle]; !ok {
		t.Error("CSRF HttpOnly finding missing")
	}
}
