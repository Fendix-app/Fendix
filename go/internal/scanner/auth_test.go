package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// newAuthTestServer creates a mock server that validates auth:
//   - validToken in Authorization header → 200
//   - missing/invalid auth → 401
//
// acceptAnything overrides to always return 200 (simulates broken auth).
func newAuthTestServer(validToken string, acceptAnything bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if acceptAnything {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == validToken {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
}

// newJWTTestServer creates a mock server that validates JWT structure:
//   - rejects malformed JWTs, expired JWTs, and alg:none JWTs
//   - accepts the given validToken
func newJWTTestServer(validToken string, rejectExpired, rejectAlgNone bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		// Reject malformed
		parts := strings.Split(token, ".")
		if len(parts) != 3 && !(len(parts) == 3 && parts[2] == "") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check for alg:none
		if rejectAlgNone && parts[2] == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check for "invalid.jwt.token" (malformed)
		if token == "invalid.jwt.token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if auth == validToken {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		// If expired checking enabled, reject unknown tokens
		if rejectExpired {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
}

func TestCheckAuth_UnauthenticatedAccess_Vulnerable(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer valid-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
		// RC-2: the spec declares this operation protected, so a successful
		// unauthenticated request CONTRADICTS a declared requirement and is a
		// confirmed bypass at CRITICAL. Without the declaration the same
		// observation is only "an endpoint answered without credentials",
		// which is what TestUnknownExpectationYieldsObservationNotBypass covers.
		AuthExpectation: models.AuthExpectationRequired,
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == authTitleBypassed {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
			if f.Category != "auth_bypass" {
				t.Errorf("category = %s, want auth_bypass", f.Category)
			}
			// Fix 3.3 (confidence corroboration): newAuthTestServer's body
			// is `{"status":"ok"}` (15 bytes) — a trivial generic ack below
			// the corroborationFloor. A 2xx + trivial body is status-only
			// evidence, so the finding is MEDIUM, not HIGH. (Pre-3.3 this
			// asserted HIGH on the status code alone — exactly the FP this
			// fix targets.)
			if f.Confidence != models.ConfidenceMedium {
				t.Errorf("confidence = %s, want MEDIUM (status-only, trivial body)", f.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected 'Missing authentication' finding for vulnerable server")
	}
}

func TestCheckAuth_UnauthenticatedAccess_Secure(t *testing.T) {
	server := newAuthTestServer("Bearer valid-token", false)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer valid-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == authTitleObserved {
			t.Error("should not report unauthenticated access for secure server")
		}
	}
}

func TestCheckAuth_NoAuthConfig_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: "http://localhost/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected no findings with nil auth, got %d", len(findings))
	}
}

// newJWTOnlyServer mocks a server that DOES check for the
// Authorization header (rejects no-auth with 401) but fails to
// validate JWT structure (accepts everything including malformed,
// expired, alg:none). This is the legitimate JWT-bypass vulnerability
// shape — distinct from a fully-public endpoint, which is handled by
// `Missing authentication on endpoint` and dedupes the JWT findings.
func newJWTOnlyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// No Authorization header → 401 (so missing-auth probe sees 401 and skips)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Any Authorization header value → 200 (no actual validation)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
}

func TestCheckAuth_MalformedJWT_Vulnerable(t *testing.T) {
	// Server REQUIRES auth header but doesn't validate JWT — real JWT-bypass.
	// (Using a fully-accept-everything server would dedup these findings as
	// FPs of the "missing authentication" root cause; see the Track 4
	// FP-dedup posture in auth.go::CheckAuth.)
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "JWT not validated" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'JWT not validated' finding")
	}
}

func TestCheckAuth_MalformedJWT_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "JWT not validated" {
			t.Error("secure server should reject malformed JWT")
		}
	}
}

func TestCheckAuth_ExpiredJWT_Vulnerable(t *testing.T) {
	// Real JWT-bypass shape: server requires header but doesn't check exp.
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/data",
		FullURL: server.URL + "/api/data",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "Expired JWT accepted" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'Expired JWT accepted' finding")
	}
}

func TestCheckAuth_ExpiredJWT_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/data",
		FullURL: server.URL + "/api/data",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "Expired JWT accepted" {
			t.Error("secure server should reject expired JWT")
		}
	}
}

func TestCheckAuth_AlgNone_Vulnerable(t *testing.T) {
	// Real JWT-bypass shape: server requires header but doesn't validate alg.
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	var found bool
	for _, f := range findings {
		if f.Title == "JWT algorithm confusion (alg:none accepted)" {
			found = true
			if f.Severity != models.SeverityCritical {
				t.Errorf("severity = %s, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected 'JWT algorithm confusion' finding")
	}
}

func TestCheckAuth_AlgNone_Secure(t *testing.T) {
	validToken := "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
	server := newJWTTestServer(validToken, true, true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Title == "JWT algorithm confusion (alg:none accepted)" {
			t.Error("secure server should reject alg:none JWT")
		}
	}
}

func TestCheckAuth_NonJWTAuth_SkipsJWTChecks(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "X-API-Key",
			Value:  "sk-live-abcdef123456",
			Type:   models.AuthTypeAPIKey,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users",
		FullURL: server.URL + "/api/users",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if strings.Contains(f.Title, "JWT") {
			t.Errorf("JWT checks should not run for non-JWT auth, found: %s", f.Title)
		}
	}

	// Should still detect unauthenticated access
	var foundUnauth bool
	for _, f := range findings {
		if f.Title == authTitleObserved {
			foundUnauth = true
		}
	}
	if !foundUnauth {
		t.Error("should still detect unauthenticated access for non-JWT auth")
	}
}

func TestIsJWTAuth(t *testing.T) {
	tests := []struct {
		name string
		auth *models.AuthContext
		want bool
	}{
		{"nil auth", nil, false},
		// Fix 3.6: header part must base64url-decode to a JSON object with an
		// "alg" key. eyJhbGciOiJIUzI1NiJ9 -> {"alg":"HS256"}.
		{"bearer JWT", &models.AuthContext{Value: "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}, true},
		{"raw JWT", &models.AuthContext{Value: "eyJhbGciOiJIUzI1NiJ9.payload.sig"}, true},
		{"api key", &models.AuthContext{Value: "sk-live-abc123"}, false},
		{"basic auth", &models.AuthContext{Value: "Basic dXNlcjpwYXNz"}, false},
		{"empty", &models.AuthContext{Value: ""}, false},
		{"bearer non-jwt", &models.AuthContext{Value: "Bearer simpletoken"}, false},
		// Fix 3.6: the old 3-dot heuristic FP'd on these; now rejected.
		{"3-dot non-jwt header not base64 json", &models.AuthContext{Value: "a.b.c"}, false},
		{"3-dot non-base64 header", &models.AuthContext{Value: "x.y.z"}, false},
		{"3-dot header has no alg key", &models.AuthContext{Value: "eyJ0eXAiOiJKV1QifQ.payload.sig"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJWTAuth(tt.auth)
			if got != tt.want {
				t.Errorf("isJWTAuth(%q) = %v, want %v", tt.auth, got, tt.want)
			}
		})
	}
}

func TestBuildExpiredJWT(t *testing.T) {
	// Empty realToken -> synthetic fallback path (fix 3.4).
	token := buildExpiredJWT("")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Error("all JWT parts should be non-empty")
	}
}

func TestBuildAlgNoneJWT(t *testing.T) {
	// Empty realToken -> synthetic fallback path (fix 3.4).
	token := buildAlgNoneJWT("")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	if parts[2] != "" {
		t.Error("alg:none JWT should have empty signature")
	}
}

// TestCheckAuth_PublicEndpointEmitsOnlyMissingAuth verifies the FP-dedup
// posture surfaced by the Track 4 heavy-eval (TwiScope-backend /metrics
// scan). When an endpoint accepts ALL Authorization values — no header,
// garbage Bearer, real JWT — it's fully public. The previous behaviour
// emitted 4 CRITICALs (Missing-auth + 3 JWT-bypass). The new behaviour
// emits only the root cause (Missing-auth); the 3 JWT findings are
// downstream byproducts of the same fix and add no operational signal.
func TestCheckAuth_PublicEndpointEmitsOnlyMissingAuth(t *testing.T) {
	server := newAuthTestServer("", true)
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/metrics",
		FullURL: server.URL + "/metrics",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
		if f.Source != models.SourceBlackbox {
			t.Errorf("finding %q source = %s, want blackbox", f.Title, f.Source)
		}
	}

	// Missing-auth fires (the root cause)
	if !titles[authTitleObserved] {
		t.Error("expected 'Missing authentication on endpoint' to fire on fully-public endpoint")
	}
	// The 3 JWT-bypass findings are suppressed as FPs of the root cause
	for _, suppressed := range []string{
		"JWT not validated",
		"Expired JWT accepted",
		"JWT algorithm confusion (alg:none accepted)",
	} {
		if titles[suppressed] {
			t.Errorf("Track 4 FP-dedup: %q should be suppressed on fully-public endpoint (root cause is missing-auth)", suppressed)
		}
	}
}

// TestCheckAuth_JWTBypassEndpointEmitsAllJWTFindings is the contrast
// case: when the endpoint DOES require an Authorization header but
// fails to validate the JWT structure, the missing-auth check does
// NOT fire, and the JWT-bypass findings should ALL fire because each
// is an independent vulnerability. This proves the dedup only kicks
// in on the public-endpoint shape, not on real JWT-bypass surfaces.
func TestCheckAuth_JWTBypassEndpointEmitsAllJWTFindings(t *testing.T) {
	server := newJWTOnlyServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
	}

	// Missing-auth should NOT fire (server returns 401 to no-auth)
	if titles[authTitleObserved] {
		t.Error("missing-auth should not fire when server returns 401 to no-Authorization request")
	}
	// All 3 JWT-bypass findings should fire (independent vulnerabilities)
	for _, expected := range []string{
		"JWT not validated",
		"Expired JWT accepted",
		"JWT algorithm confusion (alg:none accepted)",
	} {
		if !titles[expected] {
			t.Errorf("expected JWT-bypass finding %q to fire on header-checks-only server", expected)
		}
	}
}

// realJWTHeaderPayloadSig is a valid-shaped 3-part HS256 JWT used as the
// operator's "real" token in the Phase-3 tests below. Header decodes to
// {"alg":"HS256","typ":"JWT"} and payload to a claims object with a future
// exp, so isJWTAuth() accepts it and the real-token derivations (fix 3.4)
// have something to decode.
var realJWTHeaderPayloadSig = buildValidJWT("phase3-secret")

// ---------------------------------------------------------------------------
// Fix 3.1 — scheme-aware JWT tamper: a cookie-borne JWT must be tampered in
// the COOKIE channel, never on a hardcoded "Bearer" Authorization header.
// ---------------------------------------------------------------------------
func TestAuth_CookieJWTTamperUsesCookie(t *testing.T) {
	var sawAuthorization, sawCookie bool
	var cookieVal string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthorization = true
		}
		if c := r.Header.Get("Cookie"); c != "" {
			sawCookie = true
			cookieVal = c
		}
		// Require the cookie to be present (so the no-auth probe 401s and
		// missing-auth does not fire), but accept ANY cookie value (so the
		// malformed-JWT probe sees a 2xx — a real JWT-bypass shape).
		if r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","data":"protected-content-here"}`))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Cookie",
			Value:  "session=" + realJWTHeaderPayloadSig,
			Type:   models.AuthTypeCookie,
		},
	}
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/admin",
		FullURL: server.URL + "/api/admin",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	// The malformed-JWT probe must have travelled the cookie channel.
	if sawAuthorization {
		t.Error("fix 3.1: cookie-JWT tamper must NOT set a Bearer Authorization header")
	}
	if !sawCookie {
		t.Fatal("fix 3.1: cookie-JWT tamper must set the Cookie header")
	}
	if !strings.Contains(cookieVal, "session=") {
		t.Errorf("fix 3.1: tampered token must keep the cookie name; got Cookie=%q", cookieVal)
	}
	// And the JWT-bypass findings should still fire (the endpoint accepts a
	// garbage cookie value).
	var foundMalformed bool
	for _, f := range findings {
		if f.Title == "JWT not validated" {
			foundMalformed = true
		}
	}
	if !foundMalformed {
		t.Error("fix 3.1: expected 'JWT not validated' for cookie-JWT-bypass endpoint")
	}
}

// ---------------------------------------------------------------------------
// Fix 3.2 — garbage-auth dedup must send a body on POST so the auth decision
// isn't confounded by body validation (400-on-empty-body).
// ---------------------------------------------------------------------------
func TestAuth_GarbageAuthPOSTWithBody(t *testing.T) {
	// Endpoint: 400 on empty body; otherwise 200 for ANY auth (fully public
	// once a body is present). The garbage-auth dedup must send a body so it
	// observes the real auth outcome (200), letting it suppress JWT probes.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) == 0 {
			http.Error(w, `{"error":"body required"}`, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","created":true,"id":42}`))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer " + realJWTHeaderPayloadSig,
			Type:   models.AuthTypeBearer,
		},
	}
	endpoint := Endpoint{
		Method:  "POST",
		Path:    "/api/items",
		FullURL: server.URL + "/api/items",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
	}
	// Missing-auth fires (the endpoint 200s with no Authorization once a body
	// is present), and because the garbage-auth probe ALSO sends a body and
	// sees 200, the JWT-bypass probes are suppressed (Track-4 dedup). This
	// only works if both probes send a body (fix 3.2).
	if !titles[authTitleObserved] {
		t.Error("fix 3.2: expected 'Missing authentication' on body-200 endpoint (body must be sent)")
	}
	for _, suppressed := range []string{
		"JWT not validated", "Expired JWT accepted", "JWT algorithm confusion (alg:none accepted)",
	} {
		if titles[suppressed] {
			t.Errorf("fix 3.2: %q should be suppressed — garbage-auth probe must send a body so dedup sees the real auth outcome", suppressed)
		}
	}
}

// ---------------------------------------------------------------------------
// Fix 3.3 — status-only evidence is MEDIUM; a non-trivial body is HIGH.
// ---------------------------------------------------------------------------
func TestAuth_StatusOnlyIsMedium(t *testing.T) {
	t.Run("2xx empty body -> MEDIUM", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // no body
		}))
		defer server.Close()

		cfg := &models.ScanConfig{
			AllowPrivate: true, Timeout: 5,
			Auth: &models.AuthContext{Header: "Authorization", Value: "Bearer " + realJWTHeaderPayloadSig, Type: models.AuthTypeBearer},
		}
		endpoint := Endpoint{Method: "GET", Path: "/empty", FullURL: server.URL + "/empty"}

		findings := CheckAuth(context.Background(), cfg, endpoint)
		var f *ev.Evidence
		for i := range findings {
			if findings[i].Title == authTitleObserved {
				f = &findings[i]
			}
		}
		if f == nil {
			t.Fatal("expected missing-auth finding")
		}
		if f.Confidence != models.ConfidenceMedium {
			t.Errorf("fix 3.3: 2xx + empty body confidence = %s, want MEDIUM", f.Confidence)
		}
	})

	t.Run("2xx real content -> HIGH", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"users":[{"id":1,"email":"a@b.co"}],"total":1}`)) // > floor
		}))
		defer server.Close()

		cfg := &models.ScanConfig{
			AllowPrivate: true, Timeout: 5,
			Auth: &models.AuthContext{Header: "Authorization", Value: "Bearer " + realJWTHeaderPayloadSig, Type: models.AuthTypeBearer},
		}
		endpoint := Endpoint{Method: "GET", Path: "/users", FullURL: server.URL + "/users"}

		findings := CheckAuth(context.Background(), cfg, endpoint)
		var f *ev.Evidence
		for i := range findings {
			if findings[i].Title == authTitleObserved {
				f = &findings[i]
			}
		}
		if f == nil {
			t.Fatal("expected missing-auth finding")
		}
		if f.Confidence != models.ConfidenceHigh {
			t.Errorf("fix 3.3: 2xx + non-trivial body confidence = %s, want HIGH", f.Confidence)
		}
	})
}

// ---------------------------------------------------------------------------
// Fix 3.4 — the expired probe must be DERIVED from the operator's real JWT:
// same signature, but exp rewound to the past.
// ---------------------------------------------------------------------------
func TestAuth_ExpiredDerivedFromRealToken(t *testing.T) {
	secret := "derive-secret"
	realToken := buildValidJWT(secret)
	realParts := strings.Split(realToken, ".")
	realSig := realParts[2]

	expired := buildExpiredJWT(realToken)
	parts := strings.Split(expired, ".")
	if len(parts) != 3 {
		t.Fatalf("expired token: expected 3 parts, got %d", len(parts))
	}
	// Same signature as the real token (tests exp-without-resig).
	if parts[2] != realSig {
		t.Errorf("fix 3.4: expired token signature = %q, want real token's %q", parts[2], realSig)
	}
	// Header preserved.
	if parts[0] != realParts[0] {
		t.Errorf("fix 3.4: expired token header = %q, want real %q", parts[0], realParts[0])
	}
	// exp is in the past.
	claims, ok := decodeClaims(parts[1])
	if !ok {
		t.Fatal("fix 3.4: could not decode derived payload")
	}
	expF, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("fix 3.4: exp claim missing/not numeric: %v", claims["exp"])
	}
	if time.Unix(int64(expF), 0).After(time.Now()) {
		t.Errorf("fix 3.4: derived exp %v is not in the past", time.Unix(int64(expF), 0))
	}
}

// ---------------------------------------------------------------------------
// Fix 3.5 — the garbage-auth probe must use the CONFIGURED header/channel,
// not a hardcoded "Authorization".
// ---------------------------------------------------------------------------
func TestAuth_GarbageAuthUsesConfiguredHeader(t *testing.T) {
	var sawAuthorization bool
	var apiKeyVal string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthorization = true
		}
		if v := r.Header.Get("X-Api-Key"); v != "" {
			apiKeyVal = v
		}
		// Fully public (accepts everything) so missing-auth fires and the
		// garbage-auth dedup runs; the dedup must route junk via X-Api-Key.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true, Timeout: 5,
		Auth: &models.AuthContext{
			Header: "X-Api-Key",
			// A JWT value so isJWTAuth() is true and the dedup path engages.
			Value: realJWTHeaderPayloadSig,
			Type:  models.AuthTypeAPIKey,
		},
	}
	endpoint := Endpoint{Method: "GET", Path: "/data", FullURL: server.URL + "/data"}

	_ = CheckAuth(context.Background(), cfg, endpoint)

	if sawAuthorization {
		t.Error("fix 3.5: garbage-auth probe must NOT write the literal Authorization header for X-Api-Key auth")
	}
	if apiKeyVal == "" {
		t.Error("fix 3.5: garbage-auth probe must set the configured X-Api-Key header")
	}
}

// ---------------------------------------------------------------------------
// Fix 3.6 — isJWTAuth requires a real JOSE header with an alg key.
// ---------------------------------------------------------------------------
func TestIsJWTAuth_RequiresAlgHeader(t *testing.T) {
	tests := []struct {
		name string
		val  string
		want bool
	}{
		{"real JWT with alg header", realJWTHeaderPayloadSig, true},
		{"2-dot non-jwt a.b.c", "a.b.c", false},
		{"non-base64 x.y.z", "x.y.z", false},
		{"3-dot header without alg", "eyJ0eXAiOiJKV1QifQ.payload.sig", false}, // {"typ":"JWT"}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJWTAuth(&models.AuthContext{Value: tt.val})
			if got != tt.want {
				t.Errorf("isJWTAuth(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fix 3.7 — negative gate: if the REAL valid token does not yield 2xx (e.g. a
// 404 route), the JWT-bypass probes emit nothing.
// ---------------------------------------------------------------------------
func TestAuth_RealTokenAlsoFailsNoFindings(t *testing.T) {
	// Endpoint 404s regardless of auth (a route that doesn't exist / always
	// errors). A tampered token getting a 404 is NOT a bypass.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true, Timeout: 5,
		Auth: &models.AuthContext{Header: "Authorization", Value: "Bearer " + realJWTHeaderPayloadSig, Type: models.AuthTypeBearer},
	}
	endpoint := Endpoint{Method: "GET", Path: "/missing", FullURL: server.URL + "/missing"}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if strings.Contains(f.Title, "JWT") {
			t.Errorf("fix 3.7: no JWT-bypass finding should fire when the real token also fails; got %q", f.Title)
		}
	}
	if len(findings) != 0 {
		t.Errorf("fix 3.7: expected 0 findings on a 404-always endpoint, got %d", len(findings))
	}
}
