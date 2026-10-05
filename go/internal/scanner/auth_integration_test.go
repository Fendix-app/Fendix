package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// jwtMockServer is a realistic mock that validates JWT tokens:
// - Decodes header and payload
// - Verifies HS256 signature against a known secret
// - Checks exp claim
// - Rejects alg:none
// - Returns 401 for missing/invalid auth
type jwtMockServer struct {
	secret string
}

func (j *jwtMockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, `{"error":"invalid scheme"}`, http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		http.Error(w, `{"error":"malformed token"}`, http.StatusUnauthorized)
		return
	}

	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		http.Error(w, `{"error":"invalid header encoding"}`, http.StatusUnauthorized)
		return
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		http.Error(w, `{"error":"invalid header json"}`, http.StatusUnauthorized)
		return
	}

	alg, _ := header["alg"].(string)
	if alg == "none" || alg == "" {
		http.Error(w, `{"error":"algorithm not allowed"}`, http.StatusUnauthorized)
		return
	}

	if alg != "HS256" {
		http.Error(w, `{"error":"unsupported algorithm"}`, http.StatusUnauthorized)
		return
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := hmacSHA256Sign([]byte(signingInput), []byte(j.secret))
	actualSig, err := base64URLDecode(parts[2])
	if err != nil || !hmac.Equal(actualSig, expectedSig) {
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		http.Error(w, `{"error":"invalid payload encoding"}`, http.StatusUnauthorized)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		http.Error(w, `{"error":"invalid payload json"}`, http.StatusUnauthorized)
		return
	}

	if exp, ok := payload["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","user":"authenticated"}`))
}

func hmacSHA256Sign(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func base64URLDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func buildValidJWT(secret string) string {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}))
	payload := base64URLEncode(mustJSON(map[string]interface{}{
		"sub":  "user-123",
		"role": "admin",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
	}))
	signingInput := header + "." + payload
	sig := base64URLEncode(hmacSHA256Sign([]byte(signingInput), []byte(secret)))
	return signingInput + "." + sig
}

// --- Integration tests against realistic JWT mock ---

func TestIntegration_SecureJWTServer_NoFindings(t *testing.T) {
	secret := "test-secret-key-256"
	server := httptest.NewServer(&jwtMockServer{secret: secret})
	defer server.Close()

	validToken := buildValidJWT(secret)

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer " + validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/secure",
		FullURL: server.URL + "/api/secure",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding on secure server: %s (severity=%s)", f.Title, f.Severity)
		}
	}
}

// TestIntegration_VulnerableServer_AcceptsEverything is the
// fully-public endpoint shape. Under the Track 4 FP-dedup posture
// (auth.go: when missing-auth fires AND a garbage Authorization
// header also yields 200, suppress JWT-bypass findings on this
// endpoint), the only finding here is the root-cause Missing-auth.
// The 3 JWT findings would have been emitted by the pre-fix code
// but are derivative byproducts of the same defect.
func TestIntegration_VulnerableServer_AcceptsEverything(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
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

	titles := map[string]bool{}
	for _, f := range findings {
		titles[f.Title] = true
	}

	if !titles[authTitleObserved] {
		t.Error("expected 'Missing authentication on endpoint' (root cause)")
	}
	for _, suppressed := range []string{
		"JWT not validated",
		"Expired JWT accepted",
		"JWT algorithm confusion (alg:none accepted)",
	} {
		if titles[suppressed] {
			t.Errorf("Track 4 FP-dedup: %q should be suppressed on fully-public endpoint", suppressed)
		}
	}
}

func TestIntegration_ServerRejectsExpiredButAcceptsAlgNone(t *testing.T) {
	secret := "partial-security"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		parts := strings.Split(token, ".")

		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Reject malformed tokens
		if token == "invalid.jwt.token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		headerBytes, err := base64URLDecode(parts[0])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var header map[string]interface{}
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// BUG: accepts alg:none! (common vulnerability)
		if alg, _ := header["alg"].(string); alg == "HS256" {
			signingInput := parts[0] + "." + parts[1]
			expectedSig := hmacSHA256Sign([]byte(signingInput), []byte(secret))
			actualSig, err := base64URLDecode(parts[2])
			if err != nil || !hmac.Equal(actualSig, expectedSig) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		payloadBytes, err := base64URLDecode(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Does check expiration
		if exp, ok := payload["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	validToken := buildValidJWT(secret)

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer " + validToken,
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/partial",
		FullURL: server.URL + "/api/partial",
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	foundAlgNone := false
	for _, f := range findings {
		if f.Title == "JWT algorithm confusion (alg:none accepted)" {
			foundAlgNone = true
		}
		if f.Title == "Expired JWT accepted" {
			t.Error("server properly rejects expired JWT, should not report this")
		}
		if f.Title == "JWT not validated" {
			t.Error("server rejects malformed JWT, should not report this")
		}
	}

	if !foundAlgNone {
		t.Error("should detect alg:none vulnerability")
	}
}

func TestIntegration_AuthFindingsHaveCorrectFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer eyJhbGciOiJIUzI1NiJ9.p.s",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/validate",
		FullURL: server.URL + "/api/validate",
		// RC-2: this test asserts the field shape of CRITICAL auth findings, so
		// the fixture has to be the shape that produces one — a spec-declared
		// protected operation. With no declared expectation the same live
		// result is an observation at MEDIUM, which is correct and is covered
		// separately.
		AuthExpectation: models.AuthExpectationRequired,
	}

	findings := CheckAuth(context.Background(), cfg, endpoint)

	for _, f := range findings {
		if f.Source != models.SourceBlackbox {
			t.Errorf("finding %q: source = %s, want blackbox", f.Title, f.Source)
		}
		if f.Category != "auth_bypass" {
			t.Errorf("finding %q: category = %s, want auth_bypass", f.Title, f.Category)
		}
		if f.Severity != models.SeverityCritical {
			t.Errorf("finding %q: severity = %s, want CRITICAL", f.Title, f.Severity)
		}
		// Fix 3.3 (confidence corroboration): this server writes a 2xx with
		// NO body, so every finding is corroborated by the status code only
		// -> MEDIUM. (Pre-3.3 this asserted HIGH unconditionally; the empty
		// body is exactly the weak signal the corroboration rule downgrades.)
		if f.Confidence != models.ConfidenceMedium {
			t.Errorf("finding %q: confidence = %s, want MEDIUM (status-only, empty body)", f.Title, f.Confidence)
		}
		if f.Endpoint != "GET /api/validate" {
			t.Errorf("finding %q: endpoint = %s, want GET /api/validate", f.Title, f.Endpoint)
		}
		if f.Evidence == "" {
			t.Errorf("finding %q: evidence should not be empty", f.Title)
		}
		if f.Fix == "" {
			t.Errorf("finding %q: fix should not be empty", f.Title)
		}
		if len(f.References) == 0 {
			t.Errorf("finding %q: references should not be empty", f.Title)
		}
	}
}

func TestIntegration_IDOR_WithJWTServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Vulnerable: returns same data regardless of user
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"records":[{"id":1},{"id":2},{"id":3}]}`))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-jwt.token.here",
			Type:   models.AuthTypeBearer,
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2-jwt.token.here",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/records",
		FullURL: server.URL + "/api/records",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)

	if len(findings) != 1 {
		t.Fatalf("expected 1 IDOR finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Category != "idor" {
		t.Errorf("category = %s, want idor", f.Category)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
}
