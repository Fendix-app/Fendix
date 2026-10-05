package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// newIDORVulnerableServer returns the same response regardless of which user token is used.
func newIDORVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":42,"name":"Shared Resource","secret":"data"}`))
	}))
}

// newIDORSecureServer returns different responses per user token.
func newIDORSecureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":1,"name":"User 1 Data"}`))
		case "Bearer user2-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":2,"name":"User 2 Data"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
}

func TestCheckIDOR_Vulnerable(t *testing.T) {
	server := newIDORVulnerableServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
			Type:   models.AuthTypeBearer,
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users/42",
		FullURL: server.URL + "/api/users/42",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if f.Category != "idor" {
		t.Errorf("category = %s, want idor", f.Category)
	}
	// Phase 5.2/5.7 deliberate change: /api/users/42 carries a numeric
	// path object-id, so this now routes through the cross-tenant
	// id-mutation path (user2 read user1's id 42 and got 2xx) — direct
	// access-control evidence → HIGH confidence (was MEDIUM under the old
	// same-URL byte-equality heuristic).
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence = %s, want HIGH (id-mutation path)", f.Confidence)
	}
}

func TestCheckIDOR_Secure(t *testing.T) {
	server := newIDORSecureServer()
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
			Type:   models.AuthTypeBearer,
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2-token",
			Type:   models.AuthTypeBearer,
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/users/me",
		FullURL: server.URL + "/api/users/me",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure server, got %d", len(findings))
	}
}

func TestCheckIDOR_NoUser2_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1-token",
		},
		AuthUser2: nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/resource",
		FullURL: "http://localhost/api/resource",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings without user2, got %d", len(findings))
	}
}

func TestCheckIDOR_NoAuth_Skips(t *testing.T) {
	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         nil,
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/resource",
		FullURL: "http://localhost/api/resource",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings without auth, got %d", len(findings))
	}
}

func TestCheckIDOR_EmptyResponse_NoFinding(t *testing.T) {
	// No object identifier in the path → same-URL fallback (5.1). Both
	// users get an empty 200, so the fallback has no structural body
	// signal to work with and must NOT flag (avoids FP on a shared
	// always-empty endpoint that is not access-control evidence).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user1",
		},
		AuthUser2: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer user2",
		},
	}

	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/empty",
		FullURL: server.URL + "/api/empty",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("empty responses (no id, same-URL fallback) should not trigger IDOR, got %d findings", len(findings))
	}
}

// 5.1 — Structural fingerprint instead of exact byte-equality.
// Two users get 200s with the SAME JSON shape but different dynamic
// values (timestamp / request-id). Exact byte-equality missed this; the
// structural fingerprint (same top-level key set) must fire. No object
// identifier in the path → same-URL fallback → Medium confidence.
func TestIDOR_StructurallyIdenticalDynamicContent(t *testing.T) {
	var n int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n++
		w.WriteHeader(http.StatusOK)
		// Same shape, different volatile values per request.
		fmt.Fprintf(w, `{"id":7,"name":"Profile","request_id":"req-%d","ts":"2026-06-18T00:00:%02dZ"}`, n, n)
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Header: "Authorization", Value: "Bearer user1-token"},
		AuthUser2:    &models.AuthContext{Header: "Authorization", Value: "Bearer user2-token"},
	}
	// /api/profile has no object id → same-URL structural fallback.
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/profile",
		FullURL: server.URL + "/api/profile",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for structurally-identical bodies, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", findings[0].Severity)
	}
	if findings[0].Confidence != models.ConfidenceMedium {
		t.Errorf("same-URL fallback confidence = %s, want MEDIUM", findings[0].Confidence)
	}
}

// 5.1 negative — different JSON shapes (different top-level keys) must
// NOT flag, even though both are 200. Guards the structural fingerprint
// against the "both 200" over-trigger.
func TestIDOR_DifferentShapeNoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"id":1,"name":"User 1","role":"admin"}`))
		case "Bearer user2-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"order":99,"total":42}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Header: "Authorization", Value: "Bearer user1-token"},
		AuthUser2:    &models.AuthContext{Header: "Authorization", Value: "Bearer user2-token"},
	}
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/thing",
		FullURL: server.URL + "/api/thing",
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("different JSON shapes must not flag, got %d findings", len(findings))
	}
}

// 5.2 — Cross-tenant id-mutation. The endpoint carries an object id in
// the query (?id=1001 — user1's resource). user2 (a different account)
// requesting the SAME id ALSO gets 200 + body → cross-tenant IDOR. The
// server returns DIFFERENT body bytes per token, so exact-equality
// would have missed it; the id-mutation path keys on access-control
// semantics (user2 got 2xx for user1's id) → HIGH confidence.
func TestIDOR_CrossTenantIdMutation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Broken authz: any authenticated user can read order 1001.
		switch r.Header.Get("Authorization") {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"order":1001,"owner":"user1","viewer":"user1"}`))
		case "Bearer user2-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"order":1001,"owner":"user1","viewer":"user2"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Header: "Authorization", Value: "Bearer user1-token"},
		AuthUser2:    &models.AuthContext{Header: "Authorization", Value: "Bearer user2-token"},
	}
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/orders",
		FullURL: server.URL + "/api/orders?id=1001",
		Params:  []string{"id"},
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 1 {
		t.Fatalf("expected 1 cross-tenant IDOR finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %s, want HIGH", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("id-mutation confidence = %s, want HIGH (direct access-control evidence)", f.Confidence)
	}
}

// 5.2 negative — user2 gets 403 for user1's id → authz is enforced → no
// finding.
func TestIDOR_CrossTenantIdMutation_Enforced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"order":1001,"owner":"user1"}`))
		case "Bearer user2-token":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"detail":"forbidden"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Header: "Authorization", Value: "Bearer user1-token"},
		AuthUser2:    &models.AuthContext{Header: "Authorization", Value: "Bearer user2-token"},
	}
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/orders",
		FullURL: server.URL + "/api/orders?id=1001",
		Params:  []string{"id"},
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 0 {
		t.Errorf("user2 403 for user1's id → enforced authz → no finding, got %d", len(findings))
	}
}

// 5.3 — Empty-but-200 on the id-mutation path. user2 gets a 200 with an
// EMPTY body for user1's resource. The access-control bypass (user2 read
// user1's id and got 2xx) is the signal — the empty body must NOT
// silently drop it.
func TestIDOR_EmptyBody200NotSilentlyDropped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer user1-token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"order":1001,"owner":"user1"}`))
		case "Bearer user2-token":
			// 200 with empty body — still an authz bypass for user1's id.
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	cfg := &models.ScanConfig{
		AllowPrivate: true,
		Timeout:      5,
		Auth:         &models.AuthContext{Header: "Authorization", Value: "Bearer user1-token"},
		AuthUser2:    &models.AuthContext{Header: "Authorization", Value: "Bearer user2-token"},
	}
	endpoint := Endpoint{
		Method:  "GET",
		Path:    "/api/orders",
		FullURL: server.URL + "/api/orders?id=1001",
		Params:  []string{"id"},
	}

	findings := CheckIDOR(context.Background(), cfg, endpoint)
	if len(findings) != 1 {
		t.Fatalf("empty-but-200 on id-mutation is an authz bypass; expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != models.ConfidenceHigh {
		t.Errorf("id-mutation confidence = %s, want HIGH", findings[0].Confidence)
	}
}
