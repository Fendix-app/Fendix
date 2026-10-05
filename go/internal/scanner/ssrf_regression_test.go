package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestSSRFGuard_SharedClientBlocksMetadataIP proves Phase 0b C2/C3: the shared
// CheckContext clients carry the netguard SSRF egress guard, so a check can no
// longer be steered into the cloud-metadata IP. We assert at the guard layer
// directly (a request through cc.Client to 169.254.169.254) rather than via a
// loopback httptest round-trip, because relaxing the guard with
// AllowPrivate=true to reach a 127.0.0.1 test server would also unblock the
// metadata IP (AllowPrivate is a full guard passthrough) — the SSRF test
// paradox. With AllowPrivate=false the guard validates the IP literal at
// connect time with no lookup, so this is a deterministic, network-free proof.
func TestSSRFGuard_SharedClientBlocksMetadataIP(t *testing.T) {
	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: false}
	cc := NewCheckContext(cfg)

	for name, client := range map[string]*http.Client{"Client": cc.Client, "NoFollow": cc.NoFollow} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), "GET", "http://169.254.169.254/latest/meta-data/", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			_, err = client.Do(req)
			if err == nil {
				t.Fatalf("expected SSRF guard to refuse the metadata IP, but the request succeeded")
			}
			if !strings.Contains(err.Error(), "SSRF guard") {
				t.Errorf("expected an SSRF-guard refusal, got: %v", err)
			}
		})
	}
}

// TestSSRFGuard_AllowPrivateReachesLoopback confirms the guard relaxes for an
// operator-authorized private target (AllowPrivate=true) — the localhost-scan
// path real scans take. Without this, the unit tests for the migrated checks
// could not reach their httptest servers; this documents that the relaxation
// is intentional and scoped to opt-in.
func TestSSRFGuard_AllowPrivateReachesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cc := NewCheckContext(&models.ScanConfig{Timeout: 5, AllowPrivate: true})
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL, nil)
	resp, err := cc.Client.Do(req)
	if err != nil {
		t.Fatalf("AllowPrivate=true should reach the loopback test server, got: %v", err)
	}
	resp.Body.Close()
}

// TestRedirectSemantics_NoFollowSeesRaw302 proves the two-client design: the
// no-follow client (used by auth/idor/open-redirect/host-header) surfaces the
// raw 3xx instead of following it. A protected endpoint that 302-redirects an
// unauthenticated request to /login must therefore NOT be reported as "Missing
// authentication" — the 302 is not a 2xx, which is the exact failure mode the
// guarded follow-client would have caused if auth used cc.Client.
func TestRedirectSemantics_NoFollowSeesRaw302(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Authorization header → redirect to login (the secure behavior).
		if r.Header.Get("Authorization") == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &models.ScanConfig{
		Timeout:      5,
		AllowPrivate: true,
		Auth: &models.AuthContext{
			Header: "Authorization",
			Value:  "Bearer a.b.c",
			Type:   models.AuthTypeBearer,
		},
	}
	ep := Endpoint{Method: "GET", Path: "/protected", FullURL: srv.URL + "/protected"}
	got := authCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	for _, f := range got {
		if f.Title == "Missing authentication on endpoint" {
			t.Errorf("302->/login wrongly flagged as missing authentication (no-follow client should see the raw 302, not follow it)")
		}
	}
}

// TestRedirectSemantics_NoFollowDoesNotFollow is the direct mechanical proof
// that cc.NoFollow returns the 3xx without following, independent of any check.
func TestRedirectSemantics_NoFollowDoesNotFollow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/dest", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK) // /dest
	}))
	defer srv.Close()

	cc := NewCheckContext(&models.ScanConfig{Timeout: 5, AllowPrivate: true})
	req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+"/start", nil)
	resp, err := cc.NoFollow.Do(req)
	if err != nil {
		t.Fatalf("no-follow request errored: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("no-follow client should return the raw 302, got status %d", resp.StatusCode)
	}
}
