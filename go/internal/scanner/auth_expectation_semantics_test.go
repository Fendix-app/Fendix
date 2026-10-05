package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func serve200(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","uptime":123,"version":"2.1.0"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func authScanCfg(target string) *models.ScanConfig {
	return &models.ScanConfig{
		URL:          target,
		AllowPrivate: true,
		Auth:         &models.AuthContext{Type: "bearer", Value: "eyJhbGciOiJIUzI1NiJ9.e30.sig"},
	}
}

func authBypassFindings(t *testing.T, ep Endpoint, target string) []struct {
	Title    string
	Severity models.Severity
	Exp      models.AuthExpectation
	Src      string
	Evidence string
} {
	t.Helper()
	var out []struct {
		Title    string
		Severity models.Severity
		Exp      models.AuthExpectation
		Src      string
		Evidence string
	}
	for _, e := range CheckAuth(context.Background(), authScanCfg(target), ep) {
		if e.Category != "auth_bypass" {
			continue
		}
		out = append(out, struct {
			Title    string
			Severity models.Severity
			Exp      models.AuthExpectation
			Src      string
			Evidence string
		}{e.Title, e.Severity, e.AuthExpectation, e.AuthExpectationSource, e.Evidence})
	}
	return out
}

// THE RC-2 CASE. A 200 without credentials on an endpoint whose expectation was
// never established is an OBSERVATION. It must not claim bypass, must not carry
// a severity that can gate a build, and must say in its evidence why it is not
// a confirmed finding.
func TestUnknownExpectationYieldsObservationNotBypass(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{Method: "GET", Path: "/status", FullURL: srv.URL + "/status"} // AuthExpectation zero

	got := authBypassFindings(t, ep, srv.URL)
	if len(got) == 0 {
		t.Fatal("no finding — evidence must be PRESERVED and de-escalated, never dropped (Rule 3)")
	}
	f := got[0]
	if f.Title != "Unauthenticated endpoint observed" {
		t.Errorf("Title = %q, want %q", f.Title, "Unauthenticated endpoint observed")
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q, want MEDIUM — an unconfirmed observation must not gate", f.Severity)
	}
	if f.Exp != models.AuthExpectationUnknown {
		t.Errorf("AuthExpectation = %q, want unknown", f.Exp)
	}
	if f.Src != "" {
		t.Errorf("AuthExpectationSource = %q, want empty — nothing declared an expectation", f.Src)
	}
	if !strings.Contains(f.Evidence, "no authentication requirement was established") {
		t.Errorf("Evidence does not explain why this is unconfirmed: %q", f.Evidence)
	}
}

// A spec-declared protected endpoint returning 200 unauthenticated IS a bypass:
// the live observation contradicts a declared requirement, which is two
// observations disagreeing.
func TestRequiredExpectationYieldsConfirmedBypass(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{
		Method: "GET", Path: "/api/users", FullURL: srv.URL + "/api/users",
		AuthExpectation: models.AuthExpectationRequired,
	}

	got := authBypassFindings(t, ep, srv.URL)
	if len(got) == 0 {
		t.Fatal("expected a bypass finding, got none")
	}
	f := got[0]
	if f.Title != "Authentication requirement bypassed" {
		t.Errorf("Title = %q, want %q", f.Title, "Authentication requirement bypassed")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", f.Severity)
	}
	if f.Src != "openapi" {
		t.Errorf("AuthExpectationSource = %q, want %q", f.Src, "openapi")
	}
}

// A spec-declared public endpoint returning 200 is working as designed.
func TestPublicExpectationIsInformational(t *testing.T) {
	srv := serve200(t)
	ep := Endpoint{
		Method: "GET", Path: "/health", FullURL: srv.URL + "/health",
		AuthExpectation: models.AuthExpectationPublic,
	}

	for _, f := range authBypassFindings(t, ep, srv.URL) {
		if f.Severity != models.SeverityInfo {
			t.Errorf("declared-public endpoint produced %q at %q, want INFO", f.Title, f.Severity)
		}
		if f.Title == "Authentication requirement bypassed" {
			t.Errorf("declared-public endpoint reported a bypass: %q", f.Title)
		}
	}
}

// No path is special-cased. The SAME path is observational or a confirmed
// bypass depending only on what the spec declared — which is the difference
// between a semantic fix and an allowlist.
func TestClassificationIsSemanticNotPathBased(t *testing.T) {
	srv := serve200(t)

	unknown := authBypassFindings(t, Endpoint{
		Method: "GET", Path: "/status", FullURL: srv.URL + "/status",
	}, srv.URL)
	protected := authBypassFindings(t, Endpoint{
		Method: "GET", Path: "/status", FullURL: srv.URL + "/status",
		AuthExpectation: models.AuthExpectationRequired,
	}, srv.URL)

	if len(unknown) == 0 || len(protected) == 0 {
		t.Fatal("both shapes must produce a finding")
	}
	if unknown[0].Title == protected[0].Title {
		t.Errorf("both /status probes produced %q — the claim is not keyed on the expectation",
			unknown[0].Title)
	}
	if protected[0].Severity != models.SeverityCritical {
		t.Errorf("a /status the spec declares protected must still be CRITICAL, got %q",
			protected[0].Severity)
	}
}
