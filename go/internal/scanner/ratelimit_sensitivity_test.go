package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// The classifier is unit-tested directly rather than only through HTTP probes,
// so every rule is covered without twenty requests per case and without the
// active-scan gating that decides whether a POST is probed at all.
func TestAbuseSensitivityClassification(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		method   string
		want     abuseSensitivity
	}{
		// --- authentication / identity gateways: the canonical targets ---
		{"login", Endpoint{Method: "POST", Path: "/api/v1/login"}, "POST", abuseCredential},
		{"signin hyphenated", Endpoint{Method: "POST", Path: "/api/sign-in"}, "POST", abuseCredential},
		{"password reset request", Endpoint{Method: "POST", Path: "/auth/password/reset"}, "POST", abuseCredential},
		{"password reset confirm", Endpoint{Method: "POST", Path: "/auth/reset-password/confirm"}, "POST", abuseCredential},
		{"otp verify", Endpoint{Method: "POST", Path: "/api/otp/verify"}, "POST", abuseCredential},
		{"mfa challenge", Endpoint{Method: "POST", Path: "/api/mfa/challenge"}, "POST", abuseCredential},
		{"account verification", Endpoint{Method: "POST", Path: "/accounts/verify"}, "POST", abuseCredential},
		{"resend verification", Endpoint{Method: "POST", Path: "/accounts/resend-verification"}, "POST", abuseCredential},
		{"registration", Endpoint{Method: "POST", Path: "/api/v1/register"}, "POST", abuseCredential},
		{"invitation", Endpoint{Method: "POST", Path: "/org/invitations"}, "POST", abuseCredential},
		{"token issuance", Endpoint{Method: "POST", Path: "/oauth/token"}, "POST", abuseCredential},

		// Semantic (parameter) signal with a route name that gives nothing
		// away — the case a route-token list alone cannot reach.
		{
			"credential parameter on an opaque route",
			Endpoint{Method: "POST", Path: "/api/v2/gateway", BodyParams: []string{"username", "password"}},
			"POST", abuseCredential,
		},
		{
			"otp parameter on an opaque route",
			Endpoint{Method: "POST", Path: "/x/y/z", BodyParams: []string{"otp_code"}},
			"POST", abuseCredential,
		},
		{
			"camelCase credential parameter normalizes",
			Endpoint{Method: "POST", Path: "/api/step2", BodyParams: []string{"newPassword"}},
			"POST", abuseCredential,
		},

		// --- link-driven identity reads stay credential-grade ---
		{"GET email verification link", Endpoint{Method: "GET", Path: "/verify-email"}, "GET", abuseCredential},
		{"GET invitation accept", Endpoint{Method: "GET", Path: "/invitations/accept"}, "GET", abuseCredential},

		// --- identity NOUNS under a read are ordinary listings ---
		{"GET sessions list", Endpoint{Method: "GET", Path: "/api/sessions"}, "GET", abuseOrdinary},
		{"GET tokens list", Endpoint{Method: "GET", Path: "/api/tokens"}, "GET", abuseOrdinary},

		// --- ordinary operations ---
		{"ordinary list", Endpoint{Method: "GET", Path: "/api/v1/users"}, "GET", abuseOrdinary},
		{"ordinary retrieve", Endpoint{Method: "GET", Path: "/api/v1/orders/{id}"}, "GET", abuseOrdinary},
		{"ordinary nested read", Endpoint{Method: "GET", Path: "/api/v1/projects/{id}/items"}, "GET", abuseOrdinary},

		// --- the substring trap: these must NOT be graded as credentials ---
		{"authors is not auth", Endpoint{Method: "GET", Path: "/api/authors"}, "GET", abuseOrdinary},
		{"tokenizer is not token", Endpoint{Method: "GET", Path: "/api/tokenizer"}, "GET", abuseOrdinary},
		{"resetting is not reset", Endpoint{Method: "GET", Path: "/api/resettings"}, "GET", abuseOrdinary},

		// --- operation cost, modulated by declared authentication ---
		{
			"public export is elevated",
			Endpoint{Method: "GET", Path: "/api/reports/export", AuthExpectation: models.AuthExpectationUnknown},
			"GET", abuseElevated,
		},
		{
			"public mail send is elevated",
			Endpoint{Method: "POST", Path: "/api/notifications/email", AuthExpectation: models.AuthExpectationPublic},
			"POST", abuseElevated,
		},
		{
			"declared-authenticated export de-escalates",
			Endpoint{Method: "GET", Path: "/api/reports/export", AuthExpectation: models.AuthExpectationRequired},
			"GET", abuseOrdinary,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := classifyAbuseSensitivity(tc.endpoint, tc.method)
			if got != tc.want {
				t.Errorf("classify(%s %s) = %v, want %v (reason: %s)",
					tc.method, tc.endpoint.Path, got, tc.want, reason)
			}
			if reason == "" {
				t.Error("every grade must state the signal that produced it")
			}
		})
	}
}

// Unknown authentication must never be read as "probably authenticated". This
// is the same asymmetry the CORS reflection grade uses: only a POSITIVE
// declaration de-escalates, because absence of a declaration is not evidence
// that a control exists.
func TestUnknownAuthDoesNotDeescalateExpensiveOperations(t *testing.T) {
	ep := Endpoint{Method: "GET", Path: "/api/search"} // AuthExpectation zero = unknown
	got, reason := classifyAbuseSensitivity(ep, "GET")
	if got != abuseElevated {
		t.Errorf("unknown auth expectation must not de-escalate; got %v (%s)", got, reason)
	}
}

// Severity mapping is the contract the dedup key groups on, so it is asserted
// directly rather than inferred from a probe.
func TestAbuseSensitivitySeverityMapping(t *testing.T) {
	if got := abuseOrdinary.severity(); got != models.SeverityInfo {
		t.Errorf("ordinary must be INFO, got %s", got)
	}
	if got := abuseElevated.severity(); got != models.SeverityMedium {
		t.Errorf("elevated must be MEDIUM, got %s", got)
	}
	if got := abuseCredential.severity(); got != models.SeverityMedium {
		t.Errorf("credential must be MEDIUM, got %s", got)
	}
}

// End-to-end through the real probe: a login endpoint must come out MEDIUM,
// keep the bounded-burst wording, and keep both scope disclaimers. The
// prioritization must not have been bought by weakening the claim.
func TestCheckRateLimit_LoginIsPrioritized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "POST", Path: "/api/v1/login", FullURL: server.URL + "/api/v1/login"}
	// EnableActive: a POST is only burst-probed under --active, since the check
	// is passive-tier and would otherwise issue twenty writes at a live target.
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true, EnableActive: true}

	findings := CheckRateLimit(context.Background(), cfg, ep)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM for an unlimited login, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "abuse-sensitive") {
		t.Errorf("the prioritized group must be identifiable from its title, got %q", f.Title)
	}
	// Preserved evidence discipline — these are the good behaviours the
	// prioritization must not trade away.
	for _, must := range []string{
		"Scope note:",
		"cannot prove the absence of slower per-minute/per-hour limiters",
		"Granularity note:",
		"Prioritization note:",
	} {
		if !strings.Contains(f.Evidence, must) {
			t.Errorf("evidence lost %q:\n%s", must, f.Evidence)
		}
	}
}

// The acceptance criterion, exercised on the shape that motivated it: a large
// endpoint set must not collapse into one undifferentiated WARN. It must split
// into an abuse-sensitive group and an ordinary group, each aggregating its own
// endpoints — which is what the existing Severity|Category|Title dedup key does
// once severity carries the context.
func TestLargeEndpointSetSplitsIntoPrioritizedGroups(t *testing.T) {
	sensitivePaths := []string{
		"/api/v1/login", "/api/v1/register", "/auth/password/reset",
		"/api/otp/verify", "/api/mfa/challenge", "/oauth/token",
	}

	groups := map[string]int{}
	classify := func(path, method string) {
		sensitivity, _ := classifyAbuseSensitivity(Endpoint{Method: method, Path: path}, method)
		title := "No rate limiting observed within 20 requests"
		if sensitivity != abuseOrdinary {
			title += " on an abuse-sensitive operation"
		}
		// Mirrors engine.dedupKey: Severity|Category|Title.
		groups[string(sensitivity.severity())+"|rate_limiting|"+title]++
	}

	for _, p := range sensitivePaths {
		classify(p, "POST")
	}
	// 700 ordinary reads — the scale from the report that motivated this.
	for i := 0; i < 700; i++ {
		classify("/api/v1/resource"+string(rune('a'+i%26))+"/items", "GET")
	}

	if len(groups) != 2 {
		t.Fatalf("expected exactly 2 aggregation groups (prioritized + ordinary), got %d: %v", len(groups), groups)
	}

	var medium, info int
	for key, n := range groups {
		switch {
		case strings.HasPrefix(key, string(models.SeverityMedium)+"|"):
			medium = n
		case strings.HasPrefix(key, string(models.SeverityInfo)+"|"):
			info = n
		}
	}
	if medium != len(sensitivePaths) {
		t.Errorf("expected %d endpoints in the prioritized group, got %d", len(sensitivePaths), medium)
	}
	if info != 700 {
		t.Errorf("expected 700 endpoints in the ordinary group, got %d", info)
	}
	// Nothing was deleted to achieve the split.
	if medium+info != len(sensitivePaths)+700 {
		t.Errorf("endpoints went missing: %d + %d != %d", medium, info, len(sensitivePaths)+700)
	}
}
