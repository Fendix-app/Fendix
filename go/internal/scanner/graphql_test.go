package scanner

// Integration tests for the active GraphQL introspection-exposure check
// (CWE-200). They drive graphQLCheck.Run against loopback httptest servers, so
// every cfg sets AllowPrivate: true (the netguard egress guard would otherwise
// block the dial to the 127.0.0.1 test server — same paradox as the SSRF /
// host-header tests).
//
// LOAD-BEARING negative tests that MUST stay green (the full data.__schema shape
// is required for a finding, NEVER a bare 200):
//   - TestGraphQL_Bare200NoFinding: a 200 application/json body with NO __schema
//     ({"ok":true}) yields NO finding.
//   - TestGraphQL_HTML200NoFinding: a 200 text/html page yields NO finding.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeGraphQLCfg returns the standard active-scan config for these tests.
// AllowPrivate:true is mandatory so the egress guard does not block the dial to
// the loopback httptest server.
func activeGraphQLCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// graphQLRootEP builds an Endpoint at the server origin root ("/"). The bounded
// origin sweep derives the candidate /graphql-family paths from this; the path
// itself does NOT contain "graphql".
func graphQLRootEP(server *httptest.Server) Endpoint {
	return Endpoint{Method: "GET", Path: "/", FullURL: server.URL + "/"}
}

// introspectionJSON is a valid minimal introspection response body.
const introspectionJSON = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null}}}`

// introspectionWithMutations exposes a non-null named mutationType.
const introspectionWithMutations = `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"}}}}`

// gqlIntrospectionHandler returns a handler that answers POST introspection at
// /graphql with the given body (application/json) and 404s everything else.
func gqlIntrospectionHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// findGraphQLFinding returns the introspection finding (HIGH) if present.
func findGraphQLFinding(findings []ev.Evidence, titleContains string) (ev.Evidence, bool) {
	for _, f := range findings {
		if strings.Contains(f.Title, titleContains) {
			return f, true
		}
	}
	return ev.Evidence{}, false
}

// TestGraphQL_IntrospectionEnabled: /graphql answers a valid introspection
// payload (queryType present, mutationType null) → exactly one HIGH finding.
func TestGraphQL_IntrospectionEnabled(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(gqlIntrospectionHandler(introspectionJSON))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	intro, ok := findGraphQLFinding(findings, "introspection enabled")
	if !ok {
		t.Fatalf("expected a GraphQL introspection-enabled finding, got %+v", findings)
	}
	if intro.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", intro.Severity)
	}
	if intro.Category != "graphql" {
		t.Errorf("expected category=graphql, got %q", intro.Category)
	}
	if intro.Source != models.SourceBlackbox {
		t.Errorf("expected source=blackbox, got %q", intro.Source)
	}
	if !hasRef(intro, "CWE-200") {
		t.Errorf("expected CWE-200 reference, got %v", intro.References)
	}
}

// TestGraphQL_MutationsExposed: mutationType is a non-null named type → still
// HIGH, and the evidence notes mutations are exposed.
func TestGraphQL_MutationsExposed(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(gqlIntrospectionHandler(introspectionWithMutations))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	intro, ok := findGraphQLFinding(findings, "introspection enabled")
	if !ok {
		t.Fatalf("expected a GraphQL introspection-enabled finding, got %+v", findings)
	}
	if intro.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for mutations-exposed, got %s", intro.Severity)
	}
	if !strings.Contains(strings.ToLower(intro.Evidence), "mutation") {
		t.Errorf("expected evidence to note mutations are exposed, got %q", intro.Evidence)
	}
}

// TestGraphQL_GETExecutionCSRF: introspection is positive AND the SAME query
// executes via GET (?query=...) returning a valid data shape → also a MEDIUM
// GET-execution (CSRF surface) finding.
func TestGraphQL_GETExecutionCSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			// Execute the query via GET — returns a valid data shape.
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		_, _ = w.Write([]byte(introspectionJSON))
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	if _, ok := findGraphQLFinding(findings, "introspection enabled"); !ok {
		t.Fatalf("expected introspection finding, got %+v", findings)
	}
	getF, ok := findGraphQLFinding(findings, "GET")
	if !ok {
		t.Fatalf("expected a GET-execution (CSRF) finding, got %+v", findings)
	}
	if getF.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for GET-execution finding, got %s", getF.Severity)
	}
}

// TestGraphQL_Bare200NoFinding: a 200 application/json body with NO __schema
// ({"ok":true}) → NO finding. LOAD-BEARING: the full data.__schema shape is
// required, never a bare 200.
func TestGraphQL_Bare200NoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: bare 200 (no __schema) must yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestGraphQL_HTML200NoFinding: a 200 text/html page → NO finding. A static page
// is not GraphQL.
func TestGraphQL_HTML200NoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>welcome — query{__schema} here is just text</body></html>"))
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: text/html 200 must yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestGraphQL_DiscoveredGraphqlPathProbed: the crawler discovered an endpoint
// whose path itself contains "graphql" (non-standard path the bounded sweep
// would NOT cover), and introspection is enabled there → finding. Covers the
// discovery-gap "probe the current endpoint if its path contains graphql" path.
func TestGraphQL_DiscoveredGraphqlPathProbed(t *testing.T) {
	ResetGlobalAuditLog()
	const customPath = "/internal/GraphQL-API"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != customPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(introspectionJSON))
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	ep := Endpoint{Method: "POST", Path: customPath, FullURL: server.URL + customPath}
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if _, ok := findGraphQLFinding(findings, "introspection enabled"); !ok {
		t.Fatalf("expected introspection finding on the discovered graphql path, got %+v", findings)
	}
}

// TestGraphQL_NotActiveNoFinding: EnableActive:false → 0 findings (the check is
// TierActive and gated).
func TestGraphQL_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(gqlIntrospectionHandler(introspectionJSON))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	if len(findings) != 0 {
		t.Fatalf("EnableActive:false must yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestGraphQL_NoGraphQLEndpoint: every candidate path 404s → 0 findings.
func TestGraphQL_NoGraphQLEndpoint(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	findings := graphQLCheck{}.Run(context.Background(), NewCheckContext(cfg), graphQLRootEP(server))

	if len(findings) != 0 {
		t.Fatalf("404 on all candidates must yield 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestGraphQL_OncePerOrigin: two endpoints at the SAME origin → the bounded
// known-path sweep runs only the FIRST time the origin is seen, so the second
// Run does not re-POST the introspection probes. We count POSTs to /graphql and
// assert the sweep did not double-run.
func TestGraphQL_OncePerOrigin(t *testing.T) {
	ResetGlobalAuditLog()
	var graphqlPosts int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			atomic.AddInt64(&graphqlPosts, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(introspectionJSON))
	}))
	defer server.Close()

	cfg := activeGraphQLCfg()
	cc := NewCheckContext(cfg)

	ep1 := Endpoint{Method: "GET", Path: "/", FullURL: server.URL + "/"}
	ep2 := Endpoint{Method: "GET", Path: "/about", FullURL: server.URL + "/about"}

	f1 := graphQLCheck{}.Run(context.Background(), cc, ep1)
	postsAfterFirst := atomic.LoadInt64(&graphqlPosts)
	f2 := graphQLCheck{}.Run(context.Background(), cc, ep2)
	postsAfterSecond := atomic.LoadInt64(&graphqlPosts)

	if _, ok := findGraphQLFinding(f1, "introspection enabled"); !ok {
		t.Fatalf("expected introspection finding on first endpoint, got %+v", f1)
	}
	if postsAfterSecond != postsAfterFirst {
		t.Errorf("once-per-origin sweep re-ran: /graphql POSTs went from %d to %d on the second endpoint of the same origin", postsAfterFirst, postsAfterSecond)
	}
	if _, ok := findGraphQLFinding(f2, "introspection enabled"); ok {
		t.Errorf("second endpoint of the same origin must NOT re-report introspection (sweep is once-per-origin), got %+v", f2)
	}
}
