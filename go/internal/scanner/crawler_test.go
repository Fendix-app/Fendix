package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/netguard"
)

func TestFromSpec_OpenAPI3(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      summary: List users
    post:
      summary: Create user
  /users/{id}:
    get:
      summary: Get user
    put:
      summary: Update user
    delete:
      summary: Delete user
  /health:
    get:
      summary: Health check
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 6 {
		t.Fatalf("expected 6 endpoints, got %d", len(endpoints))
	}

	found := make(map[string]bool)
	for _, ep := range endpoints {
		found[ep.Method+" "+ep.Path] = true
	}

	expected := []string{
		"GET /users", "POST /users",
		"GET /users/{id}", "PUT /users/{id}", "DELETE /users/{id}",
		"GET /health",
	}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("missing endpoint: %s", e)
		}
	}
}

// TestFromSpec_FetchOverHTTP2 is the crawler-level regression test for the Kong
// h2 spec-fetch bug: a --spec given as an https:// URL served by an
// HTTP/2-enabled gateway must be fetched and parsed, not dropped. Before the
// netguard Transport.Protocols fix the guarded client spoke only HTTP/1.x, so
// the h2 handshake produced "malformed HTTP response \x00\x00\x12\x04..." and
// fromSpec returned zero endpoints. This serves the spec from an h2 TLS server,
// points SpecPath at its URL, and asserts the endpoints come back.
func TestFromSpec_FetchOverHTTP2(t *testing.T) {
	spec := `{
  "openapi": "3.0.0",
  "info": {"title": "H2 Spec API", "version": "1.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/users": {"get": {"summary": "list"}, "post": {"summary": "create"}},
    "/health": {"get": {"summary": "health"}}
  }
}`
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("spec fetch arrived over %s, expected HTTP/2 — guard suppressed h2", r.Proto)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, spec)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath:     srv.URL + "/spec.json",
		Timeout:      10,
		AllowPrivate: true, // httptest binds loopback
	})

	// Build the crawler's HTTP client through the REAL guarded transport
	// (netguard.Config.Transport — the code the fix lives in), adding only the
	// test cert to its trust store. This exercises the production h2 path; it is
	// not a stub. AllowPrivate=true so the guard reaches the loopback server.
	certs := x509.NewCertPool()
	certs.AddCert(srv.Certificate())
	tmpl := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certs}}
	cfg := netguard.Config{AllowPrivate: true}
	crawler.client = &http.Client{Transport: cfg.Transport(tmpl), CheckRedirect: cfg.CheckRedirect()}

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec over HTTP/2 failed (the Kong spec-fetch bug): %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("expected 3 endpoints from the h2-served spec, got %d: %+v", len(endpoints), endpoints)
	}
}

func TestFromSpec_Swagger2(t *testing.T) {
	spec := `
swagger: "2.0"
info:
  title: Test API
  version: "1.0"
host: api.example.com
basePath: /v1
schemes:
  - https
paths:
  /users:
    get:
      summary: List users
  /orders:
    post:
      summary: Create order
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "swagger.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}

	if endpoints[0].FullURL != "https://api.example.com/v1/users" && endpoints[1].FullURL != "https://api.example.com/v1/users" {
		t.Errorf("expected base URL from swagger host+basePath, got %s and %s", endpoints[0].FullURL, endpoints[1].FullURL)
	}
}

func TestFromSpec_JSON(t *testing.T) {
	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info":    map[string]interface{}{"title": "JSON API", "version": "1.0"},
		"paths": map[string]interface{}{
			"/items": map[string]interface{}{
				"get":  map[string]interface{}{"summary": "list"},
				"post": map[string]interface{}{"summary": "create"},
			},
		},
	}
	data, _ := json.Marshal(spec)
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.json")
	if err := os.WriteFile(specPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestFromSpec_URLOverridesServerURL(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com
paths:
  /test:
    get:
      summary: test
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		URL:      "https://custom.example.com",
		Timeout:  10,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	if endpoints[0].FullURL != "https://custom.example.com/test" {
		t.Errorf("expected --url to override spec server, got %s", endpoints[0].FullURL)
	}
}

func TestFromJS(t *testing.T) {
	jsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `var BASE="/api/v1"; fetch("/api/v1/users"); fetch("/api/v2/orders");`)
	}))
	defer jsServer.Close()

	htmlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<html><script src="%s/app.js"></script></html>`, jsServer.URL)
	}))
	defer htmlServer.Close()

	crawler := NewCrawler(&models.ScanConfig{
		URL:     htmlServer.URL,
		Timeout: 10,
	})

	endpoints, err := crawler.fromJS(context.Background())
	if err != nil {
		t.Fatalf("fromJS failed: %v", err)
	}

	if len(endpoints) == 0 {
		t.Fatal("expected at least one endpoint from JS discovery")
	}

	found := false
	for _, ep := range endpoints {
		if ep.Path == "/api/v1/users" || ep.Path == "/api/v2/orders" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find /api/v1/users or /api/v2/orders in JS-discovered endpoints")
	}
}

func TestFromBruteForce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/users", "/health", "/api/health":
			w.WriteHeader(200)
			fmt.Fprint(w, `{"status":"ok"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	crawler := NewCrawler(&models.ScanConfig{
		URL:     server.URL,
		Timeout: 10,
		DelayMs: 0,
	})

	endpoints, err := crawler.fromBruteForce(context.Background())
	if err != nil {
		t.Fatalf("fromBruteForce failed: %v", err)
	}

	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 discovered endpoints, got %d", len(endpoints))
	}

	found := make(map[string]bool)
	for _, ep := range endpoints {
		found[ep.Path] = true
	}

	for _, path := range []string{"/api/v1/users", "/health", "/api/health"} {
		if !found[path] {
			t.Errorf("missing discovered endpoint: %s", path)
		}
	}
}

func TestCrawlEndpoints_Dedup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	spec := fmt.Sprintf(`
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: %s
paths:
  /health:
    get:
      summary: health
`, server.URL)

	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		URL:      server.URL,
		SpecPath: specPath,
		Timeout:  10,
		DelayMs:  0,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	healthCount := 0
	for _, ep := range endpoints {
		if ep.Path == "/health" && ep.Method == "GET" {
			healthCount++
		}
	}
	if healthCount != 1 {
		t.Errorf("expected /health GET to appear exactly once, found %d times", healthCount)
	}
}

func TestCrawlEndpoints_Sorted(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /zebra:
    get:
      summary: z
  /alpha:
    get:
      summary: a
    post:
      summary: a
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	if len(endpoints) < 3 {
		t.Fatalf("expected at least 3 endpoints, got %d", len(endpoints))
	}

	for i := 1; i < len(endpoints); i++ {
		if endpoints[i].Path < endpoints[i-1].Path {
			t.Errorf("endpoints not sorted: %s before %s", endpoints[i-1].Path, endpoints[i].Path)
		}
	}
}

func TestExtractPathParams(t *testing.T) {
	tests := []struct {
		path   string
		params []string
	}{
		{"/users/{id}", []string{"id"}},
		{"/orgs/{org}/repos/{repo}", []string{"org", "repo"}},
		{"/health", nil},
		{"/users/{userId}/posts/{postId}", []string{"userId", "postId"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			params := extractPathParams(tt.path)
			if len(params) != len(tt.params) {
				t.Fatalf("expected %d params, got %d", len(tt.params), len(params))
			}
			for i, p := range params {
				if p != tt.params[i] {
					t.Errorf("param[%d] = %s, want %s", i, p, tt.params[i])
				}
			}
		})
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base     string
		ref      string
		expected string
	}{
		{"https://example.com", "https://cdn.example.com/app.js", "https://cdn.example.com/app.js"},
		{"https://example.com/page", "/static/app.js", "https://example.com/static/app.js"},
		{"https://example.com/sub/page", "app.js", "https://example.com/sub/app.js"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			result := resolveURL(tt.base, tt.ref)
			if result != tt.expected {
				t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, result, tt.expected)
			}
		})
	}
}

func TestFromSpec_InvalidFile(t *testing.T) {
	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: "/nonexistent/file.yaml",
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

// TestFromSpec_PopulatesParamsFromOperation is the regression test for TASK-081.
// Pre-fix, only URL-template path params (`{id}`) populated Endpoint.Params;
// the OpenAPI `parameters: [{name, in: query}]` block was dropped. This made
// the active scanner blind to non-`id` query parameters — every probe used
// the hardcoded "id" fallback in injection.go.
func TestFromSpec_PopulatesParamsFromOperation(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.com"}]
paths:
  /widgets:
    get:
      parameters:
        - name: limit
          in: query
        - name: offset
          in: query
        - name: X-Trace-Id
          in: header
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].Params
	want := map[string]bool{"limit": true, "offset": true}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected param %q in %v (header param leaked through?)", p, got)
		}
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("missing params %v from %v", want, endpoints[0].Params)
	}
}

// TestFromSpec_PathLevelParamsMergeWithOperation: path-level `parameters` apply
// to every operation under that path. Plus URL-template params should always
// appear regardless of whether the spec lists them. Dedupe across all sources.
func TestFromSpec_PathLevelParamsMergeWithOperation(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
      - name: tenant
        in: query
    get:
      parameters:
        - name: include
          in: query
    delete: {}
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}

	getParams, deleteParams := map[string]bool{}, map[string]bool{}
	for _, ep := range endpoints {
		set := getParams
		if ep.Method == "DELETE" {
			set = deleteParams
		}
		for _, p := range ep.Params {
			set[p] = true
		}
	}

	// GET should have id (path template + spec path-level), tenant (path-level), include (operation-level)
	for _, want := range []string{"id", "tenant", "include"} {
		if !getParams[want] {
			t.Errorf("GET missing param %q (got %v)", want, getParams)
		}
	}
	// DELETE has no operation-level parameters but inherits path-level + URL template
	for _, want := range []string{"id", "tenant"} {
		if !deleteParams[want] {
			t.Errorf("DELETE missing inherited param %q (got %v)", want, deleteParams)
		}
	}
	if deleteParams["include"] {
		t.Errorf("DELETE should not inherit GET-only param 'include' (got %v)", deleteParams)
	}
}

// TestFromSpec_RefParameterSkipped verifies $ref entries don't crash the parser.
// Resolving them is out of scope for v0.2 (TASK-086); for now we just skip.
func TestFromSpec_RefParameterSkipped(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /things:
    get:
      parameters:
        - $ref: "#/components/parameters/Limit"
        - name: cursor
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 || len(endpoints[0].Params) != 1 || endpoints[0].Params[0] != "cursor" {
		t.Fatalf("expected single endpoint with [cursor], got %+v", endpoints)
	}
}

// TestFromSpec_URL_JSON exercises TASK-082: --spec accepts an HTTP URL.
// Before the fix, a URL was passed to os.ReadFile and silently failed;
// the crawler then fell back to brute-force discovery.
func TestFromSpec_URL_JSON(t *testing.T) {
	specBody := `{
	  "openapi": "3.0.0",
	  "info": {"title": "Remote", "version": "1.0"},
	  "servers": [{"url": "https://api.remote.example/v1"}],
	  "paths": {
	    "/widgets": {"get": {"summary": "List"}, "post": {"summary": "Create"}},
	    "/widgets/{id}": {"get": {"summary": "Get"}}
	  }
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(specBody))
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: srv.URL + "/openapi.json",
		Timeout:  5,
		// --spec is fetched from a loopback httptest server; relax the SSRF
		// guard the same way a real private-target scan auto-does.
		AllowPrivate: true,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}
	if len(endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(endpoints), endpoints)
	}
}

// TestFromSpec_URL_YAML covers Content-Type-based format detection (URL has
// no .yaml suffix, server returns text/yaml — must still parse as YAML).
func TestFromSpec_URL_YAML(t *testing.T) {
	specBody := `openapi: "3.0.0"
info:
  title: Remote YAML
  version: "1.0"
servers:
  - url: https://api.remote.example/v1
paths:
  /things:
    get:
      summary: List things
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		_, _ = w.Write([]byte(specBody))
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		// No suffix on the URL — exercises Content-Type fallback.
		SpecPath:     srv.URL + "/spec",
		Timeout:      5,
		AllowPrivate: true,
	})

	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
}

// TestFromSpec_URL_HTTPError surfaces 4xx/5xx as errors instead of silently
// falling back. The pre-fix bug masked URL typos as "no endpoints found".
func TestFromSpec_URL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath:     srv.URL + "/missing.json",
		Timeout:      5,
		AllowPrivate: true,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for HTTP 404 response, got nil")
	}
	if !contains(err.Error(), "404") {
		t.Errorf("expected error to mention status code, got: %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFromSpec_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(specPath, []byte(":::invalid:::yaml:::"), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// TestFromSpec_PopulatesHeaderParams covers TASK-086 — `in: header` params now
// land in Endpoint.Headers, with standard auth headers (Authorization, Cookie,
// X-Api-Key) filtered out so the active scanner doesn't scribble payloads into
// real auth values.
func TestFromSpec_PopulatesHeaderParams(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /widgets:
    get:
      parameters:
        - name: X-Trace-Id
          in: header
        - name: X-Tenant-Id
          in: header
        - name: Authorization
          in: header
        - name: Cookie
          in: header
        - name: limit
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].Headers
	wantSet := map[string]bool{"X-Trace-Id": true, "X-Tenant-Id": true}
	for _, h := range got {
		if !wantSet[h] {
			t.Errorf("unexpected header %q (auth headers should be skipped); got Headers=%v", h, got)
		}
		delete(wantSet, h)
	}
	if len(wantSet) != 0 {
		t.Errorf("missing headers %v from %v", wantSet, got)
	}
	// Query param still flows through Params, not Headers.
	if len(endpoints[0].Params) != 1 || endpoints[0].Params[0] != "limit" {
		t.Errorf("expected Params=[limit], got %v", endpoints[0].Params)
	}
}

// TestFromSpec_PopulatesBodyParams_OAS3 covers TASK-086 — OpenAPI 3 JSON
// requestBody schemas surface their property names in Endpoint.BodyParams so
// the active scanner can probe POST/PUT/PATCH body fields.
func TestFromSpec_PopulatesBodyParams_OAS3(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                email:
                  type: string
                age:
                  type: integer
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].BodyParams
	want := map[string]bool{"username": true, "email": true, "age": true}
	for _, b := range got {
		if !want[b] {
			t.Errorf("unexpected body param %q in %v", b, got)
		}
		delete(want, b)
	}
	if len(want) != 0 {
		t.Errorf("missing body params %v from %v", want, got)
	}
}

// TestFromSpec_PopulatesBodyParams_Swagger2 covers Swagger 2.0 bodies, which
// live in `parameters` with `in: body` rather than the OAS 3 `requestBody`.
func TestFromSpec_PopulatesBodyParams_Swagger2(t *testing.T) {
	spec := `
swagger: "2.0"
info: {title: t, version: "1"}
host: api.example.com
basePath: /v1
paths:
  /users:
    post:
      parameters:
        - name: body
          in: body
          schema:
            type: object
            properties:
              username:
                type: string
              password:
                type: string
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "swagger.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	got := endpoints[0].BodyParams
	want := map[string]bool{"username": true, "password": true}
	for _, b := range got {
		if !want[b] {
			t.Errorf("unexpected body param %q in %v", b, got)
		}
		delete(want, b)
	}
	if len(want) != 0 {
		t.Errorf("missing body params %v from %v", want, got)
	}
}

// TestFromSpec_BodyParams_RefSchemaSkipped — schemas with $ref are not
// dereferenced in v0.3, so they yield no body params (rather than crashing).
func TestFromSpec_BodyParams_RefSchemaSkipped(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/User"
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 5})
	endpoints, err := crawler.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(endpoints))
	}
	if len(endpoints[0].BodyParams) != 0 {
		t.Errorf("expected no body params for $ref schema, got %v", endpoints[0].BodyParams)
	}
}

func TestFromSpec_NoPaths(t *testing.T) {
	dir := t.TempDir()
	specPath := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(specPath, []byte("openapi: '3.0.0'\ninfo:\n  title: empty\n  version: '1.0'\n"), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	_, err := crawler.fromSpec(context.Background())
	if err == nil {
		t.Fatal("expected error for spec with no paths")
	}
}

// === TASK-089: crawler upgrade tests ===
//
// Coverage: robots.txt parser (Disallow/Allow/Sitemap), sitemap.xml parser
// (urlset + sitemapindex), HTML link parser with recursive depth, wordlist
// loader, --max-endpoints budget. Each new discovery mode gets at least one
// happy-path test plus the tricky edge case (cross-host filtering, malformed
// XML, etc.).

func TestParseRobots_DisallowAllowAndSitemap(t *testing.T) {
	body := []byte(`# A real robots.txt
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /admin/public
Disallow:
Disallow: /search?q=*
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-news.xml
# trailing comment
`)
	disallows, allows, sitemaps := parseRobots(body)

	// Disallow paths from this fixture: /admin/, /private/, /search?q=
	// Allow paths: /admin/public
	wantDisallows := map[string]bool{"/admin/": true, "/private/": true, "/search?q=": true}
	for _, p := range disallows {
		if !wantDisallows[p] {
			t.Errorf("unexpected disallow path %q in %v", p, disallows)
		}
		delete(wantDisallows, p)
	}
	if len(wantDisallows) != 0 {
		t.Errorf("missing disallow paths %v from %v", wantDisallows, disallows)
	}
	if len(allows) != 1 || allows[0] != "/admin/public" {
		t.Errorf("expected single allow /admin/public, got %v", allows)
	}

	wantSitemaps := []string{"https://example.com/sitemap.xml", "https://example.com/sitemap-news.xml"}
	if len(sitemaps) != len(wantSitemaps) {
		t.Fatalf("expected %d sitemaps, got %d (%v)", len(wantSitemaps), len(sitemaps), sitemaps)
	}
	for i, s := range sitemaps {
		if s != wantSitemaps[i] {
			t.Errorf("sitemap[%d] = %q, want %q", i, s, wantSitemaps[i])
		}
	}
}

func TestParseRobots_IgnoresMalformedLines(t *testing.T) {
	body := []byte(`Garbage line with no colon

:::
Disallow: not-a-path
Disallow: /good
`)
	disallows, _, _ := parseRobots(body)
	if len(disallows) != 1 || disallows[0] != "/good" {
		t.Errorf("expected single disallow /good, got %v", disallows)
	}
}

// TestFromRobots_DiscoversDisallowedPaths is the end-to-end happy path: a
// mock site serves robots.txt with hidden admin paths; the crawler discovers
// them as endpoints. This was the original fendix gap on httpbin.org —
// /robots.txt was discovered but its Disallow content was thrown away.
func TestFromRobots_DiscoversDisallowedPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(200)
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin/secret\nDisallow: /internal/api\nSitemap: "+r.Host+"/sitemap.xml\n")
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5})
	res, err := crawler.fromRobots(context.Background())
	if err != nil {
		t.Fatalf("fromRobots: %v", err)
	}
	want := map[string]bool{"/admin/secret": true, "/internal/api": true}
	for _, ep := range res.endpoints {
		if !want[ep.Path] {
			t.Errorf("unexpected path %q in robots-discovered endpoints", ep.Path)
		}
		delete(want, ep.Path)
	}
	if len(want) != 0 {
		t.Errorf("missing %v from robots-discovered endpoints", want)
	}
	if len(res.sitemapURLs) != 1 {
		t.Errorf("expected 1 sitemap URL, got %v", res.sitemapURLs)
	}
}

func TestFromRobots_MissingFileReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5})
	_, err := crawler.fromRobots(context.Background())
	if err == nil {
		t.Fatal("expected error for 404 robots.txt")
	}
}

func TestParseSitemap_URLSet(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/admin/dashboard</loc></url>
  <url><loc>https://example.com/api/v1/users</loc></url>
</urlset>`)
	pages, sitemaps := parseSitemap(body)
	if len(pages) != 3 {
		t.Errorf("expected 3 pages, got %v", pages)
	}
	if len(sitemaps) != 0 {
		t.Errorf("urlset should produce no child sitemaps, got %v", sitemaps)
	}
}

func TestParseSitemap_SitemapIndex(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-2.xml</loc></sitemap>
</sitemapindex>`)
	pages, sitemaps := parseSitemap(body)
	if len(pages) != 0 {
		t.Errorf("sitemapindex should produce no pages, got %v", pages)
	}
	if len(sitemaps) != 2 {
		t.Errorf("expected 2 child sitemaps, got %v", sitemaps)
	}
}

func TestParseSitemap_MalformedReturnsEmpty(t *testing.T) {
	pages, sitemaps := parseSitemap([]byte(`<not really xml>`))
	if pages != nil || sitemaps != nil {
		t.Errorf("malformed sitemap should return nils, got pages=%v sitemaps=%v", pages, sitemaps)
	}
}

// TestFromSitemap_FollowsIndexAndStripsCrossHost: verifies the sitemap-index
// is followed one level deep, and that pages on a different host are
// filtered out so we don't probe random external sites.
func TestFromSitemap_FollowsIndexAndStripsCrossHost(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		switch r.URL.Path {
		case "/sitemap.xml":
			fmt.Fprintf(w, `<sitemapindex><sitemap><loc>%s/sitemap-pages.xml</loc></sitemap></sitemapindex>`, srv.URL)
		case "/sitemap-pages.xml":
			fmt.Fprintf(w, `<urlset>
				<url><loc>%s/api/v1/widgets</loc></url>
				<url><loc>%s/admin/login</loc></url>
				<url><loc>https://other-host.example/external</loc></url>
			</urlset>`, srv.URL, srv.URL)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5})
	endpoints, err := crawler.fromSitemap(context.Background(), []string{srv.URL + "/sitemap.xml"})
	if err != nil {
		t.Fatalf("fromSitemap: %v", err)
	}

	want := map[string]bool{"/api/v1/widgets": true, "/admin/login": true}
	for _, ep := range endpoints {
		if !want[ep.Path] {
			t.Errorf("unexpected path %q (cross-host should be filtered)", ep.Path)
		}
		delete(want, ep.Path)
	}
	if len(want) != 0 {
		t.Errorf("missing %v from sitemap-discovered endpoints", want)
	}
}

func TestExtractHTMLLinks_AnchorAndForm(t *testing.T) {
	body := []byte(`<html>
		<body>
			<a href="/admin">admin</a>
			<a href='/api/v1/users'>users</a>
			<A HREF="/UPPERCASE">tag</A>
			<form action="/login" method="post"></form>
			<a href="#fragment">fragment-only ignored</a>
			<a>no-href ignored</a>
		</body>
	</html>`)
	links := extractHTMLLinks(body)
	wantSubset := []string{"/admin", "/api/v1/users", "/UPPERCASE", "/login"}
	got := map[string]bool{}
	for _, l := range links {
		got[l] = true
	}
	for _, w := range wantSubset {
		if !got[w] {
			t.Errorf("missing link %q in %v", w, links)
		}
	}
	for _, l := range links {
		if l == "#fragment" {
			t.Errorf("fragment-only link should be filtered: %q", l)
		}
	}
}

// TestCrawlHTMLLinks_DepthAndSameHost ensures the BFS respects depth and
// rejects cross-host links. Server has 3 pages at decreasing depth; with
// depth=2 we should reach all 3, with depth=1 only the home page's links.
func TestCrawlHTMLLinks_DepthAndSameHost(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><a href="/level1">L1</a><a href="https://other.example/external">ext</a></html>`)
		case "/level1":
			fmt.Fprintf(w, `<html><a href="/level2">L2</a></html>`)
		case "/level2":
			fmt.Fprintf(w, `<html>leaf</html>`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	t.Run("depth=1 finds only home-page links", func(t *testing.T) {
		crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5, CrawlDepth: 1})
		endpoints, err := crawler.crawlHTMLLinks(context.Background(), 1)
		if err != nil {
			t.Fatalf("crawlHTMLLinks: %v", err)
		}
		paths := map[string]bool{}
		for _, ep := range endpoints {
			paths[ep.Path] = true
		}
		if !paths["/level1"] {
			t.Errorf("expected /level1 at depth=1, got %v", paths)
		}
		if paths["/level2"] {
			t.Errorf("/level2 should require depth>=2; got it at depth=1")
		}
		if paths["/external"] {
			t.Errorf("cross-host link should be filtered, got %v", paths)
		}
	})

	t.Run("depth=2 reaches /level2", func(t *testing.T) {
		crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5, CrawlDepth: 2})
		endpoints, err := crawler.crawlHTMLLinks(context.Background(), 2)
		if err != nil {
			t.Fatalf("crawlHTMLLinks: %v", err)
		}
		paths := map[string]bool{}
		for _, ep := range endpoints {
			paths[ep.Path] = true
		}
		for _, want := range []string{"/level1", "/level2"} {
			if !paths[want] {
				t.Errorf("missing %q at depth=2, got %v", want, paths)
			}
		}
	})
}

// TestCrawlHTMLLinks_FiltersUnscannableSchemes is a real-world regression:
// httpbin.org's home page has a mailto: contact link. Pre-fix the crawler
// followed it as an endpoint and the scanner produced "unsupported protocol
// scheme" warnings for every check. Now the link must be dropped at extraction.
func TestCrawlHTMLLinks_FiltersUnscannableSchemes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			fmt.Fprint(w, `<html>
				<a href="mailto:owner@example.com">contact</a>
				<a href="tel:+1234">phone</a>
				<a href="javascript:void(0)">js</a>
				<a href="data:text/plain,hi">data</a>
				<a href="/api/v1/legit">real</a>
			</html>`)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5, CrawlDepth: 1})
	endpoints, err := crawler.crawlHTMLLinks(context.Background(), 1)
	if err != nil {
		t.Fatalf("crawlHTMLLinks: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0].Path != "/api/v1/legit" {
		t.Errorf("expected single /api/v1/legit endpoint, got %+v (mailto/tel/js/data should be filtered)", endpoints)
	}
}

func TestCrawlHTMLLinks_DepthZeroIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/never-fetched">x</a>`)
	}))
	defer srv.Close()
	crawler := NewCrawler(&models.ScanConfig{URL: srv.URL, Timeout: 5, CrawlDepth: 0})
	endpoints, err := crawler.crawlHTMLLinks(context.Background(), 0)
	if err != nil {
		t.Fatalf("crawlHTMLLinks: %v", err)
	}
	if len(endpoints) != 0 {
		t.Errorf("depth=0 should return no endpoints, got %v", endpoints)
	}
}

// TestLoadWordlist_ReadsFile: --wordlist overrides CommonPaths, comment and
// blank lines stripped, leading slash auto-added.
func TestLoadWordlist_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	wlPath := filepath.Join(dir, "wl.txt")
	content := `# header comment
/admin/api
api/v9/secret

/normal/path
# trailing comment
`
	if err := os.WriteFile(wlPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	crawler := NewCrawler(&models.ScanConfig{WordlistPath: wlPath})
	got, err := crawler.loadWordlist()
	if err != nil {
		t.Fatalf("loadWordlist: %v", err)
	}
	want := []string{"/admin/api", "/api/v9/secret", "/normal/path"}
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d (%v)", len(want), len(got), got)
	}
	for i, p := range got {
		if p != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestLoadWordlist_DefaultIsCommonPaths(t *testing.T) {
	crawler := NewCrawler(&models.ScanConfig{})
	got, err := crawler.loadWordlist()
	if err != nil {
		t.Fatalf("loadWordlist: %v", err)
	}
	if len(got) != len(CommonPaths) {
		t.Errorf("expected %d default paths, got %d", len(CommonPaths), len(got))
	}
}

func TestLoadWordlist_MissingFileReturnsError(t *testing.T) {
	crawler := NewCrawler(&models.ScanConfig{WordlistPath: "/nonexistent/wordlist.txt"})
	if _, err := crawler.loadWordlist(); err == nil {
		t.Fatal("expected error for missing wordlist file")
	}
}

// TestCrawlEndpoints_MaxEndpointsBudget asserts the cap kicks in after dedupe.
// We seed a spec with 6 endpoints and cap to 3; the result must be exactly 3.
func TestCrawlEndpoints_MaxEndpointsBudget(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
paths:
  /a: {get: {summary: a}}
  /b: {get: {summary: b}}
  /c: {get: {summary: c}}
  /d: {get: {summary: d}}
  /e: {get: {summary: e}}
  /f: {get: {summary: f}}
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	crawler := NewCrawler(&models.ScanConfig{SpecPath: specPath, MaxEndpoints: 3, Timeout: 5})
	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints: %v", err)
	}
	if len(endpoints) != 3 {
		t.Errorf("expected 3 endpoints after --max-endpoints=3 cap, got %d", len(endpoints))
	}
}

func TestCrawlEndpoints_SpecOnly(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
paths:
  /users:
    get:
      summary: List
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}

	crawler := NewCrawler(&models.ScanConfig{
		SpecPath: specPath,
		Timeout:  10,
	})

	endpoints, err := crawler.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatalf("CrawlEndpoints failed: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected 1 endpoint from spec-only crawl, got %d", len(endpoints))
	}
	if endpoints[0].Method != "GET" || endpoints[0].Path != "/users" {
		t.Errorf("unexpected endpoint: %s %s", endpoints[0].Method, endpoints[0].Path)
	}
}

func TestSubstitutePathPlaceholders_NoPlaceholders(t *testing.T) {
	got := substitutePathPlaceholders("/users", nil)
	if got != "/users" {
		t.Errorf("paths without placeholders should pass through, got %q", got)
	}
	got = substitutePathPlaceholders("/", nil)
	if got != "/" {
		t.Errorf("root path should pass through, got %q", got)
	}
}

func TestSubstitutePathPlaceholders_NameHeuristic(t *testing.T) {
	tests := []struct {
		template string
		want     string
	}{
		{"/users/{id}", "/users/1"},
		{"/orgs/{org_id}/repos", "/orgs/1/repos"},
		{"/items/{userId}/x/{postId}", "/items/1/x/1"},
		{"/files/{uuid}", "/files/00000000-0000-0000-0000-000000000000"},
		{"/things/{name}", "/things/sample"},
		{"/page/{count}/x", "/page/1/x"},
		{"/p/{limit}/{offset}", "/p/1/1"},
	}
	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			got := substitutePathPlaceholders(tt.template, nil)
			if got != tt.want {
				t.Errorf("substitutePathPlaceholders(%q) = %q, want %q", tt.template, got, tt.want)
			}
		})
	}
}

func TestSubstitutePathPlaceholders_SchemaTypeDriven(t *testing.T) {
	schemas := map[string]pathParamSchema{
		"id":       {Type: "integer"},
		"flag":     {Type: "boolean"},
		"hash":     {Type: "string", Format: "uuid"},
		"d":        {Type: "string", Format: "date"},
		"dt":       {Type: "string", Format: "date-time"},
		"contact":  {Type: "string", Format: "email"},
		"category": {Type: "string"}, // no format → falls through to name-heuristic ("sample")
	}
	got := substitutePathPlaceholders("/a/{id}/b/{flag}/c/{hash}/d/{d}/e/{dt}/f/{contact}/g/{category}", schemas)
	want := "/a/1/b/true/c/00000000-0000-0000-0000-000000000000/d/2024-01-01/e/2024-01-01T00:00:00Z/f/user@example.com/g/sample"
	if got != want {
		t.Errorf("schema-typed substitution mismatch:\n got  %q\n want %q", got, want)
	}
}

func TestSubstitutePathPlaceholders_ExampleAndEnumWin(t *testing.T) {
	schemas := map[string]pathParamSchema{
		"id":     {Type: "integer", Example: 42},
		"role":   {Type: "string", Enum: []interface{}{"admin", "user"}},
		"weird":  {Type: "string", Example: "the/example"}, // verify URL-escape happens
		"strict": {Type: "string", Example: "hello world"}, // space → %20
	}
	tests := []struct {
		template string
		want     string
	}{
		{"/users/{id}", "/users/42"},
		{"/auth/{role}", "/auth/admin"},
		{"/p/{weird}", "/p/the%2Fexample"},
		{"/q/{strict}", "/q/hello%20world"},
	}
	for _, tt := range tests {
		t.Run(tt.template, func(t *testing.T) {
			got := substitutePathPlaceholders(tt.template, schemas)
			if got != tt.want {
				t.Errorf("substitute(%q) = %q, want %q", tt.template, got, tt.want)
			}
		})
	}
}

func TestSubstitutePathPlaceholders_UnknownNameFallback(t *testing.T) {
	// schemas map is non-nil but missing the placeholder name; should fall
	// back to the name-heuristic path (so `{id}` still becomes "1").
	schemas := map[string]pathParamSchema{
		"unrelated": {Type: "integer"},
	}
	got := substitutePathPlaceholders("/users/{id}", schemas)
	if got != "/users/1" {
		t.Errorf("unknown-name fallback failed: got %q", got)
	}
}

func TestSampleByName_LongerSuffixDoesNotFalseMatch(t *testing.T) {
	// "valid" contains "id" as a substring but doesn't end with id; should
	// fall through to "sample". This guards against a regression where
	// `strings.Contains(name, "id")` would have spuriously matched.
	if got := sampleByName("valid"); got != "sample" {
		t.Errorf("sampleByName(\"valid\") = %q, want \"sample\"", got)
	}
	// But `userId` ends with "Id" so should hit the *id rule.
	if got := sampleByName("userId"); got != "1" {
		t.Errorf("sampleByName(\"userId\") = %q, want \"1\"", got)
	}
}

func TestExtractPathParamSchemas_OAS3(t *testing.T) {
	// OAS 3 nests schema under parameters[*].schema and supports an
	// optional parameter-level `example` that overrides schema.example.
	raw := []interface{}{
		map[string]interface{}{
			"name": "id",
			"in":   "path",
			"schema": map[string]interface{}{
				"type":    "integer",
				"example": 7,
			},
		},
		map[string]interface{}{
			"name": "kind",
			"in":   "path",
			"schema": map[string]interface{}{
				"type": "string",
				"enum": []interface{}{"a", "b"},
			},
			"example": "z", // parameter-level wins over schema.enum
		},
		map[string]interface{}{
			// query params should be ignored — only `in: path` counts
			"name":   "q",
			"in":     "query",
			"schema": map[string]interface{}{"type": "string"},
		},
		map[string]interface{}{
			// $ref entries are skipped
			"$ref": "#/components/parameters/Foo",
		},
	}
	got := extractPathParamSchemas(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 path-param schemas, got %d: %+v", len(got), got)
	}
	if got["id"].Type != "integer" || got["id"].Example != 7 {
		t.Errorf("id schema mismatch: %+v", got["id"])
	}
	if got["kind"].Example != "z" {
		t.Errorf("kind: parameter-level example should override schema-level: %+v", got["kind"])
	}
	if _, ok := got["q"]; ok {
		t.Errorf("query param should not appear in path-schema map")
	}
}

func TestExtractPathParamSchemas_Swagger2(t *testing.T) {
	// Swagger 2 puts type/format/example/enum directly on the parameter.
	raw := []interface{}{
		map[string]interface{}{
			"name":    "userId",
			"in":      "path",
			"type":    "integer",
			"format":  "int64",
			"example": 99,
		},
		map[string]interface{}{
			"name": "status",
			"in":   "path",
			"type": "string",
			"enum": []interface{}{"active", "archived"},
		},
	}
	got := extractPathParamSchemas(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 path-param schemas, got %d", len(got))
	}
	if got["userId"].Type != "integer" || got["userId"].Format != "int64" || got["userId"].Example != 99 {
		t.Errorf("userId mismatch: %+v", got["userId"])
	}
	if len(got["status"].Enum) != 2 || got["status"].Enum[0] != "active" {
		t.Errorf("status enum mismatch: %+v", got["status"])
	}
}

func TestExtractPathParamSchemas_OpLevelOverridesPathLevel(t *testing.T) {
	// When the same name appears at both layers, op-level wins.
	pathLevel := []interface{}{
		map[string]interface{}{
			"name": "id", "in": "path",
			"schema": map[string]interface{}{"type": "integer", "example": 1},
		},
	}
	opLevel := []interface{}{
		map[string]interface{}{
			"name": "id", "in": "path",
			"schema": map[string]interface{}{"type": "string", "example": "abc"},
		},
	}
	got := extractPathParamSchemas(pathLevel, opLevel)
	if got["id"].Type != "string" || got["id"].Example != "abc" {
		t.Errorf("op-level override failed: %+v", got["id"])
	}
}

func TestFromSpec_FullURLHasNoPlaceholders(t *testing.T) {
	spec := `
openapi: "3.0.0"
info:
  title: Test
  version: "1.0"
servers:
  - url: https://api.example.com
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 7
  /items/{name}:
    get:
      parameters:
        - name: name
          in: path
          required: true
          schema:
            type: string
  /no-schema/{id}:
    get: {}
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(spec), 0644); err != nil {
		t.Fatal(err)
	}
	c := NewCrawler(&models.ScanConfig{SpecPath: specPath, Timeout: 10})
	endpoints, err := c.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec failed: %v", err)
	}

	byPath := map[string]Endpoint{}
	for _, e := range endpoints {
		byPath[e.Path] = e
	}

	got, ok := byPath["/users/{id}"]
	if !ok {
		t.Fatalf("missing endpoint /users/{id}")
	}
	if got.Path != "/users/{id}" {
		t.Errorf("Path should preserve template form, got %q", got.Path)
	}
	if got.FullURL != "https://api.example.com/users/7" {
		t.Errorf("FullURL should use schema example: got %q", got.FullURL)
	}

	got = byPath["/items/{name}"]
	if got.FullURL != "https://api.example.com/items/sample" {
		t.Errorf("FullURL should use string-name fallback: got %q", got.FullURL)
	}

	got = byPath["/no-schema/{id}"]
	if got.FullURL != "https://api.example.com/no-schema/1" {
		t.Errorf("FullURL should use name-heuristic when no spec params present: got %q", got.FullURL)
	}

	// Sanity: no FullURL contains the literal "{" placeholder leak — the
	// failure mode this whole task fixes.
	for _, e := range endpoints {
		if strings.Contains(e.FullURL, "{") || strings.Contains(e.FullURL, "%7B") {
			t.Errorf("FullURL still has placeholder leak: %q", e.FullURL)
		}
	}
}

// TestPathDisallowedByRobots is the unit-level coverage for the
// --respect-robots prefix-match (TASK-095). Disallow rules in robots.txt
// are conventionally prefix-matched: "Disallow: /admin" blocks any URL
// path starting with /admin (including /admin/users, /admin/login, etc.).
// `/` as a Disallow rule blocks everything per the robots-spec convention.
func TestPathDisallowedByRobots(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		rules   []string
		blocked bool
	}{
		{"empty rules", "/admin", nil, false},
		{"exact prefix", "/admin", []string{"/admin"}, true},
		{"deeper path under prefix", "/admin/login", []string{"/admin"}, true},
		{"sibling path not under prefix", "/admins", []string{"/admin/"}, false},
		{"unrelated path", "/api/users", []string{"/admin"}, false},
		{"slash-only blocks everything", "/anywhere", []string{"/"}, true},
		{"slash-only blocks root too", "/", []string{"/"}, true},
		{"empty rule string is skipped", "/anywhere", []string{""}, false},
		{"multi-rule any match wins", "/private/x", []string{"/admin", "/private"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathDisallowedByRobots(tt.path, tt.rules)
			if got != tt.blocked {
				t.Errorf("pathDisallowedByRobots(%q, %v) = %v, want %v", tt.path, tt.rules, got, tt.blocked)
			}
		})
	}
}

// TestCrawlEndpoints_RespectRobots_FiltersDisallowedAcrossSources is the
// integration test for --respect-robots (TASK-095). With the flag set, a
// disallowed path discovered via brute-force (and not just via robots.txt
// itself) must be filtered out of the final endpoint list — that's the
// polite-crawler convention this flag implements. Without the flag, the
// existing default behaviour (queue Disallow paths as discovery hints)
// is preserved.
func TestCrawlEndpoints_RespectRobots_FiltersDisallowedAcrossSources(t *testing.T) {
	// Mock target: serves a robots.txt with Disallow /admin, plus we'll
	// use a wordlist that includes both /admin and /api so brute-force
	// re-discovers /admin separately.
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Wordlist: both /admin (which robots disallows) and /api (allowed).
	dir := t.TempDir()
	wlPath := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wlPath, []byte("/admin\n/api\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default (--respect-robots false): /admin appears in the endpoint list
	// (queued from both robots.txt and brute-force). Verifying this first
	// also locks in the existing behaviour against accidental regression.
	cfg := &models.ScanConfig{
		URL:          srv.URL,
		Timeout:      5,
		WordlistPath: wlPath,
		CrawlDepth:   0,
	}
	c := NewCrawler(cfg)
	got, err := c.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasPath(got, "/admin") {
		t.Errorf("default mode: /admin should appear (Disallow → discovery hint), got %v", paths(got))
	}

	// With --respect-robots: /admin must be filtered out, /api must remain.
	cfg2 := &models.ScanConfig{
		URL:           srv.URL,
		Timeout:       5,
		WordlistPath:  wlPath,
		CrawlDepth:    0,
		RespectRobots: true,
	}
	c2 := NewCrawler(cfg2)
	got2, err := c2.CrawlEndpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hasPath(got2, "/admin") {
		t.Errorf("respect-robots mode: /admin should be filtered out, got %v", paths(got2))
	}
	if !hasPath(got2, "/api") {
		t.Errorf("respect-robots mode: /api (allowed) should remain, got %v", paths(got2))
	}
}

// hasPath reports whether any endpoint has the given Path.
func hasPath(eps []Endpoint, p string) bool {
	for _, e := range eps {
		if e.Path == p {
			return true
		}
	}
	return false
}

// paths extracts the Path field from each Endpoint for diagnostic logging.
func paths(eps []Endpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.Path
	}
	return out
}
