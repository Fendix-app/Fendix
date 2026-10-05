package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func writeSpec(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// OpenAPI 3.x: `security: []` and `security: [{}]` BOTH make auth optional.
// A global requirement is inherited by any operation that does not override it.
func TestSpecEndpointsCarryAuthExpectation(t *testing.T) {
	path := writeSpec(t, `{
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.com"}],
      "security": [{"jwtAuth": []}],
      "components": {"securitySchemes": {"jwtAuth": {"type": "http", "scheme": "bearer"}}},
      "paths": {
        "/inherits":     {"get": {"responses": {"200": {"description": "ok"}}}},
        "/explicit":     {"get": {"security": [{"jwtAuth": []}], "responses": {"200": {"description": "ok"}}}},
        "/opted-out":    {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/anon-object":  {"get": {"security": [{}], "responses": {"200": {"description": "ok"}}}}
      }
    }`)

	c := &Crawler{cfg: &models.ScanConfig{SpecPath: path}}
	endpoints, err := c.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}

	want := map[string]models.AuthExpectation{
		"/inherits":    models.AuthExpectationRequired,
		"/explicit":    models.AuthExpectationRequired,
		"/opted-out":   models.AuthExpectationPublic,
		"/anon-object": models.AuthExpectationPublic,
	}
	got := map[string]models.AuthExpectation{}
	for _, ep := range endpoints {
		got[ep.Path] = ep.AuthExpectation
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: AuthExpectation = %q, want %q", p, got[p], w)
		}
	}
}

// No global security and no operation security means Fendix never established
// an expectation. That must stay UNKNOWN — not Public — because "the spec is
// silent" is not "the spec declares this open".
func TestSpecWithoutSecurityLeavesExpectationUnknown(t *testing.T) {
	path := writeSpec(t, `{
      "openapi": "3.0.0",
      "servers": [{"url": "https://api.example.com"}],
      "paths": {"/silent": {"get": {"responses": {"200": {"description": "ok"}}}}}
    }`)

	c := &Crawler{cfg: &models.ScanConfig{SpecPath: path}}
	endpoints, err := c.fromSpec(context.Background())
	if err != nil {
		t.Fatalf("fromSpec: %v", err)
	}
	if len(endpoints) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(endpoints))
	}
	if endpoints[0].AuthExpectation != models.AuthExpectationUnknown {
		t.Errorf("AuthExpectation = %q, want unknown", endpoints[0].AuthExpectation)
	}
}

// specAllowsAnon mirrors python/analyzers/spec_parser.py:_allows_anon. The
// `security: [{}]` form is the one a naive truthiness check gets wrong:
// len([{}]) != 0, so "non-empty list means a requirement" misreads an explicit
// opt-out as a requirement.
func TestSpecAllowsAnonHandlesBothAnonymousForms(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want bool
	}{
		{"empty list", []interface{}{}, true},
		{"list with empty object", []interface{}{map[string]interface{}{}}, true},
		{"real requirement", []interface{}{map[string]interface{}{"jwtAuth": []interface{}{}}}, false},
		{"requirement then anon", []interface{}{
			map[string]interface{}{"jwtAuth": []interface{}{}},
			map[string]interface{}{},
		}, true},
		{"absent", nil, false},
		{"malformed", "not-a-list", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := specAllowsAnon(tc.in); got != tc.want {
				t.Errorf("specAllowsAnon(%#v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
