package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestParseIgnoreFile(t *testing.T) {
	content := `
ignore:
  - id: SEC-014
    reason: "Rate limiting at gateway"
    until: "2099-12-01"
  - endpoint: GET /health
    reason: "Public endpoint"
  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints"
`
	dir := t.TempDir()
	path := filepath.Join(dir, ".fendix-ignore")
	os.WriteFile(path, []byte(content), 0644)

	ignoreFile, err := ParseIgnoreFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ignoreFile.Ignore) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(ignoreFile.Ignore))
	}
	if ignoreFile.Ignore[0].ID != "SEC-014" {
		t.Errorf("expected ID SEC-014, got %s", ignoreFile.Ignore[0].ID)
	}
	if ignoreFile.Ignore[1].Endpoint != "GET /health" {
		t.Errorf("expected endpoint 'GET /health', got %s", ignoreFile.Ignore[1].Endpoint)
	}
	if ignoreFile.Ignore[2].Category != "auth" {
		t.Errorf("expected category 'auth', got %s", ignoreFile.Ignore[2].Category)
	}
}

func TestParseIgnoreFile_NotFound(t *testing.T) {
	_, err := ParseIgnoreFile("/nonexistent/.fendix-ignore")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseIgnoreFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".fendix-ignore")
	os.WriteFile(path, []byte("not: [valid: yaml: {{"), 0644)

	_, err := ParseIgnoreFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestApplyIgnoreRules_ByID(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1", Severity: models.SeverityHigh},
		{ID: "SEC-002", Title: "Finding 2", Severity: models.SeverityMedium},
		{ID: "SEC-003", Title: "Finding 3", Severity: models.SeverityLow},
	}
	rules := []IgnoreRule{
		{ID: "SEC-002", Reason: "False positive"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings after suppression, got %d", len(result))
	}
	for _, f := range result {
		if f.ID == "SEC-002" {
			t.Error("SEC-002 should have been suppressed")
		}
	}
}

func TestApplyIgnoreRules_ByFingerprint(t *testing.T) {
	// The fingerprint is run-stable (content hash) — unlike the positional ID
	// it survives reordering. A rule keyed on it must match the right finding
	// even when its SEC-NNN differs from the rule author's last scan.
	target := models.Finding{ID: "SEC-007", Title: "Hardcoded password", Endpoint: "app.py:8", Category: "secrets"}
	fp := models.Fingerprint(target)
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Other", Endpoint: "x.py:1", Category: "secrets"},
		// Same finding, DIFFERENT positional ID than the rule author saw — the
		// fingerprint rule must still catch it.
		{ID: "SEC-099", Title: "Hardcoded password", Endpoint: "app.py:8", Category: "secrets"},
	}
	for i := range findings {
		findings[i].Fingerprint = models.Fingerprint(findings[i])
	}
	rules := []IgnoreRule{{Fingerprint: fp, Reason: "verified false positive"}}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after fingerprint suppression, got %d", len(result))
	}
	if result[0].Title == "Hardcoded password" {
		t.Error("the fingerprinted finding should have been suppressed regardless of its SEC-NNN id")
	}
}

func TestApplyIgnoreRules_ByEndpoint(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Endpoint: "http://example.com/health", Category: "headers"},
		{ID: "SEC-002", Title: "Missing HSTS", Endpoint: "http://example.com/api/users", Category: "headers"},
	}
	rules := []IgnoreRule{
		{Endpoint: "/health", Reason: "Public endpoint"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(result))
	}
	if result[0].ID != "SEC-002" {
		t.Errorf("expected SEC-002 to remain, got %s", result[0].ID)
	}
}

func TestApplyIgnoreRules_ByEndpointGlob(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Missing auth", Endpoint: "http://example.com/api/public/docs", Category: "auth"},
		{ID: "SEC-002", Title: "Missing auth", Endpoint: "http://example.com/api/public/status", Category: "auth"},
		{ID: "SEC-003", Title: "Missing auth", Endpoint: "http://example.com/api/private/users", Category: "auth"},
	}
	rules := []IgnoreRule{
		{Endpoint: "GET /api/public/*", Category: "auth", Reason: "Public endpoints"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(result))
	}
	if result[0].ID != "SEC-003" {
		t.Errorf("expected SEC-003 to remain, got %s", result[0].ID)
	}
}

func TestApplyIgnoreRules_ByCategory(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Missing HSTS", Category: "headers"},
		{ID: "SEC-002", Title: "CORS issue", Category: "cors"},
		{ID: "SEC-003", Title: "Missing CSP", Category: "headers"},
	}
	rules := []IgnoreRule{
		{Category: "headers", Reason: "Headers handled by proxy"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after suppression, got %d", len(result))
	}
	if result[0].Category != "cors" {
		t.Errorf("expected CORS finding to remain, got %s", result[0].Category)
	}
}

func TestApplyIgnoreRules_ExpiredRule(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1", Severity: models.SeverityHigh},
	}
	rules := []IgnoreRule{
		{ID: "SEC-001", Reason: "Expired suppression", Until: "2020-01-01"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding (expired rule should not suppress), got %d", len(result))
	}
}

func TestApplyIgnoreRules_FutureUntil(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1", Severity: models.SeverityHigh},
	}
	rules := []IgnoreRule{
		{ID: "SEC-001", Reason: "Temporary suppression", Until: "2099-12-31"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 0 {
		t.Fatalf("expected 0 findings (future until should suppress), got %d", len(result))
	}
}

func TestApplyIgnoreRules_NoRules(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Finding 1"},
	}

	result := ApplyIgnoreRules(findings, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding with no rules, got %d", len(result))
	}
}

func TestApplyIgnoreRules_NoFindings(t *testing.T) {
	rules := []IgnoreRule{
		{ID: "SEC-001", Reason: "Test"},
	}

	result := ApplyIgnoreRules(nil, rules)
	if len(result) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result))
	}
}

func TestApplyIgnoreRules_EndpointWithCategory(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Missing auth", Endpoint: "http://example.com/api/public/docs", Category: "auth"},
		{ID: "SEC-002", Title: "Missing HSTS", Endpoint: "http://example.com/api/public/docs", Category: "headers"},
	}
	rules := []IgnoreRule{
		{Endpoint: "/api/public/docs", Category: "auth", Reason: "Public endpoint"},
	}

	result := ApplyIgnoreRules(findings, rules)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Category != "headers" {
		t.Errorf("expected headers finding to remain, got %s", result[0].Category)
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		pattern  string
		expected bool
	}{
		{"exact match", "/api/users", "/api/users", true},
		{"trailing wildcard", "/api/public/docs", "/api/public/*", true},
		{"trailing wildcard root", "/api/public", "/api/public/*", true},
		{"no match", "/api/private/users", "/api/public/*", false},
		{"prefix match", "/api/v1/users", "/api/v1*", true},
		{"question mark is literal", "/api/user1", "/api/user?", false},
		{"no wildcard no match", "/api/users", "/api/admin", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := globMatch(tc.s, tc.pattern)
			if got != tc.expected {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.expected)
			}
		})
	}
}

func TestEndpointMatchesPattern(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		pattern  string
		expected bool
	}{
		{"full URL vs path", "http://example.com/api/users", "/api/users", true},
		{"path vs path", "/api/users", "/api/users", true},
		{"METHOD path", "http://example.com/health", "GET /health", true},
		{"glob pattern", "http://example.com/api/public/docs", "GET /api/public/*", true},
		{"no match", "http://example.com/api/private", "/api/public", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointMatchesPattern(tc.endpoint, tc.pattern)
			if got != tc.expected {
				t.Errorf("endpointMatchesPattern(%q, %q) = %v, want %v", tc.endpoint, tc.pattern, got, tc.expected)
			}
		})
	}
}

// Endpoint glob semantics (`.fendix-ignore` `endpoint:`): "**" is zero or
// more whole segments, "*" stays inside one segment, the legacy trailing-"*"
// forms keep their prefix meaning, and source locations match on their path
// (the ":line" suffix is dropped).
func TestEndpointGlobSemantics(t *testing.T) {
	cases := []struct {
		endpoint, pattern string
		want              bool
	}{
		// ** matches zero or more directories.
		{"tests/helpers.py:2", "**/tests/**", true},
		{"pkg/tests/helpers.py:2", "**/tests/**", true},
		{"a/b/c/tests/d/e/helpers.py:9", "**/tests/**", true},
		{"tests/helpers.py:2", "tests/**", true},
		{"pkg/tests/helpers.py:2", "tests/**", false},
		{"pkg/tests", "pkg/tests/**", true},
		{"pkg/tests/x.py:1", "pkg/**/x.py", true},
		{"pkg/x.py:1", "pkg/**/x.py", true},
		{"pkg/a/b/x.py:1", "pkg/**/x.py", true},
		// Production paths that merely resemble a test path do not match.
		{"pkg/zapp/db.py:2", "**/tests/**", false},
		{"pkg/latests/db.py:2", "**/tests/**", false},
		{"pkg/tests_prod/db.py:2", "**/tests/**", false},
		{"pkg/tests.py:2", "**/tests/**", false},
		{"pkg/contests/db.py:2", "**/tests/**", false},
		// * stays within one segment.
		{"src/app.py:3", "src/*.py", true},
		{"src/sub/app.py:3", "src/*.py", false},
		{"pkg/test_db.py:1", "**/test_*.py", true},
		{"pkg/test_db.py:1", "*/test_*.py", true},
		{"a/pkg/test_db.py:1", "*/test_*.py", false},
		{"pkg/a_test.go:1", "**/*_test.go", true},
		// A wildcard pattern without "/" matches a segment at any depth and
		// everything below it (.gitignore convention).
		{"a/b/c.py:3", "*.py", true},
		{"c.py:3", "*.py", true},
		{"a/b/c.go:3", "*.py", false},
		{"pkg/fixtures/x.py:1", "*fixtures*", true},
		{"pkg/prod/x.py:1", "*fixtures*", false},
		{"/api/admin/users", "*admin*", true},
		// Legacy trailing-* prefix forms are unchanged.
		{"pkg/tests/deep/x.py:1", "pkg/tests/*", true},
		{"pkg/tests", "pkg/tests/*", true},
		{"pkg/testsuite/x.py:1", "pkg/tests/*", false},
		{"/api/v1/users", "/api/v1*", true},
		// Windows separators in a rule match forward-slash paths.
		{"pkg/tests/helpers.py:2", `**\tests\**`, true},
		// Case-insensitive, and the method in a "METHOD /path" pattern is not
		// part of the match.
		{"POST /API/Public/Docs", "GET /api/public/*", true},
		{"https://h/api/x/y?q=1", "/api/*/y", true},
		{"https://h/api/x/z/y", "/api/*/y", false},
		{"https://h/api/x/z/y", "/api/**/y", true},
		// Exact raw endpoint still pins one line.
		{"pkg/tests/helpers.py:2", "pkg/tests/helpers.py:2", true},
		{"pkg/tests/helpers.py:3", "pkg/tests/helpers.py:2", false},
	}
	for _, tc := range cases {
		if got := endpointMatchesPattern(tc.endpoint, tc.pattern); got != tc.want {
			t.Errorf("endpointMatchesPattern(%q, %q) = %v, want %v", tc.endpoint, tc.pattern, got, tc.want)
		}
	}
}

// A path rule is applied to each occurrence on its own: in one call with a
// fixture and a production occurrence of the same rule, only the fixture goes.
func TestApplyIgnoreRules_EndpointIsOccurrenceScoped(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Hardcoded password", Category: "secrets", Endpoint: "pkg/tests/helpers.py:2"},
		{ID: "SEC-001", Title: "Hardcoded password", Category: "secrets", Endpoint: "pkg/zapp/db.py:2"},
		{ID: "SEC-001", Title: "Hardcoded password", Category: "secrets", Endpoint: "tests/helpers.py:2"},
	}
	got := ApplyIgnoreRules(findings, []IgnoreRule{{Endpoint: "**/tests/**"}})
	if len(got) != 1 || got[0].Endpoint != "pkg/zapp/db.py:2" {
		t.Fatalf("got %+v, want only the production occurrence", got)
	}
}
