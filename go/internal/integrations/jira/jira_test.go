package jira

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// fakeJira spins up a httptest server that records requests and
// returns configurable responses. The default returns 200 on every
// path: tests that want a specific shape override Handler.
type fakeJira struct {
	*httptest.Server
	creates  atomic.Int64
	searches atomic.Int64
	bodies   []string
	// matchedIssues, when non-empty, is returned from /search.
	matchedIssues []string
}

func newFakeJira(t *testing.T) *fakeJira {
	t.Helper()
	fj := &fakeJira{}
	fj.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/rest/api/3/search/jql"):
			fj.searches.Add(1)
			out := map[string]any{"issues": []any{}}
			if len(fj.matchedIssues) > 0 {
				issues := make([]map[string]string, 0, len(fj.matchedIssues))
				for _, k := range fj.matchedIssues {
					issues = append(issues, map[string]string{"key": k})
				}
				out["issues"] = issues
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		case strings.Contains(r.URL.Path, "/rest/api/3/issue"):
			fj.creates.Add(1)
			b, _ := io.ReadAll(r.Body)
			fj.bodies = append(fj.bodies, string(b))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"key":"SEC-123"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fj.Close)
	return fj
}

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(Config{
		BaseURL:     baseURL,
		ProjectKey:  "SEC",
		Email:       "test@example.com",
		APIToken:    "deadbeef",
		MinSeverity: models.SeverityHigh,
		Now:         time.Now,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func makeFinding(id string, sev models.Severity) models.Finding {
	return models.Finding{
		ID:         id,
		Title:      "Hardcoded secret",
		Severity:   sev,
		Endpoint:   "src/app.py:42",
		Evidence:   "API_KEY = 'AKIA...'",
		Fix:        "Use env var.",
		Confidence: models.ConfidenceHigh,
		Category:   "secrets",
		References: []string{"CWE-798"},
	}
}

func TestNewClient_RequiresAllFields(t *testing.T) {
	cases := []Config{
		{},
		{BaseURL: "u", ProjectKey: "K", Email: "e"},    // missing token
		{BaseURL: "u", ProjectKey: "K", APIToken: "t"}, // missing email
		{BaseURL: "u", Email: "e", APIToken: "t"},      // missing project
		{ProjectKey: "K", Email: "e", APIToken: "t"},   // missing URL
	}
	for i, c := range cases {
		_, err := NewClient(c)
		if !errors.Is(err, ErrEmptyConfig) {
			t.Errorf("case %d: err = %v; want ErrEmptyConfig", i, err)
		}
	}
}

func TestNewClient_DefaultsApplied(t *testing.T) {
	c, err := NewClient(Config{
		BaseURL: "https://example.com", ProjectKey: "SEC", Email: "e", APIToken: "t",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.cfg.IssueType != "Bug" {
		t.Errorf("IssueType default = %q; want Bug", c.cfg.IssueType)
	}
	if c.cfg.MinSeverity != models.SeverityHigh {
		t.Errorf("MinSeverity default = %q; want HIGH", c.cfg.MinSeverity)
	}
	if c.cfg.HTTPClient == nil {
		t.Errorf("HTTPClient default should be a *http.Client")
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	c, _ := NewClient(Config{
		BaseURL: "https://example.com/", ProjectKey: "SEC", Email: "e", APIToken: "t",
	})
	if c.cfg.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %q; want trailing slash trimmed", c.cfg.BaseURL)
	}
}

func TestSyncFindings_CreatesNewIssue(t *testing.T) {
	fj := newFakeJira(t)
	c := newTestClient(t, fj.URL)
	out, err := c.SyncFindings(context.Background(),
		[]models.Finding{makeFinding("SEC-X1", models.SeverityCritical)})
	if err != nil {
		t.Fatalf("SyncFindings: %v", err)
	}
	if got := fj.creates.Load(); got != 1 {
		t.Errorf("creates = %d; want 1", got)
	}
	if len(out.Created) != 1 || out.Created[0] != "SEC-123" {
		t.Errorf("Created = %v; want [SEC-123]", out.Created)
	}
	if len(out.Errors) != 0 {
		t.Errorf("unexpected errors: %v", out.Errors)
	}
	// The body must carry the fendix-id label for idempotency.
	if len(fj.bodies) != 1 || !strings.Contains(fj.bodies[0], "fendix-id:SEC-X1") {
		t.Errorf("create payload missing fendix-id label: %q", fj.bodies)
	}
}

func TestSyncFindings_IdempotentWhenIssueExists(t *testing.T) {
	fj := newFakeJira(t)
	fj.matchedIssues = []string{"SEC-EXISTING"}
	c := newTestClient(t, fj.URL)
	out, err := c.SyncFindings(context.Background(),
		[]models.Finding{makeFinding("SEC-X2", models.SeverityHigh)})
	if err != nil {
		t.Fatalf("SyncFindings: %v", err)
	}
	if got := fj.creates.Load(); got != 0 {
		t.Errorf("creates = %d; want 0 (idempotent)", got)
	}
	if len(out.Unchanged) != 1 || out.Unchanged[0] != "SEC-EXISTING" {
		t.Errorf("Unchanged = %v; want [SEC-EXISTING]", out.Unchanged)
	}
}

func TestSyncFindings_SkipsBelowMinSeverity(t *testing.T) {
	fj := newFakeJira(t)
	c := newTestClient(t, fj.URL)
	out, _ := c.SyncFindings(context.Background(),
		[]models.Finding{
			makeFinding("LOW-1", models.SeverityLow),
			makeFinding("HIGH-1", models.SeverityHigh),
		})
	if got := fj.creates.Load(); got != 1 {
		t.Errorf("creates = %d; want 1 (only HIGH counts)", got)
	}
	if len(out.Skipped) != 1 || out.Skipped[0] != "LOW-1" {
		t.Errorf("Skipped = %v; want [LOW-1]", out.Skipped)
	}
}

func TestSyncFindings_RejectsUnsafeFindingID(t *testing.T) {
	// Finding IDs containing whitespace silently split into multiple
	// Jira labels (labels are space-delimited), breaking idempotency
	// — every sync run would create a fresh duplicate issue. The
	// invariant is enforced at the SyncFindings boundary; verify here
	// that unsafe IDs short-circuit before any Jira call is made.
	fj := newFakeJira(t)
	c := newTestClient(t, fj.URL)
	out, err := c.SyncFindings(context.Background(),
		[]models.Finding{
			makeFinding("good-id", models.SeverityCritical),
			makeFinding("bad id with space", models.SeverityCritical),
			makeFinding(`quote"injection`, models.SeverityCritical),
		})
	if err != nil {
		t.Fatalf("SyncFindings (transport-level): %v", err)
	}
	if len(out.Created) != 1 {
		t.Errorf("Created = %v; want exactly 1 (the good ID)", out.Created)
	}
	if len(out.Errors) != 2 {
		t.Fatalf("Errors = %+v; want 2 validation errors", out.Errors)
	}
	for _, e := range out.Errors {
		if e.Phase != "validate" {
			t.Errorf("unexpected phase %q on validation error; want \"validate\"", e.Phase)
		}
		if !errors.Is(e.Err, ErrUnsafeFindingID) {
			t.Errorf("unexpected err %v; want ErrUnsafeFindingID", e.Err)
		}
	}
}

func TestCreateIssue_DefensiveValidation(t *testing.T) {
	// createIssue is internal but reachable by any future caller that
	// bypasses SyncFindings. It must fail closed rather than silently
	// shipping an unsafe label to Jira.
	c := newTestClient(t, "https://unused.example.com")
	_, err := c.createIssue(context.Background(),
		makeFinding("bad id", models.SeverityCritical))
	if !errors.Is(err, ErrUnsafeFindingID) {
		t.Errorf("createIssue err = %v; want ErrUnsafeFindingID", err)
	}
}

func TestSyncFindings_RecordsCreateErrorButContinues(t *testing.T) {
	// Server returns 500 on the second create.
	var creates atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/search") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": []any{}})
			return
		}
		n := creates.Add(1)
		if n == 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":{"summary":"boom"}}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"SEC-OK"}`))
	}))
	defer server.Close()

	c := newTestClient(t, server.URL)
	out, err := c.SyncFindings(context.Background(),
		[]models.Finding{
			makeFinding("ONE", models.SeverityCritical),
			makeFinding("TWO", models.SeverityCritical),
			makeFinding("THREE", models.SeverityCritical),
		})
	if err != nil {
		t.Fatalf("SyncFindings (transport-level): %v", err)
	}
	if len(out.Created) != 2 {
		t.Errorf("Created = %v; want 2 successes", out.Created)
	}
	if len(out.Errors) != 1 || out.Errors[0].FindingID != "TWO" {
		t.Errorf("Errors = %+v; want one error on TWO", out.Errors)
	}
}

func TestJiraDescription_ContainsFindingFields(t *testing.T) {
	f := makeFinding("DESC-1", models.SeverityCritical)
	desc := jiraDescription(f)
	for _, want := range []string{
		"*Severity:* CRITICAL",
		"src/app.py:42",
		"Use env var.",
		"DESC-1",
		"CWE-798",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description missing %q:\n%s", want, desc)
		}
	}
}

func TestSeverityToJiraPriority(t *testing.T) {
	cases := []struct {
		in   models.Severity
		want string
	}{
		{models.SeverityCritical, "Highest"},
		{models.SeverityHigh, "High"},
		{models.SeverityMedium, "Medium"},
		{models.SeverityLow, "Low"},
		{models.SeverityInfo, "Low"},
		{models.Severity("BANANA"), "Low"},
	}
	for _, c := range cases {
		if got := severityToJiraPriority(c.in); got != c.want {
			t.Errorf("severity %q → %q; want %q", c.in, got, c.want)
		}
	}
}

func TestNewFromEnv_RequiresCreds(t *testing.T) {
	t.Setenv(EnvURL, "")
	t.Setenv(EnvProjectKey, "")
	t.Setenv(EnvEmail, "")
	t.Setenv(EnvAPIToken, "")
	_, err := NewFromEnv()
	if !errors.Is(err, ErrEmptyConfig) {
		t.Errorf("err = %v; want ErrEmptyConfig", err)
	}
}

func TestNewFromEnv_ParsesAllFields(t *testing.T) {
	t.Setenv(EnvURL, "https://example.atlassian.net")
	t.Setenv(EnvProjectKey, "SEC")
	t.Setenv(EnvEmail, "e@example.com")
	t.Setenv(EnvAPIToken, "t")
	t.Setenv(EnvIssueType, "Task")
	t.Setenv(EnvMinSeverity, "critical")
	c, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if c.cfg.IssueType != "Task" {
		t.Errorf("IssueType = %q; want Task", c.cfg.IssueType)
	}
	if c.cfg.MinSeverity != models.SeverityCritical {
		t.Errorf("MinSeverity = %q; want CRITICAL", c.cfg.MinSeverity)
	}
}
