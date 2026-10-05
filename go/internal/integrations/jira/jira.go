// Package jira ships idempotent finding → Jira-issue sync.
// Sprint 14 (Phase 5.2): create one Jira issue per finding above a
// severity floor; auto-resolve when a finding stops appearing in
// subsequent scans. Each issue carries a `fendix-id:<finding.ID>`
// label as the idempotency key.
//
// Like notify (Sprint 15), the package is designed as a library +
// CLI subcommand so it ships without waiting on Sprint 07
// (`fendix serve`). The serve-mode hook from the brief is a future
// caller, not a prerequisite.
//
// Config is read from environment variables (12-factor):
//
//	FENDIX_JIRA_URL          https://your-org.atlassian.net
//	FENDIX_JIRA_PROJECT_KEY  e.g. "SEC"
//	FENDIX_JIRA_EMAIL        Jira account email
//	FENDIX_JIRA_API_TOKEN    Jira API token
//	FENDIX_JIRA_MIN_SEVERITY CRITICAL | HIGH | MEDIUM | LOW | INFO
//	                         Default: HIGH.
//	FENDIX_JIRA_ISSUE_TYPE   Default: "Bug". Some Jira projects use
//	                         "Task" or "Vulnerability".
//
// Auth is HTTP Basic with `email:api_token` per Atlassian's docs.
package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Config carries the per-process Jira credentials. Use NewFromEnv to
// populate from env vars; or build it directly in tests.
type Config struct {
	BaseURL     string // e.g. https://your-org.atlassian.net
	ProjectKey  string // e.g. SEC
	Email       string
	APIToken    string
	IssueType   string          // default "Bug"
	MinSeverity models.Severity // default HIGH
	HTTPClient  *http.Client    // default 30s timeout
	Now         func() time.Time
}

// Client is the API surface callers use. Construct via NewClient.
type Client struct {
	cfg Config
}

// NewClient validates cfg and returns a ready-to-use Client. Returns
// ErrEmptyConfig if BaseURL / Email / APIToken / ProjectKey are
// missing — these are required and not user-overridable to a
// reasonable default.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" || cfg.ProjectKey == "" || cfg.Email == "" || cfg.APIToken == "" {
		return nil, ErrEmptyConfig
	}
	if cfg.IssueType == "" {
		cfg.IssueType = "Bug"
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = models.SeverityHigh
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg}, nil
}

// ErrEmptyConfig signals at least one required field on Config is
// unset. Callers errors.Is-check it to distinguish "user didn't
// configure Jira" from a transport error.
var ErrEmptyConfig = errors.New("jira: BaseURL, ProjectKey, Email, and APIToken are all required")

// SyncResult summarises a sync run.
type SyncResult struct {
	Created   []string    // Jira issue keys created this run
	Resolved  []string    // Jira issue keys transitioned to Done
	Unchanged []string    // Jira issue keys that already matched the scan state
	Skipped   []string    // Finding IDs below MinSeverity
	Errors    []SyncError // per-operation errors; sync continues past each
}

// SyncError is one finding's failure mode. The caller can log
// per-error; SyncFindings returns nil when the whole sync was
// transport-OK even if individual ops failed.
type SyncError struct {
	FindingID string
	Phase     string // "search" | "create" | "transition"
	Err       error
}

func (e SyncError) Error() string {
	return fmt.Sprintf("jira sync: %s for finding %q: %v", e.Phase, e.FindingID, e.Err)
}

// ErrUnsafeFindingID is returned when a finding ID contains
// characters that would break the JQL idempotency search or split
// into multiple Jira labels (which silently breaks idempotency —
// every sync run creates a fresh duplicate issue). Allowed
// characters: A-Z a-z 0-9 . _ -
var ErrUnsafeFindingID = errors.New("jira: finding ID contains characters not permitted in a Jira label (allowed: A-Z a-z 0-9 . _ -)")

// SyncFindings is the package's main entry point. It iterates
// findings ≥ MinSeverity and ensures one Jira issue exists per
// finding (idempotency via the label `fendix-id:<id>`).
//
// Auto-resolution (transition issues to Done when the finding stops
// appearing) is a follow-up — Sprint 14.5 — because it requires
// querying all existing fendix-labelled issues, which depends on a
// stable persistence story (Sprint 07.5 SQLite) to know "this scan
// is the latest." See PLAN.md decision gate D1.
//
// Finding IDs are validated against [A-Za-z0-9._-]+ at this boundary
// — once, here — so neither findExisting nor createIssue can ever
// see an ID that would inject JQL or split-on-whitespace into
// multiple Jira labels. Both helpers assert the invariant defensively;
// any future caller bypassing SyncFindings will get an immediate
// ErrUnsafeFindingID instead of a silent idempotency break.
func (c *Client) SyncFindings(ctx context.Context, findings []models.Finding) (SyncResult, error) {
	out := SyncResult{}
	for _, f := range findings {
		if !c.severityClears(f.Severity) {
			out.Skipped = append(out.Skipped, f.ID)
			continue
		}
		if !labelSafeID.MatchString(f.ID) {
			out.Errors = append(out.Errors, SyncError{FindingID: f.ID, Phase: "validate", Err: ErrUnsafeFindingID})
			continue
		}
		key, found, err := c.findExisting(ctx, f.ID)
		if err != nil {
			out.Errors = append(out.Errors, SyncError{FindingID: f.ID, Phase: "search", Err: err})
			continue
		}
		if found {
			out.Unchanged = append(out.Unchanged, key)
			continue
		}
		key, err = c.createIssue(ctx, f)
		if err != nil {
			out.Errors = append(out.Errors, SyncError{FindingID: f.ID, Phase: "create", Err: err})
			continue
		}
		out.Created = append(out.Created, key)
	}
	return out, nil
}

// severityClears reports whether a finding's severity is at-or-above
// the configured floor.
func (c *Client) severityClears(s models.Severity) bool {
	return models.SeverityRank(s) >= models.SeverityRank(c.cfg.MinSeverity)
}

// labelSafeID is the character set Jira accepts in a label. Jira
// labels can't contain whitespace or quotes; we restrict further to
// alphanumerics, dot, dash, underscore so the JQL `labels = "…"`
// literal can never be broken out of by a hostile finding ID
// (e.g. one derived from a scan of an attacker-controlled repo via
// the GH App handler).
var labelSafeID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// findExisting queries Jira for an issue with the fendix-id label
// for the given finding. Returns (issueKey, found, error). "Not
// found" is `("", false, nil)` — a normal idempotency outcome, not
// an error.
//
// Uses the POST /rest/api/3/search/jql endpoint introduced May 2025
// (the GET /rest/api/3/search endpoint was deprecated and removed
// for new instances at that time).
func (c *Client) findExisting(ctx context.Context, findingID string) (string, bool, error) {
	// Defensive: SyncFindings already enforces this, but a future
	// caller might invoke findExisting directly. Fail closed.
	if !labelSafeID.MatchString(findingID) {
		return "", false, ErrUnsafeFindingID
	}
	// JQL: project = "<KEY>" AND labels = "fendix-id:<id>"
	// Project keys are restricted by Jira to [A-Z][A-Z0-9_]+; we still
	// escape defensively in case a customer's key violates the rule.
	jql := fmt.Sprintf(`project = %s AND labels = %s`,
		quoteJQL(c.cfg.ProjectKey), quoteJQL("fendix-id:"+findingID))
	payload, err := json.Marshal(map[string]any{
		"jql":        jql,
		"fields":     []string{"key"},
		"maxResults": 1,
	})
	if err != nil {
		return "", false, fmt.Errorf("marshal search payload: %w", err)
	}
	endpoint := c.cfg.BaseURL + "/rest/api/3/search/jql"
	resp, err := c.do(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", false, fmt.Errorf("search %s: status %d (body: %s)",
			redactBasicAuth(endpoint), resp.StatusCode, strings.TrimSpace(string(excerpt)))
	}

	var body struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", false, fmt.Errorf("decode search response: %w", err)
	}
	if len(body.Issues) == 0 {
		return "", false, nil
	}
	return body.Issues[0].Key, true, nil
}

// quoteJQL renders a Go string as a JQL-quoted literal. Per
// Atlassian's JQL grammar, backslash and double-quote inside a
// quoted string must be backslash-escaped.
func quoteJQL(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// createIssue posts a new Jira issue carrying the fendix-id label
// for idempotency. Returns the new issue key.
//
// Defensive: SyncFindings already enforces labelSafeID, but a future
// caller might invoke createIssue directly. Jira labels split on
// whitespace, so an ID containing a space would produce multiple
// labels and silently break idempotency for every subsequent sync.
// Fail closed before that can happen.
func (c *Client) createIssue(ctx context.Context, f models.Finding) (string, error) {
	if !labelSafeID.MatchString(f.ID) {
		return "", ErrUnsafeFindingID
	}
	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": c.cfg.ProjectKey},
			"summary":     truncate(fmt.Sprintf("[%s] %s", f.Severity, f.Title), 240),
			"description": jiraDescription(f),
			"issuetype":   map[string]string{"name": c.cfg.IssueType},
			"labels":      []string{"fendix", "fendix-id:" + f.ID, "fendix-sev:" + string(f.Severity)},
			"priority":    map[string]string{"name": severityToJiraPriority(f.Severity)},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal issue payload: %w", err)
	}
	endpoint := c.cfg.BaseURL + "/rest/api/3/issue"
	resp, err := c.do(ctx, http.MethodPost, endpoint, raw)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("create %s: status %d (body: %s)",
			redactBasicAuth(endpoint), resp.StatusCode, strings.TrimSpace(string(excerpt)))
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode create response: %w", err)
	}
	return out.Key, nil
}

// do sends an authenticated request with Basic auth. The body, if
// non-nil, is JSON.
func (c *Client) do(ctx context.Context, method, urlStr string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, reader)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", method, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Basic "+basicAuth(c.cfg.Email, c.cfg.APIToken))
	return c.cfg.HTTPClient.Do(req)
}

// basicAuth is base64(email:token).
func basicAuth(email, token string) string {
	return base64.StdEncoding.EncodeToString([]byte(email + ":" + token))
}

// redactBasicAuth strips inline credentials from URLs in error
// messages. The Jira URL doesn't carry creds (they're in the header),
// so this is a defence-in-depth no-op today, but kept so future
// transports that DO use URL credentials don't leak them.
func redactBasicAuth(u string) string {
	if i := strings.Index(u, "://"); i > 0 {
		if at := strings.Index(u[i+3:], "@"); at > 0 {
			return u[:i+3] + "[REDACTED]@" + u[i+3+at+1:]
		}
	}
	return u
}

// jiraDescription renders a Jira-friendly plain-text issue body. We
// deliberately use the plaintext shape (rather than Atlassian
// Document Format) because plaintext is the universal lowest common
// denominator across Jira Cloud (which auto-renders ADF), Jira Server
// (which doesn't), and customer-tier limits on description format.
// The Jira API accepts plaintext as a `description: "string"` field.
func jiraDescription(f models.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*Severity:* %s\n", f.Severity)
	if f.Category != "" {
		fmt.Fprintf(&b, "*Category:* %s\n", f.Category)
	}
	if f.Confidence != "" {
		fmt.Fprintf(&b, "*Confidence:* %s\n", f.Confidence)
	}
	if f.Endpoint != "" {
		fmt.Fprintf(&b, "*Endpoint:* %s\n", f.Endpoint)
	}
	fmt.Fprintf(&b, "\n*Evidence:*\n{noformat}\n%s\n{noformat}\n", f.Evidence)
	if f.Fix != "" {
		fmt.Fprintf(&b, "\n*Fix:*\n%s\n", f.Fix)
	}
	if len(f.References) > 0 {
		fmt.Fprintf(&b, "\n*References:* %s\n", strings.Join(f.References, ", "))
	}
	fmt.Fprintf(&b, "\n----\nFendix finding ID: `%s`\n", f.ID)
	return b.String()
}

// severityToJiraPriority maps the Fendix severity scale to Jira's
// default priority enum. Customers with custom priority schemes can
// post-process; the brief deemed this acceptable scope.
func severityToJiraPriority(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "Highest"
	case models.SeverityHigh:
		return "High"
	case models.SeverityMedium:
		return "Medium"
	case models.SeverityLow:
		return "Low"
	default:
		return "Low"
	}
}

// truncate clips s to at most max runes, appending "…" when clipped.
// Rune-aware so multi-byte UTF-8 characters (e.g. file paths with
// accents in finding titles) are never split mid-byte.
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max-1]) + "…"
}

// String redacts the API token so accidental `%+v` / log dumps of
// Config don't leak credentials. GoString covers the `%#v` verb.
func (c Config) String() string {
	return fmt.Sprintf("jira.Config{BaseURL:%q ProjectKey:%q Email:%q APIToken:[REDACTED] IssueType:%q MinSeverity:%q}",
		c.BaseURL, c.ProjectKey, c.Email, c.IssueType, c.MinSeverity)
}

func (c Config) GoString() string { return c.String() }
