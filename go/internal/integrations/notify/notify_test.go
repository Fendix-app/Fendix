package notify

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

// makeFinding builds a Finding suitable for round-trip tests. Tests
// override individual fields when they need to exercise a specific
// shape (e.g. empty Endpoint).
func makeFinding(id string, sev models.Severity) models.Finding {
	return models.Finding{
		ID:         id,
		Title:      "Hardcoded secret found",
		Severity:   sev,
		Endpoint:   "src/app.py:42",
		Fix:        "Move the secret to an env var and rotate it.",
		Confidence: models.ConfidenceHigh,
	}
}

// recordingServer counts requests and captures bodies so tests can
// assert on what was POSTed.
type recordingServer struct {
	*httptest.Server
	requests atomic.Int64
	bodies   []string
	status   int
}

func newRecordingServer(t *testing.T, status int) *recordingServer {
	t.Helper()
	rs := &recordingServer{status: status}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.requests.Add(1)
		b, _ := io.ReadAll(r.Body)
		rs.bodies = append(rs.bodies, string(b))
		w.WriteHeader(rs.status)
	}))
	t.Cleanup(rs.Close)
	return rs
}

func TestSlackPayload_HasExpectedBlocks(t *testing.T) {
	p := SlackPayload(makeFinding("SEC-AWS-1", models.SeverityCritical))
	blocks, ok := p["blocks"].([]map[string]any)
	if !ok || len(blocks) < 3 {
		t.Fatalf("want ≥3 blocks; got %v", p["blocks"])
	}
	// First block must be a header section with the title.
	first := blocks[0]
	text, _ := first["text"].(map[string]any)
	body, _ := text["text"].(string)
	if !strings.Contains(body, "CRITICAL") || !strings.Contains(body, "Hardcoded secret") {
		t.Errorf("first block missing CRITICAL header / title; got %q", body)
	}
	// One of the blocks must reference the finding ID for traceability.
	var sawID bool
	for _, b := range blocks {
		if marshalled, _ := json.Marshal(b); strings.Contains(string(marshalled), "SEC-AWS-1") {
			sawID = true
		}
	}
	if !sawID {
		t.Errorf("finding ID not surfaced in any block")
	}
}

func TestSlackPayload_EscapesHTMLSpecials(t *testing.T) {
	f := makeFinding("SEC-X", models.SeverityHigh)
	f.Title = "<script>alert(1)</script> & friends"
	p := SlackPayload(f)
	bytes, _ := json.Marshal(p)
	got := string(bytes)
	if strings.Contains(got, "<script>") {
		t.Errorf("Slack payload didn't escape angle brackets: %s", got)
	}
	// json.Marshal escapes the literal '&' to "&" by default, so
	// our HTML-entity "&amp;" appears in the marshalled JSON as the
	// 9-byte sequence "&amp;". The clearest signal of correct
	// escaping is that the original "& friends" substring does NOT
	// survive verbatim.
	if strings.Contains(got, "& friends") {
		t.Errorf("Slack payload contains unescaped '& friends': %s", got)
	}
	if !strings.Contains(got, "amp;") {
		t.Errorf("Slack payload missing the 'amp;' suffix that proves we wrote &amp;: %s", got)
	}
}

func TestTeamsPayload_AdaptiveCardShape(t *testing.T) {
	p := TeamsPayload(makeFinding("SEC-Y", models.SeverityCritical))
	if p["type"] != "message" {
		t.Errorf("top-level type = %v; want 'message'", p["type"])
	}
	atts, ok := p["attachments"].([]map[string]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("want exactly one attachment; got %v", p["attachments"])
	}
	if atts[0]["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType = %v", atts[0]["contentType"])
	}
	content, _ := atts[0]["content"].(map[string]any)
	if content["version"] != "1.3" {
		t.Errorf("AdaptiveCard version = %v; want 1.3 (pinned for compatibility)", content["version"])
	}
}

func TestNotifier_SkipsBelowMinSeverity(t *testing.T) {
	slack := newRecordingServer(t, 200)
	n := NewNotifier(Config{
		SlackWebhookURL: slack.URL,
		MinSeverity:     models.SeverityCritical,
		Now:             time.Now,
	})
	results := n.NotifyAll(context.Background(),
		[]models.Finding{makeFinding("LOW-1", models.SeverityLow)})
	if slack.requests.Load() != 0 {
		t.Errorf("expected 0 requests; got %d", slack.requests.Load())
	}
	if len(results) != 1 || results[0].Skipped != "below_min_severity" {
		t.Errorf("expected one below_min_severity skip; got %+v", results)
	}
}

func TestNotifier_DedupSuppressesRepeatWithinWindow(t *testing.T) {
	slack := newRecordingServer(t, 200)
	now := time.Now()
	clk := &now
	n := NewNotifier(Config{
		SlackWebhookURL: slack.URL,
		MinSeverity:     models.SeverityCritical,
		DedupWindow:     time.Hour,
		Now:             func() time.Time { return *clk },
	})
	finding := makeFinding("DUP-1", models.SeverityCritical)

	// First call alerts.
	n.NotifyAll(context.Background(), []models.Finding{finding})
	// Second call within the window is suppressed.
	n.NotifyAll(context.Background(), []models.Finding{finding})

	if got := slack.requests.Load(); got != 1 {
		t.Errorf("requests = %d; want 1 (dedup should suppress the second)", got)
	}
}

func TestNotifier_DedupExpiresAfterWindow(t *testing.T) {
	slack := newRecordingServer(t, 200)
	now := time.Now()
	clk := &now
	n := NewNotifier(Config{
		SlackWebhookURL: slack.URL,
		MinSeverity:     models.SeverityCritical,
		DedupWindow:     time.Hour,
		Now:             func() time.Time { return *clk },
	})
	finding := makeFinding("DUP-2", models.SeverityCritical)

	n.NotifyAll(context.Background(), []models.Finding{finding})
	// Advance past the window.
	*clk = now.Add(time.Hour + time.Minute)
	n.NotifyAll(context.Background(), []models.Finding{finding})

	if got := slack.requests.Load(); got != 2 {
		t.Errorf("requests = %d; want 2 (post-window alert should fire)", got)
	}
}

func TestNotifier_SlackErrorDoesNotBlockTeams(t *testing.T) {
	slack := newRecordingServer(t, 500)
	teams := newRecordingServer(t, 200)
	n := NewNotifier(Config{
		SlackWebhookURL: slack.URL,
		TeamsWebhookURL: teams.URL,
		MinSeverity:     models.SeverityCritical,
	})
	results := n.NotifyAll(context.Background(),
		[]models.Finding{makeFinding("BOTH-1", models.SeverityCritical)})
	if len(results) != 2 {
		t.Fatalf("want 2 results (one per sink); got %d", len(results))
	}
	var slackResult, teamsResult SinkResult
	for _, r := range results {
		switch r.Sink {
		case "slack":
			slackResult = r
		case "teams":
			teamsResult = r
		}
	}
	if slackResult.Err == nil {
		t.Errorf("expected slack error from 500 status; got nil")
	}
	if !teamsResult.Sent {
		t.Errorf("teams should have sent despite slack failure; result=%+v", teamsResult)
	}
}

func TestNotifier_RedactsWebhookURLInErrors(t *testing.T) {
	slack := newRecordingServer(t, 500)
	// The recordingServer's URL doesn't include /services/, so swap in
	// a fake fully-qualified URL that does — and point the client at
	// the test server via a custom transport so the real Slack host
	// never gets contacted.
	slackURL := "https://hooks.slack.com/services/T123/B456/SECRETPART"
	n := NewNotifier(Config{
		SlackWebhookURL: slackURL,
		MinSeverity:     models.SeverityCritical,
		HTTPClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				// Redirect the request to the test server.
				req.URL.Host = strings.TrimPrefix(slack.URL, "http://")
				req.URL.Scheme = "http"
				return http.DefaultTransport.RoundTrip(req)
			}),
		},
	})
	results := n.NotifyAll(context.Background(),
		[]models.Finding{makeFinding("RED-1", models.SeverityCritical)})
	if len(results) == 0 || results[0].Err == nil {
		t.Fatalf("expected at least one error result; got %+v", results)
	}
	if strings.Contains(results[0].Err.Error(), "SECRETPART") {
		t.Errorf("webhook secret leaked into error: %v", results[0].Err)
	}
	if !strings.Contains(results[0].Err.Error(), "[REDACTED]") {
		t.Errorf("error missing [REDACTED] marker: %v", results[0].Err)
	}
}

func TestNotifier_NoOpWhenNoURLsConfigured(t *testing.T) {
	n := NewNotifier(Config{MinSeverity: models.SeverityCritical})
	if n.Enabled() {
		t.Errorf("Enabled = true; want false for no-URL config")
	}
	results := n.NotifyAll(context.Background(),
		[]models.Finding{makeFinding("X", models.SeverityCritical)})
	if results != nil {
		t.Errorf("NotifyAll on no-op notifier returned %v; want nil", results)
	}
}

func TestNewFromEnv_RequiresAtLeastOneWebhook(t *testing.T) {
	t.Setenv(EnvSlackWebhookURL, "")
	t.Setenv(EnvTeamsWebhookURL, "")
	_, err := NewFromEnv()
	if !errors.Is(err, ErrEmptyConfig) {
		t.Errorf("err = %v; want ErrEmptyConfig", err)
	}
}

func TestNewFromEnv_ParsesAllFields(t *testing.T) {
	t.Setenv(EnvSlackWebhookURL, "https://hooks.slack.com/services/T/B/C")
	t.Setenv(EnvTeamsWebhookURL, "")
	t.Setenv(EnvMinSeverity, "high")
	t.Setenv(EnvDedupWindow, "30m")
	n, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if n.cfg.MinSeverity != models.SeverityHigh {
		t.Errorf("MinSeverity = %q; want HIGH", n.cfg.MinSeverity)
	}
	if n.cfg.DedupWindow != 30*time.Minute {
		t.Errorf("DedupWindow = %s; want 30m", n.cfg.DedupWindow)
	}
}

func TestNewFromEnv_RejectsUnknownSeverity(t *testing.T) {
	t.Setenv(EnvSlackWebhookURL, "https://hooks.slack.com/services/T/B/C")
	t.Setenv(EnvTeamsWebhookURL, "")
	t.Setenv(EnvMinSeverity, "banana")
	if _, err := NewFromEnv(); err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestNotifier_PostsBothSinksWhenBothEnabled(t *testing.T) {
	slack := newRecordingServer(t, 200)
	teams := newRecordingServer(t, 200)
	n := NewNotifier(Config{
		SlackWebhookURL: slack.URL,
		TeamsWebhookURL: teams.URL,
		MinSeverity:     models.SeverityCritical,
	})
	n.NotifyAll(context.Background(),
		[]models.Finding{makeFinding("X", models.SeverityCritical)})
	if slack.requests.Load() != 1 || teams.requests.Load() != 1 {
		t.Errorf("requests: slack=%d teams=%d; want 1 each",
			slack.requests.Load(), teams.requests.Load())
	}
	// Verify each sink got JSON that mentions the finding.
	if !strings.Contains(slack.bodies[0], "X") {
		t.Errorf("slack body missing finding ID: %s", slack.bodies[0])
	}
	if !strings.Contains(teams.bodies[0], "X") {
		t.Errorf("teams body missing finding ID: %s", teams.bodies[0])
	}
}

// roundTripFunc is a tiny adapter to use a closure as an http
// RoundTripper. Used by TestNotifier_RedactsWebhookURLInErrors.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
