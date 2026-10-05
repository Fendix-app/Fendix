// Package notify ships incoming-webhook alerts for Slack and Teams.
// Sprint 15 (Phase 5.3): post a one-line summary per high-severity
// finding to one or both endpoints, with an in-memory dedup window
// that suppresses duplicate alerts for the same finding ID.
//
// The package is designed to be embeddable in three places:
//
//   - `fendix notify --findings findings.json` (one-shot CLI). The
//     `cmd/fendix` subcommand wires Config from env vars, reads
//     findings from disk, calls (*Notifier).NotifyAll, and exits.
//
//   - Future `fendix serve` post-scan-complete hook (Sprint 07).
//     The serve loop instantiates one Notifier per process and calls
//     NotifyAll after every scan completes; dedup state is shared
//     across scans within the process lifetime.
//
//   - The GitHub App handler's post-scan path (Sprint 13). Hooks
//     into ghapp.Handler.runScan after the PR comment posts.
//
// The dedup map is in-memory only: process restart re-alerts on the
// same findings. Sprint 15.5 (depends on Sprint 07.5 SQLite) persists
// the dedup state.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Config controls per-process notifier behaviour. Zero-value fields
// disable the corresponding sink; a Config with both webhook URLs
// empty is a no-op notifier.
type Config struct {
	// SlackWebhookURL is a Slack incoming-webhook URL
	// (https://hooks.slack.com/services/...). Empty disables.
	SlackWebhookURL string

	// TeamsWebhookURL is a Teams incoming-webhook URL
	// (https://outlook.office.com/webhook/... or
	// https://*.webhook.office.com/...). Empty disables.
	TeamsWebhookURL string

	// MinSeverity is the floor for alerts. Findings strictly below this
	// severity are silently skipped. Default: CRITICAL.
	MinSeverity models.Severity

	// DedupWindow is the duration during which a repeat alert for the
	// same finding ID is suppressed. Default: 1 hour. Set
	// DisableDedup to opt out entirely.
	DedupWindow time.Duration

	// DisableDedup turns off the in-memory dedup map. Every qualifying
	// finding alerts on every NotifyAll call. Useful for test fixtures
	// and short-lived CI runs where dedup state is meaningless.
	DisableDedup bool

	// HTTPClient is reused across Notify calls. Nil uses
	// http.DefaultClient with a 10s timeout.
	HTTPClient *http.Client

	// Now lets tests inject a clock. Production callers leave nil
	// (time.Now is used).
	Now func() time.Time
}

// Notifier holds the resolved Config plus the dedup map. Construct
// via NewNotifier; methods are safe for concurrent use.
type Notifier struct {
	cfg Config
	mu  sync.Mutex
	// alerts records the timestamp at which each finding ID last
	// fired. Entries older than DedupWindow are GC'd opportunistically
	// inside isSuppressed.
	alerts map[string]time.Time
}

// NewNotifier constructs a Notifier from cfg. Sensible defaults are
// applied for zero-valued fields:
//   - MinSeverity defaults to CRITICAL
//   - DedupWindow defaults to 1 hour
//   - HTTPClient defaults to a 10s-timeout client
//   - Now defaults to time.Now
func NewNotifier(cfg Config) *Notifier {
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = models.SeverityCritical
	}
	if cfg.DedupWindow == 0 {
		cfg.DedupWindow = time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Notifier{cfg: cfg, alerts: make(map[string]time.Time)}
}

// Enabled reports whether the notifier has at least one configured
// sink. A no-op notifier (both URLs empty) is useful as a default in
// hot paths so callers don't have to nil-check.
func (n *Notifier) Enabled() bool {
	return n.cfg.SlackWebhookURL != "" || n.cfg.TeamsWebhookURL != ""
}

// SinkResult records the outcome of posting to one webhook. Both
// sinks are attempted independently per finding; one failing does
// not block the other.
type SinkResult struct {
	Sink    string // "slack" or "teams"
	Finding string // finding ID
	Sent    bool
	Skipped string // "below_min_severity" | "dedup" | ""
	Err     error
}

// NotifyAll iterates findings and posts qualifying ones to all
// configured sinks. Each finding is processed independently: a sink
// failure on one finding does not abort the next. Returns the full
// list of SinkResult entries so callers can log / surface per-attempt
// outcomes.
//
// The returned error is non-nil only when the *first* per-finding
// per-sink call hit an unrecoverable error AND every subsequent
// attempt also failed — the orchestrator-level "notify completely
// broken" signal. Otherwise individual failures live in the
// SinkResult.Err fields.
func (n *Notifier) NotifyAll(ctx context.Context, findings []models.Finding) []SinkResult {
	if !n.Enabled() {
		return nil
	}
	var out []SinkResult
	for _, f := range findings {
		if !n.severityClears(f.Severity) {
			if n.cfg.SlackWebhookURL != "" {
				out = append(out, SinkResult{Sink: "slack", Finding: f.ID, Skipped: "below_min_severity"})
			}
			if n.cfg.TeamsWebhookURL != "" {
				out = append(out, SinkResult{Sink: "teams", Finding: f.ID, Skipped: "below_min_severity"})
			}
			continue
		}
		// Atomic check-and-claim under one lock — two concurrent
		// NotifyAll calls on the same finding can't both observe
		// "not suppressed" and both post. The claim happens BEFORE
		// posting so a transient sink failure doesn't allow a repeat
		// alert seconds later — dedup is "saw the finding", not
		// "successfully posted."
		if !n.claim(f.ID) {
			if n.cfg.SlackWebhookURL != "" {
				out = append(out, SinkResult{Sink: "slack", Finding: f.ID, Skipped: "dedup"})
			}
			if n.cfg.TeamsWebhookURL != "" {
				out = append(out, SinkResult{Sink: "teams", Finding: f.ID, Skipped: "dedup"})
			}
			continue
		}
		if n.cfg.SlackWebhookURL != "" {
			out = append(out, n.postSlack(ctx, f))
		}
		if n.cfg.TeamsWebhookURL != "" {
			out = append(out, n.postTeams(ctx, f))
		}
	}
	return out
}

// severityClears reports whether the finding's severity is at-or-above
// the configured floor. The ranking matches models.SeverityRank.
func (n *Notifier) severityClears(s models.Severity) bool {
	return models.SeverityRank(s) >= models.SeverityRank(n.cfg.MinSeverity)
}

// claim atomically checks the dedup map and, if the finding hasn't
// alerted within the dedup window, records "alerted now" and returns
// true. Returns false (skip — duplicate) when the entry exists and
// is still within the window. Holding the lock across the read and
// write closes the TOCTOU race that two prior separate-lock helpers
// allowed. Opportunistic GC drops entries older than the window so
// the map can't grow unboundedly.
func (n *Notifier) claim(id string) bool {
	if n.cfg.DisableDedup {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.cfg.Now()
	if last, ok := n.alerts[id]; ok {
		if now.Sub(last) < n.cfg.DedupWindow {
			return false
		}
	}
	// Opportunistic GC of expired entries.
	for k, t := range n.alerts {
		if now.Sub(t) >= n.cfg.DedupWindow {
			delete(n.alerts, k)
		}
	}
	n.alerts[id] = now
	return true
}

func (n *Notifier) postSlack(ctx context.Context, f models.Finding) SinkResult {
	payload, err := json.Marshal(SlackPayload(f))
	if err != nil {
		return SinkResult{Sink: "slack", Finding: f.ID, Err: fmt.Errorf("marshal slack payload: %w", err)}
	}
	if err := n.postJSON(ctx, n.cfg.SlackWebhookURL, payload); err != nil {
		return SinkResult{Sink: "slack", Finding: f.ID, Err: err}
	}
	return SinkResult{Sink: "slack", Finding: f.ID, Sent: true}
}

func (n *Notifier) postTeams(ctx context.Context, f models.Finding) SinkResult {
	payload, err := json.Marshal(TeamsPayload(f))
	if err != nil {
		return SinkResult{Sink: "teams", Finding: f.ID, Err: fmt.Errorf("marshal teams payload: %w", err)}
	}
	if err := n.postJSON(ctx, n.cfg.TeamsWebhookURL, payload); err != nil {
		return SinkResult{Sink: "teams", Finding: f.ID, Err: err}
	}
	return SinkResult{Sink: "teams", Finding: f.ID, Sent: true}
}

// postJSON POSTs body to webhookURL with Content-Type:
// application/json and returns an error when the response status is
// outside 2xx. The response body (truncated to 512 bytes) is included
// in the error for operator debugging.
//
// Transport-level errors from net/http carry the full request URL in
// their Error() text (e.g. `Post "https://hooks.slack.com/services/T/B/SECRET": dial tcp …`).
// We deliberately do NOT %w-wrap those errors — the wrapped chain
// would leak the secret. Instead we redact at the message boundary
// by extracting the underlying error's text and stripping any
// occurrence of webhookURL.
func (n *Notifier) postJSON(ctx context.Context, webhookURL string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %s",
			redactWebhookURL(webhookURL),
			stripURLFromMessage(err.Error(), webhookURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s: status %d (body: %s)",
			redactWebhookURL(webhookURL), resp.StatusCode, strings.TrimSpace(string(excerpt)))
	}
	// Drain to allow connection reuse.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// stripURLFromMessage replaces every occurrence of webhookURL in msg
// with its redacted form so transport-level errors (which embed the
// full URL with secret) don't leak into operator logs.
func stripURLFromMessage(msg, webhookURL string) string {
	if webhookURL == "" {
		return msg
	}
	return strings.ReplaceAll(msg, webhookURL, redactWebhookURL(webhookURL))
}

// redactWebhookURL strips the credential-bearing path components of
// Slack / Teams / Power-Automate webhook URLs so they don't leak
// into operator logs. Covered shapes:
//
//	Slack incoming        https://hooks.slack.com/services/T.../B.../<secret>
//	Teams incoming        https://*.webhook.office.com/webhookb2/<guid>/IncomingWebhook/<secret>/<guid>
//	Teams legacy          https://outlook.office.com/webhook/<guid>/IncomingWebhook/<secret>/<guid>
//	Power Automate flow   https://*.logic.azure.com/workflows/<guid>/triggers/.../?sig=<secret>
//
// Anything that doesn't match a known prefix falls back to
// scheme://host only — so a typo'd or future webhook shape still
// doesn't leak the path.
func redactWebhookURL(u string) string {
	for _, marker := range []string{"/services/", "/webhookb2/", "/webhook/", "/workflows/"} {
		if i := strings.Index(u, marker); i > 0 {
			return u[:i+len(marker)] + "[REDACTED]"
		}
	}
	// Fallback: keep scheme+host, drop everything else.
	if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + "/[REDACTED]"
	}
	return "[REDACTED]"
}

// ErrEmptyConfig is returned by NewFromEnv when no webhook URL is set.
// Callers can errors.Is-check it to differentiate "user didn't
// configure notify" from a real config error.
var ErrEmptyConfig = errors.New("notify: no FENDIX_SLACK_WEBHOOK_URL or FENDIX_TEAMS_WEBHOOK_URL set")
