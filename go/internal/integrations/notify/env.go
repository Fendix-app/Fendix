package notify

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// EnvVar names recognised by NewFromEnv. Kept in one place so the
// CLI --help text can list them without divergence.
const (
	EnvSlackWebhookURL = "FENDIX_SLACK_WEBHOOK_URL"
	EnvTeamsWebhookURL = "FENDIX_TEAMS_WEBHOOK_URL"
	EnvMinSeverity     = "FENDIX_NOTIFY_MIN_SEVERITY"
	EnvDedupWindow     = "FENDIX_NOTIFY_DEDUP_WINDOW"
)

// NewFromEnv reads notify Config from environment variables. Used by
// the `fendix notify` CLI subcommand and by future serve / ghapp
// integrations.
//
// At least one of FENDIX_SLACK_WEBHOOK_URL or FENDIX_TEAMS_WEBHOOK_URL
// must be set; otherwise NewFromEnv returns ErrEmptyConfig so callers
// can errors.Is-distinguish "user didn't configure notify" from a
// malformed value.
//
// Defaults:
//   - FENDIX_NOTIFY_MIN_SEVERITY: CRITICAL
//   - FENDIX_NOTIFY_DEDUP_WINDOW: 1h (Go duration string, e.g. "30m", "2h").
//     Set to "0" to disable dedup entirely (every alert fires).
func NewFromEnv() (*Notifier, error) {
	cfg := Config{
		SlackWebhookURL: os.Getenv(EnvSlackWebhookURL),
		TeamsWebhookURL: os.Getenv(EnvTeamsWebhookURL),
	}
	if cfg.SlackWebhookURL == "" && cfg.TeamsWebhookURL == "" {
		return nil, ErrEmptyConfig
	}

	if v := os.Getenv(EnvMinSeverity); v != "" {
		sev, err := parseSeverity(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvMinSeverity, err)
		}
		cfg.MinSeverity = sev
	}

	if v := os.Getenv(EnvDedupWindow); v != "" {
		dur, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("%s: parse %q as Go duration: %w", EnvDedupWindow, v, err)
		}
		if dur < 0 {
			return nil, fmt.Errorf("%s: negative duration %s", EnvDedupWindow, dur)
		}
		// Explicit "0" → disable dedup entirely. Distinguished from
		// "unset" (env var not present) so the documented contract
		// "set to 0 to disable" holds without conflicting with the
		// zero-value default in NewNotifier.
		if dur == 0 {
			cfg.DisableDedup = true
		} else {
			cfg.DedupWindow = dur
		}
	}

	return NewNotifier(cfg), nil
}

// parseSeverity is a case-insensitive lookup against the canonical
// severity strings. Errors include the accepted set so a user typo
// gets a useful diagnostic.
func parseSeverity(s string) (models.Severity, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	switch up {
	case string(models.SeverityCritical):
		return models.SeverityCritical, nil
	case string(models.SeverityHigh):
		return models.SeverityHigh, nil
	case string(models.SeverityMedium):
		return models.SeverityMedium, nil
	case string(models.SeverityLow):
		return models.SeverityLow, nil
	case string(models.SeverityInfo):
		return models.SeverityInfo, nil
	}
	return "", fmt.Errorf("unknown severity %q (want CRITICAL, HIGH, MEDIUM, LOW, or INFO)", s)
}
