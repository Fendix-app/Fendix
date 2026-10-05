package notify

import (
	"fmt"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// SlackPayload builds a Block Kit message for one finding. The shape
// matches the sprint-15 brief's Slack section.
//
// Slack accepts arbitrary JSON via incoming-webhook; we keep the
// schema strict enough that block-kit-builder.tools/slack.dev/block-kit
// validates without warnings. Color-by-severity is conveyed via emoji
// in the section text (Slack doesn't expose the attachment-color API
// to incoming webhooks).
func SlackPayload(f models.Finding) map[string]any {
	emoji := severityEmoji(f.Severity)
	header := fmt.Sprintf("*%s Fendix: New %s finding*\n*%s*", emoji, f.Severity, escapeSlackText(f.Title))
	if f.Endpoint != "" {
		header += "\n`" + escapeSlackText(f.Endpoint) + "`"
	}

	blocks := []map[string]any{
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": header,
			},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{"type": "mrkdwn", "text": "*Severity:* " + string(f.Severity)},
				{"type": "mrkdwn", "text": "*Confidence:* " + string(f.Confidence)},
			},
		},
	}

	if fix := escapeSlackText(f.Fix); fix != "" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": "*Fix:* " + fix,
			},
		})
	}

	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{"type": "mrkdwn", "text": "Fendix ID: `" + escapeSlackText(f.ID) + "`"},
		},
	})

	return map[string]any{"blocks": blocks}
}

// severityEmoji returns a short visual indicator. Picked to be
// terminal- and Slack-mobile-friendly.
func severityEmoji(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🟢"
	default:
		return "ℹ️"
	}
}

// escapeSlackText escapes the three characters Slack treats specially
// in mrkdwn fields (& < >). Other markdown characters (*, _, `) are
// intentionally NOT escaped because the payload uses them
// deliberately for emphasis.
func escapeSlackText(s string) string {
	// Order matters: & first so we don't double-escape the &amp; we
	// just emitted.
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	return r
}
