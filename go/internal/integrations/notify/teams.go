package notify

import (
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TeamsPayload builds an Adaptive Card 1.3 message for one finding.
// Adaptive Card 1.3 is broadly supported across Teams desktop, mobile,
// and the web client; 1.4+ adds features (e.g. input.text) we don't
// need for read-only alerts, and 1.3's compatibility surface is the
// widest. Pinning the schema version lets Teams ignore future
// Microsoft changes that break newer versions.
func TeamsPayload(f models.Finding) map[string]any {
	color := teamsSeverityColor(f.Severity)
	body := []map[string]any{
		{
			"type":   "TextBlock",
			"size":   "Medium",
			"weight": "Bolder",
			"text":   severityEmoji(f.Severity) + " Fendix: New " + string(f.Severity) + " finding",
			"color":  color,
			"wrap":   true,
		},
		{
			"type": "TextBlock",
			"text": f.Title,
			"wrap": true,
		},
	}

	facts := []map[string]any{}
	if f.Endpoint != "" {
		facts = append(facts, map[string]any{"title": "Endpoint:", "value": f.Endpoint})
	}
	if f.Confidence != "" {
		facts = append(facts, map[string]any{"title": "Confidence:", "value": string(f.Confidence)})
	}
	facts = append(facts, map[string]any{"title": "Fendix ID:", "value": f.ID})

	body = append(body, map[string]any{
		"type":  "FactSet",
		"facts": facts,
	})

	if f.Fix != "" {
		body = append(body, map[string]any{
			"type": "TextBlock",
			"text": "**Fix:** " + f.Fix,
			"wrap": true,
		})
	}

	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"type":    "AdaptiveCard",
				"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
				"version": "1.3",
				"body":    body,
			},
		}},
	}
}

// teamsSeverityColor returns the Adaptive Card "color" enum that
// renders the header text. CRITICAL/HIGH use the "Attention" red;
// MEDIUM uses "Warning" yellow; LOW/INFO use the default which is
// the theme-neutral grey.
func teamsSeverityColor(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "Attention"
	case models.SeverityMedium:
		return "Warning"
	default:
		return "Default"
	}
}
