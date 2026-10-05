package jira

import (
	"fmt"
	"os"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Environment variable names. Kept in one place so the CLI --help
// can reference them without divergence.
const (
	EnvURL         = "FENDIX_JIRA_URL"
	EnvProjectKey  = "FENDIX_JIRA_PROJECT_KEY"
	EnvEmail       = "FENDIX_JIRA_EMAIL"
	EnvAPIToken    = "FENDIX_JIRA_API_TOKEN"
	EnvMinSeverity = "FENDIX_JIRA_MIN_SEVERITY"
	EnvIssueType   = "FENDIX_JIRA_ISSUE_TYPE"
)

// NewFromEnv populates Config from environment variables and returns
// a ready Client. Used by the `fendix jira` CLI subcommand.
func NewFromEnv() (*Client, error) {
	cfg := Config{
		BaseURL:    os.Getenv(EnvURL),
		ProjectKey: os.Getenv(EnvProjectKey),
		Email:      os.Getenv(EnvEmail),
		APIToken:   os.Getenv(EnvAPIToken),
		IssueType:  os.Getenv(EnvIssueType),
	}
	if v := os.Getenv(EnvMinSeverity); v != "" {
		sev, err := parseSeverity(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvMinSeverity, err)
		}
		cfg.MinSeverity = sev
	}
	return NewClient(cfg)
}

// parseSeverity is case-insensitive. The error names the accepted
// set so user typos get a useful diagnostic.
func parseSeverity(s string) (models.Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
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
