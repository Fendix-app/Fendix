// Package diagnostic builds a redacted bug-report tarball that captures the
// runtime state of a single fendix scan: scan config, environment versions,
// probe audit log, buffered DEBUG slog stream, and resulting findings.
//
// The bundle is written when --debug-bundle is set on the scan command. All
// known credential surfaces — auth header values, env-var auth secrets,
// profile-loaded credentials — are replaced with [REDACTED] before they enter
// the tarball. The bundle is intended to be safe to share with maintainers
// when filing a bug report.
package diagnostic

import (
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// redactSecrets returns text with every non-empty secret string replaced by
// [REDACTED]. Skips empty strings so an unset auth doesn't no-op-replace
// every empty substring.
func redactSecrets(text string, secrets []string) string {
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			text = strings.ReplaceAll(text, s, "[REDACTED]")
		}
	}
	return text
}

// secretsFrom collects every credential surface from the scan config that
// must not appear in cleartext anywhere in the bundle. Includes the auth
// value, the bare token (without "Bearer "/"Basic " prefix), and the same
// for the second user's auth used by IDOR checks.
func secretsFrom(cfg *models.ScanConfig) []string {
	var secrets []string
	addAuth := func(a *models.AuthContext) {
		if a == nil || a.Value == "" {
			return
		}
		secrets = append(secrets, a.Value)
		if stripped := strings.TrimPrefix(a.Value, "Bearer "); stripped != a.Value {
			secrets = append(secrets, stripped)
		}
		if stripped := strings.TrimPrefix(a.Value, "Basic "); stripped != a.Value {
			secrets = append(secrets, stripped)
		}
	}
	if cfg != nil {
		addAuth(cfg.Auth)
		addAuth(cfg.AuthUser2)
	}
	return secrets
}

// redactedConfig returns a JSON-friendly representation of the scan config
// with credential fields masked. Auth/AuthUser2 values are shown as
// [REDACTED] when present so the operator can see the auth scheme + header
// used (helpful for debugging) without leaking the secret.
type redactedConfig struct {
	URL                  string        `json:"url,omitempty"`
	SpecPath             string        `json:"spec_path,omitempty"`
	CodePath             string        `json:"code_path,omitempty"`
	Auth                 *redactedAuth `json:"auth,omitempty"`
	AuthUser2            *redactedAuth `json:"auth_user2,omitempty"`
	EnableActive         bool          `json:"enable_active"`
	MaxProbesPerEndpoint int           `json:"max_probes_per_endpoint,omitempty"`
	Workers              int           `json:"workers,omitempty"`
	Timeout              int           `json:"timeout_seconds,omitempty"`
	DelayMs              int           `json:"delay_ms,omitempty"`
	Verbose              bool          `json:"verbose"`
	IgnorePath           string        `json:"ignore_path,omitempty"`
	BaselinePath         string        `json:"baseline_path,omitempty"`
	SaveBaselinePath     string        `json:"save_baseline_path,omitempty"`
	OutputPath           string        `json:"output_path,omitempty"`
	Format               string        `json:"format,omitempty"`
	FailOn               string        `json:"fail_on,omitempty"`
	WordlistPath         string        `json:"wordlist_path,omitempty"`
	CrawlDepth           int           `json:"crawl_depth,omitempty"`
	MaxEndpoints         int           `json:"max_endpoints,omitempty"`
	MaxRequests          int64         `json:"max_requests,omitempty"`
	MaxDuration          string        `json:"max_duration,omitempty"`
	RespectRobots        bool          `json:"respect_robots"`
}

// redactedAuth is the bundle-safe view of AuthContext: the auth scheme and
// the header name are kept, but the credential value is replaced with the
// fixed string [REDACTED] so the original secret can never leak even via
// a JSON serialization mistake.
type redactedAuth struct {
	Type   string `json:"type,omitempty"`
	Header string `json:"header,omitempty"`
	Value  string `json:"value"` // always "[REDACTED]" or ""
}

func redactAuth(a *models.AuthContext) *redactedAuth {
	if a == nil {
		return nil
	}
	out := &redactedAuth{
		Type:   a.Type,
		Header: a.Header,
	}
	if a.Value != "" {
		out.Value = "[REDACTED]"
	}
	return out
}

func newRedactedConfig(cfg *models.ScanConfig) *redactedConfig {
	if cfg == nil {
		return nil
	}
	rc := &redactedConfig{
		URL:                  cfg.URL,
		SpecPath:             cfg.SpecPath,
		CodePath:             cfg.CodePath,
		Auth:                 redactAuth(cfg.Auth),
		AuthUser2:            redactAuth(cfg.AuthUser2),
		EnableActive:         cfg.EnableActive,
		MaxProbesPerEndpoint: cfg.MaxProbesPerEndpoint,
		Workers:              cfg.Workers,
		Timeout:              cfg.Timeout,
		DelayMs:              cfg.DelayMs,
		Verbose:              cfg.Verbose,
		IgnorePath:           cfg.IgnorePath,
		BaselinePath:         cfg.BaselinePath,
		SaveBaselinePath:     cfg.SaveBaselinePath,
		OutputPath:           cfg.OutputPath,
		Format:               cfg.Format,
		FailOn:               cfg.FailOn,
		WordlistPath:         cfg.WordlistPath,
		CrawlDepth:           cfg.CrawlDepth,
		MaxEndpoints:         cfg.MaxEndpoints,
		MaxRequests:          cfg.MaxRequests,
		RespectRobots:        cfg.RespectRobots,
	}
	if cfg.MaxDuration > 0 {
		rc.MaxDuration = cfg.MaxDuration.String()
	}
	return rc
}
