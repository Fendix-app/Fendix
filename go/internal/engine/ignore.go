package engine

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"gopkg.in/yaml.v3"
)

// IgnoreFile represents the parsed .fendix-ignore YAML file.
type IgnoreFile struct {
	Ignore []IgnoreRule `yaml:"ignore"`
}

// IgnoreRule defines a single suppression rule. Exactly one of Fingerprint /
// ID / Endpoint / Category selects findings (checked in that precedence).
// Prefer Fingerprint: it is the run-stable content hash and, unlike ID
// (positional, drifts) or Endpoint+line (drifts when code above moves), keeps
// matching the same finding across scans.
type IgnoreRule struct {
	Fingerprint string `yaml:"fingerprint,omitempty"`
	ID          string `yaml:"id,omitempty"`
	Endpoint    string `yaml:"endpoint,omitempty"`
	Category    string `yaml:"category,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
	Until       string `yaml:"until,omitempty"` // optional expiry date YYYY-MM-DD
}

// ParseIgnoreFile reads and parses a .fendix-ignore YAML file.
func ParseIgnoreFile(path string) (*IgnoreFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ignore file %s: %w", path, err)
	}

	var ignoreFile IgnoreFile
	if err := yaml.Unmarshal(data, &ignoreFile); err != nil {
		return nil, fmt.Errorf("parsing ignore file %s: %w", path, err)
	}

	return &ignoreFile, nil
}

// ApplyIgnoreRules filters out findings that match any ignore rule.
// Expired rules (past their "until" date) are not applied.
func ApplyIgnoreRules(findings []models.Finding, rules []IgnoreRule) []models.Finding {
	if len(rules) == 0 {
		return findings
	}

	now := time.Now()
	var activeRules []IgnoreRule
	for _, r := range rules {
		if r.Until != "" {
			expiry, err := time.Parse("2006-01-02", r.Until)
			if err != nil {
				slog.Warn("invalid until date in ignore rule, skipping rule", "until", r.Until, "error", err)
				continue
			}
			if now.After(expiry) {
				slog.Info("ignore rule expired", "id", r.ID, "endpoint", r.Endpoint, "until", r.Until)
				continue
			}
		}
		activeRules = append(activeRules, r)
	}

	var result []models.Finding
	for _, f := range findings {
		if matchesIgnoreRule(f, activeRules) {
			slog.Info("suppressed finding", "id", f.ID, "title", f.Title, "rule_matched", true)
			continue
		}
		result = append(result, f)
	}

	suppressed := len(findings) - len(result)
	if suppressed > 0 {
		slog.Info("findings suppressed by ignore rules", "suppressed", suppressed, "remaining", len(result))
	}

	return result
}

// matchesIgnoreRule checks if a finding matches any of the ignore rules.
func matchesIgnoreRule(f models.Finding, rules []IgnoreRule) bool {
	for _, r := range rules {
		if matchesSingleRule(f, r) {
			return true
		}
	}
	return false
}

// matchesSingleRule checks if a finding matches a specific ignore rule.
func matchesSingleRule(f models.Finding, r IgnoreRule) bool {
	// Rule by fingerprint: exact match on the run-stable content hash.
	// Highest precedence — it's the most specific and the only key that
	// doesn't drift between scans. Compare against the finding's stamped
	// Fingerprint, falling back to recomputing it so a rule still matches
	// when fed findings that predate the stamping step.
	if r.Fingerprint != "" {
		fp := f.Fingerprint
		if fp == "" {
			fp = models.Fingerprint(f)
		}
		return strings.EqualFold(f.Fingerprint, r.Fingerprint) || strings.EqualFold(fp, r.Fingerprint)
	}

	// Rule by ID: exact match
	if r.ID != "" {
		return f.ID == r.ID
	}

	// Rule by endpoint (with optional category)
	if r.Endpoint != "" {
		if !endpointMatchesPattern(f.Endpoint, r.Endpoint) {
			return false
		}
		// If category is also specified, both must match
		if r.Category != "" {
			return strings.EqualFold(f.Category, r.Category)
		}
		return true
	}

	// Rule by category only
	if r.Category != "" {
		return strings.EqualFold(f.Category, r.Category)
	}

	return false
}

// endpointMatchesPattern checks if an endpoint matches an ignore pattern.
// Supports: exact match, "METHOD /path" format, and glob patterns with *.
func endpointMatchesPattern(endpoint, pattern string) bool {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	// Exact match
	if endpoint == pattern {
		return true
	}

	// Extract path from full URL for comparison
	endpointPath := normalizeEndpoint(endpoint)

	// Pattern may be "METHOD /path" or just "/path"
	patternParts := strings.SplitN(pattern, " ", 2)
	patternPath := pattern
	if len(patternParts) == 2 {
		patternPath = patternParts[1]
	}

	// Glob matching with * wildcard
	if strings.Contains(patternPath, "*") {
		return globMatch(endpointPath, patternPath)
	}

	// Exact path match
	return endpointPath == strings.ToLower(strings.TrimRight(patternPath, "/"))
}

// globMatch performs a simple glob pattern match where * matches any sequence of characters
// within a single path segment, and ** is not supported (use * at end for prefix matching).
func globMatch(s, pattern string) bool {
	// Handle trailing /* as prefix match
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(s, prefix+"/") || s == prefix
	}

	// Handle trailing * as prefix match
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(s, prefix)
	}

	// Simple case: no wildcards
	if !strings.Contains(pattern, "*") {
		return s == pattern
	}

	// General glob: split on * and match segments
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[pos:], part)
		if idx == -1 {
			return false
		}
		if i == 0 && idx != 0 {
			// First segment must match at start
			return false
		}
		pos += idx + len(part)
	}
	// If pattern ends with *, remaining string is ok
	if strings.HasSuffix(pattern, "*") {
		return true
	}
	return pos == len(s)
}
