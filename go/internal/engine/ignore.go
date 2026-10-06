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

// IgnoreRule defines a single suppression rule.
//
// Rules are applied to security OCCURRENCES before they are grouped into
// findings for presentation, so a rule suppresses exactly the occurrences it
// matches and nothing that merely shares their group. One selector decides,
// checked in this precedence:
//
//   - Fingerprint: the occurrence's fendix/v2 fingerprint (the `fingerprint`
//     of a single-location finding, or an `occurrences[].fingerprint` of a
//     grouped one). Exact, durable, occurrence-scoped. Preferred.
//   - ID: the positional SEC-NNN ID of the finding the occurrence is
//     presented in. GROUP-scoped and positional: it suppresses every
//     occurrence of that group, including ones added later, and it can name a
//     different finding after any change to the scan. Not for durable
//     suppression.
//   - Endpoint, optionally narrowed by Category: the occurrence's own path,
//     matched as described at endpointMatchesPattern / globMatch.
//   - Category alone: every occurrence in that category.
//
// When Fingerprint or ID is set, Endpoint and Category on the same rule are
// ignored (a warning is logged); write a separate rule instead.
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
//
// The orchestrator calls this with ungrouped occurrences (each carrying its own
// fingerprint and endpoint, and the positional ID of its presentation group),
// which is what makes every selector except `id` occurrence-scoped.
func ApplyIgnoreRules(findings []models.Finding, rules []IgnoreRule) []models.Finding {
	if len(rules) == 0 {
		return findings
	}

	now := time.Now()
	var activeRules []IgnoreRule
	for _, r := range rules {
		if (r.Fingerprint != "" || r.ID != "") && (r.Endpoint != "" || r.Category != "") {
			slog.Warn("ignore rule combines fingerprint/id with endpoint/category; only the fingerprint/id selector is used",
				"fingerprint", r.Fingerprint, "id", r.ID, "endpoint", r.Endpoint, "category", r.Category)
		}
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
			slog.Info("suppressed finding", "id", f.ID, "title", f.Title, "endpoint", f.Endpoint, "fingerprint", f.Fingerprint, "rule_matched", true)
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
//
// Both sides are compared case-insensitively. The endpoint is reduced to its
// path first (normalizeEndpoint): a source location "pkg/db.py:12" becomes
// "pkg/db.py" (the line is dropped), a URL "https://host/api/x?q=1" becomes
// "/api/x", and a leading HTTP method is dropped. A pattern of the form
// "METHOD /path" is compared on its path only — the method is NOT part of the
// match. A pattern without wildcards must equal the path (or, as a special
// case, the raw endpoint, so "pkg/db.py:12" still pins one line). A pattern
// with wildcards is matched by globMatch.
func endpointMatchesPattern(endpoint, pattern string) bool {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	// Exact match
	if endpoint == pattern {
		return true
	}

	// Extract path from full URL for comparison
	endpointPath := slashPath(normalizeEndpoint(endpoint))

	// Pattern may be "METHOD /path" or just "/path"
	patternParts := strings.SplitN(pattern, " ", 2)
	patternPath := pattern
	if len(patternParts) == 2 {
		patternPath = patternParts[1]
	}
	patternPath = slashPath(patternPath)

	// Glob matching with * wildcard
	if strings.Contains(patternPath, "*") {
		return globMatch(endpointPath, patternPath)
	}

	// Exact path match
	return endpointPath == strings.TrimRight(patternPath, "/")
}

// slashPath makes a path pattern or path separator-agnostic, so a rule written
// with Windows separators ("pkg\\tests\\**") matches the forward-slash paths
// every scanner emits.
func slashPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// globMatch reports whether path s matches pattern. Both are "/"-separated.
//
// Semantics (conventional path globbing, as in gitignore and doublestar):
//
//   - "**" as a whole path segment matches zero or more segments, so
//     "**/tests/**" matches "tests/helpers.py", "pkg/tests/helpers.py" and
//     "a/b/tests/c/d.py", and "pkg/**" matches "pkg" and everything below it.
//   - "*" matches any run of characters WITHIN one segment; it never crosses
//     "/". "src/*.py" matches "src/app.py" but not "src/sub/app.py".
//   - Every other character, "?" included, is literal. The match is anchored
//     at both ends.
//   - A wildcard pattern with no "/" matches a path segment at ANY depth, and
//     everything below a matching directory (the .gitignore convention):
//     "*.py" matches "a/b/c.py", and "*fixtures*" matches "pkg/fixtures/x.py".
//
// Two legacy forms keep their historical prefix meaning, because existing
// `.fendix-ignore` files depend on them. They apply only when the pattern's
// sole wildcard is one trailing "*":
//
//   - "dir/*" matches "dir" and everything below it, at any depth.
//   - "prefix*" matches any path that starts with "prefix".
func globMatch(s, pattern string) bool {
	if strings.Count(pattern, "*") == 1 && strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasSuffix(prefix, "/") {
			return s == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(s, prefix)
		}
		return strings.HasPrefix(s, prefix)
	}
	if !strings.Contains(pattern, "/") {
		return matchSegments([]string{"**", pattern, "**"}, strings.Split(s, "/"))
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(s, "/"))
}

// matchSegments matches pattern segments against path segments, with "**"
// standing for zero or more whole segments.
func matchSegments(p, s []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for len(p) > 1 && p[1] == "**" {
				p = p[1:]
			}
			if len(p) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchSegments(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 || !matchSegment(p[0], s[0]) {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

// matchSegment matches one segment, where each "*" (or run of them) matches
// any run of characters and everything else is literal.
func matchSegment(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}
	return len(s) >= len(last) && strings.HasSuffix(s, last)
}
