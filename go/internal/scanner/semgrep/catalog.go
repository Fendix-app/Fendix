package semgrep

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// CatalogRule is the public contract metadata encoded in a bundled Semgrep
// rule. Pattern bodies stay private to the executable rule pack.
type CatalogRule struct {
	ID         string
	Pack       string
	Message    string
	Severity   string
	Confidence string
	Category   string
	CWEs       []string
	Languages  []string
}

type catalogRuleYAML struct {
	ID        string   `yaml:"id"`
	Message   string   `yaml:"message"`
	Severity  string   `yaml:"severity"`
	Languages []string `yaml:"languages"`
	Metadata  struct {
		Category       string      `yaml:"category"`
		CWE            interface{} `yaml:"cwe"`
		Confidence     string      `yaml:"confidence"`
		FendixSeverity string      `yaml:"fendix_severity"`
	} `yaml:"metadata"`
}

type catalogRuleFileYAML struct {
	Rules []catalogRuleYAML `yaml:"rules"`
}

// CatalogRules parses the embedded rule pack used by the scanner itself.
func CatalogRules() ([]CatalogRule, error) {
	var out []CatalogRule
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return err
		}
		var doc catalogRuleFileYAML
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, rule := range doc.Rules {
			out = append(out, CatalogRule{
				ID: rule.ID, Pack: filepath.Base(path[:len(path)-len(filepath.Ext(path))]),
				Message: rule.Message, Severity: rule.Metadata.FendixSeverity,
				Confidence: rule.Metadata.Confidence, Category: rule.Metadata.Category,
				CWEs: normalizeCatalogCWEs(rule.Metadata.CWE), Languages: rule.Languages,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pack == out[j].Pack {
			return out[i].ID < out[j].ID
		}
		return out[i].Pack < out[j].Pack
	})
	return out, nil
}

func normalizeCatalogCWEs(value interface{}) []string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return []string{}
		}
		return []string{typed}
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return []string{}
	}
}
