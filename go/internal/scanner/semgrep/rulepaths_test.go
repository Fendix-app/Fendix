package semgrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Decision D6' (redteam4-d6-03). The replaced TestPackFiltersComeFromTheEmbeddedRules
// pinned that every rule of a language skipped tests/, mock/, e2e and *.spec.*
// paths, which D6' forbids: first-party source is never out of scope by its
// path. The extracted packs now carry no paths.exclude.
func TestExtractedPacksCarryNoPathExcludes(t *testing.T) {
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	dir, release, err := acquireRules()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no extracted rules: %v", err)
	}
	rules := 0
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []struct {
				ID    string `yaml:"id"`
				Paths struct {
					Exclude []string `yaml:"exclude"`
				} `yaml:"paths"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		for _, r := range doc.Rules {
			rules++
			if len(r.Paths.Exclude) > 0 {
				t.Errorf("%s: rule %s still excludes %v", e.Name(), r.ID, r.Paths.Exclude)
			}
		}
	}
	// The embedded pack is unchanged: the filters were there to remove.
	found := false
	_ = filepathWalkEmbedded(func(data []byte) {
		if strings.Contains(string(data), "**/tests/**") {
			found = true
		}
	})
	if !found {
		t.Log("the embedded packs no longer carry test filters; stripping is then a no-op")
	}
	if rules == 0 {
		t.Fatal("no rules were read")
	}
}

func filepathWalkEmbedded(fn func([]byte)) error {
	entries, err := embeddedRules.ReadDir("rules")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if data, err := embeddedRules.ReadFile("rules/" + e.Name()); err == nil {
			fn(data)
		}
	}
	return nil
}

func TestStripPathExcludesKeepsIncludeAndTheRule(t *testing.T) {
	in := "rules:\n  - id: a\n    languages: [javascript]\n    severity: ERROR\n    message: m\n    pattern: f($X)\n    paths:\n      exclude:\n        - \"**/tests/**\"\n  - id: b\n    languages: [javascript]\n    severity: ERROR\n    message: m\n    pattern: g($X)\n    paths:\n      include:\n        - \"**/routes/**\"\n      exclude:\n        - \"**/mock/**\"\n  - id: c\n    languages: [go]\n    severity: ERROR\n    message: m\n    pattern: h($X)\n"
	out := string(stripPathExcludes([]byte(in)))
	if strings.Contains(out, "exclude") || strings.Contains(out, "**/tests/**") || strings.Contains(out, "**/mock/**") {
		t.Errorf("an exclude survived:\n%s", out)
	}
	if !strings.Contains(out, "**/routes/**") || !strings.Contains(out, "id: c") || !strings.Contains(out, "pattern: g($X)") {
		t.Errorf("stripping removed more than the excludes:\n%s", out)
	}
	if strings.Contains(out, "id: a") && strings.Contains(out, "paths:\n    exclude") {
		t.Errorf("an emptied paths mapping was kept:\n%s", out)
	}
	if got := stripPathExcludes([]byte("not: [valid")); string(got) != "not: [valid" {
		t.Errorf("an unparseable pack must be returned unchanged, got %q", got)
	}
	if got := stripPathExcludes([]byte(in[:strings.Index(in, "    paths:")])); !strings.Contains(string(got), "id: a") {
		t.Errorf("a pack with nothing to strip must be returned as is")
	}
}
