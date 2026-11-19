package semgrep

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// Decision D6' (redteam4-d6-03): a rule never skips a file because of where it
// is. The packs carried `paths.exclude` filters ("**/tests/**", "**/mock/**",
// "*_test.go", "*.spec.*" ...) that made every rule of a language skip test and
// fixture code, so a SQL injection in lib/mock/server.js or api/e2e/handler.js
// was never evaluated and the scan read complete. First-party source is in scope
// whatever it is called or wherever it sits. A finding in a test path is not
// hidden: the engine's confidence model already lowers one (the test-path
// de-escalation, deescalate_tests_wiring_test.go), so it arrives as a lower
// severity or a warning, never as a silent absence.
//
// stripPathExcludes removes the `paths.exclude` list of every rule of a pack
// when the pack is extracted for a run. `paths.include` is left alone: it
// narrows a rule to where it applies (a route file, say), which is the rule's
// meaning, not a statement that other code is out of scope. The embedded pack
// is unchanged, so the ruletests that read it directly still see the filters
// they pin.

// stripPathExcludes returns the pack's YAML with every rule's paths.exclude
// removed (and an emptied paths mapping with it). A pack that cannot be parsed
// is returned unchanged: it carries no filter this function can remove, and
// Semgrep reports the parse problem as the rule error it is.
func stripPathExcludes(data []byte) []byte {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return data
	}
	root := doc.Content[0]
	rules := mapValue(root, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return data
	}
	changed := false
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(rule.Content); i += 2 {
			if rule.Content[i].Value != "paths" || rule.Content[i+1].Kind != yaml.MappingNode {
				continue
			}
			paths := rule.Content[i+1]
			for j := 0; j+1 < len(paths.Content); j += 2 {
				if paths.Content[j].Value == "exclude" {
					paths.Content = append(paths.Content[:j], paths.Content[j+2:]...)
					changed = true
					break
				}
			}
			if len(paths.Content) == 0 {
				rule.Content = append(rule.Content[:i], rule.Content[i+2:]...)
			}
			break
		}
	}
	if !changed {
		return data
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil || enc.Close() != nil {
		return data
	}
	return buf.Bytes()
}

// mapValue is the value of key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
