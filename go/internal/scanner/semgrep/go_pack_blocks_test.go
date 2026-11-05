package semgrep

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Semgrep rejects YAML anchors in rule files, so the Go pack repeats its
// shared blocks in every rule that uses them: the request sources and the
// taint options in each of the nine taint rules, the numeric sanitizers in
// seven of them, the call sanitizers (the constant-helper shapes, and the
// shared part of the qualified-call sanitizer), Go test-code paths in all
// nineteen rules, and each helper sink once per argument position. These
// tests hold the copies to one another, so an edit to one copy cannot
// silently leave the others behind.

// goPackRules returns the bundled Go rules in pack order.
func goPackRules(t *testing.T) []packRule {
	t.Helper()
	var out []packRule
	for _, name := range []string{"go-injection.yaml", "go-web.yaml", "go-crypto.yaml"} {
		data, err := embeddedRules.ReadFile("rules/" + name)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := decodePack(data)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		out = append(out, rules...)
	}
	return out
}

// goNumericSanitizers marks the shared numeric block: it starts at the
// strconv.Atoi sanitizer and ends at strconv.FormatBool.
const (
	goNumericFirst = "strconv.Atoi(...)"
	goNumericLast  = "strconv.FormatBool(...)"
)

// goHelperPositionPrefixes are what makes the second and third argument
// position's copy of a helper sink differ from the first's.
var goHelperPositionPrefixes = []string{"$A1 $T1, $A2 $T2, ", "$A1 $T1, ", "$X1, $X2, ", "$X1, "}

func asYAML(v any) string {
	out, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unmarshalable: %v>", err)
	}
	return string(out)
}

func patternOf(entry any) string {
	m, _ := entry.(map[string]any)
	s, _ := m["pattern"].(string)
	return s
}

// numericBlock returns the shared numeric sanitizers of a taint rule, or nil.
func numericBlock(sanitizers []any) []any {
	start, end := -1, -1
	for i, s := range sanitizers {
		switch patternOf(s) {
		case goNumericFirst:
			start = i
		case goNumericLast:
			end = i
		}
	}
	if start < 0 || end < start {
		return nil
	}
	// The block opens with the numeric-Sprintf entry just before Atoi.
	if start > 0 && strings.Contains(asYAML(sanitizers[start-1]), "$NUMERICFORMAT") {
		start--
	}
	return sanitizers[start : end+1]
}

// isAssignmentCallSanitizer tells the assignment form of the qualified-call
// sanitizer (a call assigned to a variable, matched through
// metavariable-pattern) from its call form.
func isAssignmentCallSanitizer(m map[string]any) bool {
	return strings.Contains(asYAML(m["patterns"]), "metavariable-pattern") &&
		strings.Contains(asYAML(m["patterns"]), "$OUTER(")
}

// isQualifiedCallSanitizer tells the call form of the sanitizer for qualified
// and method calls (the only call sanitizer that carries a rule's own sinks)
// from the others.
func isQualifiedCallSanitizer(m map[string]any) bool {
	return !isAssignmentCallSanitizer(m) && strings.Contains(asYAML(m["patterns"]), "$OUTER(")
}

// callSanitizers are the parts of a taint rule's call sanitizers that every
// rule shares: the constant-helper sanitizers (len and cap, and the function
// and method shapes whose every return is constant, each also as the right-hand
// side of an assignment), and, of the qualified-call sanitizer, the sources
// and the calls that hand their input back (up to and including the
// function-literal exclusion) and the same-file-method exclusions at its end,
// for the call form and for the assignment form. A rule's own sinks are left
// out.
type callSanitizers struct {
	constant, prefix, methods             []any
	assignPrefix, assignMethods           []any
	hasConstant, hasPrefix, hasAssignment bool
}

func callSanitizerShared(sanitizers []any) callSanitizers {
	var out callSanitizers
	for _, s := range sanitizers {
		m, _ := s.(map[string]any)
		if exact, _ := m["exact"].(bool); !exact {
			continue
		}
		patterns, _ := m["patterns"].([]any)
		switch {
		case isAssignmentCallSanitizer(m):
			for i, p := range patterns {
				if mvp, ok := p.(map[string]any)["metavariable-pattern"].(map[string]any); ok {
					// The forms, then the conditions on the call up to and
					// including the function-literal exclusion.
					inner, _ := mvp["patterns"].([]any)
					out.assignPrefix = append([]any{}, patterns[:i]...)
					out.assignPrefix = append(out.assignPrefix, mvp["metavariable"])
					for j, q := range inner {
						if strings.Contains(asYAML(q), "$OUTER(") {
							out.assignPrefix = append(out.assignPrefix, inner[:j+1]...)
						}
					}
				}
				if strings.Contains(asYAML(p), "$RTYPE") {
					out.assignMethods = append(out.assignMethods, p)
				}
			}
		case isQualifiedCallSanitizer(m):
			for i, p := range patterns {
				if strings.Contains(asYAML(p), "$OUTER(") {
					out.prefix = patterns[:i+1]
				}
				if strings.Contains(asYAML(p), "$RTYPE") {
					out.methods = append(out.methods, p)
				}
			}
		default:
			out.constant = append(out.constant, s)
		}
	}
	out.hasConstant = out.constant != nil
	out.hasPrefix = out.prefix != nil && out.methods != nil
	out.hasAssignment = out.assignPrefix != nil && out.assignMethods != nil
	return out
}

// helperSinkGroups returns a taint rule's helper sinks, normalised for their
// argument position and grouped in threes (first, second, third argument).
func helperSinkGroups(sinks []any) [][]string {
	var flat []string
	for _, s := range sinks {
		text := asYAML(s)
		if !strings.Contains(text, "pattern: $HELPER(") {
			continue
		}
		for _, p := range goHelperPositionPrefixes {
			text = strings.ReplaceAll(text, p, "")
		}
		flat = append(flat, text)
	}
	var groups [][]string
	for i := 0; i < len(flat); i += 3 {
		end := i + 3
		if end > len(flat) {
			end = len(flat)
		}
		groups = append(groups, flat[i:end])
	}
	return groups
}

// goPackDrift returns every way the Go pack's repeated blocks differ from
// one another; none when the copies agree.
func goPackDrift(rules []packRule) []string {
	var out []string
	var first *packRule
	var numeric []any
	var calls *callSanitizers
	numericRules := 0
	for i := range rules {
		r := &rules[i]
		if paths := r.Raw["paths"]; !reflect.DeepEqual(paths, rules[0].Raw["paths"]) {
			out = append(out, fmt.Sprintf("%s: paths differ from %s's", r.ID, rules[0].ID))
		}
		if r.Raw["mode"] != "taint" {
			continue
		}
		if first == nil {
			first = r
		}
		for _, key := range []string{"pattern-sources", "options", "pattern-propagators"} {
			if !reflect.DeepEqual(r.Raw[key], first.Raw[key]) {
				out = append(out, fmt.Sprintf("%s: %s differ from %s's", r.ID, key, first.ID))
			}
		}
		sanitizers, _ := r.Raw["pattern-sanitizers"].([]any)
		if block := numericBlock(sanitizers); block != nil {
			numericRules++
			if numeric == nil {
				numeric = block
			} else if !reflect.DeepEqual(block, numeric) {
				out = append(out, fmt.Sprintf("%s: numeric sanitizers differ", r.ID))
			}
		}
		shared := callSanitizerShared(sanitizers)
		switch {
		case !shared.hasConstant || !shared.hasPrefix:
			out = append(out, fmt.Sprintf("%s: no call sanitizer", r.ID))
		case !shared.hasAssignment:
			out = append(out, fmt.Sprintf("%s: no assignment form of the call sanitizer", r.ID))
		case calls == nil:
			calls = &shared
		default:
			if !reflect.DeepEqual(shared.constant, calls.constant) {
				out = append(out, fmt.Sprintf("%s: call sanitizer's constant-helper shapes differ", r.ID))
			}
			if !reflect.DeepEqual(shared.prefix, calls.prefix) {
				out = append(out, fmt.Sprintf("%s: call sanitizer's shared part differs", r.ID))
			}
			if !reflect.DeepEqual(shared.methods, calls.methods) {
				out = append(out, fmt.Sprintf("%s: call sanitizer's same-file-method exclusions differ", r.ID))
			}
			if !reflect.DeepEqual(shared.assignPrefix, calls.assignPrefix) {
				out = append(out, fmt.Sprintf("%s: assignment sanitizer's shared part differs", r.ID))
			}
			if !reflect.DeepEqual(shared.assignMethods, calls.assignMethods) {
				out = append(out, fmt.Sprintf("%s: assignment sanitizer's same-file-method exclusions differ", r.ID))
			}
		}
		sinks, _ := r.Raw["pattern-sinks"].([]any)
		groups := helperSinkGroups(sinks)
		if len(groups) == 0 {
			out = append(out, fmt.Sprintf("%s: no helper sinks", r.ID))
		}
		for g, group := range groups {
			if len(group) != 3 {
				out = append(out, fmt.Sprintf("%s: helper sink group %d has %d positions, want 3", r.ID, g, len(group)))
				continue
			}
			for pos := 1; pos < 3; pos++ {
				if group[pos] != group[0] {
					out = append(out, fmt.Sprintf("%s: helper sink group %d, position %d differs from position 1", r.ID, g, pos+1))
				}
			}
		}
	}
	if numericRules != 7 {
		out = append(out, fmt.Sprintf("%d taint rules carry the numeric sanitizers, want 7", numericRules))
	}
	sort.Strings(out)
	return out
}

func TestGoTaintRulesShareTheirBlocks(t *testing.T) {
	rules := goPackRules(t)
	if len(rules) != 19 {
		t.Fatalf("the Go pack has %d rules, want 19", len(rules))
	}
	for _, d := range goPackDrift(rules) {
		t.Error(d)
	}
}

// Each kind of drift is caught: an edited copy of each repeated block.
func TestGoPackDriftIsCaught(t *testing.T) {
	// clone deep-copies the decoded pack through YAML, so a mutation touches
	// only the copy.
	clone := func(t *testing.T) []packRule {
		t.Helper()
		rules := goPackRules(t)
		out := make([]packRule, len(rules))
		for i, r := range rules {
			var raw map[string]any
			if err := yaml.Unmarshal([]byte(asYAML(r.Raw)), &raw); err != nil {
				t.Fatal(err)
			}
			out[i] = packRule{ID: r.ID, Raw: raw}
		}
		return out
	}
	taintRule := func(rules []packRule, id string) map[string]any {
		for _, r := range rules {
			if r.ID == id {
				return r.Raw
			}
		}
		t.Fatalf("no rule %s", id)
		return nil
	}
	cases := []struct {
		name   string
		mutate func(rules []packRule)
		want   string
	}{
		{"a source", func(rules []packRule) {
			src := taintRule(rules, "go-xss-taint")["pattern-sources"].([]any)
			src[0] = map[string]any{"pattern": "$R.URL.Query().Get(...)"}
		}, "go-xss-taint: pattern-sources differ"},
		{"an option", func(rules []packRule) {
			taintRule(rules, "go-cmdi-taint")["options"].(map[string]any)["taint_assume_safe_indexes"] = false
		}, "go-cmdi-taint: options differ"},
		{"a test-code path", func(rules []packRule) {
			paths := taintRule(rules, "go-weak-random-token")["paths"].(map[string]any)
			paths["exclude"] = paths["exclude"].([]any)[1:]
		}, "go-weak-random-token: paths differ"},
		{"a numeric sanitizer", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-ssrf-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); patternOf(m) == "strconv.ParseInt(...)" {
					m["pattern"] = "strconv.ParseInt($X, 10, 64)"
				}
			}
		}, "go-ssrf-taint: numeric sanitizers differ"},
		{"the call sanitizer's shared part", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-path-traversal-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); m["exact"] == true && isQualifiedCallSanitizer(m) {
					patterns := m["patterns"].([]any)
					m["patterns"] = append([]any{patterns[0]}, patterns[2:]...)
				}
			}
		}, "go-path-traversal-taint: call sanitizer's shared part differs"},
		{"a constant-helper shape", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-open-redirect-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); m["exact"] == true && !isQualifiedCallSanitizer(m) && m["patterns"] != nil {
					patterns := m["patterns"].([]any)
					if either, _ := patterns[1].(map[string]any)["pattern-either"].([]any); len(either) > 0 {
						patterns[1].(map[string]any)["pattern-either"] = either[1:]
						return
					}
				}
			}
			panic("no constant-helper map family to mutate")
		}, "go-open-redirect-taint: call sanitizer's constant-helper shapes differ"},
		{"the same-file-method exclusions", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-jwt-no-verify-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); m["exact"] == true && isQualifiedCallSanitizer(m) {
					patterns := m["patterns"].([]any)
					m["patterns"] = patterns[:len(patterns)-1]
				}
			}
		}, "go-jwt-no-verify-taint: call sanitizer's same-file-method exclusions differ"},
		{"the assignment sanitizer's shared part", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-ssrf-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); m["exact"] == true && isAssignmentCallSanitizer(m) {
					for _, p := range m["patterns"].([]any) {
						if mvp, ok := p.(map[string]any)["metavariable-pattern"].(map[string]any); ok {
							inner := mvp["patterns"].([]any)
							mvp["patterns"] = append([]any{inner[0]}, inner[2:]...)
						}
					}
				}
			}
		}, "go-ssrf-taint: assignment sanitizer's shared part differs"},
		{"the assignment sanitizer's same-file-method exclusions", func(rules []packRule) {
			for _, s := range taintRule(rules, "go-xss-taint")["pattern-sanitizers"].([]any) {
				if m, _ := s.(map[string]any); m["exact"] == true && isAssignmentCallSanitizer(m) {
					patterns := m["patterns"].([]any)
					m["patterns"] = patterns[:len(patterns)-1]
				}
			}
		}, "go-xss-taint: assignment sanitizer's same-file-method exclusions differ"},
		{"one position of a helper sink", func(rules []packRule) {
			sinks := taintRule(rules, "go-sqli-taint")["pattern-sinks"].([]any)
			for i := len(sinks) - 1; i >= 0; i-- {
				if strings.Contains(asYAML(sinks[i]), "pattern: $HELPER(") {
					m := sinks[i].(map[string]any)
					patterns := m["patterns"].([]any)
					m["patterns"] = patterns[1:]
					break
				}
			}
		}, "go-sqli-taint: helper sink group"},
	}
	if drift := goPackDrift(clone(t)); len(drift) != 0 {
		t.Fatalf("an unmutated pack drifts: %v", drift)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := clone(t)
			tc.mutate(rules)
			drift := goPackDrift(rules)
			if !strings.Contains(strings.Join(drift, "\n"), tc.want) {
				t.Errorf("drift = %q; want one containing %q", drift, tc.want)
			}
		})
	}
}
