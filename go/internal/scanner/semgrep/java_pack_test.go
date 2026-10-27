package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// javaGateRule is the Java taint rule the gate tests below go through.
const javaGateRule = "java-sqli-taint"

// productionCheckID is the check id semgrep reports for rule when it loads the
// pack from dir: semgrep namespaces a rule by the path it was read from, the
// path's separators becoming dots ("/tmp/fendix-semgrep-rules-1/x.yaml" gives
// "tmp.fendix-semgrep-rules-1.<rule>"). ensureRules writes the pack to
// os.MkdirTemp("", rulesDirPrefix), so this is the id the scanner really sees.
func productionCheckID(dir, rule string) string {
	return strings.ReplaceAll(strings.TrimPrefix(filepath.ToSlash(dir), "/"), "/", ".") + "." + rule
}

// javaTaintMatch is a match of javaGateRule as semgrep reports it, logged out:
// no trace and no lines.
func javaTaintMatch(checkID string) semgrepResult {
	return semgrepResult{
		CheckID: checkID,
		Path:    "/code/src/main/java/com/example/UserController.java",
		Start:   semgrepLineCol{Line: 21, Col: 37},
		Extra: semgrepExtra{
			Message:  "SQL query built from request input.",
			Severity: "ERROR",
			Lines:    semgrepRedactedLines,
			Metadata: map[string]interface{}{
				"category":            "injection",
				"cwe":                 "CWE-89",
				"confidence":          "MEDIUM",
				"fendix_severity":     "HIGH",
				"fendix_reachability": "taint",
			},
		},
	}
}

// The scanner never sees a bare rule id: every Java taint match arrives
// namespaced by the temporary directory the pack was extracted to, which
// normalizeCheckID strips before the gate looks the rule up in the embedded
// pack. If the strip or the lookup missed, every Java finding would stay a shim
// finding with Java enabled, and nothing else would fail. This walks the
// production-shaped ids (Linux and macOS temp roots, and the directory
// ensureRules really made on this machine) through mapResult with the gate
// closed and open.
func TestJavaTaintRuleFromAProductionCheckIDOpensTheGate(t *testing.T) {
	spec, ok := bundledRuleSpec(javaGateRule)
	if !ok || spec.Mode != "taint" || !reflect.DeepEqual(spec.Languages, []string{"java"}) {
		t.Fatalf("embedded pack: %s = %+v (found %v), want mode taint and languages [java]", javaGateRule, spec, ok)
	}

	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	if !strings.HasPrefix(filepath.Base(dir), rulesDirPrefix) {
		t.Fatalf("rules dir %q does not start with %q", dir, rulesDirPrefix)
	}

	for name, checkID := range map[string]string{
		"linux temp root":          "tmp." + rulesDirPrefix + "1072928901." + javaGateRule,
		"macOS temp root":          "var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T." + rulesDirPrefix + "2865129937." + javaGateRule,
		"this machine's rules dir": productionCheckID(dir, javaGateRule),
	} {
		t.Run(name, func(t *testing.T) {
			if got := normalizeCheckID(checkID); got != javaGateRule {
				t.Fatalf("normalizeCheckID(%q) = %q, want %q", checkID, got, javaGateRule)
			}
			r := javaTaintMatch(checkID)

			enableReachability(t)
			closed, ok := mapResult(&r, "/code")
			if !ok {
				t.Fatal("mapResult rejected the match")
			}
			requireShim(t, closed)

			enableReachability(t, "java")
			open, _ := mapResult(&r, "/code")
			requireTaint(t, open)
			if open.RuleID != javaGateRule || open.ID != "SEC-JAVA_SQLI_TAINT" {
				t.Errorf("RuleID = %q, ID = %q; want %q and SEC-JAVA_SQLI_TAINT", open.RuleID, open.ID, javaGateRule)
			}
			if models.Fingerprint(open.ToFinding()) != models.Fingerprint(closed.ToFinding()) {
				t.Error("opening the gate moved the finding's fingerprint")
			}
		})
	}
}

// javaGateApp is a Spring controller whose request parameter reaches a
// JdbcTemplate query in the same method.
const javaGateApp = `package com.example;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final JdbcTemplate jdbcTemplate;

    public UserController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/users")
    public List<Map<String, Object>> search(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
`

// The same gate end to end: real semgrep over the bundled pack, through Scan,
// so the check id is whatever semgrep makes of the real temporary directory.
func TestJavaTaintMatchFromRealSemgrepIsReachableOnlyWithJavaEnabled(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)

	root := t.TempDir()
	src := filepath.Join(root, "src", "main", "java", "com", "example", "UserController.java")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(javaGateApp), 0o644); err != nil {
		t.Fatal(err)
	}
	const endpoint = "src/main/java/com/example/UserController.java:22"

	scanFor := func(t *testing.T) evidence.Evidence {
		t.Helper()
		evs, err := Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		var got []evidence.Evidence
		for _, ev := range evs {
			if ev.RuleID == javaGateRule {
				got = append(got, ev)
			}
		}
		if len(got) != 1 {
			t.Fatalf("got %d %s findings, want 1 (all findings: %+v)", len(got), javaGateRule, evs)
		}
		if got[0].Endpoint != endpoint {
			t.Errorf("Endpoint = %q, want %q", got[0].Endpoint, endpoint)
		}
		return got[0]
	}

	t.Run("java disabled", func(t *testing.T) {
		enableReachability(t)
		requireShim(t, scanFor(t))
	})
	t.Run("java enabled", func(t *testing.T) {
		enableReachability(t, "java")
		requireTaint(t, scanFor(t))
	})
	// As the binary ships: Java has met the gate (ADR-011).
	t.Run("as shipped", func(t *testing.T) {
		requireTaint(t, scanFor(t))
	})
}

// The Java request-input packs repeat two blocks in every taint rule, because
// a Semgrep rule cannot reference another's: the request sources and the
// number sanitizers (see the header of rules/java-injection.yaml). An edit to
// one copy only would leave one class with different sources from the rest,
// which nothing else would catch.
func TestJavaTaintRulesShareTheirBlocks(t *testing.T) {
	var sources, numbers, names []string
	for _, pack := range []string{"rules/java-injection.yaml", "rules/java-web.yaml"} {
		data, err := embeddedRules.ReadFile(pack)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := decodePack(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.Raw["mode"] != "taint" {
				continue
			}
			names = append(names, r.ID)
			sources = append(sources, canonicalYAML(t, r.Raw["pattern-sources"]))
			sanitizers, _ := r.Raw["pattern-sanitizers"].([]any)
			if len(sanitizers) == 0 {
				t.Fatalf("%s: no pattern-sanitizers", r.ID)
			}
			numbers = append(numbers, canonicalYAML(t, sanitizers[0]))
		}
	}
	if len(names) != 7 {
		t.Fatalf("taint rules in the Java request-input packs = %v, want 7", names)
	}
	for name, copies := range map[string][]string{"pattern-sources": sources, "number sanitizers": numbers} {
		for i := range copies {
			if copies[i] != copies[0] {
				t.Errorf("%s of %s differ from %s's", name, names[i], names[0])
			}
		}
	}
}

// The -sink rules repeat blocks of their taint rule: java-sqli-sink the SQL
// call list and the Criteria exclusions of java-sqli-taint's sink, and
// java-ssrf-sink and java-open_redirect-sink the guards of their taint rule's
// sanitizers (as negations, on the method's parameter $Q). A fix that lands
// in one copy only would make the two rules disagree on what is safe.
func TestJavaSinkRulesShareTheirTaintRulesBlocks(t *testing.T) {
	rules := map[string]map[string]any{}
	for _, pack := range []string{"rules/java-injection.yaml", "rules/java-web.yaml"} {
		data, err := embeddedRules.ReadFile(pack)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodePack(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range decoded {
			rules[r.ID] = r.Raw
		}
	}

	// SQL: the sink's call list and exclusions, in both rules.
	sinks, _ := rules["java-sqli-taint"]["pattern-sinks"].([]any)
	if len(sinks) == 0 {
		t.Fatal("java-sqli-taint has no sinks")
	}
	taintSQL := sqlBlocks(t, sinks[0].(map[string]any)["patterns"].([]any))
	shapeSQL := sqlBlocks(t, rules["java-sqli-sink"]["patterns"].([]any))
	if taintSQL == "" || taintSQL != shapeSQL {
		t.Errorf("java-sqli-sink's SQL calls and exclusions differ from java-sqli-taint's:\n%s\nvs\n%s", shapeSQL, taintSQL)
	}

	// Guards: each guard of the taint rule is a negation of the -sink rule.
	for taint, shape := range map[string]string{
		"java-ssrf-taint":          "java-ssrf-sink",
		"java-open_redirect-taint": "java-open_redirect-sink",
	} {
		var sanitizerGuards []string
		sanitizers, _ := rules[taint]["pattern-sanitizers"].([]any)
		for _, s := range sanitizers {
			if g := guard(t, s, "patterns"); g != "" {
				sanitizerGuards = append(sanitizerGuards, g)
			}
		}
		var negationGuards []string
		for _, p := range rules[shape]["patterns"].([]any) {
			if not, ok := p.(map[string]any)["pattern-not"].(map[string]any); ok {
				if g := guard(t, not, "patterns"); g != "" {
					negationGuards = append(negationGuards, strings.ReplaceAll(g, "$Q", "$GV"))
				}
			}
		}
		if len(sanitizerGuards) == 0 || !reflect.DeepEqual(sanitizerGuards, negationGuards) {
			t.Errorf("%s's guards differ from %s's (%d vs %d):\n%s\nvs\n%s", shape, taint,
				len(negationGuards), len(sanitizerGuards), strings.Join(negationGuards, "---\n"), strings.Join(sanitizerGuards, "---\n"))
		}
	}
}

// sqlBlocks renders the SQL call list (the pattern-either naming JdbcTemplate)
// and the Criteria exclusions of a patterns list.
func sqlBlocks(t *testing.T, patterns []any) string {
	var out []string
	for _, p := range patterns {
		m := p.(map[string]any)
		if either, ok := m["pattern-either"]; ok && strings.Contains(canonicalYAML(t, either), "JdbcTemplate $DB") {
			out = append(out, canonicalYAML(t, either))
		}
		if not, ok := m["pattern-not"].(string); ok && strings.Contains(not, "createQuery") {
			out = append(out, not)
		}
	}
	return strings.Join(out, "\n")
}

// guard renders a guard (a patterns list checking metavariable $GCOND)
// without its occurrence: the sanitizer's `pattern: $GV` and its
// identifier regex, or the negation's sink shapes (the pattern-either that
// holds no pattern-inside).
func guard(t *testing.T, node any, key string) string {
	m, ok := node.(map[string]any)
	if !ok {
		return ""
	}
	patterns, ok := m[key].([]any)
	if !ok || !strings.Contains(canonicalYAML(t, patterns), "metavariable: $GCOND") {
		return ""
	}
	var kept []any
	for _, p := range patterns {
		pm := p.(map[string]any)
		if pm["pattern"] == "$GV" {
			continue
		}
		if mr, ok := pm["metavariable-regex"].(map[string]any); ok && mr["metavariable"] == "$GV" {
			continue
		}
		if either, ok := pm["pattern-either"]; ok && !strings.Contains(canonicalYAML(t, either), "pattern-inside") {
			continue
		}
		kept = append(kept, p)
	}
	return canonicalYAML(t, kept)
}

func canonicalYAML(t *testing.T, v any) string {
	t.Helper()
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
