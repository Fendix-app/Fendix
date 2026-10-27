package semgrep

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// rulepackTotalCount is the count of bundled rules. When you add or
// remove a rule, update this constant in the same commit so the
// catalog test catches accidental rule deletion. v0.13.1 dropped the
// broken django-fbv-missing-auth-decorator rule (Sprint 18 review), and
// flask-missing-login-required went after v3.6.4 because it duplicated
// flask-route-no-auth-decorator on every Flask route (ADR-012). v3.7.0
// added python-random-token-assignment.
const rulepackTotalCount = 23

// rulepackFiles is the canonical list of embedded YAML rule files. The
// extraction tests (TestEnsureRules_ExtractsAllBundledFiles) assert this
// matches the disk layout. Add a new file here when you create one.
var rulepackFiles = []string{
	"auth.yaml",
	"injection.yaml",
	"secrets.yaml",
	"crypto.yaml",
}

// validFendixSeverityKeys is the set of values accepted in the
// metadata.fendix_severity rule field. Mirrors validFendixSeverities in
// scanner.go but as a string-only set since the YAML still holds strings.
var validFendixSeverityKeys = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
	"INFO":     true,
}

// validConfidenceKeys mirrors the values resolveConfidence in scanner.go
// recognises. A rule that ships a string outside this set silently
// defaults to MEDIUM, which is the wrong shape for a rule audit.
var validConfidenceKeys = map[string]bool{
	"HIGH":   true,
	"MEDIUM": true,
	"LOW":    true,
}

// ruleYAML is the subset of each rule's YAML we assert on. Unknown fields
// in real semgrep YAML (e.g. patterns, message) are ignored — this is a
// catalog audit, not a semgrep parser.
type ruleYAML struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Languages []any  `yaml:"languages"`
	Message   string `yaml:"message"`
	Metadata  struct {
		Category          string `yaml:"category"`
		CWE               any    `yaml:"cwe"` // string or []string per resolveCWE
		Confidence        string `yaml:"confidence"`
		FendixSeverity    string `yaml:"fendix_severity"`
		FendixTitle       string `yaml:"fendix_title"`
		FendixRemediation string `yaml:"fendix_remediation"`
	} `yaml:"metadata"`
}

type ruleFileYAML struct {
	Rules []ruleYAML `yaml:"rules"`
}

// loadAllRules walks the embedded FS, parses every YAML file, and returns
// every rule it finds keyed by ID. Duplicate IDs across files (or within
// one file) are reported as an error — semgrep merges rule packs by ID,
// so a duplicate is a silent override.
func loadAllRules(t *testing.T) map[string]ruleYAML {
	t.Helper()
	out := make(map[string]ruleYAML)
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var doc ruleFileYAML
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, r := range doc.Rules {
			if r.ID == "" {
				t.Errorf("%s: rule with empty id", path)
				continue
			}
			if existing, ok := out[r.ID]; ok {
				t.Errorf("duplicate rule id %q (also in %v)", r.ID, existing)
				continue
			}
			out[r.ID] = r
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func TestRulepack_TotalCountMatchesConstant(t *testing.T) {
	rules := loadAllRules(t)
	if len(rules) != rulepackTotalCount {
		ids := make([]string, 0, len(rules))
		for id := range rules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("rulepack has %d rules; rulepackTotalCount = %d. IDs: %s",
			len(rules), rulepackTotalCount, strings.Join(ids, ", "))
	}
}

// semgrepMetavariable matches a metavariable Semgrep fills in at match time
// ($FUNC, $...ARGS). Rule messages may use them; published copy may not.
var semgrepMetavariable = regexp.MustCompile(`\$(?:\.\.\.)?[A-Z_][A-Z0-9_]*\b`)

// TestRulepack_MetavariableMessagesHaveStaticCopy requires every rule whose
// runtime message interpolates a metavariable to ship placeholder-free
// metadata.fendix_title and fendix_remediation. The public security catalog
// prints those instead of the raw message (v3.6.3: eleven rules published
// '$VAR', '$FUNC' and similar on the documentation site).
func TestRulepack_MetavariableMessagesHaveStaticCopy(t *testing.T) {
	for id, r := range loadAllRules(t) {
		if !semgrepMetavariable.MatchString(r.Message) {
			continue
		}
		for field, value := range map[string]string{"fendix_title": r.Metadata.FendixTitle, "fendix_remediation": r.Metadata.FendixRemediation} {
			if strings.TrimSpace(value) == "" {
				t.Errorf("rule %q: message interpolates %v but metadata.%s is empty", id, semgrepMetavariable.FindAllString(r.Message, -1), field)
			} else if token := semgrepMetavariable.FindString(value); token != "" {
				t.Errorf("rule %q: metadata.%s carries metavariable %q; static copy must read without interpolation", id, field, token)
			}
		}
	}
}

func TestRulepack_EveryRuleHasFendixSeverity(t *testing.T) {
	for id, r := range loadAllRules(t) {
		got := strings.ToUpper(r.Metadata.FendixSeverity)
		if !validFendixSeverityKeys[got] {
			t.Errorf("rule %q: metadata.fendix_severity = %q; want one of CRITICAL/HIGH/MEDIUM/LOW/INFO",
				id, r.Metadata.FendixSeverity)
		}
	}
}

func TestRulepack_EveryRuleHasCategory(t *testing.T) {
	for id, r := range loadAllRules(t) {
		if strings.TrimSpace(r.Metadata.Category) == "" {
			t.Errorf("rule %q: metadata.category is empty", id)
		}
	}
}

func TestRulepack_EveryRuleHasCWE(t *testing.T) {
	for id, r := range loadAllRules(t) {
		switch v := r.Metadata.CWE.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				t.Errorf("rule %q: metadata.cwe is empty string", id)
			}
		case []any:
			if len(v) == 0 {
				t.Errorf("rule %q: metadata.cwe is empty list", id)
			}
		case nil:
			t.Errorf("rule %q: metadata.cwe is absent", id)
		default:
			t.Errorf("rule %q: metadata.cwe has unexpected type %T", id, v)
		}
	}
}

func TestRulepack_EveryRuleHasValidConfidence(t *testing.T) {
	for id, r := range loadAllRules(t) {
		got := strings.ToUpper(r.Metadata.Confidence)
		if !validConfidenceKeys[got] {
			t.Errorf("rule %q: metadata.confidence = %q; want HIGH/MEDIUM/LOW",
				id, r.Metadata.Confidence)
		}
	}
}

func TestRulepack_EveryRuleHasLanguage(t *testing.T) {
	for id, r := range loadAllRules(t) {
		if len(r.Languages) == 0 {
			t.Errorf("rule %q: languages list is empty", id)
		}
	}
}

func TestRulepack_LowConfidenceCappedAtMediumSeverity(t *testing.T) {
	// Mirrors the consistency rule in docs/semgrep-rules.md:
	// "a finding with confidence: LOW cannot have severity higher than
	// MEDIUM. The orchestrator will downgrade and warn."
	// At write time the rule is enforced at the orchestrator layer, not in
	// the rule pack — but a rule that ships with LOW+HIGH is shipping a
	// finding that will be silently downgraded, which is a docs-drift bug
	// of its own. Catch it here.
	rank := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for id, r := range loadAllRules(t) {
		conf := strings.ToUpper(r.Metadata.Confidence)
		sev := strings.ToUpper(r.Metadata.FendixSeverity)
		if conf == "LOW" && rank[sev] > rank["MEDIUM"] {
			t.Errorf("rule %q: confidence=LOW but fendix_severity=%s. "+
				"Downgrade severity or raise confidence — the orchestrator "+
				"will downgrade this to MEDIUM anyway.", id, sev)
		}
	}
}

// TestRulepack_ValidatesViaSemgrepCLI invokes `semgrep --validate` against
// the bundled rules. Skipped when semgrep is not on PATH (the common dev
// case + CI runners without semgrep installed). Catches pattern-syntax
// errors the YAML-only catalog tests above can't see — e.g. a malformed
// pattern-either body or a metavariable-regex with invalid Go regex syntax.
func TestRulepack_ValidatesViaSemgrepCLI(t *testing.T) {
	bin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not on PATH; skipping --validate check")
	}
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	for _, name := range rulepackFiles {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(bin, "--validate", "--config", filepath.Join(dir, name))
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("semgrep --validate %s failed: %v\noutput:\n%s",
					name, err, string(out))
			}
		})
	}
}

// TestFlaskRouteReportedOnce pins that an unprotected Flask route yields one
// missing-auth finding. flask-missing-login-required and
// flask-route-no-auth-decorator both fired on every such route, so each one
// was reported twice; the first was removed (ADR-012). It runs the real
// pipeline (bundled rule pack, semgrep, mapResult) and counts every auth
// finding, so any rule that reports the same route again fails it.
func TestFlaskRouteReportedOnce(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()

	cases := []struct {
		name string
		body string
		line string // where the finding is reported: the @app.route(...) line
	}{
		{
			name: "no auth decorator",
			body: "from flask import Flask\napp = Flask(__name__)\n\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n",
			line: "views.py:4",
		},
		{
			name: "auth decorator above the route",
			body: "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@login_required\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n",
			line: "views.py:6",
		},
		{
			// The pattern-inside matches both functions; only the inner
			// one's decorator sits above its route.
			name: "inside a protected route",
			body: "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@app.route(\"/outer\")\n@login_required\ndef outer():\n    @login_required\n    @app.route(\"/inner\")\n    def inner():\n        return \"x\"\n    return \"y\"\n",
			line: "views.py:9",
		},
		{
			// The regex can start on the docstring's "@login_required" line;
			// only the first branch may report this public route.
			name: "after a module docstring that names a decorator",
			body: "\"\"\"Admin views.\n\nEvery admin view must put\n\n    @login_required\n\nbelow its route.\n\"\"\"\nfrom flask import Flask\napp = Flask(__name__)\n\n@app.route(\"/health\")\ndef health():\n    return \"ok\"\n",
			line: "views.py:12",
		},
		{
			name: "beside a protected route, decorator above",
			body: "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@app.route(\"/a\")\n@login_required\ndef a_view():\n    return \"a\"\n\n@login_required\n@app.route(\"/b\")\ndef b_view():\n    return \"b\"\n",
			line: "views.py:11",
		},
		{
			name: "beside a protected route",
			body: "from flask import Flask\nfrom flask_login import login_required\napp = Flask(__name__)\n\n@app.route(\"/account\")\n@login_required\ndef account():\n    return \"mine\"\n\n@app.route(\"/admin\")\ndef admin_view():\n    return \"secret\"\n",
			line: "views.py:10",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "views.py"), []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var auth []string
			for _, f := range got {
				if f.Category == "auth" {
					auth = append(auth, f.RuleID+" at "+f.Endpoint)
				}
			}
			want := "flask-route-no-auth-decorator at " + tc.line
			if len(auth) != 1 || auth[0] != want {
				t.Errorf("auth findings = %v; want exactly [%s]", auth, want)
			}
		})
	}
}

// --- The rule-metadata contract (Task 4.2) -----------------------------------
//
// Every bundled rule, old or new, carries the metadata below. Tasks that add a
// pack (JavaScript/TypeScript, Java, Go) write to this contract; the test is
// what holds them to it.

// fendixCategories is the closed set of categories a bundled rule may declare.
// CollapseDuplicateLocations keys on (Category, Endpoint), so a new category
// such as "ssrf" would never collapse with textscan's JAVA_SSRF (category
// injection) on the same line. SSRF, path traversal, open redirect and SSTI
// are injection.
var fendixCategories = map[string]bool{"injection": true, "xss": true, "crypto": true, "auth": true, "secrets": true}

// ruleLanguages is the set of languages a bundled rule may target, by the
// canonical Semgrep names ReachabilityLanguages is keyed by.
var ruleLanguages = map[string]bool{"python": true, "javascript": true, "typescript": true, "java": true, "go": true}

// ruleIDLanguage maps the <lang> of a `<lang>-<class>-taint` or
// `<lang>-<class>-sink` rule id to the language it names.
var ruleIDLanguage = map[string]string{
	"python": "python", "javascript": "javascript", "js": "javascript",
	"typescript": "typescript", "ts": "typescript", "java": "java", "go": "go",
}

// conventionalRuleID matches `<lang>-<class>-taint` and `<lang>-<class>-sink`.
var conventionalRuleID = regexp.MustCompile(`^([a-z]+)-([a-z0-9]+(?:[-_][a-z0-9]+)*)-(taint|sink)$`)

var cweID = regexp.MustCompile(`^CWE-[0-9]+$`)

// sinkConstantExclusions is, per language, what a `-sink` rule's
// pattern-not-inside clauses must name: the constant bindings whose
// interpolation is not input. The corpus lookalikes are the same sink with a
// module constant (execAsync(`du -sh ${LOG_DIR}`), fmt.Sprintf("... %s",
// activeUsersTable)); they are true negatives today, and a shape rule that
// reported them would turn them into false positives.
var sinkConstantExclusions = map[string][]*regexp.Regexp{
	"javascript": {regexp.MustCompile(`\bconst\s+\$[A-Z_][A-Z0-9_]*\s*=`)},
	"typescript": {regexp.MustCompile(`\bconst\s+\$[A-Z_][A-Z0-9_]*\s*=`)},
	"java":       {regexp.MustCompile(`\bstatic\s+final\s+\w+\s+\$[A-Z_][A-Z0-9_]*\s*=`)},
	"go":         {regexp.MustCompile(`\bconst\s+\$[A-Z_][A-Z0-9_]*\s*=`), regexp.MustCompile(`\bconst\s*\(`)},
}

// ruleContractViolations returns every way one rule, decoded from YAML,
// breaks the metadata contract; none for a rule that keeps it.
func ruleContractViolations(rule map[string]any) []string {
	var out []string
	bad := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	id, _ := rule["id"].(string)
	if id == "" {
		bad("no id")
	}
	mode, _ := rule["mode"].(string)
	taint := mode == "taint"

	langs, _ := rule["languages"].([]any)
	declared := map[string]bool{}
	if len(langs) == 0 {
		bad("languages is empty")
	}
	for _, l := range langs {
		name, _ := l.(string)
		if !ruleLanguages[name] {
			bad("language %q is not one of python, javascript, typescript, java, go", l)
		}
		declared[name] = true
	}

	meta, _ := rule["metadata"].(map[string]any)
	str := func(key string) string { v, _ := meta[key].(string); return v }
	if c := str("category"); !fendixCategories[c] {
		bad("metadata.category %q is not one of injection, xss, crypto, auth, secrets", c)
	}
	switch cwe := meta["cwe"].(type) {
	case string:
		if !cweID.MatchString(cwe) {
			bad("metadata.cwe %q is not CWE-<number>", cwe)
		}
	case []any:
		if len(cwe) == 0 {
			bad("metadata.cwe is an empty list")
		}
		for _, c := range cwe {
			if s, _ := c.(string); !cweID.MatchString(s) {
				bad("metadata.cwe entry %q is not CWE-<number>", c)
			}
		}
	default:
		bad("metadata.cwe is missing")
	}
	if c := str("confidence"); !validConfidenceKeys[c] {
		bad("metadata.confidence %q is not HIGH, MEDIUM or LOW", c)
	}
	if s := str("fendix_severity"); !validFendixSeverityKeys[s] {
		bad("metadata.fendix_severity %q is not CRITICAL, HIGH, MEDIUM, LOW or INFO", s)
	}
	for _, key := range []string{"fendix_title", "fendix_remediation"} {
		v := strings.TrimSpace(str(key))
		if v == "" {
			bad("metadata.%s is empty", key)
		} else if token := semgrepMetavariable.FindString(v); token != "" {
			bad("metadata.%s carries metavariable %q; it is static public copy", key, token)
		}
	}

	// Taint rules.
	reach, hasReach := meta[reachabilityMetadataKey]
	switch {
	case taint && reach != reachabilityTaint:
		bad("a taint rule must set metadata.%s: %s", reachabilityMetadataKey, reachabilityTaint)
	case !taint && hasReach:
		bad("metadata.%s is set on a rule that is not mode: taint; a pattern match proves no flow", reachabilityMetadataKey)
	}
	if taint && str("confidence") != "MEDIUM" {
		bad("a taint rule's metadata.confidence must be MEDIUM, not %q", str("confidence"))
	}

	// Rule ids: <lang>-<class>-taint and <lang>-<class>-sink.
	m := conventionalRuleID.FindStringSubmatch(id)
	switch {
	case taint && (m == nil || m[3] != "taint"):
		bad("a taint rule's id must be <lang>-<class>-taint")
	case !taint && strings.HasSuffix(id, "-taint"):
		bad("id ends in -taint but the rule is not mode: taint")
	case strings.HasSuffix(id, "-sink") && m == nil:
		bad("a shape rule's id must be <lang>-<class>-sink")
	}
	if m != nil && !declared[ruleIDLanguage[m[1]]] {
		bad("id names language %q, which the rule's languages do not list", m[1])
	}

	// A -sink rule excludes module constants and fully literal arguments.
	if m != nil && m[3] == "sink" {
		notInside := strings.Join(textsUnder(rule, "pattern-not-inside"), "\n")
		for _, l := range langs {
			name, _ := l.(string)
			for _, want := range sinkConstantExclusions[name] {
				if !want.MatchString(notInside) {
					bad("a -sink rule for %s needs a pattern-not-inside matching %s (a constant binding)", name, want)
				}
			}
		}
		if !strings.Contains(strings.Join(textsUnder(rule, "pattern-not"), "\n"), `"..."`) {
			bad(`a -sink rule needs a pattern-not for a fully literal argument ("...")`)
		}
	}
	return out
}

// textsUnder returns every string at any depth under a key named key.
func textsUnder(node any, key string) []string {
	var out []string
	var walk func(v any, inside bool)
	walk = func(v any, inside bool) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				walk(child, inside || k == key)
			}
		case []any:
			for _, child := range t {
				walk(child, inside)
			}
		case string:
			if inside {
				out = append(out, t)
			}
		}
	}
	walk(node, false)
	return out
}

// TestEveryRuleCarriesFendixMetadata holds every bundled rule to the
// metadata contract: category (one of five), cwe, confidence,
// fendix_severity, fendix_title and fendix_remediation; languages drawn from
// python, javascript, typescript, java and go; and for a taint rule,
// fendix_reachability: taint, confidence MEDIUM and a <lang>-<class>-taint id.
func TestEveryRuleCarriesFendixMetadata(t *testing.T) {
	rules := 0
	err := fs.WalkDir(embeddedRules, "rules", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			Rules []map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, rule := range doc.Rules {
			rules++
			for _, v := range ruleContractViolations(rule) {
				t.Errorf("%s: rule %v: %s", path, rule["id"], v)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if rules != rulepackTotalCount {
		t.Errorf("checked %d rules; rulepackTotalCount = %d", rules, rulepackTotalCount)
	}
}

// TestRuleContractCatchesEachViolation shows each clause of the contract
// rejects a rule that breaks it. No bundled rule is a taint or -sink rule yet,
// so without this the clauses for them would be untested until a pack lands.
func TestRuleContractCatchesEachViolation(t *testing.T) {
	const taintRule = `
id: js-sqli-taint
mode: taint
languages: [javascript, typescript]
metadata:
  category: injection
  cwe: CWE-89
  confidence: MEDIUM
  fendix_severity: HIGH
  fendix_title: SQL query built from request input.
  fendix_remediation: Pass request input as a query parameter.
  fendix_reachability: taint
`
	const sinkRule = `
id: go-sqli-sink
languages: [go]
patterns:
  - pattern: $DB.Query(fmt.Sprintf($F, $X, ...), ...)
  - pattern-not: $DB.Query("...", ...)
  - pattern-not-inside: |
      const $X = "..."
      ...
  - pattern-not-inside: |
      const (
        ...
        $X = "..."
        ...
      )
      ...
metadata:
  category: injection
  cwe: [CWE-89]
  confidence: MEDIUM
  fendix_severity: MEDIUM
  fendix_title: SQL query built with fmt.Sprintf from a non-constant value.
  fendix_remediation: Use a placeholder and pass the value as an argument.
`
	cases := []struct {
		name, base, old, new, want string
	}{
		{"valid taint rule", taintRule, "", "", ""},
		{"valid sink rule", sinkRule, "", "", ""},
		{"new category", taintRule, "category: injection", "category: ssrf", "metadata.category"},
		{"missing cwe", taintRule, "  cwe: CWE-89\n", "", "metadata.cwe is missing"},
		{"malformed cwe", sinkRule, "[CWE-89]", "[89]", "not CWE-<number>"},
		{"missing title", taintRule, "  fendix_title: SQL query built from request input.\n", "", "metadata.fendix_title is empty"},
		{"metavariable in remediation", taintRule, "Pass request input", "Pass $X", "carries metavariable"},
		{"unsupported language", taintRule, "[javascript, typescript]", "[javascript, ruby]", `language "ruby"`},
		{"language alias", taintRule, "[javascript, typescript]", "[js, typescript]", `language "js"`},
		{"taint rule without reachability", taintRule, "  fendix_reachability: taint\n", "", "must set metadata.fendix_reachability"},
		{"taint rule at HIGH confidence", taintRule, "confidence: MEDIUM", "confidence: HIGH", "must be MEDIUM"},
		{"taint rule misnamed", taintRule, "js-sqli-taint", "express-sqli", "<lang>-<class>-taint"},
		{"pattern rule claiming reachability", sinkRule, "  fendix_title:", "  fendix_reachability: taint\n  fendix_title:", "not mode: taint"},
		{"pattern rule named -taint", sinkRule, "go-sqli-sink", "go-sqli-taint", "not mode: taint"},
		{"id names an undeclared language", taintRule, "js-sqli-taint", "java-sqli-taint", `names language "java"`},
		{"sink rule without the const block", sinkRule, "      const (", "      var (", `const\s*\(`},
		{"sink rule without a literal exclusion", sinkRule, `  - pattern-not: $DB.Query("...", ...)` + "\n", "", "fully literal argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.base
			if tc.old != "" {
				if !strings.Contains(src, tc.old) {
					t.Fatalf("fixture lacks %q", tc.old)
				}
				src = strings.Replace(src, tc.old, tc.new, 1)
			}
			var rule map[string]any
			if err := yaml.Unmarshal([]byte(src), &rule); err != nil {
				t.Fatal(err)
			}
			got := strings.Join(ruleContractViolations(rule), "\n")
			switch {
			case tc.want == "" && got != "":
				t.Errorf("a valid rule was rejected:\n%s", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Errorf("violations = %q; want one containing %q", got, tc.want)
			}
		})
	}
}

// --- Rule tests (semgrep --test) ----------------------------------------------

// ruleTestAnnotation matches a `# ruleid: <id>` or `// ok: <id>` line;
// several ids may be listed, comma-separated.
var ruleTestAnnotation = regexp.MustCompile(`(?m)(?:#|//)\s*(ruleid|ok):\s*([A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*)\s*$`)

// ruleTestProblems checks the layout `semgrep --test --config rules ruletests`
// relies on. Semgrep pairs ruletests/<stem>.<ext> with rules/<stem>.yaml and
// silently skips a test file that has no rule file of its stem, so a misnamed
// test passes without running. Every rule in a pack that targets a language
// other than Python must have a `ruleid:` and an `ok:` annotation in its pack's
// test files.
func ruleTestProblems(rules, tests fs.FS) []string {
	var out []string
	annotations := map[string]map[string]map[string]bool{} // stem -> kind -> rule id
	err := fs.WalkDir(tests, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() || p == "README.md" {
			return walkErr
		}
		stem := strings.TrimSuffix(p, path.Ext(p))
		if _, err := fs.Stat(rules, stem+".yaml"); err != nil {
			out = append(out, fmt.Sprintf("ruletests/%s has no rules/%s.yaml; semgrep --test skips it", p, stem))
			return nil
		}
		data, err := fs.ReadFile(tests, p)
		if err != nil {
			return err
		}
		if annotations[stem] == nil {
			annotations[stem] = map[string]map[string]bool{"ruleid": {}, "ok": {}}
		}
		for _, m := range ruleTestAnnotation.FindAllStringSubmatch(string(data), -1) {
			for _, id := range strings.Split(m[2], ",") {
				annotations[stem][m[1]][strings.TrimSpace(id)] = true
			}
		}
		return nil
	})
	if err != nil {
		return append(out, err.Error())
	}
	packs, err := fs.Glob(rules, "*.yaml")
	if err != nil {
		return append(out, err.Error())
	}
	for _, pack := range packs {
		data, err := fs.ReadFile(rules, pack)
		if err != nil {
			return append(out, err.Error())
		}
		var doc struct {
			Rules []struct {
				ID        string   `yaml:"id"`
				Languages []string `yaml:"languages"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return append(out, fmt.Sprintf("parse %s: %v", pack, err))
		}
		stem := strings.TrimSuffix(pack, ".yaml")
		for _, r := range doc.Rules {
			if len(r.Languages) == 0 || (len(r.Languages) == 1 && r.Languages[0] == "python") {
				continue
			}
			for _, kind := range []string{"ruleid", "ok"} {
				if !annotations[stem][kind][r.ID] {
					out = append(out, fmt.Sprintf("rule %s (rules/%s) has no `%s: %s` line in ruletests/%s.*", r.ID, pack, kind, r.ID, stem))
				}
			}
		}
	}
	return out
}

// TestRuleTestsPairWithRulePacks checks the bundled pack against
// ruletests/; CI runs the tests themselves with semgrep --test.
func TestRuleTestsPairWithRulePacks(t *testing.T) {
	rules, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range ruleTestProblems(rules, os.DirFS("ruletests")) {
		t.Error(problem)
	}
}

func TestRuleTestProblemsCatchesBrokenLayouts(t *testing.T) {
	jsPack := "rules:\n  - id: js-xss-taint\n    languages: [javascript, typescript]\n"
	pyPack := "rules:\n  - id: python-eval-injection\n    languages: [python]\n"
	cases := []struct {
		name  string
		tests fstest.MapFS
		want  []string
	}{
		{"annotated", fstest.MapFS{
			"README.md":         {Data: []byte("docs")},
			"javascript-web.ts": {Data: []byte("// ruleid: js-xss-taint\nres.send(q)\n// ok: other-rule, js-xss-taint\nres.send(esc(q))\n")},
		}, nil},
		{"misnamed test file", fstest.MapFS{
			"javascript-web.ts": {Data: []byte("// ruleid: js-xss-taint\n// ok: js-xss-taint\n")},
			"js-web.ts":         {Data: []byte("// ruleid: js-xss-taint\n")},
		}, []string{"ruletests/js-web.ts has no rules/js-web.yaml"}},
		{"no tests for a JavaScript pack", fstest.MapFS{}, []string{"no `ruleid: js-xss-taint`", "no `ok: js-xss-taint`"}},
		{"no ok case", fstest.MapFS{
			"javascript-web.ts": {Data: []byte("// ruleid: js-xss-taint\nres.send(q)\n")},
		}, []string{"no `ok: js-xss-taint`"}},
	}
	rules := fstest.MapFS{"javascript-web.yaml": {Data: []byte(jsPack)}, "injection.yaml": {Data: []byte(pyPack)}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ruleTestProblems(rules, tc.tests)
			if len(got) != len(tc.want) {
				t.Fatalf("problems = %q; want %d containing %q", got, len(tc.want), tc.want)
			}
			for i, want := range tc.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q; want it to contain %q", i, got[i], want)
				}
			}
		})
	}
}

// --- Build output and vendored code (Review Focus 3) ---------------------------

// TestBuildOutputIsExcluded runs real Semgrep over a tree with the same sinks
// inside and outside build output and vendored code. Nothing under
// node_modules/, dist/, build/, .next/, target/ or vendor/, at any depth, nor
// a *.min.js file, is reported; the copies elsewhere are, so the test cannot
// pass by finding nothing. The bundled pack has Python rules only, so the
// JavaScript sink is reported by testdata/taint_rule.yaml, a stand-in for the
// JavaScript pack, passed as a second --config.
//
// Semgrep has a built-in ignore list (node_modules/, build/, dist/, vendor/,
// *.min.js and test directories), but only for a project that has no
// .semgrepignore of its own: one that has one, for whatever reason, gets none
// of it. So the tree is scanned both ways.
func TestBuildOutputIsExcluded(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	withExtraSemgrepConfig(t, filepath.Join(testdataDir, "taint_rule.yaml"))

	// python-command-injection-shell-true reports line 5.
	const pySink = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
	files := map[string]string{
		// Reported: the positive controls, and names that only look like
		// an excluded directory.
		"app/views.py":        pySink,
		"src/app.js":          spikeApp,
		"app/build.py":        pySink,
		"distribution/app.js": spikeApp,
		// Not reported.
		"node_modules/x/index.js":          spikeApp,
		"node_modules/x/setup.py":          pySink,
		"dist/app.js":                      spikeApp,
		"dist/app.py":                      pySink,
		"build/lib/app.py":                 pySink,
		"build/app.js":                     spikeApp,
		".next/server/app.js":              spikeApp,
		"target/classes/app.py":            pySink,
		"vendor/lib/app.py":                pySink,
		"vendor/lib/app.js":                spikeApp,
		"static/app.min.js":                spikeApp,
		"packages/web/node_modules/y/a.js": spikeApp,
		"services/api/dist/app.py":         pySink,
	}
	want := map[string]bool{"app/views.py:5": true, "src/app.js:9": true, "app/build.py:5": true, "distribution/app.js:9": true}

	for _, project := range []struct{ name, semgrepignore string }{
		{"without a project .semgrepignore", ""},
		{"with a project .semgrepignore", "# project ignores\nlegacy/\n"},
	} {
		t.Run(project.name, func(t *testing.T) {
			root := t.TempDir()
			tree := files
			if project.semgrepignore != "" {
				tree = map[string]string{".semgrepignore": project.semgrepignore}
				for rel, body := range files {
					tree[rel] = body
				}
			}
			for rel, body := range tree {
				p := filepath.Join(root, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			got, err := Scan(context.Background(), root)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			assertEndpoints(t, got, want)

			// A diff that touches build output: --include names the file,
			// and the exclude still wins.
			allow := gitdiff.NewAllowlist(root, []string{"dist/app.js", "vendor/lib/app.py", "app/views.py"})
			got, err = ScanWithAllowlist(context.Background(), root, allow)
			if err != nil {
				t.Fatalf("ScanWithAllowlist: %v", err)
			}
			assertEndpoints(t, got, map[string]bool{"app/views.py:5": true})
		})
	}
}

func assertEndpoints(t *testing.T, got []evidence.Evidence, want map[string]bool) {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.Endpoint] = true
		if !want[f.Endpoint] {
			t.Errorf("unexpected finding %s at %s", f.RuleID, f.Endpoint)
		}
	}
	for endpoint := range want {
		if !seen[endpoint] {
			t.Errorf("no finding at %s; the control must be reported", endpoint)
		}
	}
}

// withExtraSemgrepConfig adds a rule file to every semgrep run for the test.
func withExtraSemgrepConfig(t *testing.T, config string) {
	t.Helper()
	orig := commandContext
	commandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return orig(ctx, name, append([]string{"--config", config}, args...)...)
	}
	t.Cleanup(func() { commandContext = orig })
}

// TestScanArgsExcludeBuildOutputAndLiftRuleTimeout pins the arguments without
// needing semgrep: the excludes, and --timeout 0. Semgrep's own per-rule,
// per-file timeout is 5 s and drops a slow rule's matches on that file
// silently; the run as a whole stays bounded by defaultTimeout.
func TestScanArgsExcludeBuildOutputAndLiftRuleTimeout(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)
	if _, err := Scan(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	raw, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	args := "\n" + string(raw)
	for _, pair := range []string{
		"--exclude\nnode_modules\n", "--exclude\ndist\n", "--exclude\nbuild\n", "--exclude\n.next\n",
		"--exclude\ntarget\n", "--exclude\nvendor\n", "--exclude\n*.min.js\n", "--timeout\n0\n",
	} {
		if !strings.Contains(args, "\n"+pair) {
			t.Errorf("semgrep argv lacks %q:\n%s", strings.ReplaceAll(pair, "\n", " "), raw)
		}
	}
	if defaultTimeout != 300*time.Second {
		t.Errorf("defaultTimeout = %s; want 300s, the bound on one run of every pack", defaultTimeout)
	}
}
