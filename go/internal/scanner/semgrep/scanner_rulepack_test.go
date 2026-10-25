package semgrep

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// rulepackTotalCount is the count of bundled rules. When you add or
// remove a rule, update this constant in the same commit so the
// catalog test catches accidental rule deletion. v0.13.1 dropped the
// broken django-fbv-missing-auth-decorator rule (Sprint 18 review), and
// flask-missing-login-required went after v3.6.4 because it duplicated
// flask-route-no-auth-decorator on every Flask route (ADR-012).
const rulepackTotalCount = 22

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
