package semgrep

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// The JavaScript/TypeScript taint pack (Task 4.3) and the per-language gate.

// jsTaintRuleID is one taint rule of the JavaScript/TypeScript pack.
const jsTaintRuleID = "js-sqli-taint"

// bundledMetadata is a bundled rule's metadata as semgrep sends it back in
// extra.metadata: the rule's own YAML block, not a stand-in.
func bundledMetadata(t *testing.T, ruleID string) map[string]interface{} {
	t.Helper()
	r, ok := loadAllRules(t)[ruleID]
	if !ok {
		t.Fatalf("rule %s is not in the bundled pack", ruleID)
	}
	meta, ok := r.Raw["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("rule %s has no metadata block", ruleID)
	}
	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return out
}

// The gate looks a rule up by the id the scanner derives from semgrep's
// check_id, and semgrep namespaces that id by the temporary directory the
// rules were extracted to. The ids below are the shapes semgrep 1.141.0 really
// prints: the macOS one was captured from `semgrep --config
// $TMPDIR/fendix-semgrep-rules-XXXX --json` and the Linux one is /tmp. If
// normalizeCheckID left any of that prefix on, the bundled-spec lookup would
// miss and every JavaScript finding would stay a shim finding however the gate
// is set. The lookup here is the real one, over the embedded pack.
func TestProductionCheckIDOfAJavaScriptTaintRuleReachesTheGate(t *testing.T) {
	meta := bundledMetadata(t, jsTaintRuleID)
	spec, ok := ruleSpecs(jsTaintRuleID)
	if !ok || spec.Mode != "taint" || !reflect.DeepEqual(spec.Languages, []string{"javascript", "typescript"}) {
		t.Fatalf("bundled spec of %s = %+v (found %v); want mode taint, languages [javascript typescript]",
			jsTaintRuleID, spec, ok)
	}

	for _, checkID := range []string{
		"var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T.fendix-semgrep-rules-B2HsHziK." + jsTaintRuleID,
		"private.var.folders.7m.08880d351wv3hcmbjbvq856r0000gn.T.fendix-semgrep-rules-1072928901." + jsTaintRuleID,
		"tmp.fendix-semgrep-rules-2173727481." + jsTaintRuleID,
	} {
		t.Run(checkID, func(t *testing.T) {
			if got := normalizeCheckID(checkID); got != jsTaintRuleID {
				t.Fatalf("normalizeCheckID(%q) = %q, want %q", checkID, got, jsTaintRuleID)
			}
			r := semgrepResult{
				CheckID: checkID,
				Path:    "routes/users.js",
				Start:   semgrepLineCol{Line: 9, Col: 3},
				Extra: semgrepExtra{
					Message:  "SQL query built from request input.",
					Severity: "ERROR",
					Lines:    semgrepRedactedLines,
					Metadata: meta,
				},
			}
			mapped := func() evidence.Evidence {
				t.Helper()
				ev, ok := mapResult(&r, "/code")
				if !ok {
					t.Fatal("mapResult dropped the result")
				}
				if ev.RuleID != jsTaintRuleID {
					t.Errorf("RuleID = %q, want %q", ev.RuleID, jsTaintRuleID)
				}
				return ev
			}

			enableReachability(t, "javascript", "typescript")
			requireTaint(t, mapped())

			// The rule also runs on TypeScript files, so JavaScript alone has
			// not met its gate.
			enableReachability(t, "javascript")
			requireShim(t, mapped())

			enableReachability(t)
			requireShim(t, mapped())
		})
	}
}

// The same path end to end: the real scanner extracts the embedded pack to its
// temporary directory, real semgrep runs it over an Express route, and the
// finding that comes back opens the gate once JavaScript and TypeScript are
// enabled.
func TestScanReportsAJavaScriptTaintFindingAsReachable(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(spikeApp), 0o644); err != nil {
		t.Fatal(err)
	}
	find := func() evidence.Evidence {
		t.Helper()
		got, err := Scan(context.Background(), dir)
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		for _, f := range got {
			if f.RuleID == jsTaintRuleID {
				if f.Endpoint != "app.js:9" {
					t.Errorf("Endpoint = %q, want app.js:9", f.Endpoint)
				}
				return f
			}
		}
		t.Fatalf("no %s finding in %d findings", jsTaintRuleID, len(got))
		return evidence.Evidence{}
	}

	enableReachability(t)
	requireShim(t, find())

	enableReachability(t, "javascript", "typescript")
	requireTaint(t, find())
}

// javascriptRules returns the bundled rules that target JavaScript, split into
// the taint rules that ask for reachability (mode: taint and
// fendix_reachability: taint) and the rest, each sorted by id. Read from the
// embedded pack, so a rule added later is covered without editing a test.
func javascriptRules(t *testing.T) (taint, other []packRule) {
	t.Helper()
	all := loadAllRules(t)
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := all[id]
		if !slices.Contains(r.Languages, "javascript") {
			continue
		}
		mode, _ := r.Raw["mode"].(string)
		meta, _ := r.Raw["metadata"].(map[string]any)
		if mode == "taint" && meta[reachabilityMetadataKey] == reachabilityTaint {
			taint = append(taint, r)
		} else {
			other = append(other, r)
		}
	}
	return taint, other
}

// The shipped gate, with no test override: JavaScript and TypeScript are
// enabled (Task 4.3), so a match of every taint rule of the pack is a reachable
// semgrep_taint finding, and a match of any other JavaScript rule stays a
// semgrep_shim finding, even when its metadata claims reachability.
func TestShippedGateOpensForTheJavaScriptTaintRulesOnly(t *testing.T) {
	taint, other := javascriptRules(t)
	if len(taint) == 0 || len(other) == 0 {
		t.Fatalf("got %d taint and %d other JavaScript rules; want both kinds", len(taint), len(other))
	}
	mapped := func(r packRule, claimReachability bool) evidence.Evidence {
		t.Helper()
		meta := bundledMetadata(t, r.ID)
		if claimReachability {
			meta[reachabilityMetadataKey] = reachabilityTaint
		}
		res := semgrepResult{
			CheckID: "tmp.fendix-semgrep-rules-1072928901." + r.ID,
			Path:    "routes/users.js",
			Start:   semgrepLineCol{Line: 9, Col: 3},
			Extra: semgrepExtra{
				Message:  "finding",
				Severity: "ERROR",
				Lines:    semgrepRedactedLines,
				Metadata: meta,
			},
		}
		ev, ok := mapResult(&res, "/code")
		if !ok {
			t.Fatalf("%s: mapResult dropped the result", r.ID)
		}
		return ev
	}
	for _, r := range taint {
		t.Run(r.ID, func(t *testing.T) { requireTaint(t, mapped(r, false)) })
	}
	for _, r := range other {
		t.Run(r.ID, func(t *testing.T) { requireShim(t, mapped(r, true)) })
	}
}

// requestSources is a taint rule's request-source block: its pattern-sources
// without the sources of another label, and without the label key itself (a
// rule that also has labelled sources, such as js-weak-password-hash-taint,
// labels the shared ones INPUT).
func requestSources(r packRule) ([]any, error) {
	sources, ok := r.Raw["pattern-sources"].([]any)
	if !ok || len(sources) == 0 {
		return nil, fmt.Errorf("%s: no pattern-sources", r.ID)
	}
	var out []any
	for _, s := range sources {
		m, ok := s.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: a source is not a mapping: %v", r.ID, s)
		}
		label, _ := m["label"].(string)
		if label != "" && label != "INPUT" {
			continue
		}
		c := make(map[string]any, len(m))
		for k, v := range m {
			if k != "label" {
				c[k] = v
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// requestSourceDrift returns every way the taint rules' request-source blocks
// differ from the first rule's; notRequest names the rules whose source is
// not request input, and each must be one of the rules.
func requestSourceDrift(taint []packRule, notRequest map[string]string) []string {
	var out []string
	var want []any
	var wantFrom string
	compared := 0
	for _, r := range taint {
		if _, skip := notRequest[r.ID]; skip {
			continue
		}
		got, err := requestSources(r)
		if err != nil {
			out = append(out, err.Error())
			continue
		}
		compared++
		if want == nil {
			want, wantFrom = got, r.ID
			continue
		}
		if !reflect.DeepEqual(got, want) {
			out = append(out, fmt.Sprintf("%s: request sources differ from %s's; keep the block identical in every rule", r.ID, wantFrom))
		}
	}
	for id := range notRequest {
		if !slices.ContainsFunc(taint, func(r packRule) bool { return r.ID == id }) {
			out = append(out, fmt.Sprintf("exempted rule %s is not a taint rule of the pack; drop the exemption", id))
		}
	}
	if compared < 2 {
		out = append(out, fmt.Sprintf("compared %d rules; want the shared block in at least two", compared))
	}
	return out
}

// Semgrep does not resolve YAML anchors, so the request sources are a copy in
// every JavaScript taint rule that follows request input. The copies must not
// drift: a source added to one rule and not another is a gap in that class.
func TestJavaScriptTaintRulesShareOneRequestSourceBlock(t *testing.T) {
	taint, _ := javascriptRules(t)
	notRequest := map[string]string{"js-weak-random-token-taint": "its source is Math.random()"}
	for _, problem := range requestSourceDrift(taint, notRequest) {
		t.Error(problem)
	}
}

func TestRequestSourceDriftIsCaught(t *testing.T) {
	rule := func(id string, sources ...any) packRule {
		return packRule{ID: id, Raw: map[string]any{"pattern-sources": sources}}
	}
	src := func(p string) map[string]any { return map[string]any{"pattern": p} }
	labelled := func(label, p string) map[string]any { return map[string]any{"label": label, "pattern": p} }
	cases := []struct {
		name  string
		rules []packRule
		want  string
	}{
		{"identical", []packRule{rule("a", src("$R.query")), rule("b", src("$R.query"))}, ""},
		{"INPUT label and an extra label", []packRule{
			rule("a", src("$R.query")),
			rule("b", labelled("INPUT", "$R.query"), labelled("PASSWORD", "$R.body.password")),
		}, ""},
		{"a source missing", []packRule{rule("a", src("$R.query"), src("$R.body")), rule("b", src("$R.query"))}, "b: request sources differ"},
		{"a source changed", []packRule{rule("a", src("$R.query")), rule("b", src("$R.params"))}, "b: request sources differ"},
		{"a stale exemption", []packRule{rule("a", src("$R.query")), rule("b", src("$R.query"))}, "exempted rule gone"},
		{"one rule only", []packRule{rule("a", src("$R.query"))}, "compared 1 rules"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			notRequest := map[string]string{}
			if tc.name == "a stale exemption" {
				notRequest["gone"] = "removed"
			}
			got := strings.Join(requestSourceDrift(tc.rules, notRequest), "\n")
			switch {
			case tc.want == "" && got != "":
				t.Errorf("unexpected problems:\n%s", got)
			case tc.want != "" && !strings.Contains(got, tc.want):
				t.Errorf("problems = %q; want one containing %q", got, tc.want)
			}
		})
	}
}
