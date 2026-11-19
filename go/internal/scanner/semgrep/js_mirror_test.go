package semgrep

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The JavaScript rule packs declare `languages: [javascript, typescript]`, and
// every one of their ruletests used to be a .ts file, so nothing tested what
// the packs report on .js. The .js mirrors pin it, and they are the parity
// guard for any change that treats the two languages differently, such as
// running a separate JavaScript flavour of the packs (Round 6, WS-E3).
//
// A mirror is its .ts file with the types erased in place: same lines, same
// annotations on the same line numbers (ruletests/README.md, "JavaScript
// mirrors"). semgrep --test then checks both files against the same
// annotations; these tests keep the two from drifting apart, which Semgrep
// cannot see, and keep every TypeScript-only-looking source item of the packs
// covered in both languages.

// wse3JSAnnotation matches one ruletest annotation line, keeping its text.
var wse3JSAnnotation = regexp.MustCompile(`(?m)^\s*//\s*(ruleid|ok|todoruleid|todook):\s*(.+?)\s*$`)

// wse3AnnotationsByLine returns each annotation line of a JavaScript or
// TypeScript ruletest keyed by its 1-based line number.
func wse3AnnotationsByLine(data string) map[int]string {
	out := map[int]string{}
	for i, line := range strings.Split(data, "\n") {
		if m := wse3JSAnnotation.FindStringSubmatch(line); m != nil {
			ids := strings.Split(m[2], ",")
			for j := range ids {
				ids[j] = strings.TrimSpace(ids[j])
			}
			sort.Strings(ids)
			out[i+1] = m[1] + ": " + strings.Join(ids, ", ")
		}
	}
	return out
}

// wse3BlankedFrom reports whether js is ts with some bytes replaced by spaces and
// trailing blanks removed: what erasing the types in place produces.
func wse3BlankedFrom(js, ts string) bool {
	if len(js) > len(ts) {
		return false
	}
	for k := 0; k < len(js); k++ {
		if js[k] != ts[k] && js[k] != ' ' {
			return false
		}
	}
	return true
}

func TestJavaScriptRuleTestsHaveJSMirror(t *testing.T) {
	tests := os.DirFS("ruletests")
	tsFiles, err := fs.Glob(tests, "javascript-*.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(tsFiles) == 0 {
		t.Fatal("no javascript-*.ts ruletests found")
	}
	for _, ts := range tsFiles {
		js := strings.TrimSuffix(ts, ".ts") + ".js"
		t.Run(js, func(t *testing.T) {
			tsData, err := fs.ReadFile(tests, ts)
			if err != nil {
				t.Fatal(err)
			}
			jsData, err := fs.ReadFile(tests, js)
			if err != nil {
				t.Fatalf("ruletests/%s has no .js mirror: %v", ts, err)
			}
			tsLines := strings.Split(string(tsData), "\n")
			jsLines := strings.Split(string(jsData), "\n")
			if len(tsLines) != len(jsLines) {
				t.Fatalf("ruletests/%s has %d lines, its mirror %d: the mirror must keep every line in place", ts, len(tsLines), len(jsLines))
			}
			for i := range jsLines {
				if !wse3BlankedFrom(jsLines[i], tsLines[i]) {
					t.Errorf("ruletests/%s:%d is not line %d of %s with its types blanked:\n  ts: %q\n  js: %q", js, i+1, i+1, ts, tsLines[i], jsLines[i])
				}
			}
			want := wse3AnnotationsByLine(string(tsData))
			got := wse3AnnotationsByLine(string(jsData))
			for line, a := range want {
				if got[line] != a {
					t.Errorf("ruletests/%s:%d is %q; ruletests/%s:%d must carry the same annotation, has %q", ts, line, a, js, line, got[line])
				}
			}
			for line, a := range got {
				if _, ok := want[line]; !ok {
					t.Errorf("ruletests/%s:%d carries %q, which ruletests/%s does not", js, line, a, ts)
				}
			}
		})
	}
}

// wse3JSPackRules decodes the JavaScript packs and returns their taint rules.
func wse3JSPackRules(t *testing.T) map[string][]packRule {
	t.Helper()
	rules, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		t.Fatal(err)
	}
	packs, err := fs.Glob(rules, "javascript-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]packRule{}
	for _, pack := range packs {
		data, err := fs.ReadFile(rules, pack)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodePack(data)
		if err != nil {
			t.Fatalf("parse %s: %v", pack, err)
		}
		for _, r := range decoded {
			if mode, _ := r.Raw["mode"].(string); mode == "taint" {
				out[strings.TrimSuffix(pack, ".yaml")] = append(out[strings.TrimSuffix(pack, ".yaml")], r)
			}
		}
	}
	return out
}

// strings of a decoded YAML node, depth first.
func wse3YAMLStrings(node any, visit func(key, s string)) {
	var walk func(key string, n any)
	walk = func(key string, n any) {
		switch v := n.(type) {
		case map[string]any:
			for k, x := range v {
				walk(k, x)
			}
		case []any:
			for _, x := range v {
				walk(key, x)
			}
		case string:
			visit(key, v)
		}
	}
	walk("", node)
}

func wse3RuleSources(r packRule) []map[string]any {
	raw, _ := r.Raw["pattern-sources"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, s := range raw {
		if m, ok := s.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// TestJavaScriptAsSourceRulesHaveFlowCase requires every rule whose sources
// include the `const {..., $V, ...} = $E as $T` item to report a .js line in a
// *.flow-as.js ruletest. Flow (0.229 and later) writes the same `as` cast in
// .js files, so the item is not TypeScript-only, and a JavaScript flavour of
// the pack that dropped it would lose these lines.
func TestJavaScriptAsSourceRulesHaveFlowCase(t *testing.T) {
	tests := os.DirFS("ruletests")
	total := 0
	for stem, rules := range wse3JSPackRules(t) {
		flow, _ := fs.ReadFile(tests, stem+".flow-as.js")
		reported := map[string]bool{}
		for _, a := range wse3AnnotationsByLine(string(flow)) {
			kind, ids, _ := strings.Cut(a, ": ")
			if kind != "ruleid" {
				continue
			}
			for _, id := range strings.Split(ids, ", ") {
				reported[id] = true
			}
		}
		for _, r := range rules {
			hasAs := false
			for _, src := range wse3RuleSources(r) {
				wse3YAMLStrings(src, func(key, s string) {
					if key == "pattern-inside" && strings.Contains(s, "= $E as $T") {
						hasAs = true
					}
				})
			}
			if !hasAs {
				continue
			}
			total++
			if !reported[r.ID] {
				t.Errorf("rule %s (rules/%s.yaml) reads a source through `$E as $T`, but ruletests/%s.flow-as.js has no `ruleid: %s` line", r.ID, stem, stem, r.ID)
			}
		}
	}
	// Nine taint rules carry the item today. A change to that number changes
	// what the Flow cases must cover: update the cases, then this pin.
	if total != 9 {
		t.Errorf("%d JavaScript taint rules carry the `$E as $T` source; this test pins 9", total)
	}
}

// wse3DecoratorSource is one parameter-decorator source item of one rule.
type wse3DecoratorSource struct{ rule, decorator, label string }

func (d wse3DecoratorSource) String() string {
	return fmt.Sprintf("%s @%s %s", d.rule, d.decorator, d.label)
}

var (
	wse3DecoratorInSource = regexp.MustCompile(`@(\w+)\(`)
	wse3SourceMarker      = regexp.MustCompile(`^\s*// source: (\S+) @(\w+) (\w+)\s*$`)
	wse3HandlerName       = regexp.MustCompile(`^\s*(?:async\s+)?(\w+)\(`)
	wse3PasswordName      = regexp.MustCompile(`(?i)pass(word)?|pwd`)
	wse3HTTPMethodName    = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}
)

// TestJavaScriptDecoratorSourcesHaveCases requires a ruletest case for every
// parameter-decorator source item of every JavaScript taint rule (@Query,
// @Param, @Body, @Headers, @Req and the PASSWORD-labelled @Body($KEY)), in
// javascript-<pack>.decorators.ts and in its .js mirror. A case is the block
// after a `// source: <rule> @<decorator> <label>` marker. It must report a
// `ruleid: <rule>` line, and it must be reachable only through that source:
// the decorated parameter is not named req or request (the Express source),
// the handler is not named after an HTTP method (the Next.js source), it
// holds no `as` cast, an INPUT case's key is not a password name, and the
// PASSWORD case's parameter is not one (so the INPUT sink, which needs a
// password-named value, cannot report it). @Req is covered under two names.
// semgrep --test proves each ruleid line is reported.
func TestJavaScriptDecoratorSourcesHaveCases(t *testing.T) {
	tests := os.DirFS("ruletests")
	want := map[wse3DecoratorSource]bool{}
	for _, rules := range wse3JSPackRules(t) {
		for _, r := range rules {
			for _, src := range wse3RuleSources(r) {
				label, _ := src["label"].(string)
				if label == "" {
					label = "INPUT"
				}
				wse3YAMLStrings(src, func(key, s string) {
					if key != "pattern-inside" {
						return
					}
					for _, m := range wse3DecoratorInSource.FindAllStringSubmatch(s, -1) {
						want[wse3DecoratorSource{r.ID, m[1], label}] = true
					}
				})
			}
		}
	}
	// 9 taint rules x {Query, Param, Body, Headers, Req}, plus the
	// PASSWORD-labelled @Body($KEY) of js-weak-password-hash-taint.
	if len(want) != 46 {
		t.Errorf("the JavaScript taint rules carry %d decorator source items; this test pins 46", len(want))
	}

	for stem := range wse3JSPackRules(t) {
		for _, ext := range []string{".ts", ".js"} {
			name := stem + ".decorators" + ext
			data, err := fs.ReadFile(tests, name)
			if err != nil {
				for d := range want {
					if strings.HasPrefix(stem, "javascript-") && wse3RuleInPack(t, stem, d.rule) {
						t.Errorf("ruletests/%s is missing: no case for %s", name, d)
					}
				}
				continue
			}
			wse3CheckDecoratorCases(t, name, string(data), want, stem)
		}
	}
}

func wse3RuleInPack(t *testing.T, stem, id string) bool {
	for _, r := range wse3JSPackRules(t)[stem] {
		if r.ID == id {
			return true
		}
	}
	return false
}

func wse3CheckDecoratorCases(t *testing.T, name, data string, want map[wse3DecoratorSource]bool, stem string) {
	t.Helper()
	lines := strings.Split(data, "\n")
	type block struct {
		src   wse3DecoratorSource
		at    int
		lines []string
	}
	var blocks []block
	for i, l := range lines {
		if m := wse3SourceMarker.FindStringSubmatch(l); m != nil {
			blocks = append(blocks, block{src: wse3DecoratorSource{m[1], m[2], m[3]}, at: i + 1})
			continue
		}
		if len(blocks) > 0 {
			blocks[len(blocks)-1].lines = append(blocks[len(blocks)-1].lines, l)
		}
	}
	covered := map[wse3DecoratorSource]map[string]bool{}
	for _, b := range blocks {
		where := fmt.Sprintf("ruletests/%s:%d (%s)", name, b.at, b.src)
		if !want[b.src] {
			t.Errorf("%s: no rule carries this source item", where)
			continue
		}
		body := strings.Join(b.lines, "\n")
		param := regexp.MustCompile(`@` + b.src.decorator + `\(([^)]*)\)\s+(\w+)`).FindStringSubmatch(body)
		if param == nil {
			t.Errorf("%s: no parameter decorated with @%s", where, b.src.decorator)
			continue
		}
		key, pname := param[1], param[2]
		if pname == "req" || pname == "request" {
			t.Errorf("%s: parameter %q is a name the Express source reads; use another", where, pname)
		}
		for _, l := range b.lines {
			if m := wse3HandlerName.FindStringSubmatch(l); m != nil && wse3HTTPMethodName[m[1]] {
				t.Errorf("%s: handler %q is a name the Next.js source reads; use another", where, m[1])
			}
		}
		if strings.Contains(body, " as ") {
			t.Errorf("%s: an `as` cast lets the `$E as $T` source report the case", where)
		}
		switch b.src.label {
		case "INPUT":
			if wse3PasswordName.MatchString(key) {
				t.Errorf("%s: key %s is a password name, so the PASSWORD source could report it", where, key)
			}
		case "PASSWORD":
			if !wse3PasswordName.MatchString(key) || wse3PasswordName.MatchString(pname) {
				t.Errorf("%s: a PASSWORD case needs a password key and a parameter that is not a password name (key %s, parameter %s)", where, key, pname)
			}
		}
		reported := false
		for _, a := range wse3AnnotationsByLine(body) {
			kind, ids, _ := strings.Cut(a, ": ")
			if kind == "ruleid" && strings.Contains(", "+ids+",", ", "+b.src.rule+",") {
				reported = true
			}
		}
		if !reported {
			t.Errorf("%s: no `ruleid: %s` line in the case", where, b.src.rule)
		}
		if covered[b.src] == nil {
			covered[b.src] = map[string]bool{}
		}
		covered[b.src][pname] = true
	}
	for d := range want {
		if !wse3RuleInPack(t, stem, d.rule) {
			continue
		}
		names := covered[d]
		if len(names) == 0 {
			t.Errorf("ruletests/%s has no case for %s", name, d)
			continue
		}
		if d.decorator == "Req" && (!names["r"] || !names["httpReq"]) {
			t.Errorf("ruletests/%s covers %s under %v; want the request named r and httpReq", name, d, names)
		}
	}
}
