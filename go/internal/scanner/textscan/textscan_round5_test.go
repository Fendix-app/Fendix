package textscan

import (
	"strings"
	"testing"
)

// Round 5, C4B-26: the extension set is case-insensitive and complete. Before,
// `eval(userCode)` in an .es6 or .mts file, or in APP.JS, was reported by no
// analyzer (Semgrep selects neither, the Python engine's JS set stops at .cts,
// and textscan matched ".js" only in lower case).
func TestScan_JavaScriptFamilyExtensionsAreCaseInsensitiveAndComplete(t *testing.T) {
	for _, name := range []string{
		"a.js", "a.jsx", "a.ts", "a.tsx", "a.mjs", "a.cjs", "a.mts", "a.cts", "a.es6", "a.vue",
		"APP.JS", "Server.TS", "x.MTS", "x.CTS", "x.Es6", "Comp.JSX", "page.VUE", "dir/Mixed.MjS",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, name, `eval(userCode);`+"\n")
			got, _ := Scan(dir, AllRules())
			if len(got) != 1 || got[0].RuleID != "JS_EVAL_LITERAL" {
				t.Errorf("%s: findings %v, want JS_EVAL_LITERAL", name, eps(got))
			}
		})
	}
}

func TestScan_OtherSourceExtensionsAreCaseInsensitive(t *testing.T) {
	cases := map[string]string{
		"Main.GO":        "package main\n\nconst k = \"AKIA" + "ZXCVBNMASDFGHJKL\"\n",
		"DOCKERFILE":     "FROM alpine:latest\nRUN echo hi\n",
		"dockerfile":     "FROM alpine:latest\nRUN echo hi\n",
		"App.DOCKERFILE": "FROM alpine:latest\nRUN echo hi\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, name, content)
			if got, _ := Scan(dir, AllRules()); len(got) == 0 {
				t.Errorf("%s: no finding", name)
			}
		})
	}
	dir := t.TempDir()
	writeFile(t, dir, "K8S.YAML", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: a\n    image: x\n    securityContext:\n      privileged: true\n")
	if got, _ := Scan(dir, AllRules()); len(got) == 0 {
		t.Errorf("K8S.YAML: no finding")
	}
	for _, p := range []string{"a.go", "a.GO"} {
		if !HasGoExtension(p) {
			t.Errorf("HasGoExtension(%s) = false", p)
		}
	}
	if HasJSExtension("a.jsonl") || HasJSExtension("a.json") || HasJSExtension("a.scss") || HasJSExtension("mts") {
		t.Errorf("HasJSExtension accepted a non-JavaScript name")
	}
}

// A forged .git is ordinary content: only <root>/.git with HEAD, objects/ and
// refs/ is skipped (C6).
func TestScan_OnlyTheRootGitDirectoryWithARealLayoutIsSkipped(t *testing.T) {
	dir := t.TempDir()
	// Real: skipped.
	writeFile(t, dir, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, dir, ".git/refs/heads/main", "0\n")
	writeFile(t, dir, ".git/objects/pack/p", "x")
	writeFile(t, dir, ".git/hooks/pre-commit.js", `eval(userCode);`+"\n")
	// Forged: a nested .git, a .git without refs/, an objects directory.
	writeFile(t, dir, "sub/.git/HEAD", "ref: x\n")
	writeFile(t, dir, "sub/.git/refs/heads/m", "0\n")
	writeFile(t, dir, "sub/.git/objects/x", "x")
	writeFile(t, dir, "sub/.git/hooks/h.js", `eval(userCode);`+"\n")
	writeFile(t, dir, "objects/y.js", `eval(userCode);`+"\n")
	got, _ := Scan(dir, AllRules())
	var seen []string
	for _, e := range eps(got) {
		seen = append(seen, e)
	}
	joined := strings.Join(seen, " ")
	if strings.Contains(joined, " .git/hooks") || strings.HasPrefix(joined, "JS_EVAL_LITERAL @ .git/hooks") {
		t.Errorf("the real root .git was scanned: %v", seen)
	}
	for _, want := range []string{"sub/.git/hooks/h.js:1", "objects/y.js:1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s was skipped but is ordinary content: %v", want, seen)
		}
	}
}
