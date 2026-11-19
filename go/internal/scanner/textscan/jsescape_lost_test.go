package textscan

import (
	"context"
	"strings"
	"testing"
)

// Release Closure Sprint, WS-C2, R6-E7a. textscan's JavaScript rules match
// identifiers with regular expressions, so a call spelled with a unicode escape
// in an identifier (`\u0065val(x)`) matches none of them although the runtime
// runs it. The file is lost evaluation, under the existing "unreadable" reason
// with the file named; a regex literal, a string, a template's text, a comment
// or JSX text that holds an escape is not an identifier and costs nothing.
func TestAnEscapedIdentifierInJavaScriptIsLostEvaluationForTextscan(t *testing.T) {
	root := t.TempDir()
	lostFiles := map[string]string{
		"app.js":        "router.post('/x', (req, res) => { \\u0065val(req.body.code); });\n",
		"dot.ts":        "const w: any = window; w.\\u0065val(code);\n",
		"view.jsx":      "export const V = () => <div>{\\u0065val(code)}</div>;\n",
		"mod.mjs":       "import cp from 'node:child_process'; cp.\\u0065xec(cmd);\n",
		"cjs.cjs":       "\\u0065xec(cmd);\n",
		"comp.tsx":      "export const C = () => <b>{x}</b>; \\u{65}val(code);\n",
		"UPPER.JS":      "\\u0065val(code);\n",
		"sub/nested.js": "const a = 8 / 2 / \\u0065val(code);\n",
	}
	cleanFiles := map[string]string{
		"ok_regex.js":   "const re = /[^\\u00C0-\\u1FFF]/; const n = a / b / c;\n",
		"ok_string.ts":  "const s = '\\u0041' + \"\\u{42}\";\n",
		"ok_tpl.js":     "const t = `\\u0041 ${ x } \\u0042`;\n",
		"ok_comment.js": "// \\u0041\n/* \\u0042 */\nvar a;\n",
		"ok_jsx.jsx":    "export const V = () => <p>don't \\u0041 it's</p>;\n",
		"plain.js":      "var a = 1;\n",
		"notjs.json":    "{\"a\": \"\\u0041\"}\n",
		"notes.md":      "\\u0065val(x)\n",
		"Dockerfile":    "FROM scratch\n",
	}
	for rel, body := range lostFiles {
		writeFile(t, root, rel, body)
	}
	for rel, body := range cleanFiles {
		writeFile(t, root, rel, body)
	}
	_, cov, err := ScanCoverage(context.Background(), root, AllRules(), nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if !cov.Lost() {
		t.Fatal("coverage reads complete")
	}
	listing := " " + strings.Join(cov.Limitations("textscan"), " | ") + " "
	for rel := range lostFiles {
		if !strings.Contains(listing, rel) {
			t.Errorf("%s spells an identifier with a unicode escape and is not recorded lost evaluation: %s", rel, listing)
		}
	}
	for rel := range cleanFiles {
		if strings.Contains(listing, rel) {
			t.Errorf("%s holds no escape in identifier position and must not be recorded lost: %s", rel, listing)
		}
	}
	for _, e := range cov.Limitations("textscan") {
		if !strings.HasPrefix(e, "textscan: lost evaluation, unreadable: ") {
			t.Errorf("entry %q is not under the existing unreadable reason", e)
		}
	}
}
