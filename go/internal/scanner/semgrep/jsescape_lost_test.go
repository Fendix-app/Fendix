package semgrep

import (
	"strings"
	"testing"
)

// Release Closure Sprint, WS-C2, R6-E7a. A JavaScript or TypeScript file that
// spells an identifier with a unicode escape (`\u0065val(x)`) is run by the
// runtime as `eval(x)` but matched by no Semgrep pattern: the file is lost
// evaluation, recorded as "not parsed" (the existing reason, no new enum), and
// it stays a target so what Semgrep does find in it is reported. An escape in a
// string, a template's text, a regular expression, a comment or JSX text is not
// an identifier and costs nothing.
func TestAnEscapedIdentifierInJavaScriptIsLostEvaluation(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"app.js":        "router.post('/x', (req, res) => { \\u0065val(req.body.code); });\n",
		"dot.ts":        "const w: any = window; w.\\u0065val(code);\n",
		"view.jsx":      "export const V = () => <div>{\\u0065val(code)}</div>;\n",
		"mod.mjs":       "import cp from 'node:child_process'; cp.\\u0065xec(cmd);\n",
		"cjs.cjs":       "\\u0065xec(cmd);\n",
		"comp.tsx":      "export const C = () => <b>{x}</b>; \\u{65}val(code);\n",
		"esm.mts":       "const \\u0066 = 7;\n",
		"cts.cts":       "x.\\u0063all();\n",
		"UPPER.JS":      "\\u0065val(code);\n",
		"es6.es6":       "\\u0065val(code);\n",
		"sub/nested.js": "const a = 8 / 2 / \\u0065val(code);\n",
		// These hold escapes and not one in identifier position.
		"ok_regex.js":   "const re = /[^\\u00C0-\\u1FFF]/; const n = a / b / c;\n",
		"ok_string.ts":  "const s = '\\u0041' + \"\\u{42}\";\n",
		"ok_tpl.js":     "const t = `\\u0041 ${ x } \\u0042`;\n",
		"ok_comment.js": "// \\u0041\n/* \\u0042 */\nvar a;\n",
		"ok_jsx.jsx":    "export const V = () => <p>don't \\u0041 it's</p>;\n",
		"plain.js":      "var a = 1;\n",
		"ok_hash.js":    "#!/usr/bin/env node \\u0041\nvar a;\n",
		"notjs.json":    "{\"a\": \"\\u0041\"}\n",
		"notes.md":      "\\u0065val(x)\n",
	})
	targets := inScopeTargets(root, nil)
	lost := " " + strings.Join(targets.Coverage.NotParsedNames(), " ") + " "
	for _, want := range []string{"app.js", "dot.ts", "view.jsx", "mod.mjs", "cjs.cjs", "comp.tsx", "esm.mts", "cts.cts", "UPPER.JS", "es6.es6", "sub/nested.js"} {
		if !strings.Contains(lost, " "+want+" ") {
			t.Errorf("%s spells an identifier with a unicode escape and is not recorded lost evaluation: %q", want, lost)
		}
	}
	for _, ok := range []string{"ok_regex.js", "ok_string.ts", "ok_tpl.js", "ok_comment.js", "ok_jsx.jsx", "plain.js", "ok_hash.js", "notjs.json", "notes.md"} {
		if strings.Contains(lost, " "+ok+" ") {
			t.Errorf("%s holds no escape in identifier position and must not be recorded lost: %q", ok, lost)
		}
	}
	// A lost file is still a target: Semgrep reports what it finds in it.
	if !strings.Contains(" "+strings.Join(targets.files, " ")+" ", " app.js ") {
		t.Errorf("app.js is no longer a target: %v", targets.files)
	}
	if !targets.Coverage.Lost() {
		t.Error("coverage reads complete")
	}
}
