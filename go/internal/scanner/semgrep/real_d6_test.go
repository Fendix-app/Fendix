package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decisions D6' and D1' against the real Semgrep: the --exclude patterns the
// engine builds name exactly the paths it declared, and the parse outcomes
// are the ones the real parser produces. Skipped without semgrep on PATH.

func realRun(t *testing.T, root string) Run {
	t.Helper()
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	return run
}

func endpoints(run Run) map[string]bool {
	out := map[string]bool{}
	for _, f := range run.Findings {
		out[f.Endpoint] = true
	}
	return out
}

// redteam3-d6-04 end to end: first-party code that only has a build-output
// name is evaluated and reported; installed and minified trees that hold the
// evidence are left out, listed, and not a gap.
func TestRealSemgrepEvaluatesFirstPartyCodeWithABuildOutputName(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"routes.min.js":                   spikeApp,
		"vendor/app/routes.js":            spikeApp,
		"dist/api.js":                     spikeApp,
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/dep/index.js":       spikeApp,
		"static/bundle.js":                minifiedJS(),
		"lib/jquery.js":                   vendoredJQuery(),
		"env[1]/pyvenv.cfg":               "home = /usr/bin\n",
		"env[1]/lib/y.py":                 picklePy,
		"a b/pyvenv.cfg":                  "home = /usr/bin\n",
		"a b/lib/z.py":                    picklePy,
		"star*/pyvenv.cfg":                "home = /usr/bin\n",
		"star*/lib/w.py":                  picklePy,
		"src/app.py":                      picklePy,
	})
	run := realRun(t, root)
	seen := endpoints(run)
	for _, want := range []string{"routes.min.js:9", "vendor/app/routes.js:9", "dist/api.js:9", "src/app.py:5"} {
		if !seen[want] {
			t.Errorf("%s was not evaluated: %v", want, seen)
		}
	}
	for ep := range seen {
		for _, left := range []string{"node_modules/", "lib/jquery.js", "env[1]/", "a b/", "star*/"} {
			if strings.HasPrefix(ep, left) {
				t.Errorf("%s was evaluated, but is declared out of scope", ep)
			}
		}
	}
	if run.Coverage.Lost() {
		t.Errorf("declared exclusions are not a gap: %s", run.Coverage.LostDetail(1<<20))
	}
	declared := run.Coverage.DeclaredDetail(1 << 20)
	for _, want := range []string{"installed npm packages 1 (node_modules/)", "vendored library 1 (lib/jquery.js)", "minified 1 (static/bundle.js)", "python virtualenv 3 (a b/, env[1]/, star*/)"} {
		if !strings.Contains(declared, want) {
			t.Errorf("declared %q lacks %q", declared, want)
		}
	}
}

// D1' on the real parser. Java reports a bare "Syntax error" and runs no rule on
// the file; Python skips the rest of a class after one error, which the span
// says; one unsupported token skips one token.
func TestRealSemgrepParseOutcomes(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"Bad.java": "class A { void f( {{{ }\n",
		"p3.py":    "import os\nclass A:\n    def f(self, x:\n        os.system(x)\n    def g(self):\n        os.popen(\"a\")\nlast(\"z\")\n",
		"one.py":   "import os\n" + strings.Repeat("x = 1\n", 60) + "y = = 2\n" + strings.Repeat("z = 3\n", 60) + "os.system(input())\n",
		"fine.py":  picklePy,
	})
	run := realRun(t, root)
	lost := run.Coverage.LostDetail(1 << 20)
	for _, want := range []string{"Bad.java", "p3.py"} {
		if !strings.Contains(lost, want) {
			t.Errorf("%s is not listed lost: %q", want, lost)
		}
	}
	for _, left := range []string{"one.py", "fine.py"} {
		if strings.Contains(lost, left) {
			t.Errorf("%s is listed lost: %q", left, lost)
		}
	}
	var bad bool
	for _, f := range run.ParseFailures {
		if f.Path == "Bad.java" && f.Type == "Syntax error" {
			bad = true
		}
	}
	if !bad {
		t.Errorf("ParseFailures = %+v; want Bad.java as a Syntax error", run.ParseFailures)
	}
	var one *PartialParse
	for i := range run.PartialParses {
		if run.PartialParses[i].Path == "one.py" {
			one = &run.PartialParses[i]
		}
	}
	if one == nil || one.Lost || one.Skipped != 1 || one.Total != 123 {
		t.Errorf("one.py partial parse = %+v; want one line skipped of 123, not lost", one)
	}
	// What the rest of one.py says was still evaluated: the call after the
	// unsupported token is reported.
	if !endpoints(run)["one.py:123"] {
		t.Errorf("one.py:123 was not evaluated after the skipped token: %v", endpoints(run))
	}
}

// A --code that is itself a symbolic link is scanned through it, and its
// declared exclusions are listed.
func TestRealSemgrepThroughALinkedRootListsTheExclusions(t *testing.T) {
	real := t.TempDir()
	writeTree(t, real, map[string]string{"app.js": spikeApp, "static/bundle.js": minifiedJS()})
	link := filepath.Join(t.TempDir(), "code")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	run := realRun(t, link)
	if !endpoints(run)["app.js:9"] {
		t.Errorf("findings = %v; want app.js:9", endpoints(run))
	}
	if got := run.Coverage.Names(scope.ReasonMinified); len(got) != 1 || got[0] != "static/bundle.js" {
		t.Errorf("minified = %q; want static/bundle.js", got)
	}
}

// vendoredJQuery is a file a known library's banner, identifier and size
// identify (scope.ClassifyFile: vendored library), with no application code.
func vendoredJQuery() string {
	var b strings.Builder
	b.WriteString("/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n")
	for i := 0; b.Len() < 12<<10; i++ {
		b.WriteString("function jQuery_helper" + strings.Repeat("x", i%7) + "(a, b) { return jQuery.fn(a, b); }\n")
	}
	return b.String()
}

// redteam4-d6-01, DE4-01: a first-party file whose header only mentions a library,
// or carries a /*! banner of its own project, is evaluated, not declared a
// vendored library: its SQL injection is reported.
func TestRealSemgrepEvaluatesAFirstPartyFileWhoseHeaderMentionsALibrary(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"chat_routes.js": "// SPDX-License-Identifier: MIT\n// Copyright (c) 2026 Acme Corp\n// Realtime chat routes that sit next to our Socket.IO server.\n" + spikeApp,
		"portal.js":      "/*! acme-portal v2.3.1 | (c) 2026 Acme Corp | MIT License */\n" + spikeApp,
		"lib/jquery.js":  vendoredJQuery(),
	})
	run := realRun(t, root)
	seen := endpoints(run)
	for _, want := range []string{"chat_routes.js:12", "portal.js:10"} {
		if !seen[want] {
			t.Errorf("%s was not evaluated: %v", want, seen)
		}
	}
	if got := run.Coverage.Names(scope.ReasonVendored); len(got) != 1 || got[0] != "lib/jquery.js" {
		t.Errorf("vendored = %q; want only the real library lib/jquery.js", got)
	}
}

// redteam4-d6-02, DE4-04: source with an upper-case extension or one Semgrep
// does not select (.mts) is evaluated through the extensions pass; a Vue
// single-file component, which Semgrep cannot read, is lost evaluation, named,
// and no source file is declared out of scope by its name.
func TestRealSemgrepEvaluatesSourceWhoseExtensionItDoesNotSelect(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"APP.JS":    spikeApp,
		"Server.Py": picklePy,
		"x.mts":     spikeApp,
		"Comp.vue":  "<template><div/></template>\n<script>\nexport default {}\n</script>\n",
	})
	run := realRun(t, root)
	seen := endpoints(run)
	for _, want := range []string{"APP.JS:9", "Server.Py:5", "x.mts:9"} {
		if !seen[want] {
			t.Errorf("%s was not evaluated: %v", want, seen)
		}
	}
	if run.Coverage.DeclaredCount(scope.ReasonNotChosen) != 0 {
		t.Errorf("a source file was declared out of scope by its extension: %v", run.Coverage.Names(scope.ReasonNotChosen))
	}
	lost := run.Coverage.LostDetail(1 << 20)
	if !strings.Contains(lost, "Comp.vue") {
		t.Errorf("Comp.vue, which Semgrep cannot evaluate, is not named lost: %q", lost)
	}
	for _, evaluated := range []string{"APP.JS", "Server.Py", "x.mts"} {
		if strings.Contains(lost, evaluated) {
			t.Errorf("%s was evaluated but is named lost: %q", evaluated, lost)
		}
	}
}

// redteam4-d6-03: test and fixture paths are evaluated; a rule never skips a
// file by where it is.
func TestRealSemgrepEvaluatesTestAndFixturePaths(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"lib/mock/server.js": spikeApp,
		"api/e2e/handler.js": spikeApp,
		"tests/user.test.js": spikeApp,
		"src/__tests__/a.js": spikeApp,
		"src/widget.spec.js": spikeApp,
		"internal/x_test.go": "package x\nimport \"os/exec\"\nfunc f(c string) { exec.Command(\"sh\", \"-c\", c).Run() }\n",
	})
	run := realRun(t, root)
	seen := endpoints(run)
	for _, want := range []string{"lib/mock/server.js:9", "api/e2e/handler.js:9", "tests/user.test.js:9", "src/__tests__/a.js:9", "src/widget.spec.js:9"} {
		if !seen[want] {
			t.Errorf("%s was not evaluated: %v", want, seen)
		}
	}
	if run.Coverage.DeclaredCount(scope.ReasonTestPath) != 0 {
		t.Errorf("a test path was declared out of scope: %v", run.Coverage.Names(scope.ReasonTestPath))
	}
	if run.Coverage.Lost() {
		t.Errorf("lost: %s", run.Coverage.LostDetail(1<<20))
	}
}

// redteam4-semgrep-01: a nosem inside a string literal or as a word prefix does
// not hide a finding; a real comment does, and is listed.
func TestRealSemgrepNosemInAStringLiteralDoesNotSuppress(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a.js": "const express = require(\"express\");\nconst app = express();\nconst db = require(\"./db\");\n" +
			"app.get(\"/a\", (req, res) => {\n  db.query(\"SELECT nosemantic FROM t WHERE id = \" + req.query.id);\n});\n" +
			"app.get(\"/b\", (req, res) => {\n  const z = 'x nosem'; db.query(\"SELECT * FROM t WHERE id = \" + req.query.id);\n});\n" +
			"app.get(\"/c\", (req, res) => {\n  db.query(\"SELECT * FROM t WHERE id = \" + req.query.id); // nosemgrep: js-sqli-taint\n});\n",
	})
	run := realRun(t, root)
	seen := endpoints(run)
	for _, want := range []string{"a.js:5", "a.js:8"} {
		if !seen[want] {
			t.Errorf("%s was hidden by a nosem that is not a comment: %v (suppressed %+v)", want, seen, run.Suppressed)
		}
	}
	var listed bool
	for _, sp := range run.Suppressed {
		if sp.Line == 11 && sp.RuleID == "js-sqli-taint" {
			listed = true
		}
		if sp.Line == 5 || sp.Line == 8 {
			t.Errorf("suppressed %+v, which has no nosemgrep comment", sp)
		}
	}
	if !listed {
		t.Errorf("the real nosemgrep comment on line 11 was not suppressed and listed: %+v", run.Suppressed)
	}
}

// DE4-03: a file whose every line Semgrep's partial parse skipped is lost
// evaluation, not "a few lines".
func TestRealSemgrepAWholeFileSkippedByAPartialParseIsLost(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"d.js":  "const f = function( { app.get(\"/u\", (req, res) => db.query(\"SELECT * FROM t WHERE id = \" + req.query.id) ...\n",
		"ok.js": spikeApp,
	})
	run := realRun(t, root)
	if lost := run.Coverage.LostDetail(1 << 20); !strings.Contains(lost, "d.js") || strings.Contains(lost, "ok.js") {
		t.Errorf("lost = %q; want d.js named and ok.js not", lost)
	}
}
