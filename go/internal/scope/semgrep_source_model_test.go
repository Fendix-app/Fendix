package scope_test

// Round 6, WS-E1: the rest of RC-1 and RC-3 on the Semgrep side.
//
//   - DE5-07: the partial-parse judge (parse.go, spansHoldNoCode/inertLine)
//     calls a skipped line harmless when it starts with "//" or "#", judged
//     alone and on "\n"-split lines. Inside a template literal, an f-string or
//     t-string, a JSX expression container or a Vue interpolation such a line
//     holds executable code, and a bare CR (or, in JS, U+2028/U+2029) ends a
//     comment where "\n" splitting sees one line. Real Semgrep 1.182.1 emits a
//     PartialParsing span on exactly such lines (checked 2026-11-14).
//   - R5-14: excludeUnreadable stops adding --exclude patterns after 512, so
//     Semgrep re-reads the rest, fails to list its targets and loses the run.
//   - R6-E5: excludePattern refuses a name with a control character or invalid
//     UTF-8, or blanks at the ends of the root-relative path, so one such
//     unreadable file is never excluded and can fail the listing on its own.
//
// Both are driven through semgrep.ScanRun with the fake semgrep of
// pep263_vectors_test.go, which honours --exclude as Semgrep does.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// wse1PartialParsing is one Semgrep 1.182.1 "PartialParsing" error entry for the
// file at abs, skipping lines start..end (shape of testdata/runs/syntax2.json).
func wse1PartialParsing(abs string, start, end int) map[string]any {
	s := map[string]any{"line": start, "col": 1, "offset": 0}
	e := map[string]any{"line": end, "col": 2, "offset": 0}
	return map[string]any{
		"code": 3, "level": "warn", "message": "Syntax error", "path": abs,
		"spans": []any{map[string]any{"start": s, "end": e, "file": abs}},
		"type":  []any{"PartialParsing", []any{map[string]any{"start": s, "end": e, "path": abs}}},
	}
}

// DE5-07 and its neighbours (engine review E1-B8). Each file has one skipped
// span on a line that starts with the language's line-comment marker (or is a
// one-line block comment); only the controls are real comments.
func TestPartialParseJudgeSeesTheLanguagesLines(t *testing.T) {
	cases := []struct {
		rel      string
		src      string
		line     int
		wantLost bool
		why      string
	}{
		{"tmpl.js", "const q = `\n// ${eval(req.query.x) @@@ }\n`;\nmodule.exports = q;\n", 2, true,
			"line 2 is inside a template literal: ${eval(...)} is code"},
		{"tblock.js", "const q = `\n/* ${eval(req.query.x) @@@ } */\n`;\nmodule.exports = q;\n", 2, true,
			"a one-line block comment inside a template literal is template text: ${eval(...)} is code"},
		{"jsx.jsx", "export const C = (req) => (\n  <div>\n    // {eval(req.query.x) @@@}\n  </div>\n);\n", 3, true,
			"JSX text: {eval(...)} is an expression container"},
		{"tsx.tsx", "export const C = (req: any) => (\n  <div>\n    // {eval(req.query.x) @@@}\n  </div>\n);\n", 3, true,
			"TSX text: {eval(...)} is an expression container"},
		{"view.vue", "<template>\n  <p>\n  // {{ eval(x) @@@ }}\n  </p>\n</template>\n", 3, true,
			"Vue template text: {{ eval(x) }} is an interpolation"},
		{"cr.js", "var a = 1;\n// note\reval(req.query.x)\n", 2, true, "a bare CR ends a JS line comment: eval(...) is code"},
		{"cr.ts", "let a = 1;\n// note\reval(req.query.x)\n", 2, true, "a bare CR ends a TS line comment: eval(...) is code"},
		{"Cr.java", "class Cr {\n  void f(String c) throws Exception {\n    // note\rRuntime.getRuntime().exec(c);\n  }\n}\n", 3, true,
			"a bare CR ends a Java line comment (JLS 3.4): exec(c) is code"},
		{"ls.js", "// a eval(x)\nvar b = 1;\n", 1, true, "U+2028 ends a JS line comment: eval(x) is code"},
		{"ps.js", "// a eval(x)\nvar b = 1;\n", 1, true, "U+2029 ends a JS line comment: eval(x) is code"},
		{"fstr.py", "import os\nq = f\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside an f-string: {os.system(x)} is code"},
		{"rfstr.py", "import os\nq = rf\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside an rf-string: {os.system(x)} is code"},
		{"frstr.py", "import os\nq = fr\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside an fr-string: {os.system(x)} is code"},
		{"Fstr.py", "import os\nq = F\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside an F-string: {os.system(x)} is code"},
		{"tstr.py", "import os\nq = t\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside a t-string (PEP 750): {os.system(x)} is code"},
		{"trstr.py", "import os\nq = tr\"\"\"\n# {os.system(x) @@@}\n\"\"\"\n", 3, true, "inside a tr-string (PEP 750): {os.system(x)} is code"},
		{"cr.py", "x = 1\n# x\rexec(y)\n", 2, true, "CPython ends the comment at the bare CR: exec(y) is a line of code"},
		{"ctl.js", "var a = 1;\n// just a comment\nvar b = 2;\n", 2, false, "a real comment line"},
		{"ctl.py", "x = 1\n# just a comment\ny = 2\n", 2, false, "a real comment line"},
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var errs []any
	for _, c := range cases {
		p := filepath.Join(root, c.rel)
		wse1WriteFile(t, p, []byte(c.src), 0o644)
		errs = append(errs, wse1PartialParsing(p, c.line, c.line))
	}
	run, _ := wse1RunFakeSemgrep(t, root, nil, errs)
	got := map[string]bool{}
	for _, pp := range run.PartialParses {
		got[pp.Path] = pp.Lost
		t.Logf("partial parse %s: spans %v, lines %d, reported %v, lost %v", pp.Path, pp.Spans, pp.Total, pp.Reported, pp.Lost)
	}
	for _, c := range cases {
		lost, seen := got[c.rel]
		if !seen {
			t.Errorf("%s: no partial parse decoded from the run", c.rel)
			continue
		}
		_, inCov := wse1LostEntry(run.Coverage, c.rel)
		if lost != c.wantLost || inCov != c.wantLost {
			t.Errorf("%s: partial parse Lost=%v, in coverage=%v; want %v (%s)", c.rel, lost, inCov, c.wantLost, c.why)
		}
	}
}

// wse1ExcludedInEveryRun reports whether rel (root-relative, slashes) is named by
// one of the anchored --exclude patterns of every recorded run, itself or
// through an ancestor directory.
func wse1ExcludedInEveryRun(t *testing.T, argvFile, rel string) bool {
	t.Helper()
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("no semgrep run recorded: %v", err)
	}
	seen := 0
	for _, r := range strings.Split(string(raw), "\x00RUN\x00\n") {
		if strings.TrimSpace(r) == "" {
			continue
		}
		seen++
		args := strings.Split(strings.TrimRight(r, "\n"), "\n")
		covered := false
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "--exclude" {
				continue
			}
			pat := strings.TrimPrefix(args[i+1], "/")
			if pat == rel || strings.HasPrefix(rel, strings.TrimSuffix(pat, "/")+"/") {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return seen > 0
}

func wse1SkipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file: the unreadable fixtures need an unprivileged user")
	}
}

const wse1ShellSource = "import subprocess\nfrom flask import request\n\ndef run():\n    subprocess.call(request.args['c'], shell=True)\n"

// R5-14. 513 unreadable Python files: every one must be kept out of Semgrep's
// own listing (one pattern each, or a coalesced ancestor), and every one named
// as lost evaluation. A readable sibling with a finding stays accounted for.
func TestEveryUnreadableEntryIsExcludedPastTheCap(t *testing.T) {
	wse1SkipIfRoot(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wse1WriteFile(t, filepath.Join(root, "ok.py"), []byte("x = 1\n"), 0o644)
	dir := filepath.Join(root, "locked")
	sibling := "locked/readable.py"
	wse1WriteFile(t, filepath.Join(root, sibling), []byte(wse1ShellSource), 0o644)
	const n = 513
	var rels []string
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("f%04d.py", i)
		wse1WriteFile(t, filepath.Join(dir, name), []byte("x = 1\n"), 0o000)
		rels = append(rels, "locked/"+name)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	run, argv := wse1RunFakeSemgrep(t, root, []any{wse1SemgrepResult(filepath.Join(root, sibling), 5)}, nil)
	missing, first := 0, ""
	for _, rel := range rels {
		if !wse1ExcludedInEveryRun(t, argv, rel) {
			if missing == 0 {
				first = rel
			}
			missing++
		}
	}
	if missing > 0 {
		t.Errorf("%d of %d unreadable files are not kept out of Semgrep's listing (first: %s): Semgrep reads them itself and fails the target listing (R5-14)", missing, n, first)
	}
	if lostN := run.Coverage.LostFiles(); lostN < n {
		t.Errorf("Coverage.LostFiles() = %d, want at least %d: every unreadable file is lost evaluation", lostN, n)
	}
	if _, lost := wse1LostEntry(run.Coverage, sibling); !lost && len(wse1FindingsAt(run.Findings, sibling)) == 0 {
		t.Errorf("the readable %s holds a finding and is neither reported nor named lost: excluded silently (E1-B7)", sibling)
	}
}

// R6-E5. One unreadable Python file whose name excludePattern cannot write (a
// control character or invalid UTF-8 anywhere in the path, or blanks at either
// end of the root-relative path) must still be kept out of Semgrep's listing,
// through its nearest patternable ancestor, and named lost. A file directly
// under the root has no ancestor but the root: there the run must say it
// failed (ScanRun returns an error) rather than ask Semgrep to list it. A
// readable sibling with a finding stays accounted for (E1-B7).
// By reading (2026-11-14): a leading blank inside a subdirectory is patternable,
// because the blank test applies to the whole relative path, and "x.py " is not
// a Python file to either Semgrep or the engine.
func TestAnUnpatternableUnreadableNameIsStillExcluded(t *testing.T) {
	wse1SkipIfRoot(t)
	cases := []struct{ dir, name string }{
		{"odd", "ctl\x01.py"},
		{"odd", "bad\xff.py"},
		{"", " lead.py"},
	}
	for _, c := range cases {
		t.Run(strings.ToValidUTF8(c.dir+"/"+c.name, "?"), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			wse1WriteFile(t, filepath.Join(root, "ok.py"), []byte("x = 1\n"), 0o644)
			sibling := "readable.py"
			if c.dir != "" {
				sibling = c.dir + "/readable.py"
			}
			wse1WriteFile(t, filepath.Join(root, sibling), []byte(wse1ShellSource), 0o644)
			if err := os.WriteFile(filepath.Join(root, c.dir, c.name), []byte("x = 1\n"), 0o000); err != nil {
				if runtime.GOOS == "darwin" {
					t.Skipf("this file system refuses the name %q: %v (run on Linux)", c.name, err)
				}
				t.Fatal(err)
			}
			rel := c.name
			if c.dir != "" {
				rel = c.dir + "/" + c.name
			}
			run, argv, err := wse1RunFakeSemgrepErr(t, root, []any{wse1SemgrepResult(filepath.Join(root, sibling), 5)}, nil)
			if err != nil && c.dir == "" {
				return // the root cannot be excluded: the run said it failed
			}
			if err != nil {
				t.Fatalf("ScanRun: %v", err)
			}
			if !wse1ExcludedInEveryRun(t, argv, rel) {
				t.Errorf("unreadable %q is not kept out of Semgrep's listing by any --exclude (itself or an ancestor), and the run did not fail: one such file can fail the listing (R6-E5)", rel)
			}
			if !run.Coverage.Lost() {
				t.Errorf("unreadable %q is not recorded as lost evaluation", rel)
			}
			if _, lost := wse1LostEntry(run.Coverage, sibling); !lost && len(wse1FindingsAt(run.Findings, sibling)) == 0 {
				t.Errorf("the readable %s holds a finding and is neither reported nor named lost: excluded silently (E1-B7)", sibling)
			}
		})
	}
}
