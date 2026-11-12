package semgrep

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// redteam3-semgrep-01: a nosemgrep comment is applied by the engine and every
// result it removes is reported. The engine's reading is a subset of Semgrep's.

func TestNosemgrepReading(t *testing.T) {
	const rule = "tmp.fendix-semgrep-rules-1.js-sqli-taint"
	for _, tc := range []struct {
		name        string
		first, prev string
		want        bool
	}{
		{"bare comment", "danger(1)  # nosemgrep", "", true},
		{"slash comment", "danger(1); // nosemgrep", "", true},
		{"short form", "danger(8)  # nosem", "", true},
		{"upper case", "danger(9)  # NOSEMGREP", "", true},
		{"names the rule", "danger(2)  # nosemgrep: js-sqli-taint", "", true},
		{"names the full id", "danger(3)  # nosemgrep: " + rule, "", true},
		{"names another rule", "danger(12) # nosemgrep: other-rule", "", false},
		{"names a partial id", "danger(4)  # nosemgrep: ql-taint", "", false},
		{"a suffix not at a dot", "danger(5)  # nosemgrep: taint", "", true}, // "...js-sqli-taint" ends with ".js-sqli-taint" only
		{"list with the rule", "danger(6)  # nosemgrep: other,js-sqli-taint", "", true},
		{"no space after the colon", "danger(7)  # nosemgrep:js-sqli-taint", "", true},
		{"space before the colon names nothing", "danger(11) # nosemgrep : other", "", true},
		{"two ids split by a blank name only the first", "danger(13) # nosemgrep: other js-sqli-taint", "", false},
		{"trailing comma", "danger(14)  # nosemgrep: js-sqli-taint,", "", true},
		{"no blank before nosem", "danger(10) #nosemgrep", "", false},
		{"a word before nosem", "danger(23) # xnosemgrep", "", false},
		{"previous comment line", "danger(15)", "# nosemgrep", true},
		{"previous slash comment", "danger(26)", "// nosemgrep", true},
		{"previous sql comment", "danger(27)", "-- nosemgrep", true},
		{"previous indented comment", "danger(19)", "    # nosemgrep", true},
		{"previous no space", "danger(18)", "#nosemgrep", true},
		{"previous names the rule", "danger(17)", "# nosemgrep: js-sqli-taint", true},
		{"previous names another", "danger(17)", "# nosemgrep: other", false},
		{"previous line is code", "danger(16)", "x = 1  # nosemgrep", false},
		{"previous line is code with a word", "danger(16)", "print('nosemgrep')", false},
		{"no comment at all", "danger(0)", "x = 1", false},
	} {
		got := nosemSuppresses(rule, tc.first, tc.prev, syntaxAny, 0)
		if tc.name == "a suffix not at a dot" {
			// "taint" is not a dot-delimited suffix of the id: the id ends in
			// "js-sqli-taint", whose last dot-component is the whole of it.
			tc.want = false
		}
		if got != tc.want {
			t.Errorf("%s: nosemSuppresses(%q, %q) = %v, want %v", tc.name, tc.first, tc.prev, got, tc.want)
		}
	}
}

func TestSplitSuppressedReportsEveryResultItRemoves(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.py": "danger(1)  # nosemgrep\ndanger(2)\n# nosemgrep: r\ndanger(3)\ndanger(4)  # nosemgrep: other\n"})
	at := func(line int) semgrepResult {
		return semgrepResult{CheckID: "tmp.fendix-semgrep-rules-1.r", Path: filepath.Join(root, "a.py"), Start: semgrepLineCol{Line: line}}
	}
	kept, suppressed := splitSuppressed([]semgrepResult{at(1), at(2), at(4), at(5), at(99)}, root)
	var gotKept, gotSupp []int
	for _, r := range kept {
		gotKept = append(gotKept, r.Start.Line)
	}
	for _, s := range suppressed {
		gotSupp = append(gotSupp, s.Line)
		if s.RuleID != "r" || s.Path != "a.py" {
			t.Errorf("suppressed %+v; want rule r in a.py", s)
		}
	}
	// Line 4 follows the comment on line 3; line 5 names another rule; line 99
	// is beyond the file and is kept.
	if len(gotSupp) != 2 || gotSupp[0] != 1 || gotSupp[1] != 4 {
		t.Errorf("suppressed lines = %v, want [1 4]", gotSupp)
	}
	if len(gotKept) != 3 || gotKept[0] != 2 || gotKept[1] != 5 || gotKept[2] != 99 {
		t.Errorf("kept lines = %v, want [2 5 99]", gotKept)
	}
}

// The comment is read only from files inside the root, and only up to the size
// cap; a result the engine cannot read a line for is kept.
func TestSplitSuppressedKeepsWhatItCannotRead(t *testing.T) {
	root := t.TempDir()
	r := semgrepResult{CheckID: "x.r", Path: filepath.Join(root, "missing.py"), Start: semgrepLineCol{Line: 1}}
	kept, suppressed := splitSuppressed([]semgrepResult{r}, root)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Errorf("kept %d suppressed %d; a result whose file cannot be read is kept", len(kept), len(suppressed))
	}
}

// Real Semgrep: the engine's reading against Semgrep's own, over the embedded
// pack. Every result the engine reports as suppressed is one the default
// (nosem-honouring) run drops, and every result the default run reports is one
// the engine keeps. The reverse (Semgrep drops, the engine keeps) is allowed:
// the engine's reading is a subset, and a kept result is reported as a finding.
func TestRealSemgrepNosemgrepAgreesWithTheEnginesReading(t *testing.T) {
	bin := requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	root := t.TempDir()
	// python-command-injection-shell-true fires on os.system(input()).
	cases := []string{
		"os.system(input())  # nosemgrep",
		"os.system(input())  # nosemgrep: python-command-injection-shell-true",
		"os.system(input())  # nosemgrep: other-rule",
		"os.system(input())  # nosemgrep: other,python-command-injection-shell-true",
		"os.system(input())  # nosemgrep:python-command-injection-shell-true",
		"os.system(input())  # NOSEMGREP",
		"os.system(input())  #nosemgrep",
		"os.system(input())  # xnosemgrep",
		"# nosemgrep\nos.system(input())",
		"# nosemgrep: other-rule\nos.system(input())",
		"x = 1  # nosemgrep\nos.system(input())",
		"os.system(\n    input())  # nosemgrep",
		"os.system(input())",
	}
	var src strings.Builder
	src.WriteString("import os\n")
	for _, c := range cases {
		src.WriteString(c + "\n\n")
	}
	writeTree(t, root, map[string]string{"a.py": src.String()})

	run, err := ScanRun(t.Context(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	kept := map[string]bool{}
	for _, f := range run.Findings {
		if f.RuleID == "python-command-injection-shell-true" {
			kept[f.Endpoint] = true
		}
	}
	supp := map[string]bool{}
	for _, s := range run.Suppressed {
		if s.RuleID == "python-command-injection-shell-true" {
			supp["a.py:"+strconv.Itoa(s.Line)] = true
		}
	}

	rules, release, err := acquireRules()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cmd := exec.Command(bin, "--config", rules, "--json", "--quiet", "--disable-version-check", "--no-git-ignore",
		"--x-ignore-semgrepignore-files", "--project-root", root, root)
	cmd.Env = append(os.Environ(), "SEMGREP_ENABLE_VERSION_CHECK=0", "SEMGREP_SEND_METRICS=off")
	out, _ := cmd.Output()
	def, _ := decodeEnvelope(out)
	if def == nil {
		t.Fatalf("default semgrep run produced no document: %s", out)
	}
	semgrepKept := map[string]bool{}
	for _, r := range def.Results {
		if strings.HasSuffix(r.CheckID, "python-command-injection-shell-true") {
			semgrepKept["a.py:"+strconv.Itoa(r.Start.Line)] = true
		}
	}
	var wrong []string
	for ep := range supp {
		if semgrepKept[ep] {
			wrong = append(wrong, "engine suppressed what Semgrep reports: "+ep)
		}
	}
	for ep := range semgrepKept {
		if !kept[ep] {
			wrong = append(wrong, "Semgrep reports, the engine dropped: "+ep)
		}
	}
	sort.Strings(wrong)
	if len(wrong) > 0 {
		t.Errorf("disagreement with Semgrep's own nosemgrep:\n%s\n(engine kept %v, suppressed %v; semgrep kept %v)", strings.Join(wrong, "\n"), kept, supp, semgrepKept)
	}
	if len(supp) == 0 {
		t.Error("no result was suppressed: the comments were not read")
	}
	// Nothing disappears: kept + suppressed is every result of the run.
	if len(kept)+len(supp) < len(semgrepKept)+len(supp) {
		t.Errorf("kept %d + suppressed %d lose results", len(kept), len(supp))
	}
}

// redteam4-semgrep-01: only a real comment, with the token whole, suppresses.
// Semgrep itself reads " nosem" anywhere on the line (a string literal and a
// word prefix included); a finding hidden that way is a finding lost, so the
// engine, which now applies the comment itself, does not.
func TestNosemgrepIsReadOnlyFromARealCommentWithAWholeToken(t *testing.T) {
	const rule = "tmp.fendix-semgrep-rules-1.js-sqli-taint"
	for _, tc := range []struct {
		name  string
		cs    commentSyntax
		first string
		prev  string
		col   int
		want  bool
	}{
		{"word prefix in a string", syntaxC, `db.query("SELECT nosemantic FROM t WHERE id = " + req.query.id);`, "", 1, false},
		{"nosem as a word in a string", syntaxC, `const z = 'x nosem'; db.query("a" + req.query.id);`, "", 1, false},
		{"nosemgrep in a string", syntaxC, `db.query("a nosemgrep " + req.query.id);`, "", 1, false},
		{"opener inside a string is not a comment", syntaxC, `db.query("http://x nosemgrep" + req.query.id);`, "", 1, false},
		{"template literal", syntaxC, "db.query(`// nosemgrep ${req.query.id}`);", "", 1, false},
		{"real trailing comment", syntaxC, `db.query("a" + req.query.id); // nosemgrep`, "", 1, true},
		{"real block comment", syntaxC, `db.query("a" + req.query.id); /* nosemgrep: js-sqli-taint */`, "", 1, true},
		{"nosem short form in a comment", syntaxC, `db.query("a" + id); // nosem`, "", 1, true},
		{"word prefix in a comment", syntaxC, `db.query("a" + id); // nosemantic reasons`, "", 1, false},
		{"hyphenated in a comment", syntaxC, `db.query("a" + id); // nosem-this`, "", 1, false},
		{"no blank before the token", syntaxC, `db.query("a" + id); //nosemgrep`, "", 1, false},
		{"comment before the match starts", syntaxC, `/* nosemgrep */ db.query("a" + req.query.id);`, "", 17, false},
		{"python hash in a string", syntaxPython, `cur.execute("x # nosemgrep " + y)`, "", 1, false},
		{"python real comment", syntaxPython, `cur.execute("x" + y)  # nosemgrep`, "", 1, true},
		{"python slashes are not a comment", syntaxPython, `z = a // nosemgrep`, "", 1, false},
		{"python triple string", syntaxPython, `q = """ # nosemgrep """ + y`, "", 1, false},
		{"js hash is not a comment", syntaxC, `this.#a(); db.query("a" + id); # nosemgrep`, "", 1, false},
		{"previous comment line", syntaxC, "db.query(a + b)", "// nosemgrep", 1, true},
		{"previous block comment", syntaxC, "db.query(a + b)", "/* nosemgrep: js-sqli-taint */", 1, true},
		{"previous line mentions nosem later", syntaxC, "db.query(a + b)", "// we do not use nosemgrep here", 1, false},
		{"previous line is a prefix word", syntaxC, "db.query(a + b)", "// nosemantic", 1, false},
		{"previous line is code with a string", syntaxC, "db.query(a + b)", `x = "// nosemgrep"`, 1, false},
		{"names another rule", syntaxC, `db.query(a); // nosemgrep: other-rule`, "", 1, false},
	} {
		if got := nosemSuppresses(rule, tc.first, tc.prev, tc.cs, tc.col); got != tc.want {
			t.Errorf("%s: nosemSuppresses(%q, %q) = %v, want %v", tc.name, tc.first, tc.prev, got, tc.want)
		}
	}
}
