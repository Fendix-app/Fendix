package semgrep

import (
	"strings"
	"testing"
)

// Release Closure Sprint, WS-C2, R6-E7b. JLS 3.3 translates unicode escapes
// before a Java program is lexed: `// <LF escape> Runtime.getRuntime().exec(cmd);`
// is a comment and a statement. A Java file with an escape that translates to a
// line terminator, a quote, a backslash, a slash or an asterisk is lost
// evaluation ("not parsed", the existing reason, no new enum) and stays a target.
func TestAStructuralUnicodeEscapeInJavaIsLostEvaluation(t *testing.T) {
	bs := "\\"
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"A.java":          "class A { void f(String h) throws Exception {\n  // " + bs + "u000a Runtime.getRuntime().exec(h);\n} }\n",
		"B.java":          "class B { void f() { String s = \"a" + bs + "u0022; run(); String t = \"b\"; } }\n",
		"C.java":          "class C { /* x *" + bs + "u002f run(); /* y */ }\n",
		"sub/D.JAVA":      "class D { char c = 'a" + bs + "u0027; run(); char d = 'b'; }\n",
		"E.java":          "class E { String s = \"" + bs + "u005c\"\" + x; }\n",
		"F.java":          "class F { // " + bs + bs + bs + "u000d run();\n}\n",
		"ok_even.java":    "class G { // " + bs + bs + "u000a run();\n}\n",
		"ok_letter.java":  "class H { String s = \"" + bs + "u0041\"; int ex" + bs + "u0065c; }\n",
		"ok_plain.java":   "class I { void f(String h) throws Exception { Runtime.getRuntime().exec(h); } }\n",
		"ok_string.java":  "class J { String s = \"a" + bs + "n" + bs + "t" + bs + "\" + " + bs + bs + "\"; }\n",
		"notjava.kt":      "// " + bs + "u000a run()\n",
		"notes.md":        "// " + bs + "u000a run()\n",
		"ok_illegal.java": "class K { // " + bs + "u00zz\n}\n",
	})
	targets := inScopeTargets(root, nil)
	lost := " " + strings.Join(targets.Coverage.NotParsedNames(), " ") + " "
	for _, want := range []string{"A.java", "B.java", "C.java", "sub/D.JAVA", "E.java", "F.java"} {
		if !strings.Contains(lost, " "+want+" ") {
			t.Errorf("%s holds a structural unicode escape and is not recorded lost evaluation: %q", want, lost)
		}
	}
	for _, ok := range []string{"ok_even.java", "ok_letter.java", "ok_plain.java", "ok_string.java", "notjava.kt", "notes.md", "ok_illegal.java"} {
		if strings.Contains(lost, " "+ok+" ") {
			t.Errorf("%s holds no structural unicode escape and must not be recorded lost: %q", ok, lost)
		}
	}
	if !strings.Contains(" "+strings.Join(targets.files, " ")+" ", " A.java ") {
		t.Errorf("A.java is no longer a target: %v", targets.files)
	}
}
