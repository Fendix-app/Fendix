package textscan

import (
	"context"
	"strings"
	"testing"
)

// Release Closure Sprint, WS-C2, R6-E7b. textscan's Java rules read a line at a
// time with no unicode translation, so a Java file whose statement is hidden
// behind a structural unicode escape (a line terminator, a quote, a backslash, a
// slash or an asterisk; JLS 3.3) is lost evaluation under the existing
// "unreadable" reason; a file whose escapes are not structural, or that has an
// even number of backslashes before the u, costs nothing.
func TestAStructuralUnicodeEscapeInJavaIsLostEvaluationForTextscan(t *testing.T) {
	bs := "\\"
	root := t.TempDir()
	lostFiles := map[string]string{
		"A.java":     "class A { void f(String h) throws Exception {\n  // " + bs + "u000a Runtime.getRuntime().exec(h);\n} }\n",
		"B.java":     "class B { void f() { String s = \"a" + bs + "u0022; run(); String t = \"b\"; } }\n",
		"C.java":     "class C { /* x *" + bs + "u002f run(); /* y */ }\n",
		"sub/D.JAVA": "class D { char c = 'a" + bs + "u0027; run(); char d = 'b'; }\n",
		"F.java":     "class F { // " + bs + bs + bs + "u000d run();\n}\n",
	}
	cleanFiles := map[string]string{
		"ok_even.java":   "class G { // " + bs + bs + "u000a run();\n}\n",
		"ok_letter.java": "class H { String s = \"" + bs + "u0041\"; int ex" + bs + "u0065c; }\n",
		"ok_plain.java":  "class I { void f(String h) throws Exception { Runtime.getRuntime().exec(h); } }\n",
		"notjava.kt":     "// " + bs + "u000a run()\n",
		"Dockerfile":     "FROM scratch\n",
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
			t.Errorf("%s holds a structural unicode escape and is not recorded lost evaluation: %s", rel, listing)
		}
	}
	for rel := range cleanFiles {
		if strings.Contains(listing, rel) {
			t.Errorf("%s holds no structural unicode escape and must not be recorded lost: %s", rel, listing)
		}
	}
	for _, e := range cov.Limitations("textscan") {
		if !strings.HasPrefix(e, "textscan: lost evaluation, unreadable: ") {
			t.Errorf("entry %q is not under the existing unreadable reason", e)
		}
	}
}
