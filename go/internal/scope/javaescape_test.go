package scope_test

// Release Closure Sprint, WS-C2, R6-E7b: a Java file with a unicode escape that
// translates to a line terminator, a quote, a backslash, a slash or an asterisk is
// lost evaluation. JLS 3.3 translates unicode escapes before the program is
// lexed, so `// <LF escape> Runtime.getRuntime().exec(cmd);` is a comment and a
// statement; an analyzer that does not translate sees only the comment.
//
// The vectors in testdata/javaescape_vectors.json are written by
// testdata/gen_javaescape_vectors.py and each carries what a real JDK did with
// the file (`jdk_hidden_ran`). `expect` is the rule; a vector whose hidden
// statement ran must expect a loss.

import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

type javaVector struct {
	ID           string   `json:"id"`
	Note         string   `json:"note"`
	Text         string   `json:"text"`
	Expect       bool     `json:"expect"`
	JDKCompiled  bool     `json:"jdk_compiled"`
	JDKOutput    []string `json:"jdk_output"`
	JDKHiddenRan bool     `json:"jdk_hidden_ran"`
}

type javaVectorFile struct {
	Schema int `json:"schema"`
	JDK    struct {
		Image   string `json:"image"`
		Version string `json:"version"`
	} `json:"jdk"`
	Vectors []javaVector `json:"vectors"`
}

func loadJavaVectors(t *testing.T) javaVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/javaescape_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc javaVectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestJavaEscapeVectorFileIsFromARealJDK(t *testing.T) {
	doc := loadJavaVectors(t)
	if doc.Schema != 1 || !strings.Contains(doc.JDK.Version, "openjdk") || doc.JDK.Image == "" {
		t.Fatalf("ground truth must come from a real JDK, got %+v", doc.JDK)
	}
	hidden, expectTrue, expectFalse := 0, 0, 0
	for _, v := range doc.Vectors {
		if v.JDKHiddenRan {
			hidden++
			if !v.Expect {
				t.Errorf("%s: the JDK ran its hidden statement and the vector expects it clean", v.ID)
			}
		}
		if v.Expect {
			expectTrue++
		} else {
			expectFalse++
		}
	}
	if hidden < 12 || expectTrue < 20 || expectFalse < 12 {
		t.Errorf("%d vectors ran a hidden statement, %d expect a loss, %d expect none: the file lost vectors", hidden, expectTrue, expectFalse)
	}
}

func TestJavaStructuralEscapeAgreesWithTheRuleOnEveryVector(t *testing.T) {
	for _, v := range loadJavaVectors(t).Vectors {
		t.Run(v.ID, func(t *testing.T) {
			got := scope.JavaStructuralEscape([]byte(v.Text))
			if got.Lost() != v.Expect {
				t.Errorf("%s (%s; JDK ran hidden=%v): lost=%v offset=%d, want %v\n%s", v.ID, v.Note, v.JDKHiddenRan, got.Lost(), got.Offset, v.Expect, v.Text)
			}
			if v.Expect && got.Lost() && (got.Offset < 0 || got.Offset >= len(v.Text) || v.Text[got.Offset] != '\\') {
				t.Errorf("%s: offset %d is not the backslash of the escape", v.ID, got.Offset)
			}
		})
	}
}

// The JLS 3.3 edge cases, spelled out: the structural characters, the number of
// u letters, hex case, and the even-backslash rule.
func TestJavaStructuralEscapeFollowsJLS33(t *testing.T) {
	bs := "\\"
	for _, tc := range []struct {
		name, src string
		lost      bool
	}{
		{"LF", "// " + bs + "u000a x", true},
		{"LF upper", "// " + bs + "u000A x", true},
		{"CR", "// " + bs + "u000d x", true},
		{"CR upper", "// " + bs + "u000D x", true},
		{"double quote", "\"a" + bs + "u0022", true},
		{"single quote", "'a" + bs + "u0027", true},
		{"backslash", "\"" + bs + "u005c\"", true},
		{"backslash upper hex", "\"" + bs + "u005C\"", true},
		{"slash", "*" + bs + "u002f", true},
		{"slash upper hex", "*" + bs + "u002F", true},
		{"asterisk", bs + "u002a/", true},
		{"asterisk upper hex", bs + "u002A/", true},
		{"two u", bs + "uu000a", true},
		{"eight u", bs + "uuuuuuuu000a", true},
		{"3 backslashes", bs + bs + bs + "u000a", true},
		{"5 backslashes", strings.Repeat(bs, 5) + "u000a", true},
		{"2 backslashes", bs + bs + "u000a", false},
		{"4 backslashes", strings.Repeat(bs, 4) + "u000a", false},
		{"6 backslashes", strings.Repeat(bs, 6) + "u000a", false},
		{"a backslash and text before", "x" + bs + bs + "y" + bs + "u000a", true},
		{"even then another text then escape", bs + bs + "x" + bs + "u000a", true},
		{"letter", bs + "u0041", false},
		{"space", bs + "u0020", false},
		{"identifier letter", "ex" + bs + "u0065c", false},
		{"paren", bs + "u0028", false},
		{"semicolon", bs + "u003b", false},
		{"tab", bs + "u0009", false},
		{"vertical tab and form feed", bs + "u000b" + bs + "u000c", false},
		{"nel and ls", bs + "u0085" + bs + "u2028" + bs + "u2029", false},
		{"upper U", bs + "U000a", false},
		{"short escape", bs + "u00a", false},
		{"truncated at the end", "x" + bs + "u00", false},
		{"non-hex digit", bs + "u00zz", false},
		{"non-hex in the first digit", bs + "u000g", false},
		{"no digits", bs + "u ", false},
		{"backslash n", bs + "n", false},
		{"empty", "", false},
		{"escape right after an escape for a backslash", bs + "u005c" + bs + "u000a", true},
		{"two escapes then LF", bs + "u0041" + bs + "u0042" + bs + "u000a", true},
		{"escape in the last bytes", "int x;\n// " + bs + "u000a", true},
	} {
		got := scope.JavaStructuralEscape([]byte(tc.src))
		if got.Lost() != tc.lost {
			t.Errorf("%s: lost=%v offset=%d, want %v: %q", tc.name, got.Lost(), got.Offset, tc.lost, tc.src)
		}
	}
	// The first escape that qualifies is the one reported.
	src := "x " + bs + "u0041 " + bs + bs + "u000a " + bs + "u0022 " + bs + "u000a"
	if got := scope.JavaStructuralEscape([]byte(src)); !got.Found || got.Offset != strings.Index(src, bs+"u0022") {
		t.Errorf("first qualifying escape: %+v in %q", got, src)
	}
}

func TestJavaSourceByName(t *testing.T) {
	for _, name := range []string{"A.java", "a.JAVA", "src/main/java/x/Y.Java"} {
		if !scope.JavaSource(name) {
			t.Errorf("%s is a Java file", name)
		}
	}
	for _, name := range []string{"A.kt", "A.scala", "A.java.txt", "A.javascript", "A.class", "java", "A.js", "pom.xml"} {
		if scope.JavaSource(name) {
			t.Errorf("%s is not a Java file", name)
		}
	}
	bs := "\\"
	if _, lost := scope.EscapeLost("a.kt", []byte("// "+bs+"u000a")); lost {
		t.Error("a Kotlin file is not read by the Java rule")
	}
	if why, lost := scope.EscapeLost("a.java", []byte("// "+bs+"u000a")); !lost || why != scope.EscapeReasonJava {
		t.Errorf("a.java: %q %v", why, lost)
	}
}

func TestJavaStructuralEscapeNeverPanicsAndIsLinear(t *testing.T) {
	bs := "\\"
	atoms := []string{bs, "u", "0", "00", "0a", "0d", "22", "27", "5c", "2f", "2a", "a", "A", "z", "\n", " ", "/", "*", `"`, "'", bs + "u000a", bs + bs, bs + "uu"}
	rng := rand.New(rand.NewSource(9))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(40) + 1; n > 0; n-- {
			b.WriteString(atoms[rng.Intn(len(atoms))])
		}
		got := scope.JavaStructuralEscape([]byte(b.String()))
		if got.Found && (got.Offset < 0 || got.Offset >= b.Len()) {
			t.Fatalf("offset %d outside %q", got.Offset, b.String())
		}
	}
	big := strings.Repeat("x"+bs, 600000) + "y"
	start := time.Now()
	if scope.JavaStructuralEscape([]byte(big)).Lost() {
		t.Error("a megabyte of backslashes that start no escape was lost")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a megabyte took %v", d)
	}
	// N backslashes, then u000a: the last backslash is eligible when N is odd.
	for _, n := range []int{1<<20 - 8, 1<<20 - 7} {
		start = time.Now()
		got := scope.JavaStructuralEscape([]byte(strings.Repeat(bs, n) + "u000a"))
		if got.Found != (n%2 == 1) {
			t.Errorf("%d backslashes then u000a: %+v, want found=%v", n, got, n%2 == 1)
		}
		if got.Found && got.Offset != n-1 {
			t.Errorf("%d backslashes: offset %d, want %d", n, got.Offset, n-1)
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("a megabyte of backslashes took %v", d)
	}
}
