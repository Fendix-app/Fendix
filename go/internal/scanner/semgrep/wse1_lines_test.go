package semgrep

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

// Round 6, WS-E1 (DE5-07, RC-1): the language's own lines for the partial-parse
// judge (parse.go, wse1LineModel and wse1SpansHoldNoCode). The lexer errs only
// toward "code": a case that wants inert is a comment line the lexer is sure of,
// a case that does not is code, a line inside a literal, or a place where the
// lexer stops trusting itself (marked "conservative").

func TestPartialParseJudgeLexicalCases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ext   string
		src   string
		line  int // the "\n"-numbered line Semgrep skipped
		inert bool
	}{
		// JavaScript and TypeScript
		{"js comment line", ".js", "var a = 1;\n// c\nvar b;\n", 2, true},
		{"js nested template, then a real comment", ".js", "const q = `a ${`b\n` + 1}`;\n// real\n", 3, true},
		{"js line inside a nested template", ".js", "const q = `a ${`b\n// x` + 1}`;\nvar a;\n", 2, false},
		{"js regex holding a backtick is not a template", ".js", "var r = /`/g;\n// real\nvar s = 1;\n", 2, true},
		{"js regex class holding a slash", ".js", "var r = /[/]/;\n// real\n", 2, true},
		{"js regex holding two slashes in a class", ".js", "var r = /[//]/;\n// real\n", 2, true},
		{"js division after an identifier", ".js", "var x = a / b;\n// c\n", 2, true},
		{"js division then a template", ".js", "var x = a / b + `\n// c\n`;\n", 2, false},
		{"js division after a parenthesis (conservative)", ".js", "var x = (a + b) / 2;\n// c\n", 2, false},
		{"js string continued by a backslash", ".js", "var s = 'a\\\n// b';\n", 2, false},
		{"js line inside a block comment", ".js", "/* a\n// b\n*/\n// c\n", 2, false},
		{"js comment line after a block comment", ".js", "/* a\n// b\n*/\n// c\n", 4, true},
		{"js jsx text", ".js", "function C() {\n  return (\n    <div>\n      // text {x}\n    </div>\n  );\n}\n", 4, false},
		{"js less-than is not jsx", ".js", "if (x < y) {}\n// c\n", 2, true},
		{"js generic call is not jsx", ".ts", "const a = f<T>(x);\n// c\n", 2, true},
		{"ts type assertion (conservative)", ".ts", "const x = <T>y;\n// c\n", 2, false},
		{"js unterminated string (conservative)", ".js", "var s = 'abc\n// c\n", 2, false},
		{"js hashbang", ".js", "#!/usr/bin/env node\n// c\n", 2, true},
		{"js crlf", ".js", "var a;\r\n// c\r\nvar b;\r\n", 2, true},
		{"js bare cr: every line a comment", ".js", "// a\r// b\r", 1, true},
		{"js bare cr: code after the comment", ".js", "// a\rvar b;\r", 1, false},
		{"js stray backslash does not hang", ".js", "var a = \\ 1;\n// c\n", 2, true},
		{"mjs unicode identifier escape", ".mjs", "var \\u0061 = 1;\n// c\n", 2, true},
		{"js one-line block comment", ".js", "a();\n/* x */\nb();\n", 2, true},
		{"js block comment that runs on", ".js", "a();\n/* x\n y */ c();\n", 2, false},
		// Python
		{"py comment line", ".py", "x = 1\n# c\ny = 2\n", 2, true},
		{"py f-string with nested quotes", ".py", "x = f\"{d['k']}\"\n# c\ny = 1\n", 2, true},
		{"py f-string with an escaped brace", ".py", "x = f\"{{\"\n# c\n", 2, true},
		{"py f-string spec holding a quote", ".py", "x = f\"{v:'>10}\"\n# c\n", 2, true},
		{"py f-string reusing its quote (3.12)", ".py", "x = f\"{d[\"k\"]}\"\n# c\n", 2, true},
		{"py nested f-string", ".py", "x = f\"{f'{y}'}\"\n# c\n", 2, true},
		{"py t-string field", ".py", "x = t\"{a}\"\n# c\n", 2, true},
		{"py line inside a plain triple string", ".py", "'''\n# not code\n'''\n# c\n", 2, false},
		{"py comment line after a triple string", ".py", "'''\n# not code\n'''\n# c\n", 4, true},
		{"py raw string ending in an escaped quote", ".py", "x = r'\\''\n# c\n", 2, true},
		{"py bytes and unicode prefixes", ".py", "x = b'a' + u'b' + rb'c'\n# c\n", 2, true},
		{"py unterminated string (conservative)", ".py", "x = 'abc\n# c\n", 2, false},
		{"py multi-line f-string field", ".py", "x = f\"\"\"{\n  y\n}\"\"\"\n# c\n", 4, true},
		{"py line inside an f-string field", ".py", "x = f\"\"\"{\n# {os.system(x)}\n}\"\"\"\n", 2, false},
		{"py bare cr", ".py", "x = 1\r# a\r# b\r", 1, false},
		{"py bare cr, comments only", ".py", "# a\r# b\r", 1, true},
		// Java, Go, Vue
		{"java text block", ".java", "String s = \"\"\"\n// not code\n\"\"\";\n// c\n", 2, false},
		{"java comment after a text block", ".java", "String s = \"\"\"\n// not code\n\"\"\";\n// c\n", 4, true},
		{"java char literal holding a quote", ".java", "char c = '\"';\n// c\n", 2, true},
		{"java bare cr", ".java", "// a\rRuntime.exec(c);\n", 1, false},
		{"go raw string", ".go", "s := `\n// x\n`\n// c\n", 2, false},
		{"go comment after a raw string", ".go", "s := `\n// x\n`\n// c\n", 4, true},
		{"go carriage return is blank space", ".go", "// a\r\n// b\r\n", 2, true},
		{"vue comment (conservative)", ".vue", "<script>\n// c\n</script>\n", 2, false},
		{"blank line anywhere", ".js", "`\n\n`;\n", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := wse1SpansHoldNoCode([]byte(tc.src), []Span{{tc.line, tc.line}}, tc.ext)
			if got != tc.inert {
				t.Errorf("line %d of %q: inert = %v, want %v", tc.line, tc.src, got, tc.inert)
			}
		})
	}
}

// The language's lines agree with the "\n" lines the run is numbered by.
func TestLanguageLinesLieInsideTheNewlineLines(t *testing.T) {
	for _, tc := range []struct {
		ext, src string
		lf       int // splitLines' count
	}{
		{".py", "a\nb\n", 2}, {".py", "a\n\n", 2}, {".py", "a\r\nb", 2}, {".py", "a\rb\rc", 1}, {".py", "", 0},
		{".js", "a\u2028b\nc", 2}, {".java", "a\rb\n", 1}, {".go", "a\rb\n", 1}, {".py", "\n", 1}, {".py", "a\n\r", 2},
	} {
		lines := wse1LineModel([]byte(tc.src), wse1LangOf(tc.ext))
		n := 0
		if len(lines) > 0 {
			n = lines[len(lines)-1].lf
		}
		if n != tc.lf || len(splitLines([]byte(tc.src))) != tc.lf {
			t.Errorf("%s %q: %d \\n-lines in the language model, %d in splitLines, want %d", tc.ext, tc.src, n, len(splitLines([]byte(tc.src))), tc.lf)
		}
	}
}

// The lexer ends on any input and never panics: random text over the alphabet
// that drives its states, in every language.
func TestLexerNeverHangsOrPanics(t *testing.T) {
	alphabet := []string{"'", "\"", "`", "{", "}", "(", ")", "[", "]", "/", "*", "\\", "\n", "\r", "\r\n", "\u2028", "$", "f", "t", "r", "#", "<", ">", "!", "u", "x", ":", " ", "e", "+", "-", "{{", "}}", "\"\"\"", "'''", "${"}
	rng := rand.New(rand.NewSource(263))
	deadline := time.Now().Add(20 * time.Second)
	for _, ext := range []string{".py", ".js", ".java", ".go", ".vue", ".txt"} {
		for i := 0; i < 1500 && time.Now().Before(deadline); i++ {
			var b strings.Builder
			for n := rng.Intn(200); n > 0; n-- {
				b.WriteString(alphabet[rng.Intn(len(alphabet))])
			}
			src := []byte(b.String())
			lines := wse1LineModel(src, wse1LangOf(ext))
			for _, l := range lines {
				if l.start < 0 || l.end > len(src) || l.start > l.end {
					t.Fatalf("%s %q: bad line %+v", ext, src, l)
				}
			}
			wse1SpansHoldNoCode(src, []Span{{1, 1}, {2, 3}}, ext)
		}
	}
	// Deep nesting is bounded, not followed.
	deep := strings.Repeat("f\"{", 500) + strings.Repeat("}\"", 500) + "\n# c\n"
	if wse1SpansHoldNoCode([]byte(deep), []Span{{2, 2}}, ".py") {
		t.Error("a 500-deep f-string nest was followed to its end: the lexer's nesting bound does not hold")
	}
	deepJS := strings.Repeat("`${", 500) + strings.Repeat("}`", 500) + "\n// c\n"
	if wse1SpansHoldNoCode([]byte(deepJS), []Span{{2, 2}}, ".js") {
		t.Error("a 500-deep template nest was followed to its end: the lexer's nesting bound does not hold")
	}
}
