package scope_test

// Release Closure Sprint, WS-C2, R6-E7a: a unicode escape in identifier position
// makes a JavaScript or TypeScript file lost evaluation. The vectors in
// testdata/jsescape_vectors.json are written by testdata/gen_jsescape_vectors.mjs
// and carry the TypeScript scanner's own verdict (`oracle`) and, for a payload
// that can run, whether Node ran it (`node_runs`). `expect` is what the lexer
// must answer; it differs from the oracle only in the conservative direction.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

type jsVector struct {
	ID        string `json:"id"`
	Ext       string `json:"ext"`
	Text      string `json:"text"`
	Note      string `json:"note"`
	Oracle    bool   `json:"oracle"`
	Expect    bool   `json:"expect"`
	Deviation string `json:"deviation"`
	NodeRuns  *bool  `json:"node_runs"`
}

type jsVectorFile struct {
	Schema int `json:"schema"`
	Oracle struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"oracle"`
	Vectors []jsVector `json:"vectors"`
}

func loadJSVectors(t *testing.T) jsVectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/jsescape_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc jsVectorFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestJSEscapeVectorFileIsFromTheTypeScriptOracle(t *testing.T) {
	doc := loadJSVectors(t)
	if doc.Schema != 1 || doc.Oracle.Name != "typescript" || !strings.HasPrefix(doc.Oracle.Version, "5.") {
		t.Fatalf("ground truth must come from the TypeScript scanner, got %+v", doc.Oracle)
	}
	ident, none, doubt := 0, 0, 0
	for _, v := range doc.Vectors {
		switch {
		case strings.HasPrefix(v.ID, "ident-"):
			ident++
		case strings.HasPrefix(v.ID, "none-"):
			none++
		case strings.HasPrefix(v.ID, "doubt-"):
			doubt++
		}
		// The lexer may only be more conservative than the oracle, and it says why.
		if v.Oracle != v.Expect && (!v.Expect || v.Deviation == "") {
			t.Errorf("%s: expect %v against oracle %v needs the conservative direction and a stated reason", v.ID, v.Expect, v.Oracle)
		}
		// A payload that really ran is never read clean.
		if v.NodeRuns != nil && *v.NodeRuns && !v.Expect {
			t.Errorf("%s: Node ran the payload and the vector expects it clean", v.ID)
		}
	}
	if ident < 55 || none < 90 || doubt < 8 {
		t.Errorf("vector families: %d ident, %d none, %d doubt; the file lost vectors", ident, none, doubt)
	}
}

func TestJSEscapeAgreesWithTheTypeScriptOracleOnEveryVector(t *testing.T) {
	for _, v := range loadJSVectors(t).Vectors {
		t.Run(v.ID, func(t *testing.T) {
			got := scope.JSIdentifierEscape("v"+v.Ext, []byte(v.Text))
			if got.Undecided {
				t.Fatalf("%s: undecided on %d bytes", v.ID, len(v.Text))
			}
			if got.Lost() != v.Expect {
				t.Errorf("%s (%s): lost=%v offset=%d, want %v (oracle %v)\n%s", v.ID, v.Note, got.Lost(), got.Offset, v.Expect, v.Oracle, v.Text)
			}
			if v.Expect && got.Lost() && got.Offset < 0 {
				t.Errorf("%s: lost without an offset", v.ID)
			}
		})
	}
}

func TestJSEscapeReadsOnlyJavaScriptAndTypeScriptByName(t *testing.T) {
	src := []byte("\\u0065val(x)")
	for _, name := range []string{"a.js", "a.jsx", "a.mjs", "a.cjs", "a.es6", "a.ts", "a.tsx", "a.mts", "a.cts", "A.JS", "dir/B.Tsx"} {
		if !scope.JSSource(name) || !scope.JSIdentifierEscape(name, src).Lost() {
			t.Errorf("%s is JavaScript or TypeScript and an escaped eval in it must be lost", name)
		}
	}
	for _, name := range []string{"a.vue", "a.py", "a.json", "a.html", "a.java", "a.go", "a.md", "Makefile", "a.js.map", "a.d.ts.txt"} {
		if scope.JSSource(name) || scope.JSIdentifierEscape(name, src).Lost() {
			t.Errorf("%s is not read by the JavaScript escape rule", name)
		}
	}
}

func TestJSEscapeFirstOffsetIsTheEscape(t *testing.T) {
	bs := "\\"
	src := "var s = '" + bs + "u0041'; /[" + bs + "u0042]/; ev" + bs + "u0061l(1)"
	got := scope.JSIdentifierEscape("a.js", []byte(src))
	if want := strings.Index(src, "ev"+bs+"u0061") + 2; !got.Found || got.Offset != want {
		t.Errorf("%+v, want the escape at %d of %q", got, want, src)
	}
}

// naive readers, as negative controls: each is a plausible first attempt, and the
// vectors must be able to tell it from the real lexer.
func naiveNoRegex(text string) bool {
	// strings and comments only: a regular expression is code.
	i := 0
	for i < len(text) {
		switch c := text[i]; {
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(text) && text[j] != c {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			i = j + 1
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				return false
			}
			i += j + 4
		case c == '\\' && i+1 < len(text) && text[i+1] == 'u':
			return true
		default:
			i++
		}
	}
	return false
}

func naiveSlashAlwaysRegex(text string) bool {
	// every `/` that closes on its line is a regex: division hides what follows.
	i := 0
	for i < len(text) {
		switch c := text[i]; {
		case c == '"' || c == '\'' || c == '`':
			j := i + 1
			for j < len(text) && text[j] != c {
				if text[j] == '\\' {
					j++
				}
				j++
			}
			i = j + 1
		case c == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				return false
			}
			i += j + 4
		case c == '/':
			j := strings.IndexByte(text[i+1:], '/')
			nl := strings.IndexByte(text[i+1:], '\n')
			if j >= 0 && (nl < 0 || j < nl) {
				i += j + 2
			} else {
				i++
			}
		case c == '\\' && i+1 < len(text) && text[i+1] == 'u':
			return true
		default:
			i++
		}
	}
	return false
}

func TestJSEscapeVectorsCanTellTheRealLexerFromNaiveReaders(t *testing.T) {
	doc := loadJSVectors(t)
	noRegexWrong, slashWrong := 0, 0
	for _, v := range doc.Vectors {
		if strings.HasSuffix(v.Ext, "x") || strings.HasPrefix(v.ID, "doubt-") { // JSX and the doubts are outside what a naive reader models
			continue
		}
		if naiveNoRegex(v.Text) != v.Expect {
			noRegexWrong++
		}
		if naiveSlashAlwaysRegex(v.Text) != v.Expect {
			slashWrong++
		}
	}
	if noRegexWrong < 15 {
		t.Errorf("a reader with no regex awareness fails only %d vectors: they do not test the regex rule", noRegexWrong)
	}
	if slashWrong < 6 {
		t.Errorf("a reader that takes every slash for a regex fails only %d vectors: they do not test the division rule", slashWrong)
	}
}

// The lexer terminates, never panics, and reads only what it is given, on random
// text built from the characters that matter to it.
func TestJSEscapeNeverHangsOrPanics(t *testing.T) {
	bs := "\\"
	atoms := []string{`\`, `u`, `0`, `00`, `65`, `{`, `}`, `(`, `)`, `[`, `]`, "`", `'`, `"`, `$`, "\n", "\r", " ", `/`, `//`, `/*`, `*/`,
		`<`, `>`, `<!--`, `-->`, `!`, `--`, `++`, `=`, `=>`, `;`, `,`, `.`, `?.`, `:`, `?`, ` `, `x`, `eval`, `of`, `await`, `yield`, `if`, `for`, `return`, `#`, `@`, bs + "u0041", bs + "u0065val", `\u{41}`, "</", "/>", `<a>`, `</a>`, `<>`, `</>`, `é`, "\ufeff"}
	exts := []string{"a.js", "a.jsx", "a.mjs", "a.ts", "a.tsx"}
	rng := rand.New(rand.NewSource(263))
	start := time.Now()
	for i := 0; i < 30000; i++ {
		var b strings.Builder
		for n := rng.Intn(60) + 1; n > 0; n-- {
			b.WriteString(atoms[rng.Intn(len(atoms))])
		}
		got := scope.JSIdentifierEscape(exts[i%len(exts)], []byte(b.String()))
		if got.Found && got.Offset < 0 || got.Offset >= len(b.String()) && got.Found {
			t.Fatalf("offset %d outside %q", got.Offset, b.String())
		}
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("30000 random files took %v", d)
	}
}

// A file built to make the lexer fork at every slash, or to nest without end, is
// decided within the budget or reported lost: giving up is never "clean".
func TestJSEscapeBudgetIsBoundedAndGivingUpIsLost(t *testing.T) {
	bs := "\\"
	tail := `"` + bs + `u0041";`
	cases := map[string]string{
		"forks":    strings.Repeat("{}/ a / ", 20000) + tail,
		"html":     strings.Repeat("a <!-- b\n", 40000) + tail,
		"nesting":  strings.Repeat("(", 60000) + tail,
		"braces":   strings.Repeat("{", 60000) + tail,
		"templ":    strings.Repeat("`${", 30000) + tail,
		"jsx":      strings.Repeat("x=<a>", 30000) + tail,
		"slashes":  strings.Repeat("/", 900000) + tail,
		"ofawait":  strings.Repeat("of / await / yield / ", 20000) + tail,
		"nonnull":  "var a;" + strings.Repeat("a!/ ", 20000) + tail,
		"longline": strings.Repeat("x", 1<<20-100) + tail,
	}
	giveUp := map[string]bool{"forks": true, "html": true, "nesting": true, "braces": true, "templ": true, "jsx": true, "ofawait": true}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			got := scope.JSIdentifierEscape("a.js", []byte(src))
			d := time.Since(start)
			t.Logf("%s: %d bytes -> %+v in %v", name, len(src), got, d)
			if d > 20*time.Second {
				t.Errorf("%s: %v for %d bytes", name, d, len(src))
			}
			if got.Undecided && !got.Lost() {
				t.Errorf("%s: undecided must be lost", name)
			}
			// These inputs are built to exceed the lexer's state, depth or step budget:
			// it gives up, and giving up is a lost file, never a clean one.
			if giveUp[name] && (!got.Undecided || !got.Lost()) {
				t.Errorf("%s: %+v, want undecided and lost", name, got)
			}
		})
	}
}

// Deep but ordinary code stays decidable: a minified bundle nests deeply and
// holds escapes in strings and regexes only.
func TestJSEscapeDeepOrdinaryCodeIsDecided(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&b, "f%d(function(){return [", i)
	}
	b.WriteString(`"A",/[B]/`)
	for i := 0; i < 400; i++ {
		b.WriteString("]})")
	}
	b.WriteString(";")
	if got := scope.JSIdentifierEscape("bundle.js", []byte(b.String())); got.Lost() {
		t.Errorf("deeply nested ordinary code read as lost: %+v", got)
	}
}

// Release Closure Sprint, CL-2 (verifier A-4): a `<` that could open a type parameter list or a
// generic JSX element's type arguments is read both ways. These vector families must stay in the
// file: each is a shape the first reading of `<` as an element start got wrong, and the file is
// the only place they are pinned against the TypeScript scanner (and Babel with Flow for the
// Flow ones). `ident-` rows hold an escape in code the other reading finds; `none-` rows hold
// it only in a string, a template or JSX text and must stay clean.
func TestJSEscapeVectorsCoverTheGenericTypeFamilies(t *testing.T) {
	have := map[string]jsVector{}
	for _, v := range loadJSVectors(t).Vectors {
		have[v.ID] = v
	}
	mustLose := []string{
		"ident-tsx-generic-jsx-element", "ident-tsx-generic-jsx-element-nested", "ident-tsx-generic-jsx-element-fn-type",
		"ident-tsx-generic-jsx-element-children", "ident-tsx-generic-jsx-element-trailing-comma", "ident-tsx-generic-jsx-element-two",
		"ident-tsx-generic-jsx-element-member", "ident-tsx-generic-arrow", "ident-tsx-generic-arrow-default", "ident-tsx-generic-arrow-const",
		"ident-tsx-generic-arrow-const-extends", "ident-tsx-generic-arrow-two", "ident-tsx-generic-arrow-extends-default",
		"ident-tsx-generic-arrow-default-comma", "ident-tsx-generic-arrow-async", "ident-tsx-generic-arrow-newline",
		"ident-tsx-generic-arrow-comment", "ident-tsx-generic-arrow-in-call", "ident-tsx-generic-arrow-in-array",
		"ident-tsx-generic-arrow-return", "ident-tsx-generic-arrow-after-element", "ident-tsx-generic-arrow-then-element",
		"ident-mts-generic-arrow", "ident-cts-generic-arrow", "ident-ts-generic-arrow-default",
		"ident-flow-generic-arrow", "ident-flow-generic-arrow-bound", "ident-flow-generic-arrow-default",
		"ident-flow-generic-arrow-variance", "ident-flow-generic-arrow-two", "ident-flow-generic-arrow-mjs",
		// R3-SEC-A2: a list over the first lexer's 64 KiB bound; V8 ran the payload after the list (node_runs)
		"ident-tsx-generic-jsx-element-union-66k", "ident-tsx-generic-jsx-element-union-80k",
	}
	mustStayClean := []string{
		"none-tsx-generic-jsx-element-string-arg", "none-tsx-generic-jsx-element-text", "none-tsx-generic-jsx-element-regex-after",
		"none-tsx-generic-arrow-string-after", "none-tsx-generic-arrow-body-template", "none-tsx-generic-arrow-jsx-body", "none-ts-generic-call",
		"none-tsx-generic-jsx-element-union-80k",
	}
	for _, id := range mustLose {
		v, ok := have[id]
		switch {
		case !ok:
			t.Errorf("vector %s is gone", id)
		case !v.Expect:
			t.Errorf("vector %s must expect lost evaluation", id)
		}
	}
	for _, id := range mustStayClean {
		v, ok := have[id]
		switch {
		case !ok:
			t.Errorf("vector %s is gone", id)
		case v.Expect:
			t.Errorf("vector %s must expect a clean read", id)
		}
	}
	// the Flow rows are in `.js`/`.mjs`: the lexer reads Flow type parameters in the files Flow
	// is written in, not only in TypeScript
	for id, v := range have {
		if strings.HasPrefix(id, "ident-flow-") {
			switch v.Ext {
			case ".js", ".jsx", ".mjs", ".cjs":
			default:
				t.Errorf("%s: a Flow vector in %s", id, v.Ext)
			}
		}
	}
}
