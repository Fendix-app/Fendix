package scope

// Release Closure Sprint, correction loop CL2-3 (verifier finding R3-SEC-A2, owner
// ruling OR-88 item 3): a lexer that gives up must never answer "clean", and no limit
// may make it resume a reading that can skip code. One test per limit of the
// JavaScript and TypeScript lexer; the Python twin has the same table
// (python/tests/test_scope_js_escape.py).
//
// The inputs end in an escape that sits in a string, so no reading of them finds an
// escape in code: only a give-up can make the file lost, and the test says at which
// limit it happened.

import (
	"strings"
	"testing"
)

func giveUpTail() string { return `"` + `\` + `u0041";` }

func TestJSEscapeEveryGiveUpNamesItsLimitAndIsLost(t *testing.T) {
	tail := giveUpTail()
	cases := []struct {
		name string
		file string
		src  string
		why  string
	}{
		{"depth: brackets nested past jsMaxDepth", "a.js", strings.Repeat("(", jsMaxDepth+500) + tail, jsGiveUpDepth},
		{"steps: more tokens read than the budget", "a.js", strings.Repeat("{}/ a / ", 2500) + tail, jsGiveUpSteps},
		{"type arguments: a template with a substitution among them", "a.tsx", "const a = <Select<`a${B}c`> />;\n" + tail, jsGiveUpTypeArgs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := jsEscapeWhy(c.file, []byte(c.src))
			if got.Found {
				t.Fatalf("the escape is in a string: nothing may be found, got %+v", got)
			}
			if !got.Undecided || !got.Lost() {
				t.Fatalf("giving up must be lost evaluation: got %+v (limit %q), want a give-up at %q", got, why, c.why)
			}
			if why != c.why {
				t.Errorf("gave up at %q, want %q", why, c.why)
			}
			if public := JSIdentifierEscape(c.file, []byte(c.src)); public != got {
				t.Errorf("the public entry point answers %+v, the reason-aware one %+v", public, got)
			}
		})
	}
}

// The states limit sits behind the step budget (every reading costs steps to the end of the
// file, so no real input reaches 20000 distinct readings first): a lexer with the limit
// lowered reaches it, and giving up there is lost evaluation too.
func TestJSEscapeStatesLimitGivesUpAsLost(t *testing.T) {
	src := []byte(strings.Repeat("{}/ a / ", 50) + giveUpTail())
	lx := newJSLexer(jsFlavour{jsx: true, html: true}, src)
	lx.maxStates = 3
	got := lx.decide()
	if got.Found || !got.Undecided || !got.Lost() || lx.why != jsGiveUpStates {
		t.Errorf("got %+v, limit %q: want a give-up at %q that is lost evaluation", got, lx.why, jsGiveUpStates)
	}
	// the same file decides within the real limits
	if got, why := jsEscapeWhy("a.js", src); got.Lost() {
		t.Errorf("without the lowered limit the file reads as lost: %+v (limit %q)", got, why)
	}
}

// The depth limit gives up as lost evaluation at the limit of this package, and a lexer
// with the limit lowered gives up at a depth that real input reaches without a long file.
func TestJSEscapeDepthLimitGivesUpAsLost(t *testing.T) {
	src := []byte(strings.Repeat("(", 40) + giveUpTail())
	lx := newJSLexer(jsFlavour{jsx: true, html: true}, src)
	lx.maxDepth = 30
	got := lx.decide()
	if got.Found || !got.Undecided || lx.why != jsGiveUpDepth {
		t.Errorf("got %+v, limit %q: want a give-up at %q", got, lx.why, jsGiveUpDepth)
	}
}

// A type argument list that nothing closes (no `>` before the end of the file, or a comment in it
// that never ends) is in no valid file, so the reading that holds it ends, as an unterminated comment
// ends one: it is not a give-up, and it is not lost evaluation by itself. Giving up there made a
// vendored react-dom.production.min.js and a PNG named .js read as lost evaluation in the Tier B census
// (a forked reading of an ordinary `<` ran into it). Where the `<` is a doubt, the other reading is
// read, and finds what is in code.
func TestJSEscapeAnOpenTypeArgumentListEndsItsReadingAndOtherReadingsStillRun(t *testing.T) {
	tail := giveUpTail()
	for name, c := range map[string]struct{ file, src string }{
		"no closing >":          {"a.tsx", "const a = <Select<A|A|A|A\n" + tail},
		"unterminated comment":  {"a.tsx", "const a = <Select</* A\n" + tail},
		"in a .js file":         {"a.js", "const a = <b<c;\n" + tail},
		"after a closing brace": {"a.js", "function f() {}\n<b<c;\n" + tail},
	} {
		got, why := jsEscapeWhy(c.file, []byte(c.src))
		if got.Lost() || why != "" {
			t.Errorf("%s: %+v (limit %q); an open list ends its reading, it is not a give-up", name, got, why)
		}
	}
	// after a `}` the `<` is read both ways: the reading that takes `<b<c` for an operator runs on
	// and finds the escaped call that follows, so the file is lost
	code := "function f() {}\n<b<c\n" + `\` + "u0065val(1);\n"
	if got, why := jsEscapeWhy("a.js", []byte(code)); !got.Found {
		t.Errorf("an escaped call after an open `<` read as clean: %+v (limit %q)", got, why)
	}
}

// A string among the type arguments may hold U+2028 or U+2029 (ES2019 allows them in a string, as in
// code): a `>` after one is part of the string, not the end of the list.
func TestJSEscapeATypeArgumentStringMayHoldALineSeparator(t *testing.T) {
	for _, sep := range []string{string(rune(0x2028)), string(rune(0x2029))} {
		src := "const a = <Select<\"a" + sep + ">b\"> items={[]} />;\n" + `\` + "u0065xec(1);\n"
		if got, why := jsEscapeWhy("a.tsx", []byte(src)); !got.Found {
			t.Errorf("U+%04X in a type argument string: %+v (limit %q), want the escaped call found", []rune(sep)[0], got, why)
		}
	}
}

// A type argument list of any length closes where it closes: the lexer reads on to it
// (R3-SEC-A2: it used to stop after 64 KiB and read the rest of the file as JSX text),
// and a file that has no escape in code stays clean.
func TestJSEscapeLongTypeArgumentListsAreReadToTheirEnd(t *testing.T) {
	list := func(members int) string { return strings.Repeat("A|", members) + "A" }
	for _, members := range []int{100, 30000, 33000, 40000, 120000, 400000} {
		head := "type A = string;\nconst Select = (p: any) => null;\nconst a = <Select<" + list(members) + "> items={[]} />;\n"
		code := head + `\` + "u0065xec('dig ' + host);\n"
		got, why := jsEscapeWhy("Page.tsx", []byte(code))
		if !got.Found || got.Offset != len(head) {
			t.Errorf("%d members: an escaped identifier after the list: %+v (limit %q), want it found at %d", members, got, why, len(head))
		}
		str := head + `const s = "` + `\` + "u0041\";\n"
		if got, why := jsEscapeWhy("Page.tsx", []byte(str)); got.Lost() {
			t.Errorf("%d members: an escape only in a string after the list read as lost: %+v (limit %q)", members, got, why)
		}
	}
}

// More modifiers than any type parameter has: the lexer cannot tell a list from an
// element tag, so it reads both ways and the file is lost when either finds an escape.
func TestJSEscapeAnEndlessModifierChainIsReadBothWays(t *testing.T) {
	for _, chain := range []string{"const in out T", "const in out const T", "in in in in in in in in in in T", "const const const const const T"} {
		src := "const f = <" + chain + ",>(x: T) => x;\n" + `\` + "u0065val('1');\n"
		got, why := jsEscapeWhy("a.tsx", []byte(src))
		if !got.Lost() {
			t.Errorf("<%s,>: read as clean: %+v (limit %q)", chain, got, why)
		}
	}
}
