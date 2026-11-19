package scope_test

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// A `;` inside a parenthesised head is followed by an expression, so a `{` there
// opens an object literal and the `/` after its `}` divides. The lexer read that `{`
// as a block, took `/ \u0065val(...) /` for a regular expression and called the file
// clean while Node runs the escaped call (automated security review of 547171e;
// Node-verified: `for (;{} / \u0065val("...") / 1;) break;` prints).
func TestJSEscapeObjectLiteralInAParenthesisedHeadIsNotABlock(t *testing.T) {
	lost := map[string]string{
		"for head":            "for (;{} / \\u0065val(\"x\") / 1;) break;\n",
		"for head, second ;":  "for (var i = 0;i < 1;{} / \\u0065val(\"x\") / 1) break;\n",
		"nested paren in for": "for (;({}) / \\u0065val(\"x\") / 1;) break;\n",
	}
	for name, src := range lost {
		if !scope.JSIdentifierEscape("a.js", []byte(src)).Lost() {
			t.Errorf("%s: an escaped call after an object literal in a for head reads clean", name)
		}
	}
	// A `;` that ends a statement still makes the next `{` a block, so the regex after
	// its `}` stays a regex: an escape inside it is not an identifier.
	clean := map[string]string{
		"block after a statement": "x = 1; {} /\\u0065val/.test(s);\n",
	}
	for name, src := range clean {
		if scope.JSIdentifierEscape("a.js", []byte(src)).Lost() {
			t.Errorf("%s: an escape inside a regular expression reads lost", name)
		}
	}
}
