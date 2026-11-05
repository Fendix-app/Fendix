package textscan

import (
	"regexp"
	"strings"
)

// File-constant suppression for the injection rules that set
// Rule.ConstArgSafe.
//
// A query or command built only from values that are declared as constant
// strings in the same file cannot carry user input:
//
//	const activeUsersTable = "users"
//	db.Query(fmt.Sprintf("SELECT id FROM %s", activeUsersTable))
//
// The rule's Pattern cannot tell, because it sees one line, so the check runs
// after a match, against the whole file's constant declarations. It is
// deliberately strict: it returns true only when the matched call has at least
// one interpolation and EVERY argument of the call is a literal, a number, a
// file constant, or an expression of them. A bare variable, a call, a selector
// (`cfg.Table`), an index, a var, a non-final field or an undeclared name
// anywhere in the argument list keeps the finding.

const literalMark = '\x00' // stands for one masked string / character literal

var (
	goConstLine      = regexp.MustCompile("^\\s*const\\s+(\\w+)(?:\\s+string)?\\s*=\\s*(?:\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`)\\s*(?://.*)?$")
	goConstBlockOpen = regexp.MustCompile(`^\s*const\s*\(\s*(?://.*)?$`)
	goConstBlockEnd  = regexp.MustCompile(`^\s*\)`)
	goConstBlockLine = regexp.MustCompile("^\\s*(\\w+)(?:\\s+string)?\\s*=\\s*(?:\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`)\\s*(?://.*)?$")
	javaFinalString  = regexp.MustCompile(`\b(?:static\s+final|final\s+static)\s+String\s+(\w+)\s*=\s*"(?:[^"\\]|\\.)*"\s*;`)
)

// fileStringConstants returns the names declared as constant strings in src:
// Go `const X = "..."` (alone or inside a `const ( ... )` block, with an
// optional `string` type) and Java `static final String X = "...";`. Only a
// single string literal counts; `const X = prefix + "y"` does not.
func fileStringConstants(src []byte, lang string) map[string]struct{} {
	out := map[string]struct{}{}
	switch lang {
	case "go":
		inBlock := false
		for _, l := range strings.Split(string(src), "\n") {
			l = strings.TrimRight(l, "\r")
			switch {
			case inBlock:
				if goConstBlockEnd.MatchString(l) {
					inBlock = false
				} else if m := goConstBlockLine.FindStringSubmatch(l); m != nil {
					out[m[1]] = struct{}{}
				}
			case goConstBlockOpen.MatchString(l):
				inBlock = true
			default:
				if m := goConstLine.FindStringSubmatch(l); m != nil {
					out[m[1]] = struct{}{}
				}
			}
		}
	case "java":
		for _, m := range javaFinalString.FindAllSubmatch(src, -1) {
			out[string(m[1])] = struct{}{}
		}
	}
	return out
}

// langOf names the constant-declaration syntax a path uses; "" when none.
func langOf(path string) string {
	switch {
	case HasGoExtension(path):
		return "go"
	case HasJavaExtension(path):
		return "java"
	}
	return ""
}

// interpolatedIdentsAreFileConstants reports whether the call that starts at
// the beginning of call (the text from the rule's match onward) is built only
// from file constants: EVERY top-level argument is a constant expression. A
// constant expression is a literal, a number, a bare identifier declared as a
// constant string in src, a parenthesised one, `+` joining such terms, a
// fmt.Sprintf / String.format over such arguments, or an array literal
// (`new String[]{...}`, `[]string{...}`) of them.
//
// It is false when the call interpolates nothing (a shell wrapper over a
// literal, or a `%s` placeholder inside a literal), so such a call keeps its
// finding, and false when ANY argument is a variable, a call, a dotted name or
// a non-constant: `exec.Command("sh", "-c", user, "x="+TABLE)` is not hidden by
// the constant beside it. A call that is not closed on the line fails closed.
//
// Scope is not modelled: a parameter or local named like a package constant is
// read as that constant (a documented limit).
func interpolatedIdentsAreFileConstants(call string, src []byte, lang string) bool {
	return callArgsAreConstants(call, fileStringConstants(src, lang))
}

// callArgsAreConstants is interpolatedIdentsAreFileConstants over a constant
// set computed once per file.
func callArgsAreConstants(call string, consts map[string]struct{}) bool {
	m := maskLiterals(call)
	open := -1
	for i := 0; i < len(m); i++ {
		// The call's own argument list is the first `(` with something inside:
		// `Runtime.getRuntime().exec(` skips getRuntime's empty pair.
		if m[i] == '(' && i+1 < len(m) && m[i+1] != ')' {
			open = i
			break
		}
	}
	if open < 0 {
		return false
	}
	args, _, closed := splitCallArgs(m, open+1)
	if !closed {
		return false
	}
	interp := 0
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue // a trailing comma
		}
		if !constExpr(a, consts, &interp) {
			return false
		}
	}
	return interp > 0
}

// constExpr reports whether expression e (literals masked) is built only from
// constants, counting each interpolation (a `+` join, a format argument) in
// *interp.
func constExpr(e string, consts map[string]struct{}, interp *int) bool {
	terms := splitTopLevel(e, '+')
	if len(terms) > 1 {
		*interp += len(terms) - 1
	}
	for _, t := range terms {
		if !constTerm(strings.TrimSpace(t), consts, interp) {
			return false
		}
	}
	return true
}

func constTerm(t string, consts map[string]struct{}, interp *int) bool {
	switch {
	case t == "":
		return false
	case t == string(literalMark), t[0] >= '0' && t[0] <= '9':
		return true
	case isIdentifier(t):
		_, ok := consts[t]
		return ok
	case t[0] == '(' && t[len(t)-1] == ')' && matchingClose(t, 0) == len(t)-1:
		return constExpr(t[1:len(t)-1], consts, interp)
	}
	for _, head := range []string{"fmt.Sprintf(", "String.format("} {
		if strings.HasPrefix(t, head) && t[len(t)-1] == ')' && matchingClose(t, len(head)-1) == len(t)-1 {
			args, _, closed := splitCallArgs(t, len(head))
			if !closed || len(args) < 2 {
				return false
			}
			*interp += len(args) - 1
			for _, a := range args {
				if !constExpr(strings.TrimSpace(a), consts, interp) {
					return false
				}
			}
			return true
		}
	}
	// An array literal: `new String[]{...}`, `new String[] {...}`, `[]string{...}`.
	if i := strings.IndexByte(t, '{'); i > 0 && t[len(t)-1] == '}' && matchingClose(t, i) == len(t)-1 && isArrayHead(strings.TrimSpace(t[:i])) {
		for _, el := range splitTopLevel(t[i+1:len(t)-1], ',') {
			el = strings.TrimSpace(el)
			if el != "" && !constExpr(el, consts, interp) {
				return false
			}
		}
		return true
	}
	return false
}

// isArrayHead matches the type part of an array literal.
func isArrayHead(h string) bool {
	h = strings.ReplaceAll(h, " ", "")
	return h == "newString[]" || h == "[]string" || h == "[]String"
}

// splitTopLevel splits s on sep outside any (), [] or {}.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, from := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[from:i])
				from = i + 1
			}
		}
	}
	return append(out, s[from:])
}

// matchingClose returns the index of the bracket that closes the one at s[open],
// or -1.
func matchingClose(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentifier(s string) bool {
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isIdentByte(s[i]) {
			return false
		}
	}
	return true
}

// splitCallArgs splits the arguments of the call whose `(` ends just before
// start, on top-level commas. closed is false when the line ends first.
func splitCallArgs(m string, start int) (args []string, next int, closed bool) {
	depth, from := 0, start
	for i := start; i < len(m); i++ {
		switch m[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return append(args, m[from:i]), i + 1, true
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, m[from:i])
				from = i + 1
			}
		}
	}
	return nil, len(m), false
}

// maskLiterals replaces every string, raw-string and character literal in line
// with one literalMark byte, so a `+`, `,` or `(` inside a literal is never
// read as syntax.
func maskLiterals(line string) string {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c != '"' && c != '\'' && c != '`' {
			b.WriteByte(c)
			continue
		}
		j := i + 1
		for j < len(line) && line[j] != c {
			if line[j] == '\\' && c != '`' {
				j++
			}
			j++
		}
		b.WriteByte(literalMark)
		i = j // the closing quote, or past the end of an unterminated literal
	}
	return b.String()
}
