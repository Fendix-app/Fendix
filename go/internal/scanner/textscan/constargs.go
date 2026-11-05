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
// deliberately strict: it returns true only when the line has at least one
// interpolated operand and EVERY one is a literal, a number or a bare
// identifier declared as a constant string in this file. A call, a selector
// (`cfg.Table`), an index, a var, a non-final field or an undeclared name
// keeps the finding.

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

// interpolatedIdentsAreFileConstants reports whether every value interpolated
// into line is a file-level constant string: each `+` operand, and each
// fmt.Sprintf / String.format argument after the format string. It is false
// when the line interpolates nothing (a shell wrapper over a variable, or a
// `%s` placeholder inside a literal) so such a line keeps its finding.
func interpolatedIdentsAreFileConstants(line string, src []byte, lang string) bool {
	return operandsAreConstants(line, fileStringConstants(src, lang))
}

// operandsAreConstants is interpolatedIdentsAreFileConstants over a constant
// set computed once per file.
func operandsAreConstants(line string, consts map[string]struct{}) bool {
	m := maskLiterals(line)
	operands := 0
	ok := func(isLiteralOrNumber bool, name string) bool {
		operands++
		if isLiteralOrNumber {
			return true
		}
		_, isConst := consts[name]
		return isConst
	}

	// `+` operands.
	for i := 0; i < len(m); i++ {
		if m[i] != '+' {
			continue
		}
		if (i+1 < len(m) && (m[i+1] == '+' || m[i+1] == '=')) || (i > 0 && m[i-1] == '+') {
			continue // ++ and +=
		}
		left, right := i-1, i+1
		for left >= 0 && m[left] == ' ' {
			left--
		}
		for right < len(m) && m[right] == ' ' {
			right++
		}
		if left < 0 || right >= len(m) {
			return false
		}
		// Left operand: a literal, or an identifier read backwards.
		switch c := m[left]; {
		case c == literalMark:
			ok(true, "")
		case isIdentByte(c):
			end := left + 1
			for left >= 0 && (isIdentByte(m[left]) || m[left] == '.') {
				left--
			}
			if !operandOK(m[left+1:end], ok) {
				return false
			}
		default:
			return false // `)` / `]` (a call or index), or an operator
		}
		// Right operand: a literal, or an identifier that is not a call.
		switch c := m[right]; {
		case c == literalMark:
			ok(true, "")
		case isIdentByte(c):
			end := right
			for end < len(m) && (isIdentByte(m[end]) || m[end] == '.') {
				end++
			}
			rest := end
			for rest < len(m) && m[rest] == ' ' {
				rest++
			}
			if rest < len(m) && (m[rest] == '(' || m[rest] == '[') {
				return false
			}
			if !operandOK(m[right:end], ok) {
				return false
			}
		default:
			return false
		}
	}

	// Format-call arguments after the format string.
	for _, head := range []string{"fmt.Sprintf(", "String.format("} {
		for from := 0; ; {
			k := strings.Index(m[from:], head)
			if k < 0 {
				break
			}
			args, next, closed := splitCallArgs(m, from+k+len(head))
			from = next
			if !closed {
				return false
			}
			for _, a := range args {
				a = strings.TrimSpace(a)
				if a == "" || strings.Contains(a, "+") {
					continue // a trailing comma; or covered by the `+` pass
				}
				if !operandOK(a, ok) {
					return false
				}
			}
		}
	}
	return operands > 0
}

// operandOK classifies one operand token: a masked literal or a number is
// constant; a bare identifier must be a declared constant; anything else (a
// dotted name, a call, an index) is not.
func operandOK(tok string, ok func(isLiteralOrNumber bool, name string) bool) bool {
	tok = strings.TrimSpace(tok)
	switch {
	case tok == string(literalMark), tok != "" && tok[0] >= '0' && tok[0] <= '9':
		return ok(true, "")
	case isIdentifier(tok):
		return ok(false, tok)
	}
	return false
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
