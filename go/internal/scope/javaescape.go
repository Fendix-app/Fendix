package scope

// R6-E7b: a Java file with a unicode escape that translates to a line terminator,
// a quote, a backslash, a slash or an asterisk is lost evaluation (Release
// Closure Sprint, owner ruling OR-85, option (4): "structural escape anywhere,
// only after JDK evidence"; the evidence is testdata/javaescape_vectors.json,
// every vector compiled and run on a real JDK).
//
// The defect. JLS 3.3 translates unicode escapes before the program is lexed, so
//
//	// <escape for LF> Runtime.getRuntime().exec(cmd);
//
// is a comment followed by a statement: the compiler runs the call. Semgrep's
// patterns and textscan's line rules do not translate, they see only a comment,
// and the file read 0 findings with every analyzer ok and coverage complete (a
// false clean). The remedy is an honest incomplete: the file is recorded lost
// evaluation through the existing mechanism (Semgrep "not parsed", textscan
// "unreadable"). No new enum, no schema change.
//
// What counts. An escape is a backslash followed by one or more u and four hex
// digits (either case), where the backslash is preceded by an even number of
// backslashes (an odd number means it is itself escaped: JLS 3.3). It is
// structural when it translates to:
//
//   - a line terminator: LF (000a) or CR (000d);
//   - a quote: " (0022) or ' (0027);
//   - a backslash (005c);
//   - a slash (002f) or an asterisk (002a).
//
// Any such escape anywhere in the file counts, in a comment and in a literal as
// well as in code: it can end a comment (`*` and an escape for `/`), a string or a
// character literal, or start a comment. The corpus holds none (0 structural
// escapes in the 14,172 Java files of the Tier B trees), so the rule costs nothing
// measurable; the any-escape alternative would have reported 11.
//
// Not covered, and said so: an escape for an ordinary character (an identifier
// spelled `exec`) is not structural and is not read by this rule.

import (
	"path"
	"strings"
)

// JavaEscape is what JavaStructuralEscape found in a file.
type JavaEscape struct {
	// Found is true when the file holds a structural unicode escape.
	Found bool
	// Offset is the byte offset of the backslash of the first one, or -1.
	Offset int
}

// Lost reports whether the file must be recorded lost evaluation.
func (e JavaEscape) Lost() bool { return e.Found }

// JavaSource reports whether JavaStructuralEscape reads a file of this name: a
// Java source file, the extension matched without regard to case.
func JavaSource(name string) bool { return strings.EqualFold(path.Ext(name), ".java") }

func javaHexValue(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

// JavaStructuralEscape reports whether src, the bytes of a Java source file,
// holds a unicode escape that translates to LF, CR, a double or single quote, a
// backslash, a slash or an asterisk (see the file comment). One pass, linear.
func JavaStructuralEscape(src []byte) JavaEscape {
	run := 0 // raw backslashes that contiguously precede the current byte
	for i := 0; i < len(src); i++ {
		if src[i] != '\\' {
			run = 0
			continue
		}
		if run%2 == 0 && i+1 < len(src) && src[i+1] == 'u' {
			j := i + 1
			for j < len(src) && src[j] == 'u' {
				j++
			}
			if j+4 <= len(src) {
				v, ok := 0, true
				for k := 0; k < 4 && ok; k++ {
					var d int
					if d, ok = javaHexValue(src[j+k]); ok {
						v = v<<4 | d
					}
				}
				if ok {
					switch v {
					case 0x0a, 0x0d, 0x22, 0x27, 0x5c, 0x2f, 0x2a:
						return JavaEscape{Found: true, Offset: i}
					}
					// An ordinary escape: its character takes no part in a further
					// escape, and the hex digits that follow are not backslashes.
					i = j + 3
					run = 0
					continue
				}
			}
		}
		run++
	}
	return JavaEscape{Offset: -1}
}
