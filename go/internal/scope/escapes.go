package scope

import "io"

// The analyzers that match source text lexically (Semgrep, textscan, the Python
// engine's pattern checks) cannot see through a unicode escape the language
// translates before it reads the program. A file in which one changes what the
// code means is lost evaluation, never a clean result (R6-E7a for JavaScript and
// TypeScript, R6-E7b for Java). This is the one entry point both Go analyzers
// call.

// Reasons EscapeLost gives, short enough to follow a file name in a detail.
const (
	// EscapeReasonIdentifier is a JavaScript or TypeScript identifier spelled
	// with a unicode escape.
	EscapeReasonIdentifier = "identifier escape"
	// EscapeReasonJava is a Java file with a unicode escape that translates to a line
	// terminator, a quote, a backslash, a slash or an asterisk (R6-E7b).
	EscapeReasonJava = "unicode escape"
	// EscapeReasonUnreadable is a file that could not be read for the check.
	EscapeReasonUnreadable = "could not be read"
)

// EscapeCovered reports whether EscapeLost reads files of this name.
func EscapeCovered(name string) bool { return JSSource(name) || JavaSource(name) }

// EscapeLost reports whether src, the content of the file called name, must be
// recorded lost evaluation for an escape its analyzers cannot see through, and
// why. A file EscapeCovered does not name is never lost by it.
func EscapeLost(name string, src []byte) (reason string, lost bool) {
	if JSSource(name) && JSIdentifierEscape(name, src).Lost() {
		return EscapeReasonIdentifier, true
	}
	if JavaSource(name) && JavaStructuralEscape(src).Lost() {
		return EscapeReasonJava, true
	}
	return "", false
}

// EscapeLostFile is EscapeLost for the file called name that r reads from its
// start: at most MaxFileBytes of it are read, and only when EscapeCovered names
// it. A read that fails is reported lost, since nothing can then be said about the
// file, and so is a file over the cap: the callers measure a file before they open
// it and record one over the cap as lost evaluation themselves, so this is a file
// that grew in between, and a file that was not read is not evidence of anything.
func EscapeLostFile(name string, r io.Reader) (reason string, lost bool) {
	if !EscapeCovered(name) {
		return "", false
	}
	src, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil || len(src) > MaxFileBytes {
		return EscapeReasonUnreadable, true
	}
	return EscapeLost(name, src)
}

// EscapeLostPath is EscapeLost for the file called name that an analyzer reads from
// path, at most max bytes of it (ReadRegular: no pipe or device, no link at the last
// element). Whatever stops the read (a name swapped for a pipe after the walk, a file
// that vanished or grew, a directory) is lost evaluation under EscapeReasonUnreadable,
// never "no escape": the caller measured the file before, so this happens only when it
// changed since, and nothing can then be said about it.
func EscapeLostPath(name, path string, max int64) (reason string, lost bool) {
	if !EscapeCovered(name) {
		return "", false
	}
	src, err := ReadRegular(path, max)
	if err != nil {
		return EscapeReasonUnreadable, true
	}
	return EscapeLost(name, src)
}
