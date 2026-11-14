package scope

import (
	"errors"
	"io"
	"path"
	"strings"
)

// Decision D5-2 (round 5, contract C6). Every supported in-scope file at or
// below the size cap (MaxFileBytes) is analysed, whatever it looks like:
// minified, vendored, generated, test and fixture code included. Nothing is
// left out because of a banner or a header ("jQuery v3", "Socket.IO",
// "Code generated ... DO NOT EDIT"), a file or directory name (min.js, vendor,
// node_modules, dist), a large literal, line statistics or code appearance.
// Round 4 excluded files on those signals (D6'), and each one was a way to
// hide code: a first-party module with one large JSON literal, a forged
// library banner or a forged marker file made a vulnerable file read "out of
// scope" and the scan complete (C4B-02, C4B-03, review items 1, 2, 7 and 8).
//
// The only content-based exclusion is an explicitly recognized lockfile (this
// file and lockfile.go): its exact base name is one of a closed, documented list
// (LockfileNames) AND its whole content parses as that format. A file with a
// lockfile's name that holds anything else, source code included, is in scope.
//
// The only directory left out is <root>/.git with a real layout (dirs.go).
//
// An in-scope file over the cap or unreadable is lost evaluation for every
// analyzer that should have read it (scope.go: Coverage.TooLarge, Unreadable),
// never an exclusion.

// Reason names why a file or directory is declared out of scope. The set is
// closed and carries no repository text, so a detail that names a reason can
// never be shaped by the scanned tree.
type Reason string

// The reasons something is declared out of scope.
const (
	// ReasonLockfile is a recognized lockfile: its exact name and a content
	// that parses as that name's format.
	ReasonLockfile Reason = "lockfile"
	// ReasonSymlink is a symbolic link the analyzer did not follow.
	ReasonSymlink Reason = "symbolic link"
)

// Verdict is the outcome of classifying a file or directory: the reason, or the
// zero value when there is no evidence and the path is in scope.
type Verdict struct {
	Reason Reason
}

// None reports that no evidence was found: the path is in scope.
func (v Verdict) None() bool { return v.Reason == "" }

// errNotRegular is why OpenRegular refuses a path.
var errNotRegular = errors.New("not a regular file")

// IsLockfileName reports whether base is one of the closed list of lockfile
// names. It is a candidate test, never evidence (ClassifyFile reads the whole
// content).
func IsLockfileName(base string) bool {
	_, ok := lockfiles[base]
	return ok
}

// ClassifyFile classifies the regular file at abs, whose path relative to the
// scan root is rel and whose size is size. The verdict is ReasonLockfile only
// for a file with a lockfile's exact name whose whole content parses as that
// format; every other file has the zero Verdict. The file is opened only when
// its name is on the list, without blocking and without following a link at
// abs (OpenRegular), so probing a name never blocks on a FIFO and never reads
// outside the root.
func ClassifyFile(abs, rel string, size int64) Verdict {
	base := path.Base(strings.ReplaceAll(rel, `\`, "/"))
	check, ok := lockfiles[base]
	if !ok || size <= 0 || size > maxLockfileBytes {
		return Verdict{}
	}
	f, err := OpenRegular(abs)
	if err != nil {
		return Verdict{}
	}
	defer f.Close()
	// A bounded read: a file that grew past the bound after the stat is not a
	// lockfile.
	lr := &io.LimitedReader{R: f, N: maxLockfileBytes + 1}
	if check(lr) && lr.N > 0 {
		return Verdict{ReasonLockfile}
	}
	return Verdict{}
}
