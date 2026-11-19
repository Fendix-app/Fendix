package scope

import (
	"os"
	"path/filepath"
	"strings"
)

// Directories (decision D5-2, contract C6). The only directory left out of an
// analyzer's scope is the version-control metadata directory of the scan root,
// <root>/.git, and only when its layout is a real one: a HEAD file and the
// objects/ and refs/ directories. It holds history, not source.
//
// Nothing else is left out by a directory's name or by marker files inside it.
// A node_modules, vendor, dist, build, target or site-packages directory, a
// virtualenv (pyvenv.cfg, conda-meta) and an installed-package tree are all
// ordinary directories whose files are scanned like any other, and so are a
// .git or an objects directory anywhere else than the root. Round 4 pruned
// them on marker files a repository's author could write, which made every
// marker a way to hide code (review items 2 and 8, C4B-03's family). If
// scanning an installed-dependency tree breaks the runtime budget on a real
// repository, that is reported with measurements and the owner decides; it is
// not worked around with an exclusion.
//
// Marker probing never reads a file and never follows a link: Lstat only, and
// a link or a special file is not a marker.

// ReasonGitMetadata is the reason for <root>/.git.
const ReasonGitMetadata Reason = "git metadata"

// ClassifyDir classifies the directory at abs (rel is its path relative to the
// scan root, forward slashes). The verdict is non-zero only for the root's own
// .git directory with a real layout.
func ClassifyDir(abs, rel string) Verdict {
	if strings.ReplaceAll(rel, `\`, "/") != ".git" || !IsGitMetadataDir(abs) {
		return Verdict{}
	}
	return Verdict{ReasonGitMetadata}
}

// IsGitMetadataDir reports whether abs, which the caller has established is
// the .git entry directly under the scan root, has a real git layout: itself a
// directory (not a link), with a regular HEAD file and objects and refs
// directories (none of them links). Only Lstat is used, so a FIFO or a link
// cannot make the probe block or leave the root. Callers must not use it for a
// .git anywhere else.
func IsGitMetadataDir(abs string) bool {
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() {
		return false
	}
	head, err := os.Lstat(filepath.Join(abs, "HEAD"))
	if err != nil || !head.Mode().IsRegular() {
		return false
	}
	for _, d := range []string{"objects", "refs"} {
		fi, err := os.Lstat(filepath.Join(abs, d))
		if err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}
