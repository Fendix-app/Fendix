package secrets

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// What the secrets scanner reads (R-010, decision D6').
//
// The scanner reads every regular file under the scan root that is text. A
// file is left unread only when there is deterministic evidence that it is not
// source worth reading, and each such case is recorded:
//
//   - a known binary file type, by extension (images, archives, compiled code,
//     fonts, media, databases): ReadsFile is false, and a NUL byte in the first
//     sniffBytes of a file of any other kind proves it binary at read time;
//   - a directory with structural evidence that it holds installed
//     dependencies, a virtual environment, a cache or version-control metadata
//     (PrunedDir), never because of its name alone;
//   - a file over the streaming cap, which is lost evaluation, not a skip.
//
// The old scanner read only files whose extension was on a list and skipped
// every directory named node_modules, vendor, dist or build. A credential
// moved into a Dockerfile, an extension-less `credentials` file or a
// .properties file was never looked at, and `fendix verify` called it
// resolved (security3-01).

// sniffBytes is how much of a file is examined to prove it binary. A NUL byte
// in it is the proof git itself uses.
const sniffBytes = 8000

// binaryExts are the file types that are binary by construction. They are not
// text, so no pattern can read a credential in them; they are the only files
// the scanner leaves unread by name.
var binaryExts = map[string]struct{}{
	// images
	".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {}, ".bmp": {}, ".ico": {}, ".icns": {},
	".webp": {}, ".tif": {}, ".tiff": {}, ".psd": {}, ".heic": {}, ".avif": {}, ".cur": {},
	// fonts
	".woff": {}, ".woff2": {}, ".ttf": {}, ".otf": {}, ".eot": {},
	// archives and packages
	".zip": {}, ".gz": {}, ".tgz": {}, ".bz2": {}, ".xz": {}, ".zst": {}, ".7z": {}, ".rar": {},
	".tar": {}, ".jar": {}, ".war": {}, ".ear": {}, ".whl": {}, ".egg": {}, ".apk": {}, ".aab": {},
	".ipa": {}, ".deb": {}, ".rpm": {}, ".dmg": {}, ".iso": {}, ".nupkg": {}, ".gem": {},
	// compiled code and objects
	".exe": {}, ".dll": {}, ".so": {}, ".dylib": {}, ".a": {}, ".o": {}, ".obj": {}, ".lib": {},
	".class": {}, ".pyc": {}, ".pyo": {}, ".pyd": {}, ".wasm": {}, ".node": {}, ".bin": {},
	// media
	".mp3": {}, ".mp4": {}, ".m4a": {}, ".mov": {}, ".avi": {}, ".mkv": {}, ".wav": {}, ".ogg": {},
	".webm": {}, ".flac": {}, ".aac": {}, ".mpg": {}, ".mpeg": {}, ".swf": {},
	// documents and databases
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {}, ".ppt": {}, ".pptx": {},
	".odt": {}, ".ods": {}, ".sqlite": {}, ".sqlite3": {}, ".db": {}, ".mdb": {}, ".parquet": {},
	".pack": {}, ".idx": {}, ".rdb": {}, ".lockb": {},
	// key and certificate stores that are binary containers
	".jks": {}, ".keystore": {}, ".p12": {}, ".pfx": {}, ".der": {},
}

// textExts are the extensions the scanner always treated as source. A NUL byte
// in such a file is not allowed to make it "binary": it is read anyway, so a
// file that used to be scanned never silently stops being scanned.
var textExts = map[string]struct{}{
	".py": {}, ".js": {}, ".ts": {}, ".jsx": {}, ".tsx": {}, ".go": {},
	".java": {}, ".rb": {}, ".php": {}, ".env": {}, ".cfg": {}, ".ini": {},
	".yaml": {}, ".yml": {}, ".toml": {}, ".json": {}, ".xml": {},
	".tf": {}, ".hcl": {}, ".sh": {}, ".bash": {}, ".zsh": {},
	".conf": {}, ".config": {},
}

// ReadsFile reports whether Scan reads a file of this base name: every file
// that is not a known binary type. A file of an unknown kind is read, and is
// then proven binary or text by its first bytes.
func ReadsFile(name string) bool {
	if isEnvFile(name) {
		return true
	}
	_, binary := binaryExts[strings.ToLower(filepath.Ext(name))]
	return !binary
}

// isKnownText reports whether name has an extension the scanner has always
// treated as source (or is an .env file).
func isKnownText(name string) bool {
	if isEnvFile(name) {
		return true
	}
	_, ok := textExts[strings.ToLower(filepath.Ext(name))]
	return ok
}

// looksBinary reports whether head proves the file binary: a NUL byte in it.
// A UTF-16 file (with or without a byte-order mark) holds a NUL in nearly every
// ASCII character and is text; the caller decodes it first.
func looksBinary(head []byte) bool {
	for _, b := range head {
		if b == 0 {
			return true
		}
	}
	return false
}

// utf16BOM reports which UTF-16 byte-order mark head starts with.
func utf16BOM(head []byte) (isUTF16, bigEndian bool) {
	if len(head) >= 2 {
		switch {
		case head[0] == 0xFF && head[1] == 0xFE:
			return true, false
		case head[0] == 0xFE && head[1] == 0xFF:
			return true, true
		}
	}
	return false, false
}

// utf16Guess recognises UTF-16 text that carries no byte-order mark. Text in
// ASCII-range characters stored as UTF-16 has a NUL in the high byte of every
// unit and none in the low byte, so NULs that fall almost only on one byte
// parity are UTF-16 of that endianness (low byte first when the odd positions
// hold them), and NULs spread over both parities are not text at all. nuls is
// how many high-byte NULs the head holds, so a caller can tell a trace from a
// pattern. A file that is mostly non-ASCII text still holds one NUL per ASCII
// unit, so a credential in it is recognised.
func utf16Guess(head []byte) (nuls int, bigEndian bool, ok bool) {
	n := len(head) &^ 1
	var even, odd int
	for i := 0; i < n; i += 2 {
		if head[i] == 0 {
			even++
		}
		if head[i+1] == 0 {
			odd++
		}
	}
	units := n / 2
	hi, lo := odd, even // little-endian: the high byte is the odd position
	big := false
	if even > odd {
		hi, lo, big = even, odd, true
	}
	// At least 8 units, and 1 in 8, are ASCII-range characters (a lone NUL or
	// two in a binary blob is not text), and the other byte position holds
	// almost no NUL: more than 1 in 16 of those would mean the NULs are not tied
	// to one position.
	if hi < 8 || hi*8 < units || lo*16 > hi {
		return 0, false, false
	}
	return hi, big, true
}

// PrunedDir says whether the directory at abs (rel is its path under the scan
// root, forward slashes) is left unread as declared out of scope, and why. The
// reason is "" when it is read. A directory is pruned only on structural
// evidence that it holds something other than first-party source, which
// scope.ClassifyDir reads from the directory itself (an installed-package tree,
// a virtualenv, a build-output tree); its name alone never prunes it (D6').
// Version-control metadata is recognised here: a .git directory with a HEAD
// file and an objects directory. It holds no source, so it is quiet: not
// worth listing in a scan's detail.
func PrunedDir(abs, rel string) (reason scope.Reason, quiet bool) {
	if filepath.Base(abs) == ".git" {
		head, errH := os.Lstat(filepath.Join(abs, "HEAD"))
		objs, errO := os.Lstat(filepath.Join(abs, "objects"))
		if errH == nil && head.Mode().IsRegular() && errO == nil && objs.IsDir() {
			return reasonGitMetadata, true
		}
	}
	if v := scope.ClassifyDir(abs, filepath.ToSlash(rel)); !v.None() {
		return v.Reason, false
	}
	return "", false
}

// reasonGitMetadata is the reason for a .git directory: version-control
// metadata, recognised by its structure.
const reasonGitMetadata scope.Reason = "git metadata"

// PrunedAncestor is prunedAncestor for another scanner's diff-aware path.
func PrunedAncestor(root, abs string) string { return prunedAncestor(root, abs) }

// NotePrunedAncestor is PrunedAncestor for a diff-aware path that also records
// the pruned directory in cov as declared out of scope, once per directory, as
// the full walk does (DE4-07): a changed file under a directory pruned on
// evidence was dropped from a --diff scan with nothing listed. It returns the
// name of the pruned directory, or "".
func NotePrunedAncestor(cov *scope.Coverage, noted map[string]bool, root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	dir := root
	for i, part := range parts[:len(parts)-1] {
		dir = filepath.Join(dir, part)
		relDir := strings.Join(parts[:i+1], "/")
		reason, quiet := PrunedDir(dir, relDir)
		if reason == "" {
			continue
		}
		if cov != nil && !quiet && !noted[relDir] {
			noted[relDir] = true
			cov.Exclude(reason, SafeName(relDir)+"/")
		}
		return part
	}
	return ""
}

// prunedAncestor returns the name of the first directory between root and abs
// (the file's own name excluded) that PrunedDir prunes, or "". The diff-aware
// fast path and SkipReason use it to keep parity with the walk.
func prunedAncestor(root, abs string) string {
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return ""
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	dir := root
	for i, part := range parts[:len(parts)-1] {
		dir = filepath.Join(dir, part)
		if reason, _ := PrunedDir(dir, strings.Join(parts[:i+1], "/")); reason != "" {
			return part
		}
	}
	return ""
}

// SafeName makes a repository-controlled path safe to put in a verify reason or
// a detail: ';', the ellipsis, control and bidirectional characters become '?'
// and the result is cut to 80 bytes at a character boundary (cross-owner
// contract C1, implemented once in scope.Sanitize).
func SafeName(s string) string { return scope.Sanitize(s) }

// lostName is SafeName for a name in the lost-evaluation segment, which the
// backend and the frontend read for loss patterns: it also replaces the
// characters those patterns are built from, so a file name cannot spell one
// (scope.SafeToken).
func lostName(s string) string { return scope.SafeToken(s) }

// LostName is lostName for another scanner's lost-evaluation names.
func LostName(s string) string { return lostName(s) }
