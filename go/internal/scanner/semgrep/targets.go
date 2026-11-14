package semgrep

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 for Semgrep. Semgrep's own JSON says which files it evaluated
// (paths.scanned) and nothing about the ones it did not: a file over
// --max-target-bytes, one it could not read, one a .semgrepignore named, all
// vanish with the run still exit 0 and every finding in them missing
// (redteam-semgrep-01). So the engine lists the files Semgrep was meant to
// evaluate itself (inScopeTargets), and after the run compares that list
// with paths.scanned (checkScanned):
//
//   - a file over scope.MaxFileBytes, unreadable, or in scope and not in
//     paths.scanned is lost evaluation: the orchestrator records the run
//     failed/execution_error with the files named, and keeps the findings;
//   - a file or directory the engine itself leaves out, on evidence read from
//     it (below), is declared out of scope: listed by name, with its reason,
//     in the ok detail and, complete, in the report's metadata; never a gap.
//     No rule skips a file by its path (rulepaths.go), so a test or fixture
//     file is evaluated like any other.
//
// Decision D5-2 (round 5, contract C6): the engine leaves out of the target
// set no source file because of what it looks like. Every file of a pack
// language at or below scope.MaxFileBytes is evaluated: minified, vendored,
// generated, test and fixture code included, whatever its banner, header, name,
// directory, literals or line statistics say. The only exclusions are the root
// .git directory with a real layout (scope.ClassifyDir), which is version
// control metadata, and, for the other analyzers, a recognized lockfile (never
// a Semgrep target: none has a pack language's extension). A source file over
// the cap or unreadable is lost evaluation, never an exclusion. A source file
// Semgrep does not select by its extension (APP.JS, x.mts) is in scope too, and
// is named to it in the extensions pass (scanner.go), by an absolute path or
// after "--" so that no file name can become an option (plan.go args).

// targetLanguages maps the extensions Semgrep 1.182.1 selects for the packs'
// languages (checked against the real binary: the match is case-sensitive, and
// .cts, .mts, .es6 and .vue are not selected) to those languages.
var targetLanguages = map[string]string{
	".py":   "python",
	".pyi":  "python",
	".js":   "javascript",
	".jsx":  "javascript",
	".cjs":  "javascript",
	".mjs":  "javascript",
	".ts":   "typescript",
	".tsx":  "typescript",
	".java": "java",
	".go":   "go",
}

// extraLanguages are source extensions of the packs' languages that Semgrep
// does not select when written so. Source with one is in scope (decision D6':
// a file name does not take first-party code out of it) and is handed to
// Semgrep explicitly (the extensions pass, plan.go), which evaluates an
// explicit target whatever its extension. A Vue single-file component is in the
// list because its <script> is JavaScript; Semgrep cannot parse the whole file,
// so it comes back as a parse failure and is named as not evaluated, which is
// what it is.
var extraLanguages = map[string]string{
	".cts": "typescript", ".mts": "typescript", ".es6": "javascript", ".vue": "javascript",
}

// languageOf is the pack language of a source file, or "" when it is not
// source of a pack language. The extension is matched without regard to case:
// APP.JS and Server.Py are source (redteam4-d6-02).
func languageOf(rel string) string {
	ext := strings.ToLower(path.Ext(rel))
	if lang, ok := targetLanguages[ext]; ok {
		return lang
	}
	return extraLanguages[ext]
}

// semgrepSelects reports whether Semgrep selects rel by its extension on its
// own. A source file it does not select (another case, or an extension in
// extraLanguages) goes to the extensions pass.
func semgrepSelects(rel string) bool {
	_, ok := targetLanguages[path.Ext(rel)]
	return ok
}

// excludePattern is the anchored gitignore-style --exclude pattern that names
// exactly the path rel under the scan root, or false when it cannot be written
// safely (a control character, a name with leading or trailing blanks, invalid
// UTF-8): such a path is simply not excluded, so it stays in scope.
func excludePattern(rel string) (string, bool) {
	if rel == "" || !utf8.ValidString(rel) || strings.TrimSpace(rel) != rel {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('/')
	for _, r := range rel {
		switch {
		case r < 0x20 || r == 0x7f:
			return "", false
		case r == '\\' || r == '[' || r == ']' || r == '*' || r == '?':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	out := b.String()
	// A leading '!' or '#' after the anchoring '/' is an ordinary character,
	// so nothing more to escape there.
	return out, true
}

// Targets is the engine's own list of the files a run is meant to evaluate,
// and what it already knows was left unread.
type Targets struct {
	// files are the in-scope files Semgrep should report in paths.scanned,
	// relative to the root, forward slashes.
	files []string
	// explicit are the files among them that Semgrep does not select by their
	// extension: they are handed to it by name (the extensions pass).
	explicit []string
	// size is each in-scope file's size in bytes, which the stage budget
	// plans from (plan.go): how to split the run and how long a retry of one
	// file may take.
	size map[string]int64
	// Coverage holds the files left unread before Semgrep ran: too large,
	// unreadable, or declared out of scope.
	Coverage scope.Coverage
	// Excludes are the anchored --exclude patterns of what was declared out of
	// scope and that Semgrep would otherwise select.
	Excludes []string
	// unreadableExcludes are the part of Excludes that names an unreadable entry.
	unreadableExcludes []string
}

// maxUnreadableExcludes bounds the --exclude arguments one run carries for
// files and directories the engine could not read.
const maxUnreadableExcludes = 512

// excludeUnreadable tells Semgrep's own listing of a root run to leave rel
// (a file or directory the engine could not read, already recorded as lost
// evaluation under its reason) alone. Without it Semgrep tries to read the
// entry itself, fails to obtain its target files and loses the whole run to one
// unreadable entry (round 5, redteam5-05). The loss stays recorded: this changes
// what Semgrep is asked, not what the report says.
func (t *Targets) excludeUnreadable(rel string) {
	if len(t.unreadableExcludes) >= maxUnreadableExcludes {
		return
	}
	if pattern, ok := excludePattern(rel); ok {
		t.unreadableExcludes = append(t.unreadableExcludes, pattern)
		t.Excludes = append(t.Excludes, pattern)
	}
}

// skipVCSMetadata tells Semgrep to skip exactly the root .git directory the
// engine left out of the target set. It is not recorded as declared: version
// control metadata is not source and is quiet in every analyzer's detail.
func (t *Targets) skipVCSMetadata() {
	if pattern, ok := excludePattern(".git"); ok {
		t.Excludes = append(t.Excludes, pattern)
	}
}

// inScopeTargets walks root (or, with a non-nil allowlist, its files) and
// returns what a Semgrep run of it should evaluate. root is the directory the
// run scans; links inside it are never followed, as Semgrep does not follow
// them, and the root .git directory (with a real layout) is not source.
func inScopeTargets(root string, allow *gitdiff.Allowlist) Targets {
	var t Targets
	consider := func(abs, rel string, info fs.FileInfo) {
		rel = filepath.ToSlash(rel)
		if !info.Mode().IsRegular() {
			return
		}
		if languageOf(rel) == "" {
			return
		}
		if info.Size() > scope.MaxFileBytes {
			// Over the cap: Semgrep skips it too (--max-target-bytes), so the
			// engine names it as lost evaluation, whatever it looks like.
			t.Coverage.TooLarge(rel)
			return
		}
		// A probe that neither blocks on a FIFO swapped in after the walk nor
		// follows a link swapped in for the file.
		f, err := scope.OpenRegular(abs)
		if err != nil {
			t.Coverage.Unreadable(rel)
			t.excludeUnreadable(rel)
			return
		}
		if isPythonSource(rel) && !declaresReadableEncoding(f) {
			// The program is not the bytes Semgrep reads: say so (redteam5-10).
			t.Coverage.NotParsed(rel)
		}
		_ = f.Close()
		t.files = append(t.files, rel)
		if !semgrepSelects(rel) {
			t.explicit = append(t.explicit, rel)
		}
		if t.size == nil {
			t.size = map[string]int64{}
		}
		t.size[rel] = info.Size()
	}

	rootGit := false
	if absRoot, err := filepath.Abs(root); err == nil {
		rootGit = !scope.ClassifyDir(filepath.Join(absRoot, ".git"), ".git").None()
	}
	if rootGit {
		t.skipVCSMetadata()
	}

	if allow != nil {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return t
		}
		listed := map[string]bool{}
		for _, abs := range allow.AbsPaths() {
			rel, err := filepath.Rel(absRoot, abs)
			if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			rel = filepath.ToSlash(rel)
			if gitdiff.TraversesSymlink(absRoot, abs) {
				if languageOf(rel) != "" {
					t.Coverage.Symlink(rel)
				}
				continue
			}
			if rootGit && strings.HasPrefix(rel, ".git/") {
				continue
			}
			if listed[rel] {
				continue
			}
			listed[rel] = true
			info, err := os.Lstat(abs)
			if err != nil {
				continue
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				if languageOf(rel) != "" {
					t.Coverage.Symlink(rel)
				}
				continue
			}
			consider(abs, rel, info)
		}
		return t
	}

	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		if walkErr != nil {
			if rel != "." {
				t.Coverage.Unreadable(filepath.ToSlash(rel) + "/")
				if d != nil && d.IsDir() {
					t.excludeUnreadable(filepath.ToSlash(rel))
				}
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// Only <root>/.git with a real layout is left out; a .git (or any
			// other directory) elsewhere is ordinary content.
			if rootGit && rel == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			slash := filepath.ToSlash(rel)
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				t.Coverage.Symlink(slash + "/")
			} else if languageOf(slash) != "" {
				t.Coverage.Symlink(slash)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if languageOf(rel) != "" {
				t.Coverage.Unreadable(filepath.ToSlash(rel))
				t.excludeUnreadable(filepath.ToSlash(rel))
			}
			return nil
		}
		consider(p, rel, info)
		return nil
	})
	return t
}

// scannedPaths decodes the document's paths.scanned, relative to absRoot,
// and whether the document had such a list at all.
func scannedPaths(raw json.RawMessage, absRoot string) (map[string]bool, bool) {
	var paths struct {
		Scanned json.RawMessage `json:"scanned"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &paths) != nil {
		return nil, false
	}
	var entries []json.RawMessage
	if !strings.HasPrefix(strings.TrimSpace(string(paths.Scanned)), "[") || json.Unmarshal(paths.Scanned, &entries) != nil {
		return nil, false
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		if p := rawString(e); p != "" {
			out[relPath(p, absRoot)] = true
		}
	}
	return out, true
}

// checkScanned files every in-scope target that the run did not report
// evaluating as lost evaluation. The packs carry no path filters (rulepaths.go),
// so a file Semgrep did not report is a file it did not evaluate. A document
// without a paths.scanned list cannot show any target was evaluated.
func (t *Targets) checkScanned(scanned map[string]bool, reported bool) {
	for _, rel := range t.files {
		if reported && scanned[rel] {
			continue
		}
		t.Coverage.NotScanned(rel)
	}
	if lost := t.Coverage.LostFiles(); lost > 0 {
		slog.Warn("semgrep: in-scope files were not evaluated; findings in them are missing",
			"files", lost, "paths_scanned_reported", reported)
	}
}

// isPythonSource reports whether rel is a file whose first two lines can declare
// a source encoding (PEP 263).
func isPythonSource(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".py", ".pyw", ".pyi":
		return true
	}
	return false
}

var (
	// pepCommentOnly is the first line a declaration may follow (blank or a
	// comment), pepCoding the declaration itself. Both are CPython's own
	// expressions (Lib/tokenize.py: cookie_re, blank_re), including that
	// "coding" is matched in lower case.
	pepCommentOnly = regexp.MustCompile(`^[ \t\f]*(?:[#\r\n]|$)`)
	pepCoding      = regexp.MustCompile(`^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)`)
	// asciiTransparentCodec names the declared encodings in which every ASCII
	// byte is the character it looks like and nothing else, so reading the bytes
	// as UTF-8 gives Semgrep the program's own text. Anything else declared (utf-7,
	// utf-16, utf-32, an EBCDIC page, a multi-byte CJK page, ...) is not.
	asciiTransparentCodec = regexp.MustCompile(`^(?:utf-?8(?:-sig)?|u8|utf|ascii|us-ascii|646|latin-?1|latin|l1|iso-?8859-\d+|latin-?\d+|l\d+|cp125\d|windows-125\d|cp(?:437|850|852|866)|koi8-[ru]|mac-?roman)$`)
)

// declaresReadableEncoding reports whether the Python file f declares no source
// encoding, or one Semgrep reads correctly as UTF-8. Only the first two lines
// are examined, as CPython does, and only the first 512 bytes are read.
func declaresReadableEncoding(f *os.File) bool {
	buf := make([]byte, 512)
	n, _ := f.ReadAt(buf, 0)
	lines := strings.SplitN(string(buf[:n]), "\n", 3)
	for i, line := range lines {
		if i >= 2 {
			break
		}
		if m := pepCoding.FindStringSubmatch(line); m != nil {
			name := strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
			return asciiTransparentCodec.MatchString(name)
		}
		if !pepCommentOnly.MatchString(line) {
			return true
		}
	}
	return true
}
