package semgrep

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sort"
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
	// scope and that Semgrep would otherwise select, and of the unreadable
	// entries it must not read itself (finalised when the walk ends).
	Excludes []string
	// wse1Unreadable is the set of root-relative paths (a file or a directory,
	// which covers everything beneath it) Semgrep's own listing is told to
	// leave alone, because the engine could not read them (excludeUnreadable).
	wse1Unreadable map[string]bool
	// wse1Unexcludable are unreadable entries no --exclude can keep out of
	// Semgrep's listing: none of their ancestors but the scan root can be
	// written as a pattern. wse1Overflow is set when more than
	// maxUnreadableExcludes entries are directly under the root. Either one means
	// Semgrep would fail to list its targets (ListingErr).
	wse1Unexcludable []string
	wse1Overflow     bool
}

// maxUnreadableExcludes bounds the --exclude arguments one run carries for
// files and directories the engine could not read.
const maxUnreadableExcludes = 512

// maxUnexcludableNamed bounds how many unexcludable names ListingErr keeps.
const maxUnexcludableNamed = 64

// wse1Parent is the directory part of a root-relative path, "" for an entry
// directly under the root.
func wse1Parent(rel string) string {
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return ""
}

// wse1Depth is how many path elements rel has.
func wse1Depth(rel string) int { return strings.Count(rel, "/") + 1 }

// wse1WritablePattern is excludePattern for an unreadable entry, which unlike a
// declared exclusion must be kept out of Semgrep's listing whatever its name is.
// It also writes a path whose only trouble is an ASCII blank at either end,
// which Semgrep 1.182.1 reads exactly when written as gitignore does (checked on
// the real binary): a leading blank needs nothing, and every trailing blank is
// escaped with a backslash, since an unescaped trailing blank is trimmed and the
// pattern would silently match nothing. A control character or invalid UTF-8
// anywhere in the path is still not writable.
func wse1WritablePattern(rel string) (string, bool) {
	if p, ok := excludePattern(rel); ok {
		return p, true
	}
	inner := strings.Trim(rel, " ")
	if inner == "" || inner == rel || strings.TrimSpace(inner) != inner {
		return "", false
	}
	p, ok := excludePattern(inner)
	if !ok {
		return "", false
	}
	lead := rel[:strings.Index(rel, inner)]
	trail := strings.Repeat(`\ `, len(rel)-len(lead)-len(inner))
	return "/" + lead + p[1:] + trail, true
}

// wse1NearestPatternable is rel, or the nearest ancestor of rel whose path
// wse1WritablePattern can write, or "" when only the scan root is left.
func wse1NearestPatternable(rel string) string {
	for rel != "" {
		if _, ok := wse1WritablePattern(rel); ok {
			return rel
		}
		rel = wse1Parent(rel)
	}
	return ""
}

// wse1Covered reports whether rel, or a directory above it, is already excluded.
func (t *Targets) wse1Covered(rel string) bool {
	for p := rel; p != ""; p = wse1Parent(p) {
		if t.wse1Unreadable[p] {
			return true
		}
	}
	return false
}

// wse1Exclude adds rel to the excluded set, and drops the entries beneath it,
// which it covers.
func (t *Targets) wse1Exclude(rel string) {
	if t.wse1Covered(rel) {
		return
	}
	if t.wse1Unreadable == nil {
		t.wse1Unreadable = map[string]bool{}
	}
	prefix := rel + "/"
	for e := range t.wse1Unreadable {
		if strings.HasPrefix(e, prefix) {
			delete(t.wse1Unreadable, e)
		}
	}
	t.wse1Unreadable[rel] = true
}

// wse1Coalesce brings the excluded set within maxUnreadableExcludes by excluding
// a directory in place of the entries inside it, deepest first. A readable
// sibling inside such a directory is no longer given to Semgrep, and is named
// lost evaluation by checkScanned (it is in t.files and not in paths.scanned):
// it is never dropped silently. Entries directly under the root cannot be
// lifted; when they alone exceed the bound, wse1Overflow is set.
func (t *Targets) wse1Coalesce() {
	if len(t.wse1Unreadable) <= maxUnreadableExcludes {
		return
	}
	deepest := 0
	for e := range t.wse1Unreadable {
		if d := wse1Depth(e); d > deepest {
			deepest = d
		}
	}
	for depth := deepest; depth > 1 && len(t.wse1Unreadable) > maxUnreadableExcludes; depth-- {
		var lift []string
		for e := range t.wse1Unreadable {
			if wse1Depth(e) == depth {
				lift = append(lift, e)
			}
		}
		for _, e := range lift {
			parent := wse1NearestPatternable(wse1Parent(e))
			if parent == "" {
				continue // only the root is left above it: it stays as it is
			}
			delete(t.wse1Unreadable, e)
			t.wse1Exclude(parent)
		}
	}
	if len(t.wse1Unreadable) > maxUnreadableExcludes {
		t.wse1Overflow = true
	}
}

// excludeUnreadable tells Semgrep's own listing of a root run to leave rel
// (a file or directory the engine could not read, already recorded as lost
// evaluation under its reason) alone. Without it Semgrep tries to read the
// entry itself, fails to obtain its target files and loses the whole run to one
// unreadable entry (round 5, redteam5-05). The loss stays recorded: this changes
// what Semgrep is asked, not what the report says.
//
// Every unreadable entry is kept out of the listing (R5-14, R6-E5). An entry
// whose own path cannot be written as a pattern (invalid UTF-8, a control
// character, a blank at either end) is excluded through its nearest ancestor
// directory that can; and when more than maxUnreadableExcludes patterns would be
// needed, directories are excluded in place of the entries inside them
// (wse1Coalesce). A readable file inside such a directory is named lost
// evaluation, not dropped. An entry with no ancestor but the scan root cannot be
// excluded at all: ListingErr says so before Semgrep is run.
func (t *Targets) excludeUnreadable(rel string) {
	if t.wse1Overflow || t.wse1Covered(rel) {
		return // the run is already one ListingErr ends
	}
	at := wse1NearestPatternable(rel)
	if at == "" {
		if len(t.wse1Unexcludable) < maxUnexcludableNamed {
			t.wse1Unexcludable = append(t.wse1Unexcludable, rel)
		} else {
			t.wse1Overflow = true
		}
		return
	}
	t.wse1Exclude(at)
	t.wse1Coalesce()
}

// wse1FinalizeExcludes appends the unreadable entries' patterns to Excludes, in
// path order so a run's arguments are the same every time.
func (t *Targets) wse1FinalizeExcludes() {
	paths := make([]string, 0, len(t.wse1Unreadable))
	for e := range t.wse1Unreadable {
		paths = append(paths, e)
	}
	sort.Strings(paths)
	for _, e := range paths {
		if pattern, ok := wse1WritablePattern(e); ok {
			t.Excludes = append(t.Excludes, pattern)
		}
	}
}

// ListingErr is non-nil when an unreadable entry cannot be kept out of
// Semgrep's own file listing by any --exclude: its name cannot be written as a
// pattern and no directory but the scan root lies above it, or more than
// maxUnreadableExcludes unreadable entries are directly under the root. Semgrep
// would try to read them itself and lose the whole run ("Failed to obtain target
// files"), so a run that starts regardless says nothing true; the caller ends it
// with this error, naming what could not be excluded.
func (t Targets) ListingErr() error {
	if len(t.wse1Unexcludable) == 0 && !t.wse1Overflow {
		return nil
	}
	msg := "semgrep: unreadable entries cannot be kept out of Semgrep's own file listing, so it would fail to list its targets"
	if n := len(t.wse1Unexcludable); n > 0 {
		var named []string
		for i, rel := range t.wse1Unexcludable {
			if i == 3 {
				break
			}
			named = append(named, scope.Sanitize(rel))
		}
		msg += fmt.Sprintf(": no pattern can name %d entr%s directly under the scan root (%s)", n, map[bool]string{true: "y", false: "ies"}[n == 1], strings.Join(named, ", "))
	}
	if t.wse1Overflow {
		msg += fmt.Sprintf("; more than %d unreadable entries are directly under the scan root", maxUnreadableExcludes)
	}
	return errors.New(msg)
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
func inScopeTargets(root string, allow *gitdiff.Allowlist) (t Targets) {
	// The unreadable entries' patterns are written once the walk has seen them
	// all, so a directory can stand in for the entries inside it.
	defer func() { t.wse1FinalizeExcludes() }()
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
		if languageOf(rel) == "python" && scope.ClassifyPythonFile(f).Lost() {
			// The program is not the bytes Semgrep reads: a codec that is not
			// ASCII-transparent, a name no codec answers to (only a run-time
			// registration could), a cookie only `python -x` reads (redteam5-10,
			// R5-01, R6-E1, R6-E6). The shared predicate reads the whole of lines
			// 1 and 2, as CPython does, and resolves the name through the table
			// measured on the reference interpreter. The file stays a target:
			// Semgrep still reports what it finds in it.
			t.Coverage.NotParsed(rel)
		}
		if _, lost := scope.EscapeLostFile(rel, f); lost {
			// An identifier spelled with a unicode escape (`\u0065val(x)` is
			// `eval(x)` to the runtime) matches no pattern: the file is not
			// evaluated, whatever Semgrep reports in it (R6-E7a). It stays a
			// target, as a PEP 263 loss does, and is named as not parsed, the
			// existing reason.
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
