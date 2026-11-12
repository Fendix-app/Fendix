package semgrep

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
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
// Decision D6' (round 4): what the engine leaves out is decided by EVIDENCE
// read from the file or directory (package scope), never by a name alone. A
// directory is left out when it holds the markers of an installed-package or
// build-output tree (scope.ClassifyDir); a JavaScript or TypeScript file is
// left out when its content is minified or carries a known vendored library's
// banner (scope.ClassifyFile). A file called *.min.js that is ordinary source,
// and a directory called vendor/ or dist/ that holds the project's own code,
// are scanned. Each exclusion is handed to Semgrep as an anchored --exclude
// pattern (excludePattern), so Semgrep skips exactly the paths the engine
// declared and no others. A source file Semgrep does not select by its
// extension (APP.JS, x.mts) is in scope too, and is named to it in the
// extensions pass (scanner.go).

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

// maxExcludes bounds the --exclude patterns of one run, so the command line
// stays far below the platform's argument limit. A path past the bound is not
// excluded: it is in scope, and Semgrep scans it.
const maxExcludes = 1000

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
}

// exclude records a path declared out of scope for reason and returns whether
// Semgrep is told to skip it. A path that cannot be excluded safely (see
// excludePattern, maxExcludes) is not recorded: it stays in scope.
func (t *Targets) exclude(reason scope.Reason, rel string, dir bool) bool {
	pattern, ok := excludePattern(rel)
	if !ok || len(t.Excludes) >= maxExcludes {
		return false
	}
	t.Excludes = append(t.Excludes, pattern)
	if dir {
		rel += "/"
	}
	t.Coverage.Exclude(reason, rel)
	return true
}

// inScopeTargets walks root (or, with a non-nil allowlist, its files) and
// returns what a Semgrep run of it should evaluate. root is the directory the
// run scans; links inside it are never followed, as Semgrep does not follow
// them, and .git is not source.
func inScopeTargets(root string, allow *gitdiff.Allowlist) Targets {
	var t Targets
	consider := func(abs, rel string, info fs.FileInfo) {
		rel = filepath.ToSlash(rel)
		if !info.Mode().IsRegular() {
			return
		}
		lang := languageOf(rel)
		if lang == "" {
			return
		}
		if info.Size() > scope.MaxFileBytes {
			if v := scope.ClassifyFile(abs, rel, info.Size()); !v.None() {
				t.Coverage.Exclude(v.Reason, rel)
			} else {
				t.Coverage.TooLarge(rel)
			}
			return
		}
		if lang == "javascript" || lang == "typescript" {
			if v := scope.ClassifyFile(abs, rel, info.Size()); v.ExcludableUnderCap() && t.exclude(v.Reason, rel, false) {
				return
			}
		}
		f, err := os.Open(abs)
		if err != nil {
			t.Coverage.Unreadable(rel)
			return
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

	if allow != nil {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			return t
		}
		dirVerdict := map[string]scope.Verdict{}
		// pruned returns the first ancestor directory of rel that holds the
		// evidence of an installed or built tree.
		pruned := func(rel string) (string, scope.Verdict) {
			parts := strings.Split(rel, "/")
			for i := 1; i < len(parts); i++ {
				dir := strings.Join(parts[:i], "/")
				v, ok := dirVerdict[dir]
				if !ok {
					v = scope.ClassifyDir(filepath.Join(absRoot, filepath.FromSlash(dir)), dir)
					dirVerdict[dir] = v
				}
				if !v.None() {
					return dir, v
				}
			}
			return "", scope.Verdict{}
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
			if dir, v := pruned(rel); !v.None() {
				if listed[dir] {
					continue
				}
				if t.exclude(v.Reason, dir, true) {
					listed[dir] = true
					continue
				}
			}
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
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			slash := filepath.ToSlash(rel)
			if v := scope.ClassifyDir(p, slash); !v.None() && t.exclude(v.Reason, slash, true) {
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
