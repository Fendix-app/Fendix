package semgrep

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 (redteam-semgrep-01): Semgrep says nothing about a file it left
// unread. The engine lists what the run was meant to evaluate and compares it
// with paths.scanned; see targets.go.

// padded is body followed by comment lines up to more than n bytes: the
// vulnerable code stays at the top, where an evaluated file reports it.
func padded(body string, n int) string {
	var b strings.Builder
	b.WriteString(body)
	for b.Len() <= n {
		b.WriteString("// padding padding padding padding padding padding padding padding\n")
	}
	return b.String()
}

// scanTreeWith writes files under a fresh root, has a stand-in Semgrep answer
// with a document whose paths.scanned lists scanned (relative to the root),
// and returns the run.
func scanTreeWith(t *testing.T, files map[string]string, scanned []string, withPaths bool) (Run, string) {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, files)
	doc := map[string]any{"results": []any{}, "errors": []any{}, "time": map[string]any{"fixpoint_timeouts": []any{}}}
	if withPaths {
		abs := make([]string, len(scanned))
		for i, rel := range scanned {
			abs[i] = filepath.Join(root, filepath.FromSlash(rel))
		}
		doc["paths"] = map[string]any{"scanned": abs}
	}
	raw, _ := json.Marshal(doc)
	installFakeSemgrep(t, string(raw), "", 0)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	return run, root
}

// minifiedJS is a bundle's worth of one long line: the content statistics (not
// the name) are what make a file minified (scope.ClassifyFile).
func minifiedJS() string { return "!function(){" + strings.Repeat("a=b(c,d);", 300) + "}();\n" }

func TestScanRunListsWhatTheRunLeftUnread(t *testing.T) {
	big := padded(spikeApp, scope.MaxFileBytes)
	run, _ := scanTreeWith(t, map[string]string{
		"app.js":                          spikeApp,
		"big.js":                          big,
		"lib/ignored.js":                  spikeApp,                 // in scope, absent from paths.scanned
		"tests/app.js":                    spikeApp,                 // in scope, absent from paths.scanned (D6': no path filters)
		"web/app.test.ts":                 spikeApp,                 // likewise
		"public/app.min.js":               minifiedJS(),             // minified by its content
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`, // an installed npm tree
		"node_modules/x/index.js":         spikeApp,
		"dist/out.js":                     spikeApp, // named like build output, no evidence: in scope
		"README.md":                       "not a target",
		"package-lock.json":               padded("{}", scope.MaxFileBytes), // not a Semgrep target at all
		"main.py":                         picklePy,
		"tests/test_main.py":              picklePy, // the Python pack has no path filters: in scope
	}, []string{"app.js", "main.py"}, true)

	cov := run.Coverage
	// D6' (redteam4-d6-03): the replaced expectation declared tests/app.js and
	// web/app.test.ts out of scope by the packs' path filters; the packs carry
	// none now, so a test path Semgrep did not report is lost like any file.
	if !cov.Lost() || cov.LostFiles() != 6 {
		t.Fatalf("LostFiles = %d (%s); want big.js, dist/out.js, lib/ignored.js, tests/app.js, tests/test_main.py and web/app.test.ts", cov.LostFiles(), cov.LostDetail(1<<20))
	}
	lost := cov.LostDetail(1 << 20)
	for _, want := range []string{"1 over 1048576 bytes (big.js)", "5 not evaluated by semgrep (dist/out.js, lib/ignored.js, tests/app.js +2 more)"} {
		if !strings.Contains(lost, want) {
			t.Errorf("lost detail %q lacks %q", lost, want)
		}
	}
	declared := cov.DeclaredDetail(1 << 20)
	for _, want := range []string{"minified 1 (public/app.min.js)", "installed npm packages 1 (node_modules/)"} {
		if !strings.Contains(declared, want) {
			t.Errorf("declared detail %q lacks %q", declared, want)
		}
	}
	for _, never := range []string{"README.md", "package-lock.json", "(app.js", ", app.js", "(main.py", ", main.py"} {
		if strings.Contains(lost+declared, never) {
			t.Errorf("%q is in a detail: %q / %q", never, lost, declared)
		}
	}
}

func TestScanRunWithEverythingScannedLosesNothing(t *testing.T) {
	run, _ := scanTreeWith(t, map[string]string{"app.js": spikeApp, "src/main.py": picklePy}, []string{"app.js", "src/main.py"}, true)
	if run.Coverage.Lost() || run.Coverage.Declared() {
		t.Errorf("coverage = %q / %q; want nothing", run.Coverage.LostDetail(240), run.Coverage.DeclaredDetail(240))
	}
}

// A document with no paths.scanned list cannot show that any target was
// evaluated: every one is lost, none is declared out of scope on its word.
func TestScanRunWithoutAScannedListLosesEveryTarget(t *testing.T) {
	run, _ := scanTreeWith(t, map[string]string{"app.js": spikeApp, "tests/app.js": spikeApp}, nil, false)
	if got := run.Coverage.LostFiles(); got != 2 {
		t.Errorf("LostFiles = %d (%s); want 2", got, run.Coverage.LostDetail(240))
	}
	// An empty tree has nothing to show, list or no list.
	if run, _ := scanTreeWith(t, map[string]string{"README.md": "x"}, nil, false); run.Coverage.Lost() {
		t.Errorf("a tree with no targets lost %s", run.Coverage.LostDetail(240))
	}
}

func TestScanRunNamesAnUnreadableTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{"keys.py": picklePy, "ok.py": picklePy})
	if err := os.Chmod(filepath.Join(root, "keys.py"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "keys.py"), 0o644) })
	targets := inScopeTargets(root, nil)
	targets.checkScanned(map[string]bool{"ok.py": true}, true)
	if got := targets.Coverage.LostDetail(240); !strings.Contains(got, "1 unreadable (keys.py)") {
		t.Errorf("lost detail %q; want keys.py unreadable", got)
	}
}

// A diff scan's targets are its changed files, not the tree.
func TestScanRunTargetsOnlyTheDiff(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.js": spikeApp, "b.js": spikeApp, "big.js": padded(spikeApp, scope.MaxFileBytes)})
	allow := gitdiff.NewAllowlist(root, []string{"a.js", "big.js"})
	targets := inScopeTargets(root, allow)
	targets.checkScanned(map[string]bool{"a.js": true}, true)
	if got := targets.Coverage.LostDetail(240); got != "lost evaluation: 1 in-scope file not read: 1 over 1048576 bytes (big.js)" {
		t.Errorf("lost detail = %q", got)
	}
}

// The --max-target-bytes the engine passes is the cap it lists files against.
func TestScanRunPassesTheSizeCap(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installVersionedSemgrep(t, "1.182.1", nil, argv)
	if _, err := ScanRun(context.Background(), t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	if args := recordedArgs(t, argv); !strings.Contains(args, "\n--max-target-bytes\n1048576\n") {
		t.Errorf("--max-target-bytes 1048576 not passed:%s", args)
	}
}

// Real Semgrep: an over-cap file, a .semgrepignore'd file and the declared
// exclusions, end to end through the run.
func TestRealSemgrepReportsWhatItLeftUnread(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"app.js":                          spikeApp,
		"big.js":                          padded(spikeApp, scope.MaxFileBytes),
		"tests/app.js":                    spikeApp,
		"public/app.min.js":               minifiedJS(), // minified by its content
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/x/index.js":         spikeApp,
		".semgrepignore":                  "app.js\n",
	})
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range run.Findings {
		seen[f.Endpoint] = true
	}
	if !seen["app.js:9"] {
		t.Errorf("app.js:9 not reported: %v", seen)
	}
	lost := run.Coverage.LostDetail(1 << 20)
	if lost != "lost evaluation: 1 in-scope file not read: 1 over 1048576 bytes (big.js)" {
		t.Errorf("lost detail = %q", lost)
	}
	declared := run.Coverage.DeclaredDetail(1 << 20)
	// D6' (redteam4-d6-03): tests/app.js is evaluated now, not declared out of
	// scope by its directory; the replaced expectation listed it as a
	// "test/fixture path".
	if !seen["tests/app.js:9"] {
		t.Errorf("tests/app.js:9 not reported: %v", seen)
	}
	const want = "declared out of scope, not scanned: installed npm packages 1 (node_modules/), minified 1 (public/app.min.js)"
	if declared != want {
		t.Errorf("declared detail = %q, want %q", declared, want)
	}
}

// Real Semgrep: a --code that is itself a symbolic link is scanned through
// it (verify-secrets2's open question).
func TestRealSemgrepScansThroughALinkedRoot(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	real := t.TempDir()
	writeTree(t, real, map[string]string{"app.js": spikeApp})
	link := filepath.Join(t.TempDir(), "code")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	run, err := ScanRun(context.Background(), link, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.Findings) == 0 || run.Findings[0].Endpoint != "app.js:9" {
		t.Errorf("findings = %+v; want app.js:9", run.Findings)
	}
	if run.Coverage.Lost() {
		t.Errorf("a linked root lost %s", run.Coverage.LostDetail(240))
	}
}

// --x-ignore-semgrepignore-files also turns off Semgrep's default list, so
// the installed-dependency directories it covered are the engine's own
// excludes now: not scanned, and listed by name, with the evidence that makes
// them so. A directory that is only CALLED .venv or venv, with no pyvenv.cfg,
// is the project's own code (decision D6'): it is scanned.
func TestVirtualEnvironmentsAreExcludedAndListed(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".venv/pyvenv.cfg": "home = /usr/bin\n",
		".venv/lib/python3.14/site-packages/x/__init__.py": picklePy,
		"env/pyvenv.cfg": "home = /usr/bin\nversion = 3.14\n", // any name
		"env/lib/y.py":   picklePy,
		"venv/lib/z.py":  picklePy, // called venv, no evidence
		"app.py":         picklePy,
	})
	targets := inScopeTargets(root, nil)
	if got := targets.Excludes; len(got) != 2 || got[0] != "/.venv" || got[1] != "/env" {
		t.Errorf("Excludes = %q; want /.venv and /env", got)
	}
	targets.checkScanned(map[string]bool{"app.py": true, "venv/lib/z.py": true}, true)
	if targets.Coverage.Lost() {
		t.Errorf("lost %s", targets.Coverage.LostDetail(240))
	}
	if got := targets.Coverage.DeclaredDetail(240); got != "declared out of scope, not scanned: python virtualenv 2 (.venv/, env/)" {
		t.Errorf("declared detail = %q", got)
	}
}
