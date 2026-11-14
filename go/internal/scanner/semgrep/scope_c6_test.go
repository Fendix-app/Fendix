package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// Review item 4 (argument injection into Semgrep): no file name and no root
// name can become an option. Every target is absolute and follows "--", and a
// changed-file filter is one "--include=<rel>" argument.

func TestAbsoluteTargetNeverStartsWithADash(t *testing.T) {
	for _, p := range []string{"-x.py", "--config=evil.py", "-root/a.py", "./-x.py", "a/b.py"} {
		got := absoluteTarget(p)
		if !filepath.IsAbs(got) {
			t.Errorf("absoluteTarget(%q) = %q, not absolute", p, got)
		}
	}
	if got := absoluteTarget("/abs/-x.py"); got != "/abs/-x.py" {
		t.Errorf("absoluteTarget of an absolute path = %q", got)
	}
}

func TestEveryTargetIsAbsoluteAndFollowsDoubleDash(t *testing.T) {
	st := &stage{target: "-root", includes: []string{"-x.py", "--config=evil.py"}}
	for name, inv := range map[string]invocation{
		"the root":        {label: "p"},
		"explicit files":  {label: "e", targets: []string{"-y.mts", "--version.js"}, explicit: true, unknownExt: true},
		"a retried file":  {label: "r", targets: []string{"-z.py"}, retry: true, explicit: true},
		"a relative file": {label: "r", targets: []string{"--scan-unknown-extensions"}, explicit: true},
	} {
		args := st.args(inv)
		dd := -1
		for i, a := range args {
			if a == "--" {
				dd = i
				break
			}
		}
		if dd < 0 {
			t.Errorf("%s: no \"--\" in %v", name, args)
			continue
		}
		if dd == len(args)-1 {
			t.Errorf("%s: nothing follows \"--\": %v", name, args)
		}
		for _, a := range args[dd+1:] {
			if !filepath.IsAbs(a) {
				t.Errorf("%s: target %q after -- is not absolute", name, a)
			}
		}
		for _, a := range args[:dd] {
			if strings.Contains(a, "evil.py") && !strings.HasPrefix(a, "--include=") {
				t.Errorf("%s: %q before -- is a bare name", name, a)
			}
		}
	}
	args := st.args(invocation{label: "p"})
	for _, want := range []string{"--include=-x.py", "--include=--config=evil.py"} {
		found := false
		for _, a := range args {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Errorf("args lack %q: %v", want, args)
		}
	}
	for _, a := range args {
		if a == "--include" {
			t.Errorf("a bare --include (its value would be a separate argument): %v", args)
		}
	}
}

// Through ScanRun, with a stand-in Semgrep that records its argv: a relative
// --code and files whose names look like options reach Semgrep as paths.
func TestScanRunHandsEveryHostileNameToSemgrepAsAPath(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)
	root := chdirTempTree(t, "-x.py", "--config=evil.py", "-y.mts", "--version.js", "ok.py")
	for _, rel := range []string{"-x.py", "--config=evil.py", "-y.mts", "--version.js", "ok.py"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(picklePy), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	if _, err := ScanRun(context.Background(), ".", nil); err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	raw, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	dd := -1
	for i, l := range lines {
		if l == "--" {
			dd = i
		}
	}
	if dd < 0 {
		t.Fatalf("no -- in the last invocation: %v", lines)
	}
	for _, l := range lines[dd+1:] {
		if !filepath.IsAbs(l) {
			t.Errorf("target %q is not absolute", l)
		}
	}
	for _, l := range lines[:dd] {
		if l == "-x.py" || l == "-y.mts" || l == "--version.js" || l == "--config=evil.py" {
			t.Errorf("a file name reached Semgrep as an option: %q", l)
		}
	}
}

// A diff scan whose changed file starts with '-' passes it as an --include
// value and finds it.
func TestDiffScanChangedFileStartingWithADashIsAnIncludeValue(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)
	root := chdirTempTree(t, "-x.py", "a.py")
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	allow := gitdiff.NewAllowlist(root, []string{"-x.py"})
	if _, err := ScanRun(context.Background(), root, allow); err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if got := recordedIncludes(t, argv); len(got) != 1 || got[0] != "-x.py" {
		t.Errorf("includes = %q; want -x.py as one --include= argument", got)
	}
}

// Marker and file probing never blocks: a FIFO and a link whose names are source
// extensions are not opened, and a regular file is probed without following a
// link.
func TestInScopeTargetsNeverBlocksOnAFifoOrFollowsALink(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"ok.py": picklePy})
	if err := mkfifoForTest(filepath.Join(root, "pipe.py")); err != nil {
		t.Skipf("no FIFOs: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "o.py")
	if err := os.WriteFile(outside, []byte(picklePy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.py")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	done := make(chan Targets, 1)
	go func() { done <- inScopeTargets(root, nil) }()
	select {
	case targets := <-done:
		if got := strings.Join(targets.files, " "); got != "ok.py" {
			t.Errorf("targets = %q; want only ok.py", got)
		}
		if got := strings.Join(targets.Coverage.Names("symbolic link"), " "); got != "link.py" {
			t.Errorf("symlinks = %q; want link.py listed", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("inScopeTargets blocked")
	}
}
