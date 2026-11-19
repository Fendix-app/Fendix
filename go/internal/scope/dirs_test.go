package scope

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mkdirs(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, r := range rels {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(r)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// Decision D5-2: no directory is left out by its name or by marker files a
// repository's author can write (review items 2 and 8, C4B-03's family). Every
// marker round 4 trusted is now ordinary content.
func TestForgedDirectoryMarkersPruneNothing(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		dir     string
		markers map[string]string
	}{
		{"venv", map[string]string{"pyvenv.cfg": "home = /usr/bin\ninclude-system-site-packages = false\n"}},
		{"envs/x", map[string]string{"conda-meta/history": ""}},
		{"node_modules", map[string]string{".package-lock.json": `{"lockfileVersion": 3}`}},
		{"web/node_modules", map[string]string{".yarn-integrity": "{}"}},
		{"pn/node_modules", map[string]string{".modules.yaml": "layoutVersion: 5\n"}},
		{"vendor", map[string]string{"modules.txt": "# github.com/a/b v1.2.3\n## explicit; go 1.20\n"}},
		{"php/vendor", map[string]string{"autoload.php": "<?php", "composer/installed.json": `{"packages": []}`}},
		{"target", map[string]string{"CACHEDIR.TAG": "Signature: 8a477f597d28d172789f06886806bc55\n"}},
		{".next", map[string]string{"BUILD_ID": "x", "build-manifest.json": "{}"}},
		{".npm", map[string]string{"_cacache/index-v5/x": "x"}},
		{"lib/site-packages", map[string]string{"requests-2.0.dist-info/METADATA": "x", "requests-2.0.dist-info/RECORD": "x"}},
		{"dist-packages", map[string]string{"x-1.0.dist-info/METADATA": "x", "x-1.0.dist-info/RECORD": "x"}},
		{"elsewhere/.git", map[string]string{"HEAD": "ref: refs/heads/main\n", "objects/x": "x", "refs/heads/main": "x"}},
		{"a/objects", map[string]string{"x": "x"}},
	} {
		for rel, body := range tc.markers {
			write(t, root, tc.dir+"/"+rel, body)
		}
		if v := ClassifyDir(filepath.Join(root, filepath.FromSlash(tc.dir)), tc.dir); !v.None() {
			t.Errorf("%s with forged markers: pruned as %q, want in scope", tc.dir, v.Reason)
		}
	}
	// A package.json that names the package, in a directory called node_modules.
	write(t, root, "node_modules/left-pad/package.json", `{"name":"left-pad","version":"1.3.0"}`)
	if v := ClassifyDir(filepath.Join(root, "node_modules", "left-pad"), "node_modules/left-pad"); !v.None() {
		t.Errorf("an installed npm package: %q", v.Reason)
	}
}

func TestOnlyTheRootGitDirectoryWithARealLayoutIsLeftOut(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, ".git/objects", ".git/refs")
	write(t, root, ".git/HEAD", "ref: refs/heads/main\n")
	if v := ClassifyDir(filepath.Join(root, ".git"), ".git"); v.Reason != ReasonGitMetadata {
		t.Errorf("a real .git at the root: %q", v.Reason)
	}
	// The same layout anywhere else is ordinary content.
	mkdirs(t, root, "sub/.git/objects", "sub/.git/refs")
	write(t, root, "sub/.git/HEAD", "ref: refs/heads/main\n")
	if v := ClassifyDir(filepath.Join(root, "sub", ".git"), "sub/.git"); !v.None() {
		t.Errorf("a nested .git: %q", v.Reason)
	}
	// An incomplete layout at the root is ordinary content too.
	for name, setup := range map[string]func(string){
		"no HEAD":     func(d string) { mkdirs(t, d, "objects", "refs") },
		"no objects":  func(d string) { mkdirs(t, d, "refs"); write(t, d, "HEAD", "x") },
		"no refs":     func(d string) { mkdirs(t, d, "objects"); write(t, d, "HEAD", "x") },
		"HEAD is dir": func(d string) { mkdirs(t, d, "objects", "refs", "HEAD") },
		"objects file": func(d string) {
			write(t, d, "objects", "x")
			mkdirs(t, d, "refs")
			write(t, d, "HEAD", "x")
		},
	} {
		r := t.TempDir()
		mkdirs(t, r, ".git")
		setup(filepath.Join(r, ".git"))
		if v := ClassifyDir(filepath.Join(r, ".git"), ".git"); !v.None() {
			t.Errorf("%s: %q", name, v.Reason)
		}
	}
}

// Probing a marker never follows a link and never blocks (review item 9).
func TestGitLayoutProbeNeverFollowsOrBlocks(t *testing.T) {
	root := t.TempDir()
	mkdirs(t, root, ".git/objects", ".git/refs")
	fifo := filepath.Join(root, ".git", "HEAD")
	if err := mkfifo(fifo); err != nil {
		t.Skipf("no FIFOs: %v", err)
	}
	done := make(chan Verdict, 1)
	go func() { done <- ClassifyDir(filepath.Join(root, ".git"), ".git") }()
	select {
	case v := <-done:
		if !v.None() {
			t.Errorf("a FIFO HEAD: %q", v.Reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ClassifyDir blocked on a FIFO HEAD")
	}
	// A HEAD that is a link to a regular file elsewhere is not a HEAD.
	r2 := t.TempDir()
	mkdirs(t, r2, ".git/objects", ".git/refs")
	outside := write(t, r2, "outside", "ref: x\n")
	if err := os.Symlink(outside, filepath.Join(r2, ".git", "HEAD")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	if v := ClassifyDir(filepath.Join(r2, ".git"), ".git"); !v.None() {
		t.Errorf("a linked HEAD: %q", v.Reason)
	}
	// A .git that is itself a link is not the metadata directory.
	r3 := t.TempDir()
	mkdirs(t, r3, "real/objects", "real/refs")
	write(t, r3, "real/HEAD", "x")
	if err := os.Symlink(filepath.Join(r3, "real"), filepath.Join(r3, ".git")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	if v := ClassifyDir(filepath.Join(r3, ".git"), ".git"); !v.None() {
		t.Errorf("a linked .git: %q", v.Reason)
	}
}
