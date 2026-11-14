//go:build unix

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The marker probe never blocks and never follows a link: a HEAD that is a FIFO,
// and an objects or refs that is a symbolic link, are not a git layout, and
// probing them returns at once (review items 8 and 9).
func TestPrunedDir_ProbingNeverBlocksOrFollowsLinks(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "real-objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(gitDir, "HEAD"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "real-objects"), filepath.Join(gitDir, "objects")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		reason, _ := PrunedDir(gitDir, ".git")
		done <- reason == ""
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Errorf("a .git with a FIFO HEAD and a linked objects was pruned")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probing a FIFO HEAD blocked")
	}
	// And a scan of the tree finishes.
	writeFile(t, root, "a.py", "x = 1\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Scan(ctx, root); err != nil {
		t.Fatalf("Scan: %v", err)
	}
}
