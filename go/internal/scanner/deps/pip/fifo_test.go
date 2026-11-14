//go:build unix

package pip

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Round 5 verification, redteam5-11: a named pipe called requirements.txt must
// not hang the scan.
func TestAFifoNamedRequirementsDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "requirements.txt"), 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readManifest(filepath.Join(dir, "requirements.txt"))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a pipe was read as a manifest")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading the manifest blocked on a named pipe")
	}
}
