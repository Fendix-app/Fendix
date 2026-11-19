//go:build unix

package npm

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Round 5 verification, redteam5-11: a named pipe called package-lock.json must
// not hang the scan.
func TestAFifoNamedPackageLockDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "package-lock.json"), 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readManifest(filepath.Join(dir, "package-lock.json"))
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
