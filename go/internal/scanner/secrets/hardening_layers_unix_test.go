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

// qa-engine-06 (R-003): the O_NONBLOCK open. A FIFO that appears where the
// walk saw a regular file has no writer, so a blocking open would wait for one
// forever and hang the scan; the non-blocking open returns, and the fstat
// check then refuses the FIFO. Only O_NONBLOCK prevents the hang: every other
// check runs after the open.

func extraNonRegular(t *testing.T, root string) {
	t.Helper()
	if err := syscall.Mkfifo(filepath.Join(root, "fifo.env"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// releaseFIFO unblocks a reader stuck opening path by opening it for writing.
func releaseFIFO(path string) {
	go func() {
		if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
		}
	}()
}

func TestReadRegularFile_DoesNotBlockOnAFIFO(t *testing.T) {
	root := t.TempDir()
	extraNonRegular(t, root)
	p := filepath.Join(root, "fifo.env")
	walked, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	r := mustOpenRoot(t, root)
	done := make(chan error, 1)
	go func() {
		_, err := readRegularFile(r, "fifo.env", walked)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO was read as a file")
		}
	case <-time.After(5 * time.Second):
		releaseFIFO(p)
		t.Fatal("opening a FIFO blocked: the read open is not non-blocking")
	}
}

func TestScan_FIFOSwappedInAfterTheWalkDoesNotHangTheScan(t *testing.T) {
	root := t.TempDir()
	a := writeFile(t, root, "a.env", "AWS_ACCESS_KEY_ID="+swappedAWS+"\n")
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	withHook(t, &testHookBeforeOpen, func(rel string) {
		if rel != "a.env" {
			return
		}
		if err := os.Remove(a); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(a, 0o600); err != nil {
			t.Error(err)
		}
	})
	done := make(chan int, 1)
	go func() {
		fs, _ := Scan(context.Background(), root)
		done <- len(findingsWith(fs, inRepoAWS))
	}()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("the rest of the tree was not scanned: %d findings for real.py", n)
		}
	case <-time.After(10 * time.Second):
		releaseFIFO(a)
		t.Fatal("a FIFO swapped in after the walk hung the scan: the read open is not non-blocking")
	}
}
