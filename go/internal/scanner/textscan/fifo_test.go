//go:build unix

package textscan

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Round 5 verification, redteam5-11 (post-commit item 9 residual). A named pipe
// called fifo.js is a "file" a rule applies to by its name. Opening it for
// reading waits for a writer that never comes, so the whole scan hung after
// Semgrep finished. Probing never blocks (contract C6): the pipe is recorded as
// a file that was not read and the rest of the tree is scanned.
func TestAFifoNamedLikeSourceDoesNotHangTheScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.js", `eval(userCode);`+"\n")
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo.js"), 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	writeFile(t, dir, "Dockerfile", "FROM alpine:latest\n")
	if err := syscall.Mkfifo(filepath.Join(dir, "app.Dockerfile"), 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	type result struct {
		findings int
		lost     bool
		detail   string
	}
	done := make(chan result, 1)
	go func() {
		got, cov, _ := ScanCoverage(dir, AllRules(), nil)
		done <- result{len(got), cov.Lost(), cov.LostDetail(240)}
	}()
	select {
	case r := <-done:
		if r.findings == 0 {
			t.Error("the readable file's findings were lost")
		}
		if !r.lost {
			t.Error("the pipes are not recorded as files that were not read")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("textscan blocked on a named pipe")
	}
}
