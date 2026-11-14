//go:build linux

package semgrep

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Round 5 verification, DE6-02. killTree used to kill a process's descendants
// before the process itself, with a second /proc scan in between. A wrapper
// that waits for its worker (Semgrep's Python entry point and semgrep-core) saw
// the worker die, printed a document and exited 0 in that gap, so a run killed
// at its deadline looked like a run that finished.
func TestKillTreeDoesNotLetAWrapperFinishAfterItsWorkerIsKilled(t *testing.T) {
	for i := 0; i < 10; i++ {
		dir := t.TempDir()
		marker := filepath.Join(dir, "finished")
		script := filepath.Join(dir, "wrapper.sh")
		// Many workers, so the second /proc scan has real work to do between the
		// last worker dying and the wrapper being killed.
		body := "#!/bin/sh\ni=0\nwhile [ $i -lt 300 ]; do sleep 30 & i=$((i+1)); done\nwait\necho '{}' > " + marker + "\nexit 0\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(script)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		// Let the wrapper start its worker.
		time.Sleep(700 * time.Millisecond)
		_ = killTree(cmd.Process)
		err := cmd.Wait()
		var ee *exec.ExitError
		if err == nil || !errors.As(err, &ee) {
			t.Fatalf("iteration %d: the wrapper exited 0 after its worker was killed (err = %v)", i, err)
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() {
			t.Fatalf("iteration %d: the wrapper was not killed by a signal: %v", i, err)
		}
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Fatalf("iteration %d: the wrapper kept running after killTree", i)
		}
	}
}
