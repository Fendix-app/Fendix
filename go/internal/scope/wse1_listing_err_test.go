package scope_test

// Round 6, WS-E1 (R5-14, R6-E5; OR-70): an unreadable entry directly under the
// scan root that no --exclude can keep out of Semgrep's own file listing (its
// name cannot be written as a pattern, or there are more than 512 of them) ends
// the run with Targets.ListingErr, before Semgrep is asked anything, instead of
// reading complete. Driven through semgrep.ScanRun with the fake Semgrep of
// pep263_vectors_test.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestARootLevelUnpatternableUnreadableNameEndsTheRun(t *testing.T) {
	wse1SkipIfRoot(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wse1WriteFile(t, filepath.Join(root, "ok.py"), []byte("x = 1\n"), 0o644)
	for _, name := range []string{"ctl\x01.py", "bad\xff.py"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x = 1\n"), 0o000); err != nil {
			if runtime.GOOS == "darwin" {
				t.Skipf("this file system refuses the name %q: %v (run on Linux)", name, err)
			}
			t.Fatal(err)
		}
	}
	run, _, err := wse1RunFakeSemgrepErr(t, root, nil, nil)
	if err == nil {
		t.Fatalf("no error: the run would ask Semgrep to list entries nothing can exclude, and reads %d lost files", run.Coverage.LostFiles())
	}
	if !strings.Contains(err.Error(), "cannot be kept out of Semgrep's own file listing") || !strings.Contains(err.Error(), "directly under the scan root") {
		t.Errorf("err = %v; want the listing error naming the entries under the scan root", err)
	}
}

func TestMoreThan512UnreadableEntriesAtTheRootEndTheRun(t *testing.T) {
	wse1SkipIfRoot(t)
	for _, tc := range []struct {
		n       int
		wantErr bool
	}{{512, false}, {513, true}} {
		t.Run(fmt.Sprintf("%d", tc.n), func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			wse1WriteFile(t, filepath.Join(root, "ok.py"), []byte("x = 1\n"), 0o644)
			for i := 0; i < tc.n; i++ {
				wse1WriteFile(t, filepath.Join(root, fmt.Sprintf("f%04d.py", i)), []byte("x = 1\n"), 0o000)
			}
			_, _, err = wse1RunFakeSemgrepErr(t, root, nil, nil)
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("%d unreadable files directly under the root cannot all be excluded (cap 512), and the run read complete", tc.n)
			case tc.wantErr && !strings.Contains(err.Error(), "more than 512 unreadable entries"):
				t.Errorf("err = %v; want the cap named", err)
			case !tc.wantErr && err != nil:
				t.Errorf("%d unreadable files fit the cap, each excluded by its own pattern: %v", tc.n, err)
			}
		})
	}
}
