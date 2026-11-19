//go:build !windows

package semgrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 5 verification, redteam5-05. A file or directory the engine cannot read
// is recorded as lost evaluation, and it must not take the rest of the run with
// it: Semgrep lists the files of a root run itself and, asked to read an entry
// it cannot open, exits 2 with "Failed to obtain target files". The engine tells
// Semgrep to leave such entries alone and keeps the loss in the report.
func unreadableTree(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("file modes do not restrict root")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"src/app.py":      picklePy,
		"src/hidden.py":   picklePy,
		"locked/inner.py": picklePy,
	})
	for _, p := range []string{"src/hidden.py", "locked"} {
		if err := os.Chmod(filepath.Join(root, p), 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "locked"), 0o700) })
	return root
}

func TestUnreadableEntriesAreExcludedFromSemgrepsOwnListing(t *testing.T) {
	root := unreadableTree(t)
	targets := inScopeTargets(root, nil)
	for _, rel := range []string{"src/hidden.py", "locked"} {
		pattern, ok := excludePattern(rel)
		if !ok {
			t.Fatalf("no pattern for %s", rel)
		}
		found := false
		for _, e := range targets.Excludes {
			if e == pattern {
				found = true
			}
		}
		if !found {
			t.Errorf("excludes %q lack %q: Semgrep would try to read it and lose the run", targets.Excludes, pattern)
		}
	}
	if got := strings.Join(targets.files, " "); got != "src/app.py" {
		t.Errorf("targets = %q, want only the readable file", got)
	}
	if !targets.Coverage.Lost() {
		t.Error("the unreadable entries are no longer recorded as lost evaluation")
	}
}

func TestRealSemgrepSurvivesAnUnreadableFileAndRecordsTheLoss(t *testing.T) {
	root := unreadableTree(t)
	run := realRun(t, root)
	if !endpoints(run)["src/app.py:5"] {
		t.Errorf("the readable file was not evaluated: %v", endpoints(run))
	}
	if !run.Coverage.Lost() {
		t.Error("the unreadable entries are not recorded as lost evaluation")
	}
}
