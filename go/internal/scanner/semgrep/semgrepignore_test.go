package semgrep

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// redteam-semgrep-02, qa2-02, redteam2-semgrep-02: a .semgrepignore in the
// scanned tree used to remove files from the Semgrep run with no error and the
// run recorded ok, so the repository under scan (a pull request's author, say)
// could hide a file from Semgrep invisibly; and a tree with no .semgrepignore
// at its root got Semgrep's built-in default list instead, which drops tests/
// and test/ at any depth with the same silence. The engine now passes
// --x-ignore-semgrepignore-files (Semgrep 1.96.0 and later), under which
// Semgrep 1.182.1 reads neither the tree's .semgrepignore files nor its
// default list (verified against the real binary below), so only the engine's
// own --excludes, the packs' path filters and the size cap decide what is
// scanned, the same for every project. Whatever those leave unread is listed
// by name (decision D6, scope_test.go).
//
// semgrep2's round-2 design passed --x-semgrepignore-filename with a random
// name instead. That neutralises the tree's files but keeps Semgrep's default
// list, which is redteam2-semgrep-02, so its tests are replaced by these.

func TestScanNeverReadsTheScannedTreesSemgrepignore(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installVersionedSemgrep(t, "1.182.1", nil, argv)
	root := t.TempDir()
	writeTree(t, root, map[string]string{".semgrepignore": "app.js\n", "app.js": spikeApp})
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if args := recordedArgs(t, argv); !strings.Contains(args, "\n--x-ignore-semgrepignore-files\n") {
		t.Fatalf("Semgrep was not told to ignore the tree's .semgrepignore files and its default list:%s", args)
	}
	if run.Report.Dropped != "" || run.Report.DroppedDetection != "" || run.Report.DroppedWhy != "" {
		t.Errorf("Report = %+v; nothing is dropped on 1.182.1", run.Report)
	}
}

// A Semgrep older than 1.96.0 does not have the option. It is run without it,
// and the run is a detection loss whatever the tree holds: with no
// .semgrepignore at the root the default list applies, so the orchestrator
// records it failed with the reason in the detail.
func TestAnOldSemgrepHonoursTheTreesSemgrepignoreAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"no .semgrepignore", map[string]string{"app.js": spikeApp}},
		{".semgrepignore at the root", map[string]string{".semgrepignore": "app.js\n", "app.js": spikeApp}},
		{".semgrepignore in a subdirectory", map[string]string{"sub/.semgrepignore": "s.js\n", "sub/s.js": spikeApp}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argv := filepath.Join(t.TempDir(), "argv")
			installVersionedSemgrep(t, "1.95.0", []string{"--x-ignore-semgrepignore-files"}, argv)
			root := t.TempDir()
			writeTree(t, root, tc.files)
			run, err := ScanRun(context.Background(), root, nil)
			if err != nil {
				t.Fatalf("ScanRun on Semgrep 1.95.0: %v", err)
			}
			if strings.Contains(recordedArgs(t, argv), "--x-ignore-semgrepignore-files") {
				t.Errorf("--x-ignore-semgrepignore-files passed to Semgrep 1.95.0")
			}
			const dropped = "--x-ignore-semgrepignore-files (needs 1.96.0)"
			if !strings.Contains(run.Report.Dropped, dropped) {
				t.Errorf("Report.Dropped = %q; want it to name %s", run.Report.Dropped, dropped)
			}
			if !strings.Contains(run.Report.DroppedDetection, dropped) {
				t.Errorf("Report.DroppedDetection = %q; the option changes what is scanned", run.Report.DroppedDetection)
			}
			for _, want := range []string{"files may be skipped", ".semgrepignore", "default ignore list"} {
				if !strings.Contains(run.Report.DroppedWhy, want) {
					t.Errorf("Report.DroppedWhy = %q; want it to say %q", run.Report.DroppedWhy, want)
				}
			}
		})
	}
}

const picklePy = "import pickle\n\n\ndef load(data):\n    return pickle.loads(data)\n"

// Real Semgrep: the file a .semgrepignore names, at the root or in a
// subdirectory, is still scanned and its finding reported, and so is a file
// under tests/ or test/ that Semgrep's default list would drop (the Python
// pack has no path filters, so nothing else excludes it).
func TestRealSemgrepScansWhatTheTreesSemgrepignoreNames(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".semgrepignore":     "app.js\n",
		"app.js":             spikeApp,
		"sub/.semgrepignore": "s.js\n",
		"sub/s.js":           spikeApp,
	})
	assertFindingsAt(t, root, "app.js:9", "sub/s.js:9")
}

func TestRealSemgrepIgnoresItsDefaultList(t *testing.T) {
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"tests/test_load.py": picklePy,
		"src/test/load.py":   picklePy,
		"load.py":            picklePy,
	})
	assertFindingsAt(t, root, "load.py:5", "tests/test_load.py:5", "src/test/load.py:5")
}

func assertFindingsAt(t *testing.T, root string, want ...string) {
	t.Helper()
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range run.Findings {
		seen[f.Endpoint] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("no finding at %s: a .semgrepignore or Semgrep's default list removed it from the run (findings %v)", w, seen)
		}
	}
}
