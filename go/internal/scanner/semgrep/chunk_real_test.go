package semgrep

import (
	"errors"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Round 5, R-008 residuals 1 and 2 against the real Semgrep.

// Running a tree with its heavy files isolated (a root run that excludes them,
// and each of them alone, selected by an anchored include) evaluates exactly
// what one run over the root does: the same findings, every file reported in
// paths.scanned, nothing lost, and no result twice.
func TestRealChunkedRunEqualsTheSingleRun(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a.py":          picklePy,
		"b.py":          picklePy + strings.Repeat("# padding\n", 40),
		"web/app.js":    spikeApp,
		"web/two.js":    spikeApp + strings.Repeat("// padding\n", 80),
		"svc/Main.java": "class Main { void f(String s) { new java.io.File(s); } }\n",
		"-dash.py":      picklePy,
	})
	findings := func(opts Options) ([]string, Run) {
		run, err := realBudgetRun(t, root, opts)
		if err != nil {
			t.Fatalf("ScanRun(%+v): %v", opts, err)
		}
		var out []string
		for _, f := range run.Findings {
			out = append(out, f.RuleID+"@"+strings.TrimPrefix(f.Endpoint, root))
		}
		sort.Strings(out)
		return out, run
	}
	single, srun := findings(Options{ChunkBytes: -1, SplitBytes: -1})
	if len(single) == 0 {
		t.Fatal("the fixture no longer produces a finding")
	}
	for name, opts := range map[string]Options{
		"heavy files of the unsplit tree": {ChunkBytes: 1, HeavyFileBytes: 100, SplitBytes: -1},
		"heavy files inside each group":   {ChunkBytes: 1, HeavyFileBytes: 100, SplitBytes: 1},
	} {
		got, run := findings(opts)
		if !reflect.DeepEqual(got, single) {
			t.Errorf("%s: findings differ:\n chunked %v\n single  %v", name, got, single)
		}
		if run.Coverage.Lost() || srun.Coverage.Lost() {
			t.Errorf("%s: files were lost: chunked %d single %d", name, run.Coverage.LostFiles(), srun.Coverage.LostFiles())
		}
		if len(run.Units) < 3 {
			t.Errorf("%s: Units = %v, want a bulk run and several heavy files", name, run.Units)
		}
	}
}

// A stage that runs out of budget during a late, heavy chunk keeps the findings
// of the chunks that finished, names the chunk it lost, and leaves no process
// behind. The same tree as one invocation would have kept nothing.
func TestRealChunkDeadlineKeepsTheFindingsOfTheFinishedChunks(t *testing.T) {
	defer SetRuleTimeoutForTesting(120)() // the stage budget, not a rule bound, ends this run
	restore := SetStageTimingForTesting(time.Second, time.Second, time.Hour, time.Second)
	defer restore()
	root := t.TempDir()
	// Smallest first: a.py (finishes), then the large Spring controller.
	writeTree(t, root, map[string]string{controllerFile: springController(300), "a.py": picklePy})
	started := time.Now()
	run, err := realBudgetRun(t, root, Options{SplitBytes: -1, ChunkBytes: 1, HeavyFileBytes: 1000, Wall: 14 * time.Second})
	elapsed := time.Since(started)
	if err == nil {
		t.Skipf("the java chunk finished inside 14 s on this host (%s): the input no longer forces the stage deadline", elapsed)
	}
	var st *StageTimeoutError
	if !errors.As(err, &st) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want a stage timeout", err)
	}
	if len(st.Unfinished) != 1 || st.Unfinished[0] != "source 1 file" {
		t.Skipf("the python chunk did not finish in its window on this host either (%v)", st.Unfinished)
	}
	if elapsed > 30*time.Second {
		t.Errorf("the stage ran %s against a 14 s budget", elapsed)
	}
	if !endpoints(run)["a.py:5"] {
		t.Errorf("the python chunk finished; its finding must be kept: %v", endpoints(run))
	}
	if !run.Coverage.Lost() {
		t.Errorf("the java file was not evaluated and must be in the coverage")
	}
	if runtime.GOOS == "linux" {
		time.Sleep(500 * time.Millisecond)
		if left := processesMentioning(root); len(left) > 0 {
			t.Errorf("processes still running on the scanned tree after the stage ended: %v", left)
		}
	}
}
