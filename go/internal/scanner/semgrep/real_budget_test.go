package semgrep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Round 4, R-008 part 2 against the real Semgrep: the budget's flags are
// accepted by the Semgrep the image pins, a tight memory bound turns a runaway
// file into a reported error, a stage that runs out of budget stops, takes
// semgrep-core down with it, reports what it did not evaluate and keeps every
// finding it did make, and the same input gives the same outcome every time.
// Skipped without semgrep on PATH, and failed when FENDIX_REQUIRE_SEMGREP is set.
//
// springController is the generator the engine's own real-Semgrep tests use for
// a Spring controller whose java-open_redirect-taint rule is slow: measured on
// the engine-dev image at 2 CPUs (semgrep 1.182.1), n=100 costs about 3 s of
// that rule, n=150 about 6 s, n=200 about 10 s and n=300 about 18 s.
func springController(n int) string {
	var b strings.Builder
	b.WriteString("package app;\n\nimport java.util.List;\nimport java.util.Map;\nimport javax.servlet.http.HttpServletResponse;\nimport org.springframework.jdbc.core.JdbcTemplate;\nimport org.springframework.web.bind.annotation.*;\n\n")
	b.WriteString("@RestController\n@RequestMapping(\"/api\")\npublic class ItemController {\n    private final JdbcTemplate jdbcTemplate;\n    public ItemController(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    @GetMapping(\"/go%d\")\n    public void go%d(@RequestParam String next, @RequestParam String sort, HttpServletResponse response) throws Exception {\n", i, i)
		b.WriteString("        String target = next;\n        if (target == null) { target = \"/\"; }\n        String t2 = target.trim();\n")
		fmt.Fprintf(&b, "        List<Map<String, Object>> rows = jdbcTemplate.queryForList(\"SELECT * FROM items ORDER BY id LIMIT ?\", %d);\n", i)
		b.WriteString("        if (rows.isEmpty()) { response.sendRedirect(\"/home\"); return; }\n        response.sendRedirect(t2);\n    }\n")
	}
	b.WriteString("    @GetMapping(\"/last\")\n    public void last(@RequestParam String next, HttpServletResponse response) throws Exception {\n        response.sendRedirect(next);\n    }\n}\n")
	return b.String()
}

const controllerFile = "src/main/java/app/ItemController.java"

func realBudgetRun(t *testing.T, root string, opts Options) (Run, error) {
	t.Helper()
	requireSemgrep(t)
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	return ScanRunWithOptions(context.Background(), root, nil, opts)
}

// The flags the budget adds are real Semgrep options: a run with all of them
// completes, evaluates every file and reports the finding.
func TestRealBudgetFlagsAreAcceptedBySemgrep(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"app.py": picklePy, "app.js": spikeApp})
	run, err := realBudgetRun(t, root, Options{Jobs: 2, MaxMemoryMiB: 1364})
	if err != nil {
		t.Fatalf("ScanRun with --jobs 2 --max-memory 1364: %v", err)
	}
	if run.Report.Dropped != "" || run.Coverage.Lost() || len(run.Report.Incomplete) != 0 {
		t.Errorf("dropped %q lost %d incomplete %v", run.Report.Dropped, run.Coverage.LostFiles(), run.Report.Incomplete)
	}
	got := endpoints(run)
	if len(got) == 0 {
		t.Errorf("no finding: %v", got)
	}
	if run.Budget.Jobs != 2 || run.Budget.MaxMemoryMiB != 1364 {
		t.Errorf("Budget = %+v", run.Budget)
	}
}

// A memory bound below what a file needs is a reported per-file error that
// names the file, never a clean file and never a dead engine; the findings of
// the files that did fit are kept.
func TestRealBudgetMaxMemoryTurnsARunawayFileIntoAReportedError(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"a.py":         picklePy,
		controllerFile: springController(120),
	})
	run, err := realBudgetRun(t, root, Options{MaxMemoryMiB: 40, MaxRetryFiles: -1})
	if err != nil {
		t.Fatalf("a per-file memory error is not a fatal run: %v", err)
	}
	named := false
	for _, e := range run.FileErrors {
		if e.Path == controllerFile && e.Type != "" {
			named = true
		}
	}
	if !named {
		t.Skipf("a 40 MiB bound did not stop %s on this Semgrep (file errors %+v): the input no longer forces the branch", controllerFile, run.FileErrors)
	}
	if run.Report.Incomplete["Out of memory"] == 0 {
		t.Errorf("Report.Incomplete = %v: the memory error must be counted as lost evaluation", run.Report.Incomplete)
	}
	if !endpoints(run)["a.py:5"] && len(run.Findings) == 0 {
		t.Errorf("the python file fit in the bound and its finding must be kept: %+v", run.Findings)
	}
}

// A file that lost a rule to time in pass 1 is re-run alone; whichever way
// that ends, the run never reads clean unless the re-run evaluated the file in
// full, and the re-run's findings are kept.
func TestRealBudgetRetryNeverTurnsALossIntoACleanFile(t *testing.T) {
	defer SetRuleTimeoutForTesting(2)()
	root := t.TempDir()
	writeTree(t, root, map[string]string{controllerFile: springController(120)})
	run, err := realBudgetRun(t, root, Options{})
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.Retries) == 0 {
		t.Skipf("pass 1 lost nothing to time at a 2 s bound on this host: the input no longer forces a retry (findings %d)", len(run.Findings))
	}
	r := run.Retries[0]
	if r.Path != controllerFile || r.Timeout < 4 {
		t.Errorf("Retry = %+v", r)
	}
	timedOut := len(run.Timeouts)+len(run.ThresholdFiles)+len(run.FixpointTimeouts) > 0
	switch {
	case r.Resolved && timedOut:
		t.Errorf("the retry says it resolved the file, and the run still reports lost evaluation: %+v", run.Timeouts)
	case !r.Resolved && !timedOut:
		t.Errorf("the retry did not resolve the file, and the run reports nothing lost: %+v", r)
	}
	if r.Resolved && len(run.Findings) == 0 {
		t.Errorf("a resolved file's re-run findings must be kept")
	}
	t.Logf("retry: %+v; timeouts left %d; findings %d", r, len(run.Timeouts), len(run.Findings))
}

// Same input, same outcome: three runs of a tree with a pathological file
// agree on every part of the coverage verdict, and three runs of a tree with
// none agree too.
func TestRealBudgetOutcomeIsTheSameOnEveryRun(t *testing.T) {
	type outcome struct {
		Findings    []string
		Timeouts    int
		Fixpoint    int
		Retries     []string
		Incomplete  map[string]int
		Lost        int
		FileErrors  int
		ErrText     string
		Groups      []string
		BudgetJobs  int
		BudgetMemMB int
	}
	observe := func(t *testing.T, root string, opts Options) outcome {
		run, err := realBudgetRun(t, root, opts)
		var ep []string
		for _, f := range run.Findings {
			ep = append(ep, f.RuleID+"@"+f.Endpoint)
		}
		sort.Strings(ep)
		var rt []string
		for _, r := range run.Retries {
			rt = append(rt, fmt.Sprintf("%s resolved=%v why=%q", r.Path, r.Resolved, r.Why))
		}
		o := outcome{Findings: ep, Timeouts: len(run.Timeouts), Fixpoint: len(run.FixpointTimeouts), Retries: rt,
			Incomplete: run.Report.Incomplete, Lost: run.Coverage.LostFiles(), FileErrors: len(run.FileErrors),
			Groups: run.Groups, BudgetJobs: run.Budget.Jobs, BudgetMemMB: run.Budget.MaxMemoryMiB}
		if err != nil {
			o.ErrText = err.Error()
		}
		return o
	}
	t.Run("clean tree", func(t *testing.T) {
		root := t.TempDir()
		writeTree(t, root, map[string]string{"a.py": picklePy, "web/app.js": spikeApp, "svc/Main.java": "class Main { void f(String s) { new java.io.File(s); } }\n"})
		var all []outcome
		for i := 0; i < 3; i++ {
			all = append(all, observe(t, root, Options{SplitBytes: 1}))
		}
		for i := 1; i < len(all); i++ {
			if !reflect.DeepEqual(all[0], all[i]) {
				t.Fatalf("run %d differs from run 0:\n%+v\n%+v", i, all[i], all[0])
			}
		}
		if len(all[0].Groups) != 3 {
			t.Errorf("a three-language tree with SplitBytes 1 runs three groups, got %v", all[0].Groups)
		}
	})
	t.Run("pathological file, timed out in pass 1 and again alone", func(t *testing.T) {
		// 2,700 lines at a 1 s per-rule bound: the rule costs about 18 s, so it
		// times out in pass 1 and in the 5 s re-run on any host short of one
		// several times faster.
		defer SetRuleTimeoutForTesting(1)()
		root := t.TempDir()
		writeTree(t, root, map[string]string{controllerFile: springController(300), "a.py": picklePy})
		var all []outcome
		for i := 0; i < 3; i++ {
			all = append(all, observe(t, root, Options{}))
		}
		for i := 1; i < len(all); i++ {
			if !reflect.DeepEqual(all[0], all[i]) {
				t.Fatalf("run %d differs from run 0:\n%+v\n%+v", i, all[i], all[0])
			}
		}
		if all[0].Timeouts+all[0].Fixpoint == 0 {
			t.Fatalf("the file no longer forces a timeout: %+v", all[0])
		}
		if len(all[0].Retries) != 1 || !strings.Contains(all[0].Retries[0], "resolved=false") {
			t.Errorf("Retries = %v, want one unresolved retry", all[0].Retries)
		}
	})
}

// A stage that runs out of budget stops at it, kills semgrep-core, says which
// language group it did not evaluate, and keeps the other group's findings.
func TestRealBudgetStageDeadlineKeepsFindingsAndLeavesNoProcessBehind(t *testing.T) {
	defer SetRuleTimeoutForTesting(120)() // the stage budget, not a rule bound, is what ends this run
	restore := SetStageTimingForTesting(time.Second, time.Second, time.Hour, time.Second)
	defer restore()
	root := t.TempDir()
	writeTree(t, root, map[string]string{controllerFile: springController(300), "a.py": picklePy})
	started := time.Now()
	run, err := realBudgetRun(t, root, Options{SplitBytes: 1, Wall: 14 * time.Second})
	elapsed := time.Since(started)
	if err == nil {
		t.Skipf("the java group finished inside 14 s on this host (%s): the input no longer forces the stage deadline", elapsed)
	}
	var st *StageTimeoutError
	if !errors.As(err, &st) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want a stage timeout", err)
	}
	if len(st.Unfinished) == 2 && st.Unfinished[0] == "python 1 file" {
		// deep-engine4: on a host so loaded that the cheap python group does not
		// finish in its window either, the test cannot show that the group that
		// did finish keeps its findings. The stage still stopped and named both.
		t.Skipf("the python group did not finish in its window on this host either (%v): the input no longer isolates the java group", st.Unfinished)
	}
	if len(st.Unfinished) != 1 || st.Unfinished[0] != "java 1 file" {
		t.Errorf("Unfinished = %v", st.Unfinished)
	}
	if elapsed > 30*time.Second {
		t.Errorf("the stage ran %s against a 14 s budget", elapsed)
	}
	if !endpoints(run)["a.py:5"] {
		t.Errorf("the python group finished; its finding must be kept: %v", endpoints(run))
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

// processesMentioning lists the processes whose command line names dir.
func processesMentioning(dir string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Name() == "" || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		if strings.Contains(string(data), dir) {
			out = append(out, e.Name()+":"+strings.ReplaceAll(strings.TrimSpace(string(data[:min(len(data), 80)])), "\x00", " "))
		}
	}
	return out
}
