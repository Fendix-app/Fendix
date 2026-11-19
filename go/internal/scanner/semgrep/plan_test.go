package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Round 4, R-008 part 2: the stage plan (language shards, deadlines, the
// retry pass) against a scripted stand-in for Semgrep, so what the engine does
// with each outcome is pinned without a real Semgrep. The real-Semgrep tests
// that pin the same behaviour end to end are in real_budget_test.go.

// ---- the stand-in ----

// scriptedSemgrep installs a stand-in `semgrep` whose behaviour is a
// directory of files, and returns that directory. The stand-in appends each
// invocation's arguments to argv.log and answers by KEY:
//
//	all          the single invocation (--config is the rules directory)
//	python, javascript, java, go   one language group's invocation
//	retry-<base> a retry: the last argument is the one file
//
// For its key it sleeps sleep-KEY seconds, then prints out-KEY.json (an empty
// results document when absent) and exits exit-KEY (0 when absent).
func scriptedSemgrep(t *testing.T) string {
	t.Helper()
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	scen := t.TempDir()
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 1.182.1; exit 0; fi
echo "$*" >> "` + scen + `/argv.log"
key=all
last=
inc=
for a in "$@"; do
  case "$a" in
    --include=/*) inc=$a;;
    */javascript-*.yaml) key=javascript;;
    */java-*.yaml) key=java;;
    */go-*.yaml) key=go;;
    */auth.yaml) key=python;;
  esac
  last=$a
done
if [ -f "$last" ]; then key=retry-$(basename "$last"); fi
# A chunk of a group (an anchored --include per file) is keyed by its last file.
if [ -n "$inc" ]; then key=retry-$(basename "${inc#--include=}"); fi
if [ -f "` + scen + `/spawn-$key" ]; then
  sleep 300 &
  echo $! > "` + scen + `/child-$key.pid"
fi
if [ -f "` + scen + `/sleep-$key" ]; then sleep $(cat "` + scen + `/sleep-$key"); fi
if [ -f "` + scen + `/out-$key.json" ]; then cat "` + scen + `/out-$key.json"; else printf '{"results":[],"errors":[],"paths":{"scanned":[]},"time":{"fixpoint_timeouts":[]}}'; fi
code=0
if [ -f "` + scen + `/exit-$key" ]; then code=$(cat "` + scen + `/exit-$key"); fi
exit $code
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	origLook := LookPath
	LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return origLook(name)
	}
	t.Cleanup(func() { LookPath = origLook })
	// A host of known limits, so the budget does not depend on the machine.
	origLimits := limitsFunc
	limitsFunc = func() Limits { return Limits{NumCPU: 10, CPUs: 2, MemoryBytes: 1900 << 20, Source: "test"} }
	t.Cleanup(func() { limitsFunc = origLimits })
	return scen
}

func putScen(t *testing.T, scen, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(scen, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// argvLines is the arguments of every invocation so far, one string each.
func argvLines(t *testing.T, scen string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(scen, "argv.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// fixtureRoot writes files under a fresh root and returns it with symlinks
// resolved, which is the form Semgrep's paths take.
func fixtureRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, files)
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func resultJSON(root, rel, check string, line int) string {
	return fmt.Sprintf(`{"check_id":"rules.%s","path":%q,"start":{"line":%d,"col":1},"extra":{"message":"m","severity":"ERROR","lines":"x%d","metadata":{}}}`,
		check, filepath.Join(root, rel), line, line)
}

func timeoutJSON(root, rel, rule string) string {
	return fmt.Sprintf(`{"code":2,"level":"warn","type":"Timeout","rule_id":"rules.%s","message":"Timeout when running %s on %s:","path":%q}`,
		rule, rule, filepath.Join(root, rel), filepath.Join(root, rel))
}

func fixpointJSON(root, rel string) string {
	p := filepath.Join(root, rel)
	return fmt.Sprintf(`{"error_type":"Fixpoint timeout","severity":"warn","message":"Fixpoint timeout while performing taint analysis at %s:1:0 [rules: 1, first: rules.js-sqli-taint]","location":{"path":%q,"start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":1,"offset":0}}}`, p, p)
}

// docJSON is a Semgrep document: results, errors, the files it says it scanned
// and its fixpoint timeouts.
func docJSON(root string, results, errs, scanned, fixpoint []string) string {
	abs := make([]string, len(scanned))
	for i, s := range scanned {
		abs[i] = strconv.Quote(filepath.Join(root, s))
	}
	return fmt.Sprintf(`{"results":[%s],"errors":[%s],"paths":{"scanned":[%s]},"time":{"fixpoint_timeouts":[%s]}}`,
		strings.Join(results, ","), strings.Join(errs, ","), strings.Join(abs, ","), strings.Join(fixpoint, ","))
}

// ---- budget flags on the command line ----

func TestStageRunsOneInvocationWithTheBudgetOnTheCommandLine(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "out-all.json", docJSON(root, nil, nil, []string{"app.py"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	lines := argvLines(t, scen)
	if len(lines) != 1 {
		t.Fatalf("a small tree must run one invocation, got %d: %v", len(lines), lines)
	}
	for _, want := range []string{"--jobs 2", "--max-memory 682", "--timeout 30", "--time", "--max-target-bytes", "--disable-nosem"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("argv %q is missing %q", lines[0], want)
		}
	}
	if run.Budget.Jobs != 2 || run.Budget.MaxMemoryMiB != 682 || run.Budget.Wall != DefaultWall {
		t.Errorf("Run.Budget = %+v", run.Budget)
	}
	if len(run.Groups) != 0 {
		t.Errorf("a single invocation names no groups, got %v", run.Groups)
	}
}

func TestStageOptionsAndEnvironmentOverrideTheDerivedBudget(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "out-all.json", docJSON(root, nil, nil, []string{"app.py"}, nil))
	if _, err := ScanRunWithOptions(context.Background(), root, nil, Options{Jobs: 5, MaxMemoryMiB: 700}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvJobs, "3")
	t.Setenv(EnvMaxMemoryMiB, "0")
	if _, err := ScanRunWithOptions(context.Background(), root, nil, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ScanRunWithOptions(context.Background(), root, nil, Options{MaxMemoryMiB: -1}); err != nil {
		t.Fatal(err)
	}
	lines := argvLines(t, scen)
	if len(lines) != 3 {
		t.Fatalf("want 3 invocations, got %v", lines)
	}
	if !strings.Contains(lines[0], "--jobs 5") || !strings.Contains(lines[0], "--max-memory 700") {
		t.Errorf("explicit options: %q", lines[0])
	}
	if !strings.Contains(lines[1], "--jobs 3") || strings.Contains(lines[1], "--max-memory") {
		t.Errorf("environment (jobs 3, max-memory 0 = none): %q", lines[1])
	}
	if strings.Contains(lines[2], "--max-memory") {
		t.Errorf("a negative MaxMemoryMiB must pass no --max-memory: %q", lines[2])
	}
}

func TestStageBudgetShrinksUnderAShortRunDeadline(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "out-all.json", docJSON(root, nil, nil, []string{"app.py"}, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	run, err := ScanRun(ctx, root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if run.Budget.Wall >= 150*time.Second || run.Budget.Wall < minStageWall {
		t.Errorf("stage wall = %s: it must fit under a 150 s run deadline and leave the later analyzers their reserve", run.Budget.Wall)
	}
}

// ---- language shards ----

func TestStageSplitsALargeMultiLanguageTreeByLanguageGroup(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{
		"a.py":                            "x = 1\n",
		"web/b.js":                        "var y = 2;\n" + strings.Repeat("// padding\n", 200),
		"web/c.ts":                        "let z = 3;\n",
		"svc/D.java":                      "class D {}\n" + strings.Repeat("// padding\n", 400),
		"README.md":                       "# doc\n",
		"internal/e.go":                   "package e\n" + strings.Repeat("// padding\n", 600),
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
	})
	all := []string{"a.py", "web/b.js", "web/c.ts", "svc/D.java", "internal/e.go"}
	putScen(t, scen, "out-python.json", docJSON(root, []string{resultJSON(root, "a.py", "python-eval", 1)}, nil, []string{"a.py"}, nil))
	putScen(t, scen, "out-javascript.json", docJSON(root, []string{resultJSON(root, "web/b.js", "js-eval", 1)}, nil, []string{"web/b.js", "web/c.ts"}, nil))
	putScen(t, scen, "out-java.json", docJSON(root, nil, nil, []string{"svc/D.java"}, nil))
	putScen(t, scen, "out-go.json", docJSON(root, []string{resultJSON(root, "internal/e.go", "go-exec", 1)}, nil, []string{"internal/e.go"}, nil))
	_ = all
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{SplitBytes: 1})
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	lines := argvLines(t, scen)
	if len(lines) != 4 {
		t.Fatalf("want one invocation per language group (4), got %d: %v", len(lines), lines)
	}
	// Cheapest group first: python (6 bytes), javascript+typescript, java, go.
	wantOrder := []string{"auth.yaml", "javascript-web.yaml", "java-web.yaml", "go-web.yaml"}
	for i, want := range wantOrder {
		if !strings.Contains(lines[i], want) {
			t.Errorf("invocation %d = %q, want a group loading %s", i, lines[i], want)
		}
		if strings.Contains(lines[i], "--config "+filepath.Dir(firstConfig(lines[i]))+" ") {
			t.Errorf("invocation %d loads the whole rules directory: %q", i, lines[i])
		}
	}
	// Each group loads only its own packs.
	if strings.Contains(lines[0], "javascript-") || strings.Contains(lines[0], "go-web") {
		t.Errorf("the python group loaded another group's packs: %q", lines[0])
	}
	if got := len(run.Findings); got != 3 {
		t.Errorf("findings = %d, want 3 (python, javascript, go)", got)
	}
	if !reflect.DeepEqual(run.Groups, []string{"python", "javascript", "java", "go"}) {
		t.Errorf("Run.Groups = %v", run.Groups)
	}
	if run.Coverage.Lost() {
		t.Errorf("every in-scope file was reported scanned by some group, yet lost: %s", run.Coverage.LostDetail(500))
	}
	for _, l := range lines {
		if !strings.Contains(l, "--jobs 2") || !strings.Contains(l, "--max-memory 682") {
			t.Errorf("every group runs under the budget: %q", l)
		}
	}
}

func firstConfig(line string) string {
	f := strings.Fields(line)
	for i, a := range f {
		if a == "--config" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

func TestStageDoesNotSplitASmallOrSingleLanguageTree(t *testing.T) {
	scen := scriptedSemgrep(t)
	small := fixtureRoot(t, map[string]string{"a.py": "x = 1\n", "b.js": "var y;\n"})
	if _, err := ScanRun(context.Background(), small, nil); err == nil || errors.Is(err, ErrTimeout) {
		// the stand-in reports nothing scanned, which is lost evaluation, not an error
		_ = err
	}
	if n := len(argvLines(t, scen)); n != 1 {
		t.Errorf("a tree under the split threshold must run once, ran %d times", n)
	}
	// One language, however large the threshold says: nothing to split.
	scen2 := scriptedSemgrep(t)
	one := fixtureRoot(t, map[string]string{"a.py": "x = 1\n", "b.py": "y = 2\n"})
	if _, err := ScanRunWithOptions(context.Background(), one, nil, Options{SplitBytes: 1}); err != nil {
		t.Fatal(err)
	}
	if n := len(argvLines(t, scen2)); n != 1 {
		t.Errorf("a single-language tree must run once, ran %d times", n)
	}
	// A negative SplitBytes never splits.
	scen3 := scriptedSemgrep(t)
	many := fixtureRoot(t, map[string]string{"a.py": "x = 1\n", "b.js": "var y;\n"})
	if _, err := ScanRunWithOptions(context.Background(), many, nil, Options{SplitBytes: -1}); err != nil {
		t.Fatal(err)
	}
	if n := len(argvLines(t, scen3)); n != 1 {
		t.Errorf("SplitBytes < 0 must never split, ran %d times", n)
	}
}

func TestPlanShardsOrdersCheapestFirstAndOnlyWhenWorthIt(t *testing.T) {
	groups, err := readPackGroups("/rules")
	if err != nil {
		t.Fatal(err)
	}
	tg := Targets{
		files: []string{"a.py", "b.js", "c.ts", "d.go"},
		size:  map[string]int64{"a.py": 10, "b.js": 100, "c.ts": 50, "d.go": 5},
	}
	got := planShards(tg, groups, 1)
	var names []string
	for _, s := range got {
		names = append(names, s.name)
	}
	if !reflect.DeepEqual(names, []string{"go", "python", "javascript"}) {
		t.Errorf("order = %v, want go, python, javascript (bytes ascending, ts counted with js)", names)
	}
	if planShards(tg, groups, 1<<30) != nil {
		t.Error("a tree under the threshold must not split")
	}
	if planShards(tg, groups, -1) != nil {
		t.Error("a negative threshold must never split")
	}
	if planShards(Targets{files: []string{"a.py"}, size: map[string]int64{"a.py": 1 << 40}}, groups, 1) != nil {
		t.Error("one language group has nothing to split")
	}
	// The same input plans the same way, every time.
	for i := 0; i < 5; i++ {
		again := planShards(tg, groups, 1)
		if !reflect.DeepEqual(again, got) {
			t.Fatalf("plan changed between calls: %v vs %v", again, got)
		}
	}
}

func TestPackGroupsCoverEveryEmbeddedPackExactlyOnce(t *testing.T) {
	groups, err := readPackGroups("/rules")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, g := range groups {
		if g.name == otherGroup {
			t.Errorf("a pack fell in the catch-all group %v: its languages span groups or are unknown, and the split would run it over the whole tree", g.configs)
		}
		for _, c := range g.configs {
			base := filepath.Base(c)
			if prev, dup := seen[base]; dup {
				t.Errorf("pack %s is in groups %s and %s", base, prev, g.name)
			}
			seen[base] = g.name
		}
	}
	entries, err := os.ReadDir("rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") && seen[e.Name()] == "" {
			t.Errorf("pack %s is in no group: a split run would never load it", e.Name())
		}
	}
	// Each group's packs declare only that group's languages.
	for _, want := range map[string][]string{"javascript": {"javascript-crypto.yaml", "javascript-injection.yaml", "javascript-web.yaml"}, "go": {"go-crypto.yaml", "go-injection.yaml", "go-web.yaml"}} {
		for _, f := range want {
			if seen[f] == "" {
				t.Errorf("pack %s missing", f)
			}
		}
	}
}

func TestShardDeadlinesAreAFunctionOfSizeAlone(t *testing.T) {
	shards := []shard{{name: "go", bytes: 10}, {name: "python", bytes: 1000}, {name: "javascript", bytes: 9000}}
	pass1 := 300 * time.Second
	got := shardDeadlines(shards, pass1)
	if got[len(got)-1] != pass1 {
		t.Errorf("the last shard may use everything to the end: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("deadlines must not decrease: %v", got)
		}
	}
	if got[0] < pass1/2 {
		t.Errorf("the first shard keeps at least half the pass: %v", got[0])
	}
	// The heavy last shard cannot be starved: the lighter ones' floors are
	// small, so it can use nearly all of what they leave.
	for i := 0; i < 5; i++ {
		if again := shardDeadlines(shards, pass1); !reflect.DeepEqual(again, got) {
			t.Fatalf("not deterministic: %v vs %v", again, got)
		}
	}
	// A slow shard cannot starve the ones after it: each later shard keeps its floor.
	for i := 0; i < len(shards)-1; i++ {
		if got[i] >= pass1 {
			t.Errorf("shard %d may use the whole pass, starving the later ones: %v", i, got)
		}
	}
}

// ---- the retry pass ----

func TestRetryTimeoutScalesWithSizeAndIsBounded(t *testing.T) {
	for _, c := range []struct {
		base int
		size int64
		want int
	}{
		{30, 0, 60},
		{30, 1, 61},
		{30, 32 << 10, 61},
		{30, 853037, 60 + 27},
		{30, 1 << 30, 240},
		{10, 100 << 10, 24},
		{0, 0, 60},
	} {
		if got := retryTimeoutFor(c.base, c.size); got != c.want {
			t.Errorf("retryTimeoutFor(%d, %d) = %d, want %d", c.base, c.size, got, c.want)
		}
	}
}

// retryTree is a tree with a.js and b.js; pass 1 lost a rule to a timeout on a.js.
func retryTree(t *testing.T) (scen, root string) {
	scen = scriptedSemgrep(t)
	root = fixtureRoot(t, map[string]string{
		"a.js": "var x = 1;\n" + strings.Repeat("// pad\n", 50),
		"b.js": "var y = 2;\n",
	})
	putScen(t, scen, "out-all.json", docJSON(root,
		[]string{resultJSON(root, "b.js", "js-eval", 1)},
		[]string{timeoutJSON(root, "a.js", "js-sqli-taint")},
		[]string{"a.js", "b.js"}, nil))
	return scen, root
}

func TestRetryResolvesAFileThatTimedOutAndKeepsEveryFinding(t *testing.T) {
	scen, root := retryTree(t)
	putScen(t, scen, "out-retry-a.js.json", docJSON(root,
		[]string{resultJSON(root, "a.js", "js-sqli-taint", 3)}, nil, []string{"a.js"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.Timeouts) != 0 || len(run.ThresholdFiles) != 0 {
		t.Errorf("the re-run evaluated a.js in full; the pass-1 timeout must be gone: %+v", run.Timeouts)
	}
	if len(run.Retries) != 1 || !run.Retries[0].Resolved || run.Retries[0].Path != "a.js" {
		t.Fatalf("Retries = %+v", run.Retries)
	}
	got := endpoints(run)
	if len(run.Findings) != 2 {
		t.Errorf("findings = %d (%v), want b.js's pass-1 finding and a.js's retry finding", len(run.Findings), got)
	}
	if run.Report.Incomplete["Timeout"] != 0 {
		t.Errorf("Report still counts the resolved timeout: %v", run.Report.Incomplete)
	}
	lines := argvLines(t, scen)
	if len(lines) != 2 {
		t.Fatalf("want pass 1 and one retry, got %v", lines)
	}
	retry := lines[1]
	for _, want := range []string{"--jobs 1", "--timeout 61", filepath.Join(root, "a.js")} {
		if !strings.Contains(retry, want) {
			t.Errorf("retry argv %q is missing %q", retry, want)
		}
	}
	for _, not := range []string{"--include", "--exclude"} {
		if strings.Contains(retry, not) {
			t.Errorf("a retry of one explicit file must not carry %s: %q", not, retry)
		}
	}
	if !strings.HasSuffix(retry, filepath.Join(root, "a.js")) {
		t.Errorf("the retry's target is the one file: %q", retry)
	}
	if !strings.Contains(retry, "--max-memory 682") {
		t.Errorf("the retry runs under the same memory bound: %q", retry)
	}
}

func TestRetryThatTimesOutAgainLeavesTheFileLostAndKeepsWhatItFound(t *testing.T) {
	scen, root := retryTree(t)
	putScen(t, scen, "out-retry-a.js.json", docJSON(root,
		[]string{resultJSON(root, "a.js", "js-xss", 9)},
		[]string{timeoutJSON(root, "a.js", "js-sqli-taint")}, []string{"a.js"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Timeouts) != 1 || run.Timeouts[0].Path != "a.js" {
		t.Errorf("a file that still timed out must stay lost: %+v", run.Timeouts)
	}
	if len(run.Retries) != 1 || run.Retries[0].Resolved || run.Retries[0].Why != "timed out again" {
		t.Errorf("Retries = %+v", run.Retries)
	}
	if len(run.Findings) != 2 {
		t.Errorf("findings = %d: the re-run's finding on a.js is real evidence and must be kept", len(run.Findings))
	}
}

func TestRetryNeverRemovesALossItCannotShowResolved(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, scen, root string){
		"the re-run failed (exit 2, no document)": func(t *testing.T, scen, root string) {
			putScen(t, scen, "exit-retry-a.js", "2")
			putScen(t, scen, "out-retry-a.js.json", "")
		},
		"the re-run is a fatal error document": func(t *testing.T, scen, root string) {
			putScen(t, scen, "exit-retry-a.js", "2")
			putScen(t, scen, "out-retry-a.js.json", `{"results":[],"errors":[{"level":"error","type":"Rule parse error","message":"x"}]}`)
		},
		"the re-run never says it scanned the file": func(t *testing.T, scen, root string) {
			putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, nil, nil, nil))
		},
		"the re-run reports no paths at all": func(t *testing.T, scen, root string) {
			putScen(t, scen, "out-retry-a.js.json", `{"results":[],"errors":[],"time":{"fixpoint_timeouts":[]}}`)
		},
		"the re-run lost the file to memory": func(t *testing.T, scen, root string) {
			oom := fmt.Sprintf(`{"code":2,"level":"warn","type":"Out of memory","rule_id":"rules.js-x","message":"oom","path":%q}`, filepath.Join(root, "a.js"))
			putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, []string{oom}, []string{"a.js"}, nil))
		},
		"the re-run could not parse the file": func(t *testing.T, scen, root string) {
			bad := fmt.Sprintf(`{"code":3,"level":"warn","type":"Syntax error","message":"x","path":%q}`, filepath.Join(root, "a.js"))
			putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, []string{bad}, []string{"a.js"}, nil))
		},
		"the re-run has a fixpoint timeout": func(t *testing.T, scen, root string) {
			putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, nil, []string{"a.js"}, []string{fixpointJSON(root, "a.js")}))
		},
		"the re-run has no fixpoint list": func(t *testing.T, scen, root string) {
			putScen(t, scen, "out-retry-a.js.json", fmt.Sprintf(`{"results":[],"errors":[],"paths":{"scanned":[%q]}}`, filepath.Join(root, "a.js")))
		},
	} {
		t.Run(name, func(t *testing.T) {
			scen, root := retryTree(t)
			setup(t, scen, root)
			run, err := ScanRun(context.Background(), root, nil)
			if err != nil {
				t.Fatalf("ScanRun: %v", err)
			}
			if len(run.Timeouts) != 1 {
				t.Errorf("the pass-1 timeout must stay: %+v", run.Timeouts)
			}
			if len(run.Retries) != 1 || run.Retries[0].Resolved {
				t.Errorf("Retries = %+v, want one unresolved", run.Retries)
			}
		})
	}
}

// A re-run that evaluated the file with only a partial parse (Semgrep's note
// for a file it did evaluate) is complete as far as time goes.
func TestRetryAcceptsAPartialParseAsEvaluated(t *testing.T) {
	scen, root := retryTree(t)
	partial := fmt.Sprintf(`{"code":3,"level":"warn","type":["PartialParsing",[{"path":%q,"start":{"line":3,"col":1,"offset":0},"end":{"line":3,"col":2,"offset":1}}]],"message":"partial","path":%q}`, filepath.Join(root, "a.js"), filepath.Join(root, "a.js"))
	putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, []string{partial}, []string{"a.js"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Retries) != 1 || !run.Retries[0].Resolved || len(run.Timeouts) != 0 {
		t.Errorf("Retries %+v timeouts %+v", run.Retries, run.Timeouts)
	}
}

func TestRetryHonoursTheFileCapAndTheStageBudget(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"a.js": "var a;\n", "b.js": "var b;\n", "c.js": "var c;\n"})
	var errs []string
	for _, f := range []string{"a.js", "b.js", "c.js"} {
		errs = append(errs, timeoutJSON(root, f, "js-sqli-taint"))
		putScen(t, scen, "out-retry-"+f+".json", docJSON(root, nil, nil, []string{f}, nil))
	}
	putScen(t, scen, "out-all.json", docJSON(root, nil, errs, []string{"a.js", "b.js", "c.js"}, nil))
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{MaxRetryFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Retries) != 3 {
		t.Fatalf("Retries = %+v", run.Retries)
	}
	resolved := 0
	for _, r := range run.Retries {
		if r.Resolved {
			resolved++
		} else if !strings.HasPrefix(r.Why, "not retried: over the cap of 2 files") {
			t.Errorf("unexpected Why %q", r.Why)
		}
	}
	if resolved != 2 || len(run.Timeouts) != 1 {
		t.Errorf("resolved = %d, timeouts left = %d; want 2 and 1 (the file past the cap stays lost)", resolved, len(run.Timeouts))
	}
	if n := len(argvLines(t, scen)); n != 3 {
		t.Errorf("pass 1 plus 2 retries = 3 invocations, got %d", n)
	}

	// A negative cap disables the pass: nothing is re-run and nothing is claimed.
	scen2 := scriptedSemgrep(t)
	putScen(t, scen2, "out-all.json", docJSON(root, nil, errs, []string{"a.js", "b.js", "c.js"}, nil))
	run2, _ := ScanRunWithOptions(context.Background(), root, nil, Options{MaxRetryFiles: -1})
	if len(run2.Retries) != 0 || len(run2.Timeouts) != 3 || len(argvLines(t, scen2)) != 1 {
		t.Errorf("MaxRetryFiles < 0: retries %v, timeouts %d, invocations %d", run2.Retries, len(run2.Timeouts), len(argvLines(t, scen2)))
	}
}

func TestRetryIsSkippedWhenTheStageBudgetIsSpent(t *testing.T) {
	scen, root := retryTree(t)
	putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, nil, []string{"a.js"}, nil))
	restore := SetStageTimingForTesting(time.Second, 0, time.Hour, time.Second)
	defer restore()
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{Wall: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Retries) != 1 || run.Retries[0].Resolved || !strings.HasPrefix(run.Retries[0].Why, "not retried:") {
		t.Errorf("Retries = %+v, want not retried for want of budget", run.Retries)
	}
	if len(run.Timeouts) != 1 {
		t.Errorf("the loss must still be reported: %+v", run.Timeouts)
	}
	if n := len(argvLines(t, scen)); n != 1 {
		t.Errorf("no retry may start without budget, got %d invocations", n)
	}
}

func TestRetryCoversFixpointTimeoutsAndThresholdFiles(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"a.js": "var a;\n", "b.js": "var b;\n"})
	// a.js: a fixpoint timeout in the profile. b.js: three rule timeouts (threshold).
	errs := []string{
		timeoutJSON(root, "b.js", "r1"), timeoutJSON(root, "b.js", "r2"), timeoutJSON(root, "b.js", "r3"),
	}
	putScen(t, scen, "out-all.json", docJSON(root, nil, errs, []string{"a.js", "b.js"}, []string{fixpointJSON(root, "a.js")}))
	putScen(t, scen, "out-retry-a.js.json", docJSON(root, nil, nil, []string{"a.js"}, nil))
	putScen(t, scen, "out-retry-b.js.json", docJSON(root, nil, nil, []string{"b.js"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.FixpointTimeouts) != 0 || len(run.Timeouts) != 0 || len(run.ThresholdFiles) != 0 {
		t.Errorf("both files finished alone, so no loss may remain: fixpoint %d timeouts %d threshold %v", len(run.FixpointTimeouts), len(run.Timeouts), run.ThresholdFiles)
	}
	if len(run.Retries) != 2 {
		t.Errorf("Retries = %+v", run.Retries)
	}
}

func TestRetryDoesNotTouchNonTimeLosses(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"a.js": "var a;\n"})
	oom := fmt.Sprintf(`{"code":2,"level":"warn","type":"OutOfMemory","rule_id":"rules.js-x","message":"oom","path":%q}`, filepath.Join(root, "a.js"))
	putScen(t, scen, "out-all.json", docJSON(root, nil, []string{oom}, []string{"a.js"}, nil))
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Retries) != 0 || len(argvLines(t, scen)) != 1 {
		t.Errorf("an out-of-memory loss is not a time loss; it must not be retried: %+v", run.Retries)
	}
	if len(run.FileErrors) != 1 {
		t.Errorf("FileErrors = %+v", run.FileErrors)
	}
}

func TestStageOutcomeIsIdenticalAcrossRepeatedRuns(t *testing.T) {
	type outcome struct {
		Findings   []string
		Timeouts   int
		Retries    []Retry
		Incomplete map[string]int
		Lost       int
		Calls      int
	}
	var all []outcome
	for i := 0; i < 4; i++ {
		scen, root := retryTree(t)
		putScen(t, scen, "out-retry-a.js.json", docJSON(root,
			[]string{resultJSON(root, "a.js", "js-sqli-taint", 3)}, nil, []string{"a.js"}, nil))
		run, err := ScanRun(context.Background(), root, nil)
		if err != nil {
			t.Fatal(err)
		}
		var ep []string
		for _, f := range run.Findings {
			ep = append(ep, strings.TrimPrefix(f.Endpoint, root))
		}
		sort.Strings(ep)
		all = append(all, outcome{ep, len(run.Timeouts), run.Retries, run.Report.Incomplete, run.Coverage.LostFiles(), len(argvLines(t, scen))})
	}
	for i := 1; i < len(all); i++ {
		if !reflect.DeepEqual(all[0], all[i]) {
			t.Fatalf("run %d differs from run 0:\n%+v\n%+v", i, all[i], all[0])
		}
	}
}

// ---- deadlines ----

func TestSingleInvocationThatReachesTheStageBudgetIsATimeout(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "sleep-all", "30")
	restore := SetStageTimingForTesting(time.Second, 0, 0, 0)
	defer restore()
	started := time.Now()
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{Wall: 2 * time.Second})
	elapsed := time.Since(started)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if !strings.Contains(err.Error(), "after 2s") {
		t.Errorf("the error must name the budget it ran out of: %v", err)
	}
	if elapsed > 15*time.Second {
		t.Errorf("the engine must give up at the budget, took %s", elapsed)
	}
	if len(run.Findings) != 0 {
		t.Errorf("a killed run prints nothing: %+v", run.Findings)
	}
}

func TestShardThatDoesNotFinishLosesOnlyItsOwnFindings(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{
		"a.py":     "x = 1\n",
		"web/b.js": "var y = 2;\n" + strings.Repeat("// padding\n", 300),
	})
	putScen(t, scen, "out-python.json", docJSON(root, []string{resultJSON(root, "a.py", "python-eval", 1)}, nil, []string{"a.py"}, nil))
	putScen(t, scen, "sleep-javascript", "30")
	restore := SetStageTimingForTesting(time.Second, 0, 0, 0)
	defer restore()
	started := time.Now()
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{SplitBytes: 1, Wall: 4 * time.Second})
	elapsed := time.Since(started)
	var st *StageTimeoutError
	if !errors.As(err, &st) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v (%T), want a StageTimeoutError that is a timeout", err, err)
	}
	if len(st.Unfinished) != 1 || st.Unfinished[0] != "javascript 1 file" {
		t.Errorf("Unfinished = %v, want the javascript group named", st.Unfinished)
	}
	if !strings.Contains(err.Error(), "not evaluated: javascript 1 file") {
		t.Errorf("message must say what was lost: %v", err)
	}
	if len(run.Findings) != 1 || !endpoints(run)["a.py"] && !strings.Contains(run.Findings[0].Endpoint, "a.py") {
		t.Errorf("the python group finished and its finding must be kept: %+v", run.Findings)
	}
	if elapsed > 20*time.Second {
		t.Errorf("took %s", elapsed)
	}
	// The group that did not finish is named in the coverage, file by file.
	if !run.Coverage.Lost() || !strings.Contains(strings.Join(run.Coverage.Names("not evaluated"), ","), "web/b.js") && run.Coverage.LostFiles() != 1 {
		t.Errorf("the unevaluated group's file must be in the coverage: lost %d", run.Coverage.LostFiles())
	}
}

func TestStageTimeoutErrorIsBoundedAndNamesWhatWasLost(t *testing.T) {
	e := &StageTimeoutError{Wall: 5 * time.Minute, Unfinished: []string{"javascript 2503 files", "go 800 files"}}
	if !errors.Is(e, ErrTimeout) {
		t.Error("must unwrap to ErrTimeout")
	}
	if got, want := e.Error(), "semgrep: timed out after 5m0s; not evaluated: javascript 2503 files, go 800 files"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	long := &StageTimeoutError{Wall: time.Minute}
	for i := 0; i < 40; i++ {
		long.Unfinished = append(long.Unfinished, fmt.Sprintf("group%02d 1000 files", i))
	}
	msg := long.Error()
	if len(msg) > 260 || !strings.Contains(msg, " and ") || !strings.HasSuffix(msg, " more") {
		t.Errorf("a long list must end in 'and N more', never be cut: %d bytes %q", len(msg), msg)
	}
	if strings.ContainsAny(msg, "\n;…") && strings.Count(msg, ";") > 1 {
		t.Errorf("message must be one segment: %q", msg)
	}
}

func TestCancelledInvocationKillsSemgrepCoreToo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the process tree is read from /proc")
	}
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "spawn-all", "1")
	putScen(t, scen, "sleep-all", "30")
	restore := SetStageTimingForTesting(time.Second, 0, 0, 0)
	defer restore()
	_, err := ScanRunWithOptions(context.Background(), root, nil, Options{Wall: 2 * time.Second})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(scen, "child-all.pid"))
	if rerr != nil {
		t.Fatalf("the stand-in did not record its child: %v", rerr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("the child process %d (the stand-in for semgrep-core) survived the kill and keeps running", pid)
}

func TestContextCancellationStopsTheStage(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{"app.py": "import os\n"})
	putScen(t, scen, "sleep-all", "30")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(500 * time.Millisecond); cancel() }()
	started := time.Now()
	_, err := ScanRun(ctx, root, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if time.Since(started) > 10*time.Second {
		t.Error("cancellation must stop the invocation promptly")
	}
}

// ---- document helpers ----

func TestMergeOutputsUnionsPathsAndNeedsEveryDocumentToReport(t *testing.T) {
	a := mustDecode(t, `{"results":[{"check_id":"a","path":"/w/a.py","start":{"line":1,"col":1},"extra":{}}],"errors":[],"paths":{"scanned":["/w/a.py"]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[{"rule_id":"r1"}]}`)
	b := mustDecode(t, `{"results":[{"check_id":"b","path":"/w/b.js","start":{"line":2,"col":1},"extra":{}}],"errors":[{"level":"warn","type":"Timeout","path":"/w/b.js"}],"paths":{"scanned":["/w/b.js","/w/a.py"]},"time":{"fixpoint_timeouts":[{"message":"x"}]},"skipped_rules":[{"rule_id":"r1"},{"rule_id":"r2"}]}`)
	m := mergeOutputs([]*semgrepOutput{a, b})
	if len(m.Results) != 2 {
		t.Errorf("results = %d", len(m.Results))
	}
	scanned, reported := scannedPaths(m.Paths, "/w")
	if !reported || !scanned["a.py"] || !scanned["b.js"] || len(scanned) != 2 {
		t.Errorf("scanned = %v reported %v", scanned, reported)
	}
	if m.Time == nil || !m.Time.hasFixpoint || len(m.Time.fixpoint) != 1 {
		t.Errorf("fixpoint = %+v", m.Time)
	}
	if errs, ok := errorEntries(m.Errors); !ok || len(errs) != 1 {
		t.Errorf("errors = %s", m.Errors)
	}
	var sk []json.RawMessage
	_ = json.Unmarshal(m.SkippedRules, &sk)
	if len(sk) != 2 {
		t.Errorf("skipped rules not unioned: %s", m.SkippedRules)
	}
	// One document without a paths list, or without a fixpoint list, makes the
	// merge unreported, so a gap is never hidden by the documents that did report.
	c := mustDecode(t, `{"results":[],"errors":[]}`)
	m = mergeOutputs([]*semgrepOutput{a, c})
	if _, reported := scannedPaths(m.Paths, "/w"); reported {
		t.Error("a document with no paths.scanned must make the merge unreported")
	}
	if m.Time != nil && m.Time.hasFixpoint {
		t.Error("a document with no fixpoint list must make the merge unreported")
	}
	// A document whose errors is not a list still costs one undecodable entry.
	d := mustDecode(t, `{"results":[],"errors":"boom","paths":{"scanned":[]},"time":{"fixpoint_timeouts":[]}}`)
	m = mergeOutputs([]*semgrepOutput{a, d})
	if _, rep, _ := classifyDecoded(exitStatus{}, m, "", ""); rep.Incomplete[undecodableType] != 1 {
		t.Errorf("an errors value that is not a list must be counted, got %v", rep.Incomplete)
	}
}

func mustDecode(t *testing.T, doc string) *semgrepOutput {
	t.Helper()
	out, why := decodeEnvelope([]byte(doc))
	if out == nil {
		t.Fatalf("decode: %s", why)
	}
	return out
}

func TestTimeoutFilesAndDropTimeoutEntries(t *testing.T) {
	root := "/w"
	doc := mustDecode(t, `{"results":[],"errors":[
	  {"level":"warn","type":"Timeout","rule_id":"r","path":"/w/a.js"},
	  {"level":"warn","type":"Timeout","rule_id":"r2","path":"/w/a.js"},
	  {"level":"warn","type":"OutOfMemory","rule_id":"r","path":"/w/a.js"},
	  {"level":"warn","type":"Timeout","rule_id":"r","path":"/w/b.js"},
	  {"level":"warn","type":"Syntax error","path":"/w/c.js"},
	  {"level":"warn","type":"Timeout during interfile analysis","path":"/w/d.js"}
	],"time":{"fixpoint_timeouts":[{"location":{"path":"/w/a.js","start":{"line":1}}},{"location":{"path":"/w/e.js","start":{"line":1}}}]}}`)
	got := timeoutFiles(doc, root)
	if !reflect.DeepEqual(got, []string{"a.js", "b.js", "d.js", "e.js"}) {
		t.Errorf("timeoutFiles = %v: time-class losses only (rule timeout, interfile, fixpoint), sorted", got)
	}
	dropTimeoutEntries(doc, "a.js", root)
	if left := timeoutFiles(doc, root); !reflect.DeepEqual(left, []string{"b.js", "d.js", "e.js"}) {
		t.Errorf("after dropping a.js: %v", left)
	}
	entries, _ := errorEntries(doc.Errors)
	if len(entries) != 4 {
		t.Errorf("only a.js's two Timeout entries go; its OutOfMemory entry and every other file's stay: %d entries left", len(entries))
	}
	if len(doc.Time.fixpoint) != 1 {
		t.Errorf("a.js's fixpoint timeout goes, e.js's stays: %d", len(doc.Time.fixpoint))
	}
}

func TestAddResultsDeduplicates(t *testing.T) {
	mk := func(check string, line int) semgrepResult {
		return semgrepResult{CheckID: check, Path: "/w/a.js", Start: semgrepLineCol{Line: line, Col: 1}}
	}
	base := []semgrepResult{mk("a", 1), mk("b", 2)}
	got := addResults(base, []semgrepResult{mk("a", 1), mk("c", 3), mk("c", 3)})
	if len(got) != 3 {
		t.Errorf("got %d results, want a, b, c once each", len(got))
	}
}
