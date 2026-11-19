package semgrep

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Round 5, R-008 residuals 1 and 2: the heaviest files of a large group run in
// invocations of their own and the rest is one root run, so the findings of
// whatever finishes are kept when a heavy file does not.

func sizedTargets(sizes map[string]int64) Targets {
	t := Targets{size: map[string]int64{}}
	var names []string
	for n := range sizes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.files = append(t.files, n)
		t.size[n] = sizes[n]
		if !semgrepSelects(n) {
			t.explicit = append(t.explicit, n)
		}
	}
	return t
}

func TestPlanUnitsSmallTreeIsOneRootRun(t *testing.T) {
	small := sizedTargets(map[string]int64{"a.js": 100, "b.js": 200})
	u := planUnits(small, nil, "/rules", "/r", DefaultChunkBytes, DefaultHeavyFileBytes)
	if len(u) != 1 || u[0].chunk() || u[0].nfiles != 2 || len(u[0].excludes) != 0 {
		t.Fatalf("a tree under the chunk size is one root invocation, got %+v", u)
	}
	// Whatever its largest file: under the chunk size nothing is isolated.
	one := sizedTargets(map[string]int64{"a.js": 900 << 10, "b.js": 10})
	if got := planUnits(one, nil, "/rules", "/r", DefaultChunkBytes, DefaultHeavyFileBytes); len(got) != 1 || got[0].chunk() {
		t.Errorf("a tree under the chunk size is one root run: %+v", got)
	}
	// And a negative chunk size never isolates.
	big := sizedTargets(map[string]int64{"a.js": 2 << 20, "b.js": 2 << 20, "c.js": 10})
	if got := planUnits(big, nil, "/rules", "/r", -1, DefaultHeavyFileBytes); len(got) != 1 || got[0].chunk() {
		t.Errorf("a negative chunk size never isolates: %+v", got)
	}
}

// A group over the chunk size runs its big files each in an invocation of their
// own and the rest together, so a bundle that does not finish loses only
// itself and the first-party files around it are evaluated (gogs: 230
// JavaScript files, seven of them 240-730 KB bundles).
func TestPlanUnitsIsolatesTheLargestFilesAndRunsTheRestTogether(t *testing.T) {
	sizes := map[string]int64{"public/js/gogs.js": 48 << 10}
	for i := 0; i < 200; i++ {
		sizes[fmt.Sprintf("public/plugins/p%03d.js", i)] = 5 << 10
	}
	bundles := []string{"semantic.min.js", "pdf.mjs", "viewer.mjs", "highlight.pack.js"}
	for i, b := range bundles {
		sizes["public/plugins/"+b] = int64(300+i*100) << 10
	}
	units := planUnits(sizedTargets(sizes), nil, "/rules", "/r", 2<<20, DefaultHeavyFileBytes)
	if len(units) != len(bundles)+1 {
		t.Fatalf("want the bulk and one unit per bundle, got %d units: %+v", len(units), units)
	}
	bulk := units[0]
	if bulk.chunk() || bulk.nfiles != 201 || len(bulk.excludes) != len(bundles) {
		t.Fatalf("the bulk runs first, over the root, without the bundles: %+v", bulk)
	}
	for _, b := range bundles {
		want := "/public/plugins/" + b
		found := false
		for _, e := range bulk.excludes {
			if e == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the bulk must exclude %s exactly (anchored), has %v", want, bulk.excludes)
		}
	}
	for i, u := range units[1:] {
		if !u.chunk() || len(u.includes) != 1 || u.nfiles != 1 || u.largest < DefaultHeavyFileBytes {
			t.Errorf("a heavy file runs alone, selected by one anchored include: %+v", u)
		}
		if i > 0 && u.largest < units[i].largest {
			t.Errorf("heavy files run smallest first: %d then %d", units[i].largest, u.largest)
		}
	}
	// Every file is in exactly one unit: the bulk (all but the bundles) or its own.
	if got := planUnits(sizedTargets(sizes), nil, "/rules", "/r", 2<<20, DefaultHeavyFileBytes); !reflect.DeepEqual(got, units) {
		t.Error("the plan changed between calls")
	}
}

// Only maxHeavyFiles files are isolated in all, the largest: each costs a
// Semgrep start-up.
func TestPlanUnitsIsolatesAtMostMaxHeavyFilesAcrossTheStage(t *testing.T) {
	sizes := map[string]int64{"x.go": 100}
	for i := 0; i < 200; i++ {
		sizes[fmt.Sprintf("web/f%03d.js", i)] = int64(200+i) << 10 // 40 MB of JavaScript
	}
	tg := sizedTargets(sizes)
	groups := []packGroup{{name: "go", configs: []string{"/rules/go.yaml"}}, {name: "javascript", configs: []string{"/rules/js.yaml"}}}
	units := planUnits(tg, planShards(tg, groups, 1), "/rules", "/r", DefaultChunkBytes, DefaultHeavyFileBytes)
	heavy := 0
	for _, u := range units {
		if u.chunk() {
			heavy++
			if u.group != "javascript" || !reflect.DeepEqual(u.configs, []string{"/rules/js.yaml"}) {
				t.Errorf("a heavy javascript file loads only the javascript packs: %+v", u)
			}
			if u.largest < int64(200+200-maxHeavyFiles)<<10 {
				t.Errorf("only the largest files are isolated, got %d bytes", u.largest)
			}
		}
	}
	if heavy != maxHeavyFiles {
		t.Errorf("%d heavy units, want %d", heavy, maxHeavyFiles)
	}
}

// A name Semgrep could read as a glob, or trim, or that is not plain ASCII, is
// never isolated: it stays in its group's root run, so no file is lost to a
// pattern that did not match it.
func TestAFileThatCannotBeAnIncludePatternStaysInTheRootRun(t *testing.T) {
	for _, n := range []string{"a[1].py", "b*.py", "c?.py", "d{e}.py", "e\\f.py", "!g.py", "#h.py", " i.py", "j.py ", "ké.py", ""} {
		if includePatternSafe(n) {
			t.Errorf("%q must not be an include pattern", n)
		}
	}
	for _, n := range []string{"a.py", "-c.py", "d/e.py", "dir with space/f.py", "g_h-i.2.py"} {
		if !includePatternSafe(n) {
			t.Errorf("%q is a plain name and must be an include pattern", n)
		}
	}
	sizes := map[string]int64{"ok.js": 2 << 20, "odd[1].js": 3 << 20, "small.js": 10}
	units := planUnits(sizedTargets(sizes), nil, "/rules", "/r", 1<<20, DefaultHeavyFileBytes)
	covered := map[string]int{}
	for _, u := range units {
		for _, inc := range u.includes {
			covered[strings.TrimPrefix(inc, "/")]++
		}
	}
	if covered["ok.js"] != 1 || covered["odd[1].js"] != 0 {
		t.Errorf("ok.js is isolated and odd[1].js is not: %v (%+v)", covered, units)
	}
	var bulk unit
	for _, u := range units {
		if !u.chunk() {
			bulk = u
		}
	}
	if len(units) != 2 || bulk.nfiles != 2 || len(bulk.excludes) != 1 || bulk.excludes[0] != "/ok.js" {
		t.Errorf("the bulk holds small.js and odd[1].js and excludes only ok.js: %+v", units)
	}
}

func TestUnfinishedNamesFoldUnitsByGroup(t *testing.T) {
	got := unfinishedNames([]unit{
		{group: "javascript", nfiles: 3}, {group: "go", nfiles: 1}, {group: "javascript", nfiles: 4},
	})
	if want := []string{"javascript 7 files", "go 1 file"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// bigPy is a source file over the heavy-file size the tests set.
func bigPy(first string) string { return first + "\n" + strings.Repeat("# pad\n", 40) }

// A heavy file that does not finish loses its own file and no other unit's
// findings (R-008 residual 1).
func TestHeavyFileThatDoesNotFinishKeepsTheFindingsOfTheOthers(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{
		"a.py": "x = 1\n",
		"b.py": bigPy("y = 1"),
		"c.py": bigPy("z = 1") + strings.Repeat("# more\n", 80),
	})
	// The bulk (a.py) and the first heavy file (b.py) finish, the larger heavy
	// file (c.py) runs last and does not.
	putScen(t, scen, "out-all.json", docJSON(root, []string{resultJSON(root, "a.py", "python-eval", 1)}, nil, []string{"a.py"}, nil))
	putScen(t, scen, "out-retry-b.py.json", docJSON(root, []string{resultJSON(root, "b.py", "python-eval", 1)}, nil, []string{"b.py"}, nil))
	putScen(t, scen, "sleep-retry-c.py", "30")
	restore := SetStageTimingForTesting(time.Second, 0, 0, 0)
	defer restore()
	started := time.Now()
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{ChunkBytes: 1, HeavyFileBytes: 100, Wall: 6 * time.Second})
	var st *StageTimeoutError
	if !errors.As(err, &st) || !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v (%T), want a StageTimeoutError that is a timeout", err, err)
	}
	if len(st.Unfinished) != 1 || st.Unfinished[0] != "source 1 file" {
		t.Errorf("Unfinished = %v, want the one unfinished heavy file counted", st.Unfinished)
	}
	var found []string
	for _, f := range run.Findings {
		found = append(found, strings.SplitN(filepath.Base(f.Endpoint), ":", 2)[0])
	}
	sort.Strings(found)
	if !reflect.DeepEqual(found, []string{"a.py", "b.py"}) {
		t.Errorf("findings of the units that finished must be kept, got %v", found)
	}
	if run.Coverage.LostFiles() != 1 {
		t.Errorf("the unfinished heavy file must be named lost evaluation, lost %d", run.Coverage.LostFiles())
	}
	if len(run.Units) != 3 {
		t.Errorf("Units = %v, want the bulk and two heavy files", run.Units)
	}
	if time.Since(started) > 25*time.Second {
		t.Errorf("took %s", time.Since(started))
	}
}

// The bulk is a root run that excludes exactly the heavy files; a heavy file is
// a root run that selects exactly itself by an anchored include. Every file is
// named once, and every target is the root after "--".
func TestIsolationRunsTheBulkWithExcludesAndEachHeavyFileWithAnInclude(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{
		"a.py":   "x = 1\n",
		"-c.py":  bigPy("z = 1"),
		"d/e.py": bigPy("w = 1") + strings.Repeat("# more\n", 80),
	})
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{ChunkBytes: 1, HeavyFileBytes: 100})
	if err != nil {
		t.Fatalf("ScanRun: %v (%v)", err, run.Coverage.LostFiles())
	}
	var includes, excludes []string
	bulk, heavy := 0, 0
	for _, line := range argvLines(t, scen) {
		args := strings.Fields(line)
		dd, inc := -1, 0
		for i, a := range args {
			if a == "--" {
				dd = i
			}
			if strings.HasPrefix(a, "--include=") {
				inc++
				includes = append(includes, strings.TrimPrefix(a, "--include="))
			}
			if a == "--exclude" && i+1 < len(args) {
				excludes = append(excludes, args[i+1])
			}
		}
		if dd < 0 {
			t.Errorf("no -- before the targets: %s", line)
			continue
		}
		if got := args[dd+1:]; len(got) != 1 || got[0] != root {
			t.Errorf("every invocation scans the root alone after --, got %v", got)
		}
		if inc > 0 {
			heavy++
		} else {
			bulk++
		}
	}
	sort.Strings(includes)
	sort.Strings(excludes)
	want := []string{"/-c.py", "/d/e.py"}
	if !reflect.DeepEqual(includes, want) || !reflect.DeepEqual(excludes, want) {
		t.Errorf("includes %v excludes %v, want each heavy file once in both %v", includes, excludes, want)
	}
	if bulk != 1 || heavy != 2 {
		t.Errorf("want one bulk run and two heavy runs, got %d and %d", bulk, heavy)
	}
}

// The same tree with isolation turned off is the old behaviour: one invocation
// that does not finish keeps nothing, so every file of it is lost. This is the
// failure R-008 residual 1 reproduced on gogs (a 230-file JavaScript group lost
// whole, first-party file included) and the isolation removes.
func TestWithoutIsolationAnUnfinishedInvocationKeepsNothing(t *testing.T) {
	scen := scriptedSemgrep(t)
	root := fixtureRoot(t, map[string]string{
		"a.py": "x = 1\n" + strings.Repeat("# pad\n", 20),
		"b.py": "y = 1\n" + strings.Repeat("# pad\n", 60),
	})
	putScen(t, scen, "sleep-all", "30")
	restore := SetStageTimingForTesting(time.Second, 0, 0, 0)
	defer restore()
	run, err := ScanRunWithOptions(context.Background(), root, nil, Options{ChunkBytes: -1, Wall: 2 * time.Second})
	if !errors.Is(err, ErrTimeout) || len(run.Findings) != 0 {
		t.Fatalf("err = %v findings = %d, want a timeout that kept nothing", err, len(run.Findings))
	}
	if len(run.Units) != 0 {
		t.Errorf("a killed single run returns no plan: %v", run.Units)
	}
}

func TestChunkAndHeavyByteSettingsFromTheEnvironment(t *testing.T) {
	for _, c := range []struct {
		raw        string
		chunk, hvy int64
	}{
		{"", DefaultChunkBytes, DefaultHeavyFileBytes},
		{"0", DefaultChunkBytes, DefaultHeavyFileBytes},
		{"-1", -1, DefaultHeavyFileBytes},
		{"524288", 512 << 10, 512 << 10},
		{"lots", DefaultChunkBytes, DefaultHeavyFileBytes},
		{"-5", DefaultChunkBytes, DefaultHeavyFileBytes},
	} {
		if got := chunkBytesFromEnv(envOf(map[string]string{EnvChunkBytes: c.raw})); got != c.chunk {
			t.Errorf("%s=%q: chunk %d, want %d", EnvChunkBytes, c.raw, got, c.chunk)
		}
		hv := c.hvy
		if c.raw == "-1" {
			hv = DefaultHeavyFileBytes // a heavy size must be positive
		}
		if got := heavyBytesFromEnv(envOf(map[string]string{EnvHeavyFileBytes: c.raw})); got != hv {
			t.Errorf("%s=%q: heavy %d, want %d", EnvHeavyFileBytes, c.raw, got, hv)
		}
	}
}

// Two invocations that print the same result (an --exclude an old Semgrep
// ignored) report it once.
func TestMergeOutputsReportsAResultTwoInvocationsPrintOnce(t *testing.T) {
	r := semgrepResult{CheckID: "rules.x", Path: "/w/a.js", Start: semgrepLineCol{Line: 3, Col: 1}}
	r.Extra.Lines = "eval(x)"
	m := mergeOutputs([]*semgrepOutput{{Results: []semgrepResult{r}}, {Results: []semgrepResult{r, {CheckID: "rules.y", Path: "/w/a.js"}}}})
	if len(m.Results) != 2 {
		t.Errorf("results = %d, want 2 (the repeated one counted once)", len(m.Results))
	}
}
