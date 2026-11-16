package semgrep

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Round 6, WS-E3 (PERFORMANCE §6 lever 6). The extensions pass names each
// source file Semgrep does not select by extension (APP.JS, x.mts, a .vue
// component) and runs after every unit, with whatever stage time is left
// (scanner.go, the `time.Until(end) < minShardWindow` check before it). When
// the units use their whole window the pass never starts: on a 94 MB
// node_modules tree it lost 657 files that way. The pass must keep a reserved
// share of the stage, so it runs even when the units before it time out; the
// units' own loss must still be reported, and the reserve must come out of the
// stage, not be added after it: the pass starts before the stage's effective
// wall (Options.Wall raised to minStageWall, budget.go), and the whole stage,
// the pass included, ends within that wall plus 10 s, even when the pass
// itself hangs (G2.5).

// wse3ExtScenario is what one run of the extensions scenario observed.
type wse3ExtScenario struct {
	wall, asked, elapsed time.Duration
	// firstSeen is when each mark ("unit", "ext-start", "ext-end", ...) was
	// first seen, measured from the start of the scan.
	firstSeen map[string]time.Duration
	// count is how many times each mark was written: "unit" is the number of
	// units (and retries) the fake was started for.
	count map[string]int
	// extArgs are the arguments the extensions pass was started with, one per
	// element (all of its invocations, in order).
	extArgs []string
	// unitArgs are the arguments the first unit was started with, one per
	// element.
	unitArgs []string
	run      Run
	err      error
}

// Trees: LEGACY.JS is the one file only the extensions pass evaluates (not
// APP.JS beside app.js: on a case-insensitive file system (macOS) the two
// names are one file, and there would be no explicit target).
var (
	wse3OneUnitTree = map[string]string{
		"src/app.js":    "module.exports = function handler(req, res) { res.end('ok'); };\n",
		"src/LEGACY.JS": "module.exports = function legacy(req, res) { res.end('ok'); };\n",
	}
	// With Options.SplitBytes 1 this tree runs as several units, one per
	// language group.
	wse3SplitTree = map[string]string{
		"src/app.js":    "module.exports = function handler(req, res) { res.end('ok'); };\n",
		"src/LEGACY.JS": "module.exports = function legacy(req, res) { res.end('ok'); };\n",
		"lib/tool.py":   "def tool():\n    return 1\n",
	}
	// Three files only the extensions pass evaluates, in three directories.
	wse3ThreeExplicitTree = map[string]string{
		"src/app.js":    "module.exports = function handler(req, res) { res.end('ok'); };\n",
		"src/LEGACY.JS": "module.exports = function legacy(req, res) { res.end('ok'); };\n",
		"lib/SECOND.JS": "module.exports = function second(req, res) { res.end('ok'); };\n",
		"web/THIRD.JS":  "module.exports = function third(req, res) { res.end('ok'); };\n",
	}
	// No file of an unselected extension: no explicit target, no pass.
	wse3NoExtensionTree = map[string]string{
		"src/app.js": "module.exports = function handler(req, res) { res.end('ok'); };\n",
	}
)

// Fake semgrep bodies. MARKS and CLEAN stand for the invocation log and the
// clean report the fake prints (testdata/runs/baseline.json).
const (
	wse3Hang = "exec sleep 600"
	// A pass that takes a real 5 s and then answers.
	wse3ExtAnswers5s = "sleep 5; echo ext-end >> MARKS; cat CLEAN; exit 0"
	// A unit that takes a real 9 s and then answers: it fits a 20 s stage
	// that keeps a modest reserve for the pass.
	wse3UnitAnswers9s = "sleep 9; echo unit-end >> MARKS; cat CLEAN; exit 0"
)

// wse3RunExtensionsScenario scans tree with a fake semgrep. Every invocation
// marks "unit" and then runs unitBody; one that carries
// --scan-unknown-extensions (the extensions pass) marks "ext-start", records
// its arguments, and then runs extBody instead. The first unit records its
// arguments too (sc.unitArgs). In a body, MARKS is the
// invocation log, CLEAN the clean report the fake prints, and ROOTDIR the
// absolute scan root (not symlink-resolved: on macOS /var is a link, and the
// engine reports paths under the root it was given).
//
// The context outlives any bounded stage, so a stage that is not bounded runs
// until it and fails the elapsed check. At or below minStageWall the context
// (60 s) is shorter than Wall + laterStagesReserve, which pins the stage at the
// 20 s floor; a larger Wall gets a context that leaves it whole, so the
// stage really is that wall.
func wse3RunExtensionsScenario(t *testing.T, unitBody, extBody string, tree map[string]string, opts Options) wse3ExtScenario {
	t.Helper()
	resetRulesCacheForTesting()
	t.Cleanup(resetRulesCacheForTesting)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)

	dir := t.TempDir()
	marks := filepath.Join(dir, "invocations")
	extArgs := filepath.Join(dir, "ext-args")
	unitArgs := filepath.Join(dir, "unit-args")
	clean, err := filepath.Abs(filepath.Join("testdata", "runs", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "semgrep")
	fill := strings.NewReplacer("MARKS", "'"+marks+"'", "CLEAN", "'"+clean+"'", "ROOTDIR", rootAbs)
	script := "#!/bin/sh\ncase \"$1\" in --version) echo 1.182.1; exit 0;; esac\n" +
		"for a in \"$@\"; do\n" +
		"  if [ \"$a\" = --scan-unknown-extensions ]; then echo ext-start >> '" + marks + "'; printf '%s\\n' \"$@\" >> '" + extArgs + "'; " + fill.Replace(extBody) + "; fi\n" +
		"done\n" +
		"[ -s '" + unitArgs + "' ] || printf '%s\\n' \"$@\" > '" + unitArgs + "'\n" +
		"echo unit >> '" + marks + "'\n" + fill.Replace(unitBody) + "\n"
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

	writeTree(t, root, tree)

	sc := wse3ExtScenario{asked: opts.Wall, firstSeen: map[string]time.Duration{}, count: map[string]int{}}
	sc.wall = sc.asked
	if sc.wall < minStageWall {
		sc.wall = minStageWall
	}
	ctxFor := 60 * time.Second
	if opts.Wall > minStageWall {
		ctxFor = opts.Wall + laterStagesReserve + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), ctxFor)
	defer cancel()

	var mu sync.Mutex
	done := make(chan struct{})
	watched := make(chan struct{})
	started := time.Now()
	note := func() {
		raw, _ := os.ReadFile(marks)
		mu.Lock()
		counted := map[string]int{}
		for _, s := range strings.Fields(string(raw)) {
			counted[s]++
			if _, ok := sc.firstSeen[s]; !ok {
				sc.firstSeen[s] = time.Since(started)
			}
		}
		sc.count = counted
		mu.Unlock()
	}
	go func() {
		defer close(watched)
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			note()
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	sc.run, sc.err = ScanRunWithOptions(ctx, root, nil, opts)
	sc.elapsed = time.Since(started)
	close(done)
	<-watched
	// A mark written just before the fake exited may land after the last
	// poll: it was written before the scan returned, so elapsed bounds it.
	note()
	for k, v := range sc.firstSeen {
		if v > sc.elapsed {
			sc.firstSeen[k] = sc.elapsed
		}
	}
	if raw, err := os.ReadFile(extArgs); err == nil {
		sc.extArgs = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	if raw, err := os.ReadFile(unitArgs); err == nil {
		sc.unitArgs = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	if _, ok := sc.firstSeen["unit"]; !ok {
		t.Fatalf("the fake semgrep never ran a unit (marks %v, err %v)", sc.firstSeen, sc.err)
	}
	return sc
}

// wse3CheckStartedInsideTheStage requires the extensions pass to have started
// before the stage's wall, and the stage to have ended within wall + 10 s.
func wse3CheckStartedInsideTheStage(t *testing.T, sc wse3ExtScenario) {
	t.Helper()
	if sc.elapsed > sc.wall+10*time.Second {
		t.Errorf("the stage took %s; its effective wall is %s (Options.Wall %s, minStageWall %s), so it must end within %s",
			sc.elapsed.Round(time.Millisecond), sc.wall, sc.asked, minStageWall, sc.wall+10*time.Second)
	}
	extStart, started := sc.firstSeen["ext-start"]
	if !started {
		t.Errorf("the units used the whole %s stage (Options.Wall %s raised to minStageWall) and the extensions pass never started "+
			"(marks %v, err %v, elapsed %s): it needs a reserved share of the stage, or LEGACY.JS is never evaluated",
			sc.wall, sc.asked, sc.firstSeen, sc.err, sc.elapsed.Round(time.Millisecond))
		return
	}
	if extStart >= sc.wall {
		t.Errorf("the extensions pass started %s after the stage began, at or after its %s wall: it ran after the deadline, not in a reserved share",
			extStart.Round(time.Millisecond), sc.wall)
	}
}

// wse3CheckPassEnded requires the extensions pass, which the fake answers
// after 5 s, to have answered inside the stage: it ended by the wall plus 10 s.
func wse3CheckPassEnded(t *testing.T, sc wse3ExtScenario) {
	t.Helper()
	if _, started := sc.firstSeen["ext-start"]; !started {
		return // wse3CheckStartedInsideTheStage reports it
	}
	extEnd, ended := sc.firstSeen["ext-end"]
	if !ended || extEnd > sc.wall+10*time.Second {
		t.Errorf("the extensions pass (a 5 s run) ended at %s (ended %v); it must answer by the wall plus 10 s, %s (marks %v, err %v)",
			extEnd.Round(time.Millisecond), ended, sc.wall+10*time.Second, sc.firstSeen, sc.err)
	}
}

// wse3CheckUnitTimeout (V1) requires the first unit to run with the per-rule
// timeout the engine always passes (ruleTimeoutSeconds): the time reserved for
// the extensions pass is taken from the units' window, never from Semgrep's own
// per-rule, per-file bound, which would cut the heaviest files off sooner and
// lose findings with no report of it.
func wse3CheckUnitTimeout(t *testing.T, sc wse3ExtScenario) {
	t.Helper()
	want := strconv.Itoa(ruleTimeoutSeconds)
	for i, a := range sc.unitArgs {
		if a == "--timeout" && i+1 < len(sc.unitArgs) {
			if sc.unitArgs[i+1] != want {
				t.Errorf("the first unit ran with --timeout %s, want %s (ruleTimeoutSeconds)", sc.unitArgs[i+1], want)
			}
			return
		}
	}
	t.Errorf("the first unit ran without --timeout (arguments %q); want --timeout %s", sc.unitArgs, want)
}

// wse3CheckUnitLossReported requires the units killed at their deadline to be
// named: reserving time for the pass must not hide them. The stage reports
// them as a StageTimeoutError whose Unfinished lists a unit ("source 2 files"),
// not only the extensions pass ("extensions javascript 1 file"). A bare "the
// run lost something" check passes when nothing is named, because LEGACY.JS
// alone is enough to make the coverage lost.
func wse3CheckUnitLossReported(t *testing.T, sc wse3ExtScenario) {
	t.Helper()
	var stage *StageTimeoutError
	if !errors.As(sc.err, &stage) {
		t.Errorf("the unit killed at its deadline is not reported: err %v is not a StageTimeoutError (lost %d)", sc.err, sc.run.Coverage.LostFiles())
		return
	}
	for _, u := range stage.Unfinished {
		if !strings.HasPrefix(u, "extensions ") {
			return
		}
	}
	t.Errorf("the unit killed at its deadline is not named in Unfinished %q: only the extensions pass is", stage.Unfinished)
}

// The units use their whole window, so without a reserved share the pass would
// never start. The pass takes a real 5 s, then answers: a pass run inside the
// stage ends before the wall plus 10 s, one run after the deadline does not
// even start before the wall.
func TestExtensionsPassKeepsATimeReserveWhenTheUnitsUseTheirWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	sc := wse3RunExtensionsScenario(t, wse3Hang, wse3ExtAnswers5s, wse3OneUnitTree, Options{Wall: 12 * time.Second})
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	wse3CheckPassEnded(t, sc)
	wse3CheckUnitLossReported(t, sc)
}

// B1: a tree in several languages runs as several units, and the reserve is a
// share of the stage for all of them, not only for a single unit.
func TestExtensionsPassKeepsItsReserveWhenTheTreeIsSplit(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	sc := wse3RunExtensionsScenario(t, wse3Hang, wse3ExtAnswers5s, wse3SplitTree, Options{Wall: 12 * time.Second, SplitBytes: 1})
	t.Logf("units started: %d, marks %v, err %v", sc.count["unit"], sc.firstSeen, sc.err)
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	wse3CheckPassEnded(t, sc)
	wse3CheckUnitLossReported(t, sc)
}

// TestExtensionsPassIsBoundedByTheStageWhenItHangs: the reserve is a share of
// the stage, never a stage of its own. A pass that hangs is killed at the
// stage's end like any unit, the stage still ends within its wall plus 10 s,
// the file it was meant to evaluate is reported as not evaluated, never as
// evaluated, and the unit that was killed at its own deadline is named too
// (B2): an error that names only the pass hides the units' loss.
func TestExtensionsPassIsBoundedByTheStageWhenItHangs(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	sc := wse3RunExtensionsScenario(t, wse3Hang, wse3Hang, wse3OneUnitTree, Options{Wall: 12 * time.Second})
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	if _, ended := sc.firstSeen["ext-end"]; ended {
		t.Fatal("the hanging fake cannot have finished the extensions pass")
	}
	if sc.err == nil {
		t.Fatalf("a stage whose extensions pass was killed returned no error: LEGACY.JS reads as evaluated (lost %d)", sc.run.Coverage.LostFiles())
	}
	var stage *StageTimeoutError
	extUnfinished := false
	if errors.As(sc.err, &stage) {
		for _, u := range stage.Unfinished {
			if strings.HasPrefix(u, "extensions ") {
				extUnfinished = true
			}
		}
	}
	lostByName := strings.Contains(sc.run.Coverage.LostDetail(1<<16), "LEGACY.JS")
	if !extUnfinished && !lostByName {
		t.Errorf("LEGACY.JS is reported neither lost nor unfinished (err %v; lost %q)", sc.err, sc.run.Coverage.LostDetail(1<<10))
	}
	wse3CheckUnitLossReported(t, sc)
}

// B3: a unit that fits the stage minus a modest reserve is not cut. The unit
// needs 9 s of the 20 s stage; a reserve that takes most of the stage for the
// pass starves it (and loses the findings it would have printed).
func TestExtensionsReserveLeavesAUnitThatFitsItsWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	sc := wse3RunExtensionsScenario(t, wse3UnitAnswers9s, wse3ExtAnswers5s, wse3OneUnitTree, Options{Wall: 12 * time.Second})
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	if _, ok := sc.firstSeen["unit-end"]; !ok {
		t.Errorf("a unit that needs 9 s of the %s stage was killed before it finished (marks %v, err %v): the reserve starves the units",
			sc.wall, sc.firstSeen, sc.err)
	}
	if _, ok := sc.firstSeen["ext-end"]; !ok {
		t.Errorf("the extensions pass did not end (marks %v, err %v)", sc.firstSeen, sc.err)
	}
	var stage *StageTimeoutError
	if errors.As(sc.err, &stage) {
		t.Errorf("a StageTimeoutError although the unit and the pass both finished: %v", sc.err)
	}
}

// B4: with no explicit target there is no pass to protect, so the unit keeps
// the whole stage and no pass starts.
func TestExtensionsReserveIsNotTakenWithoutAnExplicitTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	sc := wse3RunExtensionsScenario(t, wse3Hang, wse3Hang, wse3NoExtensionTree, Options{Wall: 12 * time.Second})
	if sc.elapsed < sc.wall-time.Second {
		t.Errorf("the stage ended at %s, before its %s wall: the unit was cut for a pass that has nothing to run",
			sc.elapsed.Round(time.Millisecond), sc.wall)
	}
	if _, ok := sc.firstSeen["ext-start"]; ok {
		t.Errorf("an extensions pass started although no file needs one (marks %v)", sc.firstSeen)
	}
}

// wse3ConfigPacks is the base names of the rule packs among args (the value of
// each --config).
func wse3ConfigPacks(args []string) map[string]bool {
	packs := map[string]bool{}
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			packs[filepath.Base(args[i+1])] = true
		}
	}
	return packs
}

// B5: the pass names the extension-only file, with the JavaScript rule pack.
// Run with the reserve in place, a pass that ran on any other file would leave
// LEGACY.JS unevaluated, and one that ran another language's rules would report
// the JavaScript file as a syntax error.
func TestExtensionsPassNamesTheExtensionOnlyFile(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	names := `case "$*" in *src/LEGACY.JS*) echo ext-names-legacy >> MARKS;; esac; ` + wse3ExtAnswers5s
	sc := wse3RunExtensionsScenario(t, wse3Hang, names, wse3ThreeExplicitTree, Options{Wall: 12 * time.Second})
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	if _, ok := sc.firstSeen["ext-names-legacy"]; !ok {
		t.Errorf("the extensions pass ran without naming src/LEGACY.JS (marks %v)", sc.firstSeen)
	}
	// V3: every explicit file is named, not only the first: a pass that is cut
	// down to fit its reserve by dropping targets leaves them unevaluated.
	for _, rel := range []string{"src/LEGACY.JS", "lib/SECOND.JS", "web/THIRD.JS"} {
		named := false
		for _, a := range sc.extArgs {
			if strings.HasSuffix(filepath.ToSlash(a), "/"+rel) {
				named = true
			}
		}
		if !named {
			t.Errorf("the extensions pass was not given %s (arguments %q)", rel, sc.extArgs)
		}
	}
	groups, err := readPackGroups("")
	if err != nil {
		t.Fatal(err)
	}
	got := wse3ConfigPacks(sc.extArgs)
	js := 0
	for _, g := range groups {
		for _, c := range g.configs {
			switch name := filepath.Base(c); {
			case g.name == "javascript":
				js++
				if !got[name] {
					t.Errorf("the extensions pass did not receive the JavaScript pack %s (it got %v)", name, got)
				}
			case g.name != otherGroup && got[name]:
				t.Errorf("the extensions pass received %s, a %s pack: it would parse LEGACY.JS as %s", name, g.name, g.name)
			}
		}
	}
	if js == 0 {
		t.Fatal("the rules hold no JavaScript pack to check the extensions pass against")
	}
}

// B6: the pass's own answer is kept. The pass reports a finding on LEGACY.JS
// and lists it among the files it scanned; a fix that runs the pass inside the
// reserve and then drops what it printed does not evaluate LEGACY.JS. The units
// hang, so the answer can only be the pass's.
func TestExtensionsPassAnswerIsKept(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	answer := "sleep 5; echo ext-end >> MARKS; sed 's#/t/ok/app.py#ROOTDIR/src/LEGACY.JS#g' CLEAN; exit 0"
	sc := wse3RunExtensionsScenario(t, wse3Hang, answer, wse3OneUnitTree, Options{Wall: 12 * time.Second})
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	found := false
	for _, f := range sc.run.Findings {
		if strings.Contains(fmt.Sprintf("%+v", f), "LEGACY.JS") {
			found = true
		}
	}
	if !found {
		t.Errorf("the finding the extensions pass printed for LEGACY.JS is not in the run (%d findings, marks %v, err %v)",
			len(sc.run.Findings), sc.firstSeen, sc.err)
	}
	if lost := sc.run.Coverage.LostDetail(1 << 12); strings.Contains(lost, "LEGACY.JS") {
		t.Errorf("LEGACY.JS is reported lost although the pass reported it scanned: %q", lost)
	}
	wse3CheckUnitLossReported(t, sc)
}

// B7: the reserve is a share of the stage, not a window fixed from its start.
// At a wall above the 20 s floor, a unit that needs 16 s of a 30 s stage keeps
// them, and the pass still ends inside the stage. This is the one case with a
// real wall: every other case sits at the floor, where Options.Wall is moot.
func TestExtensionsReserveScalesWithTheStage(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 30 s stage budget in -short mode")
	}
	unit := "sleep 16; echo unit-end >> MARKS; cat CLEAN; exit 0"
	sc := wse3RunExtensionsScenario(t, unit, wse3ExtAnswers5s, wse3OneUnitTree, Options{Wall: 30 * time.Second})
	if got := sc.run.Budget.Wall; got != 30*time.Second {
		t.Fatalf("the stage budget is %s, want the 30 s asked for: the scenario's context shrank it", got)
	}
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	if _, ok := sc.firstSeen["unit-end"]; !ok {
		t.Errorf("a unit that needs 16 s of a %s stage was killed before it finished (marks %v, err %v): the units' window is not a share of the stage",
			sc.wall, sc.firstSeen, sc.err)
	}
	if _, ok := sc.firstSeen["ext-end"]; !ok {
		t.Errorf("the extensions pass did not end (marks %v, err %v)", sc.firstSeen, sc.err)
	}
	var stage *StageTimeoutError
	if errors.As(sc.err, &stage) {
		t.Errorf("a StageTimeoutError although the unit and the pass both finished: %v", sc.err)
	}
}

// wse3Pad is body padded with a comment line to n bytes, so that files of
// different languages weigh the same and the planner gives them equal units.
func wse3Pad(body string, n int) string {
	if len(body) >= n {
		return body
	}
	return body + strings.Repeat("#", n-len(body)-1) + "\n"
}

// B8: the reserve is taken from every unit, not from the last one only. Three
// equal units (javascript, python, java), the first answers at once and the
// second hangs. With the reserve taken from every unit the second is killed at
// the reserve and the pass starts then; taken from the last unit only, the
// second runs to its whole share of the stage and the pass has less than its
// 5 s left.
func TestExtensionsReserveIsTakenFromEveryUnit(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	js := "module.exports = function handler(req, res) { res.end('ok'); };\n"
	tree := map[string]string{
		"src/app.js":    js,
		"src/LEGACY.JS": js,
		"lib/tool.py":   wse3Pad("def tool():\n    return 1\n", len(js)),
		"lib/Tool.java": wse3Pad("class Tool { }\n", len(js)),
	}
	unit := `n=$(grep -c '^unit$' MARKS); if [ "$n" -le 1 ]; then echo unit-end >> MARKS; cat CLEAN; exit 0; fi; exec sleep 600`
	sc := wse3RunExtensionsScenario(t, unit, wse3ExtAnswers5s, tree, Options{Wall: 12 * time.Second, SplitBytes: 1})
	t.Logf("units started: %d, marks %v, err %v", sc.count["unit"], sc.firstSeen, sc.err)
	wse3CheckStartedInsideTheStage(t, sc)
	wse3CheckUnitTimeout(t, sc)
	wse3CheckPassEnded(t, sc)
	wse3CheckUnitLossReported(t, sc)
}

// X: the answers of the units that finished are kept next to the pass's. A
// unit reports a finding on app.js and lists it as scanned, the pass does the
// same for LEGACY.JS; a fix that keeps the pass's answer and drops the units',
// or the reverse, leaves one of the two files unevaluated.
func TestExtensionsFinishedUnitAnswerIsKept(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a 20 s stage budget in -short mode")
	}
	unit := "sleep 9; echo unit-end >> MARKS; sed 's#/t/ok/app.py#ROOTDIR/src/app.js#g' CLEAN; exit 0"
	pass := "sleep 5; echo ext-end >> MARKS; sed 's#/t/ok/app.py#ROOTDIR/src/LEGACY.JS#g' CLEAN; exit 0"
	sc := wse3RunExtensionsScenario(t, unit, pass, wse3OneUnitTree, Options{Wall: 12 * time.Second})
	wse3CheckUnitTimeout(t, sc)
	var app, legacy bool
	for _, f := range sc.run.Findings {
		s := fmt.Sprintf("%+v", f)
		app = app || strings.Contains(s, "app.js")
		legacy = legacy || strings.Contains(s, "LEGACY.JS")
	}
	if !app || !legacy {
		t.Errorf("the findings kept name app.js %v and LEGACY.JS %v, want both (%d findings, marks %v, err %v)",
			app, legacy, len(sc.run.Findings), sc.firstSeen, sc.err)
	}
	if lost := sc.run.Coverage.LostDetail(1 << 12); lost != "" {
		t.Errorf("files are reported lost (%q) although the unit and the pass each listed theirs as scanned", lost)
	}
	var stage *StageTimeoutError
	if errors.As(sc.err, &stage) {
		t.Errorf("a StageTimeoutError although the unit and the pass both finished: %v", sc.err)
	}
}
