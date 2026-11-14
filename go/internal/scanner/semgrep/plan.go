package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Round 4, R-008 part 2: how one Semgrep stage spends its budget.
//
// A stage is a plan of invocations, each a `semgrep` process:
//
//  1. Pass 1 runs the rule packs over the tree. A small tree, or one in a
//     single language, is one invocation exactly as before. A large tree in
//     several languages is split by language group (python, javascript and
//     typescript, java, go), cheapest first: each group's invocation holds only
//     its own rules and files, so its memory is bounded by the group, and it
//     has a deadline of its own, so a group that does not finish loses its own
//     findings and no other group's. Semgrep prints one JSON document at the
//     end of a run, which is why a run killed at its deadline keeps nothing.
//  2. The retry pass re-runs, one at a time and alone, the files on which pass
//     1 lost evaluation to TIME (a rule timeout, the rule-timeout threshold, a
//     taint fixpoint timeout, an interfile timeout). A pair that took 23 s on
//     an idle host and crossed its bound on a busy one is evaluated again with
//     the host to itself and a per-file timeout scaled by the file's size. A
//     file that finishes there is complete, and its findings are merged; one
//     that does not stays lost, named, exactly as before. The retry never turns
//     a lost file into a clean one without a complete, reported re-evaluation of
//     it, and it never removes a finding.
//
// What is deterministic: the plan (which invocations, in what order, with
// what per-invocation deadline) is a function of the tree (file sizes) and the
// limits (CPU quota, memory), never of how fast the host happens to be; the
// retry candidates, their order and their timeouts are a function of pass 1's
// report and file sizes. What cannot be: whether a pair that costs almost
// exactly its time bound finishes in it. The retry moves that boundary from
// "contended pass 1" to "the file alone, at a larger bound", which is where a
// finish is a statement about the file and not about the day.

// groupName is the pack group a file language belongs to: Semgrep selects
// TypeScript files for the JavaScript packs, which declare both languages.
var groupOfLanguage = map[string]string{
	"python":     "python",
	"javascript": "javascript",
	"typescript": "javascript",
	"java":       "java",
	"go":         "go",
}

// otherGroup holds the packs that do not belong to one language group (a pack
// declaring several groups' languages, or one this engine does not know). Its
// invocation runs whenever the tree is split, over the whole tree, so no rule
// is ever left out by the split.
const otherGroup = "other"

// packGroup is the rule files one invocation of a language group loads.
type packGroup struct {
	name    string
	configs []string // absolute paths of the extracted pack files
}

// readPackGroups groups the embedded packs by the languages their rules
// declare, naming each pack by its path under dir (where the engine extracted
// them). A pack whose languages fall in one group is that group's; any other
// goes to otherGroup. A pack that cannot be read is an error: the caller then
// does not split, so a pack is never silently left out.
func readPackGroups(dir string) ([]packGroup, error) {
	entries, err := fs.ReadDir(embeddedRules, "rules")
	if err != nil {
		return nil, err
	}
	byName := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := embeddedRules.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, err
		}
		var doc struct {
			Rules []struct {
				Languages []string `yaml:"languages"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("pack %s: %w", e.Name(), err)
		}
		groups := map[string]bool{}
		for _, r := range doc.Rules {
			if len(r.Languages) == 0 {
				groups[otherGroup] = true
			}
			for _, l := range r.Languages {
				g, ok := groupOfLanguage[l]
				if !ok {
					g = otherGroup
				}
				groups[g] = true
			}
		}
		name := otherGroup
		if len(groups) == 1 {
			for g := range groups {
				name = g
			}
		}
		byName[name] = append(byName[name], filepath.Join(dir, e.Name()))
	}
	var out []packGroup
	for name, configs := range byName {
		sort.Strings(configs)
		out = append(out, packGroup{name: name, configs: configs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// shard is one pass-1 invocation of a split tree.
type shard struct {
	name    string
	configs []string
	files   []string // the in-scope files of the group (the whole tree for otherGroup)
	bytes   int64
}

// DefaultSplitBytes is the in-scope source size at which a tree in several
// languages is split into per-language invocations. Below it the single
// invocation is cheaper (each invocation pays Semgrep's start-up, about 2 s)
// and a tree this small cannot hold a memory or time problem a split would
// bound.
const DefaultSplitBytes int64 = 4 << 20

// planShards splits a tree by language group, or returns nil when it should
// run as one invocation: fewer than two groups have files, the tree is under
// splitBytes (splitBytes < 0 never splits), or a pack could not be grouped.
// Shards are ordered cheapest first (fewest bytes, then name), so the group
// most likely to be slow runs last with whatever time the others left.
func planShards(t Targets, groups []packGroup, splitBytes int64) []shard {
	if splitBytes < 0 {
		return nil
	}
	byGroup := map[string]*shard{}
	var total int64
	for _, rel := range t.files {
		g, ok := groupOfLanguage[languageOf(rel)]
		if !ok {
			continue
		}
		s := byGroup[g]
		if s == nil {
			s = &shard{name: g}
			byGroup[g] = s
		}
		s.files = append(s.files, rel)
		s.bytes += t.size[rel]
		total += t.size[rel]
	}
	if len(byGroup) < 2 || total < splitBytes {
		return nil
	}
	var out []shard
	for _, g := range groups {
		if g.name == otherGroup {
			out = append(out, shard{name: otherGroup, configs: g.configs, files: append([]string(nil), t.files...)})
			continue
		}
		s := byGroup[g.name]
		if s == nil {
			continue
		}
		s.configs = g.configs
		out = append(out, *s)
	}
	// Every file's group must have a shard that loads its packs, or the split
	// would leave a language unevaluated that the single run evaluated.
	for name := range byGroup {
		found := false
		for _, s := range out {
			if s.name == name {
				found = true
			}
		}
		if !found {
			return nil
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].bytes != out[j].bytes {
			return out[i].bytes < out[j].bytes
		}
		return out[i].name < out[j].name
	})
	return out
}

// shardDeadlines are the offsets from the start of pass 1 at which each
// shard's invocation is killed. Shard i may use everything up to the end of
// pass 1 less the floor each later shard keeps, half of its size-proportional
// share, so a slow shard can borrow the time an early one left but cannot
// starve the ones after it. The offsets depend on file sizes and the budget,
// never on how long earlier shards took.
func shardDeadlines(shards []shard, pass1 time.Duration) []time.Duration {
	var weight float64
	w := make([]float64, len(shards))
	for i, s := range shards {
		w[i] = float64(s.bytes) + 1
		weight += w[i]
	}
	floor := make([]time.Duration, len(shards))
	for i := range shards {
		floor[i] = time.Duration(float64(pass1) * 0.5 * w[i] / weight)
	}
	out := make([]time.Duration, len(shards))
	for i := range shards {
		var later time.Duration
		for j := i + 1; j < len(shards); j++ {
			later += floor[j]
		}
		out[i] = pass1 - later
	}
	return out
}

// Round 5, R-008 residuals 1 and 2: the heaviest files of a group run alone.
//
// Semgrep prints one JSON document at the end of a run, so a run killed at its
// deadline keeps nothing. Splitting by language group isolated one language
// from another, but a group is still all or nothing: with every in-scope file
// evaluated (decision D5-2), gogs' JavaScript group is 230 files and 5.4 MB
// (semantic-ui, mermaid, pdf.js, codemirror, jquery and the first-party
// public/js/gogs.js), it did not finish in the stage budget, and the one
// first-party file was lost with the bundles.
//
// What blows a budget is a few big files, not many small ones: on gogs the
// 461 KB openjpeg_nowasm_fallback.js alone costs more than 160 s (five taint
// rules each exceed 100 s on it, see docs/semgrep-rules.md), while 223 other
// files finish in 11 s. A group of more than ChunkBytes of source therefore
// runs the files of HeavyFileBytes or more, the maxHeavyFiles largest of the
// stage, each in an invocation of its own, and everything else as the group's
// one root run with those files excluded. A heavy file that does not finish
// loses only itself, which falls out of paths.scanned and is named lost
// evaluation, and the stage is recorded failed/timeout. This is an ordering,
// not an exclusion: no file is left out and nothing is chosen by its name or
// appearance, only by its size.
//
// Splitting the rest further was measured and does not pay: Semgrep resolves
// explicit file targets one process each (about 0.14 s a file) and an
// --include list is matched against every file of the tree, so a 1,000-file
// chunk of a 9,000-file tree costs 22 s before it analyses anything. Cutting
// gogs' and a node_modules tree's bulk into chunks cost more than it saved.

// DefaultChunkBytes is the in-scope source size above which a group or an
// unsplit tree isolates its heaviest files. A tree at or under it is one
// invocation over the root, exactly as before.
const DefaultChunkBytes int64 = 3 << 20

// DefaultHeavyFileBytes is the size from which a file of such a group runs in
// an invocation of its own, and maxHeavyFiles how many of a stage do (the
// largest): each costs Semgrep's start-up, about 2-3 s.
const (
	DefaultHeavyFileBytes int64 = 192 << 10
	maxHeavyFiles               = 8
)

// EnvChunkBytes is the group size from which heavy files are isolated, in
// bytes; -1 never isolates. EnvHeavyFileBytes is the size of a heavy file.
const (
	EnvChunkBytes     = "FENDIX_SEMGREP_CHUNK_BYTES"
	EnvHeavyFileBytes = "FENDIX_SEMGREP_HEAVY_FILE_BYTES"
)

// unit is one pass-1 invocation of the plan: a language group, or an unsplit
// tree, run over the root; or one heavy file of such a group, run alone.
type unit struct {
	label   string
	group   string
	configs []string
	// includes, for a heavy file: the root is scanned with one anchored
	// --include naming exactly that file. Semgrep resolves that in a single
	// targeting pass, where an explicit target costs a process.
	includes []string
	// excludes, for the rest of a group that gave up its heavy files: the
	// anchored --exclude patterns that name exactly those files.
	excludes []string
	nfiles   int // files this unit is responsible for, for the report
	bytes    int64
	// largest is the size of the unit's biggest file: what makes a unit slow
	// is a big file (a minified bundle, a taint fixpoint), not many small ones,
	// so units run in order of it.
	largest int64
}

// chunk reports whether the unit is a heavy file run alone.
func (u unit) chunk() bool { return u.includes != nil }

// includePatternSafe reports whether rel can be passed as one anchored
// --include pattern and select exactly that file, and as one anchored --exclude
// pattern that names exactly that file. Semgrep reads both as globs, so a name
// with a glob character or one it may trim is not safe; neither is any
// non-ASCII byte, whose handling is not worth betting a file's evaluation on.
// A file that is not safe is never isolated: it stays in its group's root run.
func includePatternSafe(rel string) bool {
	if rel == "" || rel[0] == ' ' || rel[len(rel)-1] == ' ' {
		return false
	}
	for i := 0; i < len(rel); i++ {
		c := rel[i]
		if c < 0x20 || c > 0x7e {
			return false
		}
		switch c {
		case '*', '?', '[', ']', '{', '}', '\\', '!', '#':
			return false
		}
	}
	_, ok := excludePattern(rel)
	return ok
}

// chunkBytesFromEnv is the group size from which heavy files are isolated:
// EnvChunkBytes when it is an integer (-1 never isolates, 0 is the default),
// else DefaultChunkBytes.
func chunkBytesFromEnv(env func(string) string) int64 {
	return int64Env(env, EnvChunkBytes, DefaultChunkBytes, -1)
}

// heavyBytesFromEnv is the size of a heavy file: EnvHeavyFileBytes when it is a
// positive integer, else DefaultHeavyFileBytes.
func heavyBytesFromEnv(env func(string) string) int64 {
	return int64Env(env, EnvHeavyFileBytes, DefaultHeavyFileBytes, 1)
}

func int64Env(env func(string) string, name string, def, min int64) int64 {
	raw := strings.TrimSpace(env(name))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < min {
		slog.Warn("semgrep: ignoring a budget setting that is not an integer in range", "name", name, "value", raw)
		return def
	}
	if v == 0 {
		return def
	}
	return v
}

// selectedBytes is the size of the files Semgrep selects by their extension,
// the ones a root run evaluates (the others go to the extensions pass), and
// the files themselves.
func selectedBytes(files []string, size map[string]int64) (sel []string, total int64) {
	for _, rel := range files {
		if semgrepSelects(rel) {
			sel = append(sel, rel)
			total += size[rel]
		}
	}
	return sel, total
}

// heavyFiles is the set of files that run each in an invocation of their own:
// the isolable files of at least heavyBytes, the maxHeavyFiles largest of them.
// The choice is a function of names and sizes only.
func heavyFiles(files []string, size map[string]int64, heavyBytes int64) map[string]bool {
	var cand []string
	for _, f := range files {
		if size[f] >= heavyBytes && includePatternSafe(f) {
			cand = append(cand, f)
		}
	}
	sort.SliceStable(cand, func(i, j int) bool {
		if size[cand[i]] != size[cand[j]] {
			return size[cand[i]] > size[cand[j]]
		}
		return cand[i] < cand[j]
	})
	if len(cand) > maxHeavyFiles {
		cand = cand[:maxHeavyFiles]
	}
	set := make(map[string]bool, len(cand))
	for _, f := range cand {
		set[f] = true
	}
	return set
}

// planUnits is the plan of pass 1. shards is the per-language split (nil when
// the tree is not split); rules is the directory holding every pack, run for
// an unsplit tree. A group whose files total no more than chunkBytes (or any
// group when chunkBytes < 0) is one root run, as before; a larger one gives up
// its heaviest files to invocations of their own (heavyFiles) and runs the
// rest over the root with those files excluded. Units are ordered cheapest
// first: the bulk, then the heavy files smallest first.
func planUnits(t Targets, shards []shard, rules, root string, chunkBytes, heavyBytes int64) []unit {
	type base struct {
		name    string
		configs []string
		files   []string
		bytes   int64
		all     int
	}
	var bases []base
	if len(shards) == 0 {
		sel, total := selectedBytes(t.files, t.size)
		bases = []base{{name: "source", configs: []string{rules}, files: sel, bytes: total, all: len(t.files)}}
	} else {
		for _, sh := range shards {
			sel, total := selectedBytes(sh.files, t.size)
			bases = append(bases, base{name: sh.name, configs: sh.configs, files: sel, bytes: total, all: len(sh.files)})
		}
	}
	isolated := func(b base) bool {
		return chunkBytes >= 0 && b.bytes > chunkBytes && !(len(shards) > 0 && b.name == otherGroup)
	}
	// The largest files of the groups that isolate any, at most maxHeavyFiles
	// in all.
	var candidates []string
	for _, b := range bases {
		if isolated(b) {
			candidates = append(candidates, b.files...)
		}
	}
	heavySet := heavyFiles(candidates, t.size, heavyBytes)
	var out []unit
	for _, b := range bases {
		var largest int64
		for _, f := range b.files {
			if t.size[f] > largest && !heavySet[f] {
				largest = t.size[f]
			}
		}
		whole := unit{label: b.name, group: b.name, configs: b.configs, nfiles: b.all, bytes: b.bytes, largest: largest}
		var heavy []string
		if isolated(b) {
			for _, f := range b.files {
				if heavySet[f] {
					heavy = append(heavy, f)
				}
			}
		}
		if len(heavy) == 0 {
			out = append(out, whole)
			continue
		}
		for _, f := range heavy {
			pattern, _ := excludePattern(f)
			whole.excludes = append(whole.excludes, pattern)
			whole.bytes -= t.size[f]
			whole.nfiles--
		}
		out = append(out, whole)
		for _, f := range heavy {
			out = append(out, unit{
				label:    fmt.Sprintf("%s %s", b.name, f),
				group:    b.name,
				configs:  b.configs,
				includes: []string{"/" + f},
				nfiles:   1,
				bytes:    t.size[f],
				largest:  t.size[f],
			})
		}
	}
	chunked := false
	for _, u := range out {
		if u.chunk() {
			chunked = true
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		// A plan with a heavy file runs the bulk first and the heavy files
		// smallest first; a plan without keeps the groups' order (fewest
		// bytes first).
		if chunked && out[i].largest != out[j].largest {
			return out[i].largest < out[j].largest
		}
		if out[i].bytes != out[j].bytes {
			return out[i].bytes < out[j].bytes
		}
		return out[i].label < out[j].label
	})
	return out
}

// unitDeadlines is shardDeadlines for any plan: the offsets from the start of
// pass 1 at which each unit's invocation is killed, from the units' sizes and
// the budget alone.
func unitDeadlines(units []unit, pass1 time.Duration) []time.Duration {
	shards := make([]shard, len(units))
	for i, u := range units {
		shards[i] = shard{name: u.label, bytes: u.bytes}
	}
	return shardDeadlines(shards, pass1)
}

// unfinishedNames names what a stage did not evaluate, one entry per group:
// "javascript 31 files". Units are folded by group in plan order.
func unfinishedNames(lost []unit) []string {
	var order []string
	n := map[string]int{}
	for _, u := range lost {
		if _, ok := n[u.group]; !ok {
			order = append(order, u.group)
		}
		n[u.group] += u.nfiles
	}
	out := make([]string, 0, len(order))
	for _, g := range order {
		out = append(out, fmt.Sprintf("%s %s", g, filesNoun(n[g])))
	}
	return out
}

// minShardWindow is the least time a language group's invocation is started
// with. A group left with less is not run and is reported not evaluated.
var minShardWindow = 5 * time.Second

// filesNoun is "1 file" or "3 files".
func filesNoun(n int) string {
	if n == 1 {
		return "1 file"
	}
	return strconv.Itoa(n) + " files"
}

// DefaultMaxRetryFiles bounds how many files the retry pass re-runs. The cap
// keeps the retry's worst case (every candidate running to its bound) inside
// the stage budget; a candidate past it is not retried and stays reported
// lost.
const DefaultMaxRetryFiles = 12

// retryStartup is what one retry attempt is allowed beyond its per-rule
// timeouts (at most timeoutThreshold of them) for Semgrep's own start-up and
// parsing.
var retryStartup = 20 * time.Second

// minRetryAttempt is the least stage time left for which a retry is started.
var minRetryAttempt = 15 * time.Second

// SetStageTimingForTesting shortens the stage's fixed time constants (the
// least stage budget, the least window of a language group, the least time a
// retry starts with, and a retry's start-up allowance) for the rest of a test
// and returns the function that restores them. Tests that need a real stage
// timeout in seconds, not minutes, use it; nothing else may.
func SetStageTimingForTesting(floor, shardWindow, retryAttempt, retryStart time.Duration) (restore func()) {
	pf, ps, pa, pr := minStageWall, minShardWindow, minRetryAttempt, retryStartup
	minStageWall, minShardWindow, minRetryAttempt, retryStartup = floor, shardWindow, retryAttempt, retryStart
	return func() { minStageWall, minShardWindow, minRetryAttempt, retryStartup = pf, ps, pa, pr }
}

// retryTimeoutFor is the per-rule --timeout of a retry of one file: twice the
// first-pass timeout, plus a second for every 32 KiB of the file, up to eight
// times the first pass. It depends on the file's size and the first-pass
// timeout, nothing else.
func retryTimeoutFor(base int, size int64) int {
	if base <= 0 {
		base = ruleTimeoutSeconds
	}
	t := 2*base + int((size+(32<<10)-1)>>15)
	if max := 8 * base; t > max {
		t = max
	}
	return t
}

// Retry is the outcome of re-running one file alone after pass 1 lost
// evaluation on it to time.
type Retry struct {
	Path string // relative to the scan root
	// Resolved is set when the re-run evaluated the file completely, so the
	// pass-1 loss for it is removed from the run.
	Resolved bool
	// Why says what happened when it was not resolved ("budget: 8s left",
	// "timed out again", "not retried: over the retry cap").
	Why string
	// Timeout is the per-rule timeout the attempt used, in seconds.
	Timeout int
}

// StageTimeoutError is returned when the stage's wall budget ran out before
// every invocation finished. It unwraps to ErrTimeout, so the orchestrator
// records the analyzer failed/timeout, and it names what was not evaluated.
type StageTimeoutError struct {
	Wall       time.Duration
	Unfinished []string // "javascript 2503 files"
}

func (e *StageTimeoutError) Error() string {
	const limit = 200
	msg := fmt.Sprintf("%v after %s", ErrTimeout, e.Wall.Round(time.Second))
	if len(e.Unfinished) == 0 {
		return msg
	}
	msg += "; not evaluated: "
	for i, u := range e.Unfinished {
		next := u
		if i > 0 {
			next = ", " + u
		}
		if len(msg)+len(next) > limit {
			return msg + fmt.Sprintf(" and %d more", len(e.Unfinished)-i)
		}
		msg += next
	}
	return msg
}

func (e *StageTimeoutError) Unwrap() error { return ErrTimeout }

// invocation is one semgrep process of the plan.
type invocation struct {
	label    string
	configs  []string
	targets  []string // explicit targets; the scan root when empty
	timeout  int      // --timeout seconds
	jobs     int
	deadline time.Time
	retry    bool // a retry of one file: no includes and no declared excludes
	// explicit marks an invocation whose targets are files named one by one
	// (a retry, or the extensions pass): no includes and no declared excludes,
	// both of which apply to a scan of the root.
	explicit bool
	// includes, when set, replace the stage's --include list: the invocation
	// scans the root and selects exactly these files (a heavy file run alone).
	includes []string
	// excludes are anchored --exclude patterns added to the stage's: the heavy
	// files a group's root run leaves to their own invocations.
	excludes []string
	// unknownExt passes --scan-unknown-extensions, so Semgrep evaluates a named
	// file whose extension it does not select (APP.JS, x.mts).
	unknownExt bool
}

// invResult is how one invocation ended.
type invResult struct {
	label    string
	stdout   []byte
	stderr   string
	status   exitStatus
	timedOut bool  // killed at its deadline
	ctxErr   error // the run's own context was cancelled
	startErr error // the process could not be started or waited on
	elapsed  time.Duration
}

// killOnCancel makes a cancelled invocation take its whole process tree down:
// Semgrep's Python wrapper starts semgrep-core, and killing the wrapper alone
// leaves the core running at full CPU and memory for the rest of the engine's
// run. The tree is killed rather than the process group because the backend
// kills the engine's own group and a child in a group of its own would escape
// that.
func killOnCancel(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killTree(cmd.Process)
	}
	cmd.WaitDelay = 5 * time.Second
}

// stage is the shared state of one stage's invocations.
type stage struct {
	bin      string
	target   string
	base     []string // flags every invocation takes
	version  semgrepVersion
	excludes []string
	includes []string
	budget   Budget
	end      time.Time // the stage's wall deadline
	// dropped notes are the same for every invocation; the first one's are kept.
	note, lossyNote, why string
	noted                bool
}

// args builds the command line of one invocation.
func (st *stage) args(inv invocation) []string {
	var args []string
	for _, c := range inv.configs {
		args = append(args, "--config", c)
	}
	args = append(args, st.base...)
	excludes := append(append([]string(nil), st.excludes...), inv.excludes...)
	if inv.retry || inv.explicit {
		excludes = nil
	}
	optional, dropped, lossy, costs := optionalArgs(st.version, st.target, excludes, runOptions{
		timeout:   inv.timeout,
		jobs:      inv.jobs,
		maxMemory: st.budget.MaxMemoryMiB,
	})
	if !st.noted {
		st.noted = true
		st.note = droppedNote(st.version, dropped)
		st.lossyNote = droppedNote(st.version, lossy)
		st.why = droppedWhy(costs)
	}
	args = append(args, optional...)
	if inv.unknownExt {
		args = append(args, "--scan-unknown-extensions")
	}
	includes := st.includes
	if inv.includes != nil {
		includes = inv.includes
	}
	if !inv.retry && !inv.explicit {
		for _, rel := range includes {
			// One argument, "--include=<rel>": a changed file called "-x.py" is a
			// value, never an option (review item 4).
			args = append(args, "--include="+rel)
		}
	}
	// Every target is absolute, and follows "--", so that no name, a file's or
	// the scan root's, can be read by Semgrep as an option: a file called
	// "--config=x.mts" or a root called "-x" reaches it as a path (review item
	// 4, decision D5-2).
	targets := inv.targets
	if len(targets) == 0 {
		targets = []string{st.target}
	}
	args = append(args, "--")
	for _, t := range targets {
		args = append(args, absoluteTarget(t))
	}
	return args
}

// absoluteTarget is p as an absolute path, so it cannot start with '-'. A path
// that cannot be made absolute is prefixed with "./", which has the same effect.
func absoluteTarget(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return "." + string(filepath.Separator) + p
}

// run starts one invocation and waits for it.
func (st *stage) run(ctx context.Context, inv invocation) invResult {
	res := invResult{label: inv.label}
	ictx, cancel := context.WithDeadline(ctx, inv.deadline)
	defer cancel()
	cmd := commandContext(ictx, st.bin, st.args(inv)...)
	killOnCancel(cmd)
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, n: stderrKeep}
	started := time.Now()
	stdout, err := cmd.Output()
	res.elapsed = time.Since(started)
	res.stdout, res.stderr = stdout, stderr.String()
	// A deadline that fired while the process ran means it was killed, even if
	// the wrapper then exited 0: its document is not trusted as a finished run
	// (round 5, DE6-02). The findings it printed are kept by the caller, as for
	// any timeout.
	deadlineFired := errors.Is(ictx.Err(), context.DeadlineExceeded) && !errors.Is(ctx.Err(), context.Canceled)
	if err == nil && !deadlineFired {
		return res
	}
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		res.ctxErr = ctx.Err()
	case deadlineFired:
		res.timedOut = true
	default:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			res.startErr = err
			return res
		}
		res.status = exitStatusOf(exitErr)
	}
	return res
}

// timeoutFiles lists, relative to absRoot, the files on which the document
// lost evaluation to time: a rule Timeout, a fixpoint timeout in the profile or
// in `errors`, any other timeout-class per-file error. Sorted, unique.
func timeoutFiles(out *semgrepOutput, absRoot string) []string {
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" {
			seen[relPath(p, absRoot)] = true
		}
	}
	entries, _ := errorEntries(out.Errors)
	for _, e := range entries {
		var d semgrepErrorDetail
		if json.Unmarshal(e, &d) == nil && d.perFile() && IsTimeoutType(d.typeTag()) {
			add(d.path())
		}
	}
	if out.Time != nil {
		for _, raw := range out.Time.fixpoint {
			var f fixpointEntry
			if json.Unmarshal(raw, &f) == nil {
				add(firstNonEmpty(f.Location.Path, f.Path))
			}
		}
	}
	files := make([]string, 0, len(seen))
	for p := range seen {
		files = append(files, p)
	}
	sort.Strings(files)
	return files
}

// dropTimeoutEntries removes from the document the time-class loss entries of
// one file (rel): its `errors` entries of a timeout type and its profile's
// fixpoint timeouts. Everything else about the file is left alone.
func dropTimeoutEntries(out *semgrepOutput, rel, absRoot string) {
	if entries, ok := errorEntries(out.Errors); ok && entries != nil {
		kept := make([]json.RawMessage, 0, len(entries))
		for _, e := range entries {
			var d semgrepErrorDetail
			if json.Unmarshal(e, &d) == nil && d.perFile() && IsTimeoutType(d.typeTag()) && d.path() != "" && relPath(d.path(), absRoot) == rel {
				continue
			}
			kept = append(kept, e)
		}
		if b, err := json.Marshal(kept); err == nil {
			out.Errors = b
		}
	}
	if out.Time != nil && out.Time.hasFixpoint {
		kept := make([]json.RawMessage, 0, len(out.Time.fixpoint))
		for _, raw := range out.Time.fixpoint {
			var f fixpointEntry
			if json.Unmarshal(raw, &f) == nil {
				if p := firstNonEmpty(f.Location.Path, f.Path); p != "" && relPath(p, absRoot) == rel {
					continue
				}
			}
			kept = append(kept, raw)
		}
		out.Time.fixpoint = kept
	}
}

// resultKey identifies one match for de-duplication across invocations.
func resultKey(r semgrepResult) string {
	return r.CheckID + "\x00" + r.Path + "\x00" + strconv.Itoa(r.Start.Line) + ":" + strconv.Itoa(r.Start.Col) + "\x00" + r.Extra.Lines
}

// addResults appends the results of extra that base does not already hold.
func addResults(base, extra []semgrepResult) []semgrepResult {
	have := make(map[string]bool, len(base))
	for _, r := range base {
		have[resultKey(r)] = true
	}
	for _, r := range extra {
		if !have[resultKey(r)] {
			have[resultKey(r)] = true
			base = append(base, r)
		}
	}
	return base
}

// mergeOutputs combines the documents of several invocations into one, as if
// one run had produced them: results and errors concatenated, skipped rules
// unioned, paths.scanned unioned (reported only when every document reported
// it) and the fixpoint profile concatenated (reported only when every document
// had one). A document whose `errors` is not a list contributes one
// undecodable entry, which classifyRun counts as lost evaluation as before.
func mergeOutputs(docs []*semgrepOutput) *semgrepOutput {
	if len(docs) == 1 {
		return docs[0]
	}
	m := &semgrepOutput{}
	var errs []json.RawMessage
	scanned := map[string]bool{}
	var scannedOrder []string
	pathsReported, fixReported := true, true
	var fix []json.RawMessage
	skipped := map[string]bool{}
	var skippedList []json.RawMessage
	seenResult := map[string]bool{}
	for _, d := range docs {
		// Invocations are disjoint by construction; a result that two of them
		// print (an --exclude an old Semgrep ignored) is one result.
		for _, r := range d.Results {
			if k := resultKey(r); !seenResult[k] {
				seenResult[k] = true
				m.Results = append(m.Results, r)
			}
		}
		entries, ok := errorEntries(d.Errors)
		if !ok {
			entries = []json.RawMessage{json.RawMessage(`"errors that are not a list"`)}
		}
		errs = append(errs, entries...)
		var paths struct {
			Scanned []string `json:"scanned"`
		}
		if len(d.Paths) == 0 || json.Unmarshal(d.Paths, &paths) != nil || paths.Scanned == nil {
			pathsReported = false
		}
		for _, p := range paths.Scanned {
			if !scanned[p] {
				scanned[p] = true
				scannedOrder = append(scannedOrder, p)
			}
		}
		if d.Time == nil || !d.Time.hasFixpoint {
			fixReported = false
		} else {
			fix = append(fix, d.Time.fixpoint...)
		}
		var sk []json.RawMessage
		if len(d.SkippedRules) > 0 && json.Unmarshal(d.SkippedRules, &sk) == nil {
			for _, s := range sk {
				if !skipped[string(s)] {
					skipped[string(s)] = true
					skippedList = append(skippedList, s)
				}
			}
		}
	}
	if b, err := json.Marshal(errs); err == nil {
		m.Errors = b
	}
	if pathsReported {
		if b, err := json.Marshal(struct {
			Scanned []string `json:"scanned"`
		}{scannedOrder}); err == nil {
			m.Paths = b
		}
	}
	if fixReported {
		m.Time = &semgrepTime{fixpoint: fix, hasFixpoint: true}
	}
	if len(skippedList) > 0 {
		if b, err := json.Marshal(skippedList); err == nil {
			m.SkippedRules = b
		}
	}
	return m
}

// retryPass re-runs the files of out on which time cost evaluation, one at a
// time and alone, and folds each complete re-run into out. It returns what it
// did for each candidate. packsFor names the pack files a file's language needs.
func (st *stage) retryPass(ctx context.Context, out *semgrepOutput, absRoot string, size func(rel string) int64, packsFor func(rel string) []string, maxFiles int) []Retry {
	cands := timeoutFiles(out, absRoot)
	if len(cands) == 0 || maxFiles < 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		si, sj := size(cands[i]), size(cands[j])
		if si != sj {
			return si < sj
		}
		return cands[i] < cands[j]
	})
	if maxFiles == 0 {
		maxFiles = DefaultMaxRetryFiles
	}
	var done []Retry
	for i, rel := range cands {
		r := Retry{Path: rel}
		abs := filepath.Join(absRoot, filepath.FromSlash(rel))
		switch {
		case ctx.Err() != nil:
			r.Why = "not retried: the run ended"
		case i >= maxFiles:
			r.Why = fmt.Sprintf("not retried: over the cap of %d files", maxFiles)
		case time.Until(st.end) < minRetryAttempt:
			r.Why = fmt.Sprintf("not retried: %s of the stage budget left", time.Until(st.end).Round(time.Second))
		case !fileExists(abs):
			r.Why = "not retried: the file is not on disk"
		default:
			r.Timeout = retryTimeoutFor(ruleTimeoutSeconds, size(rel))
			inv := invocation{
				label:   "retry " + rel,
				configs: packsFor(rel),
				targets: []string{abs},
				timeout: r.Timeout,
				jobs:    1,
				// Semgrep stops a file after timeoutThreshold rule timeouts, so one
				// attempt takes at most that many per-rule timeouts, plus start-up.
				// A bound any tighter could kill an attempt that was about to
				// report "timed out again" and would lose its findings with it.
				deadline: minTime(st.end, time.Now().Add(time.Duration(timeoutThreshold*r.Timeout)*time.Second+retryStartup)),
				retry:    true,
				// A file Semgrep does not select by its extension is named, so
				// the re-run evaluates it the way pass 1 did.
				unknownExt: !semgrepSelects(rel),
			}
			st.applyRetry(ctx, &r, inv, out, abs, absRoot)
		}
		slog.Info("semgrep: retry of a file that lost evaluation to time",
			"path", r.Path, "resolved", r.Resolved, "why", r.Why, "timeout_s", r.Timeout)
		done = append(done, r)
	}
	return done
}

// applyRetry runs one retry and folds it into out when it evaluated the file
// completely.
func (st *stage) applyRetry(ctx context.Context, r *Retry, inv invocation, out *semgrepOutput, abs, absRoot string) {
	res := st.run(ctx, inv)
	switch {
	case res.ctxErr != nil:
		r.Why = "not finished: the run ended"
		return
	case res.timedOut:
		r.Why = fmt.Sprintf("not finished: still running after %s", res.elapsed.Round(time.Second))
		return
	case res.startErr != nil:
		r.Why = "not finished: " + res.startErr.Error()
		return
	}
	doc, _, cerr := classifyRun(res.status, res.stdout, res.stderr)
	if doc == nil || cerr != nil {
		r.Why = "not finished: the re-run failed"
		return
	}
	// Findings of a re-run are real whether or not it resolved the file.
	out.Results = addResults(out.Results, doc.Results)
	scanned, reported := scannedPaths(doc.Paths, absRoot)
	lost := lostEvaluationOf(doc, r.Path, absRoot)
	switch {
	case !reported || !scanned[r.Path]:
		r.Why = "re-run did not report evaluating the file"
	case len(timeoutFiles(doc, absRoot)) > 0:
		r.Why = "timed out again"
	case lost != "":
		// Not a time loss, so pass 1 never named it, but a file whose re-run
		// lost evaluation to memory, a parse failure or any other cause is not
		// complete, and removing pass 1's entry for it would hide that.
		r.Why = "re-run lost evaluation again (" + lost + ")"
	case doc.Time == nil || !doc.Time.hasFixpoint:
		r.Why = "re-run did not report taint timeouts"
	default:
		dropTimeoutEntries(out, r.Path, absRoot)
		r.Resolved = true
	}
}

// lostEvaluationOf names the first lost-evaluation error type a document
// reports for one file (rel), or "" when it reports none. Only a partial parse,
// which Semgrep reports for a file it did evaluate, is not a loss.
func lostEvaluationOf(out *semgrepOutput, rel, absRoot string) string {
	entries, _ := errorEntries(out.Errors)
	for _, e := range entries {
		var d semgrepErrorDetail
		if json.Unmarshal(e, &d) != nil || !d.perFile() || d.path() == "" || relPath(d.path(), absRoot) != rel {
			continue
		}
		if typ := d.typeTag(); IsLossType(typ) && !ruleErrorTypes[typ] {
			return typ
		}
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.Mode().IsRegular()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
