package semgrep

import (
	"bufio"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Round 4, R-008: bounded Semgrep memory and runtime.
//
// Before this, one Semgrep run was handed the whole tree with Semgrep's own
// defaults, which are sized for a CI box, not for the container the hosted
// worker gives a scan:
//
//   - --jobs defaults to 0.85 of the CORES THE KERNEL REPORTS, which inside a
//     container is the host's: a 2-CPU quota on a 10-core VM ran 9 threads, so
//     a pair that takes 20 s alone took 25 s or more, and a pair near a
//     Semgrep-internal time bound crossed it on a busy day and not on a quiet
//     one (sre3-04: juice-shop read ok, failed, ok, failed, failed on one
//     input). The budget derives --jobs from the cgroup CPU quota.
//   - --max-memory defaults to no limit, so the only bound on one pathological
//     file was the kernel's OOM killer, which kills Semgrep whole (no JSON
//     document, so every finding of the run is lost) and sometimes the engine
//     with it. The budget derives --max-memory from the cgroup memory limit,
//     which turns a runaway pair into a reported per-file error.
//   - one 300 s deadline covered the whole tree, and Semgrep prints its JSON
//     once, at the end, so a run that reached it kept no finding at all. The
//     budget splits a large tree into per-language invocations, each with its
//     own share of one stage wall budget, so a language that does not finish
//     loses its own findings and no other language's, and it re-runs the files
//     that timed out ALONE (plan.go).
//
// Nothing here weakens detection: no rule is dropped, no file is skipped, no
// bound is raised above what Semgrep would run. What a bound cuts off is
// reported as lost evaluation, never as a clean result.

// Environment overrides. A value that does not parse, or is out of range, is
// ignored with a warning: a typo must never turn into an unbounded run or stop
// a scan.
const (
	// EnvJobs is the --jobs value, 1..maxJobs.
	EnvJobs = "FENDIX_SEMGREP_JOBS"
	// EnvMaxMemoryMiB is the --max-memory value in MiB; 0 removes the limit.
	EnvMaxMemoryMiB = "FENDIX_SEMGREP_MAX_MEMORY_MIB"
	// EnvWallSeconds is the total wall budget of the Semgrep stage, in seconds,
	// minWallSeconds..maxWallSeconds.
	EnvWallSeconds = "FENDIX_SEMGREP_BUDGET_SECONDS"
	// EnvSplitBytes is the in-scope source size from which a tree in several
	// languages runs one invocation per language group; -1 never splits.
	EnvSplitBytes = "FENDIX_SEMGREP_SPLIT_BYTES"
	// EnvConcurrency is how many scans share the memory the budget is derived
	// from: the container's memory limit, or the host's memory when there is
	// none. 1..maxConcurrency. A deployment that runs several scans in one
	// container or on one host sets it to its worker concurrency.
	EnvConcurrency = "FENDIX_SCAN_CONCURRENCY"
)

const (
	maxJobs        = 256
	maxConcurrency = 64
	minWallSeconds = 30
	maxWallSeconds = 3600

	// assumedMaxCPUs is the most CPUs a scan is planned for (round 5, D5-5).
	// The hosted worker has 2 CPUs and no per-container CPU quota, so the
	// kernel reports the whole host; a bigger host, or a quota above this,
	// does not buy a bigger plan, so the plan (jobs, and with them the memory
	// a run can claim) is the same on a 10-core VM as on the 2-CPU host.
	// FENDIX_SEMGREP_JOBS raises it deliberately.
	assumedMaxCPUs = 2

	// minJobMemoryMiB is the least --max-memory worth giving one semgrep-core
	// process: its rule packs alone hold about 250 MiB, and below this a
	// medium file is a per-file out-of-memory error. When the budget cannot
	// give every job this much, the run uses fewer jobs.
	minJobMemoryMiB = 512

	// uncappedConcurrency is how many scans are assumed to share the host's
	// memory when there is no cgroup limit and EnvConcurrency says nothing:
	// production runs celery-scans at concurrency 2 with no container limit
	// (D5-5), so nothing but this keeps two scans from each claiming half the
	// host.
	uncappedConcurrency = 2

	// minMaxMemoryMiB is the smallest --max-memory the budget will derive.
	// Below it Semgrep cannot hold a rule pack and a large file at once, so
	// every file would be a per-file out-of-memory error; that is reported as
	// such, never worked around by running unbounded.
	minMaxMemoryMiB = 256

	// reservedMiB is what the container needs beside semgrep-core's heap: the
	// Semgrep Python wrapper (about 250 MiB), the engine's own process and its
	// findings, and the page cache the scan tree fills.
	reservedMiB = 384

	// maxMemoryPercent is how much of the rest --max-memory claims. Semgrep
	// checks the limit periodically and documents that the limit "will be
	// exceeded before it gets detected" (try 5% less), so the claim leaves a
	// tenth of margin.
	maxMemoryPercent = 90

	// unlimitedHostPercent is the share of the host's memory all scans together
	// may use when no cgroup limit says what they get. The worker shares its
	// host with the web tier, the queue and the other workers, so half is the
	// budget, divided among the scans that run at once (EnvConcurrency).
	unlimitedHostPercent = 50
)

// DefaultWall is the total wall budget of one Semgrep stage (every
// invocation, the retries included) when nothing sets another. It is the
// 300 s the single run always had, and it sits far under the hosted scan's
// 1490 s subprocess deadline and its 24 min --max-duration, so the engine
// always has time left to report. The backend's Celery default of 300 s does
// not govern a scan (execute_scan carries SCAN_TASK_SOFT_TIME_LIMIT 1500 s).
const DefaultWall = 300 * time.Second

// laterStagesReserve is what the stage leaves of the run's own deadline for
// the analyzers that run after Semgrep (the Python whitebox engine, textscan,
// the dependency audits, the report). When the context carries a deadline
// shorter than DefaultWall plus this, the stage budget shrinks to fit.
const laterStagesReserve = 90 * time.Second

// minStageWall is the least a stage is given, whatever the deadline: below it
// Semgrep cannot even start and finish its rule loading on a small tree.
var minStageWall = 20 * time.Second

// Limits is what the host or container allows this process. Zero means
// "found no limit".
type Limits struct {
	// CPUs is the cgroup CPU quota in CPUs (cpu.max quota / period), the
	// tightest along the cgroup path; 0 when there is none.
	CPUs float64
	// NumCPU is how many CPUs the process may run on (its affinity mask).
	NumCPU int
	// MemoryBytes is the cgroup memory limit, the tightest along the cgroup
	// path; 0 when there is none.
	MemoryBytes int64
	// HostMemoryBytes is the host's total memory (MemTotal); 0 when unknown.
	HostMemoryBytes int64
	// Source says where each number came from, for the log.
	Source string
}

// Budget is the resource plan of one Semgrep stage.
type Budget struct {
	// Jobs is Semgrep's --jobs.
	Jobs int
	// MaxMemoryMiB is Semgrep's --max-memory; 0 passes none (no limit known).
	// Semgrep applies it to each semgrep-core process on its own, so a run
	// can claim Jobs times this much (see memoryPlan).
	MaxMemoryMiB int
	// MemoryMiB is the memory this scan's stage was sized for, 0 when unknown.
	MemoryMiB int
	// Concurrency is how many scans the memory was divided among.
	Concurrency int
	// Wall is the total wall budget of the stage.
	Wall time.Duration
	// Limits is what the budget was derived from.
	Limits Limits
	// Overridden names the settings an environment variable set.
	Overridden []string
	// memoryPinned is set when --max-memory was chosen by hand.
	memoryPinned bool
}

// String is the budget in one log line.
func (b Budget) String() string {
	mem := "none"
	if b.MaxMemoryMiB > 0 {
		mem = strconv.Itoa(b.MaxMemoryMiB) + "MiB"
	}
	s := fmt.Sprintf("jobs=%d max-memory=%s wall=%s concurrency=%d (%s)", b.Jobs, mem, b.Wall, b.Concurrency, b.Limits.Source)
	if len(b.Overridden) > 0 {
		s += " overridden: " + strings.Join(b.Overridden, ",")
	}
	return s
}

// ReadLimits reads the limits of the machine the process runs on.
func ReadLimits() Limits { return readLimitsAt("/", runtime.NumCPU()) }

// readLimitsAt reads the limits under a root directory, so a test can lay out
// a cgroup tree. numCPU is the process's affinity CPU count.
func readLimitsAt(root string, numCPU int) Limits {
	l := Limits{NumCPU: numCPU}
	var sources []string
	if cpus, mem, kind := readCgroup(root); kind != "" {
		l.CPUs, l.MemoryBytes = cpus, mem
		sources = append(sources, kind)
	}
	l.HostMemoryBytes = readMemTotal(root)
	if l.CPUs > 0 {
		sources = append(sources, fmt.Sprintf("cpu quota %.2f", l.CPUs))
	} else {
		sources = append(sources, fmt.Sprintf("no cpu quota, %d cpus", numCPU))
	}
	switch {
	case l.MemoryBytes > 0:
		sources = append(sources, fmt.Sprintf("memory limit %d MiB", l.MemoryBytes>>20))
	case l.HostMemoryBytes > 0:
		sources = append(sources, fmt.Sprintf("no memory limit, host %d MiB", l.HostMemoryBytes>>20))
	default:
		sources = append(sources, "no memory limit found")
	}
	l.Source = strings.Join(sources, ", ")
	return l
}

// unlimitedBytes is the threshold above which a cgroup memory value means
// "no limit": cgroup v1 reports a page-rounded 2^63 for it.
const unlimitedBytes = int64(1) << 60

// readCgroup reads the CPU quota and memory limit that bind the process:
// the tightest value on its cgroup path, which is where a container's limit
// or a systemd slice's lives. kind is "cgroup v2" or "cgroup v1", or "" when
// neither is present.
func readCgroup(root string) (cpus float64, mem int64, kind string) {
	base := filepath.Join(root, "sys", "fs", "cgroup")
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err == nil {
		self := cgroupPathV2(root)
		for dir := filepath.Join(base, self); ; dir = filepath.Dir(dir) {
			if c, ok := readCPUMaxV2(filepath.Join(dir, "cpu.max")); ok && (cpus == 0 || c < cpus) {
				cpus = c
			}
			if m, ok := readIntFile(filepath.Join(dir, "memory.max")); ok && m > 0 && m < unlimitedBytes && (mem == 0 || m < mem) {
				mem = m
			}
			if len(dir) <= len(base) {
				break
			}
		}
		return cpus, mem, "cgroup v2"
	}
	cpuDir := firstExisting(filepath.Join(base, "cpu"), filepath.Join(base, "cpu,cpuacct"), filepath.Join(base, "cpuacct,cpu"))
	memDir := filepath.Join(base, "memory")
	if cpuDir == "" {
		if _, err := os.Stat(memDir); err != nil {
			return 0, 0, ""
		}
	}
	paths := cgroupPathsV1(root)
	if cpuDir != "" {
		c := walkUp(cpuDir, paths["cpu"], func(dir string) (float64, bool) {
			q, qok := readIntFile(filepath.Join(dir, "cpu.cfs_quota_us"))
			p, pok := readIntFile(filepath.Join(dir, "cpu.cfs_period_us"))
			if !qok || !pok || q <= 0 || p <= 0 {
				return 0, false
			}
			return float64(q) / float64(p), true
		})
		cpus = c
	}
	m := walkUp(memDir, paths["memory"], func(dir string) (float64, bool) {
		v, ok := readIntFile(filepath.Join(dir, "memory.limit_in_bytes"))
		if !ok || v <= 0 || v >= unlimitedBytes {
			return 0, false
		}
		return float64(v), true
	})
	return cpus, int64(m), "cgroup v1"
}

// walkUp applies get to the cgroup directory rel under mount and every parent
// up to the mount, and returns the smallest value found, 0 when none.
func walkUp(mount, rel string, get func(dir string) (float64, bool)) float64 {
	best := 0.0
	for dir := filepath.Join(mount, rel); ; dir = filepath.Dir(dir) {
		if v, ok := get(dir); ok && (best == 0 || v < best) {
			best = v
		}
		if len(dir) <= len(mount) {
			break
		}
	}
	return best
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return ""
}

// cgroupPathV2 is the process's cgroup path from /proc/self/cgroup ("0::/p"),
// "" when unreadable or at the root. Inside a container with its own cgroup
// namespace it is "/".
func cgroupPathV2(root string) string {
	f, err := os.Open(filepath.Join(root, "proc", "self", "cgroup"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			return filepath.Clean("/" + strings.TrimSpace(rest))[1:]
		}
	}
	return ""
}

// cgroupPathsV1 maps a v1 controller name to the process's cgroup path for it.
func cgroupPathsV1(root string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(root, "proc", "self", "cgroup"))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		p := filepath.Clean("/" + strings.TrimSpace(parts[2]))[1:]
		for _, ctl := range strings.Split(parts[1], ",") {
			out[ctl] = p
		}
	}
	return out
}

// readCPUMaxV2 parses cpu.max, "max 100000" or "200000 100000".
func readCPUMaxV2(path string) (float64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) < 1 || f[0] == "max" {
		return 0, false
	}
	quota, err := strconv.ParseFloat(f[0], 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period := 100000.0
	if len(f) > 1 {
		if p, err := strconv.ParseFloat(f[1], 64); err == nil && p > 0 {
			period = p
		}
	}
	return quota / period, true
}

// readIntFile reads one integer from a cgroup file; "max" is not an integer.
func readIntFile(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readMemTotal is MemTotal from /proc/meminfo in bytes, 0 when unreadable.
func readMemTotal(root string) int64 {
	f, err := os.Open(filepath.Join(root, "proc", "meminfo"))
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemTotal:"); ok {
			f := strings.Fields(rest)
			if len(f) >= 1 {
				if kb, err := strconv.ParseInt(f[0], 10, 64); err == nil && kb > 0 {
					return kb << 10
				}
			}
		}
	}
	return 0
}

// jobsFor is --jobs for a CPU allowance: Semgrep's own recommendation, 0.85 of
// the CPUs rounded to the nearest whole job (so 2 CPUs run 2 jobs, 4 run 3 and
// 10 run 9, which is Semgrep's default on an uncapped 10-core host), never
// fewer than one. cpus is the allowance, not the host's core count.
func jobsFor(cpus float64) int {
	if cpus <= 0 {
		return 1
	}
	j := int(math.Floor(cpus*0.85 + 0.5))
	if j < 1 {
		j = 1
	}
	if j > maxJobs {
		j = maxJobs
	}
	return j
}

// memoryBudgetMiB is the memory ONE scan may use, from the limits: the cgroup
// limit when there is one (capped by the host's memory), else half of the
// host's, divided among the scans that share it. 0 when nothing is known.
func memoryBudgetMiB(l Limits, concurrency int) int {
	if concurrency < 1 {
		concurrency = 1
	}
	var m int64
	switch {
	case l.MemoryBytes > 0:
		m = l.MemoryBytes
		if l.HostMemoryBytes > 0 && l.HostMemoryBytes < m {
			m = l.HostMemoryBytes
		}
	case l.HostMemoryBytes > 0:
		m = l.HostMemoryBytes * unlimitedHostPercent / 100
	default:
		return 0
	}
	return int(m>>20) / concurrency
}

// memoryPlan is the run's --jobs and --max-memory for a memory budget. What is
// left after the reservation, less the detection margin, is the heap all of a
// run's semgrep-core processes may hold, and Semgrep applies --max-memory to
// each process on its own, so each gets its share of it: a pair that runs
// away on two jobs at once cannot claim twice the budget and be killed by the
// kernel (which loses every finding of the run). A share under
// minJobMemoryMiB would make ordinary files out-of-memory errors, so jobs are
// dropped until each has it, down to one. maxMemory is 0 when the budget is
// unknown, and never below minMaxMemoryMiB.
func memoryPlan(memoryMiB, jobs int) (int, int) {
	if memoryMiB <= 0 {
		return jobs, 0
	}
	avail := (memoryMiB - reservedMiB) * maxMemoryPercent / 100
	for jobs > 1 && avail/jobs < minJobMemoryMiB {
		jobs--
	}
	return jobs, perJobMemory(memoryMiB, jobs)
}

// perJobMemory is --max-memory for jobs processes sharing a memory budget.
func perJobMemory(memoryMiB, jobs int) int {
	if memoryMiB <= 0 {
		return 0
	}
	if jobs < 1 {
		jobs = 1
	}
	per := (memoryMiB - reservedMiB) * maxMemoryPercent / 100 / jobs
	if per < minMaxMemoryMiB {
		per = minMaxMemoryMiB
	}
	return per
}

// SetJobs sets the run's --jobs to n deliberately (a caller's or an
// environment override). The memory each process may hold is re-divided for n,
// unless --max-memory was set by hand, so asking for more jobs never claims
// more memory than the budget.
func (b *Budget) SetJobs(n int) {
	b.Jobs = n
	if !b.memoryPinned && b.MemoryMiB > 0 {
		b.MaxMemoryMiB = perJobMemory(b.MemoryMiB, n)
	}
}

// stageWall is the stage's wall budget: want, shrunk to leave the later
// analyzers laterStagesReserve of the run's remaining time when the run has a
// deadline, and never below minStageWall. remaining < 0 means no deadline.
func stageWall(want, remaining time.Duration) time.Duration {
	if want <= 0 {
		want = DefaultWall
	}
	if remaining >= 0 {
		if room := remaining - laterStagesReserve; room < want {
			want = room
		}
	}
	if want < minStageWall {
		want = minStageWall
	}
	return want
}

// DeriveBudget plans one stage from the limits, the run's remaining time
// (negative: no deadline) and the environment. env is os.Getenv in production.
func DeriveBudget(l Limits, remaining time.Duration, env func(string) string) Budget {
	b := Budget{Limits: l}
	cpus := float64(l.NumCPU)
	if l.CPUs > 0 && (cpus == 0 || l.CPUs < cpus) {
		cpus = l.CPUs
	}
	if cpus == 0 || cpus > assumedMaxCPUs {
		cpus = assumedMaxCPUs
	}
	b.Concurrency = 1
	if l.MemoryBytes <= 0 {
		b.Concurrency = uncappedConcurrency
	}
	if env != nil {
		if v, ok := envInt(env, EnvConcurrency, 1, maxConcurrency); ok {
			b.Concurrency = v
			b.Overridden = append(b.Overridden, EnvConcurrency)
		}
	}
	b.MemoryMiB = memoryBudgetMiB(l, b.Concurrency)
	b.Jobs, b.MaxMemoryMiB = memoryPlan(b.MemoryMiB, jobsFor(cpus))
	want := DefaultWall

	if env != nil {
		if v, ok := envInt(env, EnvJobs, 1, maxJobs); ok {
			b.SetJobs(v)
			b.Overridden = append(b.Overridden, EnvJobs)
		}
		if raw := env(EnvMaxMemoryMiB); strings.TrimSpace(raw) != "" {
			if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && (v == 0 || v >= minMaxMemoryMiB) {
				b.MaxMemoryMiB = v
				b.memoryPinned = true
				b.Overridden = append(b.Overridden, EnvMaxMemoryMiB)
			} else {
				slog.Warn("semgrep: ignoring a budget setting that is not 0 or at least the minimum",
					"name", EnvMaxMemoryMiB, "value", raw, "minimum_mib", minMaxMemoryMiB)
			}
		}
		if v, ok := envInt(env, EnvWallSeconds, minWallSeconds, maxWallSeconds); ok {
			want = time.Duration(v) * time.Second
			b.Overridden = append(b.Overridden, EnvWallSeconds)
		}
	}
	b.Wall = stageWall(want, remaining)
	return b
}

// envInt reads an integer setting in [lo, hi]; a value outside it, or one that
// is not an integer, is ignored with a warning.
func envInt(env func(string) string, name string, lo, hi int) (int, bool) {
	raw := strings.TrimSpace(env(name))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < lo || v > hi {
		slog.Warn("semgrep: ignoring a budget setting outside its range", "name", name, "value", raw, "min", lo, "max", hi)
		return 0, false
	}
	return v, true
}

// splitBytesFromEnv is the split threshold: EnvSplitBytes when it is an
// integer (-1 never splits, 0 is the default), else DefaultSplitBytes.
func splitBytesFromEnv(env func(string) string) int64 {
	raw := strings.TrimSpace(env(EnvSplitBytes))
	if raw == "" {
		return DefaultSplitBytes
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < -1 {
		slog.Warn("semgrep: ignoring a budget setting that is not an integer of at least -1", "name", EnvSplitBytes, "value", raw)
		return DefaultSplitBytes
	}
	if v == 0 {
		return DefaultSplitBytes
	}
	return v
}
