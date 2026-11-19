package semgrep

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Round 4, R-008: the budget derivation. Semgrep's own defaults read the
// host's core count and no memory limit; the budget reads the container's.

func TestJobsForFollowsTheCPUAllowanceNotTheHost(t *testing.T) {
	for _, c := range []struct {
		cpus float64
		want int
	}{
		{0, 1}, {0.25, 1}, {0.5, 1}, {1, 1}, {1.5, 1}, {2, 2}, {3, 3}, {4, 3}, {6, 5}, {8, 7}, {10, 9}, {1000, maxJobs},
	} {
		if got := jobsFor(c.cpus); got != c.want {
			t.Errorf("jobsFor(%v) = %d, want %d", c.cpus, got, c.want)
		}
	}
}

// Round 5, R-008 / D5-5: Semgrep applies --max-memory to each semgrep-core
// process on its own, so the budget divides the heap among the jobs, and gives
// fewer jobs rather than a share too small to hold a rule pack.
func TestMemoryPlanDividesTheHeapAmongTheJobs(t *testing.T) {
	for _, c := range []struct {
		name         string
		memMiB, jobs int
		wantJobs     int
		wantMax      int
	}{
		{"unknown memory: no limit is invented", 0, 2, 2, 0},
		{"the concurrency-1 share of the 3.8 GB host", 1900, 2, 2, 682}, // (1900-384)*0.9 = 1364 between two jobs
		{"the whole host", 3800, 2, 2, 1537},                            // 3074 between two jobs
		{"one job keeps all of it", 1900, 1, 1, 1364},
		{"half of that: two jobs would get 254 each, so one runs", 950, 2, 1, 509},
		{"too small to hold a pack: floor, never unbounded", 600, 2, 1, minMaxMemoryMiB},
		{"nothing left after the reservation", 384, 2, 1, minMaxMemoryMiB},
		{"a roomy box", 2048, 1, 1, (2048 - 384) * 9 / 10},
	} {
		jobs, max := memoryPlan(c.memMiB, c.jobs)
		if jobs != c.wantJobs || max != c.wantMax {
			t.Errorf("%s: memoryPlan(%d, %d) = jobs %d max-memory %d, want %d / %d", c.name, c.memMiB, c.jobs, jobs, max, c.wantJobs, c.wantMax)
		}
		// The invariant the plan exists for: every process at its limit still
		// fits the budget (the floor aside).
		if c.memMiB > reservedMiB && max > minMaxMemoryMiB && jobs*max > c.memMiB-reservedMiB {
			t.Errorf("%s: %d jobs x %d MiB = %d exceeds the budget %d MiB", c.name, jobs, max, jobs*max, c.memMiB-reservedMiB)
		}
	}
}

func TestMemoryBudgetUsesTheCgroupLimitElseHalfTheHostDividedAmongScans(t *testing.T) {
	const gib = int64(1) << 30
	for _, c := range []struct {
		name        string
		l           Limits
		concurrency int
		want        int
	}{
		{"cgroup limit", Limits{MemoryBytes: 2 * gib, HostMemoryBytes: 8 * gib}, 1, 2048},
		{"cgroup limit above the host", Limits{MemoryBytes: 16 * gib, HostMemoryBytes: 4 * gib}, 1, 4096},
		{"cgroup limit shared by two scans", Limits{MemoryBytes: 2 * gib, HostMemoryBytes: 8 * gib}, 2, 1024},
		{"no limit: half of a 3.8 GB host for one scan", Limits{HostMemoryBytes: 3800 << 20}, 1, 1900},
		{"no limit: two scans share that half", Limits{HostMemoryBytes: 3800 << 20}, 2, 950},
		{"nothing known", Limits{}, 2, 0},
	} {
		if got := memoryBudgetMiB(c.l, c.concurrency); got != c.want {
			t.Errorf("%s: memoryBudgetMiB = %d, want %d", c.name, got, c.want)
		}
	}
}

// D5-5: production has 2 CPUs, no CPU quota and no container memory limit, and
// runs celery-scans at concurrency 2. The plan must not read the host's core
// count as the allowance, and must not take the whole host's memory for itself.
func TestBudgetAssumesTwoCPUsAndNoMemoryCapAtConcurrencyTwo(t *testing.T) {
	prod := Limits{NumCPU: 2, HostMemoryBytes: 3831 << 20}
	b := DeriveBudget(prod, -1, nil)
	if b.Concurrency != uncappedConcurrency {
		t.Errorf("an uncapped host is assumed shared by %d scans, got %d", uncappedConcurrency, b.Concurrency)
	}
	if b.MemoryMiB != 3831/2/2 {
		t.Errorf("MemoryMiB = %d, want a quarter of the 3831 MiB host", b.MemoryMiB)
	}
	if b.Jobs*b.MaxMemoryMiB > b.MemoryMiB-reservedMiB {
		t.Errorf("%d jobs x %d MiB exceeds this scan's %d MiB less the %d MiB reserve", b.Jobs, b.MaxMemoryMiB, b.MemoryMiB, reservedMiB)
	}
	// A 10-core VM and a 64-CPU quota plan like the 2-CPU host.
	for name, l := range map[string]Limits{
		"10 cores, no quota": {NumCPU: 10, HostMemoryBytes: 3831 << 20},
		"quota of 64 CPUs":   {NumCPU: 64, CPUs: 64, HostMemoryBytes: 3831 << 20},
	} {
		if got := DeriveBudget(l, -1, nil); got.Jobs != b.Jobs || got.MaxMemoryMiB != b.MaxMemoryMiB {
			t.Errorf("%s: jobs %d max-memory %d, want the 2-CPU plan %d / %d", name, got.Jobs, got.MaxMemoryMiB, b.Jobs, b.MaxMemoryMiB)
		}
	}
	// The deployment says how many scans share the host.
	one := DeriveBudget(prod, -1, envOf(map[string]string{EnvConcurrency: "1"}))
	if one.MemoryMiB != 3831/2 || one.Concurrency != 1 {
		t.Errorf("FENDIX_SCAN_CONCURRENCY=1: memory %d concurrency %d", one.MemoryMiB, one.Concurrency)
	}
	// Asking for more jobs re-divides the same memory, never claims more.
	more := DeriveBudget(prod, -1, envOf(map[string]string{EnvConcurrency: "1", EnvJobs: "4"}))
	if more.Jobs != 4 || more.Jobs*more.MaxMemoryMiB > more.MemoryMiB {
		t.Errorf("4 jobs: %d x %d MiB exceeds %d MiB", more.Jobs, more.MaxMemoryMiB, more.MemoryMiB)
	}
}

// fakeRoot lays out files under a temp root: name -> content.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReadLimitsCgroupV2(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"sys/fs/cgroup/cgroup.controllers": "cpu memory",
		"sys/fs/cgroup/cpu.max":            "200000 100000\n",
		"sys/fs/cgroup/memory.max":         "1992294400\n", // 1900 MiB
		"proc/self/cgroup":                 "0::/\n",
		"proc/meminfo":                     "MemTotal:       10240000 kB\nMemFree: 1 kB\n",
	})
	l := readLimitsAt(root, 10)
	if l.CPUs != 2 {
		t.Errorf("CPUs = %v, want 2 (the quota, not the 10 cores)", l.CPUs)
	}
	if l.MemoryBytes != 1992294400 {
		t.Errorf("MemoryBytes = %d", l.MemoryBytes)
	}
	if l.HostMemoryBytes != 10240000<<10 {
		t.Errorf("HostMemoryBytes = %d", l.HostMemoryBytes)
	}
	if !strings.Contains(l.Source, "cgroup v2") {
		t.Errorf("Source = %q", l.Source)
	}
	b := DeriveBudget(l, -1, nil)
	if b.Jobs != 2 || b.MaxMemoryMiB != 682 || b.Wall != DefaultWall {
		t.Errorf("budget = %+v, want jobs 2, max-memory 682 each, wall %s", b, DefaultWall)
	}
}

func TestReadLimitsCgroupV2Unlimited(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"sys/fs/cgroup/cgroup.controllers": "cpu memory",
		"sys/fs/cgroup/cpu.max":            "max 100000\n",
		"sys/fs/cgroup/memory.max":         "max\n",
		"proc/self/cgroup":                 "0::/\n",
		"proc/meminfo":                     "MemTotal:        3891200 kB\n", // 3800 MiB
	})
	l := readLimitsAt(root, 4)
	if l.CPUs != 0 || l.MemoryBytes != 0 {
		t.Errorf("max means no limit, got cpus %v memory %d", l.CPUs, l.MemoryBytes)
	}
	b := DeriveBudget(l, -1, nil)
	// No quota: the process's own CPU count, at most the 2 CPUs a scan is
	// planned for; no memory limit: half the host, shared by two scans, which
	// leaves room for one job.
	if b.Jobs != 1 {
		t.Errorf("jobs = %d, want 1 (a quarter of the host holds one job)", b.Jobs)
	}
	if b.MemoryMiB != 950 || b.MaxMemoryMiB != 509 {
		t.Errorf("memory = %d / max-memory %d, want 950 / 509", b.MemoryMiB, b.MaxMemoryMiB)
	}
}

func TestReadLimitsCgroupV2TakesTheTightestOnThePath(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"sys/fs/cgroup/cgroup.controllers":  "cpu memory",
		"sys/fs/cgroup/cpu.max":             "max 100000\n",
		"sys/fs/cgroup/svc/cpu.max":         "100000 100000\n", // the slice: 1 CPU
		"sys/fs/cgroup/svc/memory.max":      "1073741824\n",    // 1 GiB
		"sys/fs/cgroup/svc/leaf/cpu.max":    "max 100000\n",
		"sys/fs/cgroup/svc/leaf/memory.max": "max\n",
		"proc/self/cgroup":                  "0::/svc/leaf\n",
		"proc/meminfo":                      "MemTotal: 8388608 kB\n",
	})
	l := readLimitsAt(root, 8)
	if l.CPUs != 1 || l.MemoryBytes != 1<<30 {
		t.Errorf("limits = cpus %v memory %d, want the parent slice's 1 CPU and 1 GiB", l.CPUs, l.MemoryBytes)
	}
}

func TestReadLimitsCgroupV1(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"sys/fs/cgroup/cpu/cpu.cfs_quota_us":         "150000\n",
		"sys/fs/cgroup/cpu/cpu.cfs_period_us":        "100000\n",
		"sys/fs/cgroup/memory/memory.limit_in_bytes": "2147483648\n",
		"proc/self/cgroup":                           "4:cpu,cpuacct:/\n3:memory:/\n",
		"proc/meminfo":                               "MemTotal: 16777216 kB\n",
	})
	l := readLimitsAt(root, 16)
	if l.CPUs != 1.5 || l.MemoryBytes != 2<<30 {
		t.Errorf("limits = cpus %v memory %d", l.CPUs, l.MemoryBytes)
	}
	if !strings.Contains(l.Source, "cgroup v1") {
		t.Errorf("Source = %q", l.Source)
	}
	if b := DeriveBudget(l, -1, nil); b.Jobs != 1 {
		t.Errorf("1.5 CPUs must run 1 job, got %d", b.Jobs)
	}
}

func TestReadLimitsCgroupV1Unlimited(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"sys/fs/cgroup/cpu/cpu.cfs_quota_us":         "-1\n",
		"sys/fs/cgroup/cpu/cpu.cfs_period_us":        "100000\n",
		"sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
		"proc/self/cgroup":                           "4:cpu,cpuacct:/\n3:memory:/\n",
	})
	l := readLimitsAt(root, 2)
	if l.CPUs != 0 || l.MemoryBytes != 0 {
		t.Errorf("an unlimited v1 cgroup must read as no limit, got %+v", l)
	}
}

func TestReadLimitsWithoutCgroupsOrProc(t *testing.T) {
	l := readLimitsAt(t.TempDir(), 6)
	if l.CPUs != 0 || l.MemoryBytes != 0 || l.HostMemoryBytes != 0 || l.NumCPU != 6 {
		t.Errorf("limits = %+v", l)
	}
	b := DeriveBudget(l, -1, nil)
	if b.Jobs != 2 || b.MaxMemoryMiB != 0 {
		t.Errorf("budget = %+v: jobs from the CPU count (at most 2), and no --max-memory when memory is unknown", b)
	}
}

func TestReadLimitsOfThisHostIsUsable(t *testing.T) {
	l := ReadLimits()
	if l.NumCPU < 1 {
		t.Fatalf("NumCPU = %d", l.NumCPU)
	}
	if b := DeriveBudget(l, -1, nil); b.Jobs < 1 || b.Wall <= 0 {
		t.Errorf("budget = %+v", b)
	}
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDeriveBudgetEnvironmentOverrides(t *testing.T) {
	l := Limits{NumCPU: 10, CPUs: 2, MemoryBytes: 1900 << 20}
	b := DeriveBudget(l, -1, envOf(map[string]string{
		EnvJobs: "4", EnvMaxMemoryMiB: "900", EnvWallSeconds: "120",
	}))
	if b.Jobs != 4 || b.MaxMemoryMiB != 900 || b.Wall != 120*time.Second {
		t.Errorf("budget = %+v", b)
	}
	if len(b.Overridden) != 3 {
		t.Errorf("Overridden = %v", b.Overridden)
	}
	// 0 removes the memory limit on request.
	b = DeriveBudget(l, -1, envOf(map[string]string{EnvMaxMemoryMiB: "0"}))
	if b.MaxMemoryMiB != 0 {
		t.Errorf("an explicit 0 must pass no --max-memory, got %d", b.MaxMemoryMiB)
	}
}

func TestDeriveBudgetIgnoresUnusableSettings(t *testing.T) {
	l := Limits{NumCPU: 10, CPUs: 2, MemoryBytes: 1900 << 20}
	want := DeriveBudget(l, -1, nil)
	for name, env := range map[string]map[string]string{
		"not a number":    {EnvJobs: "many", EnvMaxMemoryMiB: "lots", EnvWallSeconds: "soon"},
		"zero jobs":       {EnvJobs: "0"},
		"negative jobs":   {EnvJobs: "-3"},
		"huge jobs":       {EnvJobs: "100000"},
		"tiny memory":     {EnvMaxMemoryMiB: "10"},
		"negative memory": {EnvMaxMemoryMiB: "-1"},
		"tiny wall":       {EnvWallSeconds: "1"},
		"huge wall":       {EnvWallSeconds: "999999"},
		"blank":           {EnvJobs: "  ", EnvWallSeconds: ""},
		"zero scans":      {EnvConcurrency: "0"},
		"huge scans":      {EnvConcurrency: "100000"},
		"scans not a num": {EnvConcurrency: "two"},
	} {
		got := DeriveBudget(l, -1, envOf(env))
		if got.Jobs != want.Jobs || got.MaxMemoryMiB != want.MaxMemoryMiB || got.Wall != want.Wall || len(got.Overridden) != 0 {
			t.Errorf("%s: budget = %+v, want the derived %+v", name, got, want)
		}
	}
}

func TestStageWallLeavesRoomUnderTheRunDeadline(t *testing.T) {
	for _, c := range []struct {
		name            string
		want, remaining time.Duration
		got             time.Duration
	}{
		{"no deadline", 0, -1, DefaultWall},
		{"a hosted scan's 24 minutes", 0, 24 * time.Minute, DefaultWall},
		{"deadline tighter than the default plus the reserve", 0, 200 * time.Second, 200*time.Second - laterStagesReserve},
		{"deadline almost spent", 0, 30 * time.Second, minStageWall},
		{"already past", 0, -0 + 0, minStageWall},
		{"explicit larger", 600 * time.Second, -1, 600 * time.Second},
		{"explicit larger but the deadline wins", 600 * time.Second, 300 * time.Second, 300*time.Second - laterStagesReserve},
	} {
		if got := stageWall(c.want, c.remaining); got != c.got {
			t.Errorf("%s: stageWall = %s, want %s", c.name, got, c.got)
		}
	}
}

func TestBudgetStringNamesEverythingASRECares(t *testing.T) {
	b := DeriveBudget(Limits{NumCPU: 10, CPUs: 2, MemoryBytes: 1900 << 20, Source: "cgroup v2, cpu quota 2.00"}, -1, envOf(map[string]string{EnvJobs: "2"}))
	s := b.String()
	for _, want := range []string{"jobs=2", "max-memory=682MiB", "wall=5m0s", "concurrency=1", "cpu quota 2.00", EnvJobs} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}

func TestSplitBytesFromEnvironment(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int64
	}{
		{"", DefaultSplitBytes}, {"0", DefaultSplitBytes}, {"-1", -1}, {"1048576", 1 << 20},
		{"lots", DefaultSplitBytes}, {"-5", DefaultSplitBytes},
	} {
		if got := splitBytesFromEnv(envOf(map[string]string{EnvSplitBytes: c.raw})); got != c.want {
			t.Errorf("%q: splitBytesFromEnv = %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestChunkBytesFromEnvironment(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int64
	}{
		{"", DefaultChunkBytes}, {"0", DefaultChunkBytes}, {"-1", -1}, {"524288", 512 << 10},
		{"lots", DefaultChunkBytes}, {"-5", DefaultChunkBytes},
	} {
		if got := chunkBytesFromEnv(envOf(map[string]string{EnvChunkBytes: c.raw})); got != c.want {
			t.Errorf("%q: chunkBytesFromEnv = %d, want %d", c.raw, got, c.want)
		}
	}
}
