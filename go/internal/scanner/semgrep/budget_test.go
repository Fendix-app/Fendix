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

func TestMaxMemoryForLeavesRoomBesideSemgrepCore(t *testing.T) {
	for _, c := range []struct {
		memMiB, want int
	}{
		{0, 0},                        // unknown: no limit is invented
		{1900, 1364},                  // the concurrency-1 share of the 3.8 GB host
		{3800, 3074},                  // the whole host
		{600, minMaxMemoryMiB},        // too small to hold a pack: floor, never unbounded
		{384, minMaxMemoryMiB},        // nothing left after the reservation
		{512, minMaxMemoryMiB},        // (512-384)*0.9 = 115, floored
		{2048, (2048 - 384) * 9 / 10}, //
	} {
		if got := maxMemoryFor(c.memMiB); got != c.want {
			t.Errorf("maxMemoryFor(%d) = %d, want %d", c.memMiB, got, c.want)
		}
	}
}

func TestMemoryBudgetUsesTheCgroupLimitElseHalfTheHost(t *testing.T) {
	const gib = int64(1) << 30
	for _, c := range []struct {
		name string
		l    Limits
		want int
	}{
		{"cgroup limit", Limits{MemoryBytes: 2 * gib, HostMemoryBytes: 8 * gib}, 2048},
		{"cgroup limit above the host", Limits{MemoryBytes: 16 * gib, HostMemoryBytes: 4 * gib}, 4096},
		{"no limit: half of a 3.8 GB host", Limits{HostMemoryBytes: 3800 << 20}, 1900},
		{"nothing known", Limits{}, 0},
	} {
		if got := memoryBudgetMiB(c.l); got != c.want {
			t.Errorf("%s: memoryBudgetMiB = %d, want %d", c.name, got, c.want)
		}
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
	if b.Jobs != 2 || b.MaxMemoryMiB != 1364 || b.Wall != DefaultWall {
		t.Errorf("budget = %+v, want jobs 2, max-memory 1364, wall %s", b, DefaultWall)
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
	// No quota: the process's own CPU count; no memory limit: half the host.
	if b.Jobs != 3 {
		t.Errorf("jobs = %d, want 3 for 4 CPUs", b.Jobs)
	}
	if b.MemoryMiB != 1900 || b.MaxMemoryMiB != 1364 {
		t.Errorf("memory = %d / max-memory %d, want 1900 / 1364", b.MemoryMiB, b.MaxMemoryMiB)
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
	if b.Jobs != 5 || b.MaxMemoryMiB != 0 {
		t.Errorf("budget = %+v: jobs from the CPU count, and no --max-memory when memory is unknown", b)
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
	for _, want := range []string{"jobs=2", "max-memory=1364MiB", "wall=5m0s", "cpu quota 2.00", EnvJobs} {
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
