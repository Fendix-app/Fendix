//go:build linux

package semgrep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Round 6, WS-E3 (R6-P2). Under memory pressure the kernel's OOM killer picks
// the process with the highest badness: resident memory plus oom_score_adj.
// Nothing sets oom_score_adj today, so the victim is simply the largest
// process. When the engine (or the Celery worker that runs it) is larger than
// the Semgrep child at that moment, the engine dies, no report is written, and
// the scan is failed only by the backend's orphan sweep, long after. When
// Semgrep is the victim, the engine records semgrep failed and still writes
// the report. These tests require that every Semgrep child is the preferred
// victim.

// wse3OOMScoreAdj reads the oom_score_adj of a process ("self" or a pid).
func wse3OOMScoreAdj(t *testing.T, pid string) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + pid + "/oom_score_adj")
	if err != nil {
		t.Fatalf("read oom_score_adj of %s: %v", pid, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse oom_score_adj of %s: %q", pid, raw)
	}
	return v
}

// wse3VictimMargin is how much higher than the engine's own oom_score_adj every
// Semgrep child must run: half the badness scale, so the child outranks an
// engine holding up to half the machine's memory more than it does.
const wse3VictimMargin = 500

// wse3EngineScoreBeforeScan reads the test process's oom_score_adj before a scan
// and fails when it leaves no room for the margin: a parent at 500 or more
// cannot have a child 500 above it, and a test that passed there would prove
// nothing.
func wse3EngineScoreBeforeScan(t *testing.T) int {
	t.Helper()
	parent := wse3OOMScoreAdj(t, "self")
	if parent+wse3VictimMargin > 1000 {
		t.Fatalf("the test process already runs at oom_score_adj %d; run it at 500 or less so a child can be %d above it", parent, wse3VictimMargin)
	}
	return parent
}

// wse3EngineScoreUnchanged fails when the scan changed the engine's own score: the
// engine making itself a likelier victim (or raising its score so a child
// inherits it) is not the fix, it is the defect in another form.
func wse3EngineScoreUnchanged(t *testing.T, before int) {
	t.Helper()
	if after := wse3OOMScoreAdj(t, "self"); after != before {
		t.Errorf("the scan changed the engine's own oom_score_adj from %d to %d; only its Semgrep children may be raised", before, after)
	}
}

// wse3InstallRecordingSemgrep installs a fake semgrep that appends its own
// oom_score_adj to the returned file on every invocation, then replays a
// recorded clean run.
//
// Ruling (OR-61): the child's score must be in place before Semgrep begins
// executing, that is, set pre-exec (in the forked child before exec, or by a
// wrapper that sets it and then execs Semgrep). Raising it afterwards, by
// writing /proc/<pid>/oom_score_adj once the process has started, leaves a
// window in which Semgrep runs, and can be killed or kill, at the engine's
// score. So the fake reads its score as its very first command, with no delay
// before it, and a score raised after start is read as the old value.
func wse3InstallRecordingSemgrep(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	marks := filepath.Join(dir, "oom_score_adj")
	clean, err := filepath.Abs(filepath.Join("testdata", "runs", "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(clean); err != nil {
		t.Fatalf("recorded clean run: %v", err)
	}
	bin := filepath.Join(dir, "semgrep")
	script := "#!/bin/sh\ncat /proc/self/oom_score_adj >> '" + marks + "'\n" +
		"case \"$1\" in --version) echo 1.182.1; exit 0;; esac\n" +
		"cat '" + clean + "'\nexit 0\n"
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
	return marks
}

func TestSemgrepChildIsThePreferredOOMVictim(t *testing.T) {
	marks := wse3InstallRecordingSemgrep(t)
	parent := wse3EngineScoreBeforeScan(t)
	if _, _, err := ScanWithReport(context.Background(), t.TempDir(), nil); err != nil {
		t.Fatalf("a recorded clean run must scan cleanly: %v", err)
	}
	wse3EngineScoreUnchanged(t, parent)
	raw, err := os.ReadFile(marks)
	if err != nil {
		t.Fatalf("the fake semgrep never ran: %v", err)
	}
	want := parent + wse3VictimMargin
	lines := strings.Fields(string(raw))
	if len(lines) == 0 {
		t.Fatal("the fake semgrep recorded nothing")
	}
	for i, l := range lines {
		got, err := strconv.Atoi(l)
		if err != nil {
			t.Fatalf("invocation %d recorded %q", i, l)
		}
		if got < want {
			t.Errorf("semgrep invocation %d ran with oom_score_adj %d while the engine had %d before the scan; "+
				"want at least %d so the OOM killer takes Semgrep, not the engine", i, got, parent, want)
		}
	}
}

// TestSemgrepIsKilledInsteadOfTheEngineUnderASqueeze reproduces the squeeze
// itself. The test process plays an engine that holds more memory than its
// Semgrep child (a 230 MiB balloon); the fake semgrep then grows until the
// cgroup runs out. Without a preferred victim the kernel kills the larger
// process, this test binary, and nothing is returned: the run ends in
// "signal: killed". With one, Semgrep dies, the engine survives, and the scan
// returns ErrFatal naming the kill, from which the orchestrator records semgrep
// failed and writes the report.
//
// It needs a bounded memory cgroup and runs only when asked:
//
//	FENDIX_OOM_SQUEEZE=1, inside e.g. docker run --memory=400m --memory-swap=400m
func TestSemgrepIsKilledInsteadOfTheEngineUnderASqueeze(t *testing.T) {
	if os.Getenv("FENDIX_OOM_SQUEEZE") != "1" {
		t.Skip("set FENDIX_OOM_SQUEEZE=1 and run in a memory cgroup of at most 1 GiB")
	}
	raw, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		t.Skipf("no cgroup v2 memory limit to squeeze against: %v", err)
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || limit > 1<<30 {
		t.Skipf("memory.max is %q; the squeeze needs a bounded cgroup of at most 1 GiB", strings.TrimSpace(string(raw)))
	}
	const balloonMiB = 230
	if limit < (balloonMiB+120)<<20 {
		t.Skipf("memory.max %d is too small for a %d MiB engine and a growing child", limit, balloonMiB)
	}

	// The engine's own memory: touched, so it is resident.
	balloon := make([]byte, balloonMiB<<20)
	for i := 0; i < len(balloon); i += 4096 {
		balloon[i] = 1
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "semgrep")
	// Grow by touched 16 MiB blocks until the cgroup runs out.
	script := "#!/bin/sh\ncase \"$1\" in --version) echo 1.182.1; exit 0;; esac\n" +
		"exec python3 -c 'b=[]\nwhile True: b.append(b\"x\" * (16 << 20))'\n"
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

	parent := wse3EngineScoreBeforeScan(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _, err = ScanWithReport(ctx, t.TempDir(), nil)
	runtime.KeepAlive(balloon)
	wse3EngineScoreUnchanged(t, parent)

	// Reaching this line already means the engine survived.
	if !errors.Is(err, ErrFatal) || !strings.Contains(err.Error(), "killed") {
		t.Fatalf("Semgrep killed by the OOM killer must be a fatal, named error; got %v", err)
	}
}
