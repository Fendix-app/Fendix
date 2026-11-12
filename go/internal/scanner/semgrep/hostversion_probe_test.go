package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R-018: `semgrep --version` asks semgrep.dev for a newer release unless
// SEMGREP_ENABLE_VERSION_CHECK=0 is set; with no route out it waits (98 s
// measured on 1.182.1). The probe must be network-free, bounded, and remembered
// for the binary when it fails, so an offline scan does not pay for it on
// every run, and it must not spend the Semgrep run's own deadline.

// installProbeSemgrep is a stand-in semgrep whose --version line is written to
// calls on every call, and which answers it only when the version check is
// disabled in its environment; otherwise it sleeps, as Semgrep does offline.
// Scans print a clean --time document.
func installProbeSemgrep(t *testing.T, hangAlways bool) (calls string) {
	t.Helper()
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls")
	bin := filepath.Join(dir, "semgrep")
	hang := `[ "$SEMGREP_ENABLE_VERSION_CHECK" = 0 ] || exec sleep 60`
	if hangAlways {
		hang = "exec sleep 60"
	}
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then\n" +
		"  echo \"version check=$SEMGREP_ENABLE_VERSION_CHECK metrics=$SEMGREP_SEND_METRICS\" >> '" + calls + "'\n" +
		"  " + hang + "\n  echo 1.182.1\n  exit 0\nfi\n" +
		"printf '{\"results\":[],\"errors\":[],\"time\":{\"fixpoint_timeouts\":[]}}'\n"
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
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	return calls
}

func probeCalls(t *testing.T, calls string) []string {
	t.Helper()
	raw, err := os.ReadFile(calls)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The probe runs with the version check and metrics off, so a Semgrep that
// would otherwise wait on semgrep.dev answers at once.
func TestVersionProbeIsNetworkFree(t *testing.T) {
	calls := installProbeSemgrep(t, false)
	start := time.Now()
	run, err := ScanRun(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("ScanRun took %s: the version probe waited on the network", took)
	}
	got := probeCalls(t, calls)
	if len(got) != 1 || got[0] != "version check=0 metrics=off" {
		t.Errorf("probe environment = %q; want the version check and metrics off", got)
	}
	if run.Report.Dropped != "" {
		t.Errorf("Report.Dropped = %q; the version was read, nothing is dropped", run.Report.Dropped)
	}
}

// A probe that does not answer is bounded, is remembered for the binary (the
// next scan does not wait again), and leaves every option passed: an unknown
// version is run as a current one, so nothing is dropped silently, and a
// Semgrep that does not know an option fails the run loudly.
func TestVersionProbeThatHangsIsBoundedAndRemembered(t *testing.T) {
	calls := installProbeSemgrep(t, true)
	root := t.TempDir()
	start := time.Now()
	for i := 0; i < 2; i++ {
		run, err := ScanRun(context.Background(), root, nil)
		if err != nil {
			t.Fatalf("ScanRun %d: %v", i, err)
		}
		if run.Report.Dropped != "" {
			t.Errorf("Report.Dropped = %q; an unread version must drop nothing", run.Report.Dropped)
		}
	}
	if took := time.Since(start); took > 15*time.Second {
		t.Errorf("two scans took %s: the probe is not bounded or not remembered", took)
	}
	if got := probeCalls(t, calls); len(got) != 1 {
		t.Errorf("semgrep --version ran %d times, want once: %q", len(got), got)
	}
}

// A probe whose semgrep leaves a child holding stdout open (a wrapper script
// that backgrounds the real binary, say) must still end at its bound: killing
// the process does not close a pipe its child holds, and without
// exec.Cmd.WaitDelay the probe would wait for that child (qa-engine-06, R-018).
func TestVersionProbeIsBoundedWhenAChildHoldsStdout(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "semgrep")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  sleep 30 &\n  wait\n  echo 1.182.1\n  exit 0\nfi\n" +
		"printf '{\"results\":[],\"errors\":[],\"time\":{\"fixpoint_timeouts\":[]}}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	prev := versionProbeTimeout
	versionProbeTimeout = 300 * time.Millisecond
	t.Cleanup(func() { versionProbeTimeout = prev })

	start := time.Now()
	v := semgrepVersionOf(context.Background(), bin)
	took := time.Since(start)
	if v.known {
		t.Errorf("version = %+v; a probe that never answered must be unknown", v)
	}
	// versionProbeTimeout plus WaitDelay (1 s), with slack; the child sleeps 30 s.
	if took > 5*time.Second {
		t.Errorf("probe took %s: it waited on a child holding stdout instead of ending at its bound", took)
	}
	if why := versionProbeProblem(bin); why == "" {
		t.Error("the probe's failure was not remembered")
	}
}
