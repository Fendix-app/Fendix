package regression

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/metrics"
	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// TestScanPerformance guards against gross performance regressions on a
// trivial fixture: a --fast code scan must finish well under 30s and use
// under 500MB. Memory is read from the metrics the scan itself records
// (FENDIX_METRICS), which is exactly the peak HeapAlloc at scan end.
func TestScanPerformance(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	fixture := "../fixtures/simple-go-project"

	start := time.Now()
	_, _, exit := harness.RunEnv(t,
		[]string{"FENDIX_METRICS=true", "FENDIX_METRICS_PATH=" + logPath},
		"scan", "--code", fixture, "--fast", "--format", "json", "--output", filepath.Join(dir, "out.json"),
	)
	elapsed := time.Since(start)
	if exit != 0 {
		t.Fatalf("scan exit = %d, want 0", exit)
	}

	const maxDuration = 30 * time.Second
	if elapsed > maxDuration {
		t.Errorf("scan took %s, want < %s (performance regression)", elapsed, maxDuration)
	}

	events, err := metrics.LoadEvents(logPath)
	if err != nil {
		t.Fatalf("loading metrics: %v", err)
	}
	if len(events) == 0 {
		t.Skip("no metric event recorded (FENDIX_METRICS_PATH may be unsupported); duration check still applied")
	}
	const maxMemMB = 500.0
	for _, e := range events {
		if e.MemoryMB > maxMemMB {
			t.Errorf("scan peak memory %.0fMB, want < %.0fMB (memory regression)", e.MemoryMB, maxMemMB)
		}
	}
}
