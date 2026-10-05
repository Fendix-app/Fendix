package engine

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// FuzzWorkerPool_CancelTiming is the TASK-097b fuzz test for the
// WorkerPool's cancellation path. The fuzzer drives the pool with
// randomized (worker count, endpoint count, cancel-delay) tuples and
// asserts:
//
//  1. Run always returns (no deadlock under any cancel timing).
//  2. No panic from a nil/closed-channel race when cancel races with
//     job dispatch or with the reaper goroutine.
//  3. No goroutine leak after each iteration (workers must drain on
//     ctx cancel, not block on the jobs/results channels).
//
// The fuzzer is bounded so a single iteration can't run away — endpoint
// count and worker count are clamped to small values, and the cancel
// delay is capped at a few milliseconds. With those bounds an iteration
// completes in well under a second, which is appropriate for native
// `go test -fuzz` runs.
//
// Seed corpus exercises the boundary cases that historically broke
// hand-written cancel logic: cancel-before-start (delay 0), cancel after
// every worker is parked on the jobs channel, cancel right at job
// dispatch close, and the no-cancel control case (delay larger than the
// scan would ever take).
func FuzzWorkerPool_CancelTiming(f *testing.F) {
	// Seeds: workers, endpoints, cancelDelayMicros, checkBusyMicros.
	f.Add(uint8(1), uint8(1), uint16(0), uint16(0))   // cancel before run
	f.Add(uint8(4), uint8(64), uint16(50), uint16(5)) // cancel mid-flight
	f.Add(uint8(8), uint8(8), uint16(500), uint16(0)) // cancel after expected completion
	f.Add(uint8(1), uint8(0), uint16(100), uint16(0)) // zero endpoints — should be a no-op
	f.Add(uint8(0), uint8(4), uint16(10), uint16(1))  // workers=0 → clamped to 1 by NewWorkerPool
	f.Add(uint8(16), uint8(32), uint16(1), uint16(1)) // tight cancel race

	f.Fuzz(func(t *testing.T, workersRaw, endpointsRaw uint8, cancelDelayMicros, busyMicros uint16) {
		// Bound inputs so the test runtime stays predictable per iteration.
		workers := int(workersRaw % 32) // 0..31; pool clamps 0 → 1
		endpoints := int(endpointsRaw)  // 0..255 endpoints
		cancelDelay := time.Duration(cancelDelayMicros%5000) * time.Microsecond
		busy := time.Duration(busyMicros%200) * time.Microsecond

		var calls atomic.Int64
		check := func(ctx context.Context, _ *models.ScanConfig, _ scanner.Endpoint) []evidence.Evidence {
			calls.Add(1)
			if busy > 0 {
				// Yield-ish wait that respects ctx — same shape a real check
				// has on its sleep/timeout paths.
				select {
				case <-ctx.Done():
				case <-time.After(busy):
				}
			}
			return nil
		}

		eps := make([]scanner.Endpoint, endpoints)
		for i := range eps {
			eps[i] = scanner.Endpoint{
				Method:  "GET",
				Path:    "/x",
				FullURL: "http://127.0.0.1:1/x", // never actually hit
			}
		}

		pool := NewWorkerPool(workers, 0, []scanner.CheckFn{check})
		cfg := &models.ScanConfig{Timeout: 1}

		ctx, cancel := context.WithCancel(context.Background())

		// Schedule cancel at the fuzz-supplied delay. We always call cancel
		// to release ctx resources — the deferred call here covers the
		// fast-path where Run returned before the timer fired.
		t.Cleanup(cancel)
		go func() {
			if cancelDelay == 0 {
				cancel()
				return
			}
			time.Sleep(cancelDelay)
			cancel()
		}()

		beforeGoroutines := runtime.NumGoroutine()

		// Wrap Run in a deadline so a hung pool fails the iteration loudly
		// instead of timing out the whole fuzz run.
		done := make(chan struct{})
		var findings []models.Finding
		go func() {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("WorkerPool.Run panicked: %v", r)
				}
			}()
			findings = pool.Run(ctx, cfg, eps)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("WorkerPool.Run hung after 5s (workers=%d endpoints=%d cancelDelay=%v busy=%v)",
				workers, endpoints, cancelDelay, busy)
		}

		// findings is allocated lazily by Run; nil is valid for any-cancel-fast
		// or zero-endpoint cases. Just sanity-check we got back something
		// referenceable (the runtime must have completed without panic).
		_ = findings

		// Calls must be in [0, endpoints]: the pool may exit early on cancel,
		// and never re-runs a check.
		got := calls.Load()
		if got > int64(endpoints) {
			t.Errorf("check called %d times, expected at most %d (workers=%d cancelDelay=%v)",
				got, endpoints, workers, cancelDelay)
		}

		// Goroutine-leak gate. We wait for stragglers (cancel-mid-dispatch
		// can leave a worker mid-`time.Sleep`) and then compare. Use a
		// tolerance because the fuzz harness itself can spawn helper
		// goroutines between iterations.
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		afterGoroutines := runtime.NumGoroutine()
		const tolerance = 4
		if afterGoroutines > beforeGoroutines+tolerance {
			t.Errorf("goroutine leak: before=%d after=%d (tolerance %d, workers=%d endpoints=%d cancelDelay=%v)",
				beforeGoroutines, afterGoroutines, tolerance, workers, endpoints, cancelDelay)
		}
	})
}
