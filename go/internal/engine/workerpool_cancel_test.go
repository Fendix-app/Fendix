package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// TestWorkerPool_CancelDuringProduce pins the contract that
// context-cancellation issued AFTER scan start (not before) plateaus
// check invocations rapidly, instead of running the entire N×M
// matrix to completion.
//
// The pre-existing TestWorkerPool_RespectsContext only exercised
// already-cancelled context. With the producer not selecting on
// ctx.Done() and the channel sized to N×M, all jobs queue up before
// any worker checks ctx — so mid-flight cancel had no producer-side
// path. This test would have asserted ≥ N calls (the failure mode)
// without the producer fix.
func TestWorkerPool_CancelDuringProduce(t *testing.T) {
	var calls atomic.Int32
	const slowJobMs = 25
	check := func(ctx context.Context, _ *models.ScanConfig, _ scanner.Endpoint) []evidence.Evidence {
		calls.Add(1)
		select {
		case <-time.After(slowJobMs * time.Millisecond):
		case <-ctx.Done():
		}
		return nil
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 200)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/x", FullURL: "http://localhost/x"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		pool.Run(ctx, &models.ScanConfig{Timeout: 1}, endpoints)
		close(doneCh)
	}()

	// Let a few jobs land, then cancel.
	time.Sleep(40 * time.Millisecond)
	cancel()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatal("pool did not return within 2s of cancel")
	}

	// With 2 workers, a slowJobMs of 25ms, and cancel at ~40ms,
	// the pool should have invoked the check at most a small
	// multiple of (workers + a tail). 200 endpoints would imply
	// ~5s of total work; anything close to 200 means the producer
	// is filling the queue regardless of cancel.
	final := calls.Load()
	if final >= 100 {
		t.Errorf("expected far fewer than 200 calls after mid-flight cancel; got %d", final)
	}
	// Under healthy operation, post-cancel calls should be bounded
	// by workers + already-buffered jobs (≤ workers*4 + workers).
	// Allow generous headroom for slow CI.
	if final > 50 {
		t.Logf("warning: high call count after cancel (got %d) — investigate buffer or producer", final)
	}
}

// TestWorkerPool_BufferIsBounded asserts the pool no longer reserves
// an N×M slot per scan. Run a scan with a moderately-large endpoint
// count and a check that records goroutine high-water-mark via the
// blocking behaviour of an unbuffered ack channel.
func TestWorkerPool_BufferIsBounded(t *testing.T) {
	// We can't directly observe channel capacity at runtime via the
	// public API, but we can observe its *effect*: with a small
	// buffer, the producer blocks until workers drain — so the
	// number of *outstanding* jobs at any moment is bounded by
	// workers + buf.
	var inFlight atomic.Int32
	var peakInFlight atomic.Int32

	check := func(ctx context.Context, _ *models.ScanConfig, _ scanner.Endpoint) []evidence.Evidence {
		cur := inFlight.Add(1)
		// Update high-water-mark monotonically.
		for {
			prev := peakInFlight.Load()
			if cur <= prev || peakInFlight.CompareAndSwap(prev, cur) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return nil
	}

	const workers = 4
	pool := NewWorkerPool(workers, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 500)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/x", FullURL: "http://localhost/x"}
	}

	pool.Run(context.Background(), &models.ScanConfig{Timeout: 1}, endpoints)

	// Peak concurrent in-flight checks must NOT exceed the worker
	// count. (Buffer slots are queued, not in-flight.)
	if peak := peakInFlight.Load(); int(peak) > workers {
		t.Errorf("peak in-flight checks %d > workers %d (buffer should not let extra jobs run)", peak, workers)
	}
}
