package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// TestWorkerPool_LargeConcurrentScan_RaceClean is the TASK-097a regression
// test. It drives WorkerPool with 200 endpoints × 3 checks × 16 workers
// against a single httptest server, exercising the same concurrency surface
// the CLI hits when scanning a large API. CI runs `go test -race ./...`, so
// any data race in the pool, scanner clients, or shared findings collection
// fails this test loudly.
//
// We assert:
//
//   - All 600 (endpoints × checks) check invocations occurred.
//   - Findings count matches the deterministic per-call return.
//   - The server received at least one request from every check (proves
//     real HTTP went through the budget transport without hanging).
//   - No goroutine leak (count before vs. after with a grace window).
//
// The actual race-detection assertion is implicit: if the run completes
// without `-race` reporting anything, the pool is clean.
func TestWorkerPool_LargeConcurrentScan_RaceClean(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large concurrent scan in -short mode")
	}

	var serverHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		// Drain to keep keep-alive working — same fix from TASK-090.
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	const (
		endpointCount = 200
		workerCount   = 16
	)

	endpoints := make([]scanner.Endpoint, endpointCount)
	for i := 0; i < endpointCount; i++ {
		path := fmt.Sprintf("/p/%d", i)
		endpoints[i] = scanner.Endpoint{
			Method:  http.MethodGet,
			Path:    path,
			FullURL: srv.URL + path,
		}
	}

	// Three separate atomic counters so we can assert each check was driven
	// the full endpointCount times — pool fairness regression guard.
	var (
		checkACalls atomic.Int64
		checkBCalls atomic.Int64
		checkCCalls atomic.Int64
	)

	// httpCheck issues one real HTTP roundtrip per call. Using a real client
	// (not the scanner globals) is intentional — the goal is to exercise the
	// pool with realistic per-call cost, not to test specific scanner code
	// paths (which already have their own tests).
	client := &http.Client{Timeout: 5 * time.Second}
	httpCheck := func(counter *atomic.Int64, title string) scanner.CheckFn {
		return func(ctx context.Context, _ *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
			counter.Add(1)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.FullURL, nil)
			if err != nil {
				return nil
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return []evidence.Evidence{{
				Title:    title,
				Severity: models.SeverityLow,
				Source:   models.SourceBlackbox,
				Endpoint: ep.FullURL,
			}}
		}
	}
	checks := []scanner.CheckFn{
		httpCheck(&checkACalls, "checkA"),
		httpCheck(&checkBCalls, "checkB"),
		httpCheck(&checkCCalls, "checkC"),
	}

	pool := NewWorkerPool(workerCount, 0, checks)
	cfg := &models.ScanConfig{Timeout: 5}

	beforeGoroutines := runtime.NumGoroutine()

	start := time.Now()
	findings := pool.Run(context.Background(), cfg, endpoints)
	elapsed := time.Since(start)

	expectedCalls := int64(endpointCount * len(checks))
	totalCalls := checkACalls.Load() + checkBCalls.Load() + checkCCalls.Load()
	if totalCalls != expectedCalls {
		t.Errorf("expected %d total check invocations, got %d (a=%d b=%d c=%d)",
			expectedCalls, totalCalls, checkACalls.Load(), checkBCalls.Load(), checkCCalls.Load())
	}
	if checkACalls.Load() != endpointCount ||
		checkBCalls.Load() != endpointCount ||
		checkCCalls.Load() != endpointCount {
		t.Errorf("checks unevenly distributed: a=%d b=%d c=%d (each should be %d)",
			checkACalls.Load(), checkBCalls.Load(), checkCCalls.Load(), endpointCount)
	}

	if int64(len(findings)) != expectedCalls {
		t.Errorf("expected %d findings, got %d", expectedCalls, len(findings))
	}

	if serverHits.Load() < int64(endpointCount) {
		t.Errorf("expected server to receive at least %d hits, got %d",
			endpointCount, serverHits.Load())
	}

	// Goroutine-leak gate: give the pool's reaper goroutine + httptest server
	// connections a moment to settle, force a GC pass, then compare counts.
	// We allow a small tolerance for stragglers from the http transport's
	// idle-connection pool.
	time.Sleep(150 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()
	const goroutineLeakTolerance = 10
	if afterGoroutines > beforeGoroutines+goroutineLeakTolerance {
		t.Errorf("goroutine leak detected: before=%d after=%d (tolerance %d)",
			beforeGoroutines, afterGoroutines, goroutineLeakTolerance)
	}

	// Soft upper-bound on wall time so we notice if the pool ever serializes
	// — a 200-endpoint scan with 16 workers and a localhost server should
	// finish well under 30 seconds even on a slow CI runner.
	if elapsed > 30*time.Second {
		t.Errorf("large scan took %v, expected < 30s — pool may have serialized", elapsed)
	}
}
