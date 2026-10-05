package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// quietSlog raises the slog log level to Error for the duration of one
// benchmark, then restores the previous default. The orchestrator and worker
// pool emit Info-level lines on every iteration, which (a) skews the
// benchmark numbers with stderr-write overhead and (b) drowns the
// benchmark's own output. Each benchmark calls this in its setup phase.
func quietSlog(b *testing.B) {
	b.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	b.Cleanup(func() { slog.SetDefault(prev) })
	_ = os.Stderr // keep the import from going unused if the handler ever changes
}

// scanBenchSizes are the endpoint counts the suite reports against.
// Picked to bracket what an external evaluator is likely to throw at fendix:
//   - 10:    smoke / single API
//   - 100:   typical microservice
//   - 500:   medium API surface
//   - 1000:  large API
var scanBenchSizes = []int{10, 100, 500, 1000}

// benchHTTPCheck returns a scanner.CheckFn that issues one real HTTP roundtrip
// per call. Same shape as the workerpool large-scale test — but here we
// expose it for the benchmark suite to reuse across sizes.
func benchHTTPCheck(client *http.Client, counter *atomic.Int64, title string) scanner.CheckFn {
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

// benchScanFixture builds N endpoints pointing at one local httptest server.
// Returns the server (caller must close), the endpoint slice, and the three
// per-check counters we use to assert pool fairness in the test analogue.
func benchScanFixture(b interface {
	Helper()
	Cleanup(func())
}, n int) (*http.Client, []scanner.Endpoint, []*atomic.Int64) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	b.Cleanup(func() { srv.Close() })

	endpoints := make([]scanner.Endpoint, n)
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("/p/%d", i)
		endpoints[i] = scanner.Endpoint{
			Method:  http.MethodGet,
			Path:    path,
			FullURL: srv.URL + path,
		}
	}

	// Default http.Transport caps MaxIdleConnsPerHost at 2 — under a 32-worker
	// pool that's an immediate bottleneck and makes the benchmark numbers
	// reflect connection-pool churn rather than pool / scheduler cost. Bump
	// the limit so the loopback transport can actually serve the workers.
	transport := &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport}
	counters := []*atomic.Int64{new(atomic.Int64), new(atomic.Int64), new(atomic.Int64)}
	return client, endpoints, counters
}

// BenchmarkScan_Throughput measures end-to-end scan time as a function of
// endpoint count, with a fixed worker pool of 32 and 3 checks per endpoint.
// Each iteration does endpointCount × 3 real HTTP roundtrips against a local
// httptest server, so the cost is dominated by goroutine scheduling + the
// loopback transport's per-request overhead.
//
// Run:
//
//	make bench
//
// or directly:
//
//	go -C go test -bench BenchmarkScan_Throughput -benchmem ./internal/engine/
//
// The reported ns/op divided by (3 × N) gives the per-roundtrip cost; the
// total wall-clock per scan is ns/op × b.N.
func BenchmarkScan_Throughput(b *testing.B) {
	for _, n := range scanBenchSizes {
		b.Run(fmt.Sprintf("endpoints=%d", n), func(b *testing.B) {
			quietSlog(b)
			client, endpoints, counters := benchScanFixture(b, n)
			checks := []scanner.CheckFn{
				benchHTTPCheck(client, counters[0], "checkA"),
				benchHTTPCheck(client, counters[1], "checkB"),
				benchHTTPCheck(client, counters[2], "checkC"),
			}
			cfg := &models.ScanConfig{Timeout: 5}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pool := NewWorkerPool(32, 0, checks)
				_ = pool.Run(context.Background(), cfg, endpoints)
			}
		})
	}
}

// BenchmarkScan_Goroutines measures peak goroutine count during a scan.
// Goroutines aren't a benchmark metric in the usual sense — but the
// concurrency-correctness story is "the pool clamps to --workers", so we
// want a published number proving that's the case under load.
//
// Reports peak via b.ReportMetric (custom metric in benchstat output).
func BenchmarkScan_Goroutines(b *testing.B) {
	for _, n := range scanBenchSizes {
		b.Run(fmt.Sprintf("endpoints=%d", n), func(b *testing.B) {
			quietSlog(b)
			client, endpoints, counters := benchScanFixture(b, n)
			checks := []scanner.CheckFn{
				benchHTTPCheck(client, counters[0], "checkA"),
				benchHTTPCheck(client, counters[1], "checkB"),
				benchHTTPCheck(client, counters[2], "checkC"),
			}
			cfg := &models.ScanConfig{Timeout: 5}

			var peakGoroutines atomic.Int64
			done := make(chan struct{})
			defer close(done)
			go func() {
				ticker := time.NewTicker(2 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-done:
						return
					case <-ticker.C:
						g := int64(runtime.NumGoroutine())
						for {
							cur := peakGoroutines.Load()
							if g <= cur {
								break
							}
							if peakGoroutines.CompareAndSwap(cur, g) {
								break
							}
						}
					}
				}
			}()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pool := NewWorkerPool(32, 0, checks)
				_ = pool.Run(context.Background(), cfg, endpoints)
			}
			b.StopTimer()

			b.ReportMetric(float64(peakGoroutines.Load()), "peak-goroutines")
		})
	}
}

// BenchmarkScan_Memory reports allocated bytes during a scan via -benchmem.
// The B/op figure scales with endpoint count; the published numbers in the
// README come from this benchmark.
func BenchmarkScan_Memory(b *testing.B) {
	for _, n := range scanBenchSizes {
		b.Run(fmt.Sprintf("endpoints=%d", n), func(b *testing.B) {
			quietSlog(b)
			client, endpoints, counters := benchScanFixture(b, n)
			checks := []scanner.CheckFn{
				benchHTTPCheck(client, counters[0], "checkA"),
				benchHTTPCheck(client, counters[1], "checkB"),
				benchHTTPCheck(client, counters[2], "checkC"),
			}
			cfg := &models.ScanConfig{Timeout: 5}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				pool := NewWorkerPool(32, 0, checks)
				_ = pool.Run(context.Background(), cfg, endpoints)
			}
		})
	}
}
