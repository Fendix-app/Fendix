package engine

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

func TestWorkerPool_RunsAllChecks(t *testing.T) {
	var callCount atomic.Int32
	check1 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return []evidence.Evidence{{Title: "check1", Severity: models.SeverityLow, Source: models.SourceBlackbox}}
	}
	check2 := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return []evidence.Evidence{{Title: "check2", Severity: models.SeverityMedium, Source: models.SourceBlackbox}}
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check1, check2})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
		{Method: "GET", Path: "/b", FullURL: "http://localhost/b"},
		{Method: "GET", Path: "/c", FullURL: "http://localhost/c"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if int(callCount.Load()) != 6 {
		t.Errorf("expected 6 check calls (3 endpoints × 2 checks), got %d", callCount.Load())
	}
	if len(findings) != 6 {
		t.Errorf("expected 6 findings, got %d", len(findings))
	}
}

func TestWorkerPool_RespectsContext(t *testing.T) {
	var callCount atomic.Int32
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		callCount.Add(1)
		return nil
	}

	pool := NewWorkerPool(1, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 100)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/test", FullURL: "http://localhost/test"}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &models.ScanConfig{Timeout: 10}
	pool.Run(ctx, cfg, endpoints)

	if int(callCount.Load()) >= 100 {
		t.Errorf("expected fewer than 100 calls with cancelled context, got %d", callCount.Load())
	}
}

func TestWorkerPool_CollectsFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer server.Close()

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		return []evidence.Evidence{
			{Title: "finding for " + ep.Path, Severity: models.SeverityLow, Source: models.SourceBlackbox},
		}
	}

	pool := NewWorkerPool(3, 0, []scanner.CheckFn{check})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: server.URL + "/a"},
		{Method: "GET", Path: "/b", FullURL: server.URL + "/b"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestWorkerPool_EmptyChecks(t *testing.T) {
	pool := NewWorkerPool(2, 0, nil)
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no checks, got %d", len(findings))
	}
}

func TestWorkerPool_EmptyEndpoints(t *testing.T) {
	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		return []evidence.Evidence{{Title: "should not appear"}}
	}

	pool := NewWorkerPool(2, 0, []scanner.CheckFn{check})
	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, nil)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no endpoints, got %d", len(findings))
	}
}

// TestWorkerPool_PanicIsContained pins the per-job recover() contract: a
// check that panics on one endpoint must NOT abort the scan. The panicking
// job is recorded as a synthetic INFO finding ("Scanner check panicked") and
// every other job still runs to completion.
func TestWorkerPool_PanicIsContained(t *testing.T) {
	var goodCalls atomic.Int32
	good := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		goodCalls.Add(1)
		return []evidence.Evidence{{Title: "ok " + ep.Path, Severity: models.SeverityLow, Source: models.SourceBlackbox}}
	}
	boom := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		panic("synthetic check failure on " + ep.Path)
	}

	// Single worker so the panicking job and the good jobs share the same
	// goroutine — proves recover() lets the worker survive and keep pulling.
	pool := NewWorkerPool(1, 0, []scanner.CheckFn{boom, good})
	endpoints := []scanner.Endpoint{
		{Method: "GET", Path: "/a", FullURL: "http://localhost/a"},
		{Method: "GET", Path: "/b", FullURL: "http://localhost/b"},
		{Method: "GET", Path: "/c", FullURL: "http://localhost/c"},
	}

	cfg := &models.ScanConfig{Timeout: 10}
	findings := pool.Run(context.Background(), cfg, endpoints)

	// The good check must have run on all 3 endpoints despite the panics.
	if got := goodCalls.Load(); got != 3 {
		t.Errorf("expected good check to run on all 3 endpoints, got %d (panic aborted other jobs?)", got)
	}

	var ok, panicked int
	for _, f := range findings {
		switch f.Title {
		case "Scanner check panicked":
			panicked++
			if f.Severity != models.SeverityInfo {
				t.Errorf("panic note should be INFO severity, got %s", f.Severity)
			}
			if f.Category != "engine" {
				t.Errorf("panic note should have category 'engine', got %q", f.Category)
			}
			if f.Endpoint == "" {
				t.Errorf("panic note should record the endpoint, got empty")
			}
		default:
			ok++
		}
	}
	if ok != 3 {
		t.Errorf("expected 3 good findings, got %d", ok)
	}
	if panicked != 3 {
		t.Errorf("expected 3 synthetic panic notes (one per endpoint), got %d", panicked)
	}
}

func TestWorkerPool_SingleWorker(t *testing.T) {
	var maxConcurrent atomic.Int32
	var current atomic.Int32

	check := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence {
		c := current.Add(1)
		if c > maxConcurrent.Load() {
			maxConcurrent.Store(c)
		}
		current.Add(-1)
		return nil
	}

	pool := NewWorkerPool(1, 0, []scanner.CheckFn{check})
	endpoints := make([]scanner.Endpoint, 10)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/test", FullURL: "http://localhost/test"}
	}

	cfg := &models.ScanConfig{Timeout: 10}
	pool.Run(context.Background(), cfg, endpoints)

	if maxConcurrent.Load() > 1 {
		t.Errorf("with 1 worker, max concurrency should be 1, got %d", maxConcurrent.Load())
	}
}

// TestWorkerPool_EmitsProgress covers the gap that made the UI progress bar
// look frozen: the pool used to log exactly once, at the end, so a scan sat at
// the "scanning endpoints" checkpoint (35%) for the whole endpoint sweep —
// which on an active-probing hybrid scan is the majority of its runtime.
//
// The pool now reports completions as it goes. The backend interpolates these
// into the band between "scanning endpoints" and "worker pool complete".
func TestWorkerPool_EmitsProgress(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	prev := slog.Default()
	// The pool logs from every worker goroutine, so the test sink must be
	// safe for concurrent writes.
	slog.SetDefault(slog.New(slog.NewTextHandler(&syncWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(prev)

	noop := func(ctx context.Context, cfg *models.ScanConfig, ep scanner.Endpoint) []evidence.Evidence { return nil }
	pool := NewWorkerPool(4, 0, []scanner.CheckFn{noop, noop})
	endpoints := make([]scanner.Endpoint, 50)
	for i := range endpoints {
		endpoints[i] = scanner.Endpoint{Method: "GET", Path: "/x", FullURL: "http://localhost/x"}
	}

	pool.Run(context.Background(), &models.ScanConfig{Timeout: 10}, endpoints)

	mu.Lock()
	out := buf.String()
	mu.Unlock()

	if !strings.Contains(out, "worker pool progress") {
		t.Fatalf("the pool must report progress during the sweep, got:\n%s", out)
	}
	// Every line must carry the totals the backend needs to interpolate.
	re := regexp.MustCompile(`worker pool progress.*?done=(\d+).*?total=(\d+)`)
	matches := re.FindAllStringSubmatch(out, -1)
	if len(matches) == 0 {
		t.Fatalf("progress lines must carry done= and total=, got:\n%s", out)
	}
	total := 50 * 2
	for _, m := range matches {
		if m[2] != strconv.Itoa(total) {
			t.Errorf("total=%s, want %d (endpoints × checks)", m[2], total)
		}
	}
	// Bounded: one line per 5% of the sweep, so a 5,000-unit scan logs ~20
	// lines rather than 5,000. Noise here becomes a DB write per line.
	if len(matches) > 25 {
		t.Errorf("progress must be throttled, got %d lines", len(matches))
	}
	// Deliberately NOT asserting the lines arrive in ascending order: workers
	// log concurrently, so a higher `done` can reach the handler first. That
	// is harmless because the consumer clamps progress monotonically
	// (services._apply_progress ignores a percentage <= the one it holds), so
	// requiring ordered output here would test a guarantee the pool does not
	// make and does not need.
	//
	// What must hold is that the sweep is reported as finished: the final unit
	// always logs, so the highest `done` equals the total.
	high := 0
	for _, m := range matches {
		done, _ := strconv.Atoi(m[1])
		if done > high {
			high = done
		}
		if done < 1 || done > total {
			t.Errorf("done=%d out of range 1..%d", done, total)
		}
	}
	if high != total {
		t.Errorf("the sweep never reported completion: highest done=%d, want %d", high, total)
	}
}

// syncWriter serializes writes from the pool's worker goroutines so the test
// sink cannot interleave partial lines.
type syncWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
