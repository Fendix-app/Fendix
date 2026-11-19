package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// C4B-09 neighbour (round 6, OR-78 B2). The SSRF timing-differential signal
// takes its baseline from measureBaseline, which counts only the target's time
// (the retry pauses probeDo took are the engine's). Its canary samples must be
// measured the same way: with raw elapsed a target that only rate-limits (429
// with Retry-After: 5 on the first attempt of every request) has a baseline of
// about 0 s and a canary of about 5 s, which reads as a server-side fetch that
// blocks, and every endpoint behind a limiter gets "SSRF - timing
// differential". What must hold: the engine's own waiting never counts, on
// either side of the comparison, and a real block of the canary fetch is still
// reported through a limiter.

// wse3SSRFCanaryIn reports whether a request carries the unroutable canary URL
// ssrfTimingProbe sends.
func wse3SSRFCanaryIn(r *http.Request) bool {
	return strings.Contains(r.URL.RawQuery, "fendix-ssrf-timing-")
}

// wse3SSRFTarget answers every second request with 429 and Retry-After: 5 when
// limited, and sleeps hang on a request that carries the canary when it serves
// one (a server-side fetch that blocks).
type wse3SSRFTarget struct {
	limited bool
	hang    time.Duration
	n       atomic.Int32
}

func (s *wse3SSRFTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.limited && s.n.Add(1)%2 == 1 {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if s.hang > 0 && wse3SSRFCanaryIn(r) {
		time.Sleep(s.hang)
	}
	w.WriteHeader(http.StatusOK)
}

func wse3RunSSRFTiming(t *testing.T, h http.Handler) (found bool, took time.Duration, audit *ProbeAuditLog) {
	t.Helper()
	wse3ResetBudget(t)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	cfg := &models.ScanConfig{EnableActive: true, Timeout: 60}
	audit = NewProbeAuditLog()
	cc := &CheckContext{
		Cfg:      cfg,
		Client:   &http.Client{Timeout: 60 * time.Second},
		NoFollow: &http.Client{Timeout: 60 * time.Second},
		Audit:    audit,
	}
	ep := Endpoint{Method: "GET", Path: "/fetch", FullURL: ts.URL + "/fetch", Params: []string{"url"}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	e, ok := ssrfTimingProbe(ctx, cc, ep, "url", LocQuery)
	if ok && e.RuleID != "ssrf/timing-differential" {
		t.Fatalf("unexpected rule %q", e.RuleID)
	}
	return ok, time.Since(start), audit
}

func TestSSRFTiming_RateLimitedTargetIsNotATimingDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for real Retry-After pauses in -short mode")
	}
	found, took, audit := wse3RunSSRFTiming(t, &wse3SSRFTarget{limited: true})
	if found {
		t.Errorf("a target that only rate-limits (429, Retry-After 5, no delay on the canary) gave an SSRF timing "+
			"differential after %s (retries %d): the engine's own retry wait is not the target's fetch delay",
			took.Round(time.Second), audit.RetriesSpent())
	}
	if audit.RetriesSpent() == 0 {
		t.Errorf("the limiter never made probeDo retry, so the case does not exercise the wait")
	}
}

func TestSSRFTiming_RealBlockBehindALimiterIsStillReported(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for real 5 s delays in -short mode")
	}
	found, took, audit := wse3RunSSRFTiming(t, &wse3SSRFTarget{limited: true, hang: 5 * time.Second})
	if !found {
		t.Errorf("a server-side fetch that blocks 5 s on the canary, behind a limiter, gave no SSRF timing differential "+
			"after %s (retries %d): the target's delay must still count", took.Round(time.Second), audit.RetriesSpent())
	}
}

func TestSSRFTiming_RealBlockWithNoLimiterIsReported(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for real 5 s delays in -short mode")
	}
	if found, took, _ := wse3RunSSRFTiming(t, &wse3SSRFTarget{hang: 5 * time.Second}); !found {
		t.Errorf("a server-side fetch that blocks 5 s on the canary gave no SSRF timing differential after %s", took.Round(time.Second))
	}
}

func TestSSRFTiming_QuietTargetIsNotATimingDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("kept with the limiter cases in -short mode")
	}
	if found, took, _ := wse3RunSSRFTiming(t, &wse3SSRFTarget{}); found {
		t.Errorf("a target with no limiter and no delay gave an SSRF timing differential after %s", took.Round(time.Second))
	}
}
