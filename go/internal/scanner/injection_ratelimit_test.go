package scanner

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/budget"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// C4B-09 (Round 4b, redteam4b-03; open in Round 5) and its neighbours.
//
// probeSQLi times each payload, and the timing baseline, around probeDo, and
// probeDo sleeps for the retry backoff (1 s, then 2 s) or the target's
// Retry-After (capped at 5 s) before it re-sends a 429/502/503/504. The time
// the engine spent waiting is the engine's, not the target's:
//
//   - a target that only rate-limits looks like one that slept on the payload,
//     so every endpoint behind a limiter gets "Potential SQL Injection
//     (time-based)";
//   - a limiter that also slows the baseline raises the threshold, so a target
//     that really sleeps on the payload can be missed;
//   - the confirmation probe is sent with client.Do, outside probeDo: a 429 on
//     it answers fast, so a real, reproducible delay stays MEDIUM and does not
//     block (OR-18).
//
// What must hold: the wait the engine actually took (not the header's value)
// never counts as delay; a target that sleeps 5 s on the payload is reported
// at HIGH severity and HIGH confidence (the confirmed finding, which blocks),
// with or without a limiter, for every retryable status, with latency jitter;
// and a one-off slow answer whose confirmation is fast stays MEDIUM.

// wse3SqliPayloadIn reports whether a request carries one of sqliPayloads().
func wse3SqliPayloadIn(r *http.Request) bool {
	q := r.URL.RawQuery
	for _, m := range []string{"SLEEP", "pg_sleep", "WAITFOR", "randomblob", "DBMS_PIPE"} {
		if strings.Contains(q, m) {
			return true
		}
	}
	return false
}

// wse3RateLimitTarget is an httptest handler for one scenario.
type wse3RateLimitTarget struct {
	// burst requests are answered normally before the limiter engages, as a
	// token bucket does. 0 limits from the first request, the timing baseline
	// included.
	burst int32
	// status is the limiter's answer: 429 unless set (502, 503, 504 are also
	// retried by probeDo).
	status int
	// retryAfter returns the Retry-After value for one limited answer, read at
	// the moment it is sent; nil sends none.
	retryAfter func() string
	// always limits every request after the burst. Otherwise the limiter
	// answers every other request: sent one after another, each request's
	// first attempt is refused and its retry is served.
	always bool
	// delay is how long the handler sleeps on an SQLi payload when it serves
	// it (an injectable endpoint); 0 for a safe one.
	delay time.Duration
	// jitter is the most latency added to any answer.
	jitter time.Duration

	n   atomic.Int32
	mu  sync.Mutex
	rnd *rand.Rand
}

func (rt *wse3RateLimitTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := rt.n.Add(1)
	if rt.jitter > 0 {
		rt.mu.Lock()
		j := time.Duration(rt.rnd.Int63n(int64(rt.jitter)))
		rt.mu.Unlock()
		time.Sleep(j)
	}
	if n > rt.burst && (rt.always || (n-rt.burst)%2 == 1) {
		if rt.retryAfter != nil {
			w.Header().Set("Retry-After", rt.retryAfter())
		}
		status := rt.status
		if status == 0 {
			status = http.StatusTooManyRequests
		}
		w.WriteHeader(status)
		return
	}
	if rt.delay > 0 && wse3SqliPayloadIn(r) {
		time.Sleep(rt.delay)
	}
	w.WriteHeader(http.StatusOK)
}

func wse3RA(v string) func() string { return func() string { return v } }

// wse3RaDate is a Retry-After HTTP-date 6 s after the moment the answer is sent
// (probeDo caps the pause at 5 s). It is computed per answer, so it does not
// age while earlier requests run.
func wse3RaDate() string { return time.Now().Add(6 * time.Second).UTC().Format(http.TimeFormat) }

type wse3SqliOutcome struct {
	sev     []models.Severity
	conf    []models.Confidence
	retries int
}

func wse3RunSQLiAgainst(t *testing.T, h http.Handler) wse3SqliOutcome {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	cfg := &models.ScanConfig{EnableActive: true, Timeout: 30}
	ep := Endpoint{Method: "GET", Path: "/api/items", FullURL: ts.URL + "/api/items", Params: []string{"id"}}
	audit := NewProbeAuditLog()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	findings := probeSQLi(ctx, &http.Client{Timeout: 30 * time.Second}, cfg, ep, "id", LocQuery, audit)
	var out wse3SqliOutcome
	for _, f := range findings {
		if f.RuleID != "injection/sqli-time-based" {
			t.Fatalf("unexpected rule %q", f.RuleID)
		}
		out.sev = append(out.sev, f.Severity)
		out.conf = append(out.conf, f.Confidence)
	}
	out.retries = audit.RetriesSpent()
	return out
}

// wse3ResetBudget clears the scan-wide request budget other tests of this package
// set, before the test and after its parallel subtests (go test -shuffle).
func wse3ResetBudget(t *testing.T) {
	t.Helper()
	budget.Reset()
	t.Cleanup(budget.Reset)
}

const wse3Jitter = 250 * time.Millisecond

type wse3LimiterCase struct {
	name string
	rt   *wse3RateLimitTarget
}

// wse3LimiterCases is every limiter shape, without a delay on the payload. The
// delayed twins are the same shapes with delay set.
func wse3LimiterCases() []wse3LimiterCase {
	return []wse3LimiterCase{
		{"429 Retry-After 0", &wse3RateLimitTarget{burst: 3, retryAfter: wse3RA("0"), jitter: wse3Jitter}},
		{"429 Retry-After 5", &wse3RateLimitTarget{burst: 3, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
		{"429 Retry-After 60 (pause capped at 5 s)", &wse3RateLimitTarget{burst: 3, retryAfter: wse3RA("60"), jitter: wse3Jitter}},
		{"429 Retry-After HTTP-date +6 s", &wse3RateLimitTarget{burst: 3, retryAfter: wse3RaDate, jitter: wse3Jitter}},
		{"429 no Retry-After (1 s + 2 s backoff)", &wse3RateLimitTarget{burst: 3, jitter: wse3Jitter}},
		{"429 Retry-After 5 on every request after the burst", &wse3RateLimitTarget{burst: 3, retryAfter: wse3RA("5"), always: true, jitter: wse3Jitter}},
		{"429 Retry-After 5, burst 0: the first attempt of every request, baseline included", &wse3RateLimitTarget{burst: 0, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
		{"429 Retry-After 5, burst 1", &wse3RateLimitTarget{burst: 1, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
		{"503 Retry-After 5", &wse3RateLimitTarget{burst: 3, status: http.StatusServiceUnavailable, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
		{"502 Retry-After 5", &wse3RateLimitTarget{burst: 3, status: http.StatusBadGateway, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
		{"504 Retry-After 5", &wse3RateLimitTarget{burst: 3, status: http.StatusGatewayTimeout, retryAfter: wse3RA("5"), jitter: wse3Jitter}},
	}
}

func TestProbeSQLi_RateLimitedTargetIsNotTimeBasedSQLi(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for real Retry-After pauses in -short mode")
	}
	wse3ResetBudget(t)
	for i, tc := range wse3LimiterCases() {
		tc.rt.rnd = rand.New(rand.NewSource(int64(4209 + i)))
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := wse3RunSQLiAgainst(t, tc.rt)
			if len(got.sev) != 0 {
				t.Errorf("a target that only rate-limits (no delay on the payload) gave %d time-based SQLi finding(s) "+
					"(severity %v, confidence %v, retries %d); want 0: the engine's own retry wait is not the target's delay",
					len(got.sev), got.sev, got.conf, got.retries)
			}
		})
	}
}

func TestProbeSQLi_GenuinelyDelayedEndpointStillBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for real 5 s delays in -short mode")
	}
	wse3ResetBudget(t)
	cases := []wse3LimiterCase{{"no limiter", &wse3RateLimitTarget{burst: 1 << 30, jitter: wse3Jitter}}}
	cases = append(cases, wse3LimiterCases()...)
	for i, tc := range cases {
		// "every request after the burst" never serves the payload, so there
		// is no delay to see; it has no delayed twin.
		if tc.rt.always {
			continue
		}
		tc.rt.delay = 5 * time.Second
		tc.rt.rnd = rand.New(rand.NewSource(int64(5209 + i)))
		t.Run("delayed 5 s, "+tc.name, func(t *testing.T) {
			t.Parallel()
			got := wse3RunSQLiAgainst(t, tc.rt)
			if len(got.sev) != 1 {
				t.Fatalf("a target that sleeps 5 s on the payload gave %d time-based finding(s) (retries %d); want 1", len(got.sev), got.retries)
			}
			if got.sev[0] != models.SeverityHigh || got.conf[0] != models.ConfidenceHigh {
				t.Errorf("the finding is %s/%s (retries %d); want HIGH severity at HIGH confidence: the delay is the target's and it was reproduced, so it blocks",
					got.sev[0], got.conf[0], got.retries)
			}
		})
	}
}

// wse3OneOffSlowTarget answers the first SQLi payload 5 s late, refuses the next
// request (the confirmation) with a 429 and Retry-After 5, and serves every
// later request at once.
type wse3OneOffSlowTarget struct{ inj atomic.Int32 }

func (o *wse3OneOffSlowTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if wse3SqliPayloadIn(r) {
		switch o.inj.Add(1) {
		case 1:
			time.Sleep(5 * time.Second)
		case 2:
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// OR-18 neighbour: confirming through the retry path must not confirm a
// one-off. The confirmation's 429 is followed, after the wait, by a fast
// answer, so the delay was not reproduced: the finding stays MEDIUM, whether
// or not the confirmation goes through probeDo and however its wait is
// accounted.
func TestProbeSQLi_OneOffSlowWithRateLimitedConfirmationStaysMedium(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a real 5 s delay in -short mode")
	}
	wse3ResetBudget(t)
	got := wse3RunSQLiAgainst(t, &wse3OneOffSlowTarget{})
	if len(got.sev) != 1 {
		t.Fatalf("one slow answer gave %d time-based finding(s); want 1 (the slow answer itself)", len(got.sev))
	}
	if got.conf[0] != models.ConfidenceMedium {
		t.Errorf("a one-off slow answer whose confirmation was fast after a 429 is %s; want MEDIUM (not reproduced)", got.conf[0])
	}
}
