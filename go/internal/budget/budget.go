// Package budget enforces global scan budgets — total HTTP request count
// (--max-requests) and wall-clock duration (--max-duration). It exposes an
// http.RoundTripper wrapper that counts every outbound request and refuses
// new ones once the cap is hit, plus a one-shot cancel hook the orchestrator
// uses to stop scheduling worker-pool jobs when soft-stop should fire.
//
// The deadline budget is implemented entirely via context.WithTimeout in the
// orchestrator — this package just helps surface "we ran out of budget"
// after the fact via Stats(). The request budget is the more invasive piece
// because it crosses the scanner/engine package boundary, which is what
// motivates the package-level state design (same pattern as logagg).
//
// All package state is goroutine-safe: counters are atomic; SetCancelFunc
// and SetMaxRequests use a Mutex; capHitOnce ensures the cancel fires at
// most once per scan. Tests should call Reset() at the top.
package budget

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/Fendix-app/Fendix/go/internal/netguard"
)

// ErrBudgetExceeded is returned by the wrapped RoundTripper when the
// MaxRequests cap has been hit. Scanners see this as a normal request
// error; the orchestrator's cancel-on-cap mechanism stops the worker
// pool from scheduling much more work, so this error rarely propagates
// far before the scan winds down.
var ErrBudgetExceeded = errors.New("scan budget exceeded: --max-requests cap hit")

var (
	mu          sync.Mutex
	maxRequests int64
	sent        atomic.Int64 // every RoundTrip attempt, including over-cap
	rejected    atomic.Int64 // attempts refused after cap hit
	cancelFunc  func()       // wired by orchestrator; called once when cap is hit
	capHitOnce  sync.Once
)

// SetMaxRequests configures the global request cap. 0 (default) disables
// capping. Negative values are treated as 0. Safe to call concurrently
// with RoundTrip — the new cap is observed by the next request.
func SetMaxRequests(n int64) {
	if n < 0 {
		n = 0
	}
	mu.Lock()
	maxRequests = n
	mu.Unlock()
}

// SetCancelFunc registers a function to call exactly once when the cap is
// hit. The orchestrator wires its top-level cancel here so the worker pool
// stops scheduling new jobs as soon as the budget is exhausted. Passing
// nil removes any previously registered function.
func SetCancelFunc(fn func()) {
	mu.Lock()
	cancelFunc = fn
	mu.Unlock()
}

// Reset zeros counters and re-arms the once-cancel-on-cap mechanism for a
// new scan. Call at the top of orchestrator.Run.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	sent.Store(0)
	rejected.Store(0)
	capHitOnce = sync.Once{}
}

// Stats returns the (sent, rejected) request counts since the last Reset.
// `sent` increments on every RoundTrip attempt (including those rejected
// for budget); `rejected` increments only on cap-hit refusals. The
// difference is the number of requests actually sent over the wire.
func Stats() (sentN, rejectedN int64) {
	return sent.Load(), rejected.Load()
}

// MaxRequests returns the currently configured cap. 0 means unlimited.
func MaxRequests() int64 {
	mu.Lock()
	defer mu.Unlock()
	return maxRequests
}

// budgetTransport is the http.RoundTripper wrapper that enforces the cap.
// Every outbound request increments `sent`; if the post-increment count
// exceeds the cap, the request is refused and the once-cancel mechanism
// fires.
type budgetTransport struct {
	inner http.RoundTripper
}

// RoundTrip implements http.RoundTripper. Counter math is single-atomic:
// post-increment compare against the cap means an over-budget request is
// counted as `sent` once and `rejected` once — no double-counting, and
// concurrent overshoot is bounded by the number of in-flight goroutines
// (which matches "soft-stop" semantics).
func (b *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cap := MaxRequests()
	n := sent.Add(1)
	if cap > 0 && n > cap {
		rejected.Add(1)
		mu.Lock()
		cancel := cancelFunc
		once := &capHitOnce
		mu.Unlock()
		if cancel != nil {
			once.Do(cancel)
		}
		return nil, ErrBudgetExceeded
	}
	return b.inner.RoundTrip(req)
}

// WrapTransport wraps `rt` with budget enforcement. Pass http.DefaultTransport
// when the caller doesn't have a custom transport; pass an existing transport
// when the caller has set custom fields like MaxIdleConnsPerHost (e.g. the
// crawler's brute-force keep-alive transport — see TASK-090).
//
// If `rt` is nil, http.DefaultTransport is used. If MaxRequests is 0 (cap
// disabled), the wrapper is still returned — the per-request overhead is a
// single atomic.Add, negligible at scan scale.
func WrapTransport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &budgetTransport{inner: rt}
}

// NOTE: an unguarded `Transport()` convenience constructor used to live here.
// It was removed deliberately rather than left unreferenced: it returned a
// budget-counted transport with NO netguard SSRF policy, so any future check
// that reached for the obvious-looking helper would have silently opted out of
// egress filtering. That is the exact bypass scanner.CheckContext was built to
// close structurally. Checks must obtain their client from
// scanner.CheckContext (Client / NoFollow); everything else should call
// WrapTransportGuarded explicitly and state its allowPrivate policy.

// WrapTransportGuarded composes the SSRF egress guard (internal/netguard)
// UNDERNEATH the budget counter. The returned RoundTripper is:
//
//	budgetTransport → netguard-dialing http.Transport
//
// Layering matters. The budget counter stays the outer wrapper so every
// attempt is still counted exactly once and the --max-requests cap fires the
// same way it does for the unguarded path; the guard lives in the transport's
// DialContext, so a connection that the guard refuses still counts as a `sent`
// attempt (it failed at dial, like any other connect error). When
// allowPrivate is true the guard is a passthrough and this behaves identically
// to WrapTransport.
//
// `base` is the transport whose fields (MaxIdleConnsPerHost, timeouts, …)
// should be preserved; pass nil to start from http.DefaultTransport. Callers
// with a customised *http.Transport (e.g. the crawler's keep-alive transport)
// pass it here so the guard composes onto it rather than replacing it.
func WrapTransportGuarded(base *http.Transport, allowPrivate bool) http.RoundTripper {
	guarded := netguard.Config{AllowPrivate: allowPrivate}.Transport(base)
	return WrapTransport(guarded)
}

// TransportGuarded returns the budget+SSRF-guarded wrapper over a default
// transport. Convenience for the simple black-box checks (cors, injection,
// …) that don't customise the transport but must not be SSRF'd into the
// host's own network. Equivalent to WrapTransportGuarded(nil, allowPrivate).
func TransportGuarded(allowPrivate bool) http.RoundTripper {
	return WrapTransportGuarded(nil, allowPrivate)
}
