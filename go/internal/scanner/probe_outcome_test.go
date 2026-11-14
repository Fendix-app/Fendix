package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/budget"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Fresh per-scan state (audit log, retry accounting, request budget) and short
// retry pauses, so the retry policy can be exercised in milliseconds. The pauses
// are the only thing shrunk: the schedule, the caps and the order are the
// production ones.
func probeTestEnv(t *testing.T) (*CheckContext, *models.ScanConfig) {
	t.Helper()
	ResetGlobalAuditLog()
	budget.Reset()
	budget.SetMaxRequests(0)
	oldB, oldCap, oldTotal := probeBackoffs, probeRetryAfterCap, maxScanRetries
	probeBackoffs = [...]time.Duration{5 * time.Millisecond, 10 * time.Millisecond}
	t.Cleanup(func() {
		probeBackoffs, probeRetryAfterCap, maxScanRetries = oldB, oldCap, oldTotal
		budget.Reset()
		budget.SetMaxRequests(0)
		ResetGlobalAuditLog()
	})
	cfg := &models.ScanConfig{URL: "http://127.0.0.1", AllowPrivate: true, Timeout: 5, EnableActive: true}
	return NewCheckContext(cfg), cfg
}

func getReq(t *testing.T, ctx context.Context, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// send runs one probe through probeDo and returns the audit record a probe site
// would write, plus the status code (0 on error).
func send(t *testing.T, ctx context.Context, cc *CheckContext, cfg *models.ScanConfig, url string) (ProbeRecord, *http.Response, error) {
	t.Helper()
	start := time.Now()
	resp, pi, err := probeDo(ctx, cc.Client, getReq(t, ctx, url), cc.Audit, url, cfg)
	rec := ProbeRecord{Timestamp: start, Endpoint: url, ProbeType: ProbeSQLi, Method: "GET"}
	pi.apply(&rec)
	if err == nil {
		rec.Status = resp.StatusCode
	}
	return rec, resp, err
}

func resetConn(w http.ResponseWriter) {
	c, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0) // close sends RST
	}
	_ = c.Close()
}

func wantVerdict(t *testing.T, rec ProbeRecord, cc *CheckContext, origin ProbeOrigin, reason ProbeReason) ProbeVerdict {
	t.Helper()
	v := ClassifyProbe(rec, cc.Audit)
	if v.Evaluated || v.Origin != origin || v.Reason != reason {
		t.Fatalf("verdict = %+v (record status=%d retries=%d failure=%+v), want %s/%s not evaluated", v, rec.Status, rec.Retries, rec.Failure, origin, reason)
	}
	return v
}

// ---- 429 / 503 with retries ------------------------------------------------

func TestProbeDo_429And503RetryThenStayInconclusive(t *testing.T) {
	for _, code := range []int{429, 502, 503, 504} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			cc, cfg := probeTestEnv(t)
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(code) }))
			defer srv.Close()

			rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL+"/x")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if hits.Load() != 3 || rec.Retries != 2 {
				t.Fatalf("hits=%d retries=%d, want 3 requests (1 + 2 retries)", hits.Load(), rec.Retries)
			}
			reason := ReasonServiceUnavailable
			if code == 429 {
				reason = ReasonRateLimited
			}
			v := wantVerdict(t, rec, cc, OriginTarget, reason)
			if !strings.Contains(v.Evidence, "after 2 retries") {
				t.Fatalf("evidence %q must say the retries were spent", v.Evidence)
			}
		})
	}
}

func TestProbeDo_TemporaryFailureThatRecoversIsEvaluated(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rec.Status != 200 || rec.Retries != 1 {
		t.Fatalf("status=%d retries=%d, want 200 after 1 retry", rec.Status, rec.Retries)
	}
	if v := ClassifyProbe(rec, cc.Audit); !v.Evaluated {
		t.Fatalf("a probe that recovered on retry was evaluated, got %+v", v)
	}
}

func TestProbeDo_RetryAfterIsHonouredButCapped(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	probeRetryAfterCap = 60 * time.Millisecond
	var stamps []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stamps = append(stamps, time.Now())
		w.Header().Set("Retry-After", "30") // 30 s asked for; capped
		w.WriteHeader(503)
	}))
	defer srv.Close()
	start := time.Now()
	rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rec.Retries != 2 || len(stamps) != 3 {
		t.Fatalf("retries=%d hits=%d", rec.Retries, len(stamps))
	}
	for i := 1; i < len(stamps); i++ {
		if gap := stamps[i].Sub(stamps[i-1]); gap < 55*time.Millisecond {
			t.Fatalf("retry %d came after %s, Retry-After (capped to 60ms) was not honoured", i, gap)
		}
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("a 30 s Retry-After was not capped: took %s", time.Since(start))
	}
}

func TestProbeDo_SmallRetryAfterReplacesTheDefaultPause(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	probeBackoffs = [...]time.Duration{400 * time.Millisecond, 400 * time.Millisecond}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		hits.Add(1)
		w.WriteHeader(429)
	}))
	defer srv.Close()
	start := time.Now()
	_, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("Retry-After: 0 is honoured: took %s", time.Since(start))
	}
}

// ---- 401 / 403 / 404 / 410 -------------------------------------------------

// Round 5 (owner decision D5-6): a gated answer is a final answer (never
// retried) but it is NOT an evaluation. It evaluates nothing about the
// parameter the probe tested: the request was refused or the path is not served
// to this client. It is target-side, so it is not a scanner gap.
//
// This test replaces the round-4b test of the same subject, which pinned
// "evaluated" for these four statuses. That pin is the defect C4B-01: a target
// answering 404 to every probe read "All 2633 active probes sent were
// evaluated". The no-retry half is unchanged.
func TestProbeDo_401_403_404_410AreGatedNotRetriedNotEvaluated(t *testing.T) {
	for _, code := range []int{401, 403, 404, 410} {
		cc, cfg := probeTestEnv(t)
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(code) }))
		rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		srv.Close()
		if hits.Load() != 1 || rec.Retries != 0 {
			t.Fatalf("%d: hits=%d retries=%d, a gated status is a final answer, never retried", code, hits.Load(), rec.Retries)
		}
		v := wantVerdict(t, rec, cc, OriginTarget, ReasonGated)
		if !strings.Contains(v.Evidence, strconv.Itoa(code)) {
			t.Fatalf("%d: evidence %q does not name the status", code, v.Evidence)
		}
	}
}

func TestClassify_OnlyTheFourGatingStatusesGate(t *testing.T) {
	cc, _ := probeTestEnv(t)
	gated := map[int]bool{401: true, 403: true, 404: true, 410: true}
	for code := 100; code < 600; code++ {
		v := ClassifyProbe(ProbeRecord{Timestamp: time.Now(), Endpoint: "http://t/a", Status: code}, cc.Audit)
		switch {
		case gated[code]:
			if v.Evaluated || v.Origin != OriginTarget || v.Reason != ReasonGated {
				t.Fatalf("%d: %+v, want target/gated", code, v)
			}
		case retryableStatus(code):
			if v.Evaluated || v.Origin != OriginTarget || v.Reason == ReasonGated {
				t.Fatalf("%d: %+v, want a retryable non-answer", code, v)
			}
		default:
			if !v.Evaluated {
				t.Fatalf("%d: %+v, want evaluated", code, v)
			}
		}
	}
	// A probe that produced a finding is evidence, whatever status carried it.
	for code := range gated {
		if v := ClassifyProbe(ProbeRecord{Timestamp: time.Now(), Endpoint: "http://t/a", Status: code, Finding: true}, cc.Audit); !v.Evaluated {
			t.Fatalf("%d with a finding: %+v, want evaluated", code, v)
		}
	}
}

func TestSummarize_GatedProbesAreCountedApartAndNeverEvaluated(t *testing.T) {
	cc, _ := probeTestEnv(t)
	t0 := time.Now()
	rec := func(ep string, status int) ProbeRecord {
		return ProbeRecord{Timestamp: t0, Endpoint: "http://t" + ep, Method: "GET", ProbeType: ProbeXSS, Status: status}
	}
	records := []ProbeRecord{
		rec("/ok", 200), rec("/ok", 200),
		rec("/a", 403), rec("/a", 403), rec("/a", 404), rec("/b", 401), rec("/c", 410),
		rec("/d", 503),
	}
	cov := SummarizeProbes(records, cc.Audit)
	if cov.Attempted != 8 || cov.Evaluated != 2 {
		t.Fatalf("a gated answer must not count as evaluated: %+v", cov)
	}
	if cov.Gated.Total != 5 || cov.Gated.ByStatus["403"] != 2 || cov.Gated.ByStatus["404"] != 1 || cov.Gated.ByStatus["401"] != 1 || cov.Gated.ByStatus["410"] != 1 || len(cov.Gated.ByStatus) != 4 {
		t.Fatalf("gated = %+v", cov.Gated)
	}
	// The account still adds up: gated probes sit inside inconclusive (target-side).
	if cov.Evaluated+cov.Inconclusive+cov.UnknownOrigin+cov.ScannerFailed != cov.Attempted || cov.Inconclusive != 6 || cov.ScannerFailed != 0 || cov.UnknownOrigin != 0 {
		t.Fatalf("account = %+v", cov)
	}
	if cov.Reasons["target"]["gated"] != 5 || cov.Reasons["target"]["service_unavailable"] != 1 {
		t.Fatalf("reasons = %+v", cov.Reasons)
	}
	// The (check, endpoint) pairs stay listed, so a consumer can see that /a was never evaluated.
	var listed []string
	for _, e := range cov.NotEvaluatedChecks {
		if e.Reason == "gated" {
			if e.Origin != "target" || e.Check != "xss" {
				t.Fatalf("entry = %+v", e)
			}
			listed = append(listed, e.Endpoint)
		}
		if strings.Contains(e.Endpoint, "/ok") {
			t.Fatalf("/ok was evaluated and must not be listed: %+v", e)
		}
	}
	if len(listed) != 3 {
		t.Fatalf("gated entries = %v, want /a /b /c", listed)
	}
	// Nothing gated: the block is present and empty (a stable shape).
	cov = SummarizeProbes([]ProbeRecord{rec("/ok", 200)}, cc.Audit)
	if cov.Gated.Total != 0 || cov.Gated.ByStatus == nil || len(cov.Gated.ByStatus) != 0 {
		t.Fatalf("empty gated block = %+v", cov.Gated)
	}
}

// ---- resets, stalls, timeouts ----------------------------------------------

func TestProbeDo_ResetAfterConnectIsTargetSideAndRetried(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); resetConn(w) }))
	defer srv.Close()
	rec, _, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if hits.Load() != 3 || rec.Retries != 2 {
		t.Fatalf("hits=%d retries=%d, a reset after connect is retried twice", hits.Load(), rec.Retries)
	}
	wantVerdict(t, rec, cc, OriginTarget, ReasonConnectionReset)
	var pe *ProbeError
	if !errors.As(err, &pe) {
		t.Fatalf("error %v must carry its classification", err)
	}
}

func TestProbeDo_StallOnAcceptedConnectionIsTargetTimeout(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond) // the per-request deadline
	defer cancel()
	rec, _, err := send(t, ctx, cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	v := wantVerdict(t, rec, cc, OriginTarget, ReasonTimeout)
	if !strings.Contains(v.Evidence, "accepted") {
		t.Fatalf("evidence %q must say the connection was accepted", v.Evidence)
	}
}

func TestProbeDo_ConnectionLevelStallClientTimeout(t *testing.T) {
	// A client-level timeout (no ctx deadline) on an accepted connection is the
	// same evidence: connected, request written, no response.
	cc, cfg := probeTestEnv(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	c := *cc.Client
	c.Timeout = 150 * time.Millisecond
	cc2 := *cc
	cc2.Client = &c
	rec, _, err := send(t, context.Background(), &cc2, cfg, srv.URL)
	if err == nil {
		t.Fatal("expected a timeout")
	}
	wantVerdict(t, rec, cc, OriginTarget, ReasonTimeout)
}

// ---- origin attribution: the same error type lands in different origins ----

func closedPortURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

func TestOrigin_Refusal(t *testing.T) {
	// Split from the case above so the table reads: same errno, two origins.
	t.Run("no answer anywhere is unknown", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		rec, _, _ := send(t, context.Background(), cc, cfg, closedPortURL(t)+"/p")
		wantVerdict(t, rec, cc, OriginUnknown, ReasonConnectionRefused)
	})
	t.Run("the host answered other requests nearby is target", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		url := closedPortURL(t)
		rec, _, _ := send(t, context.Background(), cc, cfg, url+"/p")
		host := strings.TrimPrefix(url, "http://")
		cc.Audit.NoteTargetResponse(host, rec.Timestamp.Add(10*time.Second)) // within 30 s
		wantVerdict(t, rec, cc, OriginTarget, ReasonConnectionRefused)
	})
	t.Run("an answer long before or after does not count", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		url := closedPortURL(t)
		rec, _, _ := send(t, context.Background(), cc, cfg, url+"/p")
		host := strings.TrimPrefix(url, "http://")
		cc.Audit.NoteTargetResponse(host, rec.Timestamp.Add(-2*time.Minute))
		cc.Audit.NoteTargetResponse(host, rec.Timestamp.Add(2*time.Minute))
		wantVerdict(t, rec, cc, OriginUnknown, ReasonConnectionRefused)
	})
	t.Run("an answer from a different host does not count", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		rec, _, _ := send(t, context.Background(), cc, cfg, closedPortURL(t)+"/p")
		cc.Audit.NoteTargetResponse("other.example:80", rec.Timestamp)
		wantVerdict(t, rec, cc, OriginUnknown, ReasonConnectionRefused)
	})
}

func TestOrigin_RealResponsesFromTheSameHostSettleARefusal(t *testing.T) {
	// End to end through the observing transport: the host answers one request
	// (recorded by the transport), then stops listening. A refusal within the
	// window is the target's behaviour; the same refusal on a fresh scan with
	// no earlier answer is unknown-origin.
	cc, cfg := probeTestEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	host := strings.TrimPrefix(srv.URL, "http://")
	rec1, resp, err := send(t, context.Background(), cc, cfg, srv.URL+"/a")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := ClassifyProbe(rec1, cc.Audit); !v.Evaluated {
		t.Fatalf("first probe was answered: %+v", v)
	}
	srv.Close() // now refuses
	c := *cc.Client
	c.Transport = ObserveTransport(budget.TransportGuarded(true))
	cc2 := *cc
	cc2.Client = &c
	rec2, _, err := send(t, context.Background(), &cc2, cfg, "http://"+host+"/b")
	if err == nil {
		t.Skip("listener still accepted; cannot assert refusal on this platform")
	}
	wantVerdict(t, rec2, cc, OriginTarget, ReasonConnectionRefused)

	ResetGlobalAuditLog()
	cc3 := NewCheckContext(cfg)
	rec3, _, _ := send(t, context.Background(), cc3, cfg, "http://"+host+"/b")
	wantVerdict(t, rec3, cc3, OriginUnknown, ReasonConnectionRefused)
}

func TestOrigin_DNSFailureIsUnknown(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	rec, _, err := send(t, context.Background(), cc, cfg, "http://fendix-no-such-host.invalid/p")
	if err == nil {
		t.Fatal("expected a resolution failure")
	}
	wantVerdict(t, rec, cc, OriginUnknown, ReasonDNSFailure)
}

func TestOrigin_TLSAlertIsTargetAndHandshakeWithoutAlertIsUnknown(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	// A TLS server whose certificate the scanner does not trust: the scanner
	// aborts the handshake itself (no alert from the peer) -> unknown.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	rec, _, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("expected a certificate failure")
	}
	wantVerdict(t, rec, cc, OriginUnknown, ReasonTLSHandshake)

	// A plain-TCP listener that answers a ClientHello with a fatal TLS alert:
	// the peer sent the alert -> target.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}) // fatal handshake_failure
				_ = c.Close()
			}()
		}
	}()
	rec2, _, err := send(t, context.Background(), cc, cfg, "https://"+ln.Addr().String()+"/p")
	if err == nil {
		t.Fatal("expected a TLS failure")
	}
	wantVerdict(t, rec2, cc, OriginTarget, ReasonTLSError)
}

// ---- scanner-side ----------------------------------------------------------

func TestOrigin_RequestBudgetRefusalIsScannerNotSent(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	budget.SetMaxRequests(1)
	if _, resp, err := send(t, context.Background(), cc, cfg, srv.URL); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	rec, _, err := send(t, context.Background(), cc, cfg, srv.URL)
	if !errors.Is(err, budget.ErrBudgetExceeded) {
		t.Fatalf("err = %v, want the budget refusal", err)
	}
	wantVerdict(t, rec, cc, OriginScanner, ReasonNotSent)
}

func TestOrigin_ScanDeadlineAndCancellationAreScannerSide(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	t.Run("the scan's own deadline", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		scanCtx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
		defer cancel()
		SetScanContext(scanCtx)
		cc.Audit = currentAuditLog()
		rec, _, err := send(t, scanCtx, cc, cfg, srv.URL)
		if err == nil {
			t.Fatal("expected the deadline to cut the probe")
		}
		wantVerdict(t, rec, cc, OriginScanner, ReasonScanDeadline)
	})
	t.Run("the scan cancelled (budget cap or interrupt)", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		scanCtx, cancel := context.WithCancel(context.Background())
		SetScanContext(scanCtx)
		cc.Audit = currentAuditLog()
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
		rec, _, err := send(t, scanCtx, cc, cfg, srv.URL)
		if err == nil {
			t.Fatal("expected cancellation")
		}
		wantVerdict(t, rec, cc, OriginScanner, ReasonScanCancelled)
	})
	t.Run("a per-request deadline on an accepted connection is NOT the scanner's", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		scanCtx, cancel := context.WithCancel(context.Background()) // alive
		defer cancel()
		SetScanContext(scanCtx)
		cc.Audit = currentAuditLog()
		jobCtx, cancelJob := context.WithTimeout(scanCtx, 120*time.Millisecond)
		defer cancelJob()
		rec, _, err := send(t, jobCtx, cc, cfg, srv.URL)
		if err == nil {
			t.Fatal("expected the per-request deadline")
		}
		wantVerdict(t, rec, cc, OriginTarget, ReasonTimeout)
	})
	t.Run("a probe whose context already ended never left the scanner", func(t *testing.T) {
		cc, cfg := probeTestEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rec, _, err := send(t, ctx, cc, cfg, srv.URL)
		if err == nil {
			t.Fatal("expected an error")
		}
		wantVerdict(t, rec, cc, OriginScanner, ReasonNotSent)
	})
}

func TestClassify_LocalFailuresAreScannerSide(t *testing.T) {
	tr := traceFacts{getConn: true}
	for _, tc := range []struct {
		name   string
		err    error
		reason ProbeReason
	}{
		{"EMFILE", &net.OpError{Op: "dial", Err: syscall.EMFILE}, ReasonResourceExhausted},
		{"ENOMEM", &net.OpError{Op: "dial", Err: syscall.ENOMEM}, ReasonResourceExhausted},
		{"ephemeral ports", &net.OpError{Op: "dial", Err: syscall.EADDRNOTAVAIL}, ReasonResourceExhausted},
		{"proxy dial", &net.OpError{Op: "proxyconnect", Err: errors.New("refused")}, ReasonProxyFailure},
	} {
		f := classifyTransportError(tc.err, nil, tr, nil)
		if f.Origin != OriginScanner || f.Reason != tc.reason {
			t.Errorf("%s: %+v, want scanner/%s", tc.name, f, tc.reason)
		}
	}
	// No transport activity at all: the request was rejected locally.
	f := classifyTransportError(errors.New(`unsupported protocol scheme "gopher"`), nil, traceFacts{}, nil)
	if f.Origin != OriginScanner || f.Reason != ReasonRequestConstruction {
		t.Errorf("pre-connection rejection: %+v", f)
	}
	// An error type is not a verdict: ECONNRESET with no connection established
	// is not the target resetting an established connection.
	f = classifyTransportError(syscall.ECONNRESET, nil, traceFacts{getConn: true}, nil)
	if f.Origin == OriginTarget {
		t.Errorf("a reset before the connection was established must not be confirmed target-side: %+v", f)
	}
	f = classifyTransportError(syscall.ECONNRESET, nil, traceFacts{getConn: true, gotConn: true}, nil)
	if f.Origin != OriginTarget || f.Reason != ReasonConnectionReset {
		t.Errorf("a reset after connect is the target's: %+v", f)
	}
}

func TestClassify_RecordWithNoResponseAndNoEvidenceFailsClosed(t *testing.T) {
	v := ClassifyProbe(ProbeRecord{Status: 0}, nil)
	if v.Evaluated || v.Origin != OriginUnknown || v.Reason != ReasonUnclassified {
		t.Fatalf("a probe with no response and no failure evidence is unknown-origin, got %+v", v)
	}
}

func TestPanickedCheckIsScannerFailed(t *testing.T) {
	probeTestEnv(t)
	RecordScannerFailure("injection", "http://t/a?x=1", ReasonInternalError, "a scanner check panicked before it finished its probes")
	cov := SummarizeGlobalProbes()
	if cov.ScannerFailed != 1 || cov.Reasons["scanner"]["internal_error"] != 1 || len(cov.NotEvaluatedChecks) != 1 || cov.NotEvaluatedChecks[0].Check != "injection" {
		t.Fatalf("coverage = %+v", cov)
	}
}

// ---- cancellation, deadline propagation, budgets ---------------------------

func TestRetry_CancellationMidBackoffStopsAndKeepsTheLastClassification(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	probeBackoffs = [...]time.Duration{2 * time.Second, 2 * time.Second}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(80 * time.Millisecond); cancel() }()
	start := time.Now()
	rec, resp, err := send(t, ctx, cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if time.Since(start) > time.Second {
		t.Fatalf("the backoff was not interrupted: %s", time.Since(start))
	}
	if hits.Load() != 1 || rec.Retries != 0 {
		t.Fatalf("hits=%d retries=%d, a cancelled backoff sends nothing more", hits.Load(), rec.Retries)
	}
	wantVerdict(t, rec, cc, OriginTarget, ReasonServiceUnavailable)
}

func TestRetry_NeverSleepsPastTheDeadline(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	probeBackoffs = [...]time.Duration{time.Second, 2 * time.Second}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	rec, resp, err := send(t, ctx, cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if time.Since(start) > 300*time.Millisecond {
		t.Fatalf("slept toward a deadline it could not reach: %s", time.Since(start))
	}
	if hits.Load() != 1 || rec.Retries != 0 {
		t.Fatalf("hits=%d retries=%d: a 1 s pause does not fit a 400 ms deadline", hits.Load(), rec.Retries)
	}
}

func TestRetry_ScanDeadlineBoundsTheRetryToo(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	probeBackoffs = [...]time.Duration{time.Second, 2 * time.Second}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	scanCtx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	SetScanContext(scanCtx)
	cc.Audit = currentAuditLog()
	// The per-job context has no deadline of its own; the scan's does.
	rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 || rec.Retries != 0 {
		t.Fatalf("hits=%d retries=%d: the scan deadline must bound the retry pause", hits.Load(), rec.Retries)
	}
}

func TestRetry_PerEndpointBudgetIsSharedWithRetries(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	cfg.MaxProbesPerEndpoint = 2
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	url := srv.URL + "/x"
	// First probe: the in-flight request (1) + a retry (1) fit the cap of 2; a second retry does not.
	rec, resp, err := send(t, context.Background(), cc, cfg, url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if rec.Retries != 1 || hits.Load() != 2 {
		t.Fatalf("retries=%d hits=%d, want 1 retry within a cap of 2", rec.Retries, hits.Load())
	}
	if cc.Audit.Count(url) != 1 {
		t.Fatalf("Count must include the retry: %d", cc.Audit.Count(url))
	}
	// The endpoint's budget is now nearly spent: record the probe, then the next
	// probe has no room to retry at all.
	cc.Audit.Record(rec)
	hits.Store(0)
	rec2, resp2, err := send(t, context.Background(), cc, cfg, url)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if rec2.Retries != 0 || hits.Load() != 1 {
		t.Fatalf("retries=%d hits=%d, the per-endpoint budget is exhausted so the probe keeps its classification", rec2.Retries, hits.Load())
	}
	wantVerdict(t, rec2, cc, OriginTarget, ReasonServiceUnavailable)
}

func TestRetry_MaxRequestsBudgetIsNeverExceededByARetry(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	budget.SetMaxRequests(2)
	rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	sent, rejected := budget.Stats()
	if hits.Load() != 2 || sent != 2 || rejected != 0 || rec.Retries != 1 {
		t.Fatalf("hits=%d sent=%d rejected=%d retries=%d: the retry stops before the --max-requests cap is hit", hits.Load(), sent, rejected, rec.Retries)
	}
	wantVerdict(t, rec, cc, OriginTarget, ReasonServiceUnavailable) // not scanner/not_sent
}

func TestRetry_ScanWideAllowanceIsBounded(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	maxScanRetries = 3
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(503) }))
	defer srv.Close()
	total := 0
	for i := 0; i < 5; i++ {
		rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL+"/p"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		total += rec.Retries
	}
	if total != 3 || cc.Audit.RetriesSpent() != 3 {
		t.Fatalf("retries spent %d (log says %d), want exactly the allowance of 3", total, cc.Audit.RetriesSpent())
	}
}

func TestRetry_BodyIsReplayedAndAnUnreplayableBodyIsNotRetried(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(503)
	}))
	defer srv.Close()
	post := func(body io.Reader) *http.Request {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, body)
		return req
	}
	_, pi, _ := probeDo(context.Background(), cc.Client, post(strings.NewReader("payload=1")), cc.Audit, srv.URL, cfg)
	if pi.Retries != 2 || len(bodies) != 3 || bodies[2] != "payload=1" {
		t.Fatalf("retries=%d bodies=%q: every retry must carry the same body", pi.Retries, bodies)
	}
	bodies = nil
	// A body that cannot be replayed (no GetBody) is sent once, never retried.
	req := post(io.NopCloser(strings.NewReader("payload=1")))
	_, pi, _ = probeDo(context.Background(), cc.Client, req, cc.Audit, srv.URL, cfg)
	if pi.Retries != 0 || len(bodies) != 1 {
		t.Fatalf("retries=%d bodies=%d, an unreplayable body is not retried", pi.Retries, len(bodies))
	}
}

func TestRetry_ScheduleIsDeterministic(t *testing.T) {
	// Identical target behaviour gives identical retry counts and verdicts.
	var seen []string
	for i := 0; i < 3; i++ {
		cc, cfg := probeTestEnv(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
		rec, resp, err := send(t, context.Background(), cc, cfg, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		srv.Close()
		v := ClassifyProbe(rec, cc.Audit)
		seen = append(seen, string(v.Origin)+"/"+string(v.Reason)+"/"+v.Evidence)
	}
	if seen[0] != seen[1] || seen[1] != seen[2] {
		t.Fatalf("non-deterministic: %v", seen)
	}
}

// ---- the account -----------------------------------------------------------

func TestSummarize_PartialResultsAndRepeatedNonResponses(t *testing.T) {
	cc, _ := probeTestEnv(t)
	t0 := time.Now()
	rec := func(ep string, status int, f *ProbeFailure) ProbeRecord {
		return ProbeRecord{Timestamp: t0, Endpoint: "http://t" + ep, Method: "GET", ProbeType: ProbeSQLi, Status: status, Failure: f}
	}
	reset := &ProbeFailure{Origin: OriginTarget, Reason: ReasonConnectionReset, Evidence: "reset"}
	records := []ProbeRecord{
		rec("/ok", 200, nil), rec("/ok", 404, nil), rec("/gone", 410, nil),
		rec("/a", 0, reset), rec("/a", 0, reset), rec("/a", 0, reset), // the same target non-response, repeated
		rec("/b", 503, nil),
		{Timestamp: t0, Endpoint: "http://t/c", Method: "GET", ProbeType: ProbeXSS, Failure: &ProbeFailure{Origin: OriginScanner, Reason: ReasonNotSent, Evidence: "x"}},
		{Timestamp: t0, Endpoint: "http://t/d", Method: "GET", ProbeType: ProbeSSRF, Failure: &ProbeFailure{Origin: OriginUnknown, Reason: ReasonDNSFailure, Evidence: "y"}},
	}
	cov := SummarizeProbes(records, cc.Audit)
	// Round 5: /ok 404 and /gone 410 are gated (not evaluated), so only the 200 is.
	if cov.Attempted != 9 || cov.Evaluated != 1 || cov.Inconclusive != 6 || cov.UnknownOrigin != 1 || cov.ScannerFailed != 1 {
		t.Fatalf("counts = %+v", cov)
	}
	if cov.Reasons["target"]["connection_reset"] != 3 || cov.Reasons["target"]["service_unavailable"] != 1 || cov.Reasons["target"]["gated"] != 2 {
		t.Fatalf("reasons = %+v", cov.Reasons)
	}
	// Distinct (check, endpoint, origin, reason), scanner first, then unknown, then target.
	if len(cov.NotEvaluatedChecks) != 6 || cov.NotEvaluatedChecks[0].Origin != "scanner" || cov.NotEvaluatedChecks[1].Origin != "unknown" {
		t.Fatalf("list = %+v", cov.NotEvaluatedChecks)
	}
	if cov.NotEvaluatedChecks[0].Check != "xss" || cov.NotEvaluatedChecks[0].Endpoint != "GET /c" {
		t.Fatalf("entry = %+v", cov.NotEvaluatedChecks[0])
	}
	if cov.Truncated {
		t.Fatal("not truncated")
	}
	// /ok answered 200 once and 404 once: its 404 probe is listed (gated), so the
	// list never proves that pair evaluated.
	var okEntries int
	for _, e := range cov.NotEvaluatedChecks {
		if strings.Contains(e.Endpoint, "/ok") {
			okEntries++
			if e.Reason != "gated" {
				t.Fatalf("/ok entry = %+v", e)
			}
		}
	}
	if okEntries != 1 {
		t.Fatalf("/ok entries = %d, want its gated probe listed once", okEntries)
	}
}

func TestSummarize_ListIsCappedAndSaysSo(t *testing.T) {
	cc, _ := probeTestEnv(t)
	var records []ProbeRecord
	for i := 0; i < models.ActiveProbeListCap+25; i++ {
		records = append(records, ProbeRecord{Timestamp: time.Now(), Endpoint: "http://t/e" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Method: "GET", ProbeType: ProbeSQLi,
			Failure: &ProbeFailure{Origin: OriginTarget, Reason: ReasonTimeout, Evidence: "t"}})
	}
	cov := SummarizeProbes(records, cc.Audit)
	if len(cov.NotEvaluatedChecks) != models.ActiveProbeListCap || !cov.Truncated {
		t.Fatalf("len=%d truncated=%v", len(cov.NotEvaluatedChecks), cov.Truncated)
	}
	if cov.Inconclusive != len(records) {
		t.Fatalf("the counts stay complete when the list is cut: %d of %d", cov.Inconclusive, len(records))
	}
}

func TestSummarize_RepositoryControlledNamesAreSanitised(t *testing.T) {
	cc, _ := probeTestEnv(t)
	cov := SummarizeProbes([]ProbeRecord{{Timestamp: time.Now(), Endpoint: "http://t/a;b…c\nd", Method: "GET", ProbeType: ProbeSQLi,
		Failure: &ProbeFailure{Origin: OriginTarget, Reason: ReasonTimeout, Evidence: "x;y"}}}, cc.Audit)
	e := cov.NotEvaluatedChecks[0]
	// URL parsing percent-encodes some of these; none of ';', the ellipsis or a
	// control character may survive.
	if strings.ContainsAny(e.Endpoint, ";\n") || strings.Contains(e.Endpoint, "…") || strings.Contains(e.Evidence, ";") {
		t.Fatalf("unsafe entry: %+v", e)
	}
}

func TestSummarize_AllEvaluatedLeavesEmptyLists(t *testing.T) {
	cc, _ := probeTestEnv(t)
	cov := SummarizeProbes([]ProbeRecord{{Timestamp: time.Now(), Endpoint: "http://t/a", Status: 200}}, cc.Audit)
	if cov.Evaluated != 1 || cov.NotEvaluatedChecks == nil || len(cov.NotEvaluatedChecks) != 0 || cov.Reasons == nil {
		t.Fatalf("cov = %+v (lists must be non-nil so the JSON carries arrays)", cov)
	}
}
