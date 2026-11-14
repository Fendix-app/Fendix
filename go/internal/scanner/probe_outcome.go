package scanner

// Probe outcomes: what an active probe that got no useful answer means, and
// who is at fault.
//
// A probe the target never answered is NOT a successful evaluation: nothing was
// learned about the vulnerability it tested for. It is also not automatically a
// scanner gap: a target that resets, stalls or rate-limits a probe is behaving
// the way the target behaves, and punishing the scan (or refunding it) for that
// would let a hostile target steer the verdict. The origin of every failure is
// therefore established from EVIDENCE about what happened on the wire, never
// from the Go error type alone:
//
//	scanner  the engine itself failed or never sent the probe
//	target   the target is alive and chose not to answer this probe usefully
//	unknown  nothing settles it; fail-closed, counted like a scanner failure
//
// The rules (every rule is exercised by probe_outcome_test.go):
//
//	SCANNER
//	  internal_error        a scanner check panicked
//	  scan_deadline         the scan's own --max-duration context expired
//	  scan_cancelled        the scan context was cancelled (request budget, interrupt)
//	  resource_exhausted    EMFILE, ENFILE, ENOMEM, ENOBUFS or EADDRNOTAVAIL (ephemeral ports)
//	  proxy_failure         the failure happened dialling a configured proxy
//	  request_construction  the request could not be built, or was rejected before any connection attempt
//	  not_sent              the probe never left the scanner (--max-requests budget, the SSRF egress guard
//	                        refusing the probe's own destination)
//	TARGET (the connection, and TLS when used, was established unless stated)
//	  gated                 the target answered HTTP 401, 403, 404 or 410: the request was refused or the
//	                        path is not served to this client. A gated probe is NOT evaluated and proves
//	                        nothing about the parameter it tested (never "safe", never "fixed")
//	  timeout               accepted the connection, then sent no response before the per-request deadline;
//	                        also a connect timeout when another request to the host succeeded within 30 s
//	  connection_reset      reset, closed or GOAWAY after the connection was established
//	  connection_refused    only when another request to the host succeeded within 30 s
//	  tls_error             a TLS alert sent by the peer
//	  rate_limited          HTTP 429 after the bounded retries
//	  service_unavailable   HTTP 502, 503 or 504 after the bounded retries
//	  other_transport       a malformed or broken response, a redirect chain past the limit, or a redirect
//	                        into an address the SSRF egress guard refuses (the target chose where to send
//	                        the probe; it is never the scanner's doing)
//	UNKNOWN
//	  dns_failure           name resolution failed
//	  timeout               a connect timeout, no request to the host succeeded within 30 s
//	  connection_refused    refused, no request to the host succeeded within 30 s
//	  network_unreachable   ENETUNREACH, EHOSTUNREACH, ENETDOWN
//	  tls_handshake         the handshake did not complete and no peer alert arrived (including certificate verification)
//	  unclassified          a transport error with no connection established, or a probe recorded with no response and no evidence
//
// The "same host succeeded within 30 s" clause is resolved when the scan is
// summarised (SummarizeProbes), not when the probe fails, so the verdict does
// not depend on the order concurrent requests happened to finish in.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/Fendix-app/Fendix/go/internal/budget"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ProbeOrigin says who is at fault for a probe that was not evaluated.
type ProbeOrigin string

const (
	OriginScanner ProbeOrigin = "scanner"
	OriginTarget  ProbeOrigin = "target"
	OriginUnknown ProbeOrigin = "unknown"
)

// ProbeReason is the closed reason vocabulary. A reason names what was
// observed; the origin (above) says who is at fault, so the same reason can
// land in different origins depending on evidence.
type ProbeReason string

const (
	// Scanner-side.
	ReasonInternalError       ProbeReason = "internal_error"
	ReasonScanDeadline        ProbeReason = "scan_deadline"
	ReasonScanCancelled       ProbeReason = "scan_cancelled"
	ReasonResourceExhausted   ProbeReason = "resource_exhausted"
	ReasonProxyFailure        ProbeReason = "proxy_failure"
	ReasonRequestConstruction ProbeReason = "request_construction"
	ReasonNotSent             ProbeReason = "not_sent"
	// Target-side, and shared with unknown where noted.
	ReasonGated              ProbeReason = "gated"
	ReasonTimeout            ProbeReason = "timeout" // also unknown
	ReasonConnectionReset    ProbeReason = "connection_reset"
	ReasonConnectionRefused  ProbeReason = "connection_refused" // also unknown
	ReasonTLSError           ProbeReason = "tls_error"
	ReasonRateLimited        ProbeReason = "rate_limited"
	ReasonServiceUnavailable ProbeReason = "service_unavailable"
	ReasonOtherTransport     ProbeReason = "other_transport"
	// Unknown-origin only.
	ReasonDNSFailure         ProbeReason = "dns_failure"
	ReasonNetworkUnreachable ProbeReason = "network_unreachable"
	ReasonTLSHandshake       ProbeReason = "tls_handshake"
	ReasonUnclassified       ProbeReason = "unclassified"
)

// Fixed listing orders, used by the scanner-status detail and the metadata.
var (
	TargetReasonOrder  = []ProbeReason{ReasonTimeout, ReasonConnectionReset, ReasonConnectionRefused, ReasonTLSError, ReasonRateLimited, ReasonServiceUnavailable, ReasonOtherTransport}
	UnknownReasonOrder = []ProbeReason{ReasonDNSFailure, ReasonTimeout, ReasonConnectionRefused, ReasonNetworkUnreachable, ReasonTLSHandshake, ReasonUnclassified}
	ScannerReasonOrder = []ProbeReason{ReasonInternalError, ReasonScanDeadline, ReasonScanCancelled, ReasonResourceExhausted, ReasonProxyFailure, ReasonRequestConstruction, ReasonNotSent}
)

// ProbeFailure is why a probe has no usable response, with the evidence that
// settled the origin.
type ProbeFailure struct {
	Origin   ProbeOrigin `json:"origin"`
	Reason   ProbeReason `json:"reason"`
	Evidence string      `json:"evidence"`
	// refinable marks an unknown-origin pre-connect timeout or refusal whose
	// origin the "same host answered something else" clause may still settle.
	refinable bool
}

// Window is how close in time another successful request to the same host must
// be for a pre-connect timeout or refusal to count as the target's behaviour.
const targetHealthWindow = 30 * time.Second

// ---- retry policy ---------------------------------------------------------

// Retry policy for probes that get a retryable non-answer (contract C5.5).
// These are variables only so tests can shrink the sleeps; production never
// changes them, and there is no public flag.
var (
	// probeBackoffs is the pause before retry 1 and retry 2.
	probeBackoffs = [...]time.Duration{1 * time.Second, 2 * time.Second}
	// probeRetryAfterCap caps a Retry-After the target asks for.
	probeRetryAfterCap = 5 * time.Second
	// maxScanRetries bounds the retries a whole scan may spend (a resource
	// limit: a target that fails everything cannot make the scan sleep and
	// resend without bound).
	maxScanRetries = 200
)

// maxProbeRetries is the retry count per probe.
const maxProbeRetries = 2

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// ---- tracing --------------------------------------------------------------

// probeTrace is what one attempt observably did, read from httptrace. It is the
// evidence the origin rules are applied to.
type traceFacts struct {
	gotConn      bool // connection (and TLS, when used) established or reused
	getConn      bool // the transport started looking for a connection at all
	tlsStarted   bool
	tlsDone      bool
	wroteRequest bool
}

type probeTrace struct {
	mu sync.Mutex
	traceFacts
}

func (t *probeTrace) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn:           func(string) { t.mu.Lock(); t.getConn = true; t.mu.Unlock() },
		GotConn:           func(httptrace.GotConnInfo) { t.mu.Lock(); t.gotConn = true; t.mu.Unlock() },
		TLSHandshakeStart: func() { t.mu.Lock(); t.tlsStarted = true; t.mu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.mu.Lock()
			t.tlsDone = err == nil
			t.mu.Unlock()
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { t.mu.Lock(); t.wroteRequest = true; t.mu.Unlock() },
	}
}

func (t *probeTrace) snapshot() traceFacts {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.traceFacts
}

// ---- classification -------------------------------------------------------

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isResourceErr(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM, syscall.ENOBUFS, syscall.EADDRNOTAVAIL} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func isUnreachableErr(err error) bool {
	for _, e := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func isResetErr(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	// HTTP/2 carries a reset or GOAWAY as typed-but-unexported errors.
	msg := err.Error()
	return strings.Contains(msg, "GOAWAY") || strings.Contains(msg, "stream error") || strings.Contains(msg, "RST_STREAM") ||
		strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe")
}

func isProxyErr(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "proxyconnect"
}

func isTLSAlertErr(err error) bool {
	var ae tls.AlertError
	if errors.As(err, &ae) {
		return true
	}
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "remote error"
}

func isCertErr(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci)
}

// isEgressRefusal reports the SSRF egress guard refusing a destination (the
// guard's error type is unexported; its message is the engine's own).
func isEgressRefusal(err error) bool {
	return strings.Contains(err.Error(), "netguard: refusing connection")
}

func isRedirectCap(err error) bool {
	return strings.Contains(err.Error(), "netguard: stopped after")
}

// budgetExhausted reports that the scan's --max-requests cap was reached: the
// budget refused at least one request (the first refusal also cancels the scan
// context, which is how in-flight probes see it).
func budgetExhausted() bool {
	if budget.MaxRequests() <= 0 {
		return false
	}
	_, rejected := budget.Stats()
	return rejected > 0
}

func failure(o ProbeOrigin, r ProbeReason, evidence string) ProbeFailure {
	return ProbeFailure{Origin: o, Reason: r, Evidence: evidence}
}

// classifyTransportError applies the origin rules to one failed attempt.
// resp is the (closed) response a failed redirect policy leaves behind, or nil.
// scanCtx is the whole scan's context (nil when unknown).
func classifyTransportError(err error, resp *http.Response, tr traceFacts, scanCtx context.Context) ProbeFailure {
	// A failed redirect check: the target answered with a redirect and the
	// engine's policy refused to follow it (the egress guard) or hit the hop cap.
	if resp != nil {
		switch {
		case isEgressRefusal(err):
			return failure(OriginTarget, ReasonOtherTransport, "the target redirected the probe to an address the SSRF egress guard refuses")
		case isRedirectCap(err):
			return failure(OriginTarget, ReasonOtherTransport, "the target's redirect chain exceeded the hop limit")
		}
	}
	switch {
	case errors.Is(err, budget.ErrBudgetExceeded):
		return failure(OriginScanner, ReasonNotSent, "the probe was refused by the --max-requests budget and never sent")
	case isEgressRefusal(err):
		if tr.gotConn {
			// A connection to the probe's own destination was already
			// established, so this is a later hop: the target redirected the
			// client and the dial of the hop was refused.
			return failure(OriginTarget, ReasonOtherTransport, "the target redirected the probe to an address the SSRF egress guard refuses")
		}
		return failure(OriginScanner, ReasonNotSent, "the SSRF egress guard refused the destination and the probe was never sent")
	}
	if isCtxErr(err) {
		if scanCtx != nil && scanCtx.Err() != nil {
			if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
				return failure(OriginScanner, ReasonScanDeadline, "the scan's --max-duration elapsed while the probe was in flight")
			}
			if budgetExhausted() {
				// The --max-requests cap cancels the scan context. A probe it
				// stopped before the request was written never left the
				// scanner (not_sent); one already written was cut in flight.
				if !tr.wroteRequest {
					return failure(OriginScanner, ReasonNotSent, "the --max-requests budget was exhausted and the probe was never sent")
				}
				return failure(OriginScanner, ReasonScanCancelled, "the --max-requests budget was exhausted while the probe was in flight")
			}
			return failure(OriginScanner, ReasonScanCancelled, "the scan was cancelled while the probe was in flight")
		}
		if errors.Is(err, context.Canceled) {
			// Only the engine cancels contexts; a target cannot.
			return failure(OriginScanner, ReasonScanCancelled, "the probe's context was cancelled by the engine")
		}
		// A deadline that is not the scan's: the per-request deadline. Judged
		// below by what the connection did.
	}
	switch {
	case isResourceErr(err):
		return failure(OriginScanner, ReasonResourceExhausted, "local resource exhausted (file descriptors, memory, buffers or ephemeral ports)")
	case isProxyErr(err):
		return failure(OriginScanner, ReasonProxyFailure, "the configured proxy failed before the target was reached")
	case !tr.getConn && !isTimeoutErr(err):
		return failure(OriginScanner, ReasonRequestConstruction, "the request was rejected before any connection attempt")
	}
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return failure(OriginUnknown, ReasonDNSFailure, "name resolution failed")
	case isTLSAlertErr(err):
		return failure(OriginTarget, ReasonTLSError, "the peer sent a TLS alert")
	case isCertErr(err) || (tr.tlsStarted && !tr.tlsDone && !tr.gotConn):
		return failure(OriginUnknown, ReasonTLSHandshake, "the TLS handshake did not complete and the peer sent no alert")
	case isTimeoutErr(err):
		if tr.gotConn {
			if tr.wroteRequest {
				return failure(OriginTarget, ReasonTimeout, "the connection was accepted and the request sent, no response before the per-request deadline")
			}
			return failure(OriginTarget, ReasonTimeout, "the connection was accepted, the target stalled before reading the request")
		}
		f := failure(OriginUnknown, ReasonTimeout, "the connect timed out and no request to this host succeeded within 30s")
		f.refinable = true
		return f
	case errors.Is(err, syscall.ECONNREFUSED) && !tr.gotConn:
		f := failure(OriginUnknown, ReasonConnectionRefused, "the connection was refused and no request to this host succeeded within 30s")
		f.refinable = true
		return f
	case isUnreachableErr(err):
		return failure(OriginUnknown, ReasonNetworkUnreachable, "the network or host was unreachable")
	}
	if tr.gotConn {
		if isResetErr(err) {
			return failure(OriginTarget, ReasonConnectionReset, "the connection was reset or closed by the peer after it was established")
		}
		return failure(OriginTarget, ReasonOtherTransport, "a malformed or broken response arrived on an established connection")
	}
	return failure(OriginUnknown, ReasonUnclassified, "a transport error occurred before any connection was established")
}

// ProbeError carries the classified failure out of probeDo while keeping the
// original error reachable with errors.Is / errors.As.
type ProbeError struct {
	Failure ProbeFailure
	Err     error
}

func (e *ProbeError) Error() string { return e.Err.Error() }
func (e *ProbeError) Unwrap() error { return e.Err }

// FailureOf returns the classification probeDo attached to err, or a
// fail-closed unknown/unclassified one for an error that never went through it.
func FailureOf(err error) ProbeFailure {
	var pe *ProbeError
	if errors.As(err, &pe) {
		return pe.Failure
	}
	return failure(OriginUnknown, ReasonUnclassified, "an error with no classification evidence")
}

// ---- sending --------------------------------------------------------------

// probeInfo is what probeDo learned beyond the response.
type probeInfo struct {
	// Retries is how many times the probe was re-sent.
	Retries int
	// Failure is the classification of the final failed attempt (nil when the
	// probe got an HTTP response).
	Failure *ProbeFailure
}

// apply copies the outcome onto the audit record the caller is about to write.
func (pi probeInfo) apply(r *ProbeRecord) {
	r.Retries = pi.Retries
	if pi.Failure != nil {
		f := *pi.Failure
		r.Failure = &f
	}
}

func cloneForRetry(req *http.Request) (*http.Request, bool) {
	r := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, false
		}
		b, err := req.GetBody()
		if err != nil {
			return nil, false
		}
		r.Body = b
	}
	return r, true
}

func retryAfter(h http.Header) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// probeDo sends one active probe with the bounded retry policy and classifies
// what happens. It replaces client.Do at every probe send site.
//
// A 429/502/503/504, a reset after the connection was established, or a timeout
// on an accepted connection is retried up to maxProbeRetries times, after
// probeBackoffs[0] then probeBackoffs[1] (a Retry-After is honoured, capped at
// probeRetryAfterCap). The schedule is deterministic. A retry is skipped, and
// the probe keeps its last classification, when ANY of these is exhausted:
//
//   - the context: cancelled, or its deadline is not further away than the pause
//   - the per-target request budget: the per-endpoint probe cap
//     (--max-probes-per-endpoint) is shared with retries, so a retry never sends
//     a request the cap would have refused
//   - the scan's --max-requests budget
//   - the scan-wide retry allowance (maxScanRetries)
//   - a request body that cannot be replayed
func probeDo(ctx context.Context, client *http.Client, req *http.Request, log *ProbeAuditLog, endpointURL string, cfg *models.ScanConfig) (*http.Response, probeInfo, error) {
	var info probeInfo
	capProbes := effectiveMaxProbes(cfg)
	cur := req
	// A probe whose context already ended never leaves the scanner: the engine's
	// own deadline or cancellation, not anything the target did.
	if err := ctx.Err(); err != nil {
		f := failure(OriginScanner, ReasonNotSent, "the probe's context ended before it was sent")
		if sc := log.scanContext(); sc != nil && errors.Is(sc.Err(), context.DeadlineExceeded) {
			f = failure(OriginScanner, ReasonScanDeadline, "the scan's --max-duration elapsed before the probe was sent")
		} else if budgetExhausted() {
			f = failure(OriginScanner, ReasonNotSent, "the --max-requests budget was exhausted and the probe was never sent")
		}
		info.Failure = &f
		return nil, info, &ProbeError{Failure: f, Err: err}
	}
	for attempt := 0; ; attempt++ {
		tr := &probeTrace{}
		traced := cur.WithContext(httptrace.WithClientTrace(cur.Context(), tr.hooks()))
		resp, err := client.Do(traced)

		var retry bool
		var pause time.Duration
		if attempt < maxProbeRetries {
			pause = probeBackoffs[attempt]
		}
		if err != nil {
			f := classifyTransportError(err, resp, tr.snapshot(), log.scanContext())
			info.Failure = &f
			retry = f.Origin == OriginTarget && (f.Reason == ReasonConnectionReset || f.Reason == ReasonTimeout)
			err = &ProbeError{Failure: f, Err: err}
		} else {
			info.Failure = nil
			if retryableStatus(resp.StatusCode) {
				retry = true
				if d, ok := retryAfter(resp.Header); ok {
					pause = d
					if pause > probeRetryAfterCap {
						pause = probeRetryAfterCap
					}
				}
			}
		}
		if !retry || attempt >= maxProbeRetries || !retryAllowed(ctx, log, endpointURL, capProbes, pause) {
			return resp, info, err
		}
		next, ok := cloneForRetry(req)
		if !ok {
			return resp, info, err
		}
		// Wait with the previous response still open: if the context ends
		// mid-pause the caller gets that response, with its classification.
		if !sleepCtx(ctx, pause) {
			return resp, info, err
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		log.noteRetry(endpointURL)
		info.Retries++
		cur = next
	}
}

// retryAllowed reports whether one more request may be sent for this probe.
func retryAllowed(ctx context.Context, log *ProbeAuditLog, endpointURL string, capProbes int, pause time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	// Deadline propagation: a retry that cannot finish its pause before the
	// deadline is never started, so a retry never sleeps past it.
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= pause {
		return false
	}
	if scan := log.scanContext(); scan != nil {
		if scan.Err() != nil {
			return false
		}
		if dl, ok := scan.Deadline(); ok && time.Until(dl) <= pause {
			return false
		}
	}
	// --max-requests: the retry itself must fit.
	if capReq := budget.MaxRequests(); capReq > 0 {
		if sent, _ := budget.Stats(); sent+1 > capReq {
			return false
		}
	}
	// The probe in flight is not recorded yet and the retry is one more request.
	return log.reserveRetry(endpointURL, capProbes)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- scan-wide state on the audit log ------------------------------------

// probeState is the retry accounting, scan context and target-health record
// that ride on the scan-wide ProbeAuditLog (so one reset clears them all).
type probeState struct {
	mu           sync.Mutex
	scanCtx      context.Context
	retries      map[string]int
	retriesTotal int
	health       map[string]map[int64]struct{}
	healthSize   int
}

const healthMaxEntries = 200_000

func (s *probeState) scanContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanCtx
}

// SetScanContext tells the audit log which context is the whole scan's, so an
// expired probe context can be attributed to the engine's own deadline.
func (a *ProbeAuditLog) SetScanContext(ctx context.Context) {
	a.state.mu.Lock()
	a.state.scanCtx = ctx
	a.state.mu.Unlock()
}

func (a *ProbeAuditLog) scanContext() context.Context { return a.state.scanContext() }

// reserveRetry takes one retry out of the per-endpoint cap (shared with the
// probes already recorded) and the scan-wide allowance. It reports false, and
// takes nothing, when either is spent.
func (a *ProbeAuditLog) reserveRetry(endpoint string, capProbes int) bool {
	a.state.mu.Lock()
	retriesHere := a.state.retries[endpoint]
	total := a.state.retriesTotal
	a.state.mu.Unlock()
	if total >= maxScanRetries {
		return false
	}
	// in-flight probe (1) + this retry (1) + recorded probes + retries so far.
	return a.countRecords(endpoint)+retriesHere+2 <= capProbes
}

func (a *ProbeAuditLog) noteRetry(endpoint string) {
	a.state.mu.Lock()
	if a.state.retries == nil {
		a.state.retries = map[string]int{}
	}
	a.state.retries[endpoint]++
	a.state.retriesTotal++
	a.state.mu.Unlock()
}

// RetriesSpent is the number of retries the scan has sent so far.
func (a *ProbeAuditLog) RetriesSpent() int {
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	return a.state.retriesTotal
}

// NoteTargetResponse records that a request to host got an HTTP response (any
// status) at t: evidence the target is alive.
func (a *ProbeAuditLog) NoteTargetResponse(host string, t time.Time) {
	host = strings.ToLower(host)
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	if a.state.healthSize >= healthMaxEntries {
		return
	}
	if a.state.health == nil {
		a.state.health = map[string]map[int64]struct{}{}
	}
	m := a.state.health[host]
	if m == nil {
		m = map[int64]struct{}{}
		a.state.health[host] = m
	}
	sec := t.Unix()
	if _, ok := m[sec]; !ok {
		m[sec] = struct{}{}
		a.state.healthSize++
	}
}

func (a *ProbeAuditLog) answeredNear(host string, t time.Time) bool {
	host = strings.ToLower(host)
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	m := a.state.health[host]
	if len(m) == 0 {
		return false
	}
	w := int64(targetHealthWindow / time.Second)
	for s := t.Unix() - w; s <= t.Unix()+w; s++ {
		if _, ok := m[s]; ok {
			return true
		}
	}
	return false
}

// SetScanContext tells the current scan-wide audit log the scan's context.
func SetScanContext(ctx context.Context) { currentAuditLog().SetScanContext(ctx) }

// observedTransport records every HTTP response any check or the crawler gets
// from a host, the "the target is alive" evidence the origin rules use.
type observedTransport struct{ inner http.RoundTripper }

// ObserveTransport wraps rt so each response it returns is noted as evidence
// that the target answered.
func ObserveTransport(rt http.RoundTripper) http.RoundTripper { return observedTransport{inner: rt} }

func (o observedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := o.inner.RoundTrip(req)
	if err == nil && req.URL != nil {
		currentAuditLog().NoteTargetResponse(req.URL.Host, time.Now())
	}
	return resp, err
}

// RecordScannerFailure records a probe-level failure the engine itself caused
// that has no HTTP attempt to classify, for example a check that panicked.
func RecordScannerFailure(check, endpointURL string, reason ProbeReason, evidence string) {
	f := failure(OriginScanner, reason, evidence)
	currentAuditLog().Record(ProbeRecord{
		Timestamp: time.Now(),
		Endpoint:  endpointURL,
		Check:     check,
		Payload:   "(check did not complete)",
		Failure:   &f,
	})
}

// recordBuildFailure records a probe whose request could not be built: it
// never left the scanner.
func recordBuildFailure(log *ProbeAuditLog, endpointURL string, pt ProbeType, payload, param, method string) {
	f := failure(OriginScanner, ReasonRequestConstruction, "the probe request could not be built")
	log.Record(ProbeRecord{Timestamp: time.Now(), Endpoint: endpointURL, ProbeType: pt, Payload: payload, Parameter: param, Method: method, Failure: &f})
}

// ---- summarising ----------------------------------------------------------

// checkOfProbe is the rule-id family of the findings a probe type can produce.
func checkOfProbe(r ProbeRecord) string {
	if r.Check != "" {
		return r.Check
	}
	switch r.ProbeType {
	case ProbeSQLi, ProbeCMDi, ProbeCRLF:
		return "injection"
	case ProbeRedirect:
		return "openredirect"
	case ProbeXSS:
		return "xss"
	case ProbeSSRF:
		return "ssrf"
	case ProbeHostHeader:
		return "hostheader"
	case ProbeGraphQL:
		return "graphql"
	case ProbeMethodTamper:
		return "methodtamper"
	}
	return string(r.ProbeType)
}

// sanitizeField makes a repository- or target-controlled string safe for the
// report: ';', the ellipsis, control characters and newlines become '?', and it
// is cut to max bytes on a rune boundary.
func sanitizeField(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ';' || r == '…' || r < 0x20 || r == 0x7f || r == utf8.RuneError:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) <= max {
		return out
	}
	out = out[:max]
	for !utf8.ValidString(out) {
		out = out[:len(out)-1]
	}
	return out
}

func endpointLabel(r ProbeRecord) string {
	path := "/"
	if u, err := url.Parse(r.Endpoint); err == nil && u.Path != "" {
		path = u.Path
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	return sanitizeField(method+" "+path, 200)
}

func hostOf(endpointURL string) string {
	if u, err := url.Parse(endpointURL); err == nil {
		return u.Host
	}
	return ""
}

// ProbeVerdict is one probe's place in the account.
type ProbeVerdict struct {
	Evaluated bool
	Origin    ProbeOrigin
	Reason    ProbeReason
	Evidence  string
}

// ClassifyProbe decides whether a recorded probe was evaluated and, when it was
// not, who is at fault. log supplies the "target answered other requests
// nearby" evidence (nil: none).
func ClassifyProbe(r ProbeRecord, log *ProbeAuditLog) ProbeVerdict {
	if r.Failure != nil {
		f := *r.Failure
		if f.Origin == OriginUnknown && f.refinable && log != nil && log.answeredNear(hostOf(r.Endpoint), r.Timestamp) {
			f.Origin = OriginTarget
			switch f.Reason {
			case ReasonTimeout:
				f.Evidence = "the connect timed out while other requests to this host succeeded within 30s"
			case ReasonConnectionRefused:
				f.Evidence = "the connection was refused while other requests to this host succeeded within 30s"
			}
		}
		return ProbeVerdict{Origin: f.Origin, Reason: f.Reason, Evidence: f.Evidence}
	}
	if r.Status == 0 {
		return ProbeVerdict{Origin: OriginUnknown, Reason: ReasonUnclassified, Evidence: "the probe was recorded with no response and no failure evidence"}
	}
	if !r.Finding && retryableStatus(r.Status) {
		reason := ReasonServiceUnavailable
		if r.Status == http.StatusTooManyRequests {
			reason = ReasonRateLimited
		}
		ev := "HTTP " + strconv.Itoa(r.Status) + " after " + strconv.Itoa(r.Retries) + " retries"
		if r.Retries == 1 {
			ev = "HTTP " + strconv.Itoa(r.Status) + " after 1 retry"
		}
		return ProbeVerdict{Origin: OriginTarget, Reason: reason, Evidence: ev}
	}
	if !r.Finding && IsGatedStatus(r.Status) {
		return ProbeVerdict{Origin: OriginTarget, Reason: ReasonGated, Evidence: gatedEvidence(r.Status)}
	}
	return ProbeVerdict{Evaluated: true}
}

// IsGatedStatus reports whether an HTTP status gates a probe: the target
// refused the request or does not serve the path to this client, so the answer
// says nothing about the parameter the probe tested. The list is closed
// (models.GatedStatuses) and has no other member.
func IsGatedStatus(code int) bool {
	for _, g := range models.GatedStatuses {
		if code == g {
			return true
		}
	}
	return false
}

func gatedEvidence(code int) string {
	word := map[int]string{401: "authentication required", 403: "forbidden", 404: "not found", 410: "gone"}[code]
	return "the target answered HTTP " + strconv.Itoa(code) + " (" + word + "), so the probe was gated and nothing was evaluated"
}

var originRank = map[ProbeOrigin]int{OriginScanner: 0, OriginUnknown: 1, OriginTarget: 2}

// SummarizeProbes builds the active-probe coverage account from the audit
// records. Deterministic: the result depends on the records and the health
// evidence, not on the order concurrent probes finished in.
func SummarizeProbes(records []ProbeRecord, log *ProbeAuditLog) models.ActiveProbeCoverage {
	cov := models.ActiveProbeCoverage{
		Attempted:          len(records),
		Reasons:            map[string]map[string]int{},
		NotEvaluatedChecks: []models.NotEvaluatedCheck{},
		Gated:              models.ProbeGated{ByStatus: map[string]int{}},
	}
	// One entry per (check, endpoint, origin, reason). The evidence kept is the
	// smallest of the group, so the entry does not depend on probe order.
	type key struct{ check, endpoint, origin, reason string }
	byKey := map[key]string{}
	for _, r := range records {
		v := ClassifyProbe(r, log)
		if v.Evaluated {
			cov.Evaluated++
			continue
		}
		switch v.Origin {
		case OriginTarget:
			cov.Inconclusive++
		case OriginScanner:
			cov.ScannerFailed++
		default:
			cov.UnknownOrigin++
		}
		if v.Origin == OriginTarget && v.Reason == ReasonGated {
			cov.Gated.Total++
			cov.Gated.ByStatus[strconv.Itoa(r.Status)]++
		}
		o := string(v.Origin)
		if cov.Reasons[o] == nil {
			cov.Reasons[o] = map[string]int{}
		}
		cov.Reasons[o][string(v.Reason)]++
		k := key{checkOfProbe(r), endpointLabel(r), o, string(v.Reason)}
		ev := sanitizeField(v.Evidence, 160)
		if cur, ok := byKey[k]; !ok || ev < cur {
			byKey[k] = ev
		}
	}
	var entries []models.NotEvaluatedCheck
	for k, ev := range byKey {
		entries = append(entries, models.NotEvaluatedCheck{Check: k.check, Endpoint: k.endpoint, Origin: k.origin, Reason: k.reason, Evidence: ev})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if ra, rb := originRank[ProbeOrigin(a.Origin)], originRank[ProbeOrigin(b.Origin)]; ra != rb {
			return ra < rb
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.Evidence < b.Evidence
	})
	if len(entries) > models.ActiveProbeListCap {
		entries = entries[:models.ActiveProbeListCap]
		cov.Truncated = true
	}
	if entries != nil {
		cov.NotEvaluatedChecks = entries
	}
	return cov
}

// SummarizeGlobalProbes summarises the scan-wide audit log.
func SummarizeGlobalProbes() models.ActiveProbeCoverage {
	log := currentAuditLog()
	return SummarizeProbes(log.Records(), log)
}

// RuleFamilyOfCheck maps a registry check name to the rule-id family its
// findings carry (the names differ for the hyphenated checks).
func RuleFamilyOfCheck(name string) string {
	switch name {
	case "open-redirect":
		return "openredirect"
	case "host-header":
		return "hostheader"
	case "method-tamper":
		return "methodtamper"
	}
	return name
}
