package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/budget"
	"github.com/Fendix-app/Fendix/go/internal/netguard"
)

// Round 5, C4B-10: a redirect into an address the SSRF egress guard refuses is
// the TARGET's doing. The target answered and chose where to send the client;
// the scanner did not fail. Booked scanner-side it failed active-probes with a
// Fendix-owned gap, and a hostile target could produce that on demand.

// guardedClient is what a hosted scan builds: the redirect policy of
// netguard.Config{AllowPrivate: false}. The server under test is on loopback, so
// the dialer is a plain one (the first hop must connect); only the redirect hop
// is guarded.
func redirectGuardClient(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true}
	return &http.Client{
		Transport:     tr,
		Timeout:       3 * time.Second,
		CheckRedirect: netguard.Config{AllowPrivate: false}.CheckRedirect(),
	}
}

func TestOrigin_RedirectIntoBlockedAddressIsTargetSide(t *testing.T) {
	for _, loc := range []string{"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/x", "http://[::1]:1/x", "http://10.0.0.5/admin"} {
		cc, cfg := probeTestEnv(t)
		loc := loc
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loc, http.StatusFound)
		}))
		cc.Client = redirectGuardClient((&net.Dialer{}).DialContext)
		rec, _, err := send(t, context.Background(), cc, cfg, srv.URL)
		srv.Close()
		if err == nil {
			t.Fatalf("%s: the guard must refuse the hop", loc)
		}
		v := wantVerdict(t, rec, cc, OriginTarget, ReasonOtherTransport)
		if !strings.Contains(v.Evidence, "target redirected") {
			t.Fatalf("%s: evidence %q must say the target redirected the probe", loc, v.Evidence)
		}
		// A target-side non-answer: never a scanner or unknown-origin gap.
		cov := SummarizeProbes([]ProbeRecord{rec}, cc.Audit)
		if cov.ScannerFailed != 0 || cov.UnknownOrigin != 0 || cov.Inconclusive != 1 {
			t.Fatalf("%s: %+v", loc, cov)
		}
	}
}

// The dial of the redirected hop is refused (rather than the redirect check):
// a connection to the probe's own destination was already established, so the
// refusal is of a hop the target chose.
func TestOrigin_RedirectHopRefusedAtDialIsTargetSide(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://hop.example:81/", http.StatusFound)
	}))
	defer srv.Close()
	own := strings.TrimPrefix(srv.URL, "http://")
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == own {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		// The shape of netguard's blockedError, which is unexported.
		return nil, fmt.Errorf("netguard: refusing connection to %s (169.254.169.254): private/loopback/metadata address blocked (SSRF guard)", addr)
	}
	cc.Client = &http.Client{Transport: &http.Transport{DialContext: dial, DisableKeepAlives: true}, Timeout: 3 * time.Second}
	rec, _, err := send(t, context.Background(), cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("the hop must be refused")
	}
	wantVerdict(t, rec, cc, OriginTarget, ReasonOtherTransport)
}

// The probe's OWN destination refused by the guard never left the scanner: that
// stays scanner-side not_sent (nothing the target did).
func TestOrigin_RefusedOwnDestinationStaysNotSent(t *testing.T) {
	cc, cfg := probeTestEnv(t)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("netguard: refusing connection to %s (127.0.0.1): private/loopback/metadata address blocked (SSRF guard)", addr)
	}
	cc.Client = &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: 3 * time.Second}
	rec, _, err := send(t, context.Background(), cc, cfg, "http://example.invalid/")
	if err == nil {
		t.Fatal("the dial must be refused")
	}
	v := wantVerdict(t, rec, cc, OriginScanner, ReasonNotSent)
	if strings.ContainsRune(v.Evidence, ';') {
		t.Fatalf("evidence %q holds a ';', which the report sanitiser turns into '?'", v.Evidence)
	}
}

// Round 5, C4B-31: the --max-requests cap cancels the scan context. A probe it
// stopped before its request was written never left the scanner and is labelled
// not_sent (the documented label), naming the budget; one already on the wire is
// cut in flight (scan_cancelled) and also names the budget. Neither is ever the
// target's doing, and neither is labelled a bare interrupt.
func TestOrigin_RequestBudgetExhaustionIsLabelledAsTheBudget(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	cc, cfg := probeTestEnv(t)
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var probes sync.WaitGroup
	// Join both probes before probeTestEnv restores the globals they read.
	// Cleanup also joins them if an assertion exits this test early.
	t.Cleanup(func() {
		cancel()
		probes.Wait()
	})
	SetScanContext(scanCtx)
	cc.Audit = currentAuditLog()
	budget.Reset()
	budget.SetMaxRequests(2)
	budget.SetCancelFunc(cancel)
	defer budget.SetCancelFunc(nil)
	// The scanner's client is the budget's: wrap the transport as the engine does.
	cc.Client = &http.Client{Transport: budget.WrapTransport(http.DefaultTransport), Timeout: 5 * time.Second}

	inflight := make(chan ProbeRecord, 1)
	probes.Add(1)
	go func() {
		defer probes.Done()
		rec, _, _ := send(t, scanCtx, cc, cfg, srv.URL) // request 1: written, then the cap cancels it
		inflight <- rec
	}()
	time.Sleep(150 * time.Millisecond)
	// Request 2 is allowed (and hangs); request 3 is over the cap and fires the cancel.
	probes.Add(1)
	go func() {
		defer probes.Done()
		_, _, _ = send(t, scanCtx, cc, cfg, srv.URL)
	}()
	time.Sleep(100 * time.Millisecond)
	refused, _, err := send(t, scanCtx, cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("request 3 must be over the cap")
	}
	v := wantVerdict(t, refused, cc, OriginScanner, ReasonNotSent)
	if !strings.Contains(v.Evidence, "--max-requests") {
		t.Fatalf("evidence %q must name the budget", v.Evidence)
	}
	var cut ProbeRecord
	select {
	case cut = <-inflight:
	case <-time.After(3 * time.Second):
		t.Fatal("the in-flight probe was not released by the cancel")
	}
	v = wantVerdict(t, cut, cc, OriginScanner, ReasonScanCancelled)
	if !strings.Contains(v.Evidence, "--max-requests") {
		t.Fatalf("in-flight evidence %q must name the budget", v.Evidence)
	}
	// After the cancel, a new probe never leaves the scanner: not_sent, naming the budget.
	late, _, err := send(t, scanCtx, cc, cfg, srv.URL)
	if err == nil {
		t.Fatal("a probe after the cancel must not be sent")
	}
	v = wantVerdict(t, late, cc, OriginScanner, ReasonNotSent)
	if !strings.Contains(v.Evidence, "--max-requests") {
		t.Fatalf("late evidence %q must name the budget", v.Evidence)
	}
}
