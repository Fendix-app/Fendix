package scanner

import (
	"net/http"
	"strings"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/budget"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/netguard"
)

// probeResponseLimit bounds the response excerpt an active probe stores on
// Evidence.Response. Large enough to carry the matched indicator with context,
// small enough that a hostile response cannot bloat the report.
const probeResponseLimit = 512

// ProbeExcerpt returns a bounded, control-character-free excerpt of what an
// active probe observed, for storage on evidence.Evidence.Response.
//
// WHY THIS EXISTS: confidence.payloadValidated requires BOTH Payload and
// Response, and the decision layer counts "payload-validated probe" as an
// INDEPENDENT corroborating signal. No production producer set Response, so
// both were dead — and the decision layer had been leaning on a tautology
// ("Source is blackbox") in their place, which is the RC-1 defect. Recording
// what came back is what makes the honest signal real.
//
// Response is Evidence-INTERNAL: evidence.ToFinding drops it, so it never
// reaches models.Finding, the JSON report or SARIF. It exists to justify a
// decision, not to be published.
//
// Deterministic by construction — a pure function of the input string — because
// it feeds a confidence score that must be reproducible across runs.
func ProbeExcerpt(body string) string {
	if len(body) > probeResponseLimit {
		body = body[:probeResponseLimit]
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, body)
}

// ProbeTimingExcerpt renders the timing differential that confirmed a
// timing-based probe (blind SQLi, SSRF hang detection) as the response
// observation.
//
// For a timing check the confirming observation is NOT the body — the body
// proves nothing and is often empty. It is the elapsed time relative to the
// threshold the check tested against. Recording that is truthful; recording an
// unread body would be fabrication, and recording nothing would leave the
// check unable to corroborate a differential it genuinely measured.
func ProbeTimingExcerpt(elapsed, threshold time.Duration) string {
	return "response delayed " + elapsed.Round(time.Millisecond).String() +
		" against a " + threshold.Round(time.Millisecond).String() + " threshold"
}

// allowPrivate returns the effective SSRF-guard policy for a scan: the guard
// is relaxed when the operator opted in with --allow-private-targets
// (cfg.AllowPrivate) OR when the primary --url target itself resolves to a
// private/loopback address. The latter is the auto-allow rule — scanning your
// own internal/staging/localhost target must keep working without an extra
// flag. cfg.URL is the operator's declared target; per-endpoint FullURLs are
// derived from it during discovery, so keying the heuristic off cfg.URL is
// sufficient and avoids per-request DNS lookups.
func allowPrivate(cfg *models.ScanConfig) bool {
	if cfg == nil {
		return false
	}
	if cfg.AllowPrivate {
		return true
	}
	return netguard.TargetIsPrivate(cfg.URL)
}

// guardedClient builds an *http.Client whose transport composes the budget
// counter over the SSRF egress guard, and whose CheckRedirect caps redirect
// hops and re-applies the IP policy on every hop. Every black-box check that
// makes outbound requests builds its client through here so SSRF protection
// (and the auto-allow heuristic) is applied uniformly.
func guardedClient(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	timeout := 0
	if cfg != nil {
		timeout = cfg.Timeout
	}
	return &http.Client{
		Timeout:       time.Duration(timeout) * time.Second,
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: netguard.Config{AllowPrivate: ap}.CheckRedirect(),
	}
}

// guardedClientNoFollow builds a client with the SAME guarded transport as
// guardedClient (budget over netguard SSRF policy) but does NOT follow
// redirects — it returns http.ErrUseLastResponse so the caller observes the
// raw 3xx. Used by checks where a redirect IS the signal (auth, idor,
// open-redirect, host-header). Timeout is 0 because the shared client relies
// on a per-job context deadline (see runCheck).
func guardedClientNoFollow(cfg *models.ScanConfig) *http.Client {
	ap := allowPrivate(cfg)
	return &http.Client{
		Timeout:       0,
		Transport:     budget.TransportGuarded(ap),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}
