package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

const rateLimitProbeCount = 20

// rateLimitMinProbes is the floor of successfully-completed probe
// requests required before we will conclude "no rate limiting observed".
// 5.6 — if the request budget (--max-requests) is exhausted mid-loop or
// the server/transport errors on most probes, too few requests actually
// reach the target to draw any conclusion; emitting a finding then is a
// false "unprotected". Below this floor the check returns nil
// (inconclusive). Half the probe count, but never fewer than 5.
const rateLimitMinProbes = rateLimitProbeCount / 2

// staticFilePathRe / isStaticAssetPath now live in responsecontext.go, shared
// with the header and CORS checks' B4 de-escalation tagging.

// rateLimitHeaders are headers that indicate rate limiting is in place.
var rateLimitHeaders = []string{
	"X-RateLimit-Limit",
	"X-RateLimit-Remaining",
	"X-RateLimit-Reset",
	"X-Rate-Limit-Limit",
	"X-Rate-Limit-Remaining",
	"X-Rate-Limit-Reset",
	"Retry-After",
	"RateLimit-Limit",
	"RateLimit-Remaining",
	"RateLimit-Reset",
}

// rateLimitProbeMethod decides which verb this check may burst at an
// operation, and whether it may burst at all.
//
// The check used to send a hardcoded GET and then label the finding with the
// operation's own method, so Fendix reported "No rate limiting observed" for
// "POST /login" having never sent a POST — a claim about a test that did not
// happen. Probing the labelled verb is the fix, but it cannot be unconditional:
// this check is TierPassive ("always on") and it sends a BURST of
// rateLimitProbeCount requests, so probing the real verb everywhere would make
// a passive scan issue twenty writes against a production target.
//
// The policy, therefore:
//
//	GET / HEAD / OPTIONS   safe and side-effect free by definition
//	                       (RFC 9110 §9.2.1). Probed as themselves, always.
//	POST / PUT / PATCH     state-changing. Probed as themselves only under
//	                       --active, where the operator has accepted that
//	                       Fendix sends real traffic. POST matters most here:
//	                       an unlimited login endpoint is the canonical
//	                       rate-limiting defect, and it cannot be tested with
//	                       a GET.
//	DELETE                 never. Twenty deletions is data loss, not
//	                       scanning, and the active tier's licence is to send
//	                       attack payloads — not to destroy the target's data.
//	                       No opt-in short of a dedicated one covers this.
//
// An operation this returns ok=false for is REPORTED as not tested. Silence
// would read as "tested, nothing found" to anyone counting findings, which is
// the same misrepresentation in a quieter form.
func rateLimitProbeMethod(endpoint Endpoint, active bool) (method string, ok bool) {
	m := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if m == "" {
		// Discovery sources that observe a path without an operation (crawl,
		// robots.txt, JS extraction) leave Method empty. GET is the honest
		// read of "an unspecified request to this URL", and it is what the
		// finding will be labelled with.
		return http.MethodGet, true
	}
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return m, true
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return m, active
	default: // DELETE, and any verb whose side effects are unknown to us
		return m, false
	}
}

// rateLimitNotTested records an operation Fendix declined to burst-probe.
//
// INFO, because it is not a security observation about the target — it is a
// coverage statement about the scan. It exists so a reader can tell "this
// operation has no rate limiting" from "nobody looked", which the previous
// behaviour made indistinguishable.
func rateLimitNotTested(endpoint Endpoint, method string, active bool) ev.Evidence {
	reason := "state-changing method — rerun with --active to probe it"
	if method == http.MethodDelete {
		reason = "destructive method — never burst-probed, at any scan level"
	} else if active {
		reason = "method not eligible for burst probing"
	}
	label := fmt.Sprintf("%s %s", method, endpoint.Path)
	return ev.Evidence{
		Title:    "Rate limiting not tested for this operation",
		Severity: models.SeverityInfo,
		Source:   models.SourceBlackbox,
		Category: "rate_limiting",
		RuleID:   "ratelimit.not-tested",
		Endpoint: label,
		Evidence: fmt.Sprintf(
			"No rate-limit probe was sent to %s: %s. This is a statement about scan "+
				"coverage, not about the target — nothing is claimed here in either "+
				"direction about whether %s is rate limited.",
			label, reason, label),
		Fix:               "Probe this operation from a staging environment, or rerun with --active if the target tolerates write traffic.",
		References:        []string{"CWE-770"},
		Confidence:        models.ConfidenceHigh,
		DirectObservation: true,
	}
}

// rateLimitCheck implements the Check interface for the rate-limit
// detector. Structural adapter — Run holds the unchanged body of the
// historical CheckRateLimit free function.
type rateLimitCheck struct{}

func (rateLimitCheck) Name() string                        { return "ratelimit" }
func (rateLimitCheck) Category() string                    { return "rate_limiting" }
func (rateLimitCheck) Tier() Tier                          { return TierPassive }
func (rateLimitCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckRateLimit sends multiple rapid requests to detect rate limiting.
// If all requests succeed with no 429 or rate-limit headers, it reports a finding.
func CheckRateLimit(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return rateLimitCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged rate-limit detection body. Outbound requests
// go through the shared SSRF-guarded follow-redirect client (cc.Client);
// the per-job deadline comes from ctx (runCheck).
func (rateLimitCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	// TASK-123: skip the rate-limit check entirely on static-file endpoints.
	//
	// This is a SKIP, not a B4 de-escalation, and the distinction is
	// deliberate. The header/CORS checks tag static-asset findings
	// (responseContextFor) because the underlying observation — "this response
	// carries no CSP", "this response reflects any Origin" — is a real
	// security fact that context merely makes less important. Here there is no
	// comparable fact: rate limiting on a CDN/static-middleware-served file is
	// not an app-layer control at all, so "no 429 within 20 requests on
	// /favicon.ico" was never a security signal to preserve. Per Rule 3 we
	// de-escalate evidence; we do not manufacture evidence in order to
	// de-escalate it.
	//
	// Skipping also avoids spending 20 requests of the scan budget per static
	// endpoint to produce that non-signal.
	if isStaticAssetPath(endpoint.Path) {
		slog.Debug("rate-limit check skipped (static-file path — no app-layer signal)",
			"endpoint", fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path))
		return nil
	}

	// RC-8: probe the operation's OWN method, or do not probe it and say so.
	// The one thing that must not happen is a GET being sent and reported
	// under another verb's name.
	probeMethod, probeOK := rateLimitProbeMethod(endpoint, cfg.EnableActive)
	if !probeOK {
		return []ev.Evidence{rateLimitNotTested(endpoint, probeMethod, cfg.EnableActive)}
	}

	client := cc.Client

	throttledCount := 0
	rateLimitHeaderSeen := false
	// 5.6 — count probes that actually completed (got an HTTP response).
	// Requests that fail to build or error out (budget exhaustion,
	// transport errors) do NOT count, so we don't conclude "unprotected"
	// from a handful of requests that never reached the target.
	successfulProbes := 0

	for i := 0; i < rateLimitProbeCount; i++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		req, err := http.NewRequestWithContext(ctx, probeMethod, endpoint.FullURL, nil)
		if err != nil {
			continue
		}
		cfg.Auth.ApplyToRequest(req)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		successfulProbes++

		if resp.StatusCode == 429 {
			throttledCount++
		}

		for _, h := range rateLimitHeaders {
			if resp.Header.Get(h) != "" {
				rateLimitHeaderSeen = true
				break
			}
		}

		if throttledCount > 0 || rateLimitHeaderSeen {
			break
		}
	}

	// Labelled with the verb that was ACTUALLY sent, which after the policy
	// above is the operation's own verb wherever one was probed.
	epLabel := fmt.Sprintf("%s %s", probeMethod, endpoint.Path)

	if throttledCount > 0 || rateLimitHeaderSeen {
		slog.Debug("rate limiting detected", "endpoint", epLabel)
		return nil
	}

	// 5.6 — inconclusive guard. If too few probes completed (budget
	// exhausted mid-loop or repeated transport errors), we cannot
	// distinguish "unprotected" from "we never really hit it". Return nil
	// rather than emit a false finding.
	if successfulProbes < rateLimitMinProbes {
		slog.Debug("rate-limit check inconclusive (too few probes completed)",
			"endpoint", epLabel, "completed", successfulProbes, "floor", rateLimitMinProbes)
		return nil
	}

	// 5.4 / 5.7 — honest scoping. A bounded burst can only show the
	// ABSENCE of limiting within N requests; it cannot prove a per-minute
	// or per-hour limiter is missing. Title + evidence say so explicitly
	// and confidence stays Medium.
	var headerList []string
	for _, h := range rateLimitHeaders[:3] {
		headerList = append(headerList, h)
	}

	// The OBSERVATION above is identical for every operation. What differs is
	// what an unlimited version of it is worth to an attacker, so the severity
	// — and only the severity, title and one appended sentence — follows the
	// operation's abuse sensitivity. See ratelimit_sensitivity.go.
	//
	// This is prioritization, never suppression: an ordinary endpoint still
	// gets a finding, still with the full bounded-burst claim and both scope
	// disclaimers, just at INFO. Grouping falls out of the existing dedup key
	// (Severity|Category|Title), which turns a single undifferentiated WARN
	// across every endpoint into an abuse-sensitive WARN group and an ordinary
	// INFO group, each keeping its own affected_endpoints list.
	sensitivity, sensitivityReason := classifyAbuseSensitivity(endpoint, probeMethod)
	title := fmt.Sprintf("No rate limiting observed within %d requests", successfulProbes)
	if sensitivity != abuseOrdinary {
		title = fmt.Sprintf("No rate limiting observed within %d requests on an abuse-sensitive operation", successfulProbes)
	}

	return []ev.Evidence{
		{
			RuleID:   "ratelimit/none-observed",
			Title:    title,
			Severity: sensitivity.severity(),
			Source:   models.SourceBlackbox,
			Category: "rate_limiting",
			Endpoint: epLabel,
			Evidence: fmt.Sprintf(
				"Sent %d rapid %s requests with no 429 response and no rate-limit headers (%s). "+
					"Scope note: this bounded burst cannot prove the absence of slower per-minute/per-hour limiters — "+
					"it only shows no limiting within %d requests. "+
					"Granularity note: the probe observes only whether THIS operation answered with a limit. "+
					"It cannot tell a missing per-operation limiter from a shared gateway or perimeter limiter "+
					"whose threshold this burst never reached, so nothing here establishes where a limit would "+
					"have to be added. "+
					"Prioritization note: graded %s because this endpoint %s — the observation itself is the same "+
					"for every operation, only its consequence differs.",
				successfulProbes, probeMethod, strings.Join(headerList, ", "), successfulProbes,
				sensitivity.severity(), sensitivityReason),
			Fix:             "Implement rate limiting. Return 429 Too Many Requests with Retry-After header.",
			References:      []string{"CWE-770"},
			Confidence:      models.ConfidenceMedium,
			AuthExpectation: endpoint.AuthExpectation,
		},
	}
}
