package scanner

// In-band Server-Side Request Forgery (CWE-918) active check.
//
// This check detects whether the TARGET makes server-side requests to a
// client-controlled URL. It is DISTINCT from the internal netguard SSRF guard
// (httpclient.go / internal/netguard), which protects fendix's OWN outbound
// egress from being steered at private/metadata hosts. Here we are the
// attacker: we feed a URL-shaped parameter a canary destination and watch the
// target's response for evidence that the SERVER fetched it.
//
// ============================================================================
// IN-BAND SIGNALS (what this check actually relies on):
//
//   (a) ERROR-LEAK — a curated fetch-stack error signature AND our unique canary
//       host both in the body. An error MESSAGE about our host is server-side
//       fetch evidence (the server tried to dial it and failed), not mere echo.
//   (b) REDIRECT-ECHO — a raw 3xx Location header (via cc.NoFollow) carrying our
//       canary host. A Location is SERVER-controlled, not input-reflected, so it
//       cannot be produced by reflecting the injected parameter value.
//   (c) TIMING — confirmation-only differential, MEDIUM, never fires if (a)/(b)
//       did, budget-bounded.
//
// NOTE — why there is NO body-content "reflected-fetch" signal. A generic "the
// injected marker appears in the body" signal CANNOT distinguish a server-side
// fetch from plain input reflection IN-BAND: fendix cannot host the content the
// sentinel URL would serve, so any string we can look for is one we put into the
// request, and a server that echoes ANY component of the injected URL (a query
// value, a host label) reproduces it without ever fetching. That is the dominant
// SSRF false-positive class, so the body-content path is intentionally absent.
// Honest reflected-content fetch-back requires an OOB/OAST callback server
// (documented FN below); the in-band signals are error-leak + redirect-echo +
// timing only.
//
// ============================================================================
// KNOWN LIMITS (honest, documented false negatives — deliberate scope):
//
//   - NO TRUE OAST/BLIND DETECTION. fendix ships no out-of-band callback
//     (collaborator/interactsh) server, so a "blind" SSRF that fetches our
//     sentinel host with NO observable in-band side effect (no error leak, no
//     redirect echo, no timing differential) is UNDETECTABLE here. A --oob-host
//     hook is future work. This gap is asserted by TestSSRF_DocumentedBlindLimitFN
//     so it stays honest, not hidden.
//   - REFLECTED-CONTENT FETCH-BACK IS AN OOB-ONLY SIGNAL. A server that fetches
//     the sentinel URL and inlines the upstream body cannot be honestly confirmed
//     in-band (any in-band marker is reflection-indistinguishable; see NOTE
//     above). Confirming it requires an OOB host that serves a secret only the
//     server-side fetcher could retrieve. Documented FN.
//   - CLOUD-METADATA (IMDS) IS CONFIRMED ONLY INDIRECTLY. We never fetch real
//     169.254.169.254 data. We do not special-case IMDS or assert AWS/GCP/Azure
//     credentials were exfiltrated.
//   - ERROR-SUPPRESSING / IDENTICAL-RESPONSE servers evade detection. A target
//     that fetches server-side but returns a constant body regardless of the
//     fetch outcome leaks nothing in-band (the documented-blind case).
//   - SECOND-ORDER SSRF is out of scope. We inspect the immediate response to a
//     single request; a fetch triggered later (queue/cron/webhook delivery) on
//     a different request is not observed.
//   - TIMING IS NOISY. The timing-differential signal is confirmation-only,
//     capped at MEDIUM, never fires when a stronger signal already did, and is
//     gated behind a small budget-bounded sample.
//
// ============================================================================
// FALSE-POSITIVE GUARDS (load-bearing — these ARE the check):
//
//   (a) ERROR-LEAK requires BOTH a curated fetch-stack error signature AND our
//       unique canary host in the body. A generic "connection refused" page
//       that does not echo our canary host is NOT flagged (it proves only that
//       *something* failed, not that the server fetched OUR url). Reflection of
//       the injected URL alone never carries a fetch-stack error signature, so
//       this signal is reflection-proof.
//   (b) REDIRECT-ECHO reads the canary host out of the SERVER-controlled 3xx
//       Location header — a position input reflection cannot occupy — so it too
//       is reflection-proof. There is deliberately no body-content signal (it is
//       the FP source and cannot be made honest in-band; see NOTE above).
//
// Sentinel host: the ".invalid" TLD is reserved by RFC 2606 and is guaranteed
// to never resolve, be registered, or be owned by anyone — so the canary is a
// safe, non-routable destination. The TEST-NET-1 literal 192.0.2.1 (RFC 5737)
// is similarly reserved for documentation and is never a live host.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ssrfSentinelHost is the reserved-TLD base under which every canary host is
// constructed. RFC 2606 guarantees .invalid never resolves and can never be
// owned, so injecting a URL under it is a safe, non-routable probe.
const ssrfSentinelHost = "oob.fendix.invalid"

// ssrfTestNetLiteral is an RFC 5737 TEST-NET-1 address reserved for
// documentation; it is never a live host, so a server that errors trying to
// reach it leaks a fetch-stack error without us touching any real system.
const ssrfTestNetLiteral = "192.0.2.1"

// ssrfBodyLimit caps how much of each response body we read into memory.
const ssrfBodyLimit = 1 << 20 // 1 MiB

// urlParamKeywords is the set of WHOLE-TOKEN names that conventionally carry a
// URL/host/path destination — the surface where SSRF actually lives. Probing
// only params whose name contains one of these tokens (rather than every
// declared param) keeps the per-endpoint probe budget meaningful and avoids
// spraying URL payloads at obviously-non-URL fields like "comment" or
// "quantity". An all-params opt-in is intentionally deferred (future work).
var urlParamKeywords = map[string]struct{}{
	"url": {}, "uri": {}, "link": {}, "src": {}, "dest": {},
	"redirect": {}, "callback": {}, "webhook": {}, "host": {}, "domain": {},
	"feed": {}, "target": {}, "fetch": {}, "proxy": {}, "next": {},
	"return": {}, "continue": {}, "image": {}, "img": {}, "file": {},
	"path": {}, "resource": {}, "api": {}, "endpoint": {}, "site": {},
	"page": {}, "out": {}, "to": {}, "u": {},
}

// Go's regexp is RE2 (no lookahead), so camelCase boundaries are introduced by
// two explicit replaces before splitting:
//   - caseBoundaryLowerUpperRe inserts a break between a lowercase/digit and an
//     uppercase letter:  "imageUrl"→"image Url", "redirect2Uri"→"redirect2 Uri".
//   - caseBoundaryAcronymRe inserts a break inside an UPPERCASE run that is
//     immediately followed by a capitalized word, splitting the trailing capital
//     off the acronym: "URLValue"→"URL Value", "callbackURL" stays "callback URL".
//
// After both, the name is lowercased and split on any run of non-letters/digits,
// yielding clean word tokens.
var (
	caseBoundaryLowerUpperRe = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	caseBoundaryAcronymRe    = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
	paramSplitRe             = regexp.MustCompile(`[^a-z0-9]+`)
)

// isURLShapedParam reports whether a parameter name looks like it carries a URL
// or host destination. The name is split into word tokens on case transitions
// and separators, and a WHOLE token must equal one of urlParamKeywords. Matching
// whole tokens (not substrings) means "imageUrl"/"redirectUri"/"callbackURL" hit
// (token "url"/"uri"/"image"/etc.) while "occurl"/"tourl"/"comment"/"description"
// — which merely CONTAIN a keyword as a substring — do NOT.
func isURLShapedParam(name string) bool {
	spaced := caseBoundaryAcronymRe.ReplaceAllString(name, "$1 $2")
	spaced = caseBoundaryLowerUpperRe.ReplaceAllString(spaced, "$1 $2")
	for _, tok := range paramSplitRe.Split(strings.ToLower(spaced), -1) {
		if tok == "" {
			continue
		}
		if _, ok := urlParamKeywords[tok]; ok {
			return true
		}
	}
	return false
}

// ssrfErrorPatterns matches outbound fetch-stack error leakage in a response
// body — the signatures a server emits when its server-side HTTP client fails
// to reach the destination we supplied. Curated across Go/Java/Python/Node/libc
// stacks and kept tight to avoid matching unrelated prose. A match is necessary
// but NOT sufficient: signal (a) also requires our canary host in the body.
var ssrfErrorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)connection refused|ECONNREFUSED`),
	regexp.MustCompile(`(?i)no route to host|EHOSTUNREACH`),
	regexp.MustCompile(`(?i)dial tcp|getaddrinfo|Name or service not known`),
	regexp.MustCompile(`(?i)UnknownHostException|java\.net\.ConnectException`),
	regexp.MustCompile(`(?i)failed to connect|could not resolve host`),
	regexp.MustCompile(`(?i)requests\.exceptions\.(ConnectionError|Timeout)|urllib\.error`),
	regexp.MustCompile(`(?i)connection timed out|ETIMEDOUT`),
}

// matchSSRFError returns the first fetch-stack error signature found in the
// body, or "" if none match.
func matchSSRFError(body string) string {
	for _, re := range ssrfErrorPatterns {
		if m := re.FindString(body); m != "" {
			return m
		}
	}
	return ""
}

// SSRFCheck is the active in-band SSRF (CWE-918) check. For each URL-shaped
// target it sends canary fetch probes and classifies the target's response via
// three in-band signals with precedence (a) error-leak > (b) reflected-fetch >
// (c) timing. At most one finding is emitted per (param, location).
type SSRFCheck struct{}

func (SSRFCheck) Name() string     { return "ssrf" }
func (SSRFCheck) Category() string { return "ssrf" }
func (SSRFCheck) Tier() Tier       { return TierActive }
func (SSRFCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// Run probes every URL-shaped (param, location) target. Active discipline
// mirrors probeCMDi / reflectedXSSCheck: a ctx.Done()/budget check before each
// probe, a ProbeRecord per probe, and auth applied via cfg.Auth.ApplyToRequest.
// Skips non-2xx/3xx baseline endpoints (a 404 surface is not a feature, same as
// headers/cors). At most one finding per target, precedence (a)>(b)>(c).
func (SSRFCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if cc == nil || cc.Cfg == nil || !cc.Cfg.EnableActive {
		return nil
	}

	var findings []ev.Evidence
	maxProbes := effectiveMaxProbes(cc.Cfg)

	// SSRF lives in URL-shaped params; filter the target set first (all-params
	// opt-in is deferred future work). Header/body URL params are eligible too.
	// We filter BEFORE the baseline request so a non-URL-param endpoint costs
	// zero requests — there is nothing to probe, so we never touch the target.
	var targets []probeTarget
	for _, t := range targetsForEndpoint(ep) {
		if isURLShapedParam(t.Name) {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return findings
	}

	// Skip endpoints whose baseline isn't a real 2xx/3xx feature (e.g. a 404)
	// — mirrors the headers/cors behaviour of not probing dead surfaces.
	if !ssrfBaselineServiceable(ctx, cc, ep) {
		return findings
	}

	for _, t := range targets {
		// Active discipline: soft-stop on cancellation, then budget cap —
		// both checked before sending any probe (mirrors probeCMDi).
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if cc.Audit.Count(ep.FullURL) >= maxProbes {
			logagg.Warn("ssrf", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", maxProbes)
			return findings
		}

		if f, ok := probeSSRF(ctx, cc, ep, t.Name, t.Location); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

// ssrfBaselineServiceable sends one benign control request and reports whether
// the endpoint answers with a 2xx/3xx (a real feature). A non-following client
// is used so a 3xx still counts as serviceable. Returns false on transport
// error or a 4xx/5xx baseline. Records a ProbeRecord for accountability.
func ssrfBaselineServiceable(ctx context.Context, cc *CheckContext, ep Endpoint) bool {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, nil)
	if err != nil {
		return false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   "(baseline)",
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		record.Status = 0
		cc.Audit.Record(record)
		return false
	}
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)
	return resp.StatusCode >= 200 && resp.StatusCode <= 399
}

// probeSSRF runs the in-band SSRF signals against one (param, location) target
// and returns the first finding by precedence (a error-leak > b reflected-fetch
// > c timing). Returns (finding, true) on a hit, (zero, false) otherwise.
func probeSSRF(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) (ev.Evidence, bool) {
	// Unique per-target canary so a hit cannot collide with static page text and
	// the host cannot be guessed/special-cased by the target.
	canary := "fendix-ssrf-" + randHex(8)
	canaryHost := canary + "." + ssrfSentinelHost

	// ---- Signal (a): ERROR-LEAK ----
	// A probe carrying the canary host: signal (a) fires only if the body holds
	// BOTH a fetch-stack error signature AND our canary host (an ERROR ABOUT our
	// host = server-side fetch evidence, not mere reflection). There is no body-
	// content path: any in-band marker is reflection-indistinguishable, so a
	// "marker echoed in body" signal cannot honestly tell fetch from echo (see the
	// file-level NOTE). Reflected-content fetch-back is an OOB-only signal (FN).
	canaryURL := "http://" + canaryHost + "/"
	if f, ok := ssrfFetchProbe(ctx, cc, ep, param, loc, canaryURL, canaryHost); ok {
		return f, true
	}

	// A second error-leak probe with the RFC 5737 TEST-NET literal: some targets
	// reject the bogus .invalid hostname at DNS but will try (and fail) to dial a
	// syntactically-valid IP, leaking a connect-time error that still echoes the
	// literal we supplied.
	testnetURL := "http://" + ssrfTestNetLiteral + "/"
	if f, ok := ssrfFetchProbe(ctx, cc, ep, param, loc, testnetURL, ssrfTestNetLiteral); ok {
		return f, true
	}

	// ---- Signal (b): REDIRECT-ECHO (raw 3xx Location → canary host) ----
	if f, ok := ssrfRedirectProbe(ctx, cc, ep, param, loc, canaryURL, canaryHost); ok {
		return f, true
	}

	// ---- Signal (c): TIMING (confirmation-only, never if a/b fired) ----
	if f, ok := ssrfTimingProbe(ctx, cc, ep, param, loc); ok {
		return f, true
	}

	return ev.Evidence{}, false
}

// ssrfFetchProbe sends one canary URL probe via the body-following client and
// classifies the response for signal (a) ERROR-LEAK.
//
//   - (a) fires when the body contains BOTH a fetch-stack error signature AND
//     the canary host (an ERROR MESSAGE about our host = the server tried to dial
//     it server-side and failed — that is fetch evidence, not mere reflection of
//     the injected URL, which never carries a fetch-stack error signature).
//
// There is intentionally no body-content "reflected-fetch" signal here: any
// in-band marker would be indistinguishable from input reflection of an injected
// URL component (see the file-level NOTE), making it the dominant FP source.
// Reflected-content fetch-back is confirmable only out-of-band (documented FN).
func ssrfFetchProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL, canaryHost string) (ev.Evidence, bool) {
	body, status, ok := ssrfSendBody(ctx, cc, ep, param, loc, injectURL)
	if !ok {
		return ev.Evidence{}, false
	}

	// (a) ERROR-LEAK: error signature AND our canary host both present.
	if sig := matchSSRFError(body); sig != "" && strings.Contains(body, canaryHost) {
		evidence := fmt.Sprintf(
			"Outbound fetch error leakage: response (status=%d) contains fetch-stack error %q AND our canary host %q, proving the server attempted to fetch the injected URL %q. %s",
			status, sig, canaryHost, injectURL, paramLabel(param, loc),
		)
		return ev.Evidence{
			RuleID:   "ssrf/error-leakage",
			Title:    "SSRF — outbound fetch error leakage",
			Severity: models.SeverityHigh,
			Source:   models.SourceBlackbox,
			Category: "ssrf",
			Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
			Evidence: evidence,
			Fix: "Do not fetch user-supplied URLs. Enforce an allow-list of destination hosts/schemes, " +
				"resolve+pin the IP and reject private/link-local/metadata ranges, and disable redirects on the server-side fetcher.",
			References: []string{"CWE-918", "OWASP-A10"},
			Confidence: models.ConfidenceHigh,
			// The differential that confirms the claim: we injected a URL for a
			// host that cannot resolve, and the response came back carrying a
			// fetch-stack error ABOUT that host. Reflection alone never
			// produces an error signature, which is precisely why this pair —
			// and not the mere presence of the marker — is the evidence.
			Payload:  injectURL,
			Response: ProbeExcerpt(ssrfErrorContext(body, sig)),
		}, true
	}

	return ev.Evidence{}, false
}

// ssrfErrorContext returns the region of the response body around the matched
// fetch-stack error signature, so the stored differential is the sentence that
// proves the server dialled our canary rather than an arbitrary body prefix.
// Falls back to the body head when the signature cannot be located.
func ssrfErrorContext(body, sig string) string {
	idx := strings.Index(body, sig)
	if idx < 0 {
		return body
	}
	start := idx - 80
	if start < 0 {
		start = 0
	}
	end := idx + len(sig) + 160
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// ssrfRedirectProbe sends the canary URL via the NON-following client and fires
// (b, redirect-echo, MEDIUM) when the raw 3xx Location header carries our canary
// host — a server-side fetcher that 30x's onward to the supplied URL.
func ssrfRedirectProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL, canaryHost string) (ev.Evidence, bool) {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		return ev.Evidence{}, false
	}
	select {
	case <-ctx.Done():
		return ev.Evidence{}, false
	default:
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, ep, param, injectURL, loc)
	if err != nil {
		logagg.Warn("ssrf", "failed to create redirect-echo probe request", "error", err)
		return ev.Evidence{}, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   injectURL,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("ssrf", "redirect-echo probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}
	resp.Body.Close()
	record.Status = resp.StatusCode

	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		location := resp.Header.Get("Location")
		// Parse the Location and compare its HOST (exact, lowercased,
		// trailing-dot-stripped) to the canary — never a raw substring. An
		// own-host redirect that merely reflects the injected URL into a query
		// param (e.g. Location: /login?next=http://<canary>/) has host == the
		// app's own host, NOT the canary, and must not fire. Mirrors
		// openredirect.go (redirectHostConfirmed) and hostheader.go
		// (hostHeaderLocationHost).
		locHost := ""
		if location != "" {
			if u, perr := url.Parse(location); perr == nil {
				locHost = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
			}
		}
		if locHost == strings.ToLower(canaryHost) {
			record.Finding = true
			cc.Audit.Record(record)
			return ev.Evidence{
				RuleID:   "ssrf/confirmed-fetch",
				Title:    "SSRF — server-side fetch of attacker-controlled URL",
				Severity: models.SeverityMedium,
				Source:   models.SourceBlackbox,
				Category: "ssrf",
				Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
				Evidence: fmt.Sprintf(
					"Redirect echo: status=%d Location=%q carries our canary host %q — the server-side fetcher forwards to the supplied URL. %s",
					resp.StatusCode, location, canaryHost, paramLabel(param, loc),
				),
				Fix: "Do not fetch or redirect to user-supplied URLs. Enforce an allow-list of destination hosts/schemes " +
					"and disable redirect following on the server-side fetcher.",
				References: []string{"CWE-918", "OWASP-A10"},
				Confidence: models.ConfidenceMedium,
				// The differential: the canary URL we injected, and the raw
				// Location that came back carrying its HOST (exact match, not
				// substring — see the comment above). The body is irrelevant
				// here; the header is the confirming observation.
				Payload:  injectURL,
				Response: ProbeExcerpt(fmt.Sprintf("HTTP %d Location: %s", resp.StatusCode, location)),
			}, true
		}
	}

	cc.Audit.Record(record)
	return ev.Evidence{}, false
}

// ssrfTimingProbe is the confirmation-only timing-differential signal (MEDIUM).
// It only fires when neither (a) nor (b) did (precedence) and is intentionally
// minimal + budget-bounded: timing is noisy. It measures a benign baseline
// (median of a small N via measureBaseline) and one probe pointed at a host that
// would hang to connect-timeout; if the probe greatly exceeds baseline+threshold
// the target is likely fetching server-side. Conservative threshold keeps the
// FP rate low; this is the weakest signal in the precedence chain.
//
// In practice the .invalid sentinel fails fast (NXDOMAIN) rather than hanging,
// so this rarely fires in the loopback test environment — which is correct: a
// host we can't make hang produces no timing differential. The branch exists so
// real targets with a slow-failing fetcher are still surfaced at MEDIUM.
func ssrfTimingProbe(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) (ev.Evidence, bool) {
	maxProbes := effectiveMaxProbes(cc.Cfg)
	// Need at least the baseline samples (3) plus one timing probe; bail if the
	// budget can't cover them rather than overshoot the operator's cap.
	if cc.Audit.Count(ep.FullURL)+4 > maxProbes {
		return ev.Evidence{}, false
	}
	select {
	case <-ctx.Done():
		return ev.Evidence{}, false
	default:
	}

	baseline, err := measureBaseline(ctx, cc.Client, cc.Cfg, ep.Method, ep.FullURL)
	if err != nil {
		logagg.Warn("ssrf", "failed to measure baseline for timing", "endpoint", ep.FullURL, "error", err)
		return ev.Evidence{}, false
	}

	// A host under the sentinel TLD that a server-side fetcher would block on
	// while trying to connect. We measure the median of a small sample.
	hangURL := "http://" + "fendix-ssrf-timing-" + randHex(8) + "." + ssrfSentinelHost + "/"
	var samples []time.Duration
	const n = 2
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return ev.Evidence{}, false
		default:
		}
		start := time.Now()
		req, err := buildProbeRequest(ctx, ep, param, hangURL, loc)
		if err != nil {
			return ev.Evidence{}, false
		}
		cc.Cfg.Auth.ApplyToRequest(req)
		resp, err := cc.Client.Do(req)
		elapsed := time.Since(start)
		record := ProbeRecord{
			Timestamp: start,
			Endpoint:  ep.FullURL,
			ProbeType: ProbeSSRF,
			Payload:   hangURL,
			Parameter: param,
			Method:    ep.Method,
			Duration:  elapsed.Round(time.Millisecond).String(),
		}
		if err != nil {
			record.Status = 0
			cc.Audit.Record(record)
			// A transport error (fast NXDOMAIN at our own guard, refused dial)
			// is NOT a timing signal — abandon the timing branch.
			return ev.Evidence{}, false
		}
		resp.Body.Close()
		record.Status = resp.StatusCode
		cc.Audit.Record(record)
		samples = append(samples, elapsed)
	}

	probe := medianDuration(samples)
	// Conservative threshold: the probe must exceed baseline by a wide margin to
	// be attributable to a server-side connect-timeout rather than jitter.
	const ssrfTimingThreshold = 4 * time.Second
	if probe > baseline+ssrfTimingThreshold {
		return ev.Evidence{
			RuleID:   "ssrf/timing-differential",
			Title:    "SSRF — timing differential",
			Severity: models.SeverityMedium,
			Source:   models.SourceBlackbox,
			Category: "ssrf",
			Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
			Evidence: fmt.Sprintf(
				"Timing differential: baseline median=%s, canary-fetch median=%s (threshold=%s) — the server appears to block while fetching the supplied unroutable URL. Confirmation-only signal. %s",
				baseline.Round(time.Millisecond), probe.Round(time.Millisecond), ssrfTimingThreshold, paramLabel(param, loc),
			),
			Fix: "Do not fetch user-supplied URLs. Enforce an allow-list of destination hosts/schemes and a short, " +
				"bounded connect timeout on the server-side fetcher.",
			References: []string{"CWE-918", "OWASP-A10"},
			Confidence: models.ConfidenceMedium,
			// A TIMING check's confirming observation is the measured
			// differential, not a body — this probe never reads one. Recording
			// the medians is the truthful response observation.
			Payload:  hangURL,
			Response: ProbeTimingExcerpt(probe, baseline+ssrfTimingThreshold),
		}, true
	}

	return ev.Evidence{}, false
}

// ssrfSendBody sends one probe (param=injectURL at loc) via the body-following
// client, records a ProbeRecord, and returns (body, status, ok). ok=false on a
// budget exhaustion, cancellation, build, or transport error.
func ssrfSendBody(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation, injectURL string) (string, int, bool) {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		return "", 0, false
	}
	select {
	case <-ctx.Done():
		return "", 0, false
	default:
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, ep, param, injectURL, loc)
	if err != nil {
		logagg.Warn("ssrf", "failed to create ssrf probe request", "error", err)
		return "", 0, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.Client.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeSSRF,
		Payload:   injectURL,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("ssrf", "ssrf probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return "", 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, ssrfBodyLimit))
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)
	return string(body), resp.StatusCode, true
}
