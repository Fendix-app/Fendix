package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// redirectSentinelHost is the attacker-controlled host injected into redirect
// payloads. It lives under RFC2606's reserved .example TLD, so it can never
// resolve, be registered, or be owned by anyone — the probe can confirm the
// app *would* redirect off-origin without ever touching a real external host.
const redirectSentinelHost = "fendix-redirect.example"

// redirectParams are the query parameter names most commonly used by web apps
// to carry a post-action destination URL. Open redirects almost always live in
// one of these; probing this curated list (rather than every declared param)
// keeps the probe budget meaningful.
var redirectParams = []string{
	"next", "url", "return", "returnTo", "dest", "redirect", "redirect_uri", "continue",
}

// redirectPayload is one open-redirect probe value plus how to confirm it.
type redirectPayload struct {
	// Value is placed verbatim into the target query parameter.
	Value string
	// SuffixBypass marks the subdomain-style bypass payload: the attacker host
	// is a label *suffix* of the redirect host (trusted.com.fendix-redirect.example).
	// Confirmation accepts Hostname() ending in "."+sentinel, and the finding is
	// downgraded to MEDIUM confidence (a redirect filter that only checks a
	// prefix/substring of the host is exploitable but the match is fuzzier).
	SuffixBypass bool
	// DangerousScheme marks the javascript:/data:/vbscript: payload. Its
	// confirmation is the *scheme* of the reflected Location, not the host: a
	// server never legitimately emits a `Location: javascript:...` header
	// (browsers don't navigate to it, and no framework redirects there), so the
	// scheme alone is unambiguous evidence the payload reached redirect
	// construction. This carries no own-host FP risk, so it does not need the
	// sentinel-host equality gate that the URL payloads rely on.
	DangerousScheme bool
}

// redirectPayloads returns the ordered open-redirect probe set. Order is
// cheapest/most-common first so the per-param short-circuit (one finding per
// param) and the probe budget both favour the high-signal payloads.
func redirectPayloads() []redirectPayload {
	return []redirectPayload{
		{Value: "//" + redirectSentinelHost},                                           // scheme-relative
		{Value: `/\` + redirectSentinelHost},                                           // backslash bypass (browsers treat /\ as //)
		{Value: "https://" + redirectSentinelHost},                                     // absolute
		{Value: "https://trusted.com." + redirectSentinelHost, SuffixBypass: true},     // suffix/subdomain bypass
		{Value: "javascript:alert(1)//" + redirectSentinelHost, DangerousScheme: true}, // dangerous scheme
	}
}

// dangerousRedirectScheme reports whether a confirmed redirect target scheme is
// directly exploitable in a browser (XSS via javascript:/vbscript:, or data:
// document injection). These elevate the finding to HIGH severity.
func dangerousRedirectScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "javascript", "data", "vbscript":
		return true
	}
	return false
}

// openRedirectCheck is the active open-redirect (CWE-601) check. It sets a
// known redirect query parameter to a sentinel-host payload and inspects the
// raw 3xx Location header (via cc.NoFollow) to confirm the app would send the
// browser to the attacker-controlled host.
type openRedirectCheck struct{}

func (openRedirectCheck) Name() string     { return "open-redirect" }
func (openRedirectCheck) Category() string { return "redirect" }
func (openRedirectCheck) Tier() Tier       { return TierActive }
func (openRedirectCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// Run probes each redirectParam with each redirect payload, using the
// non-following client so it sees the raw Location header. Active-probe
// discipline mirrors probeCMDi: a ctx.Done()/budget check before every probe,
// a ProbeRecord per probe, and auth applied via cfg.Auth.ApplyToRequest. At
// most one finding is emitted per parameter — once a param confirms, the
// remaining payloads for that param are skipped (the underlying vuln is the
// same; more payloads would just be noise).
func (openRedirectCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if !cc.Cfg.EnableActive {
		return nil
	}

	var findings []ev.Evidence
	maxProbes := effectiveMaxProbes(cc.Cfg)

paramLoop:
	for _, param := range redirectParams {
		for _, p := range redirectPayloads() {
			// Active discipline: soft-stop on cancellation, then budget cap —
			// both checked before sending the probe (mirrors probeCMDi).
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			if cc.Audit.Count(ep.FullURL) >= maxProbes {
				logagg.Warn("open-redirect", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", maxProbes)
				return findings
			}

			f, ok := probeOpenRedirect(ctx, cc, ep, param, p)
			if ok {
				findings = append(findings, f)
				// One finding per param; move to the next param.
				continue paramLoop
			}
		}
	}

	return findings
}

// probeOpenRedirect sends a single open-redirect probe and returns a finding if
// the raw 3xx Location confirms an off-origin redirect to the sentinel host.
// Returns (finding, true) on a hit, (zero, false) otherwise. Always records a
// ProbeRecord.
func probeOpenRedirect(ctx context.Context, cc *CheckContext, ep Endpoint, param string, p redirectPayload) (ev.Evidence, bool) {
	probeURL := buildProbeURL(ep.FullURL, param, p.Value)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, ep.Method, probeURL, nil)
	if err != nil {
		logagg.Warn("open-redirect", "failed to create probe request", "error", err)
		return ev.Evidence{}, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeRedirect,
		Payload:   p.Value,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("open-redirect", "probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}
	resp.Body.Close()
	record.Status = resp.StatusCode

	// Only a 3xx with a Location header is a redirect. A 200 (no Location, even
	// if the payload is echoed in the body) is NOT an open redirect.
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}
	location := resp.Header.Get("Location")
	if location == "" {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}

	target, host, ok := parseRedirectTarget(location)
	if !ok {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}
	scheme := ""
	if target != nil {
		scheme = target.Scheme
	}

	severity := models.SeverityMedium
	confidence := models.ConfidenceHigh
	switch {
	case p.DangerousScheme:
		// Confirmation is the reflected scheme itself — a `Location:
		// javascript:...` (or data:/vbscript:) is never legitimate, so no
		// sentinel-host gate is needed (and the host of such a URL is empty).
		if !dangerousRedirectScheme(scheme) {
			cc.Audit.Record(record)
			return ev.Evidence{}, false
		}
		severity = models.SeverityHigh
		confidence = models.ConfidenceHigh
	default:
		// URL payloads: LOAD-BEARING host-equality gate (never substring).
		if !redirectHostConfirmed(host, p.SuffixBypass) {
			cc.Audit.Record(record)
			return ev.Evidence{}, false
		}
		if p.SuffixBypass {
			// Subdomain-style bypass: the match is host-suffix rather than
			// exact, so it's a fuzzier (though still real) signal.
			confidence = models.ConfidenceMedium
		}
		// A URL payload may still reflect into a dangerous scheme (e.g. the
		// server prefixes a scheme); treat that as HIGH like the dedicated probe.
		if dangerousRedirectScheme(scheme) {
			severity = models.SeverityHigh
			confidence = models.ConfidenceHigh
		}
	}

	record.Finding = true
	cc.Audit.Record(record)

	evidence := fmt.Sprintf(
		"Open redirect confirmed: param %q=%q produced status=%d Location=%q (effective host %q == attacker-controlled sentinel)",
		param, p.Value, resp.StatusCode, location, host,
	)

	return ev.Evidence{
		RuleID:   "openredirect/confirmed",
		Title:    "Open Redirect",
		Severity: severity,
		Source:   models.SourceBlackbox,
		Category: "redirect",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: evidence,
		Fix: "Do not redirect to user-supplied URLs. Validate the destination against an allow-list of " +
			"known-safe paths/hosts, or only permit relative same-origin paths.",
		References: []string{"CWE-601", "OWASP-A01"},
		Confidence: confidence,
		// The differential: the destination we injected, and the raw Location
		// header that came back carrying it. The body is irrelevant here and is
		// closed unread — the header IS the confirming observation.
		Payload:  p.Value,
		Response: ProbeExcerpt(fmt.Sprintf("HTTP %d Location: %s", resp.StatusCode, location)),
	}, true
}

// parseRedirectTarget parses a raw Location header value into a URL and returns
// its effective hostname. It applies the backslash normalization browsers do
// implicitly (treating "/\" as "//") BEFORE url.Parse, since url.Parse does not
// — without it, "/\host" parses to a path-only URL with an empty host and the
// real off-origin redirect would be missed.
//
// Returns (parsedURL, hostname, ok). ok is false only when the value can't be
// parsed at all; an empty hostname is a valid "no off-origin host" result.
func parseRedirectTarget(location string) (*url.URL, string, bool) {
	normalized := strings.ReplaceAll(location, `\`, "/")
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, "", false
	}
	return u, u.Hostname(), true
}

// redirectHostConfirmed reports whether the parsed Location host is the
// attacker-controlled sentinel — the LOAD-BEARING false-positive control.
//
// Matching is on Hostname() EQUALITY, never a substring of the raw Location.
// A server redirecting to its own host with the sentinel only in a query param
// (https://victim.test/login?next=//fendix-redirect.example) has
// Hostname()=="victim.test" and must NOT match.
//
// For the suffix-bypass payload the attacker host is a label suffix of the
// redirect host (trusted.com.fendix-redirect.example), so we accept a host that
// ends in "."+sentinel. The dot anchor prevents "evilfendix-redirect.example"
// or similar non-subdomain lookalikes from matching.
func redirectHostConfirmed(host string, suffixBypass bool) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == redirectSentinelHost {
		return true
	}
	if suffixBypass && strings.HasSuffix(host, "."+redirectSentinelHost) {
		return true
	}
	return false
}
