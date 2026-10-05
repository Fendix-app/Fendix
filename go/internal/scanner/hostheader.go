package scanner

// Active host-header injection check (CWE-644 / CWE-601).
//
// This check detects whether the TARGET trusts the client-supplied Host (or a
// Host-family header) when it builds an absolute URL — the request line and the
// Host-family headers ARE the attack surface, NOT query/body params. So this is
// a PER-ENDPOINT (active-lite) check: it probes each endpoint ONCE per header
// vector (not once per declared param). A trusted attacker-controlled Host that
// flows into a redirect Location or an absolute link in the body is exploitable
// as open-redirect / password-reset-link poisoning / web-cache poisoning.
//
// ============================================================================
// IN-BAND SIGNALS (what this check actually relies on):
//
//   (a) REDIRECT-HOST reflection (HIGH/High): a 3xx whose Location header parses
//       (url.Parse) to a Hostname() EXACTLY equal to our sentinel. A Location is
//       SERVER-constructed; if it carries the host WE supplied via the Host
//       header, the app built the absolute redirect from the attacker-controlled
//       Host → open-redirect / reset-link poisoning.
//   (b) BODY ABSOLUTE-LINK reflection (HIGH if reset-context / MEDIUM otherwise):
//       the sentinel appears in the body in a URL-HOST position — matched by the
//       anchored regex `(?:https?:)?//<sentinel>` (a bare echo NOT in a URL-host
//       position must NOT fire). HIGH when the surrounding context is a password-
//       reset / verify / confirm flow or an href/src attribute; MEDIUM otherwise.
//
// ============================================================================
// FALSE-POSITIVE CONTROLS (load-bearing — these ARE the check):
//
//   - REDIRECT detection is EXACT Hostname() equality, NEVER substring. A server
//     that redirects to its OWN host with the sentinel only in a query param
//     (https://victim.test/login?next=//fendix-hhi.example) has
//     Hostname()=="victim.test" and must NOT match.
//   - BODY detection is an ANCHORED URL-host-position regex (//sentinel or
//     scheme://sentinel), NEVER a bare substring. A bare-text echo of the header
//     value ("you searched for fendix-hhi.example") is NOT in a URL-host position
//     and must NOT fire.
//   - BASELINE DIFF on BOTH shapes: we first send an UNPOISONED request and
//     capture (status, Location-host, body-contains-sentinel-in-URL-position). A
//     reflection is attacker-controlled only if it was ABSENT in the baseline. A
//     server that always redirects to the sentinel for unrelated reasons, or one
//     whose baseline body already carries the sentinel link, does NOT FP.
//
// ============================================================================
// KNOWN LIMITS (honest, documented false negatives — deliberate scope):
//
//   - NO OUT-OF-BAND (OOB) DETECTION. fendix ships no collaborator/interactsh
//     callback server, so a host-header injection that triggers a server-side
//     side effect with NO in-band reflection (e.g. a back-channel email sent to a
//     poisoned host, or a cache key poisoned for OTHER clients) is UNDETECTABLE
//     here.
//   - CACHE POISONING is INFERRED, NOT PROVEN. We never send a second, unkeyed
//     request to confirm the poisoned response was actually CACHED and served to
//     a different client. A reflected Host in the body/Location is the precondition
//     for web-cache poisoning, but the caching itself is not demonstrated.
//   - STATEFUL RESET FLOWS may FALSE-NEGATIVE. A real password-reset poisoning
//     often requires a valid account and a POST to /forgot-password with a real
//     email; this per-endpoint GET-shaped probe cannot drive that multi-step flow,
//     so a reset link that only appears AFTER such a POST is missed.
//   - RARE VHOST-ROUTING FALSE POSITIVE. A reverse proxy / multi-tenant server
//     that legitimately routes by Host AND happens to echo the supplied Host into
//     an absolute URL could be flagged; the baseline-diff and exact-host controls
//     make this rare but not impossible.

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

// hostHeaderSentinel is the attacker-controlled host injected into the Host-
// family headers. It lives under RFC2606's reserved .example TLD, so it can
// never resolve, be registered, or be owned by anyone — the probe confirms the
// app WOULD trust an off-origin Host without ever touching a real external host.
const hostHeaderSentinel = "fendix-hhi.example"

// hostHeaderBodyLimit caps how much of each response body we read into memory.
const hostHeaderBodyLimit = 1 << 20 // 1 MiB

// hostHeaderURLPositionRe matches the sentinel ONLY when it sits in a URL-HOST
// position: preceded by a scheme-relative "//" or a full "scheme://". This is
// the LOAD-BEARING body control — a bare-text echo of the sentinel (not preceded
// by // or a scheme) does NOT match, so reflecting the header value as plain text
// never fires. The leading "(?:https?:)?" makes the scheme optional so that both
// "https://fendix-hhi.example" and the scheme-relative "//fendix-hhi.example"
// match, while a bare "fendix-hhi.example" does not.
var hostHeaderURLPositionRe = regexp.MustCompile(`(?:https?:)?//` + regexp.QuoteMeta(hostHeaderSentinel))

// hostHeaderResetContextRe matches password-reset / account-verification context
// near the reflected absolute link. Its presence elevates a body-link finding
// from MEDIUM to HIGH (a poisoned reset/verify link is directly exploitable for
// account takeover, not merely an off-origin link).
var hostHeaderResetContextRe = regexp.MustCompile(`(?i)reset|password|verify|confirm`)

// hostHeaderVector is one Host-family header injection vector. The Host header
// is special-cased in Go (req.Host, NOT req.Header.Set("Host", ...)), so the
// vector carries a flag distinguishing it from the X-Forwarded-* family.
type hostHeaderVector struct {
	// Name is the human-readable header name for evidence/audit.
	Name string
	// IsHost marks the request-line Host header, set via req.Host.
	IsHost bool
	// Value is the raw header value to inject. For the Forwarded header this is
	// the full "host=<sentinel>" token; for the others it is the bare sentinel.
	Value string
}

// hostHeaderVectors returns the ordered set of Host-family injection vectors.
// Order is Host first (the canonical surface) then the X-Forwarded-* family.
func hostHeaderVectors() []hostHeaderVector {
	return []hostHeaderVector{
		{Name: "Host", IsHost: true, Value: hostHeaderSentinel},
		{Name: "X-Forwarded-Host", Value: hostHeaderSentinel},
		{Name: "X-Forwarded-Server", Value: hostHeaderSentinel},
		{Name: "Forwarded", Value: "host=" + hostHeaderSentinel},
	}
}

// hostHeaderCheck is the active host-header injection (CWE-644/601) check. For
// each endpoint it establishes an unpoisoned baseline, then probes each Host-
// family header vector with the sentinel and classifies the response via two
// in-band signals: (a) redirect-host reflection and (b) body absolute-link
// reflection. At most ONE finding per shape per endpoint (deduped).
type hostHeaderCheck struct{}

func (hostHeaderCheck) Name() string     { return "host-header" }
func (hostHeaderCheck) Category() string { return "host_header" }
func (hostHeaderCheck) Tier() Tier       { return TierActive }
func (hostHeaderCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// hostHeaderBaseline captures the unpoisoned response shape used by the
// baseline-diff false-positive controls.
type hostHeaderBaseline struct {
	status int
	// locHost is the Hostname() of the baseline 3xx Location (empty if none).
	locHost string
	// bodyHasSentinelURL is true if the baseline body ALREADY reflects the
	// sentinel in a URL-host position (so a poisoned hit there is not new).
	bodyHasSentinelURL bool
}

// Run establishes a baseline then probes each Host-family vector once. Active-
// probe discipline mirrors probeCMDi / SSRFCheck: a ctx.Done()/budget check
// before every probe, a ProbeRecord per probe, and auth applied via
// cfg.Auth.ApplyToRequest. Skips endpoints whose baseline status is 404 (not a
// feature). Dedups so a host reflected via N headers yields ONE finding per
// shape, not N.
func (hostHeaderCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if cc == nil || cc.Cfg == nil || !cc.Cfg.EnableActive {
		return nil
	}

	maxProbes := effectiveMaxProbes(cc.Cfg)

	// Establish the unpoisoned baseline first. A 404 baseline is not a feature —
	// skip (mirrors headers/cors/ssrf not probing dead surfaces).
	baseline, ok := hostHeaderEstablishBaseline(ctx, cc, ep)
	if !ok {
		return nil
	}
	if baseline.status == http.StatusNotFound {
		return nil
	}

	var findings []ev.Evidence
	// Dedup flags: one finding per shape per endpoint, even when the host is
	// reflected via multiple Host-family headers.
	redirFlagged := false
	linkFlagged := false

	for _, v := range hostHeaderVectors() {
		// Once both shapes have fired there is nothing more to learn — stop
		// spending probes against this endpoint.
		if redirFlagged && linkFlagged {
			break
		}

		// Active discipline: soft-stop on cancellation, then budget cap — both
		// checked before sending the probe (mirrors probeCMDi).
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if cc.Audit.Count(ep.FullURL) >= maxProbes {
			logagg.Warn("host-header", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", maxProbes)
			return findings
		}

		status, location, body, ok := hostHeaderProbe(ctx, cc, ep, v)
		if !ok {
			continue
		}

		// ---- Signal (a): REDIRECT-HOST reflection ----
		if !redirFlagged && status >= 300 && status <= 399 {
			if h := hostHeaderLocationHost(location); h == hostHeaderSentinel {
				// Baseline-diff: a server that ALREADY redirects to the sentinel
				// (baseline.locHost == sentinel) is not attacker-controlled.
				if baseline.locHost != hostHeaderSentinel {
					redirFlagged = true
					findings = append(findings, hostHeaderRedirectFinding(ep, v, status, location))
					continue
				}
			}
		}

		// ---- Signal (b): BODY ABSOLUTE-LINK reflection ----
		if !linkFlagged && hostHeaderURLPositionRe.MatchString(body) {
			// Baseline-diff: the sentinel link must be NEW (absent in baseline).
			if !baseline.bodyHasSentinelURL {
				linkFlagged = true
				findings = append(findings, hostHeaderLinkFinding(ep, v, body))
				continue
			}
		}
	}

	return findings
}

// hostHeaderEstablishBaseline sends one UNPOISONED request via cc.NoFollow and
// captures the response shape (status, Location host, body-has-sentinel-URL) for
// the baseline-diff controls. Records a ProbeRecord. Returns ok=false on a build
// or transport error.
func hostHeaderEstablishBaseline(ctx context.Context, cc *CheckContext, ep Endpoint) (hostHeaderBaseline, bool) {
	select {
	case <-ctx.Done():
		return hostHeaderBaseline{}, false
	default:
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, nil)
	if err != nil {
		logagg.Warn("host-header", "failed to create baseline request", "error", err)
		return hostHeaderBaseline{}, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeHostHeader,
		Payload:   "(baseline)",
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("host-header", "baseline request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return hostHeaderBaseline{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, hostHeaderBodyLimit))
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)

	return hostHeaderBaseline{
		status:             resp.StatusCode,
		locHost:            hostHeaderLocationHost(resp.Header.Get("Location")),
		bodyHasSentinelURL: hostHeaderURLPositionRe.Match(body),
	}, true
}

// hostHeaderProbe sends ONE poisoned probe for the given Host-family vector via
// cc.NoFollow (so a 3xx Location is the raw signal, not a followed hop). Records
// a ProbeRecord. Returns (status, Location, body, ok); ok=false on a budget
// exhaustion, cancellation, build, or transport error.
func hostHeaderProbe(ctx context.Context, cc *CheckContext, ep Endpoint, v hostHeaderVector) (int, string, string, bool) {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		return 0, "", "", false
	}
	select {
	case <-ctx.Done():
		return 0, "", "", false
	default:
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, nil)
	if err != nil {
		logagg.Warn("host-header", "failed to create probe request", "error", err)
		return 0, "", "", false
	}
	// Go treats the Host header specially: req.Header.Set("Host", ...) is ignored
	// when the request is written — the Host header is taken from req.Host. So the
	// Host vector MUST set req.Host, while the X-Forwarded-* family are ordinary
	// headers set via req.Header.Set.
	if v.IsHost {
		req.Host = v.Value
	} else {
		req.Header.Set(v.Name, v.Value)
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeHostHeader,
		Payload:   v.Value,
		Parameter: v.Name,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("host-header", "probe request failed", "endpoint", ep.FullURL, "header", v.Name, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return 0, "", "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, hostHeaderBodyLimit))
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)

	return resp.StatusCode, resp.Header.Get("Location"), string(body), true
}

// hostHeaderLocationHost parses a raw Location header value and returns its
// EXACT lowercased Hostname() (trailing dot stripped). LOAD-BEARING: the
// comparison against the sentinel is exact-host equality, never a substring of
// the raw Location — so a redirect to the app's own host that merely carries the
// sentinel in a query param does NOT match. Returns "" when the value is empty or
// unparseable.
func hostHeaderLocationHost(location string) string {
	if location == "" {
		return ""
	}
	u, err := url.Parse(location)
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// hostHeaderRedirectFinding builds the HIGH/High redirect-host reflection finding.
func hostHeaderRedirectFinding(ep Endpoint, v hostHeaderVector, status int, location string) ev.Evidence {
	return ev.Evidence{
		RuleID:   "hostheader/redirect-host",
		Title:    "Host Header Injection — attacker-controlled redirect host",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "host_header",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: fmt.Sprintf(
			"Redirect host reflection: poisoning the %q header with sentinel %q produced status=%d Location=%q whose host (exact match) equals the attacker-controlled sentinel. The app builds absolute redirects from the client-supplied Host — open-redirect / password-reset-link poisoning.",
			v.Name, v.Value, status, location,
		),
		Fix: "Do not build absolute URLs from the client-supplied Host or X-Forwarded-* headers. Use a server-configured " +
			"canonical/allow-listed host for redirects, links and emails, and reject requests whose Host is not in the allow-list.",
		References: []string{"CWE-644", "CWE-601", "OWASP-A03"},
		Confidence: models.ConfidenceHigh,
		// The differential: the header we poisoned, and the Location that came
		// back built from it. A server that ignores the client Host returns its
		// own canonical host for the SAME poisoned request, so the pair — not
		// the redirect alone — is what confirms the claim.
		Payload:  fmt.Sprintf("%s: %s", v.Name, v.Value),
		Response: ProbeExcerpt(fmt.Sprintf("HTTP %d Location: %s", status, location)),
	}
}

// hostHeaderLinkFinding builds the body absolute-link reflection finding. It is
// HIGH when the surrounding context looks like a password-reset / verify flow or
// the match sits in an href/src attribute, MEDIUM otherwise.
func hostHeaderLinkFinding(ep Endpoint, v hostHeaderVector, body string) ev.Evidence {
	severity := models.SeverityMedium
	confidence := models.ConfidenceMedium
	linkContext := "off-origin absolute link"

	if hostHeaderResetContextRe.MatchString(body) || hostHeaderInHrefOrSrc(body) {
		severity = models.SeverityHigh
		confidence = models.ConfidenceHigh
		linkContext = "password-reset / verify-style absolute link"
	}

	match := hostHeaderURLPositionRe.FindString(body)
	return ev.Evidence{
		RuleID:   "hostheader/absolute-link",
		Title:    "Host Header Injection — attacker-controlled absolute link in body",
		Severity: severity,
		Source:   models.SourceBlackbox,
		Category: "host_header",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: fmt.Sprintf(
			"Body absolute-link reflection (%s): poisoning the %q header with sentinel %q caused the response body to emit a URL in a host position (%q) built from the attacker-controlled Host — link/cache poisoning.",
			linkContext, v.Name, v.Value, match,
		),
		Fix: "Do not build absolute URLs from the client-supplied Host or X-Forwarded-* headers. Generate links from a " +
			"server-configured canonical host, and validate/allow-list the Host on every request.",
		References: []string{"CWE-644", "CWE-601", "OWASP-A03"},
		Confidence: confidence,
		// The differential: the poisoned header, and the URL the body emitted
		// in a host position built from it.
		Payload:  fmt.Sprintf("%s: %s", v.Name, v.Value),
		Response: ProbeExcerpt(match),
	}
}

// hostHeaderInHrefOrSrc reports whether the sentinel URL appears inside an href=
// or src= attribute — a strong signal the reflection is a clickable/loadable
// absolute link rather than incidental prose.
func hostHeaderInHrefOrSrc(body string) bool {
	loc := hostHeaderURLPositionRe.FindStringIndex(body)
	if loc == nil {
		return false
	}
	// Look back a bounded window before the match for an href=/src= attribute.
	start := loc[0] - 16
	if start < 0 {
		start = 0
	}
	prefix := strings.ToLower(body[start:loc[0]])
	return strings.Contains(prefix, "href=") || strings.Contains(prefix, "src=")
}
