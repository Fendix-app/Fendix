package scanner

// Reflected cross-site scripting (CWE-79) active check.
//
// This is the highest-false-positive-risk active check in the engine: almost
// every web app reflects *some* user input somewhere, so "input appears in the
// response" on its own is worthless signal. The two false-positive controls in
// this file ARE the check — they are non-negotiable:
//
//  1. CONTENT-TYPE GATE (the single biggest control). A response is only
//     considered for XSS if its Content-Type contains "text/html". Reflected
//     markup in application/json, text/plain, XML, or a missing Content-Type is
//     not parsed as HTML by a conforming browser, so it is not reflected XSS.
//     We emit NOTHING for non-text/html responses.
//
//  2. ENCODED-VS-RAW DISTINCTION. Mere reflection of the canary marker is NOT a
//     finding (that is the same trap as the CMDi reflection FP). We require the
//     HTML metacharacters of the payload to survive UN-encoded adjacent to the
//     per-probe random marker — concretely, the literal substring
//     "<svg/onload=" + marker. If the body instead entity-encodes the brackets
//     (&lt;svg, &gt;, &quot;, &#x3c;, &#60;), the input was correctly output-
//     encoded and is safe → no finding.
//
// KNOWN LIMITS (documented false negatives — deliberate scope, not bugs):
//   - DOM-based XSS and stored/persistent XSS are OUT OF SCOPE. We send one
//     request and inspect its immediate response body; sinks that fire in
//     client-side JS, or reflections that surface on a *different* page/request,
//     are not detected.
//   - ATTRIBUTE-CONTEXT-WITHOUT-BREAKOUT is suppressed. If the app reflects into
//     an attribute value but neutralizes the breakout quote/angle-bracket, the
//     "<svg/onload=" substring never appears and we (correctly) do not flag —
//     but a context-specific payload might still execute (e.g. event-handler
//     attribute injection). Documented FN.
//   - CONTENT-TYPE-SNIFFING CLIENTS. Old/misconfigured clients that render a
//     text/plain (or no-Content-Type) body as HTML would execute a reflection
//     the Content-Type gate suppresses here. We accept that FN to kill the
//     dominant FP class. Modern browsers send X-Content-Type-Options or honor
//     the declared type, so this is rare in practice.
//   - SINGLE CANARY PAYLOAD. We send exactly one payload ("><svg/onload=...>)
//     per target. A WAF or filter that strips the <svg tag specifically (but
//     would let <img/<iframe/etc. through) yields a FN. The single payload is a
//     deliberate budget choice — the probe budget is SHARED per-endpoint with
//     the injection check, so spraying tag variants would starve SQLi/CMDi.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// xssMarkerPrefix prefixes every per-probe random canary. The full marker is
// xssMarkerPrefix + randHex(8); searching for it avoids matching the literal
// payload constant if it ever appears in static page content.
//
// Encoded-reflection forms we treat as SAFE (the brackets did NOT survive raw):
// a correctly output-encoding app emits the marker surrounded by entity forms
// such as &lt;svg, &lt;, &gt;, &quot;, &#x3c;, or &#60; instead of the literal
// "<svg/onload=" + marker. Because our decision is "raw signature present?",
// any of these encoded forms simply means the raw signature is ABSENT → no
// finding. No explicit encoded-list check is needed; absence of the raw
// signature is the safe path.
const xssMarkerPrefix = "fendixXSS"

// randHex returns n random bytes hex-encoded (2n chars). Used for the per-probe
// XSS canary so each probe's marker is unique and cannot collide with static
// page text. crypto/rand makes the marker unguessable by a target trying to
// fingerprint and special-case the scanner.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read never returns an error on supported platforms; fall
		// back to a fixed token rather than panicking mid-scan.
		return "fendixfallback"
	}
	return hex.EncodeToString(b)
}

// reflectedXSSCheck is the active reflected-XSS (CWE-79) check. For each probe
// target it sends ONE canary payload, gates hard on Content-Type text/html, and
// distinguishes raw (executable) from entity-encoded (safe) reflection.
type reflectedXSSCheck struct{}

func (reflectedXSSCheck) Name() string     { return "xss" }
func (reflectedXSSCheck) Category() string { return "injection" }
func (reflectedXSSCheck) Tier() Tier       { return TierActive }
func (reflectedXSSCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// Run probes every (param, location) target with a single XSS canary. Active
// discipline mirrors probeCMDi/openRedirectCheck: a ctx.Done()/budget check
// before each probe, a ProbeRecord per probe, auth via cfg.Auth.ApplyToRequest.
// At most one finding per target is emitted. Uses cc.Client (follows redirects)
// because the signal is the response BODY, not a raw Location header.
func (reflectedXSSCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if !cc.Cfg.EnableActive {
		return nil
	}

	var findings []ev.Evidence
	maxProbes := effectiveMaxProbes(cc.Cfg)

	for _, t := range targetsForEndpoint(ep) {
		// Active discipline: soft-stop on cancellation, then budget cap — both
		// checked before sending the probe (mirrors probeCMDi).
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if cc.Audit.Count(ep.FullURL) >= maxProbes {
			logagg.Warn("xss", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", maxProbes)
			return findings
		}

		if f, ok := probeXSS(ctx, cc, ep, t.Name, t.Location); ok {
			findings = append(findings, f)
		}
	}

	return findings
}

// probeXSS sends a single reflected-XSS canary into the given target and returns
// a finding iff the payload's HTML metacharacters survive un-encoded in a
// text/html response. Returns (finding, true) on a hit, (zero, false) otherwise.
// Always records a ProbeRecord.
func probeXSS(ctx context.Context, cc *CheckContext, ep Endpoint, param string, loc ProbeLocation) (ev.Evidence, bool) {
	// Per-probe random marker: unique per probe so a reflection cannot collide
	// with static page text, and unguessable so the target can't fingerprint it.
	marker := xssMarkerPrefix + randHex(8)
	// Breaks out of both attribute and text context and carries the HTML
	// metacharacters (", <, >, /) that MUST survive un-encoded for execution.
	payload := `"><svg/onload=` + marker + `>`
	// The raw signature whose survival proves the markup was not output-encoded.
	rawSignature := `<svg/onload=` + marker

	start := time.Now()
	req, err := buildProbeRequest(ctx, ep, param, payload, loc)
	if err != nil {
		logagg.Warn("xss", "failed to create xss probe request", "error", err)
		return ev.Evidence{}, false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.Client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeXSS,
		Payload:   payload,
		Parameter: param,
		Method:    ep.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("xss", "xss probe request failed", "endpoint", ep.FullURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	ct := resp.Header.Get("Content-Type")
	resp.Body.Close()
	record.Status = resp.StatusCode

	// 4xx/5xx skip: HTML error pages frequently echo the query string verbatim
	// (a self-reflection FP that isn't a real injection surface). Record and
	// bail before any body inspection.
	if resp.StatusCode >= 400 {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}

	// CONTENT-TYPE GATE (the single biggest FP control). If the response is not
	// text/html, a conforming browser will not parse the reflection as markup —
	// reflected payload in application/json / text/plain / xml / missing CT is
	// NOT reflected XSS. Emit nothing.
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}

	bodyStr := string(body)

	// ENCODED-VS-RAW DISTINCTION. The raw "<svg/onload=marker" substring proves
	// the angle brackets and slash survived un-encoded → executable markup. If
	// it is absent, the reflection was either encoded or stripped → safe, no
	// finding (mere marker reflection is not XSS).
	if !strings.Contains(bodyStr, rawSignature) {
		cc.Audit.Record(record)
		return ev.Evidence{}, false
	}

	// Confirmed raw survival in a text/html body → executable → HIGH/HIGH.
	record.Finding = true
	cc.Audit.Record(record)

	evidence := fmt.Sprintf(
		"Reflected XSS confirmed: payload %q reflected un-encoded in a text/html response (Content-Type %q), %s. Marker %q with raw HTML metacharacters survived (not entity-encoded).",
		payload, ct, paramLabel(param, loc), marker,
	)
	if snippet := xssSnippet(bodyStr, rawSignature); snippet != "" {
		evidence += fmt.Sprintf(" Snippet: %s", snippet)
	}

	return ev.Evidence{
		RuleID:   "xss/reflected",
		Title:    "Reflected Cross-Site Scripting (XSS)",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "injection",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: evidence,
		Fix: "Contextually output-encode all user input rendered into HTML (HTML-entity-encode <, >, \", ', &). " +
			"Set a restrictive Content-Security-Policy and prefer framework auto-escaping over manual string concatenation.",
		References: []string{"CWE-79", "OWASP-A03"},
		Confidence: models.ConfidenceHigh,
		// The differential: the canary we injected, and the body region proving
		// its HTML metacharacters survived un-encoded. The snippet — not the
		// whole body — is what confirms the claim.
		Payload:  payload,
		Response: ProbeExcerpt(xssSnippet(bodyStr, rawSignature)),
	}, true
}

// xssSnippet returns a body excerpt centered on the raw signature, capped at
// ~200 chars, for finding evidence — never the whole body. Returns "" if the
// signature isn't present (the caller already verified it is).
func xssSnippet(body, signature string) string {
	idx := strings.Index(body, signature)
	if idx < 0 {
		return ""
	}
	const span = 100
	startIdx := idx - 30
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := idx + len(signature) + span
	if endIdx > len(body) {
		endIdx = len(body)
	}
	snippet := body[startIdx:endIdx]
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	return snippet
}
