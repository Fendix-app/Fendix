package scanner

// Active HTTP method-tampering check (CWE-650 / CWE-693 / CWE-285).
//
// Many access-control filters are wired to a specific HTTP verb: a framework
// route guard, a reverse-proxy `location` block, or a servlet security
// constraint that only lists GET. If the application logic still SERVES the
// resource for an unlisted verb, an attacker swaps the verb and walks straight
// past the auth filter — a verb-based access-control bypass. Separately, some
// servers leave dangerous methods enabled (TRACE → Cross-Site Tracing; PUT /
// DELETE → arbitrary write/delete), which are findings on their own regardless
// of auth.
//
// ============================================================================
// TRIGGER GATE (LOAD-BEARING false-positive control — runs FIRST):
//
//   The auth-bypass comparison is only meaningful where the canonical verb is
//   actually gated. So before anything else we send ONE canonical request using
//   ep.Method WITH auth (the "authed canonical" baseline) and proceed only when:
//     (a) the authed canonical is 2xx (we have a working baseline to compare a
//         bypass against), OR
//     (b) the endpoint returned 401/403/405 (gated / method-restricted).
//   A PUBLIC 2xx endpoint with NO auth configured AND no 401/403/405 signal does
//   NOT get the auth-bypass comparison — a 200→200 verb flip on a public page is
//   not a bypass. (The dangerous-method probes — TRACE/PUT/DELETE — still run on
//   such endpoints: a public surface accepting writes is still a finding.)
//
// ============================================================================
// AUTH-BYPASS DETECTION (HIGH — the core signal):
//
//   The bypass signal is "the auth filter only covers SOME verbs":
//     (i)  establish the canonical verb WITHOUT credentials is gated (401/403);
//     (ii) try ALTERNATE verbs WITHOUT credentials;
//     (iii) an alternate verb that returns 2xx where canonical-no-auth was
//           401/403 → the filter does not cover that verb → HIGH bypass.
//   Alternate verbs tried: GET, POST, HEAD, OPTIONS, PUT (canonical skipped).
//
//   HEAD EMPTY-BODY SUPPRESSION (LOAD-BEARING FP): a 2xx on HEAD with no data-
//   bearing content is the EXPECTED HEAD contract (HEAD returns headers, no
//   body) and is NOT treated as a bypass on its own. The bypass finding requires
//   a BODY-BEARING verb (GET/POST/PUT) returning a non-trivial 2xx body. HEAD is
//   noted in evidence only when it also carried a data-bearing Content-Length.
//
// ============================================================================
// DANGEROUS METHODS (MEDIUM — run regardless of auth):
//
//   - TRACE enabled (2xx AND the response echoes the request line — the XST
//     signature) → MEDIUM Cross-Site Tracing (CWE-693).
//   - PUT or DELETE accepted (2xx, not 405/501/403/404) → MEDIUM dangerous
//     method enabled (CWE-650).
//
// ============================================================================
// DEDUP & CONFIDENCE:
//
//   One HIGH bypass finding lists ALL bypassing verbs in evidence (never N
//   findings). One MEDIUM dangerous-method finding lists ALL enabled dangerous
//   methods. Confidence: a clean 401/403 → 2xx flip is High; a weaker signal
//   (e.g. canonical-no-auth was 405, or the bypass body is thin) is Medium.
//
// ============================================================================
// KNOWN LIMITS (honest, documented false negatives — deliberate scope):
//
//   - TRACE/XST is confirmed only as "the method is enabled and echoes the
//     request". We do NOT prove a browser actually leaks an HttpOnly cookie via
//     XST (that needs a victim browser + a separate XSS/Flash vector); the
//     finding is the precondition, not a demonstrated cookie theft.
//   - A PUT "write" is NOT confirmed by a follow-up GET of the written resource.
//     fendix will not write to the target, so "PUT returned 2xx" is reported as
//     "dangerous method enabled", not "arbitrary file written and re-read".
//   - PATH-NORMALIZATION bypasses (e.g. /admin vs /admin/ vs /Admin vs
//     /admin%2f, or case/dot-segment tricks) are OUT OF SCOPE here — this check
//     varies the VERB, not the path.
//   - A CSRF-protected endpoint that 403s an unauthenticated alternate verb for
//     CSRF reasons (not auth) reads as "gated" and may FALSE-NEGATIVE a real
//     verb-bypass that would succeed with a valid CSRF token.
//   - BUDGET EXHAUSTION: the per-endpoint probe budget (effectiveMaxProbes) is
//     shared across the canonical baseline + every alternate/dangerous verb. On
//     a busy endpoint the budget can be spent before the later verbs are tried,
//     leaving them untested (a conservative false negative, never a false
//     positive).

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// methodTamperBodyLimit caps how much of each response body we read into memory.
const methodTamperBodyLimit = 1 << 20 // 1 MiB

// methodTamperBodyFloor is the minimum 2xx body length (bytes) that corroborates
// a body-bearing verb actually SERVED content (vs. an empty/trivial 2xx). Mirrors
// the auth-check corroboration floor: a status alone is a weak signal.
const methodTamperBodyFloor = 16

// methodTamperAltVerbs is the representative set of alternate verbs tried for the
// auth-bypass comparison. The canonical verb is skipped at probe time.
var methodTamperAltVerbs = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPut,
}

// methodTamperBodyBearing reports whether a verb is body-bearing for the bypass
// finding: a 2xx on one of these served (or could serve) data, unlike HEAD/
// OPTIONS whose empty 2xx is the expected contract.
func methodTamperBodyBearing(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodPost, http.MethodPut:
		return true
	}
	return false
}

// methodTamperCheck is the active HTTP method-tampering (CWE-650/693/285) check.
// It runs the trigger gate first, then (where warranted) the unauthenticated
// verb-bypass comparison, plus the always-on dangerous-method probes. At most
// ONE bypass finding and ONE dangerous-method finding per endpoint (deduped).
type methodTamperCheck struct{}

func (methodTamperCheck) Name() string     { return "method-tamper" }
func (methodTamperCheck) Category() string { return "method_tamper" }
func (methodTamperCheck) Tier() Tier       { return TierActive }
func (methodTamperCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// methodTamperResult captures the (status, body length, Content-Length>0, body
// echoes request) facts a single probe yields.
type methodTamperResult struct {
	status      int
	bodyLen     int
	hasBodyHdr  bool   // Content-Length advertised a non-empty body
	body        string // bounded copy, used for the TRACE echo check
	transportOK bool   // false on build/transport error or budget/cancellation
}

// Run executes the trigger gate, the unauthenticated verb-bypass comparison, and
// the dangerous-method probes. Active-probe discipline mirrors hostHeaderCheck:
// a ctx.Done()/budget check before every probe, a ProbeRecord per probe, and
// auth applied via cfg.Auth.ApplyToRequest. NoFollow is used so a 3xx to a login
// page reads as "not 2xx" (auth enforced) rather than being followed to a 200.
func (methodTamperCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if cc == nil || cc.Cfg == nil || !cc.Cfg.EnableActive {
		return nil
	}

	// ---- TRIGGER GATE (FIRST): authed canonical baseline ----
	canonAuthed := methodTamperProbe(ctx, cc, ep, ep.Method, true)
	if !canonAuthed.transportOK {
		return nil
	}

	canonAuthed2xx := is2xx(canonAuthed.status)
	gatedSignal := canonAuthed.status == http.StatusUnauthorized ||
		canonAuthed.status == http.StatusForbidden ||
		canonAuthed.status == http.StatusMethodNotAllowed

	// Proceed with the AUTH-BYPASS comparison only when the canonical verb looks
	// access-controlled or method-restricted: a working authed 2xx baseline OR a
	// 401/403/405 gate signal. A public 2xx with NO auth configured AND no gate
	// signal gets dangerous-method probes only (a 200→200 verb flip is not a
	// bypass).
	doBypass := canonAuthed2xx || gatedSignal
	if cc.Cfg.Auth == nil && canonAuthed2xx && !gatedSignal {
		doBypass = false
	}

	var findings []ev.Evidence

	if doBypass {
		if f, ok := methodTamperBypassFindings(ctx, cc, ep); ok {
			findings = append(findings, f)
		}
	}

	// ---- DANGEROUS METHODS (always, regardless of auth) ----
	// Pass the canonical baseline so a catch-all server (SPA host / proxy
	// try_files / API-gateway default route) that returns the SAME 2xx shell
	// for every verb is not mistaken for one that actually accepts writes.
	if f, ok := methodTamperDangerousFindings(ctx, cc, ep, canonAuthed); ok {
		findings = append(findings, f)
	}

	return findings
}

// methodTamperBypassFindings establishes that the canonical verb WITHOUT
// credentials is gated (401/403), then tries each alternate verb WITHOUT
// credentials. Returns ONE HIGH finding listing every body-bearing verb that
// returned a non-trivial 2xx where canonical-no-auth was gated, or ok=false.
func methodTamperBypassFindings(ctx context.Context, cc *CheckContext, ep Endpoint) (ev.Evidence, bool) {
	// (i) Canonical verb WITHOUT auth must be gated for the comparison to mean
	// anything. If the canonical verb is already open without auth, that is the
	// auth check's job (missing-authentication), not a verb-bypass.
	canonNoAuth := methodTamperProbe(ctx, cc, ep, ep.Method, false)
	if !canonNoAuth.transportOK {
		return ev.Evidence{}, false
	}
	gated := canonNoAuth.status == http.StatusUnauthorized || canonNoAuth.status == http.StatusForbidden
	if !gated {
		return ev.Evidence{}, false
	}

	// (ii)+(iii) Try each alternate verb WITHOUT auth; a body-bearing 2xx where
	// the canonical-no-auth was gated is a bypass. Dedup: collect all bypassing
	// verbs into ONE finding.
	var bypassVerbs []string
	headNoted := false
probeLoop:
	for _, verb := range methodTamperAltVerbs {
		if strings.EqualFold(verb, ep.Method) {
			continue // skip the canonical verb — it is the gated baseline
		}
		select {
		case <-ctx.Done():
			// Budget/cancellation: stop probing later verbs (documented limit —
			// late verbs left untested is a conservative false negative). Fall
			// through to finalize whatever was already observed.
			break probeLoop
		default:
		}
		res := methodTamperProbe(ctx, cc, ep, verb, false)
		if !res.transportOK {
			continue
		}
		if !is2xx(res.status) {
			continue
		}
		if methodTamperBodyBearing(verb) {
			// LOAD-BEARING: require a non-trivial body so an empty 2xx (e.g. a
			// soft-200 error page) does not count as served protected content.
			if res.bodyLen >= methodTamperBodyFloor {
				bypassVerbs = append(bypassVerbs, strings.ToUpper(verb))
			}
		} else if strings.EqualFold(verb, http.MethodHead) && res.hasBodyHdr {
			// HEAD EMPTY-BODY SUPPRESSION: a HEAD 2xx is a bypass note only when it
			// advertises a data-bearing body (Content-Length > 0). Even then we do
			// NOT raise the finding on HEAD alone — it is recorded in evidence.
			headNoted = true
		}
	}

	if len(bypassVerbs) == 0 {
		return ev.Evidence{}, false
	}
	sort.Strings(bypassVerbs)
	return methodTamperBypassFinding(ep, bypassVerbs, canonNoAuth.status, headNoted), true
}

// methodTamperDangerousFindings probes TRACE / PUT / DELETE and returns ONE
// MEDIUM finding listing every enabled dangerous method, or ok=false. These run
// regardless of auth — a public endpoint accepting writes/TRACE is still a
// finding.
func methodTamperDangerousFindings(ctx context.Context, cc *CheckContext, ep Endpoint, canon methodTamperResult) (ev.Evidence, bool) {
	var enabled []string
	traceXST := false

	// TRACE: 2xx AND the response body echoes the request line → XST.
	if res := methodTamperProbe(ctx, cc, ep, http.MethodTrace, false); res.transportOK {
		if is2xx(res.status) && methodTamperTRACEEchoed(res.body) {
			enabled = append(enabled, http.MethodTrace)
			traceXST = true
		}
	}

	// PUT / DELETE: 2xx (accepted) is the signal; 405/501/403/404 mean rejected.
	//
	// CATCH-ALL SUPPRESSION (FP control): a server that returns the SAME 2xx
	// shell for EVERY verb (SPA host with try_files, reverse-proxy default
	// route, API-gateway catch-all) is not accepting writes — it is echoing its
	// default page. When the canonical baseline was itself 2xx and a dangerous
	// verb returns the SAME status AND the same body, treat it as a catch-all
	// and do NOT flag it. (If the canonical was non-2xx — e.g. a gated 401 — a
	// dangerous-verb 2xx is a genuine signal and is kept.)
	canonCatchAll := is2xx(canon.status)
dangerLoop:
	for _, verb := range []string{http.MethodPut, http.MethodDelete} {
		select {
		case <-ctx.Done():
			break dangerLoop
		default:
		}
		if res := methodTamperProbe(ctx, cc, ep, verb, false); res.transportOK {
			if !is2xx(res.status) {
				continue
			}
			if canonCatchAll && res.status == canon.status && res.body == canon.body {
				// Same status + identical body as the canonical verb → catch-all
				// echo, not a real write acceptance.
				continue
			}
			enabled = append(enabled, verb)
		}
	}

	if len(enabled) == 0 {
		return ev.Evidence{}, false
	}
	sort.Strings(enabled)
	return methodTamperDangerousFinding(ep, enabled, traceXST), true
}

// methodTamperProbe sends ONE request for the given verb (with or without auth)
// via cc.NoFollow and returns the result. Active discipline: budget cap +
// ctx.Done() before sending, a ProbeRecord per probe, auth applied via
// cfg.Auth.ApplyToRequest only when withAuth is true.
func methodTamperProbe(ctx context.Context, cc *CheckContext, ep Endpoint, verb string, withAuth bool) methodTamperResult {
	if cc.Audit.Count(ep.FullURL) >= effectiveMaxProbes(cc.Cfg) {
		logagg.Warn("method-tamper", "max probes reached for endpoint", "endpoint", ep.FullURL, "max", effectiveMaxProbes(cc.Cfg))
		return methodTamperResult{}
	}
	select {
	case <-ctx.Done():
		return methodTamperResult{}
	default:
	}

	var body io.Reader
	if methodAcceptsBody(verb) {
		body = bodyForMethod(verb)
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, verb, ep.FullURL, body)
	if err != nil {
		logagg.Warn("method-tamper", "failed to create probe request", "verb", verb, "error", err)
		return methodTamperResult{}
	}
	setJSONContentType(req, verb)
	if withAuth {
		cc.Cfg.Auth.ApplyToRequest(req)
	}

	resp, err := cc.NoFollow.Do(req)
	elapsed := time.Since(start)
	authNote := "no-auth"
	if withAuth {
		authNote = "auth"
	}
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  ep.FullURL,
		ProbeType: ProbeMethodTamper,
		Payload:   verb + " (" + authNote + ")",
		Parameter: verb,
		Method:    verb,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("method-tamper", "probe request failed", "endpoint", ep.FullURL, "verb", verb, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return methodTamperResult{}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, methodTamperBodyLimit))
	resp.Body.Close()
	record.Status = resp.StatusCode
	cc.Audit.Record(record)

	return methodTamperResult{
		status:      resp.StatusCode,
		bodyLen:     len(raw),
		hasBodyHdr:  resp.ContentLength > 0,
		body:        string(raw),
		transportOK: true,
	}
}

// methodTamperTRACEEchoed reports whether a TRACE response body echoes the
// request line — the Cross-Site Tracing signature. A bare 2xx on TRACE without
// the echo is NOT enough (a server may 200 TRACE with an unrelated page).
func methodTamperTRACEEchoed(body string) bool {
	if body == "" {
		return false
	}
	upper := strings.ToUpper(body)
	// The hallmark: the body contains the literal "TRACE " request-method token,
	// typically as the echoed request line "TRACE <path> HTTP/1.1".
	return strings.Contains(upper, "TRACE ")
}

// is2xx reports whether status is in the 2xx range.
func is2xx(status int) bool {
	return status >= 200 && status < 300
}

// methodTamperBypassFinding builds the HIGH verb-based access-control bypass
// finding listing every bypassing verb. Confidence is High for a clean 401/403
// → 2xx flip (canonNoAuthStatus is 401/403, which is the only way we get here).
func methodTamperBypassFinding(ep Endpoint, bypassVerbs []string, canonNoAuthStatus int, headNoted bool) ev.Evidence {
	evidence := fmt.Sprintf(
		"Verb-based access-control bypass on %s %s: the canonical verb %s WITHOUT credentials returned %d (gated), "+
			"but the alternate verb(s) %s WITHOUT credentials returned a 2xx with a body — the auth filter only covers some verbs, "+
			"so an attacker reaches the protected resource by switching the HTTP method.",
		ep.Method, ep.Path, strings.ToUpper(ep.Method), canonNoAuthStatus, strings.Join(bypassVerbs, ", "),
	)
	if headNoted {
		evidence += " (A HEAD 2xx that advertised a non-empty Content-Length was also observed but is not itself treated as the bypass — HEAD returns no body by contract.)"
	}
	return ev.Evidence{
		RuleID:   "methodtamper/access-control-bypass",
		Title:    "HTTP method tampering — verb-based access-control bypass",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "method_tamper",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: evidence,
		Fix: "Apply authorization checks to the resource/handler, NOT to a specific HTTP method. Ensure the access-control " +
			"filter (framework guard, reverse-proxy location block, servlet security-constraint) covers ALL verbs — including " +
			"unlisted ones — and deny by default. Restrict each route to the methods it actually implements (405 for the rest).",
		References: []string{"CWE-650", "CWE-285", "OWASP-A01"},
		Confidence: models.ConfidenceHigh,
		// This check's confirmation is a CONTROLLED DIFFERENTIAL, not a single
		// response: the canonical verb without credentials was gated, the
		// alternate verb without credentials was not. Preserving both halves is
		// what justifies the claim — either half alone proves nothing, since a
		// 2xx on POST is unremarkable unless GET was refused.
		Payload: fmt.Sprintf("%s (unauthenticated) vs canonical %s (unauthenticated)",
			strings.Join(bypassVerbs, ", "), strings.ToUpper(ep.Method)),
		Response: ProbeExcerpt(fmt.Sprintf(
			"canonical %s → HTTP %d (gated); %s → HTTP 2xx with body (not gated)",
			strings.ToUpper(ep.Method), canonNoAuthStatus, strings.Join(bypassVerbs, ", "))),
	}
}

// methodTamperDangerousFinding builds the MEDIUM dangerous-method finding listing
// every enabled dangerous method. References include CWE-693 when TRACE/XST was
// confirmed and CWE-650 for PUT/DELETE.
func methodTamperDangerousFinding(ep Endpoint, enabled []string, traceXST bool) ev.Evidence {
	refs := []string{"CWE-650"}
	xstNote := ""
	if traceXST {
		refs = append([]string{"CWE-693"}, refs...)
		xstNote = " TRACE is enabled and echoes the request (Cross-Site Tracing / XST — a vector for stealing HttpOnly cookies via a separate client-side flaw)."
	}
	return ev.Evidence{
		RuleID:   "methodtamper/dangerous-method",
		Title:    "HTTP method tampering — dangerous method enabled",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
		Category: "method_tamper",
		Endpoint: fmt.Sprintf("%s %s", ep.Method, ep.Path),
		Evidence: fmt.Sprintf(
			"Dangerous HTTP method(s) enabled on %s: %s returned a 2xx (accepted), not 405/501/403/404.%s",
			ep.Path, strings.Join(enabled, ", "), xstNote,
		),
		Fix: "Disable HTTP methods the application does not need. Turn off TRACE/TRACK at the web-server/proxy layer. " +
			"Reject PUT/DELETE unless a route genuinely implements them, and gate any write verbs behind authorization.",
		References: refs,
		Confidence: models.ConfidenceMedium,
	}
}
