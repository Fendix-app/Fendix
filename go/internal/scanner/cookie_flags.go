package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// cookieFlagsCheck is a passive Check that inspects Set-Cookie headers on a
// single GET and flags missing security attributes (HttpOnly, Secure,
// SameSite) on session-shaped cookies. It is deliberately conservative:
// analytics/preference cookies are ignored outright, deletion cookies are
// skipped, and Secure is only required over https. CWE-1004 / CWE-614 /
// CWE-1275.
//
// Cookies are classified into session/auth vs CSRF double-submit token vs
// ignore (see classifyCookie), because the HttpOnly EXPECTATION differs between
// the first two: a session credential must be unreadable by script, a CSRF
// token must be readable. The Secure and SameSite expectations are identical
// for both and are checked identically.
type cookieFlagsCheck struct{}

func (cookieFlagsCheck) Name() string                        { return "cookie-flags" }
func (cookieFlagsCheck) Category() string                    { return "cookie" }
func (cookieFlagsCheck) Tier() Tier                          { return TierPassive }
func (cookieFlagsCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// cookieIgnoreList holds lowercase substrings of cookie names that are
// analytics / preference / consent cookies — never session credentials. A
// match here WINS over any session-shaped heuristic (no flag emitted), since a
// long opaque _ga value would otherwise trip the length heuristic.
var cookieIgnoreList = []string{
	"_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "ajs_", "mp_",
	"optimizely", "intercom", "__utm", "amplitude", "mixpanel", "_pk_",
	"_clck", "_clsk", "hubspotutk", "locale", "lang", "theme", "currency",
	"timezone", "cookie_consent", "cookieconsent", "consent",
}

// cookieSessionList holds lowercase substrings that strongly indicate a
// session / auth credential cookie. A name match here flags the cookie even if
// its value is short.
var cookieSessionList = []string{
	"session", "sess", "sid", "auth", "token", "jwt",
	"remember", "login", "jsessionid", "phpsessid", "asp.net_sessionid",
	"connect.sid", "laravel_session",
}

// cookieCSRFList holds lowercase substrings of cookies that are CSRF
// double-submit tokens. These are DELIBERATELY readable by JavaScript in the
// Django / Rails / Angular / Laravel AJAX patterns — the client has to read the
// token to echo it back in a header — so "missing HttpOnly" is the EXPECTED
// configuration, not a session-credential defect.
//
// "csrf" and "xsrf" used to live in cookieSessionList, which is what produced
// the mislabel this list exists to fix. They are checked BEFORE that list and
// the ordering is load-bearing: "csrftoken" also contains "token", so a
// session-first order silently reproduces the bug. classifyCookie's test table
// pins it.
var cookieCSRFList = []string{"csrf", "xsrf"}

// cookieClass is what a Set-Cookie was judged to be. It exists because the
// HttpOnly expectation differs by class while the Secure and SameSite
// expectations do not.
type cookieClass int

const (
	cookieClassNone    cookieClass = iota // not session-shaped, or ignore-listed → no findings
	cookieClassSession                    // session / auth credential
	cookieClassCSRF                       // CSRF double-submit token
)

func (cookieFlagsCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	client := cc.Client

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("cookie-flags", "cookie-flags check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("cookie-flags", "cookie-flags check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	// Skip only where there is no signal: a missing resource (404/410) or a
	// server fault (5xx) sets cookies from framework/error-page paths, not from
	// a feature surface (FP corpus pattern P2).
	//
	// A 4xx AUTH response is different, and blanket-skipping it was a false
	// negative: a login endpoint answering 401 while issuing a session cookie
	// without HttpOnly is a real, exploitable finding — arguably the single
	// most security-relevant Set-Cookie a scan can observe. Per Rule 3 the
	// evidence is preserved and the confidence scorer de-escalates it via the
	// shared B4 context, exactly like the header and CORS checks.
	if resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusGone ||
		resp.StatusCode >= 500 {
		return nil
	}

	isHTTPS := strings.HasPrefix(strings.ToLower(endpoint.FullURL), "https://")
	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	respContext := responseContextFor(resp.StatusCode, endpoint.Path)

	var findings []ev.Evidence
	// Dedup per (cookie-name, flag) so repeated Set-Cookie for the same name
	// (e.g. set twice in one response) emits at most one finding per flag.
	seen := make(map[string]bool)
	emit := func(name, flag string, f ev.Evidence) {
		key := strings.ToLower(name) + "|" + flag
		if seen[key] {
			return
		}
		seen[key] = true
		// B4: stamp the de-escalation context ("4xx" on an auth-gated response,
		// "static-asset" on a CDN path). Empty on a normal 2xx/3xx API route,
		// which leaves the finding at full confidence.
		f.ResponseContext = respContext
		findings = append(findings, f)
	}

	for _, c := range resp.Cookies() {
		if isDeletionCookie(c) {
			continue
		}
		class := classifyCookie(c)
		if class == cookieClassNone {
			continue
		}

		// Missing HttpOnly. What that MEANS depends on the class, and it is the
		// only expectation that does: a session credential must not be
		// readable by script, while a CSRF double-submit token has to be.
		if !c.HttpOnly {
			if class == cookieClassCSRF {
				// Rule 3: the observation is preserved and de-escalated, never
				// suppressed. Reporting it as a session-credential defect was a
				// mislabel, not a false positive — the cookie really is
				// readable by document.cookie, and a reader still wants to see
				// that and confirm the name is not misleading them.
				//
				// The title keeps the substring "HttpOnly" deliberately: it is
				// the observation being reported, and the DVWA corpus matches
				// its expected cookie finding on that substring in the title.
				emit(c.Name, "csrf-httponly", ev.Evidence{
					RuleID:            "cookies/csrf-no-httponly",
					Title:             "CSRF cookie readable by JavaScript (no HttpOnly) — expected for double-submit patterns (Django/Rails AJAX); verify this is intentional",
					Severity:          models.SeverityInfo,
					Source:            models.SourceBlackbox,
					Category:          "cookie",
					Endpoint:          epLabel,
					Evidence:          fmt.Sprintf("Set-Cookie %q has no HttpOnly attribute (CSRF double-submit token)", c.Name),
					Fix:               fmt.Sprintf("No action needed if %q is a CSRF double-submit token your JS client reads. If it is NOT, set HttpOnly and rename it so it is not mistaken for one.", c.Name),
					References:        []string{"CWE-1004"},
					Confidence:        models.ConfidenceHigh,
					DirectObservation: true,
				})
			} else {
				// Exposes the cookie to document.cookie / XSS theft.
				emit(c.Name, "httponly", ev.Evidence{
					RuleID:            "cookies/session-no-httponly",
					Title:             "Session cookie missing HttpOnly flag",
					Severity:          models.SeverityMedium,
					Source:            models.SourceBlackbox,
					Category:          "cookie",
					Endpoint:          epLabel,
					Evidence:          fmt.Sprintf("Set-Cookie %q has no HttpOnly attribute", c.Name),
					Fix:               fmt.Sprintf("Set the HttpOnly attribute on the %q cookie so client-side script cannot read it.", c.Name),
					References:        []string{"CWE-1004"},
					Confidence:        models.ConfidenceHigh,
					DirectObservation: true,
				})
			}
		}

		// Missing Secure — only meaningful over https (Secure is a no-op /
		// not assertable on plain http responses).
		//
		// REACHABLE FOR BOTH CLASSES, on purpose. A CSRF token has to be
		// readable by script, but it does NOT have to travel in the clear, and
		// SameSite=None on one is a real CSRF-permissive setting. Neither
		// branch is re-titled either: models.Fingerprint hashes
		// (Category, Endpoint, Title) and dedupKey hashes
		// (Severity, Category, Title), so re-wording a title mints new
		// identities and breaks every committed .fendix-ignore fingerprint rule
		// and --baseline entry for it. The residual "Session cookie …" wording
		// on a csrftoken is an accepted mislabel here; only the HttpOnly claim,
		// which was actively wrong, changes.
		if isHTTPS && !c.Secure {
			emit(c.Name, "secure", ev.Evidence{
				RuleID:            "cookies/session-no-secure",
				Title:             "Session cookie missing Secure flag",
				Severity:          models.SeverityMedium,
				Source:            models.SourceBlackbox,
				Category:          "cookie",
				Endpoint:          epLabel,
				Evidence:          fmt.Sprintf("Set-Cookie %q has no Secure attribute over HTTPS", c.Name),
				Fix:               fmt.Sprintf("Set the Secure attribute on the %q cookie so it is only sent over TLS.", c.Name),
				References:        []string{"CWE-614"},
				Confidence:        models.ConfidenceHigh,
				DirectObservation: true,
			})
		}

		// SameSite missing/None. net/http parses an ABSENT SameSite attribute
		// to the zero value http.SameSite(0) (no exported const), and an
		// explicit/unrecognized "SameSite" with no value to SameSiteDefaultMode
		// (which is 1 in this Go version, not 0). Treat both — plus None — as
		// weak. Strict/Lax → no finding.
		//
		// Deliberately NOT a DirectObservation: the sentence above is the
		// reason. The scanner cannot distinguish an absent attribute from an
		// unrecognized one, so the claim is an inference about which of two
		// parses happened — which is also why this finding already carries
		// ConfidenceMedium while HttpOnly and Secure (plain boolean reads of
		// the parsed Set-Cookie) carry ConfidenceHigh.
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode || c.SameSite == http.SameSiteNoneMode {
			severity := models.SeverityLow
			detail := "no SameSite attribute (or an unrecognized value)"
			if c.SameSite == http.SameSiteNoneMode {
				detail = "SameSite=None"
				// SameSite=None without Secure is rejected by browsers and is
				// CSRF-permissive — escalate.
				if !c.Secure {
					severity = models.SeverityMedium
				}
			}
			emit(c.Name, "samesite", ev.Evidence{
				RuleID:     "cookies/session-weak-samesite",
				Title:      "Session cookie missing or weak SameSite attribute",
				Severity:   severity,
				Source:     models.SourceBlackbox,
				Category:   "cookie",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Set-Cookie %q has %s", c.Name, detail),
				Fix:        fmt.Sprintf("Set SameSite=Lax (or Strict) on the %q cookie to mitigate CSRF. If SameSite=None is required, also set Secure.", c.Name),
				References: []string{"CWE-1275"},
				Confidence: models.ConfidenceMedium,
			})
		}
	}

	return findings
}

// isDeletionCookie reports whether a Set-Cookie is clearing the cookie rather
// than setting a live value. Max-Age<0 is an explicit immediate-expire; an
// empty value with an Expires in the past is the legacy clear idiom.
func isDeletionCookie(c *http.Cookie) bool {
	if c.MaxAge < 0 {
		return true
	}
	if c.Value == "" && !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
		return true
	}
	return false
}

// classifyCookie decides what a cookie is: an analytics/preference cookie worth
// no findings, a CSRF double-submit token, or a session/auth credential.
//
// The precedence is the whole point and each step earns its place:
//
//  1. the ignore-list (analytics/preferences) still WINS over every heuristic —
//     a long opaque _ga value would otherwise trip the length rule;
//  2. the CSRF list comes BEFORE the session list, because "csrftoken" contains
//     "token" and a session-first order reproduces the mislabel;
//  3. the session list;
//  4. the length heuristic, unchanged: a long opaque value that is not a small
//     integer is credential-shaped.
//
// Anything a caller wants to know beyond "is this worth checking" is carried by
// the class, so the HttpOnly branch can be right about a CSRF token without any
// other branch changing.
func classifyCookie(c *http.Cookie) cookieClass {
	name := strings.ToLower(c.Name)

	for _, ig := range cookieIgnoreList {
		if strings.Contains(name, ig) {
			return cookieClassNone
		}
	}

	for _, s := range cookieCSRFList {
		if strings.Contains(name, s) {
			return cookieClassCSRF
		}
	}

	for _, s := range cookieSessionList {
		if strings.Contains(name, s) {
			return cookieClassSession
		}
	}

	// Long opaque value that isn't a small integer → likely a token/session id.
	if len(c.Value) >= 16 && !isSmallInteger(c.Value) {
		return cookieClassSession
	}

	return cookieClassNone
}

// isSmallInteger reports whether v is a pure decimal integer (e.g. a unix
// timestamp or counter), which is not session-shaped on its own.
func isSmallInteger(v string) bool {
	if v == "" {
		return false
	}
	_, err := strconv.ParseInt(v, 10, 64)
	return err == nil
}
