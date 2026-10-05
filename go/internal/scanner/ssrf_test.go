package scanner

// Integration tests for the active in-band SSRF check (CWE-918). They drive
// SSRFCheck.Run against loopback httptest servers, so every cfg sets
// AllowPrivate: true. This is the SSRF TEST PARADOX: the netguard guard's
// allowPrivate=false would BLOCK the dial to the 127.0.0.1 test server (and to
// the unroutable canary literals), so the probe could never reach the handler.
// With AllowPrivate:true the egress guard is OFF — that is fine here because we
// are testing the DETECTOR's response-classification logic, NOT the egress
// guard (which has its own dedicated tests in ssrf_regression_test.go).
//
// The two negative tests are LOAD-BEARING and MUST stay green:
//   - TestSSRF_ReflectionNotSSRF: verbatim reflection of the param value is NOT
//     SSRF (the dominant FP — reflection != server-side fetch).
//   - TestSSRF_GenericErrorNoCanaryNoFinding: a generic "connection refused"
//     page that does NOT echo our canary host is NOT SSRF (FP guard a).
//   - TestSSRF_DocumentedBlindLimitFN: encodes the honest known gap — a server
//     that fetches the canary OUT-OF-BAND only (nothing observable in-band)
//     yields NO finding (fendix has no OAST callback server).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// activeSSRFCfg returns the standard active-scan config for these tests.
// AllowPrivate:true is mandatory — see the SSRF test paradox note above.
func activeSSRFCfg() *models.ScanConfig {
	return &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: true}
}

// ssrfEP builds an Endpoint declaring a single URL-shaped query param "url", so
// targetsForEndpoint yields exactly one (url, query) target that the urlParamRe
// filter accepts.
func ssrfEP(server *httptest.Server) Endpoint {
	return Endpoint{
		Method:  "GET",
		Path:    "/fetch",
		FullURL: server.URL + "/fetch",
		Params:  []string{"url"},
	}
}

// TestSSRF_ErrorLeak: handler, when the injected ?url= contains our canary host
// (under the .invalid sentinel), returns a body that echoes the canary host AND
// a fetch-stack error signature ("connection refused"). Both the canary host
// and the error signature present → HIGH/High SSRF finding (signal a).
func TestSSRF_ErrorLeak(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Simulate a server that tried to fetch the supplied URL and dumped the
		// upstream error (including the URL it attempted) into the response.
		if strings.Contains(target, "fendix.invalid") {
			_, _ = w.Write([]byte("Failed fetching " + target + ": dial tcp: connection refused"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 SSRF finding (error-leak), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity for error-leak, got %s", f.Severity)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("expected HIGH confidence for error-leak, got %s", f.Confidence)
	}
	if f.Category != "ssrf" {
		t.Errorf("expected category=ssrf, got %q", f.Category)
	}
	if !hasRef(f, "CWE-918") {
		t.Errorf("expected CWE-918 reference, got %v", f.References)
	}
	if f.Source != models.SourceBlackbox {
		t.Errorf("expected blackbox source, got %s", f.Source)
	}
}

// TestSSRF_ReflectedContentFetchIsOOBOnlyFN (HONEST KNOWN GAP): a server that
// actually FETCHES the canary URL and inlines the upstream content into the body
// — but emits no fetch-stack error and no 3xx redirect — is NOT detected in-band.
// The old code claimed a "marker reflected in body" HIGH for this shape, but that
// signal could not distinguish a real fetch from plain reflection of an injected
// URL component (see TestSSRF_QueryValueReflectionNotSSRF / SubdomainLabel...),
// so it was the dominant FP and was removed. Honest reflected-content fetch-back
// is confirmable only OUT-OF-BAND. This test asserts the gap so it stays honest.
func TestSSRF_ReflectedContentFetchIsOOBOnlyFN(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Model a real server-side fetch that inlines the (would-be) upstream body.
		// We have no OOB host to serve secret content, so the only string we could
		// look for is one we injected — indistinguishable from reflection in-band.
		if strings.Contains(target, "fendix.invalid") {
			_, _ = w.Write([]byte("<html><body>fetched upstream content for " + target + "</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body>nothing fetched</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("DOCUMENTED OOB LIMIT: reflected-content fetch-back without an error/redirect signal is an OOB-only FN and must produce 0 in-band findings, got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_QueryValueReflectionNotSSRF (LOAD-BEARING, FP regression): the
// handler reflects the injected URL's ?marker= query VALUE verbatim into the
// body ("you searched for: <value>") — classic query-value reflection. The
// reflected value IS the unique marker token (under the old design the marker
// was a substring of the canary host), so a content-marker signal that only
// guards against WHOLE-host echo fires HIGH here. It must NOT: reflecting an
// injected component is not a server-side fetch. Expect 0 findings.
func TestSSRF_QueryValueReflectionNotSSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Reflect the ?marker= value carried INSIDE the injected URL back into the
		// body, WITHOUT echoing the literal canary host. This models a search-style
		// endpoint: "you searched for: <the marker we injected>". No fetch happened.
		if u, err := url.Parse(target); err == nil {
			if m := u.Query().Get("marker"); m != "" {
				_, _ = w.Write([]byte("<html><body>you searched for: " + m + "</body></html>"))
				return
			}
		}
		_, _ = w.Write([]byte("<html><body>nothing</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING FP: query-value reflection of an injected component must produce 0 SSRF findings (reflection != fetch), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_SubdomainLabelReflectionNotSSRF (LOAD-BEARING, FP regression): the
// handler echoes the FIRST LABEL of the injected URL's host into the body. Under
// the old design that label equalled the canary which equalled the marker, so a
// content-marker signal fired HIGH on a mere subdomain-label echo. It must NOT.
// Expect 0 findings.
func TestSSRF_SubdomainLabelReflectionNotSSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo just the host's first label (e.g. "fendix-ssrf-deadbeef") — NOT the
		// full canary host. Models a tenant/subdomain greeting: "Welcome, <label>".
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			label := strings.SplitN(u.Host, ".", 2)[0]
			if label != "" {
				_, _ = w.Write([]byte("<html><body>Welcome, " + label + "</body></html>"))
				return
			}
		}
		_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING FP: subdomain-label reflection must produce 0 SSRF findings (echoing a host label != fetch), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_CamelCaseURLParam (FN regression): camelCase URL-shaped params
// (imageUrl, redirectUri, callbackURL) MUST be recognised as URL-shaped (and so
// probed), while non-URL camelCase/words that merely CONTAIN a keyword substring
// (occurl, comment) must NOT match. Asserts isURLShapedParam directly.
func TestSSRF_CamelCaseURLParam(t *testing.T) {
	probed := []string{"imageUrl", "redirectUri", "callbackURL", "image_url", "url"}
	for _, name := range probed {
		if !isURLShapedParam(name) {
			t.Errorf("expected %q to be recognised as a URL-shaped param (should be probed), but it was not", name)
		}
	}
	skipped := []string{"occurl", "comment", "description", "tourl", "quantity"}
	for _, name := range skipped {
		if isURLShapedParam(name) {
			t.Errorf("expected %q NOT to be recognised as a URL-shaped param (should be skipped), but it matched", name)
		}
	}
}

// TestSSRF_RedirectEcho: handler 302s with a Location header whose host is our
// canary host → MEDIUM finding via cc.NoFollow (signal b, redirect-echo).
func TestSSRF_RedirectEcho(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		// A server-side fetcher that 30x's onward to the supplied URL leaks the
		// canary host in the raw Location header.
		if strings.Contains(target, "fendix.invalid") {
			w.Header().Set("Location", target)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 SSRF finding (redirect-echo), got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity for redirect-echo, got %s", f.Severity)
	}
	if !hasRef(f, "CWE-918") {
		t.Errorf("expected CWE-918 reference, got %v", f.References)
	}
}

// TestSSRF_RedirectCanaryInQueryNotSSRF (LOAD-BEARING regression for the M-1
// FP): a server that does an OWN-HOST redirect (e.g. to its own /login) and
// merely reflects the injected URL into a query parameter of the Location must
// NOT be flagged. The redirect target host is the app's own host, not the
// canary — only a substring match (the bug) would fire. Mirrors the open-redirect
// and host-header checks, which both use exact url.Parse + Hostname() equality.
func TestSSRF_RedirectCanaryInQueryNotSSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		// Own-host redirect to /login that reflects the injected URL into a
		// `next=` query param. The Location's HOST is this server (127.0.0.1),
		// NOT the canary — the canary appears only inside the query string.
		w.Header().Set("Location", "/login?next="+target)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))
	if len(findings) != 0 {
		t.Fatalf("own-host redirect with canary only in the query string is NOT SSRF; want 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_ReflectionNotSSRF (LOAD-BEARING): handler reflects the param value
// VERBATIM into an HTML body — no fetch-stack error signature, no out-of-baseline
// marker, no redirect. Mere reflection of the input is NOT SSRF → 0 findings.
// This is the dominant false-positive class and the single most important guard.
func TestSSRF_ReflectionNotSSRF(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Echo the raw input back. The canary host WILL appear in the body, but
		// only because we reflected the input — there is no error signature and
		// no fetched marker. Reflection must NOT trip the error-leak guard (which
		// requires an error signature) nor the reflected-fetch guard (the marker
		// reflected here is part of the verbatim input, not a fetched body — but
		// since the whole input is echoed, the marker WOULD appear; the check
		// must therefore use a fetch-distinct marker form, see implementation).
		_, _ = w.Write([]byte("<html><body>You requested: " + target + "</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: verbatim reflection of the param value must produce 0 SSRF findings (reflection != SSRF), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_GenericErrorNoCanaryNoFinding (LOAD-BEARING, FP guard a): the body
// contains a fetch-stack error signature ("connection refused") but does NOT
// echo our canary host. This is a generic page error unrelated to our probe →
// 0 findings. The error-leak signal REQUIRES the canary host in the body to
// prove the server fetched OUR url.
func TestSSRF_GenericErrorNoCanaryNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Generic backend hiccup, no relation to the injected URL — never echoes
		// the canary host.
		_, _ = w.Write([]byte("<html><body>Backend error: connection refused while talking to the database</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("LOAD-BEARING: a generic 'connection refused' page without our canary host must produce 0 findings (FP guard a), got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_NonURLParamSkipped: an endpoint whose only param is non-URL-shaped
// ("comment") → the urlParamRe filter skips it, so no SSRF probes are sent and
// no findings are produced even against a server that WOULD leak.
func TestSSRF_NonURLParamSkipped(t *testing.T) {
	ResetGlobalAuditLog()
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		// Would leak if probed — proves the skip is the filter, not the handler.
		c := r.URL.Query().Get("comment")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetching " + c + ": connection refused"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	ep := Endpoint{
		Method:  "GET",
		Path:    "/comment",
		FullURL: server.URL + "/comment",
		Params:  []string{"comment"},
	}
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ep)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a non-URL-shaped param (urlParamRe filter), got %d: %+v", len(findings), findings)
	}
	if hit {
		t.Errorf("expected NO request to be sent for a non-URL-shaped param, but the handler was hit")
	}
}

// TestSSRF_NotActiveNoFinding: EnableActive=false → 0 findings, even against a
// blatantly leaking handler.
func TestSSRF_NotActiveNoFinding(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fetching " + target + ": connection refused"))
	}))
	defer server.Close()

	cfg := &models.ScanConfig{Timeout: 5, AllowPrivate: true, EnableActive: false}
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when EnableActive=false, got %d: %+v", len(findings), findings)
	}
}

// TestSSRF_DocumentedBlindLimitFN (HONEST KNOWN GAP): the server actually
// fetches the canary OUT-OF-BAND (would hit our sentinel host server-side) but
// returns NOTHING observable in-band — no error signature, no inlined marker,
// no redirect, no timing differential. Because fendix has no OAST callback
// server, this true-blind SSRF is UNDETECTABLE. This test ASSERTS the gap so it
// is honest and documented, not hidden.
func TestSSRF_DocumentedBlindLimitFN(t *testing.T) {
	ResetGlobalAuditLog()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pretend to fetch the URL server-side, swallow the result entirely, and
		// return a constant benign body regardless of input.
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Request accepted.</body></html>"))
	}))
	defer server.Close()

	cfg := activeSSRFCfg()
	findings := SSRFCheck{}.Run(context.Background(), NewCheckContext(cfg), ssrfEP(server))

	if len(findings) != 0 {
		t.Fatalf("DOCUMENTED OOB LIMIT: a true-blind out-of-band SSRF (nothing observable in-band) must produce 0 findings without an OAST server, got %d: %+v", len(findings), findings)
	}
}
