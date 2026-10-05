package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Browser-document headers (CSP, X-Frame-Options, COOP, COEP,
// Permissions-Policy) constrain a browser RENDERING a document. On a response
// parsed as data they describe a control that had nothing to control, so they
// are de-escalated to INFO — never deleted, and never on a guess about the
// media type.

func headersFor(t *testing.T, contentType string, extra map[string]string) []ev.Evidence {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/api/data", FullURL: server.URL + "/api/data"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	return CheckHeaders(context.Background(), cfg, ep)
}

func findByTitle(evs []ev.Evidence, substr string) (ev.Evidence, bool) {
	for _, e := range evs {
		if strings.Contains(e.Title, substr) {
			return e, true
		}
	}
	return ev.Evidence{}, false
}

// A JSON API response: the missing-CSP finding is preserved but INFO, so it
// stops producing a WARN that implies a protection is missing.
func TestJSONResponseDeescalatesDocumentHeaders(t *testing.T) {
	found := headersFor(t, "application/json", nil)

	csp, ok := findByTitle(found, "Content-Security-Policy")
	if !ok {
		t.Fatalf("the CSP observation must be PRESERVED, not deleted: %+v", found)
	}
	if csp.Severity != models.SeverityInfo {
		t.Errorf("missing CSP on a JSON API should be INFO, got %s", csp.Severity)
	}
	if !strings.Contains(csp.Evidence, "parses as data") {
		t.Errorf("the de-escalation must explain itself in the evidence: %s", csp.Evidence)
	}
	// The fix is still actionable if the endpoint ever serves a document.
	if csp.Fix == "" {
		t.Error("the remediation guidance must survive de-escalation")
	}
}

// Headers that genuinely matter for an API response are untouched. nosniff in
// particular is what stops a browser MIME-sniffing a JSON body into something
// executable, so de-escalating it would be a real regression.
func TestJSONResponseKeepsTransportAndSniffingHeaders(t *testing.T) {
	found := headersFor(t, "application/json", nil)

	nosniff, ok := findByTitle(found, "X-Content-Type-Options")
	if !ok {
		t.Fatal("X-Content-Type-Options must still be checked on an API response")
	}
	if nosniff.Severity != models.SeverityLow {
		t.Errorf("nosniff matters for JSON and must keep its severity, got %s", nosniff.Severity)
	}
	if strings.Contains(nosniff.Evidence, "parses as data") {
		t.Error("nosniff must not be de-escalated as a document-only header")
	}

	hsts, ok := findByTitle(found, "Strict-Transport-Security")
	if !ok {
		t.Fatal("HSTS must still be checked on an API response")
	}
	if strings.Contains(hsts.Evidence, "parses as data") {
		t.Error("HSTS governs the connection, not the document; it must not be de-escalated")
	}
}

// An HTML response keeps the existing behaviour byte for byte.
func TestHTMLResponseKeepsDocumentHeadersAtFullWeight(t *testing.T) {
	found := headersFor(t, "text/html; charset=utf-8", nil)

	csp, ok := findByTitle(found, "Content-Security-Policy")
	if !ok {
		t.Fatalf("expected a missing-CSP finding on an HTML response: %+v", found)
	}
	if csp.Severity != models.SeverityMedium {
		t.Errorf("missing CSP on a document must stay MEDIUM, got %s", csp.Severity)
	}
	if strings.Contains(csp.Evidence, "parses as data") {
		t.Error("an HTML response must not be treated as data")
	}
}

// The conservative case, and the one that matters most: an unknown or absent
// media type must change NOTHING. Not knowing what a response is can never be
// spent as a reason to care less about it.
func TestUnknownContentTypeChangesNothing(t *testing.T) {
	for _, ct := range []string{"", "application/octet-stream", "font/woff2", "video/mp4"} {
		t.Run("content-type="+ct, func(t *testing.T) {
			found := headersFor(t, ct, nil)
			csp, ok := findByTitle(found, "Content-Security-Policy")
			if !ok {
				t.Fatalf("expected a missing-CSP finding, got %+v", found)
			}
			if csp.Severity != models.SeverityMedium {
				t.Errorf("unrecognised media type %q must not de-escalate; got %s", ct, csp.Severity)
			}
		})
	}
}

// A redirect carries no rendered body of its own. It is classified by whatever
// Content-Type it actually sends: text/html is still a document, and a bare
// redirect with no media type falls to the conservative unknown branch.
func TestRedirectIsClassifiedByItsOwnContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(302)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/go", FullURL: server.URL + "/go"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	found := CheckHeaders(context.Background(), cfg, ep)

	if csp, ok := findByTitle(found, "Content-Security-Policy"); ok {
		if csp.Severity != models.SeverityMedium {
			t.Errorf("a redirect with no media type must take the conservative branch, got %s", csp.Severity)
		}
	}
}

// A static asset is de-escalated by the pre-existing B4 "static-asset" context,
// which is a CONFIDENCE penalty. That path is orthogonal to this one and must
// keep working alongside it.
func TestStaticAssetKeepsItsOwnResponseContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.WriteHeader(200)
	}))
	defer server.Close()

	ep := Endpoint{Method: "GET", Path: "/static/app.js", FullURL: server.URL + "/static/app.js"}
	cfg := &models.ScanConfig{Timeout: 10, AllowPrivate: true}
	found := CheckHeaders(context.Background(), cfg, ep)

	csp, ok := findByTitle(found, "Content-Security-Policy")
	if !ok {
		t.Fatalf("expected a missing-CSP finding on a static asset: %+v", found)
	}
	if csp.ResponseContext != "static-asset" {
		t.Errorf("the B4 static-asset context must still be tagged, got %q", csp.ResponseContext)
	}
}

// The classifier itself, including the three-state contract the caller depends
// on. A false/false result means "unknown", not "not a document".
func TestClassifyDocumentRendering(t *testing.T) {
	cases := []struct {
		ct    string
		isDoc bool
		known bool
	}{
		{"text/html", true, true},
		{"text/html; charset=utf-8", true, true},
		{"application/xhtml+xml", true, true},
		{"image/svg+xml", true, true},
		{"application/json", false, true},
		{"application/json; charset=utf-8", false, true},
		{"application/problem+json", false, true},
		{"application/vnd.api+json", false, true},
		{"application/xml", false, true},
		{"text/csv", false, true},
		// Unknown — the third state.
		{"", false, false},
		{"application/octet-stream", false, false},
		{"text/plain", false, false},
		{"font/woff2", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			isDoc, known := classifyDocumentRendering(tc.ct)
			if isDoc != tc.isDoc || known != tc.known {
				t.Errorf("classify(%q) = (%v, %v), want (%v, %v)",
					tc.ct, isDoc, known, tc.isDoc, tc.known)
			}
		})
	}
}
