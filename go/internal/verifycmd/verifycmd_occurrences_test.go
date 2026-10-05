package verifycmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// cspServer serves the CSP header on every path except `missing`.
func cspServer(t *testing.T, missing string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != missing {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func groupedCSP(withOccurrences bool) models.Finding {
	f := models.Finding{
		ID: "SEC-001", Title: "Missing Content-Security-Policy header", Category: "headers",
		Endpoint: "GET /a", AffectedEndpoints: []string{"GET /a", "GET /b"},
	}
	if withOccurrences {
		f.Fingerprint = strings.Repeat("a", 40)
		f.Occurrences = []models.Occurrence{
			{Endpoint: "GET /a", Fingerprint: strings.Repeat("a", 40)},
			{Endpoint: "GET /b", Fingerprint: strings.Repeat("b", 40)},
		}
	}
	return f
}

// The primary location is fixed, another occurrence is not: the group is
// still present, never "resolved".
func TestVerify_GroupIsResolvedOnlyWhenEveryOccurrenceIs(t *testing.T) {
	for _, withOcc := range []bool{true, false} {
		srv := cspServer(t, "/b")
		baseline := writeBaseline(t, t.TempDir(), []models.Finding{groupedCSP(withOcc)})
		r, err := Run(context.Background(), "SEC-001", Options{BaselinePath: baseline, URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != StatusStillPresent {
			t.Errorf("occurrences=%v: status %v (%s); want still-present — GET /b is still missing CSP", withOcc, r.Status, r.Reason)
		}
		if len(r.Occurrences) != 2 {
			t.Fatalf("want a verdict per occurrence, got %+v", r.Occurrences)
		}
		for _, o := range r.Occurrences {
			want := StatusResolved
			if o.Endpoint == "GET /b" {
				want = StatusStillPresent
			}
			if o.Status != want {
				t.Errorf("%s: %v, want %v", o.Endpoint, o.Status, want)
			}
		}
	}

	srv := cspServer(t, "/nothing-missing")
	baseline := writeBaseline(t, t.TempDir(), []models.Finding{groupedCSP(true)})
	r, _ := Run(context.Background(), "SEC-001", Options{BaselinePath: baseline, URL: srv.URL})
	if r.Status != StatusResolved {
		t.Errorf("every occurrence fixed: status %v (%s); want resolved", r.Status, r.Reason)
	}
}

// An occurrence that cannot be re-tested keeps the group from resolving.
func TestVerify_UnverifiableOccurrenceIsNotResolved(t *testing.T) {
	f := groupedCSP(true)
	f.Occurrences[1].Endpoint, f.AffectedEndpoints[1] = "pkg/x.py:3", "pkg/x.py:3"
	srv := cspServer(t, "/nothing-missing")
	baseline := writeBaseline(t, t.TempDir(), []models.Finding{f})
	r, _ := Run(context.Background(), "SEC-001", Options{BaselinePath: baseline, URL: srv.URL})
	if r.Status == StatusResolved {
		t.Errorf("status resolved although one occurrence was never re-tested: %+v", r.Occurrences)
	}
}
