package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func configLeakCfg(target string) *models.ScanConfig {
	return &models.ScanConfig{URL: target, AllowPrivate: true}
}

// configleak's claim is a DETERMINISTIC READ of a live response: the status, the
// content type and the size, taken from the wire with no inference step. It
// deliberately never stores the body — persisting a leaked secret file would
// itself be a leak — so "the 200 + path is the proof" is the design, not an
// oversight.
//
// That is precisely what Evidence.DirectObservation means, and it was never
// set. After RC-1 removed the tautological blackbox signal, these CRITICAL
// findings had NO corroboration of any class and silently stopped gating.
func TestConfigLeakEarnsDirectObservation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A genuinely exposed .env: plain text, key=value.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("DB_PASSWORD=s3cr3t\nAPI_KEY=abcdef0123456789\n"))
	}))
	defer srv.Close()

	ep := Endpoint{Method: "GET", Path: "/.env", FullURL: srv.URL + "/.env"}
	got := configLeakCheck{}.Run(context.Background(), NewCheckContext(configLeakCfg(srv.URL)), ep)
	if len(got) == 0 {
		t.Fatal("no finding for a plain-text .env; the fixture no longer triggers the check")
	}

	f := got[0]
	if !f.DirectObservation {
		t.Error("DirectObservation = false — the claim IS the wire read, and without this the " +
			"finding has no corroborating signal of any class and can never gate")
	}
	d := decision.DecideWithOptions(f, "HIGH",
		decision.Options{EnforceConfidence: true, DeescalateTests: true})
	if d.Status != decision.StatusBlock {
		t.Errorf("Status = %q, want BLOCK (score=%d band=%s reason=%q)",
			d.Status, d.Score.Value, d.Score.Band, d.Reason)
	}
}

// THE CATCH-ALL FALSE POSITIVE. The existing guard rejects an HTML body, because
// SPA servers return index.html for every unknown path. A JSON API catch-all
// defeats it completely — and a JSON API is the far more common shape for the
// targets Fendix scans.
//
// Found end-to-end: a fixture returning application/json for every path produced
// five phantom CRITICALs (.env, .git/HEAD, .htaccess, .htpasswd, .DS_Store). A
// real .env / .git/HEAD / .htpasswd is never served as a JSON document.
func TestConfigLeakIgnoresJSONCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"data":[1,2,3],"note":"generic API response"}`))
	}))
	defer srv.Close()

	for _, path := range []string{"/.env", "/.git/HEAD", "/.htpasswd", "/.htaccess", "/.DS_Store"} {
		ep := Endpoint{Method: "GET", Path: path, FullURL: srv.URL + path}
		got := configLeakCheck{}.Run(context.Background(), NewCheckContext(configLeakCfg(srv.URL)), ep)
		if len(got) != 0 {
			t.Errorf("%s: got %d findings from a JSON catch-all, want 0 — %q",
				path, len(got), got[0].Evidence)
		}
	}
}

// The guard must not swing too far: a config file whose contents happen to look
// structured is still a leak when it is served as text/plain or octet-stream.
func TestConfigLeakStillFiresOnNonHTMLNonJSONBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("ref: refs/heads/main\n"))
	}))
	defer srv.Close()

	ep := Endpoint{Method: "GET", Path: "/.git/HEAD", FullURL: srv.URL + "/.git/HEAD"}
	got := configLeakCheck{}.Run(context.Background(), NewCheckContext(configLeakCfg(srv.URL)), ep)
	if len(got) == 0 {
		t.Error("a genuinely exposed .git/HEAD served as octet-stream was suppressed")
	}
}
