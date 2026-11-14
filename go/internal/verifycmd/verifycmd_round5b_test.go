package verifycmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Round 5 follow-up (deep-engine5 DE5-02, contract C8, D5-3): verify never
// resolves a finding the secrets scanner did not produce. A re-test of a URL or a
// dependency reads what one response or one inventory shows now, which is an
// observation and not a remediation: the result is unknown (exit 2) and says so.

func r5bRun(t *testing.T, f models.Finding, opts Options) *Result {
	t.Helper()
	f.ID = "SEC-R5B"
	opts.BaselinePath = writeBaseline(t, t.TempDir(), []models.Finding{f})
	r, err := Run(context.Background(), "SEC-R5B", opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return r
}

// A server that answers 404 carries no CORS header and no version string, which
// the old re-test read as "Access-Control-Allow-Origin now \"\"" and
// "no longer contains an obvious version string": resolved.
func TestDE502_URLFindingsOnA404AreUnknownNeverResolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	for _, f := range []models.Finding{
		{Title: "CORS allows any origin", Endpoint: "GET /api", Category: "cors", Source: models.SourceBlackbox},
		{Title: "Software version string in response", Endpoint: "GET /", Category: "info_disclosure", Source: models.SourceBlackbox},
		{Title: "Server version disclosed", Endpoint: "GET /", Category: "info_disclosure", Source: models.SourceBlackbox},
		{Title: "X-Frame-Options header missing", Endpoint: "GET /", Category: "headers", Source: models.SourceBlackbox},
		{Title: "Exposed admin panel", Endpoint: "GET /admin", Category: "exposure", Source: models.SourceBlackbox},
	} {
		t.Run(f.Title, func(t *testing.T) {
			r := r5bRun(t, f, Options{URL: srv.URL})
			if r.Status == StatusResolved {
				t.Fatalf("a 404 resolved %q: %s", f.Title, r.Reason)
			}
			if r.Status != StatusUnknown {
				t.Fatalf("status %s (%s); want unknown", r.Status, r.Reason)
			}
		})
	}
}

// The scanner sends an Origin header (cors.go) and the finding exists because the
// server answered it with a wildcard. A server that answers the wildcard only to a
// request that carries an Origin is still vulnerable; verify used to send none,
// saw no header, and resolved.
func TestDE502_CORSWildcardThatNeedsAnOriginIsStillPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := r5bRun(t, models.Finding{Title: "CORS allows any origin", Endpoint: "GET /api", Category: "cors", Source: models.SourceBlackbox}, Options{URL: srv.URL})
	if r.Status != StatusStillPresent {
		t.Fatalf("status %s (%s); want still-present", r.Status, r.Reason)
	}
}

// And a server that sends no wildcard to an Origin request now is unknown, not
// resolved: one response is an observation.
func TestDE502_CORSWildcardGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	r := r5bRun(t, models.Finding{Title: "CORS allows any origin", Endpoint: "GET /api", Category: "cors", Source: models.SourceBlackbox}, Options{URL: srv.URL})
	if r.Status != StatusUnknown || !strings.Contains(r.Reason, "not proof that the vulnerability is fixed") {
		t.Fatalf("status %s (%s); want unknown with the not-a-fix note", r.Status, r.Reason)
	}
}

// The backstop: whatever a verifier returns, a finding the secrets scanner did not
// produce never leaves verifyOne as resolved, so a verifier added later cannot
// regress this.
func TestDE502_BackstopTurnsAnyOtherResolvedIntoUnknown(t *testing.T) {
	for name, f := range map[string]*models.Finding{
		"semgrep":   {RuleID: "semgrep/python-eval", Source: models.SourceWhitebox, Endpoint: "a.py:3"},
		"textscan":  {RuleID: "textscan/JS_EVAL", Source: models.SourceWhitebox, Endpoint: "a.js:3"},
		"url":       {Source: models.SourceBlackbox, Endpoint: "GET /", Title: "x"},
		"no rule":   {Source: models.SourceWhitebox, Endpoint: "a.py:3", Category: "secrets"},
		"tiered":    {RuleID: "secrets/AWS_SECRET_KEY", SourceTier: "semgrep", Source: models.SourceWhitebox, Endpoint: "a.py:3"},
		"probe src": {RuleID: "secrets/AWS_SECRET_KEY", Source: models.SourceBlackbox, Endpoint: "a.py:3"},
	} {
		t.Run(name, func(t *testing.T) {
			if why := notSecretsScannerFinding(f); why == "" {
				t.Fatal("the finding reads as a secrets-scanner finding")
			}
		})
	}
	if why := notSecretsScannerFinding(&models.Finding{RuleID: "secrets/AWS_SECRET_KEY", Source: models.SourceWhitebox, Endpoint: "a.py:3"}); why != "" {
		t.Fatalf("a secrets-scanner finding was refused: %s", why)
	}
}

// A dependency finding whose manifest no longer lists it is unknown, never
// resolved, even when the manifest is a lockfile that lists nothing.
func TestDE502_DepFindingGoneFromTheManifestIsUnknown(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("# nothing pinned\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := r5bRun(t, models.Finding{
		Title: "left-pad 1.0.0 vulnerable", Endpoint: "requirements.txt", Category: "deps", Source: models.SourceWhitebox,
		RuleID: "deps/pip",
	}, Options{CodePath: root})
	if r.Status == StatusResolved {
		t.Fatalf("a dependency finding resolved: %s", r.Reason)
	}
}
