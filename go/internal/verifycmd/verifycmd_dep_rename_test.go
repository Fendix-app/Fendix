package verifycmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/pip"
)

// fakeOSVForDepVerify answers /v1/query with one flask advisory whose CVE
// exists ONLY as an alias — the exact shape that makes FIX-05 rename the
// finding from SEC-DEPS-PYSEC_2022_43012 to SEC-DEPS-CVE_2022_99999.
func fakeOSVForDepVerify(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var q struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		}
		_ = json.NewDecoder(r.Body).Decode(&q)
		if q.Package.Name != "flask" {
			_, _ = w.Write([]byte(`{"vulns":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[{
			"id": "PYSEC-2022-43012",
			"summary": "Flask path traversal",
			"aliases": ["CVE-2022-99999"],
			"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.2"}]}]}]
		}]}`))
	}))
}

// TestVerifyDep_PreRenameFindingStillMatchesItsCanonicalTwin is the
// regression test for the false all-clear FIX-05 would otherwise have
// introduced.
//
// verifyDep used to decide "same vulnerability?" from the ID TAIL alone. A
// finding saved before FIX-05 is recorded as SEC-DEPS-PYSEC_2022_43012; the
// re-scan now emits SEC-DEPS-CVE_2022_99999 for the very same advisory, so
// the tail no longer matches and `fendix verify` would report RESOLVED for
// a vulnerability that is still installed. A security tool announcing
// "fixed" about something that is not is the worst direction this could
// fail in, which is why the id SET — every merged alias, preserved in
// References — is the identity now.
func TestVerifyDep_PreRenameFindingStillMatchesItsCanonicalTwin(t *testing.T) {
	srv := fakeOSVForDepVerify(t)
	defer srv.Close()
	restore := pip.SetOSVAPIBaseForTest(srv.URL)
	defer restore()
	t.Setenv("HOME", t.TempDir()) // isolate the OSV cache

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"), []byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		// Exactly what a pre-FIX-05 scan wrote: named after the PYSEC
		// record, with only the first alias in References.
		ID:         "SEC-DEPS-PYSEC_2022_43012",
		Title:      "Vulnerable dependency: flask==2.0.1 (PYSEC-2022-43012)",
		Severity:   models.SeverityHigh,
		Category:   "deps",
		Source:     models.SourceWhitebox,
		Endpoint:   "requirements.txt",
		References: []string{"PYSEC-2022-43012", "CVE-2022-99999"},
	}})

	r, err := Run(context.Background(), "SEC-DEPS-PYSEC_2022_43012",
		Options{BaselinePath: baseline, CodePath: codeDir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusStillPresent {
		t.Fatalf("status = %v (reason=%q); want %v — the vulnerability is still installed, only its canonical id changed",
			r.Status, r.Reason, StatusStillPresent)
	}
}

// TestVerifyDep_ResolvedWhenTheDependencyIsGone is the counter-case: the
// alias-set match must not be so permissive that nothing ever resolves.
func TestVerifyDep_ResolvedWhenTheDependencyIsGone(t *testing.T) {
	srv := fakeOSVForDepVerify(t)
	defer srv.Close()
	restore := pip.SetOSVAPIBaseForTest(srv.URL)
	defer restore()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	// flask has been upgraded out of the vulnerable range — the fake OSV
	// only reports for the pinned 2.0.1, and this manifest pins something
	// else entirely.
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID:         "SEC-DEPS-PYSEC_2022_43012",
		Title:      "Vulnerable dependency: flask==2.0.1 (PYSEC-2022-43012)",
		Severity:   models.SeverityHigh,
		Category:   "deps",
		Source:     models.SourceWhitebox,
		Endpoint:   "requirements.txt",
		References: []string{"PYSEC-2022-43012", "CVE-2022-99999"},
	}})

	r, err := Run(context.Background(), "SEC-DEPS-PYSEC_2022_43012",
		Options{BaselinePath: baseline, CodePath: codeDir})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.Status != StatusResolved {
		t.Fatalf("status = %v (reason=%q); want %v", r.Status, r.Reason, StatusResolved)
	}
}
