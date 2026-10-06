package verifycmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// `fendix scan --save-baseline <path>` routes through engine.SaveBaseline,
// which writes a versioned baseline document (format v2; older builds wrote a
// BARE JSON ARRAY of findings). `fendix verify --baseline <path>` must be able
// to read every shape back — otherwise the tool's own output is not valid
// input to its own verify command. The engine-side loader
// (engine.loadBaseline) accepts the v2 document, the bare array and the full
// report envelope; verify has to match.
//
// This test deliberately produces the file with the REAL writer rather than
// a hand-rolled fixture, so it keeps holding whatever shape SaveBaseline
// emits.
func TestLoadBaseline_AcceptsSaveBaselineOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := engine.SaveBaseline([]models.Finding{
		{ID: "SEC-001", Title: "Missing Content-Security-Policy header", Endpoint: "GET /", Category: "headers"},
		{ID: "SEC-002", Title: "Other finding", Endpoint: "GET /other", Category: "headers"},
	}, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	report, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("loadBaseline on --save-baseline output: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("got %d findings; want 2", len(report.Findings))
	}
	if f := findByID(report, "SEC-001"); f == nil {
		t.Errorf("SEC-001 not found in loaded baseline")
	} else if f.Title != "Missing Content-Security-Policy header" {
		t.Errorf("title = %q; want the saved title", f.Title)
	}
}

// End-to-end through Run: a bare-array baseline must dispatch to the normal
// verifier, not blow up with a load error. Endpoint is unreachable on
// purpose, so the expected verdict is `unknown` — the point is that we got
// far enough to HAVE a verdict.
func TestRun_BareArrayBaselineIsUsable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := engine.SaveBaseline([]models.Finding{
		{ID: "SEC-001", Title: "Missing Content-Security-Policy header", Endpoint: "GET /", Category: "headers"},
	}, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	r, err := Run(context.Background(), "SEC-001", Options{BaselinePath: path, URL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("Run on --save-baseline output: %v", err)
	}
	if r.Status == StatusNotFound {
		t.Errorf("finding present in the baseline array was not located; reason=%q", r.Reason)
	}
	if r.Original == nil {
		t.Fatalf("Original should be populated from the bare-array baseline")
	}
	if r.Original.ID != "SEC-001" {
		t.Errorf("Original.ID = %q; want SEC-001", r.Original.ID)
	}
}

// The full report envelope (from `fendix scan --format json`) must keep
// working — including the hardening ParseJSONReport adds. Regression guard
// for the array support not swallowing the object path.
func TestLoadBaseline_StillAcceptsReportEnvelope(t *testing.T) {
	dir := t.TempDir()
	path := writeBaseline(t, dir, []models.Finding{{ID: "SEC-007", Title: "Envelope finding"}})
	report, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("loadBaseline on report envelope: %v", err)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "SEC-007" {
		t.Fatalf("got %+v; want the single SEC-007 finding", report.Findings)
	}
}

// A SARIF file is still rejected with the actionable message — accepting
// arrays must not turn into "accept any JSON".
func TestLoadBaseline_StillRejectsSARIF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.sarif")
	sarif := `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[]}`
	if err := os.WriteFile(path, []byte(sarif), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(path); err == nil {
		t.Fatal("expected SARIF input to be rejected")
	} else if !strings.Contains(err.Error(), "SARIF") {
		t.Errorf("error should name SARIF; got %v", err)
	}
}

// A JSON array of the wrong shape must FAIL, not silently load as an empty
// baseline — an empty baseline would make every verify report
// not-found-in-baseline, quietly hiding a broken input. Failure modes
// default to deny.
func TestLoadBaseline_RejectsNonFindingArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(path, []byte(`["not", "findings"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(path); err == nil {
		t.Fatal("expected a JSON array of non-findings to be rejected")
	}
}

// Truncated / malformed JSON must fail loudly regardless of which branch it
// lands in.
func TestLoadBaseline_RejectsTruncatedArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.json")
	if err := os.WriteFile(path, []byte(`[{"id":"SEC-001"`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(path); err == nil {
		t.Fatal("expected truncated JSON to be rejected")
	}
}

// engine.SaveBaseline marshals a nil/empty findings slice to the JSON
// literal `null` (a clean scan with --save-baseline). That is also the
// tool's own output, so verify must read it as an empty baseline and answer
// not-found-in-baseline (exit 2, "verify couldn't tell") rather than
// erroring out of the load.
func TestLoadBaseline_AcceptsEmptySaveBaselineOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := engine.SaveBaseline(nil, path); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	report, err := loadBaseline(path)
	if err != nil {
		t.Fatalf("loadBaseline on empty --save-baseline output: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("got %d findings; want 0", len(report.Findings))
	}

	r, runErr := Run(context.Background(), "SEC-001", Options{BaselinePath: path, URL: "http://127.0.0.1:1"})
	if runErr != nil {
		t.Fatalf("Run on empty baseline: %v", runErr)
	}
	if r.Status != StatusNotFound {
		t.Errorf("status = %q; want %q", r.Status, StatusNotFound)
	}
}

// A baseline document from a future format is refused, not half-read.
func TestLoadBaseline_RejectsUnsupportedBaselineVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.json")
	if err := os.WriteFile(path, []byte(`{"baseline_version": 99, "findings": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBaseline(path); err == nil || !strings.Contains(err.Error(), "baseline_version") {
		t.Fatalf("err = %v; want an unsupported baseline_version error", err)
	}
}
