package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
)

// pip-audit JSON sample matching the >= 2.7.0 schema. Two pinned deps
// where one has a CVE; mirrors the shape an actual pip-audit invocation
// returns when --format json is set.
const fakePipAuditFindingsJSON = `{
  "dependencies": [
    {
      "name": "flask",
      "version": "2.0.1",
      "vulns": [
        {
          "id": "PYSEC-2022-43012",
          "fix_versions": ["2.0.2"],
          "description": "Flask vulnerability fixed in 2.0.2",
          "aliases": ["CVE-2022-99999"]
        }
      ]
    },
    {
      "name": "requests",
      "version": "2.28.0",
      "vulns": []
    }
  ]
}`

const fakePipAuditNoFindingsJSON = `{"dependencies": [{"name": "flask", "version": "3.1.0", "vulns": []}]}`

// writeFakePipAudit installs a fake pip-audit shell script in dir, prints
// jsonOutput on stdout, exits exitCode, and prepends dir to PATH for the
// test duration. Skips on non-Unix where /bin/sh shebangs aren't honoured.
func writeFakePipAudit(t *testing.T, dir, jsonOutput string, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary subprocess pattern needs /bin/sh; skipping on Windows")
	}
	// Use a heredoc tagged with a deterministic sentinel so JSON braces
	// don't terminate the script early. Quote the sentinel ('EOF') so the
	// shell does not expand $-substitutions inside the JSON body.
	script := fmt.Sprintf("#!/bin/sh\ncat <<'PIPAUDIT_EOF'\n%s\nPIPAUDIT_EOF\nexit %d\n", jsonOutput, exitCode)
	path := filepath.Join(dir, "pip-audit")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// writeFakePipAuditExit writes a pip-audit that prints nothing on stdout
// and exits with the given code (used to simulate hard failures like
// command-not-found-style 127 or schema-error 2).
func writeFakePipAuditExit(t *testing.T, dir string, exitCode int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary subprocess pattern needs /bin/sh; skipping on Windows")
	}
	script := fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	path := filepath.Join(dir, "pip-audit")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// withEmptyPath replaces PATH with just dir for the test, so exec.LookPath
// cannot find any real pip-audit on the developer's machine.
func withEmptyPath(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

// captureStderr captures os.Stderr writes during fn(). Restores the
// original on return regardless of panic.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// TestScanViaSubprocess_HappyPath uses a fake pip-audit binary on PATH.
// Verifies that --use-pip-audit causes the subprocess path to run and
// converts pip-audit's JSON shape to []models.Finding correctly.
func TestScanViaSubprocess_HappyPath(t *testing.T) {
	binDir := t.TempDir()
	writeFakePipAudit(t, binDir, fakePipAuditFindingsJSON, 1) // exit 1 = findings present

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\nrequests==2.28.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir()) // isolate cache dir even though subprocess path doesn't use it

	findings, err := ScanRecursiveWithOptions(context.Background(), codeDir, DefaultRecurseDepth,
		Options{UsePipAudit: true})
	if err != nil {
		t.Fatalf("ScanRecursiveWithOptions: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %#v", len(findings), findings)
	}
	f := findings[0]
	// The pip-audit fixture carries aliases: ["CVE-2022-99999"], and
	// pip-audit's output DOES decode them — so this path gets the same
	// FIX-05 canonicalisation as /v1/query, not the alias-less batch
	// treatment. Both paths must agree or dedup stops collapsing them.
	if f.ID != "SEC-DEPS-CVE_2022_99999" {
		t.Errorf("ID drift: %s", f.ID)
	}
	if !strings.Contains(f.Title, "flask==2.0.1") {
		t.Errorf("Title should name the package+version: %s", f.Title)
	}
	if f.Endpoint != "requirements.txt" {
		t.Errorf("Endpoint should be the manifest path: got %q", f.Endpoint)
	}
}

// TestScanViaSubprocess_PipAuditNotInstalled verifies that --use-pip-audit
// with no pip-audit on PATH falls back to the OSV.dev client cleanly with a
// stderr warning, NOT a hard error.
func TestScanViaSubprocess_PipAuditNotInstalled(t *testing.T) {
	withEmptyPath(t)

	srv := newFakeOSVServer(t, map[string][]osvVuln{
		"flask": {{ID: "PYSEC-2022-43012", Summary: "fb"}},
	})
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var findings []evidence.Evidence
	stderr := captureStderr(t, func() {
		got, err := ScanRecursiveWithOptions(context.Background(), codeDir, DefaultRecurseDepth,
			Options{UsePipAudit: true})
		if err != nil {
			t.Fatalf("ScanRecursiveWithOptions: %v", err)
		}
		findings = got
	})
	if !strings.Contains(stderr, "pip-audit not found on PATH") {
		t.Errorf("expected fallback warning on stderr; got %q", stderr)
	}
	if !strings.Contains(stderr, "falling back to OSV.dev client") {
		t.Errorf("expected fallback hint on stderr; got %q", stderr)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Errorf("expected OSV.dev fallback to produce 1 finding; got %#v", findings)
	}
}

// TestScanViaSubprocess_ExitCode1WithFindingsIsNormal asserts that
// pip-audit's "exit 1 = findings exist" convention is handled — we don't
// treat it as failure.
func TestScanViaSubprocess_ExitCode1WithFindingsIsNormal(t *testing.T) {
	binDir := t.TempDir()
	writeFakePipAudit(t, binDir, fakePipAuditFindingsJSON, 1) // pip-audit exits 1 on findings

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())

	stderr := captureStderr(t, func() {
		findings, err := ScanRecursiveWithOptions(context.Background(), codeDir, DefaultRecurseDepth,
			Options{UsePipAudit: true})
		if err != nil {
			t.Fatalf("exit-1 with findings should NOT propagate error: got %v", err)
		}
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
	})
	if strings.Contains(stderr, "pip-audit failed") {
		t.Errorf("exit-1 with findings should NOT log a failure; stderr was: %q", stderr)
	}
}

// TestScanViaSubprocess_RealFailureLogsAndContinues asserts that a fake
// pip-audit exiting 127 (real failure) logs to stderr and continues
// the scan (does NOT propagate as an error to the orchestrator).
func TestScanViaSubprocess_RealFailureLogsAndContinues(t *testing.T) {
	binDir := t.TempDir()
	writeFakePipAuditExit(t, binDir, 127)

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", t.TempDir())

	stderr := captureStderr(t, func() {
		findings, err := ScanRecursiveWithOptions(context.Background(), codeDir, DefaultRecurseDepth,
			Options{UsePipAudit: true})
		if err != nil {
			t.Fatalf("real pip-audit failure should be logged + swallowed, got error: %v", err)
		}
		// No findings because pip-audit failed; that's the documented
		// "log and continue" posture.
		if len(findings) != 0 {
			t.Fatalf("expected zero findings on subprocess failure; got %d", len(findings))
		}
	})
	if !strings.Contains(stderr, "pip-audit failed") {
		t.Errorf("expected 'pip-audit failed' on stderr, got %q", stderr)
	}
}

// TestParsePipAuditJSON_HappyPath asserts the schema mapping into Finding.
func TestParsePipAuditJSON_HappyPath(t *testing.T) {
	findings, err := parsePipAuditJSON([]byte(fakePipAuditFindingsJSON), "svc_a/requirements.txt")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	// FIX-05: canonical id from the alias set, same as the OSV.dev path.
	if f.ID != "SEC-DEPS-CVE_2022_99999" {
		t.Errorf("ID: %s", f.ID)
	}
	if f.Endpoint != "svc_a/requirements.txt" {
		t.Errorf("Endpoint should be the manifest path stamp: %s", f.Endpoint)
	}
	if !strings.Contains(f.Fix, "flask==2.0.2") {
		t.Errorf("Fix should call out the patched version: %s", f.Fix)
	}
	// Aliases parity: at least the first alias is included as a reference.
	hasAlias := false
	for _, r := range f.References {
		if r == "CVE-2022-99999" {
			hasAlias = true
			break
		}
	}
	if !hasAlias {
		t.Errorf("expected CVE alias in references, got %v", f.References)
	}
}

// TestParsePipAuditJSON_BadSchemaErrors asserts that malformed JSON returns
// a clear "upgrade pip-audit" error.
func TestParsePipAuditJSON_BadSchemaErrors(t *testing.T) {
	// Garbage JSON — definitely not the documented schema.
	_, err := parsePipAuditJSON([]byte("not json at all"), "requirements.txt")
	if err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "pip-audit") {
		t.Errorf("error should mention pip-audit so the user knows what to upgrade: %v", err)
	}
}

// TestParsePipAuditJSON_NoFindings confirms the empty-vulns case yields
// zero findings without an error (parity with scanViaOSV's quiet path).
func TestParsePipAuditJSON_NoFindings(t *testing.T) {
	findings, err := parsePipAuditJSON([]byte(fakePipAuditNoFindingsJSON), "requirements.txt")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(findings))
	}
}

// TestScanRecursive_BackwardCompatNoOptions confirms the original
// ScanRecursive(ctx, code, depth) signature still produces the same
// results as before Sprint 01 (callers that don't opt in to the new flag
// see no behaviour change).
func TestScanRecursive_BackwardCompatNoOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			Package osvPackage `json:"package"`
			Version string     `json:"version"`
		}
		_ = json.Unmarshal(body, &q)
		if q.Package.Name == "flask" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{ID: "PYSEC-2022-43012", Summary: "fb"}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(osvQueryResponse{})
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(codeDir, "requirements.txt"),
		[]byte("flask==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanRecursive(context.Background(), codeDir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("ScanRecursive: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Fatalf("backward-compat path produced unexpected output: %#v", findings)
	}
}
