//go:build e2e

// Package e2e contains end-to-end tests that exercise the built fendix
// binary against externally-observable effects (files written, exit codes,
// report contents). Run with:
//
//	make e2e
//	# or
//	go test -tags e2e ./internal/e2e/...
//
// These tests catch CLI-wiring bugs that pass unit tests — for example,
// a flag that's declared in cobra but never read into ScanConfig
// (the bug behind TASK-079). Every CLI flag should have a matching
// e2e test here.
package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// repoRoot returns the repository root by walking up from this test file.
// e2e_test.go lives at <repo>/go/internal/e2e/, so root is three levels up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// buildOnce builds the fendix binary once per test process. The first test
// to call it triggers `make build`, subsequent calls return the cached path.
// Builds via `make build` to ensure the embedded Python engine is bundled —
// raw `go build` would skip embed-engine and the white-box path would fail.
var (
	buildOnceMu  sync.Mutex
	buildOnceErr error
	buildPath    string
)

func fendixBinary(t *testing.T) string {
	t.Helper()
	buildOnceMu.Lock()
	defer buildOnceMu.Unlock()
	if buildPath != "" || buildOnceErr != nil {
		if buildOnceErr != nil {
			t.Fatalf("fendix binary build failed: %v", buildOnceErr)
		}
		return buildPath
	}
	root := repoRoot(t)
	cmd := exec.Command("make", "build")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		buildOnceErr = err
		t.Fatalf("make build failed: %v\n%s", err, out)
	}
	buildPath = filepath.Join(root, "bin", "fendix")
	return buildPath
}

// tinyWordlist writes a 1-path wordlist into the test's tempdir and returns
// its path. Use it via `--wordlist` to short-circuit brute-force discovery
// in tests that don't care about it. Without this, every URL-based e2e test
// pays for ~117 sequential HTTP connections to its mock target — which on
// macOS reliably exhausts ephemeral ports across the suite (port-rotation
// + TIME_WAIT accumulation). Tests that DO exercise brute-force opt in by
// not calling this helper.
func tinyWordlist(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(path, []byte("/fendix-e2e-probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// mockTarget returns an httptest server with one weak-headers endpoint.
// Sufficient to produce non-zero findings so save-baseline has something to
// write — we want to verify the file is created, not validate its contents
// in detail (other tests cover JSON schema).
func mockTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestActiveProbe_UsesSpecParam is the regression test for TASK-081.
// Pre-fix, the active scanner ignored OpenAPI `parameters` arrays and always
// probed the hardcoded `id` query param. Here we record every incoming request
// to a mock target, declare a single endpoint with one query param `host`,
// and assert at least one probe arrived with `?host=` set — proving spec
// params now flow into Endpoint.Params and out to injection.go.
func TestActiveProbe_UsesSpecParam(t *testing.T) {
	bin := fendixBinary(t)

	var (
		mu          sync.Mutex
		hostProbes  int
		idProbes    int
		totalProbes int
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		totalProbes++
		q := r.URL.Query()
		if q.Get("host") != "" {
			hostProbes++
		}
		if q.Get("id") != "" {
			idProbes++
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	specBody := `openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: ` + target.URL + `
paths:
  /api/ping:
    get:
      parameters:
        - name: host
          in: query
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--spec", specPath,
		"--enable-active",
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--output", filepath.Join(dir, "report.json"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if totalProbes == 0 {
		t.Fatalf("no requests reached the target — scan never ran active probes\noutput:\n%s", out)
	}
	if hostProbes == 0 {
		t.Fatalf("active scanner never probed the spec-declared 'host' query param "+
			"(TASK-081 regressed). hostProbes=%d idProbes=%d total=%d\noutput:\n%s",
			hostProbes, idProbes, totalProbes, out)
	}
}

// TestCodeOnlyScan_ProducesFindings is the regression test for TASK-080.
// Before the fix, the orchestrator early-exited on "no endpoints discovered"
// before reaching the white-box branch — so `fendix scan --code ./repo` always
// failed with exit 2, even though the CLI accepted the flag combination.
// We assert the scan completes (exit 0 or 1) and the report contains at least
// one secret finding from the embedded fixture.
func TestCodeOnlyScan_ProducesFindings(t *testing.T) {
	bin := fendixBinary(t)

	// Self-contained fixture: one file with an obviously-fake AWS key matching
	// the AKIA[0-9A-Z]{16} pattern in python/analyzers/secrets.py. Using the
	// well-known AWS-doc example keeps this readable and avoids triggering
	// any real-secret scanners on this repo.
	codeDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(codeDir, "config.py"),
		[]byte(`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`+"\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--code", codeDir,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
	)
	out, err := cmd.CombinedOutput()
	// Exit 0 (no findings above --fail-on threshold) or 1 (findings) both fine.
	// Exit 2 = the bug we're guarding against.
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok || exitErr.ExitCode() == 2 {
			t.Fatalf("code-only scan returned exit 2 (TASK-080 regressed) or unexpected error: %v\noutput:\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}
	if !contains(string(report), "AKIA") && !contains(string(report), "AWS Access Key") {
		t.Fatalf("expected report to contain AWS-key finding, got:\n%s\n\nfendix output:\n%s", report, out)
	}
}

// TestSpecURL_FetchedAndParsed is the regression test for TASK-082.
// Before the fix, --spec http://host/openapi.json was passed to os.ReadFile
// which silently failed; the crawler then fell back to brute-force discovery,
// effectively ignoring the user's spec. We assert the spec path actually wins
// by serving a spec with one declared endpoint and asserting the scanner logs
// "endpoints from spec count=1" — anything else means the URL wasn't honored.
func TestSpecURL_FetchedAndParsed(t *testing.T) {
	bin := fendixBinary(t)

	specSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "openapi": "3.0.0",
		  "info": {"title":"e2e","version":"1"},
		  "servers": [{"url": "` + r.Host + `/api"}],
		  "paths": {"/widgets": {"get": {"summary":"x"}}}
		}`))
	}))
	t.Cleanup(specSrv.Close)
	apiSrv := mockTarget(t)

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", apiSrv.URL,
		"--spec", specSrv.URL+"/openapi.json",
		"--output", outputPath,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
	)
	out, err := cmd.CombinedOutput()
	// Accept exit 0 or 1 (findings vs. no findings); reject 2 (config/network error).
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	// Confirm the URL path was taken (not silent fallback to brute-force).
	if !contains(string(out), "endpoints from spec") {
		t.Fatalf("expected 'endpoints from spec' in stderr — URL spec was not parsed.\noutput:\n%s", out)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestActiveProbe_BodyParam_FindsErrorBasedSQLi is the regression test for
// TASK-086 — the active scanner now probes JSON-body fields on POST/PUT/PATCH
// endpoints, and error-based SQLi detection surfaces a finding when the
// response body contains a known DB error signature.
//
// We stand up a mock POST endpoint that:
//
//  1. Accepts JSON body
//  2. Reflects a MySQL syntax error if the `username` field contains a single
//     quote (mimicking an unparameterized query)
//
// Then we declare the endpoint via OpenAPI 3 with `requestBody` containing a
// `username` property — this is the exact path TASK-086 added (body-param
// extraction in crawler.go + body-location probing in injection.go).
//
// Pre-fix: body params weren't extracted, body probes weren't sent, no finding.
// Post-fix: error-based SQLi finding appears in the report.
func TestActiveProbe_BodyParam_FindsErrorBasedSQLi(t *testing.T) {
	bin := fendixBinary(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		// Naive vulnerable handler: any single quote in the body → MySQL error
		// reflection. This is exactly the signature error-based SQLi looks for.
		if bytes.Contains(body, []byte(`'`)) {
			fmt.Fprintln(w, `{"error":"You have an error in your SQL syntax; check the manual"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	specBody := `openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: ` + target.URL + `
paths:
  /api/users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--spec", specPath,
		"--enable-active",
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--output", outputPath,
	)
	out, err := cmd.CombinedOutput()
	// Exit 1 (findings present) is expected and acceptable; exit 2 means a
	// scan error which would be a regression.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}
	if !contains(string(report), "error-based") {
		t.Fatalf("expected error-based SQLi finding in report (TASK-086 body-param probing regressed). Report:\n%s\n\nfendix output:\n%s", report, out)
	}
}

// TestActiveProbe_HeaderParam_ProbesCustomHeader is a regression test for the
// header-probing half of TASK-086. We declare a custom header parameter
// (X-Trace-Id) and assert the active scanner sends at least one probe with
// X-Trace-Id set — proves header-location probing actually fires.
func TestActiveProbe_HeaderParam_ProbesCustomHeader(t *testing.T) {
	bin := fendixBinary(t)

	var (
		mu      sync.Mutex
		hdrHits int
	)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Header.Get("X-Trace-Id") != "" {
			hdrHits++
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	specBody := `openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: ` + target.URL + `
paths:
  /api/items:
    get:
      parameters:
        - name: X-Trace-Id
          in: header
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--spec", specPath,
		"--enable-active",
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--output", filepath.Join(dir, "report.json"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if hdrHits == 0 {
		t.Fatalf("expected at least one X-Trace-Id-bearing probe (TASK-086 header probing regressed)\noutput:\n%s", out)
	}
}

// TestDedup_GroupsSameFindingAcrossEndpoints is the TASK-088 regression
// test. We expose three endpoints from the mock target's spec — all
// served by the same handler that returns weak headers — so the headers
// check fires the same finding three times. After dedup, exactly one
// finding should appear in the report with `affected_endpoints` listing
// all three. Pre-fix the same scan would have produced three near-identical
// findings and three SARIF rules.
func TestDedup_GroupsSameFindingAcrossEndpoints(t *testing.T) {
	bin := fendixBinary(t)

	// Same handler for every path → identical headers → identical findings.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	specBody := `openapi: "3.0.0"
info: {title: t, version: "1"}
servers:
  - url: ` + target.URL + `
paths:
  /api/users:
    get:
      summary: List users
  /api/posts:
    get:
      summary: List posts
  /api/orders:
    get:
      summary: List orders
`
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--spec", specPath,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--output", outputPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}

	// At least one finding should carry an `affected_endpoints` array — the
	// passive headers check fires identically on each spec endpoint and
	// should collapse into one. We don't assert an exact count because the
	// number of triggered headers on a stub server varies; the existence of
	// the array is the signal that dedup ran.
	if !contains(string(report), `"affected_endpoints"`) {
		t.Fatalf("expected 'affected_endpoints' in report (TASK-088 dedup regressed). Report:\n%s\nfendix output:\n%s",
			report, out)
	}
}

// TestSaveBaseline_WritesFile is the regression test for TASK-079.
// Before the fix, --save-baseline was declared in cobra but never read into
// ScanConfig, so the orchestrator's SaveBaseline path was unreachable. The
// existing unit test at baseline_test.go:156 called SaveBaseline() directly
// and passed — it didn't catch the missing CLI wiring. This test runs the
// actual binary and asserts the file appears on disk.
func TestSaveBaseline_WritesFile(t *testing.T) {
	bin := fendixBinary(t)
	srv := mockTarget(t)

	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, "baseline.json")
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--save-baseline", baselinePath,
		"--output", outputPath,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
	)
	out, err := cmd.CombinedOutput()
	// Exit code 1 is acceptable: --fail-on default may trigger when findings
	// exist on the mock target. We only care that the file was written.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed unexpectedly: %v\n%s", err, out)
		}
	}

	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline file not written at %s: %v\nfendix output:\n%s",
			baselinePath, err, out)
	}

	info, err := os.Stat(baselinePath)
	if err == nil && info.Size() == 0 {
		t.Fatalf("baseline file is empty at %s\nfendix output:\n%s", baselinePath, out)
	}
}

// TestCrawler_RobotsDisallowDiscovered is the TASK-089 regression test for
// robots.txt discovery. The mock target hides /admin/secret behind a
// Disallow directive and serves it with weak headers; pre-TASK-089 fendix
// would only see /robots.txt itself (the path was in CommonPaths) and never
// probe what robots.txt was actually advertising. After the fix the report
// must contain a finding whose endpoint references /admin/secret.
func TestCrawler_RobotsDisallowDiscovered(t *testing.T) {
	bin := fendixBinary(t)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/secret\n"))
		case "/admin/secret":
			// Serve with weak headers so the headers check fires and the
			// finding's endpoint metadata captures /admin/secret.
			w.Header().Set("Server", "Apache/2.4.1")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"hidden":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(target.Close)

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", target.URL,
		"--workers", "2",
		"--delay", "0",
		"--timeout", "5",
		// Keep the wordlist out of the way — we want to prove robots.txt
		// added /admin/secret, not that brute-force tripped over it.
		"--crawl-depth", "0",
		"--wordlist", tinyWordlist(t),
		"--output", outputPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("fendix scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}
	if !contains(string(report), "/admin/secret") {
		t.Fatalf("expected /admin/secret to appear as an endpoint in report (TASK-089 robots.txt parsing regressed).\nReport:\n%s\nfendix output:\n%s",
			report, out)
	}
}

// TestDepsScan_VulnerableRequirements is the TASK-090 regression test.
// We feed `fendix scan --code` a requirements.txt with several known-vulnerable
// PyPI packages and assert dep findings show up in the report. This test
// passes regardless of whether pip-audit is installed: when present, pip-audit
// is the primary path; when absent, the local known-vuln list is the fallback.
// Pre-TASK-090 a quirk in the pip-audit JSON key (`vulnerabilities` vs the real
// `dependencies`) made the primary path produce zero findings without falling
// back, and a tool failure (timeout, non-success exit) silently dropped the
// scan. Now both the success and failure cases route to a non-empty report.
// TestCorrelator_HybridScanProducesCorrelatedFinding (TASK-091) is the
// regression for the original Phase 11 motivation: hybrid scans must actually
// emit `source: correlated` findings. Pre-fix, real-world petstore3 hybrid
// scans found zero correlated findings even when both engines fired on the
// same endpoint, because (a) the spec-parser emits endpoints in
// "<METHOD> <PATH>" format which broke endpoint normalization, and (b) there
// was no path-suffix match for base-path skew.
//
// Setup: mock target accepts GET /api/v1/admin without auth (200 OK). Spec
// describes that same endpoint with no security requirement. Pass --auth so
// the blackbox auth check fires.
//
// Expected: spec_parser whitebox finding (category=auth) correlates with
// blackbox auth_bypass finding on the same endpoint → ≥1 finding with
// source=correlated.
func TestCorrelator_HybridScanProducesCorrelatedFinding(t *testing.T) {
	bin := fendixBinary(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 200 OK regardless of auth header — this is what
		// triggers blackbox checkUnauthenticated (auth check sends a no-auth
		// request and sees a 200).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// Minimal OpenAPI 3 spec — `/api/v1/admin` exists, no security defined.
	// Spec parser will emit "Endpoint has no authentication requirement".
	specDir := t.TempDir()
	specPath := filepath.Join(specDir, "openapi.yaml")
	specBody := `openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  /api/v1/admin:
    get:
      responses:
        '200':
          description: OK
`
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	// The spec-parser whitebox check that emits "no auth requirement"
	// lives in python/analyzers/spec_parser.py. A spec-only scan does not
	// auto-enable Python, so point FENDIX_ENGINE at the repo's python/ tree
	// and pass --python-engine so the spec parser runs.
	t.Setenv("FENDIX_ENGINE", filepath.Join(repoRoot(t), "python"))

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--spec", specPath,
		"--auth", "Bearer test-token",
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--crawl-depth", "0",
		"--python-engine",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("hybrid scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}

	body := string(report)
	if !contains(body, `"source":"correlated"`) && !contains(body, `"source": "correlated"`) {
		t.Fatalf(
			"expected at least one correlated finding (TASK-091 correlator regression).\n"+
				"Report:\n%s\nfendix output:\n%s",
			body, out,
		)
	}
}

func TestDepsScan_VulnerableRequirements(t *testing.T) {
	bin := fendixBinary(t)

	codeDir := t.TempDir()
	// All six packages are in the local known-vuln list (deps.py
	// _KNOWN_PYPI_VULNS), so the fallback path produces findings even when
	// the test runs on a machine without pip-audit installed.
	if err := os.WriteFile(
		filepath.Join(codeDir, "requirements.txt"),
		[]byte("Django==1.11.0\nFlask==0.12.0\nrequests==2.6.0\nPyYAML==3.12\nPillow==2.0.0\nurllib3==1.21.0\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--code", codeDir,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "30",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("deps scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}

	// The report must contain at least one CVE-tagged finding tied to a
	// known-vulnerable package. We don't pin to a specific CVE because pip-audit
	// (when installed) might emit GHSA IDs while the local fallback emits CVE
	// IDs — either is acceptable as long as we got SOMETHING.
	body := string(report)
	if !contains(body, `"category":"deps"`) && !contains(body, `"category": "deps"`) {
		t.Fatalf(
			"expected at least one deps-category finding (TASK-090 dep scan regressed).\n"+
				"Report:\n%s\nfendix output:\n%s",
			body, out,
		)
	}
	if !contains(body, "Django") && !contains(body, "django") {
		t.Fatalf(
			"expected Django to appear as a vulnerable dependency.\n"+
				"Report:\n%s\nfendix output:\n%s",
			body, out,
		)
	}
}

// TestReport_RejectsSARIFInput is the regression for the silent-empty-report
// bug surfaced in real-world usage: `fendix report --input results.sarif
// --format html` previously deserialized the SARIF document into a
// zero-value JSONReport and rendered an empty HTML page with "0 findings"
// and a Go-zero-time timestamp — no error, no warning. ParseJSONReport now
// detects SARIF and exits non-zero with an actionable message.
func TestReport_RejectsSARIFInput(t *testing.T) {
	bin := fendixBinary(t)

	dir := t.TempDir()
	sarifPath := filepath.Join(dir, "input.sarif")
	if err := os.WriteFile(sarifPath, []byte(`{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [{"tool": {"driver": {"name": "Fendix"}}, "results": []}]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin,
		"report",
		"--input", sarifPath,
		"--format", "html",
		"--output", filepath.Join(dir, "report.html"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit on SARIF input, got success.\noutput:\n%s", out)
	}
	if !contains(string(out), "SARIF") {
		t.Fatalf("expected error message to mention SARIF, got:\n%s", out)
	}
	if !contains(string(out), "--format json") {
		t.Fatalf("expected actionable hint with --format json, got:\n%s", out)
	}
}

// TestPathParamSubstitution_HitsServerWithSampleValue is the regression for
// TASK-093. Pre-fix, an OpenAPI spec declaring `/users/{id}` produced
// HTTP requests to `/users/%7Bid%7D` because http.NewRequest URL-encodes
// the literal `{` and `}` characters — every server returned 404 and every
// black-box check observed nothing on the templated endpoint.
//
// This test stands up a server that 200s on `/users/1` (a concrete integer
// matching the spec's `schema.example: 1`) and 404s everywhere else. The
// scan should observe the 200 response and emit a finding tied to that
// endpoint. We also assert the report never contains the raw `%7B` percent-
// encoded brace, which would mean substitution failed somewhere.
func TestPathParamSubstitution_HitsServerWithSampleValue(t *testing.T) {
	bin := fendixBinary(t)

	// Track which paths the server received — the test passes only if
	// `/users/1` (substituted form) was hit, not `/users/%7Bid%7D` (raw).
	var (
		mu   sync.Mutex
		hits []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		// Respond 200 only on the substituted form. The headers response is
		// also intentionally weak (no CSP/HSTS/X-Frame-Options/etc) so the
		// passive headers check has something to report — providing finding
		// content in the report.
		if r.URL.Path == "/users/1" {
			w.Header().Set("Server", "test/1.0")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":1,"name":"alice"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	specDir := t.TempDir()
	specPath := filepath.Join(specDir, "openapi.yaml")
	specBody := `openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
servers:
  - url: ` + srv.URL + `
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
            example: 1
      responses:
        '200':
          description: OK
`
	if err := os.WriteFile(specPath, []byte(specBody), 0o644); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--spec", specPath,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--crawl-depth", "0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("scan failed: %v\n%s", err, out)
		}
	}

	report, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("expected report at %s: %v\noutput:\n%s", outputPath, err, out)
	}
	body := string(report)

	// Server side: the substituted URL must have been hit.
	mu.Lock()
	hitsCopy := append([]string(nil), hits...)
	mu.Unlock()
	hitSubstituted := false
	for _, h := range hitsCopy {
		if h == "/users/1" {
			hitSubstituted = true
		}
		if h == "/users/%7Bid%7D" || h == "/users/{id}" {
			t.Errorf("server received un-substituted path %q (TASK-093 regression)", h)
		}
	}
	if !hitSubstituted {
		t.Fatalf("server never received /users/1.\nhits: %v\noutput:\n%s", hitsCopy, out)
	}

	// Report side: the report must not leak the raw percent-encoded brace
	// anywhere — that would indicate substitution failed at some emission site.
	if contains(body, "%7B") || contains(body, "%7b") {
		t.Errorf("report contains raw %%7B placeholder leak (TASK-093 regression):\n%s", body)
	}

	// At least one finding should be present (proves the scan actually got
	// observable response data — the headers check fires against a server
	// missing CSP/HSTS/X-Frame-Options/etc.). Tolerant of pretty-printed
	// vs compact JSON: an empty array is `[]` regardless of formatting.
	if contains(body, `"findings": []`) || contains(body, `"findings":[]`) {
		t.Errorf("expected at least one finding in report; got empty.\nReport:\n%s\nOutput:\n%s", body, out)
	}

	// And confirm at least one finding's endpoint references the templated
	// `/users/{id}` form (Path is preserved on findings even though FullURL
	// is substituted), so users see the spec-shaped path in reports.
	if !contains(body, "/users/{id}") {
		t.Errorf("expected templated path /users/{id} in finding endpoints (reports lose template form):\n%s", body)
	}
}

// TestMaxRequests_SoftStopCapsTotalRequests is the regression test for
// TASK-095 --max-requests. A 50-endpoint scan with 4 active checks would
// normally fire ~200 requests; with --max-requests 20 the cap should be
// honoured (allowing for the soft-stop overshoot of in-flight requests).
// We measure server-side hit count rather than the budget summary string
// so the test is robust against minor log-format changes.
func TestMaxRequests_SoftStopCapsTotalRequests(t *testing.T) {
	bin := fendixBinary(t)

	var (
		mu   sync.Mutex
		hits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Build a wordlist with 50 paths so the scanner has lots of work.
	dir := t.TempDir()
	wlPath := filepath.Join(dir, "wl.txt")
	var wl bytes.Buffer
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&wl, "/path%d\n", i)
	}
	if err := os.WriteFile(wlPath, wl.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--output", outputPath,
		"--workers", "4",
		"--timeout", "5",
		"--wordlist", wlPath,
		"--crawl-depth", "0",
		"--max-requests", "20",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("scan failed: %v\n%s", err, out)
		}
	}

	// Soft-stop overshoot bound: at most workers (4) extra in-flight requests
	// can sneak past the cap before the worker pool sees the ctx cancel.
	// Use a generous upper bound (cap × 4) to keep the test resilient on
	// CI machines with different scheduling. The pre-fix path would have
	// fired ~200 requests (50 paths × 4 checks), so even the loose bound
	// catches a regression.
	mu.Lock()
	finalHits := hits
	mu.Unlock()
	const cap = 20
	const upperBound = cap * 4
	if finalHits > upperBound {
		t.Errorf("max-requests soft-cap not enforced: server saw %d hits, want <= %d (cap=%d)\noutput:\n%s",
			finalHits, upperBound, cap, out)
	}

	// And the budget summary must appear in the log output, signalling the
	// cap mechanism actually engaged.
	if !contains(string(out), "budget summary") {
		t.Errorf("expected 'budget summary' in fendix output, got:\n%s", out)
	}
}

// TestRespectRobots_FiltersDisallowedFromEndpointList is the e2e regression
// test for the --respect-robots half of TASK-095. The mock target's
// robots.txt disallows /admin; the scan should not hit /admin even though
// the wordlist would otherwise discover it via brute-force.
func TestRespectRobots_FiltersDisallowedFromEndpointList(t *testing.T) {
	bin := fendixBinary(t)

	var (
		mu       sync.Mutex
		adminHit bool
		apiHit   bool
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		adminHit = true
		mu.Unlock()
		w.WriteHeader(200)
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		apiHit = true
		mu.Unlock()
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	wlPath := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wlPath, []byte("/admin\n/api\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
		"--wordlist", wlPath,
		"--crawl-depth", "0",
		"--respect-robots",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("scan failed: %v\n%s", err, out)
		}
	}

	mu.Lock()
	a, b := adminHit, apiHit
	mu.Unlock()

	if a {
		t.Errorf("--respect-robots regression: /admin was hit despite Disallow rule.\noutput:\n%s", out)
	}
	if !b {
		t.Errorf("--respect-robots regression: /api was not hit (allowed path should still be scanned).\noutput:\n%s", out)
	}
}
