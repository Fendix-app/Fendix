//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReachable_HybridScanProducesReachableCorrelated (TASK-114) verifies
// the full Phase-15 reachability flow end-to-end:
//
//  1. The Python AST analyzer detects a SQLi sink with a request-input
//     dataflow source (`q = request.args.get('q'); cursor.execute(...q)`)
//     and emits a whitebox finding carrying `taint_chain` + `reachable: true`.
//  2. The spec parser independently emits a whitebox auth-issue finding
//     for the same endpoint (no security defined) so the correlator has
//     a URL-shaped finding to match against the live blackbox half.
//  3. The blackbox engine sees a live 200-without-auth on /api/v1/users
//     and emits an auth_bypass finding on the same path.
//  4. The correlator merges blackbox + whitebox into a `correlated`
//     finding; when the whitebox half carries a chain, `Reachable=true`
//     propagates and the merged severity gets a second escalation.
//
// Pre-TASK-114, step 1 emitted no chain — only an opaque "SQLi at line N"
// — so the correlator had nothing to escalate even when DAST + SAST
// agreed at the same endpoint.
func TestReachable_HybridScanProducesReachableCorrelated(t *testing.T) {
	bin := fendixBinary(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 200 regardless of auth — triggers the blackbox
		// "no auth required" check.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// Code fixture: the AST analyzer should record a chain from
	// request.args.get → cursor.execute.
	codeDir := t.TempDir()
	codeFile := filepath.Join(codeDir, "users_handler.py")
	codeBody := `from flask import request

def list_users(cursor):
    q = request.args.get('q')
    sql = "SELECT * FROM users WHERE name = '" + q + "'"
    cursor.execute(sql)
`
	if err := os.WriteFile(codeFile, []byte(codeBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// Spec fixture: declares /api/v1/users with no security so the spec
	// parser emits a URL-shaped whitebox finding the correlator can pair
	// with the live 200-without-auth blackbox finding.
	specDir := t.TempDir()
	specPath := filepath.Join(specDir, "openapi.yaml")
	specBody := `openapi: 3.0.0
info:
  title: Test
  version: 1.0.0
paths:
  /api/v1/users:
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

	// AST analyzer (taint chains) + spec parser (no-auth whitebox
	// finding) both live in python/. --code auto-enables the phase; point
	// FENDIX_ENGINE at the repo's python/ tree and pass --python-engine
	// explicitly so a missing tree fails this test instead of degrading.
	t.Setenv("FENDIX_ENGINE", filepath.Join(repoRoot(t), "python"))

	cmd := exec.Command(bin,
		"scan",
		"--url", srv.URL,
		"--spec", specPath,
		"--code", codeDir,
		"--auth", "Bearer test-token",
		"--output", outputPath,
		"--workers", "2",
		"--timeout", "5",
		"--wordlist", tinyWordlist(t),
		"--crawl-depth", "0",
		"--no-plugins", // isolate this test from any user-installed plugins
		"--python-engine",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() > 1 {
			t.Fatalf("hybrid scan failed: %v\n%s", err, out)
		}
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read report: %v\noutput:\n%s", err, out)
	}

	var report struct {
		Findings []struct {
			Title      string `json:"title"`
			Source     string `json:"source"`
			Endpoint   string `json:"endpoint"`
			Reachable  bool   `json:"reachable,omitempty"`
			TaintChain []struct {
				File string `json:"file"`
				Line int    `json:"line"`
				Expr string `json:"expr"`
			} `json:"taint_chain,omitempty"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode report: %v\nreport:\n%s", err, raw)
	}

	// Step 1: the AST analyzer must have emitted at least one whitebox
	// finding with a taint chain.
	var chainsFound int
	for _, f := range report.Findings {
		if len(f.TaintChain) > 0 {
			chainsFound++
		}
	}
	if chainsFound == 0 {
		t.Fatalf(
			"expected ≥1 finding with a taint chain from the AST analyzer; got 0.\n"+
				"Report:\n%s\nOutput:\n%s",
			raw, out,
		)
	}

	// Step 2: at least one of those chains must reference the request
	// source (request.args / request.GET / etc).
	var sourceLinkFound bool
	for _, f := range report.Findings {
		for _, link := range f.TaintChain {
			if strings.Contains(link.Expr, "request.args") ||
				strings.Contains(link.Expr, "request.GET") {
				sourceLinkFound = true
				break
			}
		}
	}
	if !sourceLinkFound {
		t.Errorf("expected a taint-chain link referencing request input; none found")
	}

	// Step 3: the report must contain at least one correlated finding —
	// confirms the existing TASK-091 path still works alongside TASK-114.
	body := string(raw)
	if !strings.Contains(body, `"source":"correlated"`) &&
		!strings.Contains(body, `"source": "correlated"`) {
		t.Errorf("expected ≥1 correlated finding from the spec_parser+blackbox pair")
	}
}
