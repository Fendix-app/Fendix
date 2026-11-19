//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Sprint 03 introduced CI-script-friendly exit codes for `fendix verify`:
//
//	1  still-present
//	2  unknown OR not-found-in-baseline
//
// Round 6 (D4 Option A): verify never exits 0. The 0 / resolved row this table
// once had is gone with the verdict: absence is not proof.
//
// Pre-Sprint-03 verify always exited 0; CI scripts had to parse JSON
// output to fail the build. These tests lock in the new contract via the
// real binary so a future RunE refactor can't silently regress it.

// minimalBaseline writes a baseline JSON containing one finding with the
// given fields and returns the file path. Mirrors writeBaseline from
// verifycmd_test.go but lives under e2e/ where it can be used without
// importing the unit-test helpers.
func minimalBaseline(t *testing.T, dir string, finding map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, "baseline.json")
	report := map[string]any{
		"metadata": map[string]any{
			"version": "test",
			"mode":    "blackbox",
		},
		"total":    1,
		"findings": []any{finding},
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyBaseline writes a baseline JSON with zero findings, used for the
// not-found-in-baseline path.
func emptyBaseline(t *testing.T, dir string) string {
	t.Helper()
	return minimalBaselineRaw(t, dir, []any{})
}

func minimalBaselineRaw(t *testing.T, dir string, findings []any) string {
	t.Helper()
	path := filepath.Join(dir, "baseline.json")
	report := map[string]any{
		"metadata": map[string]any{
			"version": "test",
			"mode":    "blackbox",
		},
		"total":    len(findings),
		"findings": findings,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runVerify runs `fendix verify <id> --baseline <baseline> --url <url>`
// and returns the process exit code (0 on clean exit). Stderr/stdout
// are captured and reported on test failure for diagnostic value.
func runVerify(t *testing.T, bin, findingID, baseline, targetURL string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, "verify", findingID, "--baseline", baseline, "--url", targetURL)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected non-exit error: %v\nstderr=%s", err, stderr.String())
		}
	}
	return exitCode, stdout.String(), stderr.String()
}

// runVerifyCode runs `fendix verify <id> --baseline <baseline> --code <root>`.
func runVerifyCode(t *testing.T, bin, findingID, baseline, root string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, "verify", findingID, "--baseline", baseline, "--code", root, "--json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected non-exit error: %v\nstderr=%s", err, stderr.String())
		}
	}
	return exitCode, stdout.String(), stderr.String()
}

// scanForSecretBaseline scans a tree that commits the (synthetic) credential and
// returns the baseline file and the secrets finding's id.
func scanForSecretBaseline(t *testing.T, bin, dir, tree string) (string, string) {
	t.Helper()
	baseline := filepath.Join(dir, "scan.json")
	cmd := exec.Command(bin, "scan", "--code", tree, "--format", "json", "--offline", "--fast", "--output", baseline)
	_ = cmd.Run() // exit 1 is a blocking finding, which is the point
	data, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatalf("scan wrote no baseline: %v", err)
	}
	var rep struct {
		Findings []struct {
			ID     string `json:"id"`
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "secrets/AWS_ACCESS_KEY" {
			return baseline, f.ID
		}
	}
	t.Fatalf("the scan reported no AWS key finding: %s", data)
	return "", ""
}

// TestE2EVerifyExit0_Resolved: a credential the secrets scanner found in source,
// removed from the whole --code tree, was the one finding that resolved and
// exited 0. Round 6 (D4 Option A): not finding a credential is absence, not
// proof, so verify exits 2 (unknown) and never answers resolved. The name is
// kept so the case stays traceable.
//
// Round 5 follow-up (DE5-02, contract C8, D5-3): this test used a "Missing
// Content-Security-Policy header" finding that "resolved" because one response
// now carried the header. That is an observation of a response, not a
// remediation, so a URL finding exits 2 (see TestE2EVerifyExit2_HeaderNowSetIsUnknown).
func TestE2EVerifyExit0_Resolved(t *testing.T) {
	bin := fendixBinary(t)
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(tree, "cfg.py")
	if err := os.WriteFile(cfg, []byte("AWS_ACCESS_KEY_ID = \"AKIAQ3EGUZ7PJSXWMOVE\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline, id := scanForSecretBaseline(t, bin, dir, tree)

	// The credential is gone from the tree.
	if err := os.WriteFile(cfg, []byte("AWS_ACCESS_KEY_ID = os.environ[\"AWS_ACCESS_KEY_ID\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exit, stdout, stderr := runVerifyCode(t, bin, id, baseline, tree)
	if exit != 2 {
		t.Errorf("want exit 2 (unknown: a credential found nowhere is not proof it is gone), got %d\nstdout=%s\nstderr=%s", exit, stdout, stderr)
	}
	if strings.Contains(stdout, "\"resolved\"") || !strings.Contains(stdout, "\"unknown\"") {
		t.Errorf("want status unknown, never resolved, got %s", stdout)
	}
}

// TestE2EVerifyExit2_HeaderNowSetIsUnknown: a passive header finding whose
// header the response carries now is unknown (exit 2), never resolved: what one
// response shows is not proof of a fix, and only a secrets-scanner finding can
// resolve (C8, D5-3).
func TestE2EVerifyExit2_HeaderNowSetIsUnknown(t *testing.T) {
	bin := fendixBinary(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := minimalBaseline(t, dir, map[string]any{
		"id":       "SEC-001-header-set",
		"title":    "Missing Content-Security-Policy header",
		"endpoint": "GET /",
		"category": "headers",
		"source":   "blackbox",
		"severity": "MEDIUM",
	})

	exit, stdout, stderr := runVerify(t, bin, "SEC-001-header-set", baseline, srv.URL)
	if exit != 2 {
		t.Errorf("want exit 2 (unknown), got %d\nstdout=%s\nstderr=%s", exit, stdout, stderr)
	}
	if !strings.Contains(stdout, "unknown") || !strings.Contains(stdout, "not proof") {
		t.Errorf("want an unknown verdict that says it is not a fix\nstdout=%s", stdout)
	}
}

// TestE2EVerifyExit1_StillPresent: the finding still fires; CI should
// receive exit 1 so the build fails.
func TestE2EVerifyExit1_StillPresent(t *testing.T) {
	bin := fendixBinary(t)

	// Target returns NO CSP header → finding is still present.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := minimalBaseline(t, dir, map[string]any{
		"id":       "SEC-001-still",
		"title":    "Missing Content-Security-Policy header",
		"endpoint": "GET /",
		"category": "headers",
		"source":   "blackbox",
		"severity": "MEDIUM",
	})

	exit, stdout, stderr := runVerify(t, bin, "SEC-001-still", baseline, srv.URL)
	if exit != 1 {
		t.Errorf("want exit 1 (still-present), got %d\nstdout=%s\nstderr=%s", exit, stdout, stderr)
	}
}

// TestE2EVerifyExit2_CorrelatedUnknown: a correlated-source finding hits
// the new dispatcher gate and returns Status=unknown. Exit 2 (operator
// should investigate, but CI shouldn't auto-fail).
func TestE2EVerifyExit2_CorrelatedUnknown(t *testing.T) {
	bin := fendixBinary(t)

	// Target doesn't matter — verify gates correlated findings before
	// the URL re-test. Use any reachable httptest server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := minimalBaseline(t, dir, map[string]any{
		"id":       "SEC-CORR-002",
		"title":    "Correlated finding for exit-code test",
		"endpoint": "GET /api/something",
		"category": "auth",
		"source":   "correlated",
		"severity": "HIGH",
	})

	exit, stdout, stderr := runVerify(t, bin, "SEC-CORR-002", baseline, srv.URL)
	if exit != 2 {
		t.Errorf("want exit 2 (correlated → unknown), got %d\nstdout=%s\nstderr=%s", exit, stdout, stderr)
	}
}

// TestE2EVerifyExit2_NotInBaseline: the requested ID isn't in the
// baseline → verify exits 2 (also "could not produce a confident result").
func TestE2EVerifyExit2_NotInBaseline(t *testing.T) {
	bin := fendixBinary(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	baseline := emptyBaseline(t, dir)

	exit, stdout, stderr := runVerify(t, bin, "SEC-DOES-NOT-EXIST", baseline, srv.URL)
	if exit != 2 {
		t.Errorf("want exit 2 (not-found-in-baseline), got %d\nstdout=%s\nstderr=%s", exit, stdout, stderr)
	}
}

// guard: confirm the binary --help output advertises the new exit-code
// table, so a future docs-drift regression is caught in CI.
func TestE2EVerifyHelpListsExitCodes(t *testing.T) {
	bin := fendixBinary(t)
	out, err := exec.Command(bin, "verify", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("verify --help: %v\n%s", err, out)
	}
	help := string(out)
	for _, want := range []string{"Exit codes", "still-present", "not-found-in-baseline", "Verify never answers"} {
		if !strings.Contains(help, want) {
			t.Errorf("verify --help should advertise %q\nfull help:\n%s", want, help)
		}
	}
}
