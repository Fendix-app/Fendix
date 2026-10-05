package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/cli"
)

// The --enforce-confidence flag is the last hop of the FIX-08 wiring
// (CLI → ScanConfig → orchestrator.decisionOptions → decision.decide). These
// tests cover the CLI end; the decision-layer rule table lives in
// internal/decision and the orchestrator hop in internal/engine.

func TestEnforceConfidenceFlagDefaultsToOn(t *testing.T) {
	scan := newScanCmd()
	f := scan.Flags().Lookup("enforce-confidence")
	if f == nil {
		t.Fatal("scan has no --enforce-confidence flag; the FIX-08 gate is unreachable from the CLI")
	}
	if f.DefValue != "true" {
		t.Errorf("--enforce-confidence default = %q, want \"true\" — the CHANGELOG documents\n"+
			"confidence-gated enforcement as the shipped default", f.DefValue)
	}
	if f.Value.Type() != "bool" {
		t.Errorf("--enforce-confidence type = %q, want bool", f.Value.Type())
	}
}

func TestEnforceConfidenceFlagIsDocumented(t *testing.T) {
	f := newScanCmd().Flags().Lookup("enforce-confidence")
	if f == nil {
		t.Fatal("missing --enforce-confidence flag")
	}
	// A team reading --help must be able to learn, without reading the source,
	// that this flag is what decides whether --fail-on actually fails.
	for _, want := range []string{"confidence", "fail-on", "corroborating"} {
		if !strings.Contains(strings.ToLower(f.Usage), want) {
			t.Errorf("--enforce-confidence usage should mention %q: %q", want, f.Usage)
		}
	}
}

// TestEnforceConfidenceFlagIsOverridable proves the escape hatch parses; a bool
// flag with a true default is only useful if `=false` works, and the policy
// precedence machinery keys off Changed().
func TestEnforceConfidenceFlagIsOverridable(t *testing.T) {
	scan := newScanCmd()
	if err := scan.Flags().Parse([]string{"--enforce-confidence=false"}); err != nil {
		t.Fatalf("parsing --enforce-confidence=false: %v", err)
	}
	got, err := scan.Flags().GetBool("enforce-confidence")
	if err != nil {
		t.Fatalf("GetBool: %v", err)
	}
	if got {
		t.Error("--enforce-confidence=false did not turn the gate off")
	}
	if !scan.Flags().Changed("enforce-confidence") {
		t.Error("flags.Changed(\"enforce-confidence\") = false; policy precedence relies on it")
	}
}

// TestEnforceConfidenceFlagReachesScanConfig closes the CLI -> ScanConfig hop
// by running the REAL scan command and reading the emitted report + exit code.
//
// This is the only test shape that catches a mis-wired assignment: the zero
// value of both ScanConfig.EnforceConfidence and decision.Options.EnforceConfidence
// is false, so dropping the assignment in main.go leaves every unit test green
// while the shipped binary quietly runs the legacy gate. That is exactly how
// DeescalateTests shipped as dead code.
//
// The fixture is a hardcoded credential in a NON-test path scanned with
// --deescalate-tests=false, so the confidence gate is the only policy in play
// and a flip cannot be blamed on FIX-09.
//
// The VALUE matters: a run of one character is what the secrets scanner's
// placeholder classifier recognises as fixture-shaped, so this finding scores
// 35 base + 10 static - 20 placeholder = 25 → LOW band. A real-looking
// credential here would band HIGH via deterministicDetection and BLOCK under
// both policies, proving nothing about the wiring.
func TestEnforceConfidenceFlagReachesScanConfig(t *testing.T) {
	code := t.TempDir()
	secret := "api_key = \"" + strings.Repeat("A", 32) + "\"\n"
	if err := os.WriteFile(filepath.Join(code, "settings.py"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, args ...string) ([]map[string]any, int) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "report.json")
		root := newRootCmd()
		base := []string{
			"scan", "--code", code, "--format", "json", "--output", out,
			// --fast keeps this hermetic: native scanners only, no semgrep
			// subprocess and no dep-CVE network calls.
			"--fast", "--python-engine=false", "--no-plugins",
			// Isolate the confidence gate from the test-fixture rule.
			"--deescalate-tests=false", "--fail-on", "HIGH",
		}
		root.SetArgs(append(base, args...))
		root.SetOut(new(strings.Builder))
		root.SetErr(new(strings.Builder))
		// The REAL process exit code, not one re-derived from the statuses:
		// a scan that gates returns *cli.ExitError{Code: 1} up to main(), and
		// that error IS the CI contract this fix changes.
		exit := 0
		if err := root.Execute(); err != nil {
			var exitErr *cli.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("scan failed: %v", err)
			}
			exit = exitErr.Code
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		var rep struct {
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("parsing report: %v\n%s", err, raw)
		}
		if len(rep.Findings) == 0 {
			t.Fatal("no findings produced — the fixture secret was not detected")
		}
		return rep.Findings, exit
	}

	t.Run("default (flag omitted) holds an uncorroborated finding at WARN", func(t *testing.T) {
		findings, exit := run(t)
		for _, f := range findings {
			if f["status"] == "BLOCK" {
				t.Errorf("finding %v blocked under the default gate: score=%v band=%v reasons=%v",
					f["endpoint"], f["confidence_score"], f["confidence_band"], f["confidence_reasons"])
			}
		}
		if exit != 0 {
			t.Error("expected exit 0 with the confidence gate on")
		}
	})

	t.Run("--enforce-confidence=false restores the severity-only gate", func(t *testing.T) {
		findings, exit := run(t, "--enforce-confidence=false")
		var sawBlock bool
		for _, f := range findings {
			if f["status"] == "BLOCK" {
				sawBlock = true
			}
		}
		if !sawBlock || exit != 1 {
			t.Errorf("expected a BLOCK and exit 1 with --enforce-confidence=false; got exit %d, findings %v",
				exit, findings)
		}
	})
}

// TestRealProductionSecretStillFailsTheBuild is DECISIONS.md D1 as an
// end-to-end contract, and it is the single most important test in this file.
//
// FIX-08 makes BLOCK band-dependent. A whitebox secrets finding scores
// 35 base + 10 static = 45 (MEDIUM) with no live corroboration available on a
// code-only scan, so without the deterministicDetection delta a real hardcoded
// production credential would have STOPPED failing the build — a security
// regression dressed up as a precision win. The delta puts it at 75 (HIGH), and
// the InTest gate on that delta is what keeps its fixture twin at WARN.
//
// The two files carry the SAME credential text, so nothing but the path (and
// therefore the band) can explain the different verdicts.
func TestRealProductionSecretStillFailsTheBuild(t *testing.T) {
	const credential = "STRIPE_SECRET_KEY = \"sk_live_51H8xQ2KzYbWpLmNvR4tGcE7dJ9aX\"\n"

	scan := func(t *testing.T, dir string) (int, []map[string]any) {
		t.Helper()
		out := filepath.Join(t.TempDir(), "report.json")
		root := newRootCmd()
		root.SetArgs([]string{
			"scan", "--code", dir, "--format", "json", "--output", out,
			"--fast", "--python-engine=false", "--no-plugins", "--fail-on", "HIGH",
		})
		root.SetOut(new(strings.Builder))
		root.SetErr(new(strings.Builder))
		exit := 0
		if err := root.Execute(); err != nil {
			var exitErr *cli.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("scan failed: %v", err)
			}
			exit = exitErr.Code
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("reading report: %v", err)
		}
		var rep struct {
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatalf("parsing report: %v\n%s", err, raw)
		}
		return exit, rep.Findings
	}

	t.Run("production code still exits 1", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(credential), 0o600); err != nil {
			t.Fatal(err)
		}
		exit, findings := scan(t, dir)
		if exit != 1 {
			t.Errorf("a real hardcoded production credential exited %d, want 1 — the confidence\n"+
				"gate has produced a SECURITY REGRESSION; findings: %v", exit, findings)
		}
		var blocked bool
		for _, f := range findings {
			if f["status"] == "BLOCK" {
				blocked = true
			}
		}
		if !blocked {
			t.Errorf("no finding reached BLOCK: %v", findings)
		}
	})

	t.Run("the same credential in tests/ does not", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "tests"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tests", "test_billing.py"), []byte(credential), 0o600); err != nil {
			t.Fatal(err)
		}
		exit, findings := scan(t, dir)
		if exit != 0 {
			t.Errorf("a fixture credential exited %d, want 0 — the FP mitigation did not reach\n"+
				"the gate; findings: %v", exit, findings)
		}
		// Rule 3: de-escalated, not suppressed. The finding is still reported,
		// with its evidence, at its original severity.
		if len(findings) == 0 {
			t.Fatal("the test-code finding was SUPPRESSED; Rule 3 requires it to be reported")
		}
		for _, f := range findings {
			if f["status"] == "BLOCK" {
				t.Errorf("test-code finding still blocks: %v", f)
			}
			if f["evidence"] == "" {
				t.Errorf("test-code finding lost its evidence text: %v", f)
			}
		}
	})
}
