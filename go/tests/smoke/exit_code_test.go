package smoke

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// These exercise the ACTUAL CLI exit path — build the binary, run it as a
// subprocess, read the process exit code — not decision.Status in isolation.
// The exit code is the product surface CI gates on, and it is the last place a
// policy change can go wrong after every unit test is green.

// codeTree writes a throwaway project and returns its path.
func codeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// scanJSON runs a code scan and returns the parsed report plus the exit code.
func scanJSON(t *testing.T, root string, extra ...string) (map[string]interface{}, int) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	args := append([]string{"scan", "--code", root, "--fast", "--format", "json", "--output", out}, extra...)
	_, stderr, exit := harness.Run(t, args...)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written (exit=%d): %v\nstderr: %s", exit, err, stderr)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	return doc, exit
}

func findingsOf(t *testing.T, doc map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, _ := doc["findings"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

// A REAL hardcoded credential in production source is a deterministic pattern
// match the scanner can make on its own — the case that must still fail CI on a
// code-only scan, where a second observation is impossible in principle.
//
// The literal matters: AWS's own documentation example key
// (wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) is correctly classified as a
// PLACEHOLDER and scores LOW, so using it here would have made this test pass
// for the wrong reason — or, as it did on first run, fail misleadingly. The
// value below is high-entropy and carries no placeholder marker.
func TestExitCode_ConfirmedFindingBlocks(t *testing.T) {
	root := codeTree(t, map[string]string{
		"app/settings.py": "AWS_SECRET_ACCESS_KEY = \"kR7bQ2vN8sXpL4wZ1tYcH6mJ3fD9gA5nE0uT2iOe\"\n",
	})

	doc, exit := scanJSON(t, root, "--fail-on", "HIGH")
	if exit != 1 {
		t.Errorf("exit = %d, want 1 — a real production credential must gate the build", exit)
	}

	var blocked bool
	for _, f := range findingsOf(t, doc) {
		if f["status"] == "BLOCK" {
			blocked = true
			if f["decision_reason"] == nil || f["decision_reason"] == "" {
				t.Errorf("BLOCK finding %q has no decision_reason", f["title"])
			}
			if f["decision_policy"] != "enforced" {
				t.Errorf("decision_policy = %v, want %q", f["decision_policy"], "enforced")
			}
			if f["policy_override"] == true {
				t.Errorf("an evidence-backed BLOCK is marked policy_override")
			}
		}
	}
	if !blocked {
		t.Error("no BLOCK finding in the report despite exit 1")
	}
}

// A synthetic credential in test code is the canonical false positive. It must
// be REPORTED (evidence preserved) and must NOT gate.
func TestExitCode_SyntheticTestSecretDoesNotBlock(t *testing.T) {
	root := codeTree(t, map[string]string{
		"tests/test_client.py": "FAKE_API_KEY = \"AKIAIOSFODNN7EXAMPLE0000\"\n",
	})

	doc, exit := scanJSON(t, root, "--fail-on", "HIGH")
	if exit != 0 {
		t.Errorf("exit = %d, want 0 — a fixture-shaped credential in test code must not gate", exit)
	}
	if len(findingsOf(t, doc)) == 0 {
		t.Error("the finding was suppressed entirely; it must be de-escalated, never deleted (Rule 3)")
	}
	for _, f := range findingsOf(t, doc) {
		if f["status"] == "BLOCK" {
			t.Errorf("finding %q reached BLOCK", f["title"])
		}
	}
}

// A mixture must still gate: one confirmed BLOCK among many WARNs is exit 1.
func TestExitCode_MixtureWithOneConfirmedBlockStillGates(t *testing.T) {
	root := codeTree(t, map[string]string{
		"tests/test_a.py": "FAKE_API_KEY = \"AKIAIOSFODNN7EXAMPLE0000\"\n",
		"tests/test_b.py": "DUMMY_TOKEN = \"AKIAIOSFODNN7EXAMPLE1111\"\n",
		"app/settings.py": "AWS_SECRET_ACCESS_KEY = \"kR7bQ2vN8sXpL4wZ1tYcH6mJ3fD9gA5nE0uT2iOe\"\n",
		"app/__init__.py": "",
	})

	_, exit := scanJSON(t, root, "--fail-on", "HIGH")
	if exit != 1 {
		t.Errorf("exit = %d, want 1 — one confirmed BLOCK among WARNs must gate", exit)
	}
}

// THE POLICY-OVERRIDE PATH. --enforce-confidence=false restores the legacy
// severity-only gate, so an uncorroborated finding blocks again. The exit code
// changes AND the report must say the gate was relaxed — otherwise a relaxed
// BLOCK is indistinguishable from an evidence-backed one.
func TestExitCode_RelaxedPolicyBlocksAndIsAudited(t *testing.T) {
	// The fixture has to be a finding the SHIPPED policy declines but the
	// LEGACY one blocks — and it must not be test code, because the
	// test-fixture de-escalation is gated on --deescalate-tests rather than
	// --enforce-confidence and therefore fires under BOTH policies.
	//
	// AWS's documentation example key in production source is exactly that
	// shape: CRITICAL severity (so the legacy severity-only gate blocks), but
	// the placeholder classifier scores it LOW, so the shipped policy warns.
	root := codeTree(t, map[string]string{
		"app/settings.py": "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
	})

	// Baseline: the shipped policy does not gate on this.
	if _, exit := scanJSON(t, root, "--fail-on", "HIGH"); exit != 0 {
		t.Fatalf("shipped-policy exit = %d, want 0; the override test needs this baseline", exit)
	}

	doc, exit := scanJSON(t, root, "--fail-on", "HIGH", "--enforce-confidence=false")
	if exit != 1 {
		t.Fatalf("relaxed-policy exit = %d, want 1 — the legacy gate must still block on severity", exit)
	}

	var audited bool
	for _, f := range findingsOf(t, doc) {
		if f["status"] != "BLOCK" {
			continue
		}
		if f["decision_policy"] != "relaxed" {
			t.Errorf("decision_policy = %v, want %q", f["decision_policy"], "relaxed")
		}
		if f["policy_override"] != true {
			t.Errorf("policy_override = %v, want true — this BLOCK exists only because the "+
				"evidence requirement was switched off", f["policy_override"])
		}
		if r, _ := f["decision_reason"].(string); !strings.Contains(r, "relaxed policy") {
			t.Errorf("decision_reason = %q, does not name the relaxation", r)
		}
		audited = true
	}
	if !audited {
		t.Error("no BLOCK finding carried the override audit fields")
	}
}

// Raw secret values must never reach the report, on any path.
func TestExitCode_ReportNeverCarriesTheRawSecret(t *testing.T) {
	const secret = "kR7bQ2vN8sXpL4wZ1tYcH6mJ3fD9gA5nE0uT2iOe"
	root := codeTree(t, map[string]string{
		"app/settings.py": "AWS_SECRET_ACCESS_KEY = \"" + secret + "\"\n",
	})

	out := filepath.Join(t.TempDir(), "report.sarif")
	harness.Run(t, "scan", "--code", root, "--fast", "--format", "sarif", "--output", out, "--fail-on", "HIGH")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no SARIF written: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Error("the raw credential appears verbatim in the SARIF report")
	}
}
