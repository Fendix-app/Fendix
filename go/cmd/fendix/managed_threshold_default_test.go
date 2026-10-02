package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A managed run's local report can never show BLOCK, and that is by design.
//
// The managed scan is run without --fail-on, and --fail-on defaults to unset,
// which means no threshold: every finding takes the below-threshold arm, so a
// HIGH finding is at most WARN locally. The backend classifies the same facts
// against the binding's fail_on_severity (default HIGH) and can BLOCK. The
// v3.5.0-rc.2 end to end showed exactly that pair for GO-2021-0113.
//
// These tests pin the settings behind it: the threshold is the ONE setting a
// default local scan and a managed evaluation do not share. The three decision
// options the finding policy fixes for managed CI are the CLI's own defaults.

const managedFindingPolicyPath = "../../../contracts/managed-ci/v2/policy/finding-policy-1.0.0.json"

func TestFailOnDefaultsToNoThreshold(t *testing.T) {
	f := newScanCmd().Flags().Lookup("fail-on")
	if f == nil {
		t.Fatal("scan has no --fail-on flag")
	}
	if f.DefValue != "" {
		t.Fatalf("--fail-on default = %q, want \"\" (no threshold): a managed run's local report "+
			"depends on it, and the managed step in action.yml passes no --fail-on", f.DefValue)
	}
}

func TestManagedDecisionOptionsAreTheCLIDefaults(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(managedFindingPolicyPath))
	if err != nil {
		t.Fatalf("read finding policy: %v", err)
	}
	var spec struct {
		Options      map[string]map[string]bool `json:"options"`
		FailOnValues []string                   `json:"fail_on_values"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("decode finding policy: %v", err)
	}
	managed, ok := spec.Options["managed_ci_default"]
	if !ok || len(managed) != 3 {
		t.Fatalf("managed_ci_default options = %v, want exactly three", managed)
	}
	flags := newScanCmd().Flags()
	for option, flag := range map[string]string{
		"enforce_confidence":    "enforce-confidence",
		"deescalate_tests":      "deescalate-tests",
		"block_on_inapplicable": "block-on-inapplicable",
	} {
		f := flags.Lookup(flag)
		if f == nil {
			t.Fatalf("scan has no --%s flag", flag)
		}
		want, present := managed[option]
		if !present {
			t.Fatalf("managed_ci_default has no %s", option)
		}
		if f.DefValue != strconv.FormatBool(want) {
			t.Errorf("--%s default = %s, managed_ci_default.%s = %t: a default local scan and a "+
				"managed evaluation would differ in more than the threshold", flag, f.DefValue, option, want)
		}
	}
	// The managed policy has no threshold-less value, so the CLI default has no
	// managed counterpart.
	for _, v := range spec.FailOnValues {
		if v == "" {
			t.Fatalf("fail_on_values contains the empty threshold: %v", spec.FailOnValues)
		}
	}
}

// The managed Action step runs the scan without --fail-on: the threshold is
// the binding's, held by the backend.
func TestManagedActionStepPassesNoFailOn(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean("../../../action.yml"))
	if err != nil {
		t.Fatalf("read action.yml: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "- name: Run Fendix managed scan")
	if start < 0 {
		t.Fatal("action.yml has no managed scan step")
	}
	step := text[start+1:]
	if end := strings.Index(step, "\n    - name:"); end >= 0 {
		step = step[:end]
	}
	if !strings.Contains(step, "fendix scan") {
		t.Fatal("managed scan step does not run fendix scan")
	}
	for _, line := range strings.Split(step, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "--fail-on") {
			t.Fatalf("managed scan step passes --fail-on: %q", trimmed)
		}
	}
}
