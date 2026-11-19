package engine

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Round 5 verification, security5-05. Two analyzers describe one eval() call:
// the Python engine's rule asserts a literal match (confidence HIGH, which earns
// the deterministic-detection delta and so can block under --fail-on) and
// textscan's rule grades it MEDIUM. The textscan finding is the higher-trust
// representative, and it used to survive alone: a finding that blocked on its
// own (an .mts file before textscan covered it) became a WARN the moment a second
// analyzer reported the same call. The representative keeps its severity and its
// wording, but not at the cost of a stronger claim the other analyzer made.
func TestCollapseKeepsTheStrongestConfidenceOfTheNonSemgrepMembers(t *testing.T) {
	native := wbAt("injection", "app.mts:3", "eval() with non-literal argument", models.SeverityHigh, models.TierNativeGo)
	native.Confidence, native.RuleID = models.ConfidenceMedium, "JS_EVAL_LITERAL"
	python := wbAt("injection", "app.mts:3", "Unsafe use of eval() in JavaScript", models.SeverityHigh, "")
	python.Confidence, python.RuleID = models.ConfidenceHigh, "SEC-JS_EVAL"

	for name, in := range map[string][]models.Finding{
		"native first": {native, python},
		"python first": {python, native},
	} {
		got := CollapseDuplicateLocations(in)
		if len(got) != 1 {
			t.Fatalf("%s: want one finding, got %d", name, len(got))
		}
		if got[0].Title != native.Title {
			t.Errorf("%s: representative = %q, want the higher-trust native finding", name, got[0].Title)
		}
		if got[0].Confidence != models.ConfidenceHigh {
			t.Errorf("%s: confidence = %s; the collapse weakened the claim of the dropped HIGH finding", name, got[0].Confidence)
		}
	}
}

// A Semgrep claim never strengthens a native one: Semgrep's tiers are excluded
// from the deterministic-detection delta on purpose, and adopting its HIGH
// would hand it back through the representative.
func TestCollapseDoesNotLetASemgrepConfidenceStrengthenTheRepresentative(t *testing.T) {
	native := wbAt("injection", "app.js:3", "eval() with non-literal argument", models.SeverityHigh, models.TierNativeGo)
	native.Confidence, native.RuleID = models.ConfidenceMedium, "JS_EVAL_LITERAL"
	shim := wbAt("injection", "app.js:3", "eval injection (semgrep)", models.SeverityHigh, models.TierSemgrepShim)
	shim.Confidence, shim.RuleID = models.ConfidenceHigh, "python-eval-injection"
	got := CollapseDuplicateLocations([]models.Finding{native, shim})
	if len(got) != 1 || got[0].Confidence != models.ConfidenceMedium {
		t.Errorf("confidence = %v; a Semgrep shim finding must not strengthen the representative", got)
	}
}

// Verification pass 1, integration5-01: the rule of a finding the collapse drops
// stays visible on the representative, as a rule: reference.
func TestCollapseKeepsTheDroppedRulesOnTheRepresentative(t *testing.T) {
	// RC-9: the pair must be one construct to fold. (It was a child_process
	// finding and a SQL-injection taint finding, two constructs the collapse
	// folded into one; they now stay two findings, see collapse_construct_test.go.)
	native := wbAt("injection", "app.js:1", "child_process shell", models.SeverityHigh, models.TierNativeGo)
	native.RuleID = "JS_CHILD_PROCESS_SHELL"
	native.References = []string{"CWE-78"}
	taint := wbAt("injection", "app.js:1", "command injection sink", models.SeverityHigh, models.TierSemgrepShim)
	taint.RuleID = "js-cmdi-sink"
	taint.References = []string{"CWE-78"}
	got := CollapseDuplicateLocations([]models.Finding{native, taint})
	if len(got) != 1 {
		t.Fatalf("want one finding, got %d", len(got))
	}
	have := map[string]bool{}
	for _, r := range got[0].References {
		have[r] = true
	}
	if !have["rule:js-cmdi-sink"] || !have["CWE-78"] {
		t.Errorf("references = %v; the dropped rule and its CWE must survive on the representative", got[0].References)
	}
}
