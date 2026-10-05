package reporters

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// A dependency finding held back by applicability must SHOW that in the report.
// Without it, a reader sees a HIGH-severity CVE at WARN with no stated reason
// and cannot tell a considered de-escalation from a missed detection.
func TestApplicabilityEvidenceIsExportedForDependencyFindings(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:    "Vulnerable dependency: django==5.2.16 (CVE-2026-15830)",
		Category: "deps",
		Severity: models.SeverityHigh,
		Source:   models.SourceWhitebox,
		Endpoint: "requirements.txt",
		Status:   "WARN",
		DecisionReason: "severity at or above the --fail-on threshold, but the vulnerable package " +
			"is installed and Fendix found no import of the advisory's affected component",
		DecisionPolicy: "enforced",
		Applicability:  models.ApplicabilityEvidenceAgainst,
	})

	dec := decisionBlock(t, res)
	evi, _ := dec["evidence"].(map[string]interface{})
	if evi["applicability"] != "evidence_against" {
		t.Errorf("decision.evidence.applicability = %v, want %q", evi["applicability"], "evidence_against")
	}
	if reason, _ := dec["reason"].(string); !strings.Contains(reason, "affected component") {
		t.Errorf("decision.reason = %q, does not explain the de-escalation", reason)
	}
}

// An applicable dependency exports the positive verdict too — the state the old
// bool could not express at all.
func TestApplicableDependencyExportsItsVerdict(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:          "Vulnerable dependency: cryptography==48.0.1 (CVE-2026-69247)",
		Category:       "deps",
		Severity:       models.SeverityHigh,
		Source:         models.SourceWhitebox,
		Endpoint:       "requirements.txt",
		Status:         "BLOCK",
		DecisionPolicy: "enforced",
		Applicability:  models.ApplicabilityApplicable,
	})

	evi, _ := decisionBlock(t, res)["evidence"].(map[string]interface{})
	if evi["applicability"] != "applicable" {
		t.Errorf("decision.evidence.applicability = %v, want %q", evi["applicability"], "applicable")
	}
}

// Unknown applicability stays ABSENT. It was never evaluated, and an absent key
// is the only honest encoding of that.
func TestUnknownApplicabilityIsAbsentFromSarif(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:          "Vulnerable dependency: leftpad==1.0.0",
		Category:       "deps",
		Severity:       models.SeverityHigh,
		Source:         models.SourceWhitebox,
		Endpoint:       "requirements.txt",
		Status:         "BLOCK",
		DecisionPolicy: "enforced",
	})

	evi, _ := decisionBlock(t, res)["evidence"].(map[string]interface{})
	if v, present := evi["applicability"]; present {
		t.Errorf("applicability = %v is present but was never evaluated; want the key omitted", v)
	}
}
