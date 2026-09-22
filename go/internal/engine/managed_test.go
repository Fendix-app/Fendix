package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/managedci"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// Managed coverage must account for every analyzer this engine can run. An
// analyzer in no family would silently vanish from managed evidence: the
// backend would never hear that it ran, failed or was skipped.
func TestEveryRegistryAnalyzerBelongsToExactlyOneFamily(t *testing.T) {
	for _, name := range Registry {
		families := managedci.FamiliesOf([]string{name})
		if len(families) != 1 {
			t.Errorf("analyzer %q maps to %v, want exactly one contract analyzer", name, families)
		}
	}
}

func writeContext(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "context.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}
	return path
}

const validContext = `{
  "evidence_submission_id": "44444444-4444-4444-8444-444444444444",
  "context": {
    "schema_version": "managed-scan-context/v1",
    "scan_execution_id": "33333333-3333-4333-8333-333333333333",
    "tenant_id": "11111111-1111-4111-8111-111111111111",
    "asset_id": "22222222-2222-4222-8222-222222222222",
    "environment": "staging", "provider": "github",
    "repository_id": "123456", "repository_owner_id": "7654321",
    "repository": "acme/payments",
    "head_sha": "1111111111111111111111111111111111111111",
    "base_sha": "2222222222222222222222222222222222222222",
    "pull_request": 17,
    "workflow_name": "Fendix managed scan",
    "workflow_ref": "acme/payments/.github/workflows/fendix.yml@refs/heads/main",
    "run_id": "987654", "run_attempt": 1, "event_name": "pull_request"
  }
}`

func TestManagedContextIsValidatedBeforeUse(t *testing.T) {
	if _, err := readManagedContext(""); err == nil {
		t.Error("a missing --managed-context was accepted")
	}
	if _, err := readManagedContext(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("an unreadable context was accepted")
	}
	// An unknown field means the runner and the engine disagree about the
	// contract; guessing which half is right is how evidence gets forged.
	extra := strings.Replace(validContext, `"evidence_submission_id"`, `"token": "fxci_secret", "evidence_submission_id"`, 1)
	if _, err := readManagedContext(writeContext(t, extra)); err == nil {
		t.Error("an unknown context field was accepted")
	}
	if _, err := readManagedContext(writeContext(t, `{"context": {}}`)); err == nil {
		t.Error("a context without a submission id was accepted")
	}
	runner, err := readManagedContext(writeContext(t, validContext))
	if err != nil {
		t.Fatalf("valid context rejected: %v", err)
	}
	if runner.Context.RepositoryID != "123456" || runner.EvidenceSubmissionID == "" {
		t.Errorf("context decoded wrongly: %+v", runner)
	}
}

// The configuration hash travels to the backend, so its inputs must describe
// HOW the scan ran and never WHERE it ran or against what.
func TestManagedConfigurationCarriesNoPathsOrTargets(t *testing.T) {
	o := &Orchestrator{cfg: &models.ScanConfig{
		CodePath: "/home/runner/work/acme/payments",
		URL:      "https://staging.internal.example",
	}}
	for key, value := range o.managedConfiguration() {
		if strings.Contains(value, "/") || strings.Contains(value, "example") || strings.Contains(value, "secret") {
			t.Errorf("configuration input %q leaks %q", key, value)
		}
	}
	if o.managedConfiguration()["code_scan"] != "true" || o.managedConfiguration()["url_scan"] != "true" {
		t.Error("the configuration must still record that a code and url scan ran")
	}
}

func managedOrchestrator(t *testing.T, evidencePath, contextPath string) *Orchestrator {
	t.Helper()
	return &Orchestrator{
		cfg: &models.ScanConfig{
			CodePath: t.TempDir(), ManagedEvidencePath: evidencePath, ManagedContextPath: contextPath,
			EnforceConfidence: true, DeescalateTests: true,
		},
		version:         "v3.4.1",
		analyzerTimings: map[string]time.Duration{"secrets": 1500 * time.Millisecond},
	}
}

func managedFixture() ([]models.Finding, []decision.Decision, reporters.ScanMetadata) {
	finding := models.Finding{
		ID: "SEC-001", Fingerprint: strings.Repeat("e", 40), RuleID: "SEC-SECRET-001",
		Title: "Hardcoded credential", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Category: "secrets", Endpoint: "app/config.py:7", Evidence: "[REDACTED len=20]",
		Confidence: models.ConfidenceHigh, SourceTier: models.TierNativeGo,
		Secret: &models.SecretRef{},
		// A decided finding: none of this may reach the document.
		Status: "BLOCK", ConfidenceScore: 75, ConfidenceBand: "HIGH",
	}
	decided := decision.Decision{Evidence: evidence.Evidence{
		Severity: finding.Severity, Source: finding.Source, Category: finding.Category,
		Confidence: finding.Confidence, SourceTier: finding.SourceTier,
	}}
	meta := reporters.ScanMetadata{ScannerStatus: []reporters.ScannerStatus{
		{Name: AnalyzerSecrets, State: reporters.ScannerOK},
		{Name: AnalyzerTextscan, State: reporters.ScannerOK},
		{Name: AnalyzerPip, State: reporters.ScannerOK},
	}}
	return []models.Finding{finding}, []decision.Decision{decided}, meta
}

func TestWriteManagedEvidenceProducesAnObservationOnlyDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	o := managedOrchestrator(t, path, writeContext(t, validContext))
	findings, decisions, meta := managedFixture()
	if err := o.writeManagedEvidence(findings, decisions, meta); err != nil {
		t.Fatalf("writeManagedEvidence: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	var submission managedci.Submission
	if err := json.Unmarshal(raw, &submission); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if submission.APIVersion != managedci.APIVersion {
		t.Errorf("api_version = %q", submission.APIVersion)
	}
	if len(submission.Manifest.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(submission.Manifest.Findings))
	}
	exported := submission.Manifest.Findings[0]
	if exported.AnalyzerID != managedci.AnalyzerSecrets {
		t.Errorf("analyzer_id = %q, want secrets", exported.AnalyzerID)
	}
	if exported.EvidenceFacts.RulePrecision != "high" || exported.EvidenceFacts.ObservationSource != "whitebox" {
		t.Errorf("facts were not exported from the evidence: %+v", exported.EvidenceFacts)
	}
	if len(exported.Locations) != 1 || exported.Locations[0].Path != "app/config.py" {
		t.Errorf("locations = %+v, want a repository-relative path", exported.Locations)
	}
	// Nothing the engine decided may appear anywhere in the body. Checked
	// structurally (keys and string values), because a digest can contain
	// any digit sequence by chance.
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("decode: %v", err)
	}
	manifest, _ := tree.(map[string]any)["manifest"].(map[string]any)
	if _, ok := manifest["producer_diagnostics"]; ok {
		t.Error("the document carries producer diagnostics")
	}
	// Analyzer execution status is a legitimate observation; a conclusion
	// ABOUT A FINDING is not. Only the findings subtree is checked.
	for _, conclusion := range findConclusions(manifest["findings"], []string{"findings"}) {
		t.Errorf("a finding carries a conclusion at %s", conclusion)
	}
	// The secrets family ran, so it is observed; sca did too via pip.
	if strings.Join(submission.Manifest.Coverage.ObservedAnalyzers, ",") != "sast,sca,secrets" {
		t.Errorf("observed = %v", submission.Manifest.Coverage.ObservedAnalyzers)
	}
	secrets := analyzerByID(submission.Manifest.Analyzers, managedci.AnalyzerSecrets)
	if secrets == nil || secrets.DurationMS != 1500 || secrets.FindingCount != 1 {
		t.Errorf("secrets analyzer = %+v, want 1500ms and one finding", secrets)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("evidence file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestManagedEvidenceRefusesANonReleaseEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.json")
	o := managedOrchestrator(t, path, writeContext(t, validContext))
	o.version = "dev"
	findings, decisions, meta := managedFixture()
	err := o.writeManagedEvidence(findings, decisions, meta)
	if err == nil {
		t.Fatal("a development build produced managed evidence")
	}
	if !strings.Contains(err.Error(), "released engine build") {
		t.Errorf("error = %v, want it to name the release requirement", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("a document was written despite the failure")
	}
}

func analyzerByID(analyzers []managedci.Analyzer, id string) *managedci.Analyzer {
	for i := range analyzers {
		if analyzers[i].AnalyzerID == id {
			return &analyzers[i]
		}
	}
	return nil
}

// findConclusions reports any key or string value that states a conclusion
// rather than an observation. The contract prohibits these keys outright;
// this is the producer-side half of the same rule.
func findConclusions(node any, path []string) []string {
	banned := map[string]bool{
		"status": true, "confidence": true, "confidence_score": true, "confidence_band": true,
		"confidence_reasons": true, "decision": true, "decision_reason": true, "tier": true,
		"blocking": true, "is_blocking": true, "exit_code": true, "finding_status": true,
		"verdict": true, "risk_score": true, "producer_diagnostics": true,
	}
	var found []string
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			here := append(append([]string{}, path...), key)
			if banned[strings.ToLower(key)] {
				found = append(found, strings.Join(here, "."))
			}
			found = append(found, findConclusions(child, here)...)
		}
	case []any:
		for i, child := range value {
			found = append(found, findConclusions(child, append(append([]string{}, path...), string(rune('0'+i%10))))...)
		}
	case string:
		for _, verdict := range []string{"BLOCK", "WARN", "PASS", "INCOMPLETE"} {
			if value == verdict {
				found = append(found, strings.Join(path, ".")+"="+value)
			}
		}
	}
	return found
}
