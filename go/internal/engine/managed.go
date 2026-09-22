package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/managedci"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// Managed-CI evidence export (ADR-010, contract managed-ci/v2).
//
// The engine produces the EXACT request body the runner submits, so the
// runner never edits evidence: it transports bytes and polls for the
// backend's decision. Everything here is an observation; the run's own
// status, confidence and exit code stay behind.
//
// Any failure is fatal to the scan (exit 2). A managed run that cannot
// produce evidence must not look like a run that produced clean evidence.

// managedRunner is the runner-supplied half of a managed submission: the CI
// identity of this workflow attempt plus the submission id. The engine
// copies the context verbatim and validates it; the backend then compares
// every field with the binding its credential carries.
type managedRunner struct {
	EvidenceSubmissionID string            `json:"evidence_submission_id"`
	Context              managedci.Context `json:"context"`
}

// writeManagedEvidence builds and writes the submission document.
func (o *Orchestrator) writeManagedEvidence(
	findings []models.Finding, decisions []decision.Decision, meta reporters.ScanMetadata,
) error {
	runner, err := readManagedContext(o.cfg.ManagedContextPath)
	if err != nil {
		return err
	}
	digest, err := managedci.SelfDigest()
	if err != nil {
		return err
	}
	executions := make(map[string]managedci.Execution, len(meta.ScannerStatus))
	for _, status := range meta.ScannerStatus {
		executions[status.Name] = managedci.Execution{Status: status, Duration: o.analyzerTimings[status.Name]}
	}
	_, body, err := managedci.Export(managedci.ExportInput{
		Findings:             findings,
		Decisions:            decisions,
		Executions:           executions,
		Context:              runner.Context,
		RequiredAnalyzers:    managedci.FamiliesOf(o.cfg.RequiredAnalyzers),
		EvidenceSubmissionID: runner.EvidenceSubmissionID,
		EngineVersion:        reportVersion(o.version),
		BuildDigest:          digest,
		ReportSchemaVersion:  reporters.SchemaVersion,
		FindingPolicyVersion: decision.PolicyVersion,
		Workspace:            o.cfg.CodePath,
		GeneratedAt:          time.Now().UTC(),
		Configuration:        o.managedConfiguration(),
	})
	if err != nil {
		return err
	}
	// 0600: the document contains no secrets by construction, but it is
	// evidence about a customer's code and only the runner needs to read it.
	if err := os.WriteFile(o.cfg.ManagedEvidencePath, body, 0o600); err != nil {
		return fmt.Errorf("write managed evidence: %w", err)
	}
	return nil
}

func readManagedContext(path string) (managedRunner, error) {
	var runner managedRunner
	if path == "" {
		return runner, fmt.Errorf("managed evidence requires --managed-context")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return runner, fmt.Errorf("read managed context: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&runner); err != nil {
		return runner, fmt.Errorf("managed context is not valid: %w", err)
	}
	if runner.EvidenceSubmissionID == "" {
		return runner, fmt.Errorf("managed context is missing evidence_submission_id")
	}
	return runner, nil
}

// managedConfiguration is the effective scan configuration, as the
// configuration hash records it. It carries decisions about HOW the scan ran
// — never a path, a target, a credential or anything from the scanned code,
// because the hash travels to the backend and the inputs must be safe to
// describe.
func (o *Orchestrator) managedConfiguration() map[string]string {
	return map[string]string{
		"block_on_inapplicable": strconv.FormatBool(o.cfg.BlockOnInapplicable),
		"code_scan":             strconv.FormatBool(o.cfg.CodePath != ""),
		"deescalate_tests":      strconv.FormatBool(o.cfg.DeescalateTests),
		"diff_scan":             strconv.FormatBool(o.cfg.Diff),
		"enforce_confidence":    strconv.FormatBool(o.cfg.EnforceConfidence),
		"offline":               strconv.FormatBool(o.cfg.Offline),
		"python_engine":         strconv.FormatBool(o.cfg.PythonEngine),
		"url_scan":              strconv.FormatBool(o.cfg.URL != ""),
	}
}
