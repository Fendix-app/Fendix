package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/sarifimport"
)

// ReportingContractSchemaVersion versions this documentation artifact. It is
// independent of the JSON report schema and the coverage contract.
const ReportingContractSchemaVersion = 1

type ReportingContract struct {
	SchemaVersion int                 `json:"schema_version"`
	EngineVersion string              `json:"engine_version"`
	Formats       []string            `json:"formats"`
	JSON          JSONReportContract  `json:"json_report"`
	Fingerprint   FingerprintContract `json:"fingerprint"`
	SARIF         SARIFContract       `json:"sarif"`
	Examples      ReportingExamples   `json:"examples"`
}

type JSONReportContract struct {
	SchemaVersion        int             `json:"schema_version"`
	FingerprintAlgorithm string          `json:"fingerprint_algorithm"`
	Schema               json.RawMessage `json:"schema"`
}

type FingerprintContract struct {
	Algorithm       string               `json:"algorithm"`
	LegacyAlgorithm string               `json:"legacy_algorithm"`
	Digest          string               `json:"digest"`
	Uses            []string             `json:"uses"`
	Excluded        []string             `json:"excluded"`
	Examples        []FingerprintExample `json:"examples"`
}

type FingerprintExample struct {
	Name        string   `json:"name"`
	Components  []string `json:"components"`
	Fingerprint string   `json:"fingerprint"`
}

type SARIFContract struct {
	Version              string              `json:"version"`
	Schema               string              `json:"schema"`
	AutomationID         string              `json:"automation_id"`
	PartialFingerprint   string              `json:"partial_fingerprint_key"`
	StatusLevels         map[string]string   `json:"status_levels"`
	SeverityFallback     map[string]string   `json:"severity_fallback"`
	SecuritySeverity     map[string]string   `json:"security_severity"`
	ResultPropertyFields []string            `json:"result_property_fields"`
	RunPropertyKeys      []string            `json:"run_property_keys"`
	Import               SARIFImportContract `json:"import"`
}

type SARIFImportContract struct {
	SupportedVersion      string            `json:"supported_version"`
	LevelSeverity         map[string]string `json:"level_severity"`
	PrecisionConfidence   map[string]string `json:"precision_confidence"`
	SecurityThresholds    []string          `json:"security_severity_thresholds"`
	ToolNormalization     string            `json:"tool_normalization"`
	EvidenceLimitBytes    int               `json:"evidence_limit_bytes"`
	TitleLimitBytes       int               `json:"title_limit_bytes"`
	RemediationLimitBytes int               `json:"remediation_limit_bytes"`
	TrustBoundary         []string          `json:"trust_boundary"`
}

type ReportingExamples struct {
	MinimalJSON  json.RawMessage `json:"minimal_json"`
	DecisionJSON json.RawMessage `json:"decision_json"`
	SARIFExport  json.RawMessage `json:"sarif_export"`
	SARIFImport  json.RawMessage `json:"sarif_import"`
}

func BuildReporting(schema []byte) (ReportingContract, error) {
	var normalized any
	if err := json.Unmarshal(schema, &normalized); err != nil {
		return ReportingContract{}, fmt.Errorf("decode report schema: %w", err)
	}
	schema, err := json.Marshal(normalized)
	if err != nil {
		return ReportingContract{}, fmt.Errorf("normalize report schema: %w", err)
	}

	minimal, decision, sarifExport, sarifImport, err := reportingExamples()
	if err != nil {
		return ReportingContract{}, err
	}

	return ReportingContract{
		SchemaVersion: ReportingContractSchemaVersion,
		EngineVersion: StableEngineVersion,
		Formats:       []string{"json", "html", "sarif", "pdf"},
		JSON: JSONReportContract{
			SchemaVersion:        reporters.SchemaVersion,
			FingerprintAlgorithm: models.FingerprintAlgorithm,
			Schema:               schema,
		},
		Fingerprint: fingerprintContract(),
		SARIF:       sarifContract(sarifExport),
		Examples: ReportingExamples{
			MinimalJSON: minimal, DecisionJSON: decision,
			SARIFExport: sarifExport, SARIFImport: sarifImport,
		},
	}, nil
}

func fingerprintContract() FingerprintContract {
	line := "41"
	code := models.Finding{
		RuleID: "python.sql-injection.taint", Category: "injection",
		Source: models.SourceWhitebox, Endpoint: "src/users.py:41", Line: &line,
		Symbol: "get_user", Sink: "cursor.execute(query)",
	}
	secret := models.Finding{
		RuleID: "secrets/aws-access-key", Category: "secrets",
		Source: models.SourceWhitebox, Endpoint: "config/settings.py:9",
		Secret: &models.SecretRef{File: "config/settings.py", Identifier: "AWS_ACCESS_KEY_ID"},
	}
	service := models.Finding{
		RuleID: "dast/auth", Category: "auth", Source: models.SourceBlackbox,
		Endpoint: "https://staging.example.com/users/42", Route: &models.Route{Method: "GET", Pattern: "/users/{id}"},
	}
	examples := []FingerprintExample{}
	for _, item := range []struct {
		name string
		f    models.Finding
	}{{"code", code}, {"secret", secret}, {"service", service}} {
		examples = append(examples, FingerprintExample{
			Name: item.name, Components: models.FingerprintIdentityComponents(item.f), Fingerprint: models.Fingerprint(item.f),
		})
	}
	return FingerprintContract{
		Algorithm: models.FingerprintAlgorithm, LegacyAlgorithm: "fendix/v1",
		Digest:   "SHA-256 over NUL-separated labelled components, truncated to 20 bytes and hex encoded",
		Uses:     []string{"baseline matching", "fingerprint suppressions", "finding diffing", "SARIF partialFingerprints"},
		Excluded: []string{"title", "evidence prose", "fix text", "references", "severity", "confidence", "finding disposition", "line and column", "timestamps", "credential material"},
		Examples: examples,
	}
}

func reportingExamples() (json.RawMessage, json.RawMessage, json.RawMessage, json.RawMessage, error) {
	started := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	minimalMeta := reporters.ScanMetadata{Target: "https://staging.example.com", StartedAt: started, Duration: "1.2s", Version: StableEngineVersion, Mode: "blackbox", EndpointsCount: 1, ActiveProbes: false}
	minimal, err := renderJSON(nil, minimalMeta)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	finding := models.Finding{
		ID: "SEC-001", RuleID: "python.auth.missing", Title: "Missing authentication on user data endpoint",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, SourceTier: models.TierTreeSitter,
		Category: "auth", Endpoint: "app/users.py:42", Evidence: "GET /api/users/{id} reaches users.get without an authentication guard",
		Fix: "Require authentication before returning user data.", References: []string{"CWE-306"},
		Confidence: models.ConfidenceMedium, ConfidenceScore: 68, ConfidenceBand: "MEDIUM", Status: "WARN",
		DecisionReason: "Evidence does not meet the enforced blocking requirement.", DecisionPolicy: "enforced",
		AuthExpectation: models.AuthExpectationRequired, Symbol: "users.get", Sink: "return user_record",
	}
	finding.Fingerprint = models.Fingerprint(finding)
	finding.FingerprintV1 = models.FingerprintV1(finding)
	status := []reporters.ScannerStatus{
		{Name: "semgrep", State: reporters.ScannerOK},
		{Name: "dast", State: reporters.ScannerOK},
		{Name: "pip", State: reporters.ScannerSkipped, Reason: reporters.ReasonDependencyMissing, Detail: "required manifest was not delivered"},
	}
	coverage := reporters.BuildCoverage(status, []string{"semgrep", "dast", "pip"}, true)
	decisionMeta := reporters.ScanMetadata{
		Target: "https://staging.example.com", StartedAt: started, Duration: "2.4s", Version: StableEngineVersion,
		Mode: "hybrid", EndpointsCount: 12, ActiveProbes: false, ScannerStatus: status, Coverage: &coverage,
		PolicyVersion: "v2", ReleaseDecision: "incomplete", CoverageState: "incomplete", DecisionPolicyVersion: "v2",
	}
	decision, err := renderJSON([]models.Finding{finding}, decisionMeta)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var sarif bytes.Buffer
	if err := reporters.RenderSARIF(&sarif, []models.Finding{finding}, decisionMeta); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("render SARIF example: %w", err)
	}

	importExample := json.RawMessage(`{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"ExampleSAST","semanticVersion":"4.2.0","rules":[{"id":"EXT-SQL-001","shortDescription":{"text":"SQL query built from request input"},"helpUri":"https://example.invalid/rules/EXT-SQL-001","properties":{"tags":["external/cwe/CWE-89"],"precision":"high","security-severity":"8.0"}}]}},"results":[{"ruleId":"EXT-SQL-001","level":"error","message":{"text":"Request parameter reaches a SQL query."},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/users.py"},"region":{"startLine":42}}}],"partialFingerprints":{"example/v1":"safe-example-identity"}}]}]}`)
	doc, err := sarifimport.Parse(importExample)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse SARIF import example: %w", err)
	}
	if _, _, err := sarifimport.Normalize(doc); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("normalize SARIF import example: %w", err)
	}
	return minimal, decision, json.RawMessage(sarif.Bytes()), importExample, nil
}

func renderJSON(findings []models.Finding, meta reporters.ScanMetadata) (json.RawMessage, error) {
	var out bytes.Buffer
	if err := reporters.RenderJSON(&out, findings, meta); err != nil {
		return nil, fmt.Errorf("render JSON example: %w", err)
	}
	return json.RawMessage(out.Bytes()), nil
}

func sarifContract(example json.RawMessage) SARIFContract {
	facts := reporters.SARIFDocumentationContract()
	importFacts := sarifimport.DocumentationContract()
	var log reporters.SARIFLog
	if err := json.Unmarshal(example, &log); err != nil {
		panic(fmt.Sprintf("decode generated SARIF example: %v", err))
	}
	properties := jsonFieldNames(reflect.TypeOf(reporters.SARIFResultProperties{}))
	runKeys := []string{}
	if len(log.Runs) > 0 {
		for key := range log.Runs[0].Properties {
			runKeys = append(runKeys, key)
		}
	}
	sort.Strings(runKeys)
	return SARIFContract{
		Version: facts.Version, Schema: facts.Schema,
		AutomationID: facts.AutomationID, PartialFingerprint: models.FingerprintAlgorithm,
		StatusLevels:         facts.StatusLevels,
		SeverityFallback:     facts.SeverityFallback,
		SecuritySeverity:     facts.SecuritySeverity,
		ResultPropertyFields: properties, RunPropertyKeys: runKeys,
		Import: SARIFImportContract{
			SupportedVersion:    importFacts.SupportedVersion,
			LevelSeverity:       importFacts.LevelSeverity,
			PrecisionConfidence: importFacts.PrecisionConfidence,
			SecurityThresholds:  importFacts.SecurityThresholds,
			ToolNormalization:   importFacts.ToolNormalization,
			EvidenceLimitBytes:  importFacts.EvidenceLimitBytes, TitleLimitBytes: importFacts.TitleLimitBytes, RemediationLimitBytes: importFacts.RemediationLimitBytes,
			TrustBoundary: importFacts.TrustBoundary,
		},
	}
}

func jsonFieldNames(t reflect.Type) []string {
	fields := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}
