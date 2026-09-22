package managedci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// Contract identity and limits (contracts/managed-ci/v2/contract-set.json).
// contract_test.go pins every one of these against the vendored bundle, so a
// canonical change cannot leave the exporter quietly out of step.
const (
	APIVersion            = "managed-ci/v2"
	ManifestSchemaVersion = "evidence-manifest/v2"
	ContextSchemaVersion  = "managed-scan-context/v1"
	SanitizationProfile   = "managed-ci-default/v1"
	CoverageContract      = 1

	// MaxFindings and MaxBodyBytes are INDEPENDENT ceilings. Evidence that
	// exceeds either one is refused; it is never truncated and never split,
	// because the contract has no atomic multipart submission and a partial
	// manifest would understate the risk while looking complete.
	MaxFindings        = 10000
	MaxBodyBytes       = 8 * 1024 * 1024
	MaxAnalyzers       = 200
	MaxCorroborating   = 20
	MaxEvidenceHashes  = 20
	MaxLocations       = 20
	maxIdentifierRunes = 128
)

// Context is the CI identity of one workflow execution attempt. The runner
// supplies it; the engine copies it verbatim into the manifest and never
// invents any part of it. The backend compares every field with the binding
// the credential itself carries, so a wrong value is refused, not trusted.
type Context struct {
	SchemaVersion     string  `json:"schema_version"`
	ScanExecutionID   string  `json:"scan_execution_id"`
	TenantID          string  `json:"tenant_id"`
	AssetID           string  `json:"asset_id"`
	Environment       string  `json:"environment"`
	Provider          string  `json:"provider"`
	RepositoryID      string  `json:"repository_id"`
	RepositoryOwnerID string  `json:"repository_owner_id"`
	Repository        string  `json:"repository"`
	HeadSHA           string  `json:"head_sha"`
	BaseSHA           *string `json:"base_sha"`
	PullRequest       *int    `json:"pull_request"`
	WorkflowName      string  `json:"workflow_name"`
	WorkflowRef       string  `json:"workflow_ref"`
	RunID             string  `json:"run_id"`
	RunAttempt        int     `json:"run_attempt"`
	EventName         string  `json:"event_name"`
}

// Engine identifies the exact build that produced the evidence. The backend
// accepts only allowlisted (version, build_digest) pairs, which is what binds
// a submission to a signed release rather than to "some fendix".
type Engine struct {
	Version              string `json:"version"`
	BuildDigest          string `json:"build_digest"`
	ReportSchemaVersion  int    `json:"report_schema_version"`
	FindingPolicyVersion string `json:"finding_policy_version"`
}

// Analyzer is one analyzer's execution result.
type Analyzer struct {
	AnalyzerID      string `json:"analyzer_id"`
	AnalyzerVersion string `json:"analyzer_version"`
	Status          string `json:"status"`
	ReasonCode      string `json:"reason_code"`
	Attempts        int    `json:"attempts"`
	DurationMS      int    `json:"duration_ms"`
	FindingCount    int    `json:"finding_count"`
}

// Gap is a coverage hole the runner reports about itself.
type Gap struct {
	AnalyzerID string `json:"analyzer_id"`
	ReasonCode string `json:"reason_code"`
	Detail     string `json:"detail,omitempty"`
}

// Coverage is what ran. `required_analyzers` is recorded only: the backend
// decides what is required from the binding policy, never from this list.
type Coverage struct {
	ContractVersion     int      `json:"contract_version"`
	RequiredAnalyzers   []string `json:"required_analyzers"`
	ObservedAnalyzers   []string `json:"observed_analyzers"`
	Gaps                []Gap    `json:"gaps"`
	FilesConsidered     *int     `json:"files_considered,omitempty"`
	ManifestsConsidered *int     `json:"manifests_considered,omitempty"`
}

// Location is bounded, repo-relative display context.
type Location struct {
	Path      string `json:"path"`
	StartLine *int   `json:"start_line,omitempty"`
	EndLine   *int   `json:"end_line,omitempty"`
}

// Package names the dependency a dependency finding is about.
type Package struct {
	Ecosystem   string   `json:"ecosystem"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	AdvisoryIDs []string `json:"advisory_ids,omitempty"`
}

// Finding is one normalized finding: identity, provenance and FACTS. It
// carries no status, no confidence and no decision of any kind.
type Finding struct {
	AnalyzerID     string     `json:"analyzer_id"`
	Category       string     `json:"category"`
	EvidenceFacts  Facts      `json:"evidence_facts"`
	EvidenceHashes []string   `json:"evidence_hashes"`
	FindingID      string     `json:"finding_id"`
	Fingerprint    string     `json:"fingerprint"`
	Locations      []Location `json:"locations,omitempty"`
	Package        *Package   `json:"package,omitempty"`
	RuleID         string     `json:"rule_id"`
	Severity       string     `json:"severity"`
}

// Sanitization records the redaction profile the producer applied.
type Sanitization struct {
	Profile                string `json:"profile"`
	RedactionCount         int    `json:"redaction_count"`
	SourceExcerptsIncluded bool   `json:"source_excerpts_included"`
}

// Manifest is the evidence document. Field order is the schema's alphabetical
// order so identical observations serialize to identical bytes.
//
// `producer_diagnostics` is deliberately absent. The contract permits it as
// explicitly untrusted, but managed mode has no reason to send a local
// verdict, exit code or confidence label: they are conclusions, they are
// never read, and not sending them removes any doubt about what decided.
type Manifest struct {
	Analyzers         []Analyzer   `json:"analyzers"`
	ArtifactHash      string       `json:"artifact_hash"`
	ConfigurationHash string       `json:"configuration_hash"`
	Context           Context      `json:"context"`
	Coverage          Coverage     `json:"coverage"`
	Engine            Engine       `json:"engine"`
	Findings          []Finding    `json:"findings"`
	GeneratedAt       string       `json:"generated_at"`
	Sanitization      Sanitization `json:"sanitization"`
	SchemaVersion     string       `json:"schema_version"`
}

// Submission is the exact request body the runner POSTs to /api/ci/v2/submissions.
type Submission struct {
	APIVersion           string   `json:"api_version"`
	EvidenceSubmissionID string   `json:"evidence_submission_id"`
	IdempotencyKey       string   `json:"idempotency_key"`
	Manifest             Manifest `json:"manifest"`
}

// ErrTooLarge reports evidence that exceeds a contract ceiling. It is a
// fail-closed condition: the runner reports an error and makes NO managed
// PASS, WARN or BLOCK claim.
type ErrTooLarge struct {
	Limit  string
	Actual int
	Max    int
}

func (e ErrTooLarge) Error() string {
	return fmt.Sprintf("managed evidence exceeds the %s limit: %d > %d", e.Limit, e.Actual, e.Max)
}

// ErrProvenance reports a manifest whose parts do not account for each other.
type ErrProvenance struct{ Reason string }

func (e ErrProvenance) Error() string { return "managed evidence provenance: " + e.Reason }

// Input is everything Build needs. The caller assembles it from one scan.
type Input struct {
	Context              Context
	Engine               Engine
	Analyzers            []Analyzer
	Coverage             Coverage
	Findings             []Finding
	GeneratedAt          time.Time
	RedactionCount       int
	EvidenceSubmissionID string
	// ConfigurationInputs is the effective managed scan configuration —
	// never secrets, never the target's contents. It is hashed, not sent.
	ConfigurationInputs map[string]string
}

// Build validates and serializes one submission.
//
// It fails closed on anything the backend would refuse or could not classify:
// a finding whose facts contradict each other, a finding attributed to an
// analyzer that did not run, an analyzer whose count disagrees with its
// findings, an observed analyzer nobody reported, or evidence over either
// ceiling. Returning an error is always better than a document that decides
// nothing (INCOMPLETE) or is rejected at the door.
func Build(in Input) (Submission, []byte, error) {
	var zero Submission
	if err := in.Context.validate(); err != nil {
		return zero, nil, err
	}
	if len(in.Findings) > MaxFindings {
		return zero, nil, ErrTooLarge{Limit: "finding count", Actual: len(in.Findings), Max: MaxFindings}
	}
	if len(in.Analyzers) > MaxAnalyzers {
		return zero, nil, ErrTooLarge{Limit: "analyzer count", Actual: len(in.Analyzers), Max: MaxAnalyzers}
	}
	analyzers := append([]Analyzer(nil), in.Analyzers...)
	sort.Slice(analyzers, func(i, j int) bool { return analyzers[i].AnalyzerID < analyzers[j].AnalyzerID })
	findings := append([]Finding(nil), in.Findings...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Fingerprint != findings[j].Fingerprint {
			return findings[i].Fingerprint < findings[j].Fingerprint
		}
		return findings[i].FindingID < findings[j].FindingID
	})
	if err := checkProvenance(analyzers, findings, in.Coverage); err != nil {
		return zero, nil, err
	}
	for _, finding := range findings {
		if err := finding.EvidenceFacts.Consistent(models.Severity(finding.Severity)); err != nil {
			if inconsistent, ok := err.(ErrInconsistent); ok {
				inconsistent.FindingID = finding.FindingID
				return zero, nil, inconsistent
			}
			return zero, nil, err
		}
		if len(finding.EvidenceHashes) == 0 {
			return zero, nil, ErrProvenance{Reason: "finding " + finding.FindingID + " identifies no evidence"}
		}
	}

	coverage := in.Coverage
	coverage.ContractVersion = CoverageContract
	coverage.RequiredAnalyzers = nonNilSorted(coverage.RequiredAnalyzers)
	coverage.ObservedAnalyzers = nonNilSorted(coverage.ObservedAnalyzers)
	if coverage.Gaps == nil {
		coverage.Gaps = []Gap{}
	}

	manifest := Manifest{
		Analyzers:     analyzers,
		Context:       in.Context,
		Coverage:      coverage,
		Engine:        in.Engine,
		Findings:      findings,
		GeneratedAt:   in.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Sanitization:  Sanitization{Profile: SanitizationProfile, RedactionCount: in.RedactionCount},
		SchemaVersion: ManifestSchemaVersion,
	}
	manifest.ConfigurationHash = hashOf(in.ConfigurationInputs)
	// The artifact hash identifies the EVIDENCE, not the request: the same
	// scan re-submitted after a lost response hashes identically (a replay),
	// while different evidence under the same key is a conflict the backend
	// audits.
	manifest.ArtifactHash = hashOf(struct {
		Analyzers []Analyzer `json:"analyzers"`
		Coverage  Coverage   `json:"coverage"`
		Engine    Engine     `json:"engine"`
		Findings  []Finding  `json:"findings"`
	}{analyzers, coverage, in.Engine, findings})

	submission := Submission{
		APIVersion:           APIVersion,
		EvidenceSubmissionID: in.EvidenceSubmissionID,
		IdempotencyKey: fmt.Sprintf("github:%s:%s:%d:%s",
			in.Context.RepositoryID, in.Context.RunID, in.Context.RunAttempt, in.Context.HeadSHA),
		Manifest: manifest,
	}
	body, err := json.Marshal(submission)
	if err != nil {
		return zero, nil, fmt.Errorf("serialize managed evidence: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return zero, nil, ErrTooLarge{Limit: "request body", Actual: len(body), Max: MaxBodyBytes}
	}
	return submission, body, nil
}

// checkProvenance enforces the contract's three provenance rules locally, so
// a manifest that cannot be attributed never leaves the runner.
func checkProvenance(analyzers []Analyzer, findings []Finding, coverage Coverage) error {
	reported := make(map[string]int, len(analyzers))
	for _, analyzer := range analyzers {
		if _, dup := reported[analyzer.AnalyzerID]; dup {
			return ErrProvenance{Reason: "analyzer " + analyzer.AnalyzerID + " is reported twice"}
		}
		reported[analyzer.AnalyzerID] = analyzer.FindingCount
	}
	attributed := make(map[string]int, len(reported))
	for _, finding := range findings {
		if _, ok := reported[finding.AnalyzerID]; !ok {
			return ErrProvenance{Reason: "finding " + finding.FindingID + " names unreported analyzer " + finding.AnalyzerID}
		}
		attributed[finding.AnalyzerID]++
	}
	for id, declared := range reported {
		if declared != attributed[id] {
			return ErrProvenance{Reason: fmt.Sprintf("analyzer %s declares %d findings but %d name it", id, declared, attributed[id])}
		}
	}
	for _, observed := range coverage.ObservedAnalyzers {
		if _, ok := reported[observed]; !ok {
			return ErrProvenance{Reason: "observed analyzer " + observed + " was never reported"}
		}
	}
	return nil
}

func (c Context) validate() error {
	if c.SchemaVersion != ContextSchemaVersion {
		return ErrProvenance{Reason: "context schema is " + c.SchemaVersion + ", want " + ContextSchemaVersion}
	}
	missing := []string{}
	for name, value := range map[string]string{
		"scan_execution_id": c.ScanExecutionID, "tenant_id": c.TenantID, "asset_id": c.AssetID,
		"environment": c.Environment, "provider": c.Provider, "repository_id": c.RepositoryID,
		"repository_owner_id": c.RepositoryOwnerID, "repository": c.Repository, "head_sha": c.HeadSHA,
		"workflow_name": c.WorkflowName, "workflow_ref": c.WorkflowRef, "run_id": c.RunID,
		"event_name": c.EventName,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if c.RunAttempt < 1 {
		missing = append(missing, "run_attempt")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return ErrProvenance{Reason: "context is missing " + strings.Join(missing, ", ")}
	}
	return nil
}

// EvidenceHash identifies one evidence item by digest. The item itself — the
// snippet, the probe exchange, the matched value — never leaves the runner.
func EvidenceHash(item string) string {
	sum := sha256.Sum256([]byte(item))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashOf(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// Every value hashed here is a plain struct or map of strings.
		return EvidenceHash("unhashable")
	}
	return EvidenceHash(string(encoded))
}

func nonNilSorted(values []string) []string {
	out := append([]string(nil), values...)
	if out == nil {
		out = []string{}
	}
	sort.Strings(out)
	return out
}

// RelativeLocation normalizes an engine endpoint ("path" or "path:line") into
// a bounded, repository-relative location. It returns ok=false for anything
// absolute, parent-relative or home-prefixed: the semantic rules reject those
// outright, and a location is display context the manifest can simply omit.
func RelativeLocation(endpoint, workspace string) (Location, bool) {
	path := strings.TrimSpace(endpoint)
	if path == "" {
		return Location{}, false
	}
	var startLine *int
	if index := strings.LastIndex(path, ":"); index > 0 {
		if line, err := strconv.Atoi(path[index+1:]); err == nil && line > 0 {
			startLine = &line
			path = path[:index]
		}
	}
	if workspace != "" && strings.HasPrefix(path, workspace) {
		path = strings.TrimPrefix(strings.TrimPrefix(path, workspace), "/")
	}
	path = strings.TrimPrefix(path, "./")
	if path == "" || strings.HasPrefix(path, "/") || strings.HasPrefix(path, "\\") ||
		strings.HasPrefix(path, "Users/") || strings.HasPrefix(path, "home/") ||
		strings.Contains(path, "../") || strings.Contains(path, "\x00") {
		return Location{}, false
	}
	if len(path) > 1 && path[1] == ':' {
		return Location{}, false // a Windows drive-absolute path
	}
	return Location{Path: path, StartLine: startLine, EndLine: startLine}, true
}
