package managedci

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// releaseVersion is the engine-version shape the contract accepts. Managed
// evidence may only come from a released build: "dev" and
// `git describe`-style fallbacks are refused, because the backend's
// accepted-build allowlist is keyed by (version, build digest) and a
// non-release version can never appear in it.
var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)

// ExportInput is one finished scan, as the orchestrator holds it at the
// moment decisions are stamped: findings and their decisions are index
// aligned, and each decision carries the provenance-restored Evidence the
// scorer read.
type ExportInput struct {
	Findings  []models.Finding
	Decisions []decision.Decision
	// Executions is the per-engine-analyzer outcome, keyed by registry name.
	Executions map[string]Execution
	Context    Context
	// RequiredAnalyzers is recorded only. The backend requires what the
	// binding policy says, never what the runner claims.
	RequiredAnalyzers    []string
	EvidenceSubmissionID string
	EngineVersion        string
	BuildDigest          string
	ReportSchemaVersion  int
	FindingPolicyVersion string
	Workspace            string
	FilesConsidered      *int
	ManifestsConsidered  *int
	GeneratedAt          time.Time
	Configuration        map[string]string
}

// Export builds the exact request body for POST /api/ci/v2/submissions.
//
// Everything it emits is an observation. Nothing it emits is a conclusion:
// the findings' Status, ConfidenceScore, ConfidenceBand, DecisionReason and
// the run's exit code are all left behind here, which is what makes the
// backend's decision the only decision.
func Export(in ExportInput) (Submission, []byte, error) {
	var zero Submission
	if len(in.Findings) != len(in.Decisions) {
		return zero, nil, fmt.Errorf("managed evidence: %d findings but %d decisions", len(in.Findings), len(in.Decisions))
	}
	if !releaseVersion.MatchString(in.EngineVersion) {
		return zero, nil, fmt.Errorf(
			"managed evidence requires a released engine build; this binary reports version %q", in.EngineVersion)
	}
	if !sha256Ref.MatchString(in.BuildDigest) {
		return zero, nil, fmt.Errorf("managed evidence requires the engine build digest")
	}
	counts, attribution, err := CountByAnalyzer(in.Findings)
	if err != nil {
		return zero, nil, err
	}
	analyzers, observed, gaps := BuildAnalyzers(in.Executions, counts, in.EngineVersion)

	findings := make([]Finding, 0, len(in.Findings))
	for i, source := range in.Findings {
		facts, err := FactsFrom(in.Decisions[i].Evidence)
		if err != nil {
			return zero, nil, fmt.Errorf("finding %s: %w", source.ID, err)
		}
		finding := Finding{
			AnalyzerID:     attribution[source.ID],
			Category:       source.Category,
			EvidenceFacts:  facts,
			EvidenceHashes: evidenceHashes(source),
			FindingID:      source.ID,
			Fingerprint:    source.Fingerprint,
			RuleID:         ruleID(source),
			Severity:       string(source.Severity),
			Locations:      locations(source, in.Workspace),
			Package:        packageOf(source),
		}
		findings = append(findings, finding)
	}

	return Build(Input{
		Context: in.Context,
		Engine: Engine{
			Version:              in.EngineVersion,
			BuildDigest:          in.BuildDigest,
			ReportSchemaVersion:  in.ReportSchemaVersion,
			FindingPolicyVersion: in.FindingPolicyVersion,
		},
		Analyzers: analyzers,
		Coverage: Coverage{
			RequiredAnalyzers:   in.RequiredAnalyzers,
			ObservedAnalyzers:   observed,
			Gaps:                gaps,
			FilesConsidered:     in.FilesConsidered,
			ManifestsConsidered: in.ManifestsConsidered,
		},
		Findings:             findings,
		GeneratedAt:          in.GeneratedAt,
		EvidenceSubmissionID: in.EvidenceSubmissionID,
		ConfigurationInputs:  in.Configuration,
	})
}

var sha256Ref = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SelfDigest hashes the running executable, which is exactly the artifact the
// release publishes and the installer verifies. A digest compiled in with
// ldflags could not describe the binary containing it, so the binary hashes
// itself instead.
func SelfDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate the running engine: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the running engine: %w", err)
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash the running engine: %w", err)
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

// ruleID falls back to the category when a scanner set no rule id: the field
// is required, and the category is the coarser identity of the same check.
func ruleID(finding models.Finding) string {
	if finding.RuleID != "" {
		return finding.RuleID
	}
	return finding.Category
}

// evidenceHashes identifies the evidence items a finding rests on WITHOUT
// carrying them: the snippet, the matched value and any probe exchange stay
// on the runner. A correlated finding also names its merged inputs.
func evidenceHashes(finding models.Finding) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(item string) {
		if item == "" || len(out) >= MaxEvidenceHashes {
			return
		}
		hash := EvidenceHash(item)
		if _, dup := seen[hash]; dup {
			return
		}
		seen[hash] = struct{}{}
		out = append(out, hash)
	}
	add(finding.Category + "\x00" + finding.Endpoint + "\x00" + finding.Title + "\x00" + finding.Evidence)
	for _, endpoint := range finding.AffectedEndpoints {
		add(finding.Category + "\x00" + endpoint + "\x00" + finding.Title)
	}
	sort.Strings(out)
	return out
}

func locations(finding models.Finding, workspace string) []Location {
	out := []Location{}
	if location, ok := RelativeLocation(finding.Endpoint, workspace); ok {
		out = append(out, location)
	}
	for _, endpoint := range finding.AffectedEndpoints {
		if len(out) >= MaxLocations {
			break
		}
		if location, ok := RelativeLocation(endpoint, workspace); ok {
			out = append(out, location)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func packageOf(finding models.Finding) *Package {
	if finding.Dependency == nil || finding.Dependency.Package == "" {
		return nil
	}
	ecosystem := finding.Dependency.Ecosystem
	if ecosystem == "" {
		ecosystem = "unknown"
	}
	version := finding.Dependency.Version
	if version == "" {
		version = "unknown"
	}
	return &Package{Ecosystem: ecosystem, Name: finding.Dependency.Package, Version: version}
}
