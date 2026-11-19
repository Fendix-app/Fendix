// Package sarifimport ingests SARIF 2.1.0 reports produced by OTHER scanners
// (CodeQL, semgrep, trivy, …) and normalizes them into evidence.Evidence so
// the standard fendix finalization chain — fingerprinting, confidence
// scoring, dedup, baseline/ignore, confidence-gated --fail-on, reporters —
// treats them as first-class findings.
//
// The package owns its own MINIMAL SARIF struct set: only the fields the
// normalization rules read. It deliberately does not depend on a third-party
// SARIF model, and the reporters/sarif.go WRITER types stay untouched — they
// model fendix's own output, not arbitrary foreign input.
//
// Trust boundaries (see docs/superpowers/specs/2026-08-25-sarif-import-design.md):
//   - Source is always models.SourceImported and SourceTier is always empty,
//     so imports get the correlator's most-conservative treatment.
//   - Reachable / TaintChain / Route are NEVER set from SARIF codeFlows in
//     v1 — an imported finding must not masquerade as a native-proven path.
//   - Weakness (normalized CWE ids) and ToolID are extracted here, at the
//     normalization boundary, so the cross-tool correlator receives
//     structured metadata and never parses free-form strings.
package sarifimport

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// SupportedVersion is the only SARIF version this importer accepts. Every
// mainstream scanner emits 2.1.0 today; best-effort parsing of an older
// contract would silently corrupt severity mapping, so anything else is an
// explicit error rather than a guess.
const SupportedVersion = "2.1.0"

// Document is the minimal SARIF 2.1.0 shape the normalizer reads.
type Document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one tool's run within a SARIF document.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
	// OriginalURIBaseIDs lets absolute URIs be relativized safely: a result
	// whose artifactLocation carries a uriBaseId is already repo-relative,
	// and an absolute URI that starts with one of these bases can be
	// relativized without guessing.
	OriginalURIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds"`
	// Invocations carry the producer's own account of the run: whether it
	// succeeded and what it reported going wrong.
	Invocations []Invocation `json:"invocations"`
	// Artifacts lists the files the run says it analysed or reported on.
	Artifacts []Artifact `json:"artifacts"`
}

// Invocation is one execution of the tool within a run. ExecutionSuccessful is
// a pointer because a document that does not say is not a document that says
// true. ExitCode, ExitSignalName and ExitSignalNumber are the process's own end
// (SARIF 2.1.0 3.20.14 to 3.20.17); recordOf reads them as failure signals
// (R5-09).
type Invocation struct {
	ExecutionSuccessful            *bool          `json:"executionSuccessful"`
	ExitCode                       *int           `json:"exitCode"`
	ExitSignalName                 string         `json:"exitSignalName"`
	ExitSignalNumber               *int           `json:"exitSignalNumber"`
	ToolExecutionNotifications     []Notification `json:"toolExecutionNotifications"`
	ToolConfigurationNotifications []Notification `json:"toolConfigurationNotifications"`
}

// Notification is a tool-reported event; only its level is read.
type Notification struct {
	Level string `json:"level"`
}

// Artifact is a file the run lists. Roles say what the file was to the run
// (analysisTarget, resultFile, tool, driver, ...); an absent role list is a
// plain analysed file.
type Artifact struct {
	Location ArtifactLocation `json:"location"`
	Roles    []string         `json:"roles"`
}

// Tool wraps the driver that produced a run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver identifies the producing tool and carries its rule metadata.
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
	Rules           []Rule `json:"rules"`
}

// Rule is a reportingDescriptor: the static metadata behind results.
type Rule struct {
	ID                   string                  `json:"id"`
	ShortDescription     Message                 `json:"shortDescription"`
	FullDescription      Message                 `json:"fullDescription"`
	Help                 Message                 `json:"help"`
	HelpURI              string                  `json:"helpUri"`
	Properties           RuleProperties          `json:"properties"`
	Relationships        []Relationship          `json:"relationships"`
	DefaultConfiguration *ReportingConfiguration `json:"defaultConfiguration"`
}

// ReportingConfiguration carries the rule-level default severity level.
type ReportingConfiguration struct {
	Level string `json:"level"`
}

// RuleProperties is the property bag GitHub-convention metadata lives in.
type RuleProperties struct {
	Tags      []string `json:"tags"`
	Precision string   `json:"precision"`
	// SecuritySeverity is a 0–10 CVSS-like score. Tools disagree on whether
	// it is a JSON number or a string; FlexFloat accepts both.
	SecuritySeverity *FlexFloat `json:"security-severity"`
	// CWE is a non-standard-but-common property ("cwe": "CWE-89", or a
	// list). RawMessage so both shapes decode.
	CWE json.RawMessage `json:"cwe"`
}

// Relationship links a rule to a taxonomy entry (typically CWE).
type Relationship struct {
	Target ReportingDescriptorRef `json:"target"`
}

// ReportingDescriptorRef is a reference into a taxonomy.
type ReportingDescriptorRef struct {
	ID            string            `json:"id"`
	ToolComponent *ToolComponentRef `json:"toolComponent"`
}

// ToolComponentRef names the taxonomy a descriptor reference points into.
type ToolComponentRef struct {
	Name string `json:"name"`
}

// Result is one finding-shaped SARIF result.
type Result struct {
	RuleID              string                   `json:"ruleId"`
	RuleIndex           *int                     `json:"ruleIndex"`
	Level               string                   `json:"level"`
	Message             Message                  `json:"message"`
	Locations           []Location               `json:"locations"`
	Suppressions        []Suppression            `json:"suppressions"`
	PartialFingerprints map[string]string        `json:"partialFingerprints"`
	Taxa                []ReportingDescriptorRef `json:"taxa"`
}

// Location wraps the physical location of a result.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation is artifact + region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation is the file/URL a result points at.
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// Region is the line range (and optional snippet) within the artifact.
type Region struct {
	StartLine int              `json:"startLine"`
	EndLine   int              `json:"endLine"`
	Snippet   *ArtifactContent `json:"snippet"`
}

// ArtifactContent carries a code snippet.
type ArtifactContent struct {
	Text string `json:"text"`
}

// Suppression records that a result was suppressed at the source or by an
// external mechanism. Per the SARIF spec an absent status means "accepted".
type Suppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
}

// Message is a SARIF message object (text preferred over markdown).
type Message struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

// FlexFloat decodes a JSON number OR a numeric string — real-world SARIF
// emitters use both for security-severity.
type FlexFloat float64

// UnmarshalJSON implements the number-or-string decode.
func (f *FlexFloat) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if len(s) >= 2 && s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		s = strings.TrimSpace(str)
		if s == "" {
			return nil
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("security-severity is not numeric: %q", s)
	}
	*f = FlexFloat(v)
	return nil
}

// Parse decodes and validates a SARIF 2.1.0 document. Errors name the
// problem precisely: malformed JSON, a document that is not SARIF-shaped,
// and an unsupported SARIF version are all distinct messages, because each
// has a different fix for the operator.
func Parse(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing SARIF JSON: %w", err)
	}
	looksSARIF := strings.Contains(strings.ToLower(doc.Schema), "sarif") ||
		(doc.Runs != nil && doc.Version != "")
	if !looksSARIF {
		return nil, fmt.Errorf("input is valid JSON but does not look like a SARIF document (missing $schema/version/runs)")
	}
	if doc.Version != SupportedVersion {
		return nil, fmt.Errorf("unsupported SARIF version %q — fendix import supports %s only", doc.Version, SupportedVersion)
	}
	return &doc, nil
}
