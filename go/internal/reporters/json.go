package reporters

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// SchemaVersion is the version of the JSON report contract this build
// writes. RenderJSON stamps it into every report's metadata, so a consumer
// can read the shape it is holding off one field instead of inferring it
// from which optional keys happen to be present.
//
// Bump it only for a change a consumer must react to. Purely additive keys
// — the way `decisions`, `scanner_status` and `endpoints_discovered` all
// landed — do NOT bump it: a reader that ignores an unknown key still reads
// a v1 report correctly.
//
// 2 — the fingerprint algorithm changed from sha1(Category|Endpoint|Title) to
// the semantic fendix/v2 scheme. The report SHAPE is only additively extended
// (rule_id, dependency, secret, sink, symbol, all omitempty), but the meaning
// of an existing field changed: v1 and v2 fingerprints share no hash, so a
// saved baseline or a `.fendix-ignore` `fingerprint:` rule written under v1
// matches nothing and every finding reads as new. Matching nothing SILENTLY is
// precisely the failure this field exists to warn about, so it is the bump the
// rule above asks for.
const SchemaVersion = 2

// ScanMetadata contains metadata about the scan run for report output.
type ScanMetadata struct {
	// SchemaVersion is the report-contract version (see SchemaVersion).
	// RenderJSON overwrites whatever the caller set, so it always reflects
	// the build that wrote the bytes. Every report produced BEFORE this
	// field existed omits the key entirely and decodes to 0 — consumers
	// must read 0 as "pre-versioned", never as invalid, and
	// ParseJSONReport deliberately does not gate on it.
	SchemaVersion int `json:"schema_version"`
	// FingerprintAlgorithm names the identity scheme that produced this
	// report's fingerprints. RenderJSON overwrites whatever the caller set,
	// like SchemaVersion, so it always describes the build that wrote the
	// bytes.
	//
	// The version number says something changed; this says WHAT the
	// fingerprints are, so a consumer comparing two archived reports can tell
	// whether their identities are even comparable. SARIF carries the same
	// fact in its partialFingerprints key; JSON had nowhere to put it.
	FingerprintAlgorithm string    `json:"fingerprint_algorithm,omitempty"`
	Target               string    `json:"target"`
	StartedAt            time.Time `json:"started_at"`
	Duration             string    `json:"duration"`
	Version              string    `json:"version"`
	Mode                 string    `json:"mode"`
	EndpointsCount       int       `json:"endpoints_scanned"`
	// EndpointsDiscovered is the number of endpoints found BEFORE the
	// --max-endpoints cap truncated the list; EndpointsTruncated is true when
	// the cap actually dropped some. Without these, endpoints_scanned=500 is
	// indistinguishable from "found exactly 500" vs "found 801, capped to
	// 500" — a silent coverage gap a CI gate can't detect. When no cap fires,
	// EndpointsDiscovered == EndpointsCount and EndpointsTruncated is false.
	EndpointsDiscovered int      `json:"endpoints_discovered,omitempty"`
	EndpointsTruncated  bool     `json:"endpoints_truncated,omitempty"`
	ActiveProbes        bool     `json:"active_probes"`
	ChecksRun           []string `json:"checks_run,omitempty"`
	// ScannerStatus records the per-scanner outcome for the dep-CVE,
	// secrets, semgrep, and textscan passes (F-L7/F-L13/F-L14). It ends
	// the historical fail-open behaviour where a scanner crash was logged
	// at WARN and silently dropped: every failure is now recorded here,
	// surfaced in a scan-end summary line, and (with --fail-on-scanner-error)
	// can force a non-zero exit. SARIF derives invocations[].executionSuccessful
	// from it. Empty for pure black-box scans that run no code scanners.
	ScannerStatus []ScannerStatus `json:"scanner_status,omitempty"`
	// Imports is the per-tool accounting for SARIF-imported findings
	// (`fendix import` / `scan --import`): every result in the source
	// document is either imported, skipped as suppressed, or imported with
	// no usable location — the counts always reconcile. ADDITIVE: absent
	// (omitempty) for scans with no imports, so schema_version stays 1.
	Imports []ImportedTool `json:"imports,omitempty"`
	// Coverage is the engine's configured-completeness statement (coverage
	// contract v1). Nil on reports that predate the contract; a re-render
	// passes it through verbatim.
	Coverage *Coverage `json:"coverage,omitempty"`
	// PolicyVersion is the finding-decision policy version
	// (docs/DECISION_POLICY.md) this build applies.
	PolicyVersion string `json:"policy_version,omitempty"`
	// Backend passthrough. A live scan never sets these; the hosted backend
	// embeds them in the input it hands to `fendix report --input` so the
	// verdict it derived travels into SARIF/HTML/PDF. They are opaque here.
	ReleaseDecision       string          `json:"release_decision,omitempty"`
	CoverageState         string          `json:"coverage_state,omitempty"`
	DecisionPolicyVersion string          `json:"decision_policy_version,omitempty"`
	DecisionRationale     json.RawMessage `json:"decision_rationale,omitempty"`
}

// ImportedTool is one source tool's accounting block within
// ScanMetadata.Imports — one entry per normalized tool, folded across every
// run and every attached file that tool contributed.
type ImportedTool struct {
	Tool       string `json:"tool"`
	Version    string `json:"version,omitempty"`
	Results    int    `json:"results"`
	Suppressed int    `json:"suppressed,omitempty"`
	NoLocation int    `json:"no_location,omitempty"`
	// Corroborated: imported findings that strong cross-tool correlation
	// collapsed into a native representative. Lets a consumer explain why N
	// uploaded findings produced fewer than N rows, instead of leaving the
	// difference looking like data loss.
	Corroborated int `json:"corroborated,omitempty"`
}

// ScannerStatusState enumerates the terminal state of one scanner pass.
type ScannerStatusState string

const (
	// ScannerOK means the scanner ran to completion without error.
	ScannerOK ScannerStatusState = "ok"
	// ScannerSkipped means the scanner did not run because its
	// precondition was absent (no manifest, tool not installed) or it
	// cannot run in the current mode (e.g. govulncheck in --offline,
	// which needs vuln.go.dev). A skip is not a failure.
	ScannerSkipped ScannerStatusState = "skipped"
	// ScannerFailed means the scanner ran but errored (network blip,
	// malformed output, parse failure). Counts as a failure for
	// --fail-on-scanner-error and for SARIF executionSuccessful.
	ScannerFailed ScannerStatusState = "failed"
)

// ScannerStatus is the recorded outcome of a single analyzer pass. Name is
// the registry identity (see engine.Registry); Reason is the closed
// explanation for a non-ok state (coverage contract v1); Detail is a short
// human-readable excerpt; Attempts is present only when an in-process
// retry ran (>1) and State/Reason describe the final attempt.
type ScannerStatus struct {
	Name     string             `json:"name"`
	State    ScannerStatusState `json:"state"`
	Reason   ScannerReason      `json:"reason,omitempty"`
	Detail   string             `json:"detail,omitempty"`
	Attempts int                `json:"attempts,omitempty"`
}

// Failed reports whether this scanner ran and errored. Skips and OK
// states return false.
func (s ScannerStatus) Failed() bool { return s.State == ScannerFailed }

// SeverityCounts holds the count of findings per severity level.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// SourceCounts holds the count of findings per source type.
type SourceCounts struct {
	Blackbox   int `json:"blackbox"`
	Whitebox   int `json:"whitebox"`
	Correlated int `json:"correlated"`
}

// StatusCounts is the v0.24 decision summary: a wall of findings reduced to
// "what needs action". Confirmed counts HIGH-confidence findings (the v0.23
// score axis), kept deliberately distinct from sources.correlated (cross-engine
// agreement) so the two signals aren't conflated.
type StatusCounts struct {
	Total         int `json:"total"`         // == len(findings)
	Confirmed     int `json:"confirmed"`     // confidence_band == HIGH
	Blocking      int `json:"blocking"`      // status == BLOCK
	Warning       int `json:"warning"`       // status == WARN
	Informational int `json:"informational"` // status == INFO
}

// JSONReport is the top-level structure for JSON report output.
type JSONReport struct {
	Metadata  ScanMetadata     `json:"metadata"`
	Summary   SeverityCounts   `json:"summary"`
	Sources   SourceCounts     `json:"sources"`
	Total     int              `json:"total"`
	Decisions StatusCounts     `json:"decisions"` // v0.24 (additive)
	Findings  []models.Finding `json:"findings"`
}

// CountSeverities tallies findings by severity level.
func CountSeverities(findings []models.Finding) SeverityCounts {
	var counts SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			counts.Critical++
		case models.SeverityHigh:
			counts.High++
		case models.SeverityMedium:
			counts.Medium++
		case models.SeverityLow:
			counts.Low++
		case models.SeverityInfo:
			counts.Info++
		}
	}
	return counts
}

// CountSources tallies findings by source type.
func CountSources(findings []models.Finding) SourceCounts {
	var counts SourceCounts
	for _, f := range findings {
		switch f.Source {
		case models.SourceBlackbox:
			counts.Blackbox++
		case models.SourceWhitebox:
			counts.Whitebox++
		case models.SourceCorrelated:
			counts.Correlated++
		}
	}
	return counts
}

// CountStatuses tallies the v0.24 decision summary from the per-finding
// status + confidence band stamped by the orchestrator. When findings carry
// no decision fields (reporter called without the orchestrator pass), only
// Total is non-zero — additive and harmless.
func CountStatuses(findings []models.Finding) StatusCounts {
	counts := StatusCounts{Total: len(findings)}
	for _, f := range findings {
		switch f.Status {
		case "BLOCK":
			counts.Blocking++
		case "WARN":
			counts.Warning++
		case "INFO":
			counts.Informational++
		}
		if f.ConfidenceBand == string(models.ConfidenceHigh) {
			counts.Confirmed++
		}
	}
	return counts
}

// RenderJSON writes a full JSON report to the writer.
//
// The `findings` field is always serialised as a JSON array (`[]` when the
// input is nil or empty) — never `null` — so consumers can iterate without
// a null-check. This is part of the public schema (docs/schema.md).
func RenderJSON(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	if findings == nil {
		findings = []models.Finding{}
	}
	// Stamp the contract version over whatever the caller passed: this
	// build wrote these bytes, so this build's version is the honest
	// answer — including on the `fendix report --input old.json --format
	// json` re-render path, where meta was decoded from a report that
	// predates the field and carries 0.
	meta.SchemaVersion = SchemaVersion
	// Same reasoning: the report must describe the build that wrote it, not
	// whatever a re-render path decoded from an older file.
	meta.FingerprintAlgorithm = models.FingerprintAlgorithm
	report := JSONReport{
		Metadata:  meta,
		Summary:   CountSeverities(findings),
		Sources:   CountSources(findings),
		Total:     len(findings),
		Decisions: CountStatuses(findings),
		Findings:  findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON report: %w", err)
	}
	return nil
}
