package reporters

import (
	"encoding/json"
	"fmt"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// BaselineFormatVersion is the baseline file format `fendix scan
// --save-baseline` writes.
//
// Version 2 records every finding together with its per-occurrence
// identities (models.Finding.Occurrences), so a later scan can tell exactly
// which occurrences were present when the baseline was taken. Earlier
// baselines — a bare JSON array of findings — recorded only grouped findings,
// whose single fingerprint names one occurrence of the group; see
// engine.ApplyBaselineDiffStrict for how those are still read safely.
const BaselineFormatVersion = 2

// BaselineDocument is the on-disk shape of a version 2 baseline.
type BaselineDocument struct {
	// BaselineVersion is the format version; always BaselineFormatVersion
	// when written by this build.
	BaselineVersion int `json:"baseline_version"`
	// FingerprintAlgorithm names the identity scheme the recorded
	// fingerprints were computed with (models.FingerprintAlgorithm).
	FingerprintAlgorithm string `json:"fingerprint_algorithm"`
	// Findings are the grouped findings, each listing its occurrences.
	Findings []models.Finding `json:"findings"`
}

// IsBaselineDocument reports whether data is a JSON object carrying a
// `baseline_version` key — a versioned baseline rather than a scan report or
// a legacy findings array.
func IsBaselineDocument(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	_, ok := probe["baseline_version"]
	return ok
}

// ParseBaselineDocument decodes a versioned baseline. A version newer than
// this build understands is an error: its identities may not mean what this
// build would take them to mean, and guessing could suppress findings.
func ParseBaselineDocument(data []byte) (*BaselineDocument, error) {
	var doc BaselineDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing baseline document: %w", err)
	}
	if doc.BaselineVersion < 2 || doc.BaselineVersion > BaselineFormatVersion {
		return nil, fmt.Errorf("unsupported baseline_version %d (this build reads 2..%d); regenerate it with `fendix scan --save-baseline`",
			doc.BaselineVersion, BaselineFormatVersion)
	}
	if doc.FingerprintAlgorithm != "" && doc.FingerprintAlgorithm != models.FingerprintAlgorithm {
		return nil, fmt.Errorf("baseline fingerprints use %q but this build computes %q; regenerate it with `fendix scan --save-baseline`",
			doc.FingerprintAlgorithm, models.FingerprintAlgorithm)
	}
	return &doc, nil
}
