package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// ApplyBaselineDiff filters out findings that were already present in a previous scan.
// It compares by the stable fingerprint (not ID, since IDs are reassigned each run).
// Returns only new findings not present in the baseline. On any load error it
// logs and returns all findings (fail-open) — callers that need fail-closed
// semantics for a CORRUPT baseline should use ApplyBaselineDiffStrict.
func ApplyBaselineDiff(current []models.Finding, baselinePath string) []models.Finding {
	out, _ := ApplyBaselineDiffStrict(current, baselinePath)
	return out
}

// ApplyBaselineDiffStrict is ApplyBaselineDiff that distinguishes a MISSING
// baseline (legitimate first run — fail-open, returns all findings, nil error)
// from a CORRUPT/unparseable one (a real misconfiguration — returns the
// original findings and a non-nil error so the caller can fail closed, exit 2).
// This mirrors the fail-closed posture --ignore now has: a broken security
// control input must not silently disable the gate.
func ApplyBaselineDiffStrict(current []models.Finding, baselinePath string) ([]models.Finding, error) {
	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// First-run / not-yet-saved baseline: not an error, no diff.
			slog.Info("baseline file not found — scanning without a diff", "path", baselinePath)
			return current, nil
		}
		// Corrupt/unreadable baseline: surface it so the caller fails closed.
		slog.Error("failed to load baseline", "path", baselinePath, "error", err)
		return current, fmt.Errorf("loading baseline %s: %w", baselinePath, err)
	}

	baselineKeys := make(map[string]bool)
	for _, f := range baseline {
		baselineKeys[findingKey(f)] = true
	}

	var newFindings []models.Finding
	for _, f := range current {
		if !baselineKeys[findingKey(f)] {
			newFindings = append(newFindings, f)
		}
	}

	suppressed := len(current) - len(newFindings)
	if suppressed > 0 {
		slog.Info("baseline diff applied",
			"baseline_count", len(baseline),
			"current_count", len(current),
			"new_findings", len(newFindings),
			"suppressed", suppressed,
		)
	}

	return newFindings, nil
}

// SaveBaseline writes the current findings to a JSON file for use as a future baseline.
func SaveBaseline(findings []models.Finding, path string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing baseline to %s: %w", path, err)
	}

	slog.Info("baseline saved", "path", path, "findings", len(findings))
	return nil
}

// loadBaseline reads a baseline file. Supports both:
// - Raw Finding array: [{"id":...}, ...]
// - JSONReport format: {"findings": [{"id":...}, ...]}
func loadBaseline(path string) ([]models.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	// Try JSONReport format first
	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err == nil && report.Findings != nil {
		return report.Findings, nil
	}

	// Try raw Finding array
	var findings []models.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parsing baseline JSON: %w", err)
	}

	return findings, nil
}

// findingKey produces a stable key for baseline matching. It delegates to
// models.Fingerprint so baseline identity, the emitted finding.Fingerprint and
// `fingerprint:` ignore rules all share one definition of "the same finding
// across runs".
//
// Both sides RECOMPUTE the key from the finding's fields rather than reading
// the stored fingerprint, which is what let baselines saved before the
// fingerprint field existed keep matching.
//
// That recomputation does NOT carry the fendix/v2 change across the upgrade,
// and it is worth being precise about why. A baseline written by a pre-v2
// build has no rule_id, dependency, secret, sink or symbol — those fields did
// not exist — so recomputing v2 over it yields components the current scan's
// findings do not produce. Measured on a 30-finding fixture, a genuine
// pre-upgrade baseline matched 0 of 30. Baselines must be regenerated once,
// which the changelog says plainly; a regenerated baseline matches 30 of 30.
func findingKey(f models.Finding) string {
	return models.Fingerprint(f)
}
