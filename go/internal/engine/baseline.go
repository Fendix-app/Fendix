package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

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
//
// # Occurrence semantics
//
// The orchestrator passes ungrouped OCCURRENCES, and each is kept or dropped
// on its own: an occurrence is "known" only when the baseline proves that
// this occurrence was present when the baseline was taken. Grouping never
// carries knowledge from one occurrence to another, so a new occurrence that
// would be presented in the same finding as a baselined one is still new.
//
// What counts as proof depends on what the baseline recorded:
//
//   - A finding that lists `occurrences` (every baseline written by this
//     build, and every JSON report from it) proves exactly those occurrence
//     fingerprints.
//   - In a versioned (v2) baseline, a finding without `occurrences` proves
//     its own fingerprint.
//   - A LEGACY entry (a bare-array baseline or older report, no
//     `occurrences`) may be a whole group whose single fingerprint names only
//     its primary occurrence. It proves that fingerprint, plus — for each
//     location it recorded (`endpoint` and `affected_endpoints`) — that a
//     finding of the same category and the same title or rule existed at that
//     exact location. A current occurrence at any other location is new. The
//     group's fingerprint is never extended to occurrences it did not name.
func ApplyBaselineDiffStrict(current []models.Finding, baselinePath string) ([]models.Finding, error) {
	baseline, versioned, err := loadBaseline(baselinePath)
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

	idx := indexBaseline(baseline, versioned)
	if idx.legacyEntries > 0 {
		slog.Warn("baseline predates per-occurrence identities: its grouped entries match only their recorded fingerprint and exact recorded locations — regenerate it with --save-baseline",
			"path", baselinePath, "legacy_entries", idx.legacyEntries)
	}

	var newFindings []models.Finding
	for _, f := range current {
		if !idx.known(f) {
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
			"unit", "occurrence",
		)
	}

	return newFindings, nil
}

// baselineIndex is what a baseline proves about which occurrences existed.
type baselineIndex struct {
	// fingerprints are occurrence identities the baseline proves present.
	fingerprints map[string]bool
	// locations are exact (category, endpoint, title-or-rule) locations a
	// LEGACY grouped entry recorded. Populated only from legacy entries.
	locations map[baselineLocation]bool
	// legacyEntries counts entries read under legacy semantics.
	legacyEntries int
}

type baselineLocation struct {
	category string
	endpoint string
	// kind is "title" or "rule"; value is the title or rule ID.
	kind, value string
}

func indexBaseline(entries []models.Finding, versioned bool) baselineIndex {
	idx := baselineIndex{fingerprints: map[string]bool{}, locations: map[baselineLocation]bool{}}
	for _, e := range entries {
		if len(e.Occurrences) > 0 {
			for _, o := range e.Occurrences {
				idx.addFingerprint(o.Fingerprint)
			}
			continue
		}
		if versioned {
			fp := e.Fingerprint
			if fp == "" {
				fp = findingKey(e)
			}
			idx.addFingerprint(fp)
			continue
		}
		idx.legacyEntries++
		idx.addFingerprint(findingKey(e))
		eps := append([]string{e.Endpoint}, e.AffectedEndpoints...)
		for _, ep := range eps {
			ep = baselineEndpoint(ep)
			if ep == "" {
				continue
			}
			if e.Title != "" {
				idx.locations[baselineLocation{e.Category, ep, "title", e.Title}] = true
			}
			if e.RuleID != "" {
				idx.locations[baselineLocation{e.Category, ep, "rule", e.RuleID}] = true
			}
		}
	}
	return idx
}

func (idx baselineIndex) addFingerprint(fp string) {
	if fp = strings.ToLower(strings.TrimSpace(fp)); fp != "" {
		idx.fingerprints[fp] = true
	}
}

// known reports whether the baseline proves occurrence f was present.
func (idx baselineIndex) known(f models.Finding) bool {
	fp := f.Fingerprint
	if fp == "" {
		fp = findingKey(f)
	}
	if idx.fingerprints[strings.ToLower(fp)] {
		return true
	}
	if len(idx.locations) == 0 {
		return false
	}
	ep := baselineEndpoint(f.Endpoint)
	if ep == "" {
		return false
	}
	if f.Title != "" && idx.locations[baselineLocation{f.Category, ep, "title", f.Title}] {
		return true
	}
	return f.RuleID != "" && idx.locations[baselineLocation{f.Category, ep, "rule", f.RuleID}]
}

// baselineEndpoint normalizes a recorded location for exact comparison:
// separators and surrounding space only — the line number stays, because a
// legacy location is proof only for the exact place it names.
func baselineEndpoint(ep string) string {
	return strings.TrimSpace(strings.ReplaceAll(ep, `\`, "/"))
}

// SaveBaseline writes the current findings to a JSON file for use as a
// future baseline, in baseline format v2 (reporters.BaselineDocument): the
// grouped findings, each listing the occurrence identities it contains. The
// file stays a valid input to `fendix verify --baseline`.
func SaveBaseline(findings []models.Finding, path string) error {
	if findings == nil {
		findings = []models.Finding{}
	}
	doc := reporters.BaselineDocument{
		BaselineVersion:      reporters.BaselineFormatVersion,
		FingerprintAlgorithm: models.FingerprintAlgorithm,
		Findings:             findings,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing baseline to %s: %w", path, err)
	}

	slog.Info("baseline saved", "path", path, "findings", len(findings), "format_version", reporters.BaselineFormatVersion)
	return nil
}

// loadBaseline reads a baseline file. Supports:
//   - A versioned baseline document (format v2): {"baseline_version": 2, ...}
//   - A JSONReport: {"findings": [...]}
//   - A legacy raw Finding array: [{"id":...}, ...]
//
// versioned is true only for the first. A JSONReport's findings are
// self-describing: those that list occurrences are read exactly, those that
// do not are read as legacy entries.
func loadBaseline(path string) (findings []models.Finding, versioned bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	if reporters.IsBaselineDocument(data) {
		doc, err := reporters.ParseBaselineDocument(data)
		if err != nil {
			return nil, false, err
		}
		return doc.Findings, true, nil
	}

	// Try JSONReport format first
	var report reporters.JSONReport
	if err := json.Unmarshal(data, &report); err == nil && report.Findings != nil {
		return report.Findings, false, nil
	}

	// Try raw Finding array
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, false, fmt.Errorf("parsing baseline JSON: %w", err)
	}

	return findings, false, nil
}

// findingKey produces a stable key for baseline matching. It delegates to
// models.Fingerprint so baseline identity, the emitted finding.Fingerprint and
// `fingerprint:` ignore rules all share one definition of "the same finding
// across runs".
//
// Legacy entries RECOMPUTE the key from the finding's fields rather than
// reading the stored fingerprint, which is what let baselines saved before the
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
