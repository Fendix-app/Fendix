package managedci

import (
	"fmt"
	"sort"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// The contract names ABSTRACT analyzers; the engine names concrete ones. The
// backend's binding policy requires `sast` and `sca`, and neither it nor the
// customer should have to know that SCA is three different engine analyzers.
//
// Aggregation is pessimistic about FAILURE and honest about capability:
//
//   - any member that FAILED fails the family, because a family that broke
//     part-way cannot vouch for the target;
//   - otherwise a family that ran at all is `completed`. Which concrete
//     analyzers a runner has is engine-internal detail — the binding requires
//     the CAPABILITY, and a stock runner without semgrep installed still
//     performed static analysis;
//   - a family where nothing ran is `not_applicable` when its members had
//     nothing to look at, and `skipped` otherwise.
//
// The strict reading (any absent member skips the family) was tried first and
// is wrong: on a runner without semgrep it made `sast` permanently unobserved,
// so every managed scan would have been INCOMPLETE no matter how clean the
// code was. The engine's own report still records each analyzer's state for
// the customer; the manifest states what the CAPABILITY did.
const (
	AnalyzerSAST    = "sast"
	AnalyzerSCA     = "sca"
	AnalyzerSecrets = "secrets"
	AnalyzerDAST    = "dast"
)

// families maps each contract analyzer to the engine analyzers that back it,
// in registry order. Every registry entry appears exactly once across the
// families; analyzers_test.go proves it against engine.Registry, so a new
// engine analyzer cannot be silently absent from managed coverage.
var families = []struct {
	ID      string
	Members []string
}{
	{AnalyzerSAST, []string{"textscan", "semgrep", "python-engine", "python-engine/auth", "python-engine/injection", "plugins"}},
	{AnalyzerSCA, []string{"govulncheck", "pip", "npm", "python-engine/deps"}},
	{AnalyzerSecrets, []string{"secrets"}},
	{AnalyzerDAST, []string{"dast", "spec", "active-probes"}},
}

// Contract analyzer statuses.
const (
	statusCompleted     = "completed"
	statusFailed        = "failed"
	statusSkipped       = "skipped"
	statusNotApplicable = "not_applicable"
)

// AttributeFinding names the contract analyzer that produced a finding.
//
// Attribution is STRUCTURAL, not a guess from a title or a category string:
// a dependency finding carries a dependency reference, a secret finding
// carries a secret reference, and what remains is static or live analysis by
// its observation source. A finding that cannot be attributed is an error —
// the contract requires every finding to name a reported analyzer, and a
// wrong attribution would misstate which analyzer attested to it.
func AttributeFinding(finding models.Finding) (string, error) {
	switch {
	case finding.Dependency != nil || finding.Category == "deps":
		return AnalyzerSCA, nil
	case finding.Secret != nil || finding.Category == "secrets":
		return AnalyzerSecrets, nil
	}
	switch finding.Source {
	case models.SourceWhitebox, models.SourceCorrelated:
		return AnalyzerSAST, nil
	case models.SourceBlackbox:
		return AnalyzerDAST, nil
	default:
		return "", fmt.Errorf("managed evidence: finding %s (source %q) cannot be attributed to an analyzer",
			finding.ID, finding.Source)
	}
}

// Execution is the engine-side input for one analyzer family member.
type Execution struct {
	Status   reporters.ScannerStatus
	Duration time.Duration
}

// BuildAnalyzers projects the engine's per-analyzer status onto the contract's
// analyzer families, and reports which families actually observed the target.
//
// `observed` is the honest answer to "did this analyzer look?": only a family
// that completed is observed. The backend's required-analyzer invariant then
// needs both completed AND observed, so a family that skipped, failed or was
// not applicable can never satisfy a requirement.
func BuildAnalyzers(executions map[string]Execution, counts map[string]int, version string) ([]Analyzer, []string, []Gap) {
	analyzers := make([]Analyzer, 0, len(families))
	observed := []string{}
	gaps := []Gap{}
	for _, family := range families {
		members := memberStatuses(executions, family.Members)
		if len(members) == 0 {
			continue // the family did not run at all in this scan mode
		}
		status, reason := aggregate(members)
		var duration time.Duration
		attempts := 1
		for _, member := range members {
			duration += member.Duration
			if member.Status.Attempts > attempts {
				attempts = member.Status.Attempts
			}
		}
		analyzers = append(analyzers, Analyzer{
			AnalyzerID:      family.ID,
			AnalyzerVersion: version,
			Status:          status,
			ReasonCode:      reason,
			Attempts:        attempts,
			DurationMS:      int(duration.Milliseconds()),
			FindingCount:    counts[family.ID],
		})
		if status == statusCompleted {
			observed = append(observed, family.ID)
		}
		// A family that failed or was cut short is a coverage gap in its own
		// right; the backend decides what that means for the binding policy.
		if status == statusFailed || status == statusSkipped {
			gaps = append(gaps, Gap{AnalyzerID: family.ID, ReasonCode: reason})
		}
	}
	sort.Slice(analyzers, func(i, j int) bool { return analyzers[i].AnalyzerID < analyzers[j].AnalyzerID })
	sort.Strings(observed)
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].AnalyzerID < gaps[j].AnalyzerID })
	return analyzers, observed, gaps
}

func memberStatuses(executions map[string]Execution, members []string) []Execution {
	out := make([]Execution, 0, len(members))
	for _, name := range members {
		if execution, ok := executions[name]; ok {
			out = append(out, execution)
		}
	}
	return out
}

// aggregate folds the members of one family into a single contract status.
//
// Order matters: any failure wins, then anything that actually ran, then the
// reason nothing did.
func aggregate(members []Execution) (string, string) {
	var (
		failed        *reporters.ScannerStatus
		skipped       *reporters.ScannerStatus
		notApplicable *reporters.ScannerStatus
		completed     bool
	)
	for i := range members {
		status := members[i].Status
		switch {
		case status.State == reporters.ScannerFailed:
			if failed == nil {
				failed = &members[i].Status
			}
		case status.State == reporters.ScannerSkipped && status.Reason == reporters.ReasonNotApplicable:
			if notApplicable == nil {
				notApplicable = &members[i].Status
			}
		case status.State == reporters.ScannerSkipped:
			if skipped == nil {
				skipped = &members[i].Status
			}
		case status.State == reporters.ScannerOK:
			completed = true
		}
	}
	switch {
	case failed != nil:
		return statusFailed, reasonOf(*failed, "execution_error")
	case completed:
		return statusCompleted, "completed"
	case skipped != nil:
		return statusSkipped, reasonOf(*skipped, "unsupported_target")
	case notApplicable != nil:
		return statusNotApplicable, "not_applicable"
	default:
		return statusSkipped, "unsupported_target"
	}
}

func reasonOf(status reporters.ScannerStatus, fallback string) string {
	if status.Reason != "" {
		return string(status.Reason)
	}
	return fallback
}

// CountByAnalyzer attributes every finding, so the per-analyzer counts and
// the findings can never disagree — the contract's provenance rule holds by
// construction rather than by a later check.
func CountByAnalyzer(findings []models.Finding) (map[string]int, map[string]string, error) {
	counts := map[string]int{}
	attribution := make(map[string]string, len(findings))
	for _, finding := range findings {
		analyzer, err := AttributeFinding(finding)
		if err != nil {
			return nil, nil, err
		}
		counts[analyzer]++
		attribution[finding.ID] = analyzer
	}
	return counts, attribution, nil
}

// FamiliesOf maps engine analyzer names onto the contract analyzers that
// cover them, for the `required_analyzers` the manifest RECORDS. The backend
// requires what the binding policy says; this list is provenance about how
// the run was configured, never a claim about what must be required.
func FamiliesOf(engineNames []string) []string {
	owner := map[string]string{}
	for _, family := range families {
		for _, member := range family.Members {
			owner[member] = family.ID
		}
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, name := range engineNames {
		family, ok := owner[name]
		if !ok {
			continue
		}
		if _, dup := seen[family]; dup {
			continue
		}
		seen[family] = struct{}{}
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}
