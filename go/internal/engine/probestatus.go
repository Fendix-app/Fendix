package engine

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// The active-probes scanner-status detail (contract C5.3). Segments are joined
// by "; " and composed by scope.Compose, so a listing is never cut half-way and
// the loss segment always comes first; when the budget runs out the detail ends
// with "and N more (see report metadata)", and the complete account is in
// metadata.coverage.active_probes.
//
//	lost evaluation: <U+F> probe(s) not evaluated (U unknown-origin, F scanner-failed)
//	probe evaluation: A attempted, E evaluated, I inconclusive (target), U unknown-origin, F scanner-failed
//	inconclusive probes (target did not answer): timeout 3, connection_reset 1
//	gated probes (target answered 401/403/404/410 so not evaluated): 403 2, 404 1
//	unknown-origin probes (not evaluated): dns_failure 2
//	scanner-failed probes (not evaluated): not_sent 1
//
// A segment lists only non-zero reasons, in the fixed vocabulary order. The
// counts segment is byte-for-byte the one every reader parses: a gated probe is
// counted inside "inconclusive (target)" (A = E + I + U + F still holds), and
// the gated segment, which no older reader knows and none needs, says how many
// of those I were gated and by which status. The "inconclusive probes" segment
// lists only the probes the target did not answer, so its wording stays true.
//
// The entry is FAILED (reason no_endpoints, a target-owned reason: the probe
// pass found no endpoint it could evaluate) when probes were attempted and not
// one was evaluated, whoever's doing that was. That is the backend's rule
// (probe_coverage.detail_reports_lost_evaluation: unknown-origin or
// scanner-failed probes, or attempted > 0 with none evaluated) applied where the
// CLI, the Action and --require-analyzers read it.

func probeReasonList(cov models.ActiveProbeCoverage, origin scanner.ProbeOrigin, order []scanner.ProbeReason) string {
	counts := cov.Reasons[string(origin)]
	var parts []string
	for _, r := range order {
		if n := counts[string(r)]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r, n))
		}
	}
	return strings.Join(parts, ", ")
}

// gatedList is "403 2, 404 1": the gated probes by HTTP status, in status order.
func gatedList(cov models.ActiveProbeCoverage) string {
	var parts []string
	for _, code := range models.GatedStatuses {
		k := strconv.Itoa(code)
		if n := cov.Gated.ByStatus[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", k, n))
		}
	}
	return strings.Join(parts, ", ")
}

func probeCountsSegment(cov models.ActiveProbeCoverage) string {
	return fmt.Sprintf("probe evaluation: %d attempted, %d evaluated, %d inconclusive (target), %d unknown-origin, %d scanner-failed",
		cov.Attempted, cov.Evaluated, cov.Inconclusive, cov.UnknownOrigin, cov.ScannerFailed)
}

// probeDetailSegs are the composable segments after the first (loss or counts).
func probeSegs(cov models.ActiveProbeCoverage, lead string) []scope.Seg {
	fixed := func(s string) scope.Seg { return func(int) string { return s } }
	segs := []scope.Seg{}
	if lead != "" {
		segs = append(segs, fixed(lead))
	}
	segs = append(segs, fixed(probeCountsSegment(cov)))
	if cov.Inconclusive-cov.Gated.Total > 0 {
		segs = append(segs, fixed("inconclusive probes (target did not answer): "+probeReasonList(cov, scanner.OriginTarget, scanner.TargetReasonOrder)))
	}
	if cov.Gated.Total > 0 {
		segs = append(segs, fixed("gated probes (target answered 401/403/404/410 so not evaluated): "+gatedList(cov)))
	}
	if cov.UnknownOrigin > 0 {
		segs = append(segs, fixed("unknown-origin probes (not evaluated): "+probeReasonList(cov, scanner.OriginUnknown, scanner.UnknownReasonOrder)))
	}
	if cov.ScannerFailed > 0 {
		segs = append(segs, fixed("scanner-failed probes (not evaluated): "+probeReasonList(cov, scanner.OriginScanner, scanner.ScannerReasonOrder)))
	}
	return segs
}

// probeLossSegment is the failed entry's first segment.
func probeLossSegment(cov models.ActiveProbeCoverage) string {
	return fmt.Sprintf("lost evaluation: %d probe(s) not evaluated (%d unknown-origin, %d scanner-failed)",
		cov.UnknownOrigin+cov.ScannerFailed, cov.UnknownOrigin, cov.ScannerFailed)
}

// probeDetail composes the active-probes detail. lead, when set, is the
// pass-level cause (deadline, request budget) that precedes everything.
func probeDetail(cov models.ActiveProbeCoverage, failed bool, lead string) string {
	if failed && lead == "" {
		lead = probeLossSegment(cov)
	}
	return scope.Compose(detailMax, probeSegs(cov, lead)...)
}

// probeNoneEvaluatedSegment is the failed entry's first segment when probes were
// attempted and not one was evaluated and nothing is scanner-side or unknown
// (those carry the "lost evaluation" segment instead).
func probeNoneEvaluatedSegment(cov models.ActiveProbeCoverage) string {
	return fmt.Sprintf("no probe was evaluated: the target gave none of the %d probes an evaluable answer", cov.Attempted)
}

// cutShortOf describes the limit that ended the probe pass, or nil when none did.
// The deadline outranks the request budget, as in recordBlackbox.
func cutShortOf(cfg *models.ScanConfig, phase checkPhaseOutcome) *models.ProbeCutShort {
	switch {
	case phase.Deadline:
		return &models.ProbeCutShort{Cause: "max_duration", Limit: "--max-duration", Configured: cfg.MaxDuration.String(), Refused: phase.Rejected}
	case phase.Rejected > 0:
		return &models.ProbeCutShort{Cause: "max_requests", Limit: "--max-requests", Configured: strconv.FormatInt(cfg.MaxRequests, 10), Refused: phase.Rejected}
	}
	return nil
}
