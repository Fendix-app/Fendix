package engine

import (
	"log/slog"
	"sort"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CollapseDuplicateLocations merges static findings that describe the SAME
// issue at the SAME source location but were produced by different analyzers.
//
// Why this exists. Fendix runs several static engines over one tree — the
// native secrets scanner, textscan, the shelled-out semgrep pack, and the
// Python AST taint analyzer. When two of them recognise the same construct
// they each emit a finding, and because Deduplicate groups on
// (Title, Category, Severity), differing titles keep them apart forever. The
// user sees one vulnerability reported N times.
//
// Measured on fastapi 0.110.0, a single `SECRET_KEY = "..."` line produced
// THREE findings — "Hardcoded API key or token" (native), "Hardcoded secret
// found in assignment to 'SECRET_KEY'" (semgrep, CRITICAL) and "Hardcoded
// secret value in config-style assignment" (native) — at different severities.
// On the accuracy corpus the same double-report cascaded into a phantom false
// positive and held the synthetic F1 at 0.987, below its 0.990 CI floor.
//
// The rule: within one (Category, Endpoint), keep the finding from the
// most-trusted analyzer tier. Severity is NOT raised to the group maximum —
// that would let the lowest-trust engine (semgrep) escalate a finding through
// the back door, which is exactly what the SourceTier gate in mergeFindings
// exists to prevent. References are unioned so no CWE mapping is lost.
//
// Scope is deliberately narrow:
//   - blackbox findings are untouched (one endpoint legitimately carries many
//     distinct HTTP observations);
//   - correlated findings are untouched (they already represent a merge, and
//     collapsing them could drop the half that carries the taint chain);
//   - a group with a single member is returned verbatim.
//
// Runs BEFORE Deduplicate, while each finding is still one (endpoint, title)
// pair — afterwards the endpoint sets have already been merged and the
// per-location identity needed here is gone.
//
// Determinism: the representative is chosen by a total order (trust rank, then
// severity, then findingLess), so the result is a pure function of the input
// SET, not its order (F-L6). Output keeps first-occurrence order.
func CollapseDuplicateLocations(findings []models.Finding) []models.Finding {
	if len(findings) <= 1 {
		return findings
	}

	type key struct{ category, endpoint string }
	groups := make(map[key][]int, len(findings))
	order := make([]key, 0, len(findings))

	// Findings that are not eligible pass straight through, keeping position.
	eligible := make([]bool, len(findings))
	for i, f := range findings {
		if f.Source != models.SourceWhitebox || f.Endpoint == "" {
			continue
		}
		eligible[i] = true
		k := key{f.Category, f.Endpoint}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}

	// winner[i] is true when finding i survives its group.
	winner := make([]bool, len(findings))
	extraRefs := make(map[int][]string)
	collapsed := 0
	for _, k := range order {
		idxs := groups[k]
		// CROSS-TIER ONLY. Two findings from the SAME analyzer at one location
		// are two different rules that the rule author meant to fire
		// separately — a Dockerfile legitimately gets both "no USER directive"
		// and "pins to :latest" from textscan, and collapsing those loses a
		// real, separately-actionable issue (caught by the output-format
		// snapshot regression). Only when DIFFERENT engines describe the same
		// location is it the same construct seen twice in different words.
		if !hasDistinctTiers(findings, idxs) {
			continue
		}
		best := idxs[0]
		for _, i := range idxs[1:] {
			if duplicateLess(findings[i], findings[best]) {
				best = i
			}
		}
		winner[best] = true
		for _, i := range idxs {
			if i == best {
				continue
			}
			collapsed++
			extraRefs[best] = append(extraRefs[best], findings[i].References...)
		}
	}

	// A group we declined to collapse has no winner; keep every member.
	for _, k := range order {
		idxs := groups[k]
		if !hasDistinctTiers(findings, idxs) {
			for _, i := range idxs {
				winner[i] = true
			}
		}
	}

	out := make([]models.Finding, 0, len(findings))
	for i, f := range findings {
		if eligible[i] && !winner[i] {
			continue
		}
		if refs := extraRefs[i]; len(refs) > 0 {
			f.References = mergeRefs(f.References, refs)
			sort.Strings(f.References)
		}
		out = append(out, f)
	}

	if collapsed > 0 {
		slog.Debug("collapsed duplicate static findings at shared locations",
			"collapsed", collapsed, "remaining", len(out))
	}
	return out
}

// hasDistinctTiers reports whether a location group contains findings from
// more than one analyzer tier — the signal that two engines described one
// construct rather than one engine reporting two separate issues.
func hasDistinctTiers(findings []models.Finding, idxs []int) bool {
	if len(idxs) < 2 {
		return false
	}
	first := findings[idxs[0]].SourceTier
	for _, i := range idxs[1:] {
		if findings[i].SourceTier != first {
			return true
		}
	}
	return false
}

// duplicateLess reports whether a should represent its location group instead
// of b. Total order: higher analyzer trust first, then higher severity, then
// the same deterministic tiebreak dedup uses — so the winner never depends on
// which analyzer happened to emit first.
func duplicateLess(a, b models.Finding) bool {
	if ta, tb := a.SourceTier.TrustRank(), b.SourceTier.TrustRank(); ta != tb {
		return ta > tb
	}
	if sa, sb := models.SeverityRank(a.Severity), models.SeverityRank(b.Severity); sa != sb {
		return sa > sb
	}
	return findingLess(a, b)
}
