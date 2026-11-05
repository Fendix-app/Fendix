package engine

import (
	"log/slog"
	"sort"
	"strings"

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
//   - a group with a single member is returned verbatim;
//   - one exception to "cross-tier only": a Semgrep <base>-taint finding and
//     its <base>-sink twin on one line collapse even within one tier, because
//     they are one sink seen by two rules (see semgrepTwinSinks).
//
// Runs BEFORE Deduplicate, while each finding is still one (endpoint, title)
// pair — afterwards the endpoint sets have already been merged and the
// per-location identity needed here is gone.
//
// The representative's severity is kept, but not at the cost of the proof.
// Two engines that tie on trust (textscan and a Semgrep taint rule both rank
// 2) are ordered by severity and text, so the unproven textscan finding can
// represent a sink that the taint rule proved. When the representative carries
// no taint chain it adopts the chain, Reachable and ProvenPath of the member
// with the longest chain (see proofDonor), so a proven injection is never
// reported as an unproven pattern match.
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

	// A Semgrep taint rule and its -sink twin on one line are one sink even
	// when both are the same tier (gate closed). Drop each twin sink now, so
	// the tier logic below sees the group without it.
	twinSink := make(map[int]int) // dropped sink index -> the taint member that absorbs it
	for _, k := range order {
		for sink, taint := range semgrepTwinSinks(findings, groups[k]) {
			twinSink[sink] = taint
		}
	}
	if len(twinSink) > 0 {
		for _, k := range order {
			live := make([]int, 0, len(groups[k]))
			for _, i := range groups[k] {
				if _, dropped := twinSink[i]; !dropped {
					live = append(live, i)
				}
			}
			groups[k] = live
		}
	}

	// winner[i] is true when finding i survives its group.
	winner := make([]bool, len(findings))
	extraRefs := make(map[int][]string)
	// proofFrom[best] is the group member whose taint proof the winner adopts.
	proofFrom := make(map[int]int)
	collapsed := len(twinSink)
	for sink, taint := range twinSink {
		extraRefs[taint] = append(extraRefs[taint], findings[sink].References...)
	}
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
		if donor, ok := proofDonor(findings, idxs, best); ok {
			proofFrom[best] = donor
		}
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
		if d, ok := proofFrom[i]; ok {
			// Severity, tier and wording stay the representative's; only the
			// evidence that the sink was proven reachable is carried over.
			f.TaintChain = findings[d].TaintChain
			f.Reachable = f.Reachable || findings[d].Reachable
			f.ProvenPath = f.ProvenPath || findings[d].ProvenPath
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

// proofDonor picks the group member whose taint proof the representative
// adopts. It returns false when the representative already has a chain (it
// keeps its own) or when no other member carries any proof; nothing is
// synthesized. The longest chain wins, with findingLess (dedup's preferChain
// tie-break) deciding equal lengths, so the choice is a pure function of the
// member set (F-L6). A member that is Reachable or ProvenPath but sent no
// chain (a Semgrep taint match without a dataflow trace) is the fallback, so
// the flag survives even when there is no chain to copy.
func proofDonor(findings []models.Finding, idxs []int, rep int) (int, bool) {
	if len(findings[rep].TaintChain) > 0 {
		return 0, false
	}
	donor, found := 0, false
	better := func(i int, byChain bool) bool {
		if !found {
			return true
		}
		if byChain {
			if li, ld := len(findings[i].TaintChain), len(findings[donor].TaintChain); li != ld {
				return li > ld
			}
		}
		return findingLess(findings[i], findings[donor])
	}
	for _, i := range idxs {
		if i != rep && len(findings[i].TaintChain) > 0 && better(i, true) {
			donor, found = i, true
		}
	}
	if found {
		return donor, true
	}
	for _, i := range idxs {
		if i != rep && (findings[i].Reachable || findings[i].ProvenPath) && better(i, false) {
			donor, found = i, true
		}
	}
	return donor, found
}

const (
	twinTaintSuffix = "-taint"
	twinSinkSuffix  = "-sink"
)

// semgrepTwinSinks finds, within one (category, location) group, the Semgrep
// -sink findings whose -taint twin (same rule base: js-cmdi-taint and
// js-cmdi-sink) is also in the group. It returns each such sink index mapped
// to the taint member that represents the pair (ruling R-pf83).
//
// The pair is one sink seen by two rules: the taint rule proves a request
// source reaches it, the sink rule matches the same call by shape. Only an
// exact base match pairs, so js-cmdi-taint beside js-ssti-sink or
// js-ssti-taint stays two findings. The taint member is kept untouched, so its
// severity (never raised by the twin) and fingerprint are unchanged. With
// several taint members of one base, the findingLess minimum represents the
// pair, so the result does not depend on input order (F-L6).
func semgrepTwinSinks(findings []models.Finding, idxs []int) map[int]int {
	if len(idxs) < 2 {
		return nil
	}
	taintOf := map[string]int{} // base -> representative taint member
	for _, i := range idxs {
		f := findings[i]
		base, ok := strings.CutSuffix(f.RuleID, twinTaintSuffix)
		if !ok || base == "" || !f.SourceTier.IsSemgrep() {
			continue
		}
		if cur, seen := taintOf[base]; !seen || findingLess(f, findings[cur]) {
			taintOf[base] = i
		}
	}
	if len(taintOf) == 0 {
		return nil
	}
	var out map[int]int
	for _, i := range idxs {
		f := findings[i]
		base, ok := strings.CutSuffix(f.RuleID, twinSinkSuffix)
		if !ok || !f.SourceTier.IsSemgrep() {
			continue
		}
		if taint, paired := taintOf[base]; paired {
			if out == nil {
				out = map[int]int{}
			}
			out[i] = taint
		}
	}
	return out
}
