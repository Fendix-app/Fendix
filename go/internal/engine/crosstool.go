package engine

import (
	"log/slog"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ── Cross-tool correlation (SARIF import) ───────────────────────────────────
//
// Finding identity ≠ cross-tool correlation identity. The fendix/v2 semantic
// fingerprint answers "is this the same logical finding across scans?" and
// stays the key for baselines and .fendix-ignore. It is
// NOT the mechanism that decides whether two independent engines confirmed
// the same vulnerability — this file is.
//
// The product claim "both engines confirm" must mean genuinely independent
// corroborating evidence. So a pair of findings counts as STRONG
// corroboration only when ALL of these hold:
//
//	different effective tool (see toolIdentity — independence)
//	AND same normalized weakness (exact CWE equality, structured metadata only)
//	AND same normalized file/endpoint
//	AND same or very-near source location (|lineA−lineB| <= strongLineDistance,
//	    with overlapping regions preferred when BOTH sides carry a range)
//
// Title similarity, category equality, fingerprint collisions, same-file
// proximity alone, an imported tool's self-declared confidence, and the same
// external tool appearing in two SARIF runs NEVER count. Uncertainty fails
// conservatively: a finding with no recognized CWE or no precise location is
// simply excluded from strong corroboration. False non-correlation is
// preferable to false confirmation.
//
// Scope: only pairs where at least one side is IMPORTED are considered.
// Native↔native agreement is owned by the existing blackbox↔whitebox
// correlator and CollapseDuplicateLocations; stamping cross-tool
// corroboration between fendix's own engines would silently create a new
// escalation channel for every existing scan.
//
// Effect: strong corroboration stamps the INTERNAL flags
// Evidence.CrossToolCorroborated + CorroboratingTools (carried past dedup by
// ScoringProvenance's proof-union fold), which the decision layer counts as
// one corroborating signal and the confidence scorer rewards with a bonus.
// Severity is never escalated, SourceCorrelated is never minted, and
// Reachable/Route/TaintChain/SourceTier are never touched — the F1
// escalation gate cannot be reached through an import.
//
// BOUNDARY: this function is the ONLY producer of cross-tool corroboration.
// Correlation decides whether independent engines confirmed the issue; dedup
// decides which occurrence represents it. Dedup and the provenance index may
// only preserve or conservatively discard the records established here —
// they must never mint a CorroboratingTools entry, and "same-looking
// findings" is never grounds for corroboration downstream of this point.

// strongLineDistance is the deliberately conservative maximum line distance
// for strong location agreement when both findings carry a valid start line
// and no overlapping ranges. Two tools rarely blame the identical line for
// one defect (sink vs. source, statement vs. expression), but a real shared
// defect stays within a handful of lines.
const strongLineDistance = 5

// MatchLevel classifies how closely two findings agree. Only MatchStrong may
// ever feed the corroboration/escalation path; MatchMedium and MatchWeak
// exist so tests (and future UI grouping) can name the non-qualifying
// levels explicitly.
type MatchLevel int

const (
	// MatchNone — nothing meaningful in common.
	MatchNone MatchLevel = iota
	// MatchWeak — same category, similar titles, or same file only. MUST
	// NOT affect blocking confidence.
	MatchWeak
	// MatchMedium — same weakness in the same file/endpoint but outside the
	// strong location threshold. MUST NOT satisfy the escalation gate.
	MatchMedium
	// MatchStrong — independent tools, same normalized weakness, same
	// normalized location within the strong threshold. The only level that
	// counts as cross-engine confirmation.
	MatchStrong
)

// corrMeta is the pre-computed correlation view of one Evidence.
type corrMeta struct {
	tool     string
	weakness map[string]bool
	isURL    bool
	locPath  string // normalized file path or URL path ("" = unusable)
	line     int    // 0 = unknown
	lineEnd  int    // 0 = no range
	imported bool
}

// CorrelateCrossTool stamps strong cross-tool corroboration onto evs and
// collapses each imported finding that strongly matches a NATIVE finding
// into that native representative (references and tool provenance folded
// in), so the report shows one finding confirmed by two engines instead of
// duplicate rows. Imported↔imported strong pairs (different tools) are both
// kept and both stamped. Pure and deterministic; returns evs unchanged when
// no imported evidence is present.
//
// The second return counts, per normalized ToolID, how many imported findings
// were collapsed into a native representative. Keyed by tool rather than
// totalled because report metadata carries one accounting block per tool: a
// scalar could not be attributed when two tools each collapse findings.
func CorrelateCrossTool(evs []evidence.Evidence) ([]evidence.Evidence, map[string]int) {
	hasImported := false
	for i := range evs {
		if evs[i].Source == models.SourceImported {
			hasImported = true
			break
		}
	}
	if !hasImported {
		return evs, nil
	}

	// Normalization boundary: structured weakness + tool identity are
	// stamped BEFORE any matching, so the matcher below never reads
	// free-form references or guesses.
	evidence.StampWeakness(evs)
	stampToolIDs(evs)

	metas := make([]corrMeta, len(evs))
	for i := range evs {
		metas[i] = metaFor(evs[i])
	}

	// Pairwise strong matches — only pairs involving an import.
	corroboratedBy := make(map[int]map[string]bool) // ev index → tool set
	strongNative := make(map[int][]int)             // imported idx → native partner idxs
	for i := 0; i < len(evs); i++ {
		for j := i + 1; j < len(evs); j++ {
			if !metas[i].imported && !metas[j].imported {
				continue
			}
			if classify(metas[i], metas[j]) != MatchStrong {
				continue
			}
			addTool(corroboratedBy, i, metas[j].tool)
			addTool(corroboratedBy, j, metas[i].tool)
			switch {
			case metas[i].imported && !metas[j].imported:
				strongNative[i] = append(strongNative[i], j)
			case metas[j].imported && !metas[i].imported:
				strongNative[j] = append(strongNative[j], i)
			}
			slog.Debug("strong cross-tool corroboration",
				"a_tool", metas[i].tool, "a_endpoint", evs[i].Endpoint,
				"b_tool", metas[j].tool, "b_endpoint", evs[j].Endpoint,
				"weakness", strings.Join(sortedSet(intersect(metas[i].weakness, metas[j].weakness)), ","),
			)
		}
	}
	if len(corroboratedBy) == 0 {
		return evs, nil
	}

	// Stamp the flags on every strong participant.
	for i, tools := range corroboratedBy {
		evs[i].CrossToolCorroborated = true
		evs[i].CorroboratingTools = sortedSet(tools)
	}

	// Representative selection: an imported finding that strongly matched a
	// native finding collapses into it — the native stays the
	// representative (it is the trusted engine), and the imported side's
	// references/tool provenance survive on it. Corroboration evidence is
	// preserved via the stamps above, NOT by keeping duplicate rows.
	drop := make([]bool, len(evs))
	collapsedByTool := map[string]int{}
	for imp, natives := range strongNative {
		drop[imp] = true
		rep := natives[0] // pairs were generated in index order → deterministic
		evs[rep].References = mergeRefs(evs[rep].References, evs[imp].References)
		collapsedByTool[metas[imp].tool]++
	}

	out := make([]evidence.Evidence, 0, len(evs))
	dropped := 0
	for i := range evs {
		if drop[i] {
			dropped++
			continue
		}
		out = append(out, evs[i])
	}
	if dropped > 0 {
		slog.Info("collapsed imported findings into corroborated native representatives", "collapsed", dropped)
	}
	return out, collapsedByTool
}

// ClassifyCrossTool classifies one pair of Evidence. Exported for tests: the
// security invariant lives in this predicate, and tests assert it directly.
func ClassifyCrossTool(a, b evidence.Evidence) MatchLevel {
	evs := []evidence.Evidence{a, b}
	evidence.StampWeakness(evs)
	stampToolIDs(evs)
	return classify(metaFor(evs[0]), metaFor(evs[1]))
}

// classify implements the match-level table. Evaluation is strictly
// conservative: every uncertainty degrades the level, never upgrades it.
func classify(a, b corrMeta) MatchLevel {
	sameWeakness := len(intersect(a.weakness, b.weakness)) > 0
	sameLocation := a.locPath != "" && a.locPath == b.locPath && a.isURL == b.isURL

	if sameWeakness && sameLocation && independent(a, b) && locationClose(a, b) {
		return MatchStrong
	}
	if sameWeakness && sameLocation {
		return MatchMedium
	}
	if sameLocation {
		return MatchWeak
	}
	if sameWeakness {
		return MatchWeak
	}
	return MatchNone
}

// independent reports whether two findings come from different EFFECTIVE
// engines. Normalized tool identity is the test — never SARIF filename, and
// never run multiplicity: the same external tool in two runs/files gains
// nothing by duplication.
func independent(a, b corrMeta) bool {
	return a.tool != "" && b.tool != "" && a.tool != b.tool
}

// locationClose is the location-precision half of the strong predicate,
// evaluated only when the normalized paths already match.
//
//   - URL findings carry no lines; exact normalized-endpoint equality (already
//     established by the caller) is the whole location claim.
//   - File findings: when BOTH sides declare a region range, overlapping
//     ranges decide (an exact region agreement beats raw distance); otherwise
//     both must carry a valid start line within strongLineDistance. A missing
//     line on either side fails conservatively.
func locationClose(a, b corrMeta) bool {
	if a.isURL {
		return true
	}
	if a.line <= 0 || b.line <= 0 {
		return false
	}
	if a.lineEnd > 0 && b.lineEnd > 0 {
		return a.line <= b.lineEnd && b.line <= a.lineEnd
	}
	d := a.line - b.line
	if d < 0 {
		d = -d
	}
	return d <= strongLineDistance
}

// stampToolIDs fills Evidence.ToolID where empty. Imported evidence arrives
// with it set by sarifimport; native evidence is "fendix" — except the
// semgrep shim tier, which is "semgrep", so fendix's own semgrep pass and an
// imported semgrep SARIF are correctly NOT independent of each other.
func stampToolIDs(evs []evidence.Evidence) {
	for i := range evs {
		if evs[i].ToolID != "" {
			continue
		}
		if evs[i].SourceTier == models.TierSemgrepShim {
			evs[i].ToolID = "semgrep"
			continue
		}
		evs[i].ToolID = "fendix"
	}
}

// metaFor pre-computes the correlation view of one Evidence.
func metaFor(ev evidence.Evidence) corrMeta {
	m := corrMeta{
		tool:     ev.ToolID,
		weakness: map[string]bool{},
		lineEnd:  ev.LineEnd,
		imported: ev.Source == models.SourceImported,
	}
	for _, w := range ev.Weakness {
		m.weakness[w] = true
	}
	m.isURL = isURLEndpoint(ev.Endpoint)
	if m.isURL {
		m.locPath = normalizeEndpoint(ev.Endpoint)
	} else {
		m.locPath = normalizeFilePath(ev.Endpoint)
	}
	if ev.Line != nil {
		if n, err := strconv.Atoi(strings.TrimSpace(*ev.Line)); err == nil && n > 0 {
			m.line = n
		}
	}
	// Whitebox convention embeds the line in the endpoint ("src/a.py:14");
	// recover it when the Line field is absent.
	if m.line == 0 && !m.isURL {
		if _, l, ok := splitPathLine(ev.Endpoint); ok {
			m.line = l
		}
	}
	return m
}

// normalizeFilePath reduces a file-style endpoint ("src/App.py:14",
// ".\\src\\app.py") to a comparable path: line suffix stripped, backslashes
// normalized, "." segments cleaned, lowercased. Lossy ONLY for comparison —
// the rendered Endpoint is untouched.
func normalizeFilePath(endpoint string) string {
	p, _, ok := splitPathLine(endpoint)
	if !ok {
		p = endpoint
	}
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "./")
	if p == "." || p == "" {
		return ""
	}
	return strings.ToLower(p)
}

// splitPathLine splits a "path:line" endpoint. ok is false when the endpoint
// has no trailing numeric segment.
func splitPathLine(endpoint string) (string, int, bool) {
	i := strings.LastIndex(endpoint, ":")
	if i <= 0 || i == len(endpoint)-1 {
		return endpoint, 0, false
	}
	n, err := strconv.Atoi(endpoint[i+1:])
	if err != nil || n <= 0 {
		return endpoint, 0, false
	}
	return endpoint[:i], n, true
}

func addTool(m map[int]map[string]bool, idx int, tool string) {
	if m[idx] == nil {
		m[idx] = map[string]bool{}
	}
	m[idx][tool] = true
}

func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
