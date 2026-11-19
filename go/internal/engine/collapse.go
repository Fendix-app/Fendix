package engine

import (
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
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
//   - only findings that describe the SAME construct fold (constructClasses):
//     two different constructs on one line, say eval(x) and require(y) in a
//     minified file, stay two findings, each with its own title, rule,
//     fingerprint and grade, and neither inherits the other's confidence or
//     proof (RC-9);
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
// The representative's severity is kept, but not at the cost of the proof or of
// a stronger confidence claim another non-Semgrep member made (strongestClaim).
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
	return collapseDuplicateLocations(findings, nil)
}

// collapseDuplicateLocations is CollapseDuplicateLocations that also reports
// each fold: onFold(representative, member) is called once for every member the
// collapse folds into a representative, in a deterministic order. The
// orchestrator uses it to carry what only the producer knows about a PROVIDER
// member onto the representative's provenance (ProvenanceIndex.FoldMember), so
// that a generic rule's judgement of its own value never lowers a provider
// token that was read at the same place (CL2-2, R3-SEC-B1).
func collapseDuplicateLocations(findings []models.Finding, onFold func(rep, member models.Finding)) []models.Finding {
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

	// Within one location, only findings that describe the same construct may
	// fold. Everything below runs per construct class, so a representative, a
	// confidence or a proof can only come from a member of the same construct.
	classes := make([][]int, 0, len(order))
	for _, k := range order {
		for _, class := range constructClasses(findings, groups[k]) {
			classes = append(classes, splitByCredentialTarget(findings, class)...)
		}
	}

	// winner[i] is true when finding i survives its group.
	winner := make([]bool, len(findings))
	extraRefs := make(map[int][]string)
	// proofFrom[best] is the group member whose taint proof the winner adopts.
	proofFrom := make(map[int]int)
	// confidenceFrom[best] is the stronger confidence the winner adopts.
	confidenceFrom := make(map[int]models.Confidence)
	collapsed := len(twinSink)
	for sink, taint := range twinSink {
		extraRefs[taint] = append(extraRefs[taint], mergedRefs(findings[sink])...)
	}
	for _, idxs := range classes {
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
		if c := strongestClaim(findings, idxs, best); c != "" {
			confidenceFrom[best] = c
		}
		for _, i := range idxs {
			if i == best {
				continue
			}
			collapsed++
			extraRefs[best] = append(extraRefs[best], mergedRefs(findings[i])...)
			if onFold != nil {
				onFold(findings[best], findings[i])
			}
		}
	}

	// A group we declined to collapse has no winner; keep every member.
	for _, idxs := range classes {
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
		if c, ok := confidenceFrom[i]; ok {
			f.Confidence = c
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

// strongestClaim returns the confidence the representative should carry when a
// member of its group that the collapse drops made a stronger claim, or "" when
// it keeps its own. Two engines that read one construct can disagree on how
// literal the match is: the Python engine's eval() rule asserts HIGH (a literal
// match, which earns the deterministic-detection delta and so can block), while
// textscan's grades the same call MEDIUM. The higher-trust textscan finding
// represents the location, and keeping only its confidence turned a blocking
// finding into a warning once a second analyzer saw the same call (round 5,
// security5-05).
//
// Only members whose tier can earn that delta themselves donate, and only to a
// representative that can: a Semgrep tier is excluded on both sides, as it is
// from confidence.HasDeterministicDetection, so the adoption can never hand a
// Semgrep claim to a native finding, and can never make a blocking finding out
// of one that no analyzer asserted HIGH for. The representative's severity and
// wording are untouched.
func strongestClaim(findings []models.Finding, idxs []int, rep int) models.Confidence {
	if findings[rep].SourceTier.IsSemgrep() {
		return ""
	}
	best := findings[rep].Confidence
	for _, i := range idxs {
		if i == rep || findings[i].SourceTier.IsSemgrep() {
			continue
		}
		if confidenceRank(findings[i].Confidence) > confidenceRank(best) {
			best = findings[i].Confidence
		}
	}
	if best == findings[rep].Confidence {
		return ""
	}
	return best
}

// mergedRefs is what a finding the collapse drops leaves on its representative:
// its references, and the id of its rule as "rule:<id>". The representative
// reports the same code, so a consumer that follows an issue by its rule can
// still see that a rule it knows is reported at this location, under another
// rule's finding (verification pass 1: integration5-01).
func mergedRefs(f models.Finding) []string {
	refs := append([]string(nil), f.References...)
	if f.RuleID != "" {
		refs = append(refs, "rule:"+f.RuleID)
	}
	return refs
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

// ── Construct identity (RC-9) ───────────────────────────────────────────────
//
// Two findings on one source line describe the SAME construct when they are two
// analyzers' reading of one piece of code: textscan's eval rule and the Python
// engine's eval heuristic, the native secrets scanner and Semgrep on one
// password assignment. They describe DIFFERENT constructs when they are two
// things the line does: `eval(x); require(y)` is an eval and a require.
//
// No analyzer exports a column or a span, so the identity is a reviewed one:
//
//  1. a rule in constructFamilies belongs to the named family, whatever CWE it
//     cites. This is where CWE alone is wrong: the native scanner cites CWE-259
//     for a password where Semgrep cites CWE-798 (one credential), and
//     textscan's eval and require rules both cite CWE-95 (two constructs);
//  2. any other rule is identified by the CWE ids it references;
//  3. a finding is also identified by its exact title: the same words for the
//     same claim at the same location are one claim;
//  4. a finding identified by none of these is not identified. It is never
//     folded into another finding: kept twice is a duplicate, folded wrongly is
//     a lost finding.
//
// Members of one line are in one construct class when their identities share a
// token, transitively (union-find), so the classes are a function of the member
// SET and not of its order (F-L6).

// constructFamilies are the reviewed families: rule id, or "prefix*" for a rule
// id prefix, to the family it belongs to. Keep it to rules where the CWE alone
// would be wrong.
var constructFamilies = map[string]string{
	// eval and exec of a non-literal.
	"JS_EVAL_LITERAL":       "eval",
	"SEC-JS_EVAL":           "eval",
	"python.ast/JS_EVAL":    "eval",
	"python.ast/PY_EVAL":    "eval",
	"python-eval-injection": "eval",
	// A dynamic require is a different construct from eval, although both cite
	// CWE-95.
	"JS_REQUIRE_INTERPOLATION": "dynamic-require",
	// A hardcoded credential, whoever found it and whichever CWE they cite.
	"secrets/*":                          "hardcoded-credential",
	"GO_HARDCODED_AWS_KEY":               "hardcoded-credential",
	"JS_HARDCODED_AWS_KEY":               "hardcoded-credential",
	"python-hardcoded-secret-assignment": "hardcoded-credential",
	"python-hardcoded-db-url":            "hardcoded-credential",
	"python-gcp-service-account-inline":  "hardcoded-credential",
	"python-aws-access-key-id-literal":   "hardcoded-credential",
	"python-slack-webhook-url-literal":   "hardcoded-credential",
	"python-pem-private-key-literal":     "hardcoded-credential",
	// A fast hash used for a password: CWE-327, -328 or -916 by analyzer.
	"python.ast/PY_WEAK_CRYPTO_PASSWORD": "weak-password-hash",
	"python-md5-used-for-password":       "weak-password-hash",
	"python-sha1-used-for-password":      "weak-password-hash",
	"GO_WEAK_HASH_PASSWORD":              "weak-password-hash",
	"JAVA_WEAK_HASH_PASSWORD":            "weak-password-hash",
	"go-weak-password-hash-*":            "weak-password-hash",
	"js-weak-password-hash-*":            "weak-password-hash",
	"java-weak_password_hash-*":          "weak-password-hash",
	// Server-side template injection: CWE-94 or -1336 by analyzer.
	"python.ast/PY_SSTI":                     "ssti",
	"flask-render-template-string-injection": "ssti",
	"go-ssti-*":                              "ssti",
	"js-ssti-*":                              "ssti",
	"java-ssti-*":                            "ssti",
}

// constructFamily returns the reviewed family of a rule id, or "".
func constructFamily(ruleID string) string {
	if ruleID == "" {
		return ""
	}
	if fam, ok := constructFamilies[ruleID]; ok {
		return fam
	}
	for pat, fam := range constructFamilies {
		if prefix, ok := strings.CutSuffix(pat, "*"); ok && strings.HasPrefix(ruleID, prefix) {
			return fam
		}
	}
	return ""
}

var constructCWE = regexp.MustCompile(`^CWE-([0-9]+)\b`)

// constructTokens are the identity tokens of one finding: its reviewed family,
// else the CWE ids it references; and, for every finding, its exact title. Two
// findings that word their claim identically at one location are one claim, so a
// finding with no family and no CWE still folds into the finding that says the
// same thing, and never into one that says something else.
func constructTokens(f models.Finding) []string {
	var out []string
	if fam := constructFamily(f.RuleID); fam != "" {
		out = append(out, "family:"+fam)
	} else {
		seen := map[string]bool{}
		for _, r := range f.References {
			if m := constructCWE.FindStringSubmatch(r); m != nil && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, "cwe:"+m[1])
			}
		}
	}
	if f.Title != "" {
		out = append(out, "title:"+f.Title)
	}
	return out
}

// constructClasses partitions the findings idxs (one location) into construct
// classes: two findings are in one class when they share an identity token,
// directly or through a third. A finding with no token is a class of its own.
// idxs is in input order; the classes come back ordered by their first member.
func constructClasses(findings []models.Finding, idxs []int) [][]int {
	if len(idxs) < 2 {
		if len(idxs) == 1 {
			return [][]int{idxs}
		}
		return nil
	}
	parent := make([]int, len(idxs))
	for p := range parent {
		parent[p] = p
	}
	var find func(int) int
	find = func(p int) int {
		for parent[p] != p {
			parent[p] = parent[parent[p]]
			p = parent[p]
		}
		return p
	}
	owner := map[string]int{}
	for p, i := range idxs {
		for _, tok := range constructTokens(findings[i]) {
			if q, ok := owner[tok]; ok {
				if a, b := find(p), find(q); a != b {
					if a < b {
						parent[b] = a
					} else {
						parent[a] = b
					}
				}
			} else {
				owner[tok] = p
			}
		}
	}
	byRoot := map[int][]int{}
	var roots []int
	for p, i := range idxs {
		r := find(p)
		if _, seen := byRoot[r]; !seen {
			roots = append(roots, r)
		}
		byRoot[r] = append(byRoot[r], i)
	}
	out := make([][]int, 0, len(roots))
	for _, r := range roots {
		out = append(out, byRoot[r])
	}
	return out
}

// isNativeSecret reports whether a finding is the native secrets scanner's.
func isNativeSecret(f models.Finding) bool { return strings.HasPrefix(f.RuleID, "secrets/") }

// splitByCredentialTarget splits a construct class of native secrets findings by
// the name each credential is bound to (CL3, F-B1; RC-9 (1a)).
//
// The family says that two secrets rules reading one line read "a hardcoded
// credential", but a line can hold two credentials: `password = "<real>"; tok =
// "<sample token>"`, or `{"password": "<real>", "tok": "<sample token>"}`. They are
// two constructs, and folding them let the sample's status stand for the real
// value, which then had no finding of its own. The scanner records the name each
// credential is bound to (SecretRef.Identifier: the assignment to the left of the
// literal the value sits in), so findings bound to different names are kept apart,
// each folding only with its own Semgrep twin or same-target findings.
//
//   - A class with one target (or none) is returned unchanged: one credential read
//     by several rules, and its Semgrep twin, is still one construct.
//   - A class with several targets is split by target, in order of first member.
//   - A finding that is not the native scanner's (a Semgrep finding names no
//     target) cannot be placed in any of them, so it is kept as a finding of its
//     own: kept twice is a duplicate, folded wrongly is a lost finding.
func splitByCredentialTarget(findings []models.Finding, class []int) [][]int {
	targets := map[string]int{}
	var order []string
	for _, i := range class {
		if !isNativeSecret(findings[i]) {
			continue
		}
		id := ""
		if findings[i].Secret != nil {
			id = findings[i].Secret.Identifier
		}
		if _, ok := targets[id]; !ok {
			targets[id] = len(order)
			order = append(order, id)
		}
	}
	if len(order) < 2 {
		return [][]int{class}
	}
	parts := make([][]int, len(order))
	var out [][]int
	for _, i := range class {
		if !isNativeSecret(findings[i]) {
			out = append(out, []int{i})
			continue
		}
		id := ""
		if findings[i].Secret != nil {
			id = findings[i].Secret.Identifier
		}
		parts[targets[id]] = append(parts[targets[id]], i)
	}
	return append(parts, out...)
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
	if findingLess(a, b) || findingLess(b, a) {
		return findingLess(a, b)
	}
	// Identical in everything findingLess reads: a generic secrets rule and a
	// provider rule reading one literal produce the same redacted snippet, fix
	// and line. Without a last tie-break the winner was whichever arrived first,
	// so the representative (its rule, title, fingerprint and the group it joins)
	// depended on input order, against F-L6. The scanner's own rule order breaks
	// the tie, which is the order production always delivered them in, then the
	// rule id and title for anything else.
	if oa, ob := secrets.RuleOrder(a.RuleID), secrets.RuleOrder(b.RuleID); oa != ob {
		return oa < ob
	}
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return a.Title < b.Title
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
