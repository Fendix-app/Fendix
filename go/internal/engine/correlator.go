package engine

import (
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// correlationKey identifies a finding by its normalized endpoint and category
// for cross-referencing blackbox and whitebox results.
type correlationKey struct {
	endpoint string
	category string
}

// categoryMap maps whitebox categories to their blackbox counterparts
// for cross-correlation matching.
var categoryMap = map[string]string{
	"secrets":   "data_exposure",
	"injection": "injection",
	"auth":      "auth_bypass",
}

// methodPrefixRe strips a leading HTTP method token from an endpoint string.
// Whitebox emitters such as the spec parser format endpoints as "GET /pet/findByStatus";
// without stripping, the leading "GET " corrupts URL parsing and fuzzy-segment matching.
var methodPrefixRe = regexp.MustCompile(`(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+`)

// Correlate cross-references blackbox and whitebox findings.
//
// Rules:
//   - If both engines agree on a vulnerability (same normalized endpoint + related category):
//     merge into a single correlated finding with source=correlated, confidence=HIGH,
//     and severity escalated by one level.
//   - If whitebox finds an issue at a URL endpoint but blackbox does NOT confirm:
//     keep whitebox finding, confidence=MEDIUM, add "Unconfirmed by live scan" note.
//     The note is only added when the whitebox endpoint normalises to a URL
//     path (`/...`) — file:line findings such as a hardcoded secret in
//     `src/config.py:14` cannot be confirmed by a live HTTP scan, so the
//     suffix is misleading there and is skipped (TASK-092).
//   - If blackbox finds an issue but no whitebox counterpart:
//     keep as-is.
//
// Match strategy (per whitebox finding, in order):
//  1. Exact normalized endpoint + related category (fast path via index).
//  2. Path-suffix match: one normalized path is a suffix of the other on a `/`
//     boundary. Handles base-path skew (whitebox `/pet/findByStatus`
//     matches blackbox `/api/v3/pet/findByStatus`).
//  3. Fuzzy segment match: at least one non-noise path segment of length > 2 is
//     shared. Handles file-path-vs-URL-path matches like `routes/users.py` vs
//     `/api/v1/users`.
//
// Each blackbox finding can correlate with at most one whitebox finding.
//
// Correlate is a thin wrapper over correlateWithMarks so the exported signature
// and the rendered output stay exactly as they were; the Evidence pipeline uses
// the marked form.
func Correlate(findings []models.Finding) []models.Finding {
	out, _ := correlateWithMarks(findings)
	return out
}

// correlateWithMarks is Correlate plus a parallel []bool recording, for each
// returned finding, whether THIS function is what appended the
// "[Unconfirmed by live scan]" suffix to its evidence text.
//
// The prose suffix is part of the published `evidence` string (docs/schema.md)
// and cannot be removed, but prose is not something the decision layer can
// safely gate on. The parallel slice is the machine-readable counterpart:
// engine.CorrelateEvidence stamps it onto Evidence.UnconfirmedByLiveScan, and
// decision.decide reads it to hold such a finding at WARN. This function is the
// SINGLE producer of that marker — if a third suffix site is ever added, it must
// append `true` here too, or the marker and the prose drift apart silently.
//
// The returned slice is always the same length as the returned findings, in the
// same order, so callers can index them together.
func correlateWithMarks(findings []models.Finding) ([]models.Finding, []bool) {
	var blackbox, whitebox, imported []models.Finding
	for _, f := range findings {
		switch f.Source {
		case models.SourceBlackbox:
			blackbox = append(blackbox, f)
		case models.SourceWhitebox:
			whitebox = append(whitebox, f)
		case models.SourceImported:
			// SECURITY FENCE: imported findings must never enter this
			// correlator. Routed into the blackbox bucket (the old default
			// arm) they could fuzzy-match a whitebox finding and mint a
			// Source=correlated, confidence-HIGH, severity-escalated result
			// — external evidence masquerading as fendix's own cross-engine
			// confirmation. The ONLY way an import strengthens another
			// finding is the strong-corroboration path in
			// CorrelateCrossTool. Pass through untouched.
			imported = append(imported, f)
		default:
			// Already correlated or unknown source — pass through
			blackbox = append(blackbox, f)
		}
	}

	slog.Debug("correlator inputs",
		"blackbox_count", len(blackbox),
		"whitebox_count", len(whitebox),
	)

	if len(whitebox) == 0 || len(blackbox) == 0 {
		// Nothing to correlate — return all findings as-is.
		// When some live scan ran (blackbox findings exist) but didn't match
		// a given whitebox finding, downgrade that finding's confidence and
		// suffix its evidence. The suffix is only meaningful for whitebox
		// findings tied to a URL endpoint; file-path findings (e.g. a
		// hardcoded secret at src/config.py:14) cannot be confirmed by a
		// live scan, so they keep their original evidence and confidence.
		//
		// NOTE: the len(blackbox)==0 branch below is not reachable from
		// orchestrator.Run — it only correlates when hasWhitebox && hasBlackbox
		// — so it is a test-only path. It is marked anyway: the marker must
		// track the suffix at EVERY site that writes it, or the two drift.
		unconfirmed := make([]bool, 0, len(blackbox)+len(whitebox))
		wbUnconfirmed := make([]bool, len(whitebox))
		if len(blackbox) == 0 && len(whitebox) > 0 {
			for i := range whitebox {
				if isURLEndpoint(whitebox[i].Endpoint) {
					whitebox[i].Confidence = models.ConfidenceMedium
					whitebox[i].Evidence += " [Unconfirmed by live scan]"
					wbUnconfirmed[i] = true
				}
			}
		}
		result := make([]models.Finding, 0, len(blackbox)+len(whitebox)+len(imported))
		result = append(result, blackbox...)
		unconfirmed = append(unconfirmed, make([]bool, len(blackbox))...)
		result = append(result, whitebox...)
		unconfirmed = append(unconfirmed, wbUnconfirmed...)
		result = append(result, imported...)
		unconfirmed = append(unconfirmed, make([]bool, len(imported))...)
		return result, unconfirmed
	}

	// Pre-compute normalized blackbox endpoints once. The suffix and fuzzy
	// passes walk all blackbox findings per whitebox finding, and re-running
	// url.Parse on every iteration is the dominant allocator for large scans.
	//
	// Also pre-compute the per-blackbox segment set used by the fuzzy
	// matcher. The fuzzy pass calls pathSegments on BOTH sides of every
	// (W,B) comparison; caching the blackbox side here means the segment
	// split runs B times instead of W·B times. The matching whitebox
	// segment is cached once per whitebox iteration inside the Correlate
	// loop below (see `wbSegments` capture).
	bbNorm := make([]string, len(blackbox))
	bbSegments := make([][]string, len(blackbox))
	bbIndex := make(map[correlationKey][]int)
	for i, f := range blackbox {
		bbNorm[i] = normalizeEndpoint(f.Endpoint)
		bbSegments[i] = pathSegments(bbNorm[i])
		bbIndex[correlationKey{endpoint: bbNorm[i], category: f.Category}] = append(
			bbIndex[correlationKey{endpoint: bbNorm[i], category: f.Category}], i,
		)
	}

	// Track which blackbox findings are already merged so we don't merge the
	// same one twice with different whitebox findings.
	bbCorrelated := make(map[int]bool)

	var result []models.Finding
	var unconfirmed []bool

	for _, wf := range whitebox {
		wbNorm := normalizeEndpoint(wf.Endpoint)
		relCats := relatedCategories(wf.Category)
		// Cache the whitebox segments once per iteration of the outer
		// loop; the fuzzy pass would otherwise re-split this string
		// on every (W,B) comparison.
		wbSegments := pathSegments(wbNorm)

		bbIdx, matchKind, routeConfirmed := findCorrelationMatch(wf, wbNorm, wbSegments, relCats, blackbox, bbNorm, bbSegments, bbIndex, bbCorrelated)
		if bbIdx >= 0 {
			bf := blackbox[bbIdx]
			bbCorrelated[bbIdx] = true
			merged := mergeFindings(bf, wf, routeConfirmed)
			result = append(result, merged)
			unconfirmed = append(unconfirmed, false)
			slog.Info("correlated finding",
				"wb_endpoint", wf.Endpoint,
				"bb_endpoint", bf.Endpoint,
				"wb_category", wf.Category,
				"bb_category", bf.Category,
				"match_kind", matchKind,
				"route_confirmed", routeConfirmed,
				"proven_path", merged.ProvenPath,
			)
			continue
		}

		slog.Debug("correlator no blackbox match",
			"wb_title", wf.Title,
			"wb_endpoint_norm", wbNorm,
			"wb_category", wf.Category,
		)

		// Unconfirmed whitebox finding. Suffix only when the endpoint is a
		// URL — file:line findings can't be confirmed by a live scan.
		marked := isURLEndpoint(wf.Endpoint)
		if marked {
			wf.Confidence = models.ConfidenceMedium
			wf.Evidence += " [Unconfirmed by live scan]"
		}
		result = append(result, wf)
		unconfirmed = append(unconfirmed, marked)
	}

	// Add uncorrelated blackbox findings as-is
	for i, bf := range blackbox {
		if !bbCorrelated[i] {
			result = append(result, bf)
			unconfirmed = append(unconfirmed, false)
		}
	}

	// Imported findings pass through verbatim — never merged, never marked.
	result = append(result, imported...)
	unconfirmed = append(unconfirmed, make([]bool, len(imported))...)

	return result, unconfirmed
}

// findCorrelationMatch returns the index of a blackbox finding that matches
// the whitebox finding `wf` (identified by `wbNorm` + `relCats`), the match
// kind ("route", "exact", "suffix", or "fuzzy"), and whether the match was
// route-pattern-confirmed. Returns (-1, "", false) if no match.
//
// `bbNorm` and `bbSegments` are the pre-computed normalized endpoint and
// segment-set for each blackbox finding (avoids re-running url.Parse and
// pathSegments per inner-loop iteration). `wbSegments` is the same for
// the current whitebox finding. The `taken` set excludes blackbox
// findings already merged into another correlated finding so each
// blackbox is consumed at most once.
//
// Match priority (Proven Path v1): route-pattern match runs FIRST so a
// confirmed route→endpoint binding outranks a fuzzy URL match. The existing
// three strategies are unchanged and run, in order, only when no route match
// fires (or `wf.Route` is nil/empty).
func findCorrelationMatch(
	wf models.Finding,
	wbNorm string,
	wbSegments []string,
	relCats []string,
	blackbox []models.Finding,
	bbNorm []string,
	bbSegments [][]string,
	bbIndex map[correlationKey][]int,
	taken map[int]bool,
) (int, string, bool) {
	// 0. Route-pattern match (highest priority, Proven Path v1). Degrades
	// gracefully: a nil Route or empty Pattern simply skips this block and
	// falls through to the existing endpoint-only strategies.
	if wf.Route != nil && wf.Route.Pattern != "" {
		normalizedPattern := normalizeRoutePattern(wf.Route.Pattern)
		for i, bf := range blackbox {
			if taken[i] {
				continue
			}
			if !categoryRelated(relCats, bf.Category) {
				continue
			}
			if !pathSegmentsMatch(normalizedPattern, bbNorm[i]) {
				continue
			}
			// Method gate: only block the match when BOTH sides declare a
			// method and they disagree. An unknown method on either side
			// ("" route method, or a blackbox endpoint with no "<METHOD> "
			// prefix) does not block — we can't prove a mismatch.
			bbMethod := blackboxMethod(bf.Endpoint)
			if wf.Route.Method != "" && bbMethod != "" &&
				!strings.EqualFold(wf.Route.Method, bbMethod) {
				continue
			}
			return i, "route", true
		}
	}

	// 1. Exact match via index (fast path).
	for _, cat := range relCats {
		key := correlationKey{endpoint: wbNorm, category: cat}
		for _, idx := range bbIndex[key] {
			if !taken[idx] {
				return idx, "exact", false
			}
		}
	}

	// 2. Path-suffix match (handles base-path skew).
	for i, bf := range blackbox {
		if taken[i] {
			continue
		}
		if !categoryRelated(relCats, bf.Category) {
			continue
		}
		if pathSuffixMatch(wbNorm, bbNorm[i]) {
			return i, "suffix", false
		}
	}

	// 3. Fuzzy segment match (handles file-path-vs-URL-path).
	// Uses pre-computed segments for both sides — the F2 fix to avoid
	// O(W·B) recomputation of pathSegments inside the inner loop.
	for i, bf := range blackbox {
		if taken[i] {
			continue
		}
		if !categoryRelated(relCats, bf.Category) {
			continue
		}
		if segmentsRelated(wbSegments, bbSegments[i]) {
			return i, "fuzzy", false
		}
	}

	return -1, "", false
}

// categoryRelated reports whether `bbCat` is in the related-categories list.
func categoryRelated(relCats []string, bbCat string) bool {
	for _, c := range relCats {
		if c == bbCat {
			return true
		}
	}
	return false
}

// mergeFindings creates a correlated finding from matching blackbox and whitebox findings.
// Severity is escalated by one level, confidence is HIGH, source is correlated.
//
// TASK-114: when the whitebox half carries a TaintChain (the AST analyzer
// proved an intra-function source→sink dataflow), the merged finding inherits
// the chain plus Reachable=true and gets a *second* severity escalation. This
// is the "DAST + SAST agree AND we can show the path" case — exactly the
// confirmed-finding-only-when-both-agree wedge promised in the README hero.
func mergeFindings(bb, wb models.Finding, routeConfirmed bool) models.Finding {
	severity := escalateSeverity(higherSeverity(bb.Severity, wb.Severity))
	// Proven Path v1 / tier-provenance enforcement: the second "reachable"
	// escalation is the strong claim ("we can show the exploit path"), so it
	// is only granted to the high-trust tree-sitter taint tier. A
	// semgrep_shim finding that never cleared the F1≥0.95 gate must not ride
	// correlation up to CRITICAL — that would silently bypass the gate the
	// roadmap explicitly protects. Empty tier (legacy/native) keeps the
	// prior behaviour so this change can't regress existing escalations.
	if wb.Reachable && wb.SourceTier != models.TierSemgrepShim {
		severity = escalateSeverity(severity)
	}

	// Proven Path signal: the blackbox endpoint was bound to this finding's
	// route pattern AND the whitebox half proved the sink is reachable from a
	// request-input source. That combination — "DAST hit + SAST taint path +
	// the exact route that reaches it" — is the strongest claim the engine
	// makes, so force it to CRITICAL regardless of base severity and flag it.
	// Tier gate still applies: a semgrep_shim finding that hasn't cleared the
	// F1 gate must not ride a route match up to a Proven Path CRITICAL.
	provenPath := routeConfirmed && wb.Reachable && wb.SourceTier != models.TierSemgrepShim
	if provenPath {
		severity = models.SeverityCritical
	}

	merged := models.Finding{
		Title:          bb.Title,
		Severity:       severity,
		Source:         models.SourceCorrelated,
		SourceTier:     wb.SourceTier,
		Category:       bb.Category,
		Endpoint:       bb.Endpoint,
		Evidence:       bb.Evidence + " | Code: " + wb.Evidence,
		Fix:            bb.Fix,
		References:     mergeRefs(bb.References, wb.References),
		Confidence:     models.ConfidenceHigh,
		Line:           wb.Line,
		TaintChain:     wb.TaintChain,
		Reachable:      wb.Reachable,
		Route:          wb.Route,
		RouteConfirmed: routeConfirmed,
		ProvenPath:     provenPath,
	}
	return merged
}

// routeParamRe matches a single path-parameter placeholder in any of the four
// framework styles the route extractor emits, so a route pattern can be
// reduced to a parameter-agnostic shape for comparison against a concrete
// blackbox URL:
//
//	Django   /users/<int:pk>/      → /users/{}/
//	Flask    /users/<id>           → /users/{}/   (also covered by the <...> arm)
//	FastAPI  /items/{item_id}      → /items/{}
//	Express  /users/:id            → /users/{}
//
// The three arms are mutually exclusive per segment, so a single pass with an
// alternation is safe. `<...>` covers both Django (`<int:pk>`) and Flask
// (`<id>`) because both wrap the param in angle brackets; `{...}` covers
// FastAPI; `:name` covers Express. We intentionally do not try to validate the
// inner name — any placeholder collapses to the same `{}` token.
var routeParamRe = regexp.MustCompile(`<[^/>]*>|\{[^/}]*\}|:[^/]+`)

// doubleSlashRe collapses runs of `/` so `//users//{}` compares equal to
// `/users/{}`. Declared at package scope to avoid recompiling per call.
var doubleSlashRe = regexp.MustCompile(`/{2,}`)

// normalizeRoutePattern reduces a framework route pattern to a
// parameter-agnostic, trailing-slash-free, lowercase shape so it can be
// segment-compared against a normalized blackbox endpoint. Path parameters in
// Django (`<int:pk>` / `<id>`), FastAPI (`{item_id}`), Express (`:id`), and
// Flask (`<id>`) all collapse to the literal token `{}`.
//
// Examples:
//
//	"/users/<int:pk>/"  → "/users/{}"
//	"/items/{item_id}"  → "/items/{}"
//	"/users/:id"        → "/users/{}"
//	"users/<id>"        → "/users/{}"   (a leading slash is added for parity
//	                                      with normalizeEndpoint output)
func normalizeRoutePattern(pattern string) string {
	if pattern == "" {
		return ""
	}
	p := routeParamRe.ReplaceAllString(pattern, "{}")
	p = doubleSlashRe.ReplaceAllString(p, "/")
	p = strings.ToLower(p)
	// Mirror normalizeEndpoint: ensure a leading slash so segment comparison
	// lines up (the route extractor emits Django patterns without one, e.g.
	// "users/<int:id>").
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Strip trailing slash(es) for comparison; keep "/" for the root.
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	return p
}

// pathSegmentsMatch reports whether a normalized route pattern matches a
// normalized concrete endpoint segment-by-segment, treating the `{}`
// placeholder as a wildcard that matches exactly one path segment. Both inputs
// must already be normalized (normalizeRoutePattern / normalizeEndpoint).
//
// The match is exact on segment count and on every literal segment; a `{}`
// segment in the pattern matches any single non-empty endpoint segment. This
// is deliberately stricter than the fuzzy segment matcher — a route-confirmed
// match is the strongest correlation signal, so a base-path-skewed endpoint
// (e.g. blackbox "/api/v3/users/42" vs pattern "/users/{}") is NOT a
// route-pattern match here; it can still be caught by the existing
// suffix/fuzzy strategies that run after this one.
//
// Examples:
//
//	pattern "/users/{}"      endpoint "/users/42"      → true
//	pattern "/users/{}"      endpoint "/users/42/edit" → false (segment count)
//	pattern "/users/{}/edit" endpoint "/users/42/edit" → true
//	pattern "/users/{}"      endpoint "/orders/42"     → false (literal "users")
func pathSegmentsMatch(pattern, endpoint string) bool {
	if pattern == "" || endpoint == "" {
		return false
	}
	pSeg := splitPathSegments(pattern)
	eSeg := splitPathSegments(endpoint)
	if len(pSeg) != len(eSeg) {
		return false
	}
	if len(pSeg) == 0 {
		// Both normalized to root "/" — a routeless root match. Treat as a
		// match only when both are exactly root (handled by equal length 0).
		return pattern == endpoint
	}
	for i := range pSeg {
		if pSeg[i] == "{}" {
			// Wildcard: matches any single non-empty segment. eSeg[i] is
			// guaranteed non-empty by splitPathSegments (it drops empties).
			continue
		}
		if pSeg[i] != eSeg[i] {
			return false
		}
	}
	return true
}

// splitPathSegments splits a normalized path into its non-empty, lowercased
// segments WITHOUT the noise filtering that pathSegments() applies. The
// route-pattern matcher needs every literal segment preserved (filtering out
// "api"/"users"/etc. would make "/api/{}" match "/{}" and destroy precision),
// so this is a separate, simpler splitter from the fuzzy-match pathSegments.
func splitPathSegments(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// blackboxMethod extracts the HTTP method token from a blackbox finding's
// endpoint string, which whitebox/blackbox emitters format as "<METHOD> <PATH>"
// (e.g. "GET /users/42"). Returns "" when no method prefix is present, which
// the route-method check treats as "unknown — don't block the match". The
// Finding struct has no dedicated Method field; the method lives only in this
// prefix and on the Route struct, so this mirrors how normalizeEndpoint already
// recovers (and strips) the prefix.
func blackboxMethod(endpoint string) string {
	m := methodPrefixRe.FindString(endpoint)
	return strings.ToUpper(strings.TrimSpace(m))
}

// normalizeEndpoint extracts a comparable path from an endpoint string,
// stripping HTTP method prefixes, scheme, host, port, and query parameters.
func normalizeEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}

	// Strip a leading HTTP method token (e.g., "GET /pet" → "/pet").
	// Whitebox emitters format endpoints as "<METHOD> <PATH>"; without this,
	// the prefix corrupts both URL parsing and segment matching.
	endpoint = methodPrefixRe.ReplaceAllString(endpoint, "")

	// Handle file:line format (whitebox findings like "src/config.py:14")
	if !strings.Contains(endpoint, "://") && !strings.HasPrefix(endpoint, "/") {
		// Looks like a file path — extract the filename without line number
		parts := strings.SplitN(endpoint, ":", 2)
		return strings.ToLower(parts[0])
	}

	// Handle URL or bare-path format (blackbox findings, or whitebox after
	// method strip).
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return strings.ToLower(endpoint)
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}

	// Remove trailing slash for consistency
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}

	return strings.ToLower(path)
}

// isURLEndpoint reports whether a Finding.Endpoint string points at an HTTP
// endpoint (URL or bare path) rather than a source location like
// "src/config.py:14". The suffix `[Unconfirmed by live scan]` is only
// meaningful for the former — a live HTTP scan cannot confirm a finding
// that lives in source code.
func isURLEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	endpoint = methodPrefixRe.ReplaceAllString(endpoint, "")
	return strings.HasPrefix(endpoint, "/") || strings.Contains(endpoint, "://")
}

// pathSuffixMatch reports whether one normalized path is a suffix of the other
// on a `/` boundary. Both inputs must be URL-style paths starting with `/`;
// file paths and empty inputs return false.
//
// Example: pathSuffixMatch("/pet/findbystatus", "/api/v3/pet/findbystatus") = true.
// Counter-example: pathSuffixMatch("/3/pet", "/api/v3/pet") = false (the suffix
// boundary is mid-segment in `v3`).
func pathSuffixMatch(a, b string) bool {
	if !strings.HasPrefix(a, "/") || !strings.HasPrefix(b, "/") {
		return false
	}
	if a == b {
		return true
	}
	// Reject the trivial root case — every path is a suffix of itself plus "/".
	if a == "/" || b == "/" {
		return false
	}

	short, long := a, b
	if len(b) < len(a) {
		short, long = b, a
	}

	// HasSuffix with a leading-`/` short pattern enforces a clean segment
	// boundary because the literal `/` must align in `long`.
	return strings.HasSuffix(long, short)
}

// endpointsRelated checks if two normalized endpoints refer to the same
// resource. Handles cases where whitebox uses file paths and blackbox
// uses URL paths. Kept for callers that don't pre-compute segments;
// the correlator hot path uses segmentsRelated directly to avoid
// re-splitting.
func endpointsRelated(a, b string) bool {
	if a == b {
		return true
	}
	return segmentsRelated(pathSegments(a), pathSegments(b))
}

// segmentsRelated is the inner kernel of endpointsRelated: given two
// already-split segment lists, report whether any segment of length >2
// appears in both. Lifted out so the correlator can pre-compute
// segments once per finding (F2 fix in the 2026-05-16 complexity
// audit) instead of re-splitting on every (W, B) comparison.
func segmentsRelated(aSegments, bSegments []string) bool {
	for _, as := range aSegments {
		if len(as) <= 2 {
			continue
		}
		for _, bs := range bSegments {
			if as == bs {
				return true
			}
		}
	}
	return false
}

// pathSegmentNoise is the set of path tokens we filter out during fuzzy
// matching. Hoisted to package level so we don't allocate it on every
// pathSegments() call — the fuzzy-match pass calls pathSegments W·B
// times per scan, and the F2 finding in the time-complexity audit
// (2026-05-16) pinpointed this map as the dominant allocator in
// BenchmarkMemory_Correlate1000.
//
// Add tokens here only if they're (a) genuinely noise (not a vuln
// signal) and (b) common enough that filtering them improves match
// precision. Don't add per-customer tokens — that belongs in
// configuration, not in this package.
var pathSegmentNoise = map[string]bool{
	"api": true, "v1": true, "v2": true, "v3": true,
	"src": true, "py": true, "js": true, "go": true, "ts": true,
	"internal": true, "routes": true, "handlers": true,
	// HTTP methods leak in when an endpoint format like "GET /pet" is
	// normalized; filter them so they don't pollute fuzzy matching.
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "head": true, "options": true,
}

// pathSegments splits a path into meaningful segments, filtering out
// common noise. See pathSegmentNoise for the filter set and why it's
// at package scope.
func pathSegments(path string) []string {
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\' || r == '.'
	})

	// Pre-size: usually 1-3 segments survive filtering.
	segments := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if !pathSegmentNoise[p] && len(p) > 1 {
			segments = append(segments, p)
		}
	}
	return segments
}

// relatedCategories returns the list of categories that should be considered
// matches for correlation purposes.
func relatedCategories(category string) []string {
	result := []string{category}

	if mapped, ok := categoryMap[category]; ok {
		result = append(result, mapped)
	}

	// Reverse mapping
	for wb, bb := range categoryMap {
		if bb == category {
			result = append(result, wb)
		}
	}

	return result
}

// escalateSeverity bumps severity up by one level.
func escalateSeverity(s models.Severity) models.Severity {
	switch s {
	case models.SeverityInfo:
		return models.SeverityLow
	case models.SeverityLow:
		return models.SeverityMedium
	case models.SeverityMedium:
		return models.SeverityHigh
	case models.SeverityHigh:
		return models.SeverityCritical
	case models.SeverityCritical:
		return models.SeverityCritical // Can't go higher
	default:
		return s
	}
}

// higherSeverity returns whichever severity is more severe.
func higherSeverity(a, b models.Severity) models.Severity {
	if models.SeverityRank(a) >= models.SeverityRank(b) {
		return a
	}
	return b
}

// mergeRefs combines two reference lists, deduplicating.
func mergeRefs(a, b []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, r := range a {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	for _, r := range b {
		if !seen[r] {
			seen[r] = true
			result = append(result, r)
		}
	}
	return result
}
