package benchmark

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"gopkg.in/yaml.v3"
)

// FPClass is the false-positive taxonomy (design §5). It is also the enum
// used in a label's `fp_class:` field, so a labels file can never name a
// class the fixes don't track.
type FPClass string

const (
	FPConstantAuthority FPClass = "constant-authority"
	FPReceiverConfusion FPClass = "receiver-confusion"
	FPSafeAPIMisread    FPClass = "safe-api-misread"
	FPConstFoldMiss     FPClass = "const-fold-miss"
	FPGuardDominance    FPClass = "guard-dominance"
	FPTestFixture       FPClass = "test-fixture"
	FPHTTP4xxContext    FPClass = "http-4xx-context"
	FPStaticAssetCtx    FPClass = "static-asset-context"
	FPDoubleSanitize    FPClass = "double-sanitize"
	FPHeuristicOverfire FPClass = "heuristic-overfire"
	FPVersionRangeFloor FPClass = "version-range-floor"
	FPFabricatedChain   FPClass = "fabricated-chain"
)

var validFPClasses = map[FPClass]bool{
	FPConstantAuthority: true, FPReceiverConfusion: true, FPSafeAPIMisread: true,
	FPConstFoldMiss: true, FPGuardDominance: true, FPTestFixture: true,
	FPHTTP4xxContext: true, FPStaticAssetCtx: true, FPDoubleSanitize: true,
	FPHeuristicOverfire: true, FPVersionRangeFloor: true, FPFabricatedChain: true,
}

// Valid reports whether c is a recognized FP class.
func (c FPClass) Valid() bool { return validFPClasses[c] }

// fpClassMechanism names, for every FP class, the shipped code that actually
// enforces it. The taxonomy is a claim about the engine's behaviour — a class
// that no code implements makes BENCHMARKS.md's per-class table a promise the
// binary does not keep, which is exactly what happened to `test-fixture` and
// `static-asset-context` before v1.1's wiring pass (both were scored/labelled
// but had no reachable producer).
//
// TestEveryFPClassNamesItsMechanism is the drift guard: add a class here
// without an implementation, or delete an implementation without retiring its
// class, and the build goes red. Keep the strings short and greppable — they
// are the pointer a reader follows from a label to the code.
var fpClassMechanism = map[FPClass]string{
	FPConstantAuthority: "python/analyzers/ast_analyzer.py:_url_authority_is_constant " +
		"(settings.* / UPPER_CASE / literal scheme+host fixes the SSRF authority)",
	FPReceiverConfusion: "python/analyzers/ast_analyzer.py:_receiver_is_http_client " +
		"(redis .get/.delete is not an HTTP client)",
	FPSafeAPIMisread: "python/analyzers/ast_analyzer.py:_is_psycopg_sql_composable " +
		"(psycopg2 sql.SQL(...).format is not str.format)",
	FPConstFoldMiss: "python/analyzers/ast_analyzer.py:_sql_expr_is_constant " +
		"(const-folds %-format / join / ternary SQL)",
	FPGuardDominance: "python/analyzers/ast_analyzer.py:_name_is_membership_guarded " +
		"(the membership guard must dominate the sink)",
	FPTestFixture: "internal/decision.DecideWithOptions + models.ScanConfig.DeescalateTests " +
		"(test/fixture findings demote WARN→INFO, and an uncorroborated BLOCK→WARN; " +
		"evidence preserved, a corroborated finding at or above --fail-on still blocks)",
	FPHTTP4xxContext: "internal/scanner.responseContextFor → \"4xx\" + " +
		"internal/confidence httpContextPenalty",
	FPStaticAssetCtx: "internal/scanner.responseContextFor → \"static-asset\" + " +
		"internal/confidence httpContextPenalty",
	FPDoubleSanitize: "python/analyzers/ast_analyzer.py:_expr_is_fully_escaped " +
		"(Markup / escaped f-string wrap)",
	FPHeuristicOverfire: "python/analyzers/ast_analyzer.py:_looks_like_password_id " +
		"(weak-crypto skips metadata-named identifiers)",
	FPVersionRangeFloor: "internal/scanner/deps/npm.ErrLockfileMissingButPackageJsonPresent → " +
		"engine.recordNpmScanResult INFO advisory (never assert CVEs from caret/tilde ranges)",
	FPFabricatedChain: "python/analyzers/ast_analyzer.py:_is_path_traversal_sink " +
		"(a from-imported non-filesystem open() is not traversal)",
}

// Mechanism returns the shipped code that enforces class c, or "" when c is not
// a recognized class.
func (c FPClass) Mechanism() string { return fpClassMechanism[c] }

// Verdict is a label's ground-truth call for a matched finding.
type Verdict string

const (
	VerdictTP      Verdict = "tp"
	VerdictFP      Verdict = "fp"
	VerdictUnknown Verdict = "unknown" // never in a file; the scorer's bucket for unlabeled findings
)

// Label is one ground-truth entry keyed by a STABLE (rule+file+line) tuple,
// not a fingerprint — fingerprints embed evidence text that legitimate fixes
// change, silently orphaning labels (design §4.3).
type Label struct {
	Rule    string  `yaml:"rule"`
	File    string  `yaml:"file"`
	Line    int     `yaml:"line"`
	Verdict Verdict `yaml:"verdict"`
	FPClass FPClass `yaml:"fp_class,omitempty"`
	Note    string  `yaml:"note,omitempty"`
}

// LabelSet is the parsed labels.yaml for one corpus entry.
type LabelSet struct {
	Labels []Label
}

// NormalizePath makes a repo-relative path stable for matching: forward
// slashes, no leading "./".
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return p
}

// LoadLabelSet reads and validates a labels.yaml. verdict:fp requires a valid
// fp_class; any verdict other than tp/fp is rejected.
func LoadLabelSet(path string) (*LabelSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading labels %s: %w", path, err)
	}
	var labels []Label
	if err := yaml.Unmarshal(data, &labels); err != nil {
		return nil, fmt.Errorf("parsing labels %s: %w", path, err)
	}
	for i := range labels {
		labels[i].File = NormalizePath(labels[i].File)
		switch labels[i].Verdict {
		case VerdictTP:
		case VerdictFP:
			if !labels[i].FPClass.Valid() {
				return nil, fmt.Errorf("labels %s: entry %d verdict:fp needs a valid fp_class (got %q)", path, i, labels[i].FPClass)
			}
		default:
			return nil, fmt.Errorf("labels %s: entry %d has invalid verdict %q (want tp|fp)", path, i, labels[i].Verdict)
		}
	}
	return &LabelSet{Labels: labels}, nil
}

const lineTolerance = 3

// ruleToCWE maps a label's rule id to the single CWE reference that rule
// emits (verified against python/analyzers/ast_analyzer.py `_emit_finding`
// call sites, 2026-07-07). This is the rule identity that SURVIVES the
// orchestrator's positional ID renumbering (`SEC-%03d`,
// internal/engine/orchestrator.go:581): the production JSON report carries
// `references: ["CWE-…"]` verbatim while the ID is rewritten.
//
// Verification corrections vs. the design sketch:
//   - PY_WEAK_CRYPTO_PASSWORD emits CWE-916 only (not CWE-327).
//   - PY_AUTH_HEADER_TRUST emits CWE-290 (not CWE-287).
//   - PY_LLM_PROMPT_INJECTION emits CWE-77 (both emit sites).
var ruleToCWE = map[string]string{
	"PY_SSRF":                 "CWE-918",
	"PY_SQL_INJECTION":        "CWE-89",
	"PY_OS_SYSTEM":            "CWE-78",
	"PY_OS_POPEN":             "CWE-78",
	"PY_SUBPROCESS_SHELL":     "CWE-78",
	"PY_PATH_TRAVERSAL":       "CWE-22",
	"PY_XSS_HTML_SINK":        "CWE-79",
	"PY_EVAL":                 "CWE-95",
	"PY_PICKLE_LOAD":          "CWE-502",
	"PY_YAML_UNSAFE_LOAD":     "CWE-502",
	"PY_OPEN_REDIRECT":        "CWE-601",
	"PY_JWT_WEAK":             "CWE-347",
	"PY_WEAK_CRYPTO_PASSWORD": "CWE-916",
	"PY_SECRET_IN_LOG":        "CWE-532",
	"PY_AUTH_HEADER_TRUST":    "CWE-290",
	"PY_LLM_PROMPT_INJECTION": "CWE-77",
	// JS heuristic rules (same emitter, `_JS_PATTERNS`).
	"JS_EVAL":           "CWE-95",
	"JS_INNER_HTML":     "CWE-79",
	"JS_DOCUMENT_WRITE": "CWE-79",
	"JS_SQL_TEMPLATE":   "CWE-89",
}

// ruleTitleKeywords is the FINAL fallback: when a positional-ID finding
// carries no references (or the label's rule has no CWE mapping), the rule
// matches iff every keyword appears (case-insensitively) in the finding's
// title. Deterministic — a fixed table, substring containment, no scoring.
var ruleTitleKeywords = map[string][]string{
	// PY_LLM_PROMPT_INJECTION emits CWE-77 today; the title keyword keeps
	// SANAD's recall anchors matchable if the reference ever goes away.
	"PY_LLM_PROMPT_INJECTION": {"prompt injection"},
}

// MatchFinding reports whether f corresponds to label l: same rule identity
// (see ruleMatches), same normalized file, and line within ±3 of the anchor.
// The file+line anchor applies in ALL rule-matching paths.
func MatchFinding(l Label, f models.Finding) bool {
	file, line, ok := splitEndpoint(f.Endpoint)
	if !ok {
		return false
	}
	if NormalizePath(file) != l.File {
		return false
	}
	d := line - l.Line
	if d < 0 {
		d = -d
	}
	if d > lineTolerance {
		return false
	}
	return ruleMatches(l.Rule, f)
}

// ruleMatches resolves a finding's rule identity against the label's rule.
// Production reports do NOT carry the rule id in Finding.ID — the
// orchestrator renumbers every finding positionally to "SEC-NNN"
// (internal/engine/orchestrator.go:581) — so the matching chain is:
//
//  1. Rule-shaped ID (the raw analyzer shape "SEC-PY_SSRF" — the remainder
//     after "SEC-" contains letters/underscores): match the label's rule
//     directly. Preserves the Phase A contract and any engine that keeps
//     rule ids in output.
//  2. Positional ID ("SEC-001"): match via the static ruleToCWE map against
//     the finding's references.
//  3. Final fallback (rule absent from the CWE map, or the finding carries
//     no references): the deterministic ruleTitleKeywords table.
func ruleMatches(rule string, f models.Finding) bool {
	id := ruleOf(f.ID)
	if isRuleShaped(id) {
		return id == rule
	}
	if cwe, ok := ruleToCWE[rule]; ok && len(f.References) > 0 {
		for _, ref := range f.References {
			if ref == cwe {
				return true
			}
		}
		return false
	}
	keywords, ok := ruleTitleKeywords[rule]
	if !ok {
		return false
	}
	title := strings.ToLower(f.Title)
	for _, kw := range keywords {
		if !strings.Contains(title, kw) {
			return false
		}
	}
	return true
}

// isRuleShaped reports whether an ID remainder (after "SEC-") carries a rule
// identity like "PY_SSRF" (letters/underscores) rather than a positional
// number like "001".
func isRuleShaped(rest string) bool {
	for _, r := range rest {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// ruleOf strips the "SEC-" prefix so "SEC-PY_SSRF" → "PY_SSRF".
func ruleOf(id string) string { return strings.TrimPrefix(id, "SEC-") }

// splitEndpoint splits "path/to/file.py:42" into ("path/to/file.py", 42, true).
func splitEndpoint(ep string) (string, int, bool) {
	i := strings.LastIndex(ep, ":")
	if i <= 0 {
		return "", 0, false
	}
	line, err := strconv.Atoi(ep[i+1:])
	if err != nil {
		return "", 0, false
	}
	return ep[:i], line, true
}

// RealWorldResult is the scored outcome of one real-world corpus entry. It is
// richer than BenchmarkResult (which the baseline stores): it carries the
// unknown bucket, the per-fp_class breakdown, and the noise-density metric.
type RealWorldResult struct {
	Entry    string
	TruePos  int
	FalsePos int
	Unknown  int
	FalseNeg int
	PerClass map[FPClass]int
	// Unknowns is the triage list: findings that matched no label.
	Unknowns []models.Finding
	// LabelNotes are the matched labels that carry a reviewer `note:` — the
	// recorded justification for a tp/fp verdict. Collected so the triage
	// report can show WHY a finding was classed the way it was; without it the
	// note field is written by humans and read by nobody.
	LabelNotes []Label
	LOC        int
}

// Precision is over LABELED findings only (tp/(tp+fp)); unknowns are excluded
// until triaged, which is what makes the number defensible (design §4.3).
func (r *RealWorldResult) Precision() float64 {
	d := r.TruePos + r.FalsePos
	if d == 0 {
		return 0
	}
	return float64(r.TruePos) / float64(d)
}

// FindingsPerKLOC is noise density over emitted findings that carry a label
// (tp+fp); unknowns are excluded so density tracks the same defensible set as
// precision.
func (r *RealWorldResult) FindingsPerKLOC() float64 {
	if r.LOC == 0 {
		return 0
	}
	return float64(r.TruePos+r.FalsePos) / (float64(r.LOC) / 1000.0)
}

// ScoreRealWorld matches each finding to at most one label and buckets it.
func ScoreRealWorld(entry string, ls *LabelSet, findings []models.Finding, loc int) *RealWorldResult {
	r := &RealWorldResult{Entry: entry, PerClass: map[FPClass]int{}, LOC: loc}
	labelHit := make([]bool, len(ls.Labels))
	for _, f := range findings {
		matched := -1
		for i, l := range ls.Labels {
			if MatchFinding(l, f) {
				matched = i
				break
			}
		}
		if matched < 0 {
			r.Unknown++
			r.Unknowns = append(r.Unknowns, f)
			continue
		}
		labelHit[matched] = true
		if n := ls.Labels[matched].Note; n != "" {
			r.LabelNotes = append(r.LabelNotes, ls.Labels[matched])
		}
		switch ls.Labels[matched].Verdict {
		case VerdictTP:
			r.TruePos++
		case VerdictFP:
			r.FalsePos++
			r.PerClass[ls.Labels[matched].FPClass]++
		}
	}
	for i, l := range ls.Labels {
		if l.Verdict == VerdictTP && !labelHit[i] {
			r.FalseNeg++
		}
	}
	return r
}
