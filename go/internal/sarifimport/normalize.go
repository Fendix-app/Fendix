package sarifimport

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// evidenceCap bounds the Evidence text of an imported finding so one chatty
// tool cannot balloon the report. Title and Fix get proportionally smaller
// caps.
const (
	evidenceCap                 = 2000
	titleCap                    = 200
	fixCap                      = 2000
	securitySeverityCriticalMin = 9.0
	securitySeverityHighMin     = 7.0
	securitySeverityMediumMin   = 4.0
)

// DocumentationFacts projects importer behavior into the generated contract.
// Values are derived through the same normalization helpers used at runtime.
type DocumentationFacts struct {
	SupportedVersion      string
	LevelSeverity         map[string]string
	PrecisionConfidence   map[string]string
	SecurityThresholds    []string
	ToolNormalization     string
	EvidenceLimitBytes    int
	TitleLimitBytes       int
	RemediationLimitBytes int
	TrustBoundary         []string
}

// DocumentationContract returns the stable machine-facing import contract.
func DocumentationContract() DocumentationFacts {
	levels := map[string]string{}
	for _, level := range []string{"error", "warning", "note", "none"} {
		levels[level] = string(mapSeverity(level, nil))
	}
	precision := map[string]string{}
	for _, value := range []string{"very-high", "high", "medium", "low"} {
		precision[value] = string(mapConfidence("warning", &Rule{Properties: RuleProperties{Precision: value}}))
	}
	return DocumentationFacts{
		SupportedVersion: SupportedVersion, LevelSeverity: levels, PrecisionConfidence: precision,
		SecurityThresholds: []string{
			fmt.Sprintf("score >= %.1f: CRITICAL", securitySeverityCriticalMin),
			fmt.Sprintf("score >= %.1f: HIGH", securitySeverityHighMin),
			fmt.Sprintf("score >= %.1f: MEDIUM", securitySeverityMediumMin),
			fmt.Sprintf("score < %.1f: LOW", securitySeverityMediumMin),
		},
		ToolNormalization:  "lowercase; collapse spaces to hyphens; retain only a-z, 0-9, dot, underscore, and hyphen; empty becomes unknown-tool",
		EvidenceLimitBytes: evidenceCap, TitleLimitBytes: titleCap, RemediationLimitBytes: fixCap,
		TrustBoundary: []string{"source is imported", "source tier is unset", "codeFlows do not establish native reachability", "route and taint chain are not trusted from imported SARIF"},
	}
}

// ImportStats reconciles what the importer did with what the document held:
// every result is either imported, skipped as suppressed, or imported with
// Endpoint "unknown" (counted in NoLocation) — counts always add up.
type ImportStats struct {
	Tools []ToolStat
}

// ToolStat is the per-TOOL accounting block surfaced in report metadata —
// one entry per normalized tool identity, folded across every run that tool
// contributed (see Normalize).
type ToolStat struct {
	Tool       string `json:"tool"`
	Version    string `json:"version,omitempty"`
	Results    int    `json:"results"`
	Suppressed int    `json:"suppressed,omitempty"`
	NoLocation int    `json:"no_location,omitempty"`
	// Corroborated counts imported findings that strong cross-tool
	// correlation collapsed into a native representative. Always 0 here —
	// Normalize runs BEFORE correlation; the orchestrator stamps it in
	// finalize once CorrelateCrossTool has reported its per-tool counts.
	Corroborated int `json:"corroborated,omitempty"`
}

// cweToCategory maps CWE families fendix already understands onto the NATIVE
// category vocabulary (the exact strings the built-in scanners emit — see
// internal/scanner). Small and explicit on purpose: an entry is added only
// when the mapping is unambiguous, and everything else falls back to
// import/<tool>. Do not attempt to cover the CWE catalog.
var cweToCategory = map[string]string{
	"CWE-89":  "injection", // SQL injection
	"CWE-78":  "injection", // OS command injection
	"CWE-77":  "injection", // command injection
	"CWE-95":  "injection", // eval injection
	"CWE-79":  "xss",       // cross-site scripting
	"CWE-918": "ssrf",      // server-side request forgery
	"CWE-798": "secrets",   // hardcoded credentials
	"CWE-259": "secrets",   // hardcoded password
	"CWE-287": "auth",      // improper authentication
	"CWE-306": "auth",      // missing authentication
	"CWE-862": "auth",      // missing authorization
	"CWE-863": "auth",      // incorrect authorization
}

// Normalize walks every run in doc and maps each non-suppressed result to an
// evidence.Evidence with Source=imported. Deterministic: the same document
// always yields the same evidence in the same order.
func Normalize(doc *Document) ([]evidence.Evidence, ImportStats, error) {
	if doc == nil {
		return nil, ImportStats{}, fmt.Errorf("nil SARIF document")
	}
	var out []evidence.Evidence
	// Accumulate by normalized tool identity — the SAME key independence uses
	// in engine.CorrelateCrossTool. A document may carry several runs of one
	// tool; the correlator treats them as one tool, so the accounting must
	// too. Emitting one block per RUN would leave a per-tool corroborated
	// count with two identically-named blocks and no way to choose between
	// them. `order` preserves first-appearance order so output is stable.
	byTool := map[string]*ToolStat{}
	var order []string
	for _, run := range doc.Runs {
		toolID := NormalizeToolName(run.Tool.Driver.Name)
		version := driverVersion(run.Tool.Driver)
		st, seen := byTool[toolID]
		if !seen {
			st = &ToolStat{Tool: toolID, Version: version}
			byTool[toolID] = st
			order = append(order, toolID)
		} else if st.Version != version {
			// Mixed versions of one tool are pathological; the tool name is
			// what carries provenance, so drop the ambiguous version rather
			// than assert one run's over another's.
			st.Version = ""
		}
		rules := indexRules(run.Tool.Driver.Rules)
		for _, res := range run.Results {
			if isSuppressed(res) {
				st.Suppressed++
				continue
			}
			ev := normalizeResult(res, rules, run, toolID, version)
			if ev.Endpoint == "unknown" {
				st.NoLocation++
			}
			st.Results++
			out = append(out, ev)
		}
	}
	stats := ImportStats{Tools: make([]ToolStat, 0, len(order))}
	for _, id := range order {
		stats.Tools = append(stats.Tools, *byTool[id])
	}
	return out, stats, nil
}

// NormalizeToolName reduces a driver name to the normalized tool identity
// used for provenance and independence checks: lowercased, spaces collapsed
// to dashes, anything outside [a-z0-9._-] dropped. "CodeQL" → "codeql",
// "Trivy Scanner" → "trivy-scanner". Empty input becomes "unknown-tool".
func NormalizeToolName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, " ", "-")
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if s == "" {
		return "unknown-tool"
	}
	return s
}

func driverVersion(d Driver) string {
	if d.SemanticVersion != "" {
		return d.SemanticVersion
	}
	return d.Version
}

// isSuppressed reports whether a result carries at least one ACCEPTED
// suppression (per the SARIF spec an absent status means accepted). A
// suppression under review or rejected does not suppress.
func isSuppressed(res Result) bool {
	for _, s := range res.Suppressions {
		if s.Status == "" || strings.EqualFold(s.Status, "accepted") {
			return true
		}
	}
	return false
}

// indexRules builds the ruleId → Rule lookup for a run.
func indexRules(rules []Rule) map[string]*Rule {
	ix := make(map[string]*Rule, len(rules))
	for i := range rules {
		ix[rules[i].ID] = &rules[i]
	}
	return ix
}

// normalizeResult maps one SARIF result to Evidence. The trust rules are
// non-negotiable: Source=imported, SourceTier empty, and Reachable /
// TaintChain / Route are never populated — SARIF codeFlows are deliberately
// ignored in v1 so an import cannot masquerade as a native-proven path.
func normalizeResult(res Result, rules map[string]*Rule, run Run, toolID, toolVersion string) evidence.Evidence {
	rule := resolveRule(res, rules, run)

	level := resolveLevel(res, rule)
	cwes := extractCWEs(res, rule)
	endpoint, line, lineEnd := normalizeLocation(res, run)
	snippet := locationSnippet(res)

	ev := evidence.Evidence{
		Title:      normalizeTitle(res, rule),
		Severity:   mapSeverity(level, rule),
		Source:     models.SourceImported,
		Category:   mapCategory(cwes, toolID),
		Endpoint:   endpoint,
		Evidence:   buildEvidence(res, snippet),
		Fix:        buildFix(rule),
		References: buildReferences(res, rule, cwes, toolID, toolVersion),
		Confidence: mapConfidence(level, rule),
		Weakness:   cwes,
		ToolID:     toolID,
		RuleID:     res.RuleID,
		LineEnd:    lineEnd,
	}
	if line > 0 {
		s := strconv.Itoa(line)
		ev.Line = &s
	}
	return ev
}

// resolveRule finds the rule metadata behind a result: ruleIndex when valid,
// otherwise ruleId lookup. Nil when the run carries no matching rule — every
// consumer falls back gracefully.
func resolveRule(res Result, rules map[string]*Rule, run Run) *Rule {
	if res.RuleIndex != nil {
		if i := *res.RuleIndex; i >= 0 && i < len(run.Tool.Driver.Rules) {
			return &run.Tool.Driver.Rules[i]
		}
	}
	if r, ok := rules[res.RuleID]; ok {
		return r
	}
	return nil
}

// resolveLevel applies the SARIF level fallback chain: result.level →
// rule.defaultConfiguration.level → "warning" (the spec default).
func resolveLevel(res Result, rule *Rule) string {
	if res.Level != "" {
		return strings.ToLower(res.Level)
	}
	if rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
		return strings.ToLower(rule.DefaultConfiguration.Level)
	}
	return "warning"
}

// mapSeverity derives the fendix severity. GitHub's security-severity score
// wins when present (>=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, else LOW);
// otherwise the SARIF level maps error→HIGH, warning→MEDIUM, note→INFO.
func mapSeverity(level string, rule *Rule) models.Severity {
	if rule != nil && rule.Properties.SecuritySeverity != nil {
		score := float64(*rule.Properties.SecuritySeverity)
		switch {
		case score >= securitySeverityCriticalMin:
			return models.SeverityCritical
		case score >= securitySeverityHighMin:
			return models.SeverityHigh
		case score >= securitySeverityMediumMin:
			return models.SeverityMedium
		default:
			return models.SeverityLow
		}
	}
	switch level {
	case "error":
		return models.SeverityHigh
	case "note", "none":
		return models.SeverityInfo
	default: // "warning" and anything unrecognized
		return models.SeverityMedium
	}
}

// mapConfidence derives the fendix confidence enum from the rule's declared
// precision, falling back to the level: error→HIGH, warning→MEDIUM,
// note→LOW. This is INPUT evidence (what the tool claims about itself), not
// proof of fendix verification — the deterministic scorer decides what it is
// worth.
func mapConfidence(level string, rule *Rule) models.Confidence {
	if rule != nil {
		switch strings.ToLower(rule.Properties.Precision) {
		case "very-high", "high":
			return models.ConfidenceHigh
		case "medium":
			return models.ConfidenceMedium
		case "low":
			return models.ConfidenceLow
		}
	}
	switch level {
	case "error":
		return models.ConfidenceHigh
	case "note", "none":
		return models.ConfidenceLow
	default:
		return models.ConfidenceMedium
	}
}

// mapCategory picks the native fendix category when a recognized CWE maps
// cleanly (first match over the sorted CWE list, so the choice is
// deterministic), and falls back to import/<tool> otherwise. The tool name
// is provenance, not taxonomy — it only appears in the category when fendix
// has no taxonomy for the weakness.
func mapCategory(cwes []string, toolID string) string {
	for _, c := range cwes { // cwes is sorted by extractCWEs
		if cat, ok := cweToCategory[c]; ok {
			return cat
		}
	}
	return "import/" + toolID
}

// cweTagRe recognizes a CWE mention inside STRUCTURED metadata (rule tags /
// property values), e.g. "external/cwe/cwe-089", "CWE-89", "cwe:79". It is
// applied ONLY to tags and taxa — never to message prose — so weakness
// identity is read, not guessed.
var cweTagRe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])cwe[-_/: ]0*(\d{1,5})(?:$|[^0-9])`)

// extractCWEs collects normalized CWE ids from every structured source SARIF
// offers: rule relationships into a CWE taxonomy, result taxa, rule tags,
// and the common non-standard "cwe" property. Sorted + deduped.
func extractCWEs(res Result, rule *Rule) []string {
	seen := map[string]bool{}
	addNum := func(digits string) {
		if cwe := evidence.NormalizeCWE("CWE-" + strings.TrimLeft(digits, "0")); cwe != "" {
			seen[cwe] = true
		}
	}
	addToken := func(s string) {
		for _, m := range cweTagRe.FindAllStringSubmatch(s, -1) {
			addNum(m[1])
		}
	}
	fromRef := func(ref ReportingDescriptorRef) {
		if ref.ToolComponent != nil && strings.EqualFold(ref.ToolComponent.Name, "cwe") {
			if _, err := strconv.Atoi(ref.ID); err == nil {
				addNum(ref.ID)
				return
			}
			addToken(ref.ID)
		}
	}
	if rule != nil {
		for _, rel := range rule.Relationships {
			fromRef(rel.Target)
		}
		for _, tag := range rule.Properties.Tags {
			if strings.Contains(strings.ToLower(tag), "cwe") {
				addToken(tag)
			}
		}
		if len(rule.Properties.CWE) > 0 {
			var one string
			var many []string
			if err := json.Unmarshal(rule.Properties.CWE, &one); err == nil {
				addToken(one)
			} else if err := json.Unmarshal(rule.Properties.CWE, &many); err == nil {
				for _, s := range many {
					addToken(s)
				}
			}
		}
	}
	for _, taxon := range res.Taxa {
		fromRef(taxon)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalizeLocation resolves the primary location to the fendix Endpoint
// convention: URLs stay verbatim; file paths become repo-relative-ish
// cleaned paths with a ":line" suffix (matching the native whitebox
// "src/config.py:14" shape). A result with no usable location gets
// "unknown" rather than being dropped, so counts reconcile — such a finding
// is excluded from location-based corroboration by construction.
func normalizeLocation(res Result, run Run) (endpoint string, line, lineEnd int) {
	if len(res.Locations) == 0 {
		return "unknown", 0, 0
	}
	pl := res.Locations[0].PhysicalLocation
	uri := strings.TrimSpace(pl.ArtifactLocation.URI)
	if uri == "" {
		return "unknown", 0, 0
	}
	line = pl.Region.StartLine
	lineEnd = pl.Region.EndLine
	if lineEnd < line {
		lineEnd = 0
	}

	if isHTTPURL(uri) {
		// DAST-shaped location: keep the URL verbatim (the native blackbox
		// convention); no line suffix.
		return uri, line, lineEnd
	}

	p := NormalizePath(uri, run)
	if p == "" {
		return "unknown", 0, 0
	}
	if line > 0 {
		return p + ":" + strconv.Itoa(line), line, lineEnd
	}
	return p, line, lineEnd
}

func isHTTPURL(uri string) bool {
	l := strings.ToLower(uri)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://")
}

// NormalizePath canonicalizes a SARIF artifact URI into the path form the
// rest of fendix compares against: file:// scheme stripped, backslashes
// normalized, redundant "." segments cleaned, and absolute paths relativized
// against a matching originalUriBaseIds entry when — and only when — one
// makes that safe. Meaningful path information is never silently dropped: an
// absolute path with no matching base stays absolute.
func NormalizePath(uri string, run Run) string {
	p := uri
	p = strings.TrimPrefix(p, "file:///")
	if strings.HasPrefix(uri, "file:///") && !strings.HasPrefix(p, "/") {
		// file:///home/x → /home/x ; file:///C:/x stays C:/x
		if len(p) < 2 || p[1] != ':' {
			p = "/" + p
		}
	}
	p = strings.TrimPrefix(p, "file://")
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	if p == "." || p == "/" {
		return ""
	}

	// Relativize against a base URI when the absolute path starts with one.
	if strings.HasPrefix(p, "/") {
		for _, base := range run.OriginalURIBaseIDs {
			b := strings.TrimPrefix(base.URI, "file://")
			b = strings.TrimRight(strings.ReplaceAll(b, "\\", "/"), "/")
			if b == "" {
				continue
			}
			if strings.HasPrefix(p, b+"/") {
				return strings.TrimPrefix(p, b+"/")
			}
		}
	}
	return strings.TrimPrefix(p, "./")
}

func locationSnippet(res Result) string {
	if len(res.Locations) == 0 {
		return ""
	}
	if s := res.Locations[0].PhysicalLocation.Region.Snippet; s != nil {
		return strings.TrimSpace(s.Text)
	}
	return ""
}

// normalizeTitle prefers the rule's short description, then the first line
// of the result message, then the rule id — always non-empty, always capped.
func normalizeTitle(res Result, rule *Rule) string {
	title := ""
	if rule != nil {
		title = strings.TrimSpace(rule.ShortDescription.Text)
	}
	if title == "" {
		title = firstLine(res.Message.Text)
	}
	if title == "" {
		title = res.RuleID
	}
	if title == "" {
		title = "Imported finding"
	}
	return truncate(title, titleCap)
}

func buildEvidence(res Result, snippet string) string {
	msg := strings.TrimSpace(res.Message.Text)
	if msg == "" {
		msg = strings.TrimSpace(res.Message.Markdown)
	}
	out := msg
	if snippet != "" {
		if out != "" {
			out += " | "
		}
		out += "Snippet: " + snippet
	}
	if out == "" {
		out = "Imported from SARIF (no message provided by the source tool)"
	}
	return truncate(out, evidenceCap)
}

func buildFix(rule *Rule) string {
	if rule == nil {
		return ""
	}
	fix := strings.TrimSpace(rule.Help.Text)
	if fix == "" {
		fix = strings.TrimSpace(rule.FullDescription.Text)
	}
	return truncate(fix, fixCap)
}

// buildReferences preserves everything from the source document that has
// provenance value: help URI, normalized CWE tokens (the same exact-token
// form native rules emit), tool + rule identity, and the source tool's own
// partialFingerprints (provenance ONLY — fendix identity stays the native
// fingerprint). Sorted for determinism, except the leading helpUri.
func buildReferences(res Result, rule *Rule, cwes []string, toolID, toolVersion string) []string {
	var refs []string
	if rule != nil && rule.HelpURI != "" {
		refs = append(refs, rule.HelpURI)
	}
	refs = append(refs, cwes...)
	tool := "tool:" + toolID
	if toolVersion != "" {
		tool += "@" + toolVersion
	}
	refs = append(refs, tool)
	if res.RuleID != "" {
		refs = append(refs, "rule:"+res.RuleID)
	}
	fpKeys := make([]string, 0, len(res.PartialFingerprints))
	for k := range res.PartialFingerprints {
		fpKeys = append(fpKeys, k)
	}
	sort.Strings(fpKeys)
	for _, k := range fpKeys {
		refs = append(refs, "sarif-fingerprint:"+k+"="+res.PartialFingerprints[k])
	}
	return refs
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	// Don't split a UTF-8 rune.
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}
