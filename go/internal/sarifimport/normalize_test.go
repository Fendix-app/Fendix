package sarifimport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func parseFixture(t *testing.T, name string) *Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return doc
}

// minimalDoc builds a one-run document programmatically for table tests.
func minimalDoc(rule Rule, res Result) *Document {
	return &Document{
		Version: SupportedVersion,
		Runs: []Run{{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{rule}}},
			Results: []Result{res},
		}},
	}
}

func loc(uri string, start, end int) []Location {
	return []Location{{PhysicalLocation: PhysicalLocation{
		ArtifactLocation: ArtifactLocation{URI: uri},
		Region:           Region{StartLine: start, EndLine: end},
	}}}
}

// ── Stats consolidation ─────────────────────────────────────────────────────
//
// One SARIF document may carry many runs of one tool, and the correlator
// treats them as ONE tool for independence. The accounting must agree, or a
// per-tool corroborated count has no unambiguous block to land in.

func TestNormalize_ConsolidatesStatsByTool(t *testing.T) {
	doc := &Document{Version: SupportedVersion, Runs: []Run{
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "a"}, Locations: loc("a.py", 1, 0)}},
		},
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "b"}, Locations: loc("b.py", 2, 0)}},
		},
	}}
	_, stats, err := Normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Tools) != 1 {
		t.Fatalf("two runs of one tool must consolidate to one block, got %d", len(stats.Tools))
	}
	if stats.Tools[0].Tool != "codeql" || stats.Tools[0].Results != 2 {
		t.Fatalf("got %+v, want codeql with 2 results", stats.Tools[0])
	}
	if stats.Tools[0].Version != "2.19.0" {
		t.Fatalf("agreeing versions must be retained, got %q", stats.Tools[0].Version)
	}
}

func TestNormalize_MixedVersionsClearVersion(t *testing.T) {
	doc := &Document{Version: SupportedVersion, Runs: []Run{
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.19.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "a"}, Locations: loc("a.py", 1, 0)}},
		},
		{
			Tool:    Tool{Driver: Driver{Name: "CodeQL", SemanticVersion: "2.20.0", Rules: []Rule{{ID: "r"}}}},
			Results: []Result{{RuleID: "r", Level: "error", Message: Message{Text: "b"}, Locations: loc("b.py", 2, 0)}},
		},
	}}
	_, stats, _ := Normalize(doc)
	if len(stats.Tools) != 1 {
		t.Fatalf("still one block per TOOL, got %d", len(stats.Tools))
	}
	if stats.Tools[0].Version != "" {
		t.Fatalf("disagreeing versions must clear the field, got %q", stats.Tools[0].Version)
	}
	if stats.Tools[0].Results != 2 {
		t.Fatalf("results still sum across runs, got %d", stats.Tools[0].Results)
	}
}

// ── Parse validation ────────────────────────────────────────────────────────

func TestParse_RejectsMalformedJSON(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Fatal("malformed JSON must be rejected")
	}
}

func TestParse_RejectsNonSARIF(t *testing.T) {
	_, err := Parse([]byte(`{"metadata": {"version": "1.0"}, "findings": []}`))
	if err == nil || !strings.Contains(err.Error(), "does not look like a SARIF") {
		t.Fatalf("non-SARIF JSON must be named as such, got %v", err)
	}
}

func TestParse_RejectsUnsupportedVersion(t *testing.T) {
	_, err := Parse([]byte(`{"version": "2.0.0", "runs": []}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported SARIF version") {
		t.Fatalf("SARIF != 2.1.0 must be rejected explicitly, got %v", err)
	}
}

func TestParse_EmptyRunsIsValid(t *testing.T) {
	doc, err := Parse([]byte(`{"version": "2.1.0", "runs": []}`))
	if err != nil {
		t.Fatalf("empty runs is a clean report, not an error: %v", err)
	}
	evs, _, err := Normalize(doc)
	if err != nil || len(evs) != 0 {
		t.Fatalf("want zero findings, got %d (err %v)", len(evs), err)
	}
}

// ── Severity mapping ────────────────────────────────────────────────────────

func TestMapSeverity_SecuritySeverityScoreWins(t *testing.T) {
	cases := []struct {
		score string
		want  models.Severity
	}{
		{"9.8", models.SeverityCritical},
		{"7.0", models.SeverityHigh},
		{"4.2", models.SeverityMedium},
		{"2.0", models.SeverityLow},
	}
	for _, tc := range cases {
		doc := minimalDoc(
			Rule{ID: "r"},
			Result{RuleID: "r", Level: "note", Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)},
		)
		// security-severity as a JSON string (the GitHub convention) — the
		// level says note, the score must win.
		var f FlexFloat
		if err := f.UnmarshalJSON([]byte(`"` + tc.score + `"`)); err != nil {
			t.Fatal(err)
		}
		doc.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity = &f
		evs, _, _ := Normalize(doc)
		if evs[0].Severity != tc.want {
			t.Errorf("score %s: got %v, want %v", tc.score, evs[0].Severity, tc.want)
		}
	}
}

func TestMapSeverity_LevelFallback(t *testing.T) {
	cases := []struct {
		level string
		want  models.Severity
	}{
		{"error", models.SeverityHigh},
		{"warning", models.SeverityMedium},
		{"note", models.SeverityInfo},
	}
	for _, tc := range cases {
		doc := minimalDoc(Rule{ID: "r"}, Result{RuleID: "r", Level: tc.level, Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)})
		evs, _, _ := Normalize(doc)
		if evs[0].Severity != tc.want {
			t.Errorf("level %s: got %v, want %v", tc.level, evs[0].Severity, tc.want)
		}
	}
}

func TestResolveLevel_RuleDefaultConfiguration(t *testing.T) {
	doc := minimalDoc(
		Rule{ID: "r", DefaultConfiguration: &ReportingConfiguration{Level: "error"}},
		Result{RuleID: "r", Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)},
	)
	evs, _, _ := Normalize(doc)
	if evs[0].Severity != models.SeverityHigh {
		t.Fatalf("rule defaultConfiguration.level must back-fill a missing result level, got %v", evs[0].Severity)
	}
}

// ── Confidence mapping ──────────────────────────────────────────────────────

func TestMapConfidence_PrecisionThenLevel(t *testing.T) {
	cases := []struct {
		precision string
		level     string
		want      models.Confidence
	}{
		{"very-high", "note", models.ConfidenceHigh},
		{"high", "note", models.ConfidenceHigh},
		{"medium", "error", models.ConfidenceMedium},
		{"low", "error", models.ConfidenceLow},
		{"", "error", models.ConfidenceHigh},
		{"", "warning", models.ConfidenceMedium},
		{"", "note", models.ConfidenceLow},
	}
	for _, tc := range cases {
		doc := minimalDoc(
			Rule{ID: "r", Properties: RuleProperties{Precision: tc.precision}},
			Result{RuleID: "r", Level: tc.level, Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)},
		)
		evs, _, _ := Normalize(doc)
		if evs[0].Confidence != tc.want {
			t.Errorf("precision=%q level=%q: got %v, want %v", tc.precision, tc.level, evs[0].Confidence, tc.want)
		}
	}
}

// ── Weakness + category ─────────────────────────────────────────────────────

func TestExtractCWEs_FromTagsRelationshipsAndTaxa(t *testing.T) {
	doc := minimalDoc(
		Rule{
			ID:         "r",
			Properties: RuleProperties{Tags: []string{"security", "external/cwe/cwe-089"}},
			Relationships: []Relationship{{Target: ReportingDescriptorRef{
				ID: "918", ToolComponent: &ToolComponentRef{Name: "CWE"},
			}}},
		},
		Result{
			RuleID: "r", Level: "warning", Message: Message{Text: "x"},
			Locations: loc("a.py", 1, 0),
			Taxa:      []ReportingDescriptorRef{{ID: "79", ToolComponent: &ToolComponentRef{Name: "cwe"}}},
		},
	)
	evs, _, _ := Normalize(doc)
	got := strings.Join(evs[0].Weakness, ",")
	if got != "CWE-79,CWE-89,CWE-918" {
		t.Fatalf("weakness = %q, want CWE-79,CWE-89,CWE-918", got)
	}
}

func TestMapCategory_NativeWhenCWEKnown_FallbackOtherwise(t *testing.T) {
	sql := minimalDoc(
		Rule{ID: "r", Properties: RuleProperties{Tags: []string{"external/cwe/cwe-089"}}},
		Result{RuleID: "r", Level: "warning", Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)},
	)
	evs, _, _ := Normalize(sql)
	if evs[0].Category != "injection" {
		t.Fatalf("CWE-89 must map to the NATIVE category 'injection', got %q", evs[0].Category)
	}

	unknown := minimalDoc(
		Rule{ID: "r", Properties: RuleProperties{Tags: []string{"external/cwe/cwe-1004"}}},
		Result{RuleID: "r", Level: "warning", Message: Message{Text: "x"}, Locations: loc("a.py", 1, 0)},
	)
	evs, _, _ = Normalize(unknown)
	if evs[0].Category != "import/codeql" {
		t.Fatalf("an unmapped CWE must fall back to import/<tool>, got %q", evs[0].Category)
	}
}

// ── Trust rules ─────────────────────────────────────────────────────────────

func TestImportedFindingsNeverCarryNativeTrustMarkers(t *testing.T) {
	doc := parseFixture(t, "codeql.sarif")
	evs, _, err := Normalize(doc)
	if err != nil || len(evs) == 0 {
		t.Fatalf("fixture must normalize: %v", err)
	}
	for _, ev := range evs {
		if ev.Source != models.SourceImported {
			t.Fatalf("Source = %q, want imported", ev.Source)
		}
		if ev.SourceTier != "" {
			t.Fatalf("SourceTier must stay empty (unknown tier), got %q", ev.SourceTier)
		}
		if ev.Reachable || ev.ProvenPath || ev.RouteConfirmed || ev.Route != nil || len(ev.TaintChain) > 0 {
			t.Fatal("an import must never claim reachability, routes, or taint chains")
		}
	}
}

// ── Suppressions, stats, locations ──────────────────────────────────────────

func TestSuppressedResultsSkippedAndCounted(t *testing.T) {
	doc := minimalDoc(Rule{ID: "r"}, Result{
		RuleID: "r", Level: "warning", Message: Message{Text: "x"},
		Locations:    loc("a.py", 1, 0),
		Suppressions: []Suppression{{Kind: "inSource"}}, // absent status = accepted
	})
	doc.Runs[0].Results = append(doc.Runs[0].Results, Result{
		RuleID: "r", Level: "warning", Message: Message{Text: "y"},
		Locations:    loc("b.py", 2, 0),
		Suppressions: []Suppression{{Kind: "external", Status: "rejected"}}, // NOT suppressed
	})
	evs, stats, _ := Normalize(doc)
	if len(evs) != 1 {
		t.Fatalf("accepted suppression must skip, rejected must import: got %d findings", len(evs))
	}
	if stats.Tools[0].Suppressed != 1 || stats.Tools[0].Results != 1 {
		t.Fatalf("stats must reconcile: %+v", stats.Tools[0])
	}
}

func TestMissingLocationBecomesUnknown(t *testing.T) {
	doc := minimalDoc(Rule{ID: "r"}, Result{RuleID: "r", Level: "warning", Message: Message{Text: "x"}})
	evs, stats, _ := Normalize(doc)
	if evs[0].Endpoint != "unknown" {
		t.Fatalf("no location → Endpoint 'unknown', got %q", evs[0].Endpoint)
	}
	if stats.Tools[0].NoLocation != 1 {
		t.Fatalf("NoLocation must count it: %+v", stats.Tools[0])
	}
}

func TestNormalizeLocation_PathAndLineConvention(t *testing.T) {
	doc := minimalDoc(Rule{ID: "r"}, Result{
		RuleID: "r", Level: "warning", Message: Message{Text: "x"},
		Locations: loc("src/app.py", 42, 45),
	})
	evs, _, _ := Normalize(doc)
	if evs[0].Endpoint != "src/app.py:42" {
		t.Fatalf("file endpoints follow the native path:line convention, got %q", evs[0].Endpoint)
	}
	if evs[0].Line == nil || *evs[0].Line != "42" {
		t.Fatalf("Line = %v, want 42", evs[0].Line)
	}
	if evs[0].LineEnd != 45 {
		t.Fatalf("LineEnd = %d, want 45", evs[0].LineEnd)
	}
}

func TestNormalizePath_FileURIAndBaseRelativization(t *testing.T) {
	run := Run{OriginalURIBaseIDs: map[string]ArtifactLocation{
		"SRCROOT": {URI: "file:///home/runner/work/repo"},
	}}
	cases := []struct{ in, want string }{
		{"file:///home/runner/work/repo/src/app.py", "src/app.py"},
		{"./src/app.py", "src/app.py"},
		{"src\\app.py", "src/app.py"},
		{"/opt/other/app.py", "/opt/other/app.py"}, // no matching base: kept, not dropped
	}
	for _, tc := range cases {
		if got := NormalizePath(tc.in, run); got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestURLLocationsKeptVerbatim(t *testing.T) {
	doc := minimalDoc(Rule{ID: "r"}, Result{
		RuleID: "r", Level: "warning", Message: Message{Text: "x"},
		Locations: loc("https://api.example.com/users?id=1", 0, 0),
	})
	evs, _, _ := Normalize(doc)
	if evs[0].Endpoint != "https://api.example.com/users?id=1" {
		t.Fatalf("URL endpoints stay verbatim, got %q", evs[0].Endpoint)
	}
}

// ── Evidence / provenance content ───────────────────────────────────────────

func TestEvidenceCappedAtTwoThousand(t *testing.T) {
	doc := minimalDoc(Rule{ID: "r"}, Result{
		RuleID: "r", Level: "warning",
		Message:   Message{Text: strings.Repeat("A", 5000)},
		Locations: loc("a.py", 1, 0),
	})
	evs, _, _ := Normalize(doc)
	if len(evs[0].Evidence) > evidenceCap+len("…") {
		t.Fatalf("evidence must be capped at %d, got %d bytes", evidenceCap, len(evs[0].Evidence))
	}
}

func TestReferencesCarryProvenance(t *testing.T) {
	doc := minimalDoc(
		Rule{ID: "py/sql-injection", HelpURI: "https://codeql.github.com/qhelp/py/sql-injection",
			Properties: RuleProperties{Tags: []string{"external/cwe/cwe-089"}}},
		Result{
			RuleID: "py/sql-injection", Level: "error", Message: Message{Text: "x"},
			Locations:           loc("a.py", 1, 0),
			PartialFingerprints: map[string]string{"primaryLocationLineHash": "abc123:1"},
		},
	)
	evs, _, _ := Normalize(doc)
	refs := strings.Join(evs[0].References, "\n")
	for _, want := range []string{
		"https://codeql.github.com/qhelp/py/sql-injection",
		"CWE-89",
		"tool:codeql@2.19.0",
		"rule:py/sql-injection",
		"sarif-fingerprint:primaryLocationLineHash=abc123:1",
	} {
		if !strings.Contains(refs, want) {
			t.Errorf("references missing %q:\n%s", want, refs)
		}
	}
}

// ── Multi-run + real-world fixtures ─────────────────────────────────────────

func TestMultiRunDocument(t *testing.T) {
	doc := parseFixture(t, "multitool.sarif")
	evs, stats, err := Normalize(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Tools) != 2 {
		t.Fatalf("want 2 tool stat blocks, got %d", len(stats.Tools))
	}
	tools := map[string]bool{}
	for _, ev := range evs {
		tools[ev.ToolID] = true
	}
	if !tools["codeql"] || !tools["semgrep"] {
		t.Fatalf("both runs must import: %v", tools)
	}
}

func TestRealWorldFixtures(t *testing.T) {
	for _, name := range []string{"codeql.sarif", "semgrep.sarif", "trivy.sarif"} {
		doc := parseFixture(t, name)
		evs, stats, err := Normalize(doc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(evs) == 0 {
			t.Fatalf("%s: no findings imported", name)
		}
		total := 0
		for _, ts := range stats.Tools {
			total += ts.Results
		}
		if total != len(evs) {
			t.Fatalf("%s: stats (%d) and findings (%d) must reconcile", name, total, len(evs))
		}
		if strings.HasPrefix(name, "codeql") {
			// The fixture's rule declares CWE-89 → native category.
			if evs[0].Category != "injection" {
				t.Fatalf("codeql fixture: category %q, want injection", evs[0].Category)
			}
		}
	}
}

func TestNormalizeToolName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"CodeQL", "codeql"},
		{"Trivy Scanner", "trivy-scanner"},
		{"  ", "unknown-tool"},
		{"Semgrep OSS", "semgrep-oss"},
	}
	for _, tc := range cases {
		if got := NormalizeToolName(tc.in); got != tc.want {
			t.Errorf("NormalizeToolName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
