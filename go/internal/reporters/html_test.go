package reporters

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters/i18n"
)

func TestRenderHTML_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "dev",
		Mode:      "blackbox",
	}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE declaration")
	}
	if !strings.Contains(html, "Fendix Security Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(html, "api.example.com") {
		t.Error("missing target URL")
	}
}

func TestRenderHTML_ContainsSeverityCounts(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	checks := []string{
		`<div class="stat critical">`,
		`<div class="stat high">`,
		`<div class="stat medium">`,
		`<div class="stat low">`,
		`<div class="stat info">`,
	}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("missing severity stat: %s", check)
		}
	}
}

func TestRenderHTML_ContainsFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	findings := sampleFindings()
	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	for _, f := range findings {
		if !strings.Contains(html, f.Title) {
			t.Errorf("missing finding title in HTML: %s", f.Title)
		}
	}
}

func TestRenderHTML_SelfContained(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()

	if strings.Contains(html, `<link rel="stylesheet"`) {
		t.Error("HTML report should not have external CSS links")
	}
	if strings.Contains(html, `<script src=`) {
		t.Error("HTML report should not have external JS scripts")
	}
	if !strings.Contains(html, "<style>") {
		t.Error("HTML report should contain inline CSS")
	}
}

func TestRenderHTML_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "dev"}

	err := RenderHTML(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "Total findings: 0") {
		t.Error("expected total findings to be 0")
	}
}

func TestRenderHTML_SeverityBadges(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev"}

	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Issue", Severity: models.SeverityCritical, Source: models.SourceBlackbox, References: []string{"CWE-1"}},
		{ID: "SEC-002", Title: "Low Issue", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{"CWE-2"}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, `class="badge CRITICAL"`) {
		t.Error("missing CRITICAL badge class")
	}
	if !strings.Contains(html, `class="badge LOW"`) {
		t.Error("missing LOW badge class")
	}
}

func TestRenderHTML_WithLineField(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev"}
	line := "src/app.py:42"
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Secret found", Severity: models.SeverityHigh, Source: models.SourceWhitebox, Line: &line, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "src/app.py:42") {
		t.Error("expected line reference in HTML output")
	}
}

func TestRenderHTML_ContainsSortButtons(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "sortFindings") {
		t.Error("missing sortFindings JavaScript function")
	}
	if !strings.Contains(html, `sortFindings('severity'`) {
		t.Error("missing severity sort button")
	}
	if !strings.Contains(html, `sortFindings('endpoint'`) {
		t.Error("missing endpoint sort button")
	}
	if !strings.Contains(html, `sortFindings('source'`) {
		t.Error("missing source sort button")
	}
}

func TestRenderHTML_ContainsExpandCollapseButtons(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "toggleAll") {
		t.Error("missing toggleAll JavaScript function")
	}
	if !strings.Contains(html, "Expand All") {
		t.Error("missing Expand All button")
	}
	if !strings.Contains(html, "Collapse All") {
		t.Error("missing Collapse All button")
	}
}

func TestRenderHTML_ContainsSeverityDataAttributes(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Issue", Severity: models.SeverityCritical, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-002", Title: "Low Issue", Severity: models.SeverityLow, Source: models.SourceWhitebox, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, `data-severity="4"`) {
		t.Error("missing severity rank data attribute for CRITICAL (4)")
	}
	if !strings.Contains(html, `data-severity="1"`) {
		t.Error("missing severity rank data attribute for LOW (1)")
	}
	if !strings.Contains(html, `data-source="blackbox"`) {
		t.Error("missing source data attribute")
	}
}

func TestRenderHTML_PrintCSS(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "@media print") {
		t.Error("missing print media query")
	}
	if !strings.Contains(html, "display:block !important") {
		t.Error("print CSS should force finding bodies to display:block")
	}
	if !strings.Contains(html, ".toolbar{display:none}") {
		t.Error("print CSS should hide toolbar")
	}
}

func TestRenderHTML_ContainsMode(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "hybrid"}

	err := RenderHTML(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "hybrid scan") {
		t.Error("missing scan mode in subtitle")
	}
	if !strings.Contains(html, "Mode: hybrid") {
		t.Error("missing mode in metadata footer")
	}
}

func TestRenderHTML_ContainsFindingID(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test Finding", Severity: models.SeverityHigh, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "SEC-001") {
		t.Error("expected finding ID in HTML output")
	}
}

func TestRenderHTML_ContainsCategory(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityHigh, Source: models.SourceBlackbox, Category: "injection", References: []string{}},
	}

	err := RenderHTML(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(buf.String(), "injection") {
		t.Error("expected category in finding body")
	}
}

// TestRenderHTML_AffectedEndpointsList covers TASK-088: a deduplicated
// finding (multiple AffectedEndpoints) renders an "Affected endpoints (N)"
// section listing each endpoint plus a "+N more" badge in the header.
func TestRenderHTML_AffectedEndpointsList(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{
			ID:                "SEC-001",
			Title:             "Missing CSP header",
			Severity:          models.SeverityMedium,
			Source:            models.SourceBlackbox,
			Category:          "headers",
			Endpoint:          "GET /api/users",
			AffectedEndpoints: []string{"GET /api/users", "GET /api/posts", "GET /api/orders"},
			References:        []string{},
		},
	}
	if err := RenderHTML(&buf, findings, meta); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "Affected endpoints (3)") {
		t.Errorf("expected affected-endpoints header with count 3, got:\n%s", html)
	}
	if !strings.Contains(html, "+2 more") {
		t.Errorf("expected '+2 more' badge in header, got:\n%s", html)
	}
	for _, ep := range []string{"GET /api/users", "GET /api/posts", "GET /api/orders"} {
		if !strings.Contains(html, ep) {
			t.Errorf("expected endpoint %q in HTML, got:\n%s", ep, html)
		}
	}
}

// TestRenderHTML_NeutralizesBidiAndControl covers F-L1/F-L2: bidi
// override / zero-width / control characters in untrusted finding
// fields must not survive into the rendered HTML.
func TestRenderHTML_NeutralizesBidiAndControl(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{
			ID:                "SEC-001",
			Title:             "Trojan" + rlo + "title",
			Severity:          models.SeverityCritical,
			Source:            models.SourceBlackbox,
			Category:          "data" + zwsp + "exposure",
			Endpoint:          "GET /api" + rlo + "/users",
			Evidence:          "leak" + zwj + "ed token",
			Fix:               "rotate\x07now",
			AffectedEndpoints: []string{"GET /a" + bom + "b", "POST /c" + rlo + "d"},
			References:        []string{},
		},
	}
	if err := RenderHTML(&buf, findings, meta); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	for _, bad := range []string{rlo, zwsp, zwj, bom} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML output still contains a bidi/zero-width char %U", []rune(bad)[0])
		}
	}
	if strings.ContainsRune(out, '\x07') {
		t.Error("HTML output still contains a C0 control char")
	}
}

// TestRenderHTML_AutoEscapingHolds confirms that neutralization runs
// BEFORE html/template auto-escaping and does not disable it: HTML
// metacharacters in a finding title must still be entity-escaped, not
// emitted as live markup.
func TestRenderHTML_AutoEscapingHolds(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{
			ID:         "SEC-001",
			Title:      `<script>alert(1)</script>` + rlo,
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Endpoint:   "GET /x",
			References: []string{},
		},
	}
	if err := RenderHTML(&buf, findings, meta); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("html/template auto-escaping regressed: raw <script> survived")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected entity-escaped <script> in output")
	}
	// And the bidi char must still be stripped.
	if strings.Contains(out, rlo) {
		t.Error("bidi char survived alongside escaped markup")
	}
}

// TestRenderHTML_SingletonHasNoAffectedSection: a finding without
// AffectedEndpoints (the common case) must NOT render an empty
// "Affected endpoints" block — that would just be visual noise.
func TestRenderHTML_SingletonHasNoAffectedSection(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "blackbox"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityHigh, Source: models.SourceBlackbox, Endpoint: "/x"},
	}
	if err := RenderHTML(&buf, findings, meta); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(buf.String(), "Affected endpoints") {
		t.Error("singleton finding should not render 'Affected endpoints' section")
	}
}

// TestRenderHTML_DecisionCards covers the v0.24 HTML: a Blocking decision
// card + per-finding confidence score appear.
func TestRenderHTML_DecisionCards(t *testing.T) {
	var buf bytes.Buffer
	findings := []models.Finding{
		{ID: "SEC-001", Title: "x", Severity: models.SeverityHigh, Category: "c", Status: "BLOCK", ConfidenceScore: 80, ConfidenceBand: "HIGH"},
	}
	if err := RenderHTML(&buf, findings, ScanMetadata{}); err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"stat block", "Blocking", "Confirmed", "(80/100)"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestRenderHTML_CoverageTableAndVerdict(t *testing.T) {
	status := []ScannerStatus{
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "semgrep binary not installed"},
		{Name: "pip", State: ScannerOK, Attempts: 2},
	}
	cov := BuildCoverage(status, nil, false)
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "3.4.0", Mode: "whitebox", ScannerStatus: status, Coverage: &cov,
		ReleaseDecision: "block", CoverageState: "incomplete"}
	if err := RenderHTML(&buf, sampleFindings(), meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Scanner coverage", "semgrep", "unavailable", "dependency_missing", "semgrep binary not installed", "Blocked — coverage also incomplete", "coverage incomplete: semgrep"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if !strings.Contains(out, ">2<") {
		t.Error("attempts column must show the retry count")
	}
}

func TestRenderHTML_IncompleteIsPrimaryOnlyWhenDecisionIsIncomplete(t *testing.T) {
	var buf bytes.Buffer
	cov := BuildCoverage(nil, nil, false)
	_ = RenderHTML(&buf, nil, ScanMetadata{Version: "3.4.0", Mode: "whitebox", Coverage: &cov, ReleaseDecision: "incomplete", CoverageState: "incomplete"})
	if !strings.Contains(buf.String(), "Coverage incomplete") || strings.Contains(buf.String(), "Blocked") {
		t.Fatalf("release_decision=incomplete must render the incomplete verdict alone")
	}
}

func TestRenderHTML_NoCoverageBlockSaysNotRecorded(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderHTML(&buf, nil, ScanMetadata{Version: "3.3.0", Mode: "blackbox"})
	if !strings.Contains(buf.String(), "not recorded by this engine version") {
		t.Fatal("pre-contract input must say coverage was not recorded")
	}
}

func TestRenderHTML_ArabicCoverageTitle(t *testing.T) {
	var buf bytes.Buffer
	cov := BuildCoverage([]ScannerStatus{{Name: "secrets", State: ScannerOK}}, nil, false)
	_ = RenderHTMLOpts(&buf, nil, ScanMetadata{Version: "3.4.0", Mode: "whitebox", Coverage: &cov}, HTMLOptions{Lang: "ar"})
	if !strings.Contains(buf.String(), i18n.Get("ar").CoverageTitle) {
		t.Fatal("Arabic report must use the Arabic coverage title")
	}
}
