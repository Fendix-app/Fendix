package reporters

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestRenderSARIF_ValidOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "1.0.0",
		Mode:      "hybrid",
	}

	err := RenderSARIF(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", log.Version)
	}
	if log.Schema == "" {
		t.Error("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "Fendix" {
		t.Errorf("expected tool name Fendix, got %s", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("expected tool version 1.0.0, got %s", run.Tool.Driver.Version)
	}
	if len(run.Results) != 7 {
		t.Errorf("expected 7 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 7 {
		t.Errorf("expected 7 rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestRenderSARIF_SeverityMapping(t *testing.T) {
	tests := []struct {
		severity models.Severity
		level    string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityMedium, "warning"},
		{models.SeverityLow, "note"},
		{models.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := sarifLevel(tt.severity)
			if got != tt.level {
				t.Errorf("sarifLevel(%s) = %s, want %s", tt.severity, got, tt.level)
			}
		})
	}
}

func TestRenderSARIF_HelpURI(t *testing.T) {
	tests := []struct {
		name string
		refs []string
		want string
	}{
		{"CWE reference", []string{"CWE-89"}, "https://cwe.mitre.org/data/definitions/89.html"},
		{"URL reference", []string{"https://owasp.org/api-security"}, "https://owasp.org/api-security"},
		{"CWE + URL prefers URL", []string{"https://example.com", "CWE-89"}, "https://example.com"},
		{"empty references", []string{}, ""},
		{"nil references", nil, ""},
		{"empty string", []string{""}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sarifHelpURI(tt.refs)
			if got != tt.want {
				t.Errorf("sarifHelpURI(%v) = %q, want %q", tt.refs, got, tt.want)
			}
		})
	}
}

// TestRenderSARIF_ParseLine locks the FIX-02 contract clause by clause: only
// a TRAILING ":<digits>" run is a line suffix; anything else comes back whole
// with line 0. Each row documents one clause.
func TestRenderSARIF_ParseLine(t *testing.T) {
	tests := []struct {
		name     string
		line     *string
		wantFile string
		wantLine int
	}{
		{"file:line", strPtr("src/app.py:42"), "src/app.py", 42},
		{"file only", strPtr("src/app.py"), "src/app.py", 0},
		{"nil", nil, "", 0},
		{"empty", strPtr(""), "", 0},
		{"deep path", strPtr("src/pkg/handler.go:100"), "src/pkg/handler.go", 100},
		{"sast file:line", strPtr("app/views.py:674"), "app/views.py", 674},

		// FIX-02: a URL is never a "file:line". The pre-fix splitter turned
		// the first into filePath "https" and the second into filePath
		// "https://host" + a fabricated startLine 8080.
		{"url", strPtr("https://api.example.com/openapi.json"), "https://api.example.com/openapi.json", 0},
		{"url with port", strPtr("https://host:8080/api/x"), "https://host:8080/api/x", 0},
		// A URL that really does end in ":<digits>" is indistinguishable from
		// a line suffix by this rule, and is consumed as one. RenderSARIF's
		// looksLikeURLPath guard is what keeps the leftover out of a
		// physicalLocation.
		{"url with trailing line number", strPtr("https://host/api/x:42"), "https://host/api/x", 42},
		{"bare scheme with port", strPtr("https:8080"), "https", 8080},

		// A Windows drive path keeps its "C:" — the colon is not trailing.
		{"windows drive path", strPtr(`C:\src\app.go:42`), `C:\src\app.go`, 42},

		// Manifest-shaped lines from the deps scanners: no suffix, no line.
		{"manifest name", strPtr("requirements.txt"), "requirements.txt", 0},

		// Pre-existing behaviour, reproduced on purpose and out of FIX-02's
		// scope: only the LAST segment is considered, so "file:line:col"
		// still leaves ":42" glued to the path.
		{"file line col", strPtr("src/app.py:42:10"), "src/app.py:42", 10},

		// Everything that is not an all-digit trailing run stays whole.
		{"non numeric suffix", strPtr("file.py:notanumber"), "file.py:notanumber", 0},
		{"empty suffix keeps colon", strPtr("src/app.py:"), "src/app.py:", 0},
		{"negative suffix", strPtr("src/app.py:-5"), "src/app.py:-5", 0},
		{"overflowing digits", strPtr("src/app.py:99999999999999999999"), "src/app.py:99999999999999999999", 0},

		// A leading ":<digits>" is a legal (if useless) suffix parse: the
		// path half is empty, which RenderSARIF then treats as "no artifact".
		{"leading colon digits", strPtr(":42"), "", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, line := parseLine(tt.line)
			if file != tt.wantFile {
				t.Errorf("parseLine() file = %q, want %q", file, tt.wantFile)
			}
			if line != tt.wantLine {
				t.Errorf("parseLine() line = %d, want %d", line, tt.wantLine)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}

// TestLooksLikeURLPath pins the narrowness of the FIX-02 URL guard. The
// Windows and CWE rows are the ones that matter: reusing uriSchemeRE (which
// matches any RFC 3986 scheme prefix, "C:" included) would send every Windows
// whitebox finding to the logicalLocations branch.
func TestLooksLikeURLPath(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://api.example.com/openapi.json", true},
		{"http://host/x", true},
		{"ws://host/socket", true},
		{"https", true},
		{"HTTPS", true},
		{"  https  ", true},
		{"javascript", true},
		{`C:\src\app.go`, false},
		{"src/app.py", false},
		{"requirements.txt", false},
		{"Dockerfile", false},
		{"https-config.yaml", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := looksLikeURLPath(tt.in); got != tt.want {
				t.Errorf("looksLikeURLPath(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestRenderSARIF_URLLineDoesNotBecomeFilePath is the FIX-02 regression test,
// modelled on the real producer: python/analyzers/spec_parser.py stamps the
// spec path into `line`, and that path can be an https:// URL. Pre-fix the
// emitter published artifactLocation.uri "https".
//
// Note what the fix is NOT: the logicalLocations branch below already
// produced the right answer for this finding shape. The bug was feeding it a
// non-empty `line` so it never ran.
func TestRenderSARIF_URLLineDoesNotBecomeFilePath(t *testing.T) {
	var buf bytes.Buffer
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Spec missing security scheme", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Category: "auth",
			Endpoint: "https://api.example.com/openapi.json",
			Line:     strPtr("https://api.example.com/openapi.json"),
			Evidence: "no securitySchemes declared", Fix: "declare one",
			Confidence: models.ConfidenceMedium,
		},
	}
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	if strings.Contains(buf.String(), `"uri": "https"`) {
		t.Errorf("emitted the pre-fix bogus artifact uri \"https\":\n%s", buf.String())
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	locs := log.Runs[0].Results[0].Locations
	if len(locs) != 1 {
		t.Fatalf("expected 1 location, got %d", len(locs))
	}
	if locs[0].PhysicalLocation != nil {
		t.Errorf("a URL is not a file: physicalLocation should be nil, got %+v", locs[0].PhysicalLocation)
	}
	if len(locs[0].LogicalLocations) != 1 {
		t.Fatalf("expected 1 logical location, got %d", len(locs[0].LogicalLocations))
	}
	if got := locs[0].LogicalLocations[0].Name; got != "https://api.example.com/openapi.json" {
		t.Errorf("logical location name = %q, want the full URL", got)
	}
	if got := locs[0].LogicalLocations[0].Kind; got != "endpoint" {
		t.Errorf("logical location kind = %q, want endpoint", got)
	}
}

// TestRenderSARIF_URLWithPortDoesNotFabricateLineNumber covers the nastier
// half of FIX-02. "https://host:8080/api/x" split into three parts, Sscanf
// read 8080 out of "8080/api/x", and the emitter published uri "host" (the
// scheme having been stripped by normalizeArtifactURI) with startLine 8080 —
// a line number that was never observed, in a file that does not exist.
func TestRenderSARIF_URLWithPortDoesNotFabricateLineNumber(t *testing.T) {
	var buf bytes.Buffer
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Spec served over a nonstandard port", Severity: models.SeverityLow,
			Source: models.SourceWhitebox, Category: "auth",
			Endpoint: "https://host:8080/api/x", Line: strPtr("https://host:8080/api/x"),
			Confidence: models.ConfidenceLow,
		},
	}
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	if strings.Contains(buf.String(), "8080") && strings.Contains(buf.String(), `"startLine"`) {
		t.Errorf("output still carries a startLine near the port:\n%s", buf.String())
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, loc := range log.Runs[0].Results[0].Locations {
		if loc.PhysicalLocation != nil {
			t.Fatalf("expected no physicalLocation for a URL line, got %+v", loc.PhysicalLocation)
		}
	}
	if got := log.Runs[0].Results[0].Locations[0].LogicalLocations[0].Name; got != "https://host:8080/api/x" {
		t.Errorf("logical location name = %q, want the full URL", got)
	}
}

// TestRenderSARIF_BareSchemeLineFallsBackToEndpoint guards the
// bareURISchemes half of looksLikeURLPath. "https:8080" parses as a legal
// path+suffix ("https", 8080) — the leftover of a URL, not a file — so the
// finding must fall through to its endpoint.
func TestRenderSARIF_BareSchemeLineFallsBackToEndpoint(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing auth", Severity: models.SeverityHigh,
			Source: models.SourceBlackbox, Category: "auth", Endpoint: "GET /api/users",
			Line: strPtr("https:8080"), Confidence: models.ConfidenceHigh,
		},
	}
	locs := renderAndDecode(t, findings)[0].Locations
	if len(locs) != 1 {
		t.Fatalf("expected 1 location, got %d", len(locs))
	}
	if locs[0].PhysicalLocation != nil {
		t.Errorf("a bare scheme is not a file: got %+v", locs[0].PhysicalLocation)
	}
	if got := locs[0].LogicalLocations[0].Name; got != "GET /api/users" {
		t.Errorf("logical location name = %q, want the endpoint", got)
	}
}

// TestRenderSARIF_WindowsPathStaysPhysical is the negative control for the
// looksLikeURLPath narrowness constraint. It fails if anyone swaps the guard
// for uriSchemeRE, which matches the "C:" drive prefix.
func TestRenderSARIF_WindowsPathStaysPhysical(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Hardcoded secret", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Category: "secrets",
			Line: strPtr(`C:\src\app.go:42`), Evidence: "apiKey := \"redacted\"",
			Confidence: models.ConfidenceHigh,
		},
	}
	locs := renderAndDecode(t, findings)[0].Locations
	if len(locs) != 1 || locs[0].PhysicalLocation == nil {
		t.Fatalf("a Windows path must stay a physical location, got %+v", locs)
	}
	if locs[0].PhysicalLocation.Region == nil || locs[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("expected startLine 42, got %+v", locs[0].PhysicalLocation.Region)
	}
}

// TestRenderSARIF_URLLineWithNoEndpointStillYieldsLocation is the working
// rule 3 guard on the FIX-02 fallback: a URL-shaped `line` on a finding with
// no endpoint at all is DE-ESCALATED to a logical location, never dropped.
func TestRenderSARIF_URLLineWithNoEndpointStillYieldsLocation(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Spec fetched over https", Severity: models.SeverityInfo,
			Source: models.SourceWhitebox, Category: "auth",
			Endpoint: "", AffectedEndpoints: nil,
			Line: strPtr("https://host/spec.json"), Confidence: models.ConfidenceLow,
		},
	}
	locs := renderAndDecode(t, findings)[0].Locations
	if len(locs) != 1 {
		t.Fatalf("expected exactly 1 (de-escalated, not deleted) location, got %d", len(locs))
	}
	if locs[0].PhysicalLocation != nil {
		t.Errorf("expected no physicalLocation, got %+v", locs[0].PhysicalLocation)
	}
	if got := locs[0].LogicalLocations[0].Name; got != "https://host/spec.json" {
		t.Errorf("logical location name = %q, want the URL", got)
	}
	if got := locs[0].LogicalLocations[0].Kind; got != "endpoint" {
		t.Errorf("logical location kind = %q, want endpoint", got)
	}
}

func TestRenderSARIF_WhiteboxLocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	line := "src/config.py:14"
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Hardcoded secret", Severity: models.SeverityCritical,
			Source: models.SourceWhitebox, Category: "secrets", Endpoint: "src/config.py:14",
			Evidence: "API_KEY = 'sk-live-...'", Fix: "Use env var", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-798"}, Line: &line,
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	result := log.Runs[0].Results[0]
	if len(result.Locations) == 0 {
		t.Fatal("expected location for whitebox finding")
	}
	loc := result.Locations[0]
	if loc.PhysicalLocation == nil {
		t.Fatal("expected physical location for whitebox finding")
	}
	if loc.PhysicalLocation.ArtifactLocation.URI != "src/config.py" {
		t.Errorf("expected URI src/config.py, got %s", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 14 {
		t.Fatal("expected start line 14")
	}
	// FIX-13.4: the code line lives in the region snippet, and the message is
	// a description of the finding rather than a copy of the source.
	if loc.PhysicalLocation.Region.Snippet == nil ||
		loc.PhysicalLocation.Region.Snippet.Text != "API_KEY = 'sk-live-...'" {
		t.Errorf("expected the evidence as region.snippet.text, got %+v", loc.PhysicalLocation.Region.Snippet)
	}
	if want := "Hardcoded secret at src/config.py:14"; result.Message.Text != want {
		t.Errorf("message.text = %q, want %q", result.Message.Text, want)
	}
}

func TestRenderSARIF_BlackboxLocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing auth", Severity: models.SeverityCritical,
			Source: models.SourceBlackbox, Category: "auth", Endpoint: "GET /api/users",
			Evidence: "200 without auth", Fix: "Add auth", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-306"},
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	result := log.Runs[0].Results[0]
	if len(result.Locations) == 0 {
		t.Fatal("expected location for blackbox finding")
	}
	loc := result.Locations[0]
	if len(loc.LogicalLocations) == 0 {
		t.Fatal("expected logical location for blackbox finding")
	}
	if loc.LogicalLocations[0].Name != "GET /api/users" {
		t.Errorf("expected endpoint name, got %s", loc.LogicalLocations[0].Name)
	}
	if loc.LogicalLocations[0].Kind != "endpoint" {
		t.Errorf("expected kind endpoint, got %s", loc.LogicalLocations[0].Kind)
	}
}

// TestRenderSARIF_AffectedEndpointsAsMultipleLocations covers TASK-088:
// a deduplicated finding should serialize each affected endpoint as its
// own SARIFLocation under the result. Per SARIF 2.1.0 §3.27.12, multiple
// locations on a result mean "this issue applies to all of them" — exactly
// the semantics we want.
func TestRenderSARIF_AffectedEndpointsAsMultipleLocations(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing CSP", Severity: models.SeverityMedium,
			Source: models.SourceBlackbox, Category: "headers",
			Endpoint:          "GET /api/users",
			AffectedEndpoints: []string{"GET /api/users", "GET /api/posts", "POST /api/login"},
			Evidence:          "no CSP header observed", Fix: "Add Content-Security-Policy",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-693"},
		},
	}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	results := log.Runs[0].Results
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	locs := results[0].Locations
	if len(locs) != 3 {
		t.Fatalf("expected 3 SARIFLocation entries (one per affected endpoint), got %d", len(locs))
	}
	gotNames := []string{
		locs[0].LogicalLocations[0].Name,
		locs[1].LogicalLocations[0].Name,
		locs[2].LogicalLocations[0].Name,
	}
	wantSet := map[string]bool{"GET /api/users": true, "GET /api/posts": true, "POST /api/login": true}
	for _, n := range gotNames {
		if !wantSet[n] {
			t.Errorf("unexpected endpoint name in SARIFLocation: %q (got names: %v)", n, gotNames)
		}
	}
}

// TestNormalizeArtifactURI covers F-L3: an artifactLocation.uri must
// never carry a scheme (javascript:/http://), an absolute path, or a
// ".." traversal — SARIF consumers resolve these against the project
// root.
func TestNormalizeArtifactURI(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain relative", "src/app.py", "src/app.py"},
		{"javascript scheme", "javascript:alert(1)", "alert(1)"},
		{"http scheme", "http://evil.com/x", "evil.com/x"},
		{"https scheme", "https://evil.com/x", "evil.com/x"},
		{"file scheme", "file:///etc/passwd", "etc/passwd"},
		{"data scheme", "data:text/html,evil", "text/html,evil"},
		{"absolute path", "/etc/passwd", "etc/passwd"},
		{"parent traversal", "../../etc/passwd", "etc/passwd"},
		{"embedded traversal", "src/../../secret", "src/secret"},
		{"current-dir segments", "./a/./b", "a/b"},
		{"windows separators + traversal", "..\\..\\windows\\system32", "windows/system32"},
		{"collapses double slash", "a//b", "a/b"},
		{"control char stripped", "src/\x07app.py", "src/app.py"},
		{"empty", "", ""},
		{"only traversal", "../..", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeArtifactURI(tt.in)
			if got != tt.want {
				t.Errorf("normalizeArtifactURI(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRenderSARIF_RejectsTraversalAndSchemeURI is the F-L3 integration
// check: a whitebox finding whose Line carries a traversal/scheme path
// must serialize a safe relative artifactLocation.uri.
func TestRenderSARIF_RejectsTraversalAndSchemeURI(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	line := "../../etc/passwd:14"
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Traversal path", Severity: models.SeverityHigh,
			Source: models.SourceWhitebox, Category: "secrets",
			Endpoint: "../../etc/passwd:14", Evidence: "x", Fix: "y",
			Confidence: models.ConfidenceHigh, References: []string{}, Line: &line,
		},
	}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if strings.Contains(uri, "..") {
		t.Errorf("artifactLocation.uri must not contain '..': %q", uri)
	}
	if strings.HasPrefix(uri, "/") {
		t.Errorf("artifactLocation.uri must be relative: %q", uri)
	}
	if uri != "etc/passwd" {
		t.Errorf("expected normalized uri 'etc/passwd', got %q", uri)
	}
}

// TestRenderSARIF_NeutralizesControlAndBidi is the F-L3 integration
// check for message/name/tags: bidi and control chars in untrusted
// finding fields must not survive into the SARIF output.
func TestRenderSARIF_NeutralizesControlAndBidi(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID:       "SEC-001",
			Title:    "SQL" + rlo + "injection",
			Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Category: "inj" + zwsp + "ection",
			Endpoint: "GET /api" + rlo + "/users",
			Evidence: "payload" + zwsp + "=1",
			Fix:      "use" + rlo + "params",
			// A reference tag carrying a control char (and a legit CWE).
			References: []string{"CWE-89", "tag" + zwsp + "evil"},
			Confidence: models.ConfidenceHigh,
		},
	}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	out := buf.String()
	for _, bad := range []string{rlo, zwsp} {
		if strings.Contains(out, bad) {
			t.Errorf("SARIF output still contains a bidi/zero-width char %U", []rune(bad)[0])
		}
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if containsAnyNeutralized(rule.Name) {
		t.Errorf("rule.Name not neutralized: %q", rule.Name)
	}
	if containsAnyNeutralized(rule.Help.Text) {
		t.Errorf("rule.Help.Text not neutralized: %q", rule.Help.Text)
	}
	if containsAnyNeutralized(rule.Properties.Category) {
		t.Errorf("rule.Properties.Category not neutralized: %q", rule.Properties.Category)
	}
	for _, tag := range rule.Properties.Tags {
		if containsAnyNeutralized(tag) {
			t.Errorf("rule tag not neutralized: %q", tag)
		}
	}
	res := log.Runs[0].Results[0]
	if containsAnyNeutralized(res.Message.Text) {
		t.Errorf("result.Message.Text not neutralized: %q", res.Message.Text)
	}
	if containsAnyNeutralized(res.Locations[0].LogicalLocations[0].Name) {
		t.Errorf("logical location Name not neutralized: %q", res.Locations[0].LogicalLocations[0].Name)
	}
}

// TestRenderSARIF_HelpURIUnchanged confirms F-L3 left the existing
// http/https helpUri filtering intact (we explicitly do NOT touch it).
func TestRenderSARIF_HelpURIUnchanged(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "X", Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Endpoint: "GET /x", References: []string{"https://owasp.org/api-security"},
		},
	}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)
	if log.Runs[0].Tool.Driver.Rules[0].HelpURI != "https://owasp.org/api-security" {
		t.Errorf("helpUri should pass through unchanged, got %q",
			log.Runs[0].Tool.Driver.Rules[0].HelpURI)
	}
}

func TestRenderSARIF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	err := RenderSARIF(&buf, nil, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(log.Runs[0].Results))
	}
}

func TestRenderSARIF_RuleProperties(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "SQL Injection", Severity: models.SeverityCritical,
			Source: models.SourceBlackbox, Category: "injection", Endpoint: "POST /api/search",
			Evidence: "Response delayed", Fix: "Use parameterized queries", Confidence: models.ConfidenceHigh,
			References: []string{"CWE-89"},
		},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties.Category != "injection" {
		t.Errorf("expected category injection, got %s", rule.Properties.Category)
	}
	if rule.Properties.Confidence != "HIGH" {
		t.Errorf("expected confidence HIGH, got %s", rule.Properties.Confidence)
	}
	if rule.Help.Text != "Use parameterized queries" {
		t.Errorf("expected fix text in help, got %s", rule.Help.Text)
	}
}

// TestRenderSARIF_RulesDedupedByCheckType is the regression test for TASK-083.
// Pre-fix, the rule dedup keyed on Finding.ID (per-instance, never duplicates),
// so 21 findings of "Missing CSP header" produced 21 distinct rules. After
// the fix, identical (category, title) collapse into one rule referenced N
// times — which is what GitHub Code Scanning expects for grouping.
func TestRenderSARIF_RulesDedupedByCheckType(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	// Same check fired across three endpoints — should yield 1 rule, 3 results.
	findings := []models.Finding{
		{ID: "SEC-001", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "GET /api/users", References: []string{}},
		{ID: "SEC-002", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "GET /api/orders", References: []string{}},
		{ID: "SEC-003", Category: "headers", Title: "Missing Content-Security-Policy header",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Endpoint: "POST /api/orders", References: []string{}},
		// A different check; should produce a second rule.
		{ID: "SEC-004", Category: "cors", Title: "CORS reflects arbitrary origin",
			Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Endpoint: "GET /api/users", References: []string{}},
	}

	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}

	rules := log.Runs[0].Tool.Driver.Rules
	results := log.Runs[0].Results

	if len(rules) != 2 {
		t.Fatalf("expected 2 unique rules (1 headers + 1 cors), got %d:\n%s",
			len(rules), buf.String())
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}

	// All three "headers" findings should share the same ruleId, and that ruleId
	// must match the rule's stable ID (not a per-finding SEC-NNN).
	headersRuleID := ""
	for _, r := range results[:3] {
		if headersRuleID == "" {
			headersRuleID = r.RuleID
		}
		if r.RuleID != headersRuleID {
			t.Errorf("expected identical ruleId across same-check findings, got %q vs %q",
				r.RuleID, headersRuleID)
		}
	}
	if headersRuleID == "SEC-001" || headersRuleID == "SEC-002" {
		t.Errorf("ruleId %q looks like per-finding ID — TASK-083 regressed", headersRuleID)
	}
	if headersRuleID == "" || results[3].RuleID == headersRuleID {
		t.Errorf("cors finding should have a different ruleId from headers; got %q vs %q",
			results[3].RuleID, headersRuleID)
	}

	// Result.ruleIndex must point to the dedup'd rule.
	for i, r := range results[:3] {
		if r.RuleIndex < 0 || r.RuleIndex >= len(rules) || rules[r.RuleIndex].ID != headersRuleID {
			t.Errorf("result[%d].ruleIndex=%d does not point to headers rule", i, r.RuleIndex)
		}
	}
}

func TestRenderSARIF_RuleIndex(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Issue 1", Severity: models.SeverityHigh, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-002", Title: "Issue 2", Severity: models.SeverityMedium, Source: models.SourceBlackbox, References: []string{}},
		{ID: "SEC-003", Title: "Issue 3", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	for i, result := range log.Runs[0].Results {
		if result.RuleIndex != i {
			t.Errorf("result %d: expected ruleIndex %d, got %d", i, i, result.RuleIndex)
		}
	}
}

func TestRenderSARIF_Invocation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}

	err := RenderSARIF(&buf, sampleFindings(), meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	if len(log.Runs[0].Invocations) == 0 {
		t.Fatal("expected invocation")
	}
	if !log.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("expected executionSuccessful to be true")
	}
}

// TestRenderSARIF_ExecutionSuccessfulFalseOnScannerFailure verifies F-L13:
// a recorded scanner failure flips executionSuccessful to false and emits a
// toolExecutionNotification, so SARIF consumers see a degraded run. Every
// non-ok entry is now itemised, so the skip alongside the failure also
// produces a notification; this test pins down only the failure's.
func TestRenderSARIF_ExecutionSuccessfulFalseOnScannerFailure(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Version: "dev",
		ScannerStatus: []ScannerStatus{
			{Name: "secrets", State: ScannerOK},
			{Name: "govulncheck", State: ScannerSkipped, Detail: "offline mode"},
			{Name: "pip", State: ScannerFailed, Detail: "osv.dev returned 503"},
		},
	}

	if err := RenderSARIF(&buf, sampleFindings(), meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	json.Unmarshal(buf.Bytes(), &log)

	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("expected executionSuccessful=false when a scanner failed")
	}
	if len(inv.ToolExecutionNotifications) != 2 {
		t.Fatalf("expected 2 notifications (one per non-ok entry), got %d", len(inv.ToolExecutionNotifications))
	}
	var errorNotifications []SARIFNotification
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "error" {
			errorNotifications = append(errorNotifications, n)
		}
	}
	if len(errorNotifications) != 1 {
		t.Fatalf("expected exactly 1 notification at level error, got %d: %+v", len(errorNotifications), inv.ToolExecutionNotifications)
	}
	n := errorNotifications[0]
	if !strings.Contains(n.Message.Text, "pip") || !strings.Contains(n.Message.Text, "503") {
		t.Errorf("notification message %q should name the failed scanner and detail", n.Message.Text)
	}
}

func renderSARIFLog(t *testing.T, meta ScanMetadata) SARIFLog {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, sampleFindings(), meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	return log
}

// Skips alone keep executionSuccessful=true (default CLI mode is
// unchanged) but every non-ok analyzer is now itemised as a note.
func TestRenderSARIF_SkipOnlyIsSuccessfulWithNotes(t *testing.T) {
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: []ScannerStatus{
		{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline, Detail: "--offline"},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonNotApplicable, Detail: "no --code"},
	}})
	inv := log.Runs[0].Invocations[0]
	if !inv.ExecutionSuccessful {
		t.Error("skips alone must not flip executionSuccessful in default mode")
	}
	if len(inv.ToolExecutionNotifications) != 2 {
		t.Fatalf("expected one notification per non-ok entry, got %d", len(inv.ToolExecutionNotifications))
	}
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level != "note" {
			t.Errorf("disabled/not_applicable must be level note, got %q", n.Level)
		}
	}
}

func TestRenderSARIF_NotificationLevelsFollowClass(t *testing.T) {
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: []ScannerStatus{
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "semgrep binary not installed"},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget, Detail: "yarn.lock"},
		{Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError, Detail: "osv.dev returned HTTP 503"},
		{Name: "textscan", State: ScannerSkipped}, // legacy: no reason → unknown
	}})
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("a failed entry must flip executionSuccessful in default mode")
	}
	got := map[string]string{}
	for _, n := range inv.ToolExecutionNotifications {
		name := strings.SplitN(n.Message.Text, ":", 2)[0]
		got[name] = n.Level
	}
	want := map[string]string{"semgrep": "warning", "npm": "note", "pip": "error", "textscan": "warning"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("levels = %v, want %v", got, want)
	}
	if _, ok := got["secrets"]; ok {
		t.Error("ok entries must not produce notifications")
	}
}

func TestRenderSARIF_StrictModeFailsOnRequiredGap(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}, {Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag, Detail: "--fast"}}
	cov := BuildCoverage(status, []string{"semgrep"}, true)
	log := renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: status, Coverage: &cov})
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Fatal("strict run with required_gaps must be unsuccessful even though configured_complete is true")
	}
	found := false
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "error" && strings.Contains(n.Message.Text, "required analyzer semgrep not delivered") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an error notification for the required gap, got %+v", inv.ToolExecutionNotifications)
	}
	// The same status without strict is successful: disabled is not an engine gap.
	covLoose := BuildCoverage(status, nil, false)
	if !renderSARIFLog(t, ScanMetadata{Version: "dev", ScannerStatus: status, Coverage: &covLoose}).Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("non-strict run with only a disabled analyzer must be successful")
	}
}

func TestRenderSARIF_HostedIncompleteIsUnsuccessfulAndKeepsBlockResults(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}}
	cov := BuildCoverage(status, nil, false)
	meta := ScanMetadata{Version: "3.4.0", ScannerStatus: status, Coverage: &cov,
		ReleaseDecision: "block", CoverageState: "incomplete", DecisionPolicyVersion: "2.0.0",
		DecisionRationale: json.RawMessage(`{"missing_coverage":[{"scanner":"python-engine","state":"unavailable"}]}`)}
	log := renderSARIFLog(t, meta)
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Fatal("hosted export with coverage_state=incomplete must be unsuccessful regardless of the verdict")
	}
	warned := false
	for _, n := range inv.ToolExecutionNotifications {
		if n.Level == "warning" && strings.HasPrefix(n.Message.Text, "Required coverage incomplete") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected the coverage warning, got %+v", inv.ToolExecutionNotifications)
	}
	if len(log.Runs[0].Results) != len(sampleFindings()) {
		t.Fatal("results must be untouched by the coverage state")
	}
	props := log.Runs[0].Properties
	if props["fendix/release"] == nil || props["fendix/coverage"] == nil {
		t.Fatalf("property bag must carry release and coverage, got %v", props)
	}
	rel := props["fendix/release"].(map[string]any)
	if rel["release_decision"] != "block" || rel["coverage_state"] != "incomplete" {
		t.Fatalf("release properties = %v", rel)
	}
}

func TestRenderSARIF_PrettyPrinted(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Version: "dev"}
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Test", Severity: models.SeverityLow, Source: models.SourceBlackbox, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	output := buf.String()
	// Pretty-printed JSON should contain newlines and indentation
	if len(output) < 50 {
		t.Error("output too short to be pretty-printed")
	}
}

// TestRenderSARIF_SchemaValidation validates the SARIF output against
// the key structural requirements of SARIF 2.1.0 schema:
// - Required top-level fields: version, $schema, runs
// - Required run fields: tool, results
// - Required tool fields: driver with name, rules
// - Required result fields: ruleId, ruleIndex, level, message
// - Level values: "error", "warning", or "note"
// - Rules match results by index
func TestRenderSARIF_SchemaValidation(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:    "https://api.example.com",
		StartedAt: time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
		Duration:  "12.5s",
		Version:   "1.0.0",
		Mode:      "hybrid",
	}

	line := "src/app.py:42"
	findings := []models.Finding{
		{ID: "SEC-001", Title: "Critical Auth", Severity: models.SeverityCritical, Source: models.SourceBlackbox,
			Category: "auth", Endpoint: "GET /api/users", Evidence: "200 without auth", Fix: "Add auth",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-306", "OWASP-A01"}},
		{ID: "SEC-002", Title: "Hardcoded Secret", Severity: models.SeverityHigh, Source: models.SourceWhitebox,
			Category: "secrets", Endpoint: "src/app.py:42", Evidence: "secret=...", Fix: "Use env var",
			Confidence: models.ConfidenceMedium, References: []string{"CWE-798"}, Line: &line},
		{ID: "SEC-003", Title: "Missing HSTS", Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Category: "headers", Endpoint: "GET /api/health", Evidence: "No HSTS header", Fix: "Add HSTS",
			Confidence: models.ConfidenceHigh, References: []string{"CWE-319"}},
		{ID: "SEC-004", Title: "Server Version", Severity: models.SeverityInfo, Source: models.SourceBlackbox,
			Category: "info_disclosure", Endpoint: "GET /", Evidence: "Server: nginx/1.21", Fix: "Remove version",
			Confidence: models.ConfidenceLow, References: []string{}},
	}

	err := RenderSARIF(&buf, findings, meta)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	// Parse as raw JSON to validate structure
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// 1. Top-level required fields
	if raw["version"] != "2.1.0" {
		t.Errorf("version must be 2.1.0, got %v", raw["version"])
	}
	schema, ok := raw["$schema"].(string)
	if !ok || schema == "" {
		t.Error("$schema must be a non-empty string")
	}
	runs, ok := raw["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("runs must be a non-empty array")
	}

	// 2. Run structure
	run := runs[0].(map[string]interface{})
	tool, ok := run["tool"].(map[string]interface{})
	if !ok {
		t.Fatal("run.tool must be an object")
	}
	driver, ok := tool["driver"].(map[string]interface{})
	if !ok {
		t.Fatal("run.tool.driver must be an object")
	}
	if driver["name"] != "Fendix" {
		t.Errorf("driver.name must be Fendix, got %v", driver["name"])
	}
	if _, ok := driver["version"].(string); !ok {
		t.Error("driver.version must be a string")
	}
	if _, ok := driver["informationUri"].(string); !ok {
		t.Error("driver.informationUri must be a string")
	}

	// 3. Rules array
	rules, ok := driver["rules"].([]interface{})
	if !ok {
		t.Fatal("driver.rules must be an array")
	}
	if len(rules) != len(findings) {
		t.Errorf("expected %d rules, got %d", len(findings), len(rules))
	}

	// Validate each rule has required fields
	validLevels := map[string]bool{"error": true, "warning": true, "note": true}
	for i, r := range rules {
		rule := r.(map[string]interface{})
		if _, ok := rule["id"].(string); !ok {
			t.Errorf("rule[%d].id must be a string", i)
		}
		if _, ok := rule["shortDescription"].(map[string]interface{}); !ok {
			t.Errorf("rule[%d].shortDescription must be an object", i)
		}
		help, ok := rule["help"].(map[string]interface{})
		if !ok {
			t.Errorf("rule[%d].help must be an object", i)
		}
		if _, ok := help["text"].(string); !ok {
			t.Errorf("rule[%d].help.text must be a string", i)
		}
		cfg := rule["defaultConfiguration"].(map[string]interface{})
		level := cfg["level"].(string)
		if !validLevels[level] {
			t.Errorf("rule[%d].defaultConfiguration.level = %q is not a valid SARIF level", i, level)
		}
	}

	// 4. Results array
	results, ok := run["results"].([]interface{})
	if !ok {
		t.Fatal("run.results must be an array")
	}
	if len(results) != len(findings) {
		t.Errorf("expected %d results, got %d", len(findings), len(results))
	}

	for i, r := range results {
		result := r.(map[string]interface{})
		ruleID, ok := result["ruleId"].(string)
		if !ok || ruleID == "" {
			t.Errorf("result[%d].ruleId must be a non-empty string", i)
		}
		ruleIndex, ok := result["ruleIndex"].(float64)
		if !ok {
			t.Errorf("result[%d].ruleIndex must be a number", i)
		}
		if int(ruleIndex) < 0 || int(ruleIndex) >= len(rules) {
			t.Errorf("result[%d].ruleIndex %d out of range", i, int(ruleIndex))
		}
		level, ok := result["level"].(string)
		if !ok || !validLevels[level] {
			t.Errorf("result[%d].level = %q is not a valid SARIF level", i, level)
		}
		msg, ok := result["message"].(map[string]interface{})
		if !ok {
			t.Errorf("result[%d].message must be an object", i)
		}
		if _, ok := msg["text"].(string); !ok {
			t.Errorf("result[%d].message.text must be a string", i)
		}
	}

	// 5. Verify invocations
	invocations, ok := run["invocations"].([]interface{})
	if !ok || len(invocations) == 0 {
		t.Error("run.invocations must be a non-empty array")
	} else {
		inv := invocations[0].(map[string]interface{})
		if inv["executionSuccessful"] != true {
			t.Error("invocation.executionSuccessful must be true")
		}
	}

	// 6. Verify severity level mapping for each finding
	expectedLevels := []string{"error", "error", "warning", "note"}
	for i, r := range results {
		result := r.(map[string]interface{})
		if result["level"] != expectedLevels[i] {
			t.Errorf("result[%d] level = %q, expected %q", i, result["level"], expectedLevels[i])
		}
	}
}

// TestRenderSARIF_DASTUpgradeCategoriesRoundTrip verifies that findings from
// the new DAST checks (Phase 1 + Phases 6-9) — each carrying its CWE
// reference(s) — round-trip through RenderSARIF into a valid rule with a
// non-empty ruleId, a CWE taxon tag, and a cwe.mitre.org helpUri. The SARIF
// emitter is category-agnostic and ref-driven, so this proves the new
// categories/CWEs serialize correctly with no per-category emitter changes.
func TestRenderSARIF_DASTUpgradeCategoriesRoundTrip(t *testing.T) {
	cases := []struct {
		category string
		title    string
		cwe      string
		severity models.Severity
	}{
		{"cookie", "Session cookie missing HttpOnly flag", "CWE-1004", models.SeverityMedium},
		{"redirect", "Open redirect", "CWE-601", models.SeverityMedium},
		{"injection", "Reflected XSS", "CWE-79", models.SeverityHigh},
		{"ssrf", "SSRF — outbound fetch error leakage", "CWE-918", models.SeverityHigh},
		{"host_header", "Host-header injection", "CWE-644", models.SeverityHigh},
		{"graphql", "GraphQL introspection enabled", "CWE-200", models.SeverityHigh},
		{"method_tamper", "Verb-based access-control bypass", "CWE-650", models.SeverityHigh},
		{"rate_limiting", "No rate limiting observed within N requests", "CWE-770", models.SeverityMedium},
	}

	findings := make([]models.Finding, 0, len(cases))
	for _, c := range cases {
		findings = append(findings, models.Finding{
			Title:      c.title,
			Severity:   c.severity,
			Source:     models.SourceBlackbox,
			Category:   c.category,
			Endpoint:   "GET /probe",
			Evidence:   "evidence for " + c.title,
			Fix:        "remediation for " + c.title,
			References: []string{c.cwe},
			Confidence: models.ConfidenceHigh,
		})
	}

	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://api.example.com", Version: "1.0.0", Mode: "dast"}
	if err := RenderSARIF(&buf, findings, meta); err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != len(cases) {
		t.Fatalf("expected %d deduped rules, got %d", len(cases), len(rules))
	}

	// Each rule must have a non-empty ruleId and surface its CWE taxon.
	byName := map[string]SARIFRule{}
	for _, r := range rules {
		if r.ID == "" {
			t.Errorf("rule %q has empty ruleId", r.Name)
		}
		byName[r.Name] = r
	}
	for _, c := range cases {
		r, ok := byName[c.title]
		if !ok {
			t.Errorf("no SARIF rule emitted for %q (%s)", c.title, c.category)
			continue
		}
		// CWE tag survives into properties.tags.
		hasCWE := false
		for _, tag := range r.Properties.Tags {
			if strings.Contains(tag, c.cwe) {
				hasCWE = true
				break
			}
		}
		if !hasCWE {
			t.Errorf("rule %q missing CWE taxon %s in tags %v", c.title, c.cwe, r.Properties.Tags)
		}
		// helpUri points at the CWE MITRE page.
		num := strings.TrimPrefix(c.cwe, "CWE-")
		if !strings.Contains(r.HelpURI, "cwe.mitre.org/data/definitions/"+num) {
			t.Errorf("rule %q helpUri %q does not reference CWE %s", c.title, r.HelpURI, c.cwe)
		}
	}
}

// TestSARIF_DecisionDrivesLevel covers the v0.24 behavioral change: the
// result level follows the decision status, not raw severity (BLOCK→error,
// WARN→warning), and confidence/status land in result properties.
func TestSARIF_DecisionDrivesLevel(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "blk", Severity: models.SeverityHigh, Category: "x", Status: "BLOCK", ConfidenceScore: 80, ConfidenceBand: "HIGH"},
		{ID: "SEC-002", Title: "wrn", Severity: models.SeverityHigh, Category: "y", Status: "WARN", ConfidenceScore: 45, ConfidenceBand: "MEDIUM"},
	}
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, findings, ScanMetadata{}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	results := log.Runs[0].Results
	if results[0].Level != "error" {
		t.Errorf("BLOCK/HIGH result level = %q, want error", results[0].Level)
	}
	if results[1].Level != "warning" {
		t.Errorf("WARN/HIGH result level = %q, want warning (decision overrides severity)", results[1].Level)
	}
	if results[0].Properties == nil || results[0].Properties.Status != "BLOCK" || results[0].Properties.ConfidenceScore != 80 {
		t.Errorf("decision properties not stamped: %+v", results[0].Properties)
	}
}

// TestSARIF_NoDecisionFallsBackToSeverity confirms byte-compat: unstamped
// findings keep severity-based levels.
func TestSARIF_NoDecisionFallsBackToSeverity(t *testing.T) {
	var buf bytes.Buffer
	_ = RenderSARIF(&buf, []models.Finding{{ID: "SEC-001", Title: "a", Severity: models.SeverityHigh, Category: "x"}}, ScanMetadata{})
	var log SARIFLog
	_ = json.Unmarshal(buf.Bytes(), &log)
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("unstamped HIGH should stay error, got %q", log.Runs[0].Results[0].Level)
	}
}

// TestRenderSARIF_PartialFingerprints covers FIX-13.1 under DECISIONS.md D4:
// the "fendix/v1" key is published ONLY for a finding that already carries a
// real engine-scheme fingerprint. A finding without one gets no key at all —
// never an invented or empty value — because two producers hashing differently
// under one key would flip a finding's identity depending on which path
// rendered the SARIF.
func TestRenderSARIF_PartialFingerprints(t *testing.T) {
	var buf bytes.Buffer
	findings := []models.Finding{
		{
			ID: "SEC-001", Fingerprint: "a1b2c3d4", Title: "Missing auth",
			Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Category: "auth", Endpoint: "GET /api/users", Confidence: models.ConfidenceHigh,
		},
		{
			ID: "SEC-002", Fingerprint: "", Title: "Missing CSP",
			Severity: models.SeverityMedium, Source: models.SourceBlackbox,
			Category: "headers", Endpoint: "GET /api/posts", Confidence: models.ConfidenceHigh,
		},
	}
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	results := log.Runs[0].Results
	// The metadata here announces no algorithm, so the key is the archived-report
	// default — see fingerprintKeyFor.
	key := sarifLegacyFingerprintKey
	if got := results[0].PartialFingerprints[key]; got != "a1b2c3d4" {
		t.Errorf("partialFingerprints[%q] = %q, want a1b2c3d4", key, got)
	}
	if results[1].PartialFingerprints != nil {
		t.Errorf("a finding without a fingerprint must get no key, got %v", results[1].PartialFingerprints)
	}

	// Backward compat: a pre-fingerprint report must stay byte-identical, so
	// the key has to be absent from the raw JSON, not present-and-empty.
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	rawResults := raw["runs"].([]any)[0].(map[string]any)["results"].([]any)
	if _, ok := rawResults[1].(map[string]any)["partialFingerprints"]; ok {
		t.Error("result without a fingerprint still emitted a partialFingerprints key")
	}
}

// TestSARIFSecuritySeverity_FromSeverityOnly locks the exact strings against
// GitHub's bucket thresholds (>=9.0 critical, >=7.0 high, >=4.0 medium,
// >0.0 low). Changing one of these re-ranks every alert already ingested.
func TestSARIFSecuritySeverity_FromSeverityOnly(t *testing.T) {
	tests := []struct {
		sev  models.Severity
		want string
	}{
		{models.SeverityCritical, "9.5"},
		{models.SeverityHigh, "8.0"},
		{models.SeverityMedium, "5.5"},
		{models.SeverityLow, "3.0"},
		{models.SeverityInfo, "1.0"},
		{models.Severity(""), "1.0"},
		{models.Severity("BOGUS"), "1.0"},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			if got := sarifSecuritySeverity(tt.sev); got != tt.want {
				t.Errorf("sarifSecuritySeverity(%q) = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}

// TestRenderSARIF_SecuritySeverityIgnoresConfidence is the working-rule-8
// guard. Two findings of the SAME check at the same severity but opposite
// confidence share one rule; the score must come from severity alone.
func TestRenderSARIF_SecuritySeverityIgnoresConfidence(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Reflected XSS", Category: "injection",
			Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Endpoint: "GET /a", Confidence: models.ConfidenceHigh,
			ConfidenceScore: 95, ConfidenceBand: "HIGH",
		},
		{
			ID: "SEC-002", Title: "Reflected XSS", Category: "injection",
			Severity: models.SeverityHigh, Source: models.SourceBlackbox,
			Endpoint: "GET /b", Confidence: models.ConfidenceLow,
			ConfidenceScore: 5, ConfidenceBand: "LOW",
		},
	}
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 deduped rule, got %d", len(rules))
	}
	if got := rules[0].Properties.SecuritySeverity; got != "8.0" {
		t.Errorf("security-severity = %q, want 8.0 (HIGH) regardless of confidence", got)
	}
}

// TestRenderSARIF_DedupedRuleTakesMaxSeverity is the determinism test for
// FIX-13.2. A rule spans severities for a real reason: the engine's dedupKey
// includes severity, so Deduplicate keeps a same-check pair at two severities
// as two findings, and enforceConsistency caps one occurrence but not another.
// First-wins made the rule's level depend on the input ORDER; max does not.
func TestRenderSARIF_DedupedRuleTakesMaxSeverity(t *testing.T) {
	low := models.Finding{
		ID: "SEC-001", Title: "Reflected XSS", Category: "injection",
		Severity: models.SeverityLow, Source: models.SourceBlackbox,
		Endpoint: "GET /a", Confidence: models.ConfidenceLow,
	}
	crit := models.Finding{
		ID: "SEC-002", Title: "Reflected XSS", Category: "injection",
		Severity: models.SeverityCritical, Source: models.SourceBlackbox,
		Endpoint: "GET /b", Confidence: models.ConfidenceHigh,
	}

	// The two severity-derived rule fields, which are what FIX-13.2 makes a
	// function of the finding SET rather than of its order. Deliberately NOT
	// the whole rule: Name, Help, HelpURI, Properties.Category/Tags/Confidence
	// stay on the pre-existing first-wins path, so `confidence` really does
	// still flip between "LOW" and "HIGH" here depending on input order. That
	// is out of this fix's scope — and an independent reason security-severity
	// must never be derived from confidence, since the value it would read is
	// itself order-dependent.
	severityFields := func(t *testing.T, findings []models.Finding) [2]string {
		t.Helper()
		var buf bytes.Buffer
		if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
			t.Fatalf("RenderSARIF: %v", err)
		}
		var log SARIFLog
		if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		rules := log.Runs[0].Tool.Driver.Rules
		if len(rules) != 1 {
			t.Fatalf("expected 1 deduped rule, got %d", len(rules))
		}
		if got := rules[0].Properties.SecuritySeverity; got != "9.5" {
			t.Errorf("security-severity = %q, want 9.5 (the max severity in the set)", got)
		}
		// The two must never contradict each other: level "note" alongside
		// security-severity "9.5" is a defect, not a nuance.
		if got := rules[0].DefaultConfig.Level; got != "error" {
			t.Errorf("defaultConfiguration.level = %q, want error (the max severity in the set)", got)
		}
		return [2]string{rules[0].DefaultConfig.Level, rules[0].Properties.SecuritySeverity}
	}

	lowFirst := severityFields(t, []models.Finding{low, crit})
	critFirst := severityFields(t, []models.Finding{crit, low})
	if lowFirst != critFirst {
		t.Errorf("rule severity depends on finding order: [LOW,CRITICAL]=%v [CRITICAL,LOW]=%v",
			lowFirst, critFirst)
	}
}

// TestRenderSARIF_AutomationDetails covers FIX-13.3. It asserts on the RAW
// map rather than the typed struct on purpose: that is what proves the key
// sits on the RUN object (SARIF §3.14.3) and not on tool/driver/result.
func TestRenderSARIF_AutomationDetails(t *testing.T) {
	cases := map[string][]models.Finding{
		"with findings": sampleFindings(),
		// A clean run needs the category too — without it the "no alerts"
		// upload cannot clear the previous run's alerts for that category.
		"zero findings": nil,
	}
	for name, findings := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
				t.Fatalf("RenderSARIF: %v", err)
			}
			var raw map[string]any
			if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			run := raw["runs"].([]any)[0].(map[string]any)
			ad, ok := run["automationDetails"].(map[string]any)
			if !ok {
				t.Fatalf("runs[0].automationDetails missing or not an object: %v", run["automationDetails"])
			}
			if ad["id"] != "fendix/scan" {
				t.Errorf("automationDetails.id = %v, want fendix/scan", ad["id"])
			}
			// Negative control: it must not have been hung off the tool.
			tool := run["tool"].(map[string]any)
			if _, ok := tool["automationDetails"]; ok {
				t.Error("automationDetails must live on the run, not on tool")
			}
			if _, ok := tool["driver"].(map[string]any)["automationDetails"]; ok {
				t.Error("automationDetails must live on the run, not on driver")
			}
		})
	}
}

// TestRenderSARIF_MessageIsDescriptionNotEvidence covers FIX-13.4 for a SAST
// finding: message.text is prose, the source line moves to region.snippet.text,
// and the evidence is ALSO kept verbatim in properties (working rule 3 —
// de-escalated, never deleted).
func TestRenderSARIF_MessageIsDescriptionNotEvidence(t *testing.T) {
	const code = "API_KEY = 'sk-live-abc'"
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Hardcoded secret", Severity: models.SeverityCritical,
			Source: models.SourceWhitebox, Category: "secrets",
			Line: strPtr("src/config.py:14"), Evidence: code,
			Confidence: models.ConfidenceHigh,
		},
	}
	r := renderAndDecode(t, findings)[0]
	if want := "Hardcoded secret at src/config.py:14"; r.Message.Text != want {
		t.Errorf("message.text = %q, want %q", r.Message.Text, want)
	}
	if strings.Contains(r.Message.Text, "sk-live-abc") {
		t.Errorf("message.text still carries the raw code line: %q", r.Message.Text)
	}
	snip := r.Locations[0].PhysicalLocation.Region.Snippet
	if snip == nil || snip.Text != code {
		t.Errorf("region.snippet.text = %+v, want %q", snip, code)
	}
	if r.Properties == nil || r.Properties.Evidence != code {
		t.Errorf("properties.evidence = %+v, want %q", r.Properties, code)
	}
}

// TestRenderSARIF_EvidencePreservedForBlackboxFinding is the working-rule-3
// guard for the branch with no physicalLocation: there is no snippet to hold
// the evidence, so properties is its only surviving home.
func TestRenderSARIF_EvidencePreservedForBlackboxFinding(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing auth", Severity: models.SeverityCritical,
			Source: models.SourceBlackbox, Category: "auth", Endpoint: "GET /api/users",
			Evidence: "200 without auth", Confidence: models.ConfidenceHigh,
		},
	}
	r := renderAndDecode(t, findings)[0]
	if r.Locations[0].PhysicalLocation != nil {
		t.Fatalf("blackbox finding should have no physicalLocation, got %+v", r.Locations[0].PhysicalLocation)
	}
	if r.Properties == nil || r.Properties.Evidence != "200 without auth" {
		t.Errorf("properties.evidence = %+v, want the evidence verbatim", r.Properties)
	}
	if want := "Missing auth at GET /api/users"; r.Message.Text != want {
		t.Errorf("message.text = %q, want %q", r.Message.Text, want)
	}
}

// TestRenderSARIF_NoSnippetWithoutLineNumber covers the deps-scanner shape:
// govulncheck/pip/npm set Line to a bare manifest name, so there is a real
// file but no line. SARIF requires region.startLine >= 1, so no region may be
// emitted — and therefore no snippet — while the evidence still survives.
func TestRenderSARIF_NoSnippetWithoutLineNumber(t *testing.T) {
	var buf bytes.Buffer
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Vulnerable dependency", Severity: models.SeverityMedium,
			Source: models.SourceWhitebox, Category: "deps",
			Line: strPtr("requirements.txt"), Evidence: "CVE-2024-1234: description",
			Confidence: models.ConfidenceHigh,
		},
	}
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "dev"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	if strings.Contains(buf.String(), `"startLine": 0`) {
		t.Errorf("emitted an invalid startLine 0:\n%s", buf.String())
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	r := log.Runs[0].Results[0]
	pl := r.Locations[0].PhysicalLocation
	if pl == nil || pl.ArtifactLocation.URI != "requirements.txt" {
		t.Fatalf("expected physicalLocation on requirements.txt, got %+v", pl)
	}
	if pl.Region != nil {
		t.Errorf("expected no region without a line number, got %+v", pl.Region)
	}
	if r.Properties == nil || r.Properties.Evidence != "CVE-2024-1234: description" {
		t.Errorf("properties.evidence = %+v, want the evidence verbatim", r.Properties)
	}
	if want := "Vulnerable dependency at requirements.txt"; r.Message.Text != want {
		t.Errorf("message.text = %q, want %q", r.Message.Text, want)
	}
}

// TestRenderSARIF_MultiEndpointMessageNamesCount proves the message and the
// locations are derived from the SAME branch and cannot disagree: the TASK-088
// deduped fixture yields 3 locations and a message that says so.
func TestRenderSARIF_MultiEndpointMessageNamesCount(t *testing.T) {
	findings := []models.Finding{
		{
			ID: "SEC-001", Title: "Missing CSP", Severity: models.SeverityMedium,
			Source: models.SourceBlackbox, Category: "headers",
			Endpoint:          "GET /api/users",
			AffectedEndpoints: []string{"GET /api/users", "GET /api/posts", "POST /api/login"},
			Evidence:          "no CSP header observed", Confidence: models.ConfidenceHigh,
		},
	}
	r := renderAndDecode(t, findings)[0]
	if len(r.Locations) != 3 {
		t.Fatalf("expected 3 locations, got %d", len(r.Locations))
	}
	if want := "Missing CSP at GET /api/users (+2 more)"; r.Message.Text != want {
		t.Errorf("message.text = %q, want %q", r.Message.Text, want)
	}
}

// TestRenderSARIF_MessageNeverEmpty guards a real pre-fix defect: an
// evidence-less finding produced message.text "", and GitHub rejects an empty
// result message. ruleKeyFor's own fallback is the backstop.
func TestRenderSARIF_MessageNeverEmpty(t *testing.T) {
	findings := []models.Finding{
		{ID: "SEC-001", Title: "", Category: "", Endpoint: "", Evidence: "", Line: nil},
	}
	r := renderAndDecode(t, findings)[0]
	if r.Message.Text == "" {
		t.Fatal("message.text must never be empty")
	}
	if want := "fendix.uncategorized.unnamed"; r.Message.Text != want {
		t.Errorf("message.text = %q, want the ruleKeyFor fallback %q", r.Message.Text, want)
	}
}
