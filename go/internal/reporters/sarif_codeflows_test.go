package reporters

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func lineP(s string) *string { return &s }

// renderAndDecode renders findings to SARIF and decodes the result objects.
func renderAndDecode(t *testing.T, findings []models.Finding) []SARIFResult {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, buf.String())
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	return log.Runs[0].Results
}

func TestRenderSARIF_EmitsCodeFlowForTaintChain(t *testing.T) {
	f := models.Finding{
		ID:         "SEC-001",
		Title:      "SQL injection",
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		SourceTier: models.TierTreeSitter,
		Category:   "injection",
		Endpoint:   "app/views.py:42",
		Line:       lineP("app/views.py:42"),
		Confidence: models.ConfidenceHigh,
		Reachable:  true,
		TaintChain: []models.TaintLink{
			{File: "app/views.py", Line: 40, Expr: "uid = request.GET.get('id')"},
			{File: "app/views.py", Line: 41, Expr: "q = 'SELECT ... ' + uid"},
			{File: "app/views.py", Line: 42, Expr: "cursor.execute(q)"},
		},
	}
	results := renderAndDecode(t, []models.Finding{f})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if len(r.CodeFlows) != 1 {
		t.Fatalf("expected 1 codeFlow, got %d", len(r.CodeFlows))
	}
	tfs := r.CodeFlows[0].ThreadFlows
	if len(tfs) != 1 {
		t.Fatalf("expected 1 threadFlow, got %d", len(tfs))
	}
	locs := tfs[0].Locations
	if len(locs) != 3 {
		t.Fatalf("expected 3 threadFlow locations (source→sink), got %d", len(locs))
	}
	// Order must be preserved source→sink.
	if locs[0].Location.PhysicalLocation.Region.StartLine != 40 {
		t.Errorf("first step should be line 40 (source), got %d", locs[0].Location.PhysicalLocation.Region.StartLine)
	}
	if locs[2].Location.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("last step should be line 42 (sink), got %d", locs[2].Location.PhysicalLocation.Region.StartLine)
	}
	// Each step carries its expression as the location message.
	if locs[0].Location.Message == nil || !strings.Contains(locs[0].Location.Message.Text, "request.GET") {
		t.Errorf("source step missing its expression message: %+v", locs[0].Location.Message)
	}
}

func TestRenderSARIF_StampsProvenanceProperties(t *testing.T) {
	f := models.Finding{
		ID:         "SEC-002",
		Title:      "SQLi",
		Severity:   models.SeverityCritical,
		Source:     models.SourceCorrelated,
		SourceTier: models.TierTreeSitter,
		Category:   "injection",
		Endpoint:   "POST /users",
		Line:       lineP("app/views.py:42"),
		Confidence: models.ConfidenceHigh,
		Reachable:  true,
		Route: &models.Route{
			Method:  "POST",
			Pattern: "/users",
			Handler: "views.create_user",
			File:    "app/urls.py",
			Line:    12,
		},
	}
	r := renderAndDecode(t, []models.Finding{f})[0]
	if r.Properties == nil {
		t.Fatal("expected provenance properties on the result")
	}
	if r.Properties.SourceTier != "tree_sitter_sidecar" {
		t.Errorf("source_tier = %q; want tree_sitter_sidecar", r.Properties.SourceTier)
	}
	if !r.Properties.Reachable {
		t.Error("reachable should be true in properties")
	}
	if r.Properties.RoutePattern != "/users" || r.Properties.RouteMethod != "POST" {
		t.Errorf("route binding not stamped: %+v", r.Properties)
	}
}

func TestRenderSARIF_NoCodeFlowWithoutChain(t *testing.T) {
	f := models.Finding{
		ID:       "SEC-003",
		Title:    "Missing header",
		Severity: models.SeverityLow,
		Source:   models.SourceBlackbox,
		Category: "headers",
		Endpoint: "GET /",
		// The absent Evidence is LOAD-BEARING as of FIX-13.4: evidence is now
		// one of the things sarifResultProperties records, so a fixture with an
		// Evidence value would legitimately produce a non-nil properties object
		// and fail the assertion below. See
		// TestRenderSARIF_EvidenceAloneCreatesProperties for the complement.
		Confidence: models.ConfidenceMedium,
	}
	r := renderAndDecode(t, []models.Finding{f})[0]
	if len(r.CodeFlows) != 0 {
		t.Errorf("blackbox finding without a chain must have no codeFlows, got %d", len(r.CodeFlows))
	}
	if r.Properties != nil {
		t.Errorf("finding with no tier/route/reachable should have nil properties, got %+v", r.Properties)
	}
}

// TestRenderSARIF_EvidenceAloneCreatesProperties is the complement to
// TestRenderSARIF_NoCodeFlowWithoutChain, and the trip-wire for the one slip
// in FIX-13.4 that would silently DELETE evidence: forgetting `evidence == ""`
// in the widened sarifResultProperties nil-guard. Without it every plain
// blackbox finding — no tier, no route, no decision stamp — loses its evidence
// entirely once message.text stops carrying it, which is a working-rule-3
// violation rather than a formatting change.
func TestRenderSARIF_EvidenceAloneCreatesProperties(t *testing.T) {
	f := models.Finding{
		ID:         "SEC-004",
		Title:      "Missing header",
		Severity:   models.SeverityLow,
		Source:     models.SourceBlackbox,
		Category:   "headers",
		Endpoint:   "GET /",
		Evidence:   "x",
		Confidence: models.ConfidenceMedium,
	}
	r := renderAndDecode(t, []models.Finding{f})[0]
	if r.Properties == nil {
		t.Fatal("a finding carrying only evidence must still produce properties")
	}
	if r.Properties.Evidence != "x" {
		t.Errorf("properties.evidence = %q, want x", r.Properties.Evidence)
	}
}
