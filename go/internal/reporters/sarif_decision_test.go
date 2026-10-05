package reporters

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

func renderOneResult(t *testing.T, f models.Finding) map[string]interface{} {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, []models.Finding{f}, ScanMetadata{}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []map[string]interface{} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want exactly one run with one result, got %s", buf.String())
	}
	return doc.Runs[0].Results[0]
}

func decisionBlock(t *testing.T, res map[string]interface{}) map[string]interface{} {
	t.Helper()
	props, ok := res["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("result has no properties block")
	}
	dec, ok := props["decision"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties.decision is missing — the verdict is not auditable from the report")
	}
	return dec
}

// THE EXPORT INVARIANT: every BLOCK must be reconstructable from the exported
// result alone. A consumer must be able to answer "why exactly did this gate my
// build?" without access to the engine.
func TestBlockExportsItsJustification(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:              "Potential SSRF — dynamic URL passed to HTTP client",
		Category:           "injection",
		Severity:           models.SeverityHigh,
		Source:             models.SourceWhitebox,
		Endpoint:           "app/views.py:674",
		Line:               strPtr("app/views.py:674"),
		Status:             "BLOCK",
		DecisionReason:     "severity at or above the --fail-on threshold; corroborated by: reachable taint path",
		IndependentSignals: []string{"reachable taint path"},
		Reachable:          true,
		TaintChain: []models.TaintLink{
			{File: "app/views.py", Line: 652, Expr: "request.query_params.get('url')"},
			{File: "app/views.py", Line: 674, Expr: "requests.get(image_url)"},
		},
	})

	dec := decisionBlock(t, res)
	if dec["status"] != "BLOCK" {
		t.Errorf("decision.status = %v, want BLOCK", dec["status"])
	}
	if reason, _ := dec["reason"].(string); !strings.Contains(reason, "reachable taint path") {
		t.Errorf("decision.reason = %q, does not name what corroborated the verdict", reason)
	}
	sigs, _ := dec["independent_signals"].([]interface{})
	if len(sigs) == 0 {
		t.Error("decision.independent_signals is empty on a BLOCK — invariant violated")
	}
	evi, _ := dec["evidence"].(map[string]interface{})
	if evi["reachable"] != true {
		t.Errorf("decision.evidence.reachable = %v, want true", evi["reachable"])
	}
	if evi["flow_established"] != true {
		t.Errorf("decision.evidence.flow_established = %v, want true", evi["flow_established"])
	}
}

// UNKNOWN MUST STAY UNKNOWN. A field that was never evaluated is ABSENT, never
// false. Rendering unknown as false is the single most misleading thing this
// exporter could do: a consumer cannot tell a cleared check from one that never
// ran.
func TestUnevaluatedEvidenceIsAbsentNotFalse(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:              "Unauthenticated endpoint observed",
		Category:           "auth_bypass",
		Severity:           models.SeverityMedium,
		Source:             models.SourceBlackbox,
		Endpoint:           "GET /status",
		Status:             "WARN",
		DecisionReason:     "severity above threshold but nothing corroborates the claim — needs corroboration to block",
		SelfEvidentSignals: []string{"direct observation of a live response"},
	})

	dec := decisionBlock(t, res)
	evi, _ := dec["evidence"].(map[string]interface{})

	for _, key := range []string{"auth_expectation", "flow_established", "reachable", "source_controlled", "applicability"} {
		if v, present := evi[key]; present {
			t.Errorf("decision.evidence.%s is present (%v) but was never established — "+
				"absence is the only honest encoding of unknown", key, v)
		}
	}
	if _, present := dec["independent_signals"]; present {
		t.Error("independent_signals present on a finding that had none; want the key omitted")
	}
	if sigs, _ := dec["self_evident_signals"].([]interface{}); len(sigs) != 1 {
		t.Errorf("self_evident_signals = %v, want the one signal that did fire", dec["self_evident_signals"])
	}
}

// A declared auth expectation IS evaluated state and must be exported, so a
// reader can see which of the three states drove the claim.
func TestDeclaredAuthExpectationIsExported(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:              "Authentication requirement bypassed",
		Category:           "auth_bypass",
		Severity:           models.SeverityCritical,
		Source:             models.SourceBlackbox,
		Endpoint:           "GET /api/users",
		Status:             "BLOCK",
		DecisionReason:     "severity at or above the --fail-on threshold; corroborated by: contradicted authentication requirement",
		IndependentSignals: []string{"contradicted authentication requirement"},
		AuthExpectation:    models.AuthExpectationRequired,
	})

	evi, _ := decisionBlock(t, res)["evidence"].(map[string]interface{})
	if evi["auth_expectation"] != "required" {
		t.Errorf("decision.evidence.auth_expectation = %v, want %q", evi["auth_expectation"], "required")
	}
}

// A report produced WITHOUT the decision pass (fendix report --input on a
// pre-v0.24 document) must stay byte-identical: no hollow decision block.
func TestNoDecisionBlockWhenNoDecisionPassRan(t *testing.T) {
	res := renderOneResult(t, models.Finding{
		Title:    "Missing Content-Security-Policy header",
		Category: "headers",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
		Endpoint: "GET /",
		Evidence: "Response does not include Content-Security-Policy header",
	})

	props, ok := res["properties"].(map[string]interface{})
	if !ok {
		return // no properties at all is also acceptable here
	}
	if _, present := props["decision"]; present {
		t.Errorf("emitted a decision block for a finding with no Status: %v", props["decision"])
	}
}
