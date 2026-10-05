package engine

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/decision"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// THE CROSS-FORMAT CONTRACT.
//
// Native JSON and SARIF are two SERIALIZERS over one decision model. They may
// differ structurally — SARIF nests the verdict under
// result.properties.decision, native JSON keeps it flat on the finding — but
// they must never differ SEMANTICALLY. A consumer that can only read SARIF has
// to reach the same conclusion as one reading the native report.
//
// This file renders ONE stamped finding into both formats and compares the
// decision semantics field by field. It is deliberately end-to-end from
// evidence: the stamping pass is where a field gets forgotten, so a test that
// hand-built the Finding would pass while the shipped path dropped it.

// decisionSemantics is the normalized verdict, extracted from whichever format
// it came from. Comparing normalized structs (rather than diffing raw JSON) is
// what lets the two formats stay structurally different on purpose.
type decisionSemantics struct {
	Status            string
	ConfidenceScore   int
	ConfidenceBand    string
	IntrinsicSeverity string
	EffectiveRisk     string
	Policy            string
	Override          bool
	Reason            string
	Independent       []string
	SelfEvident       []string
	Reachable         bool
	BreakdownCodes    []string
}

func nativeSemantics(t *testing.T, f models.Finding) decisionSemantics {
	t.Helper()
	var buf bytes.Buffer
	if err := reporters.RenderJSON(&buf, []models.Finding{f}, reporters.ScanMetadata{}); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Findings []struct {
			Status              string                    `json:"status"`
			ConfidenceScore     int                       `json:"confidence_score"`
			ConfidenceBand      string                    `json:"confidence_band"`
			Severity            string                    `json:"severity"`
			DecisionPolicy      string                    `json:"decision_policy"`
			DecisionReason      string                    `json:"decision_reason"`
			PolicyOverride      bool                      `json:"policy_override"`
			IndependentSignals  []string                  `json:"independent_signals"`
			SelfEvidentSignals  []string                  `json:"self_evident_signals"`
			Reachable           bool                      `json:"reachable"`
			ConfidenceBreakdown []models.ConfidenceReason `json:"confidence_breakdown"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal native: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(doc.Findings))
	}
	n := doc.Findings[0]
	codes := make([]string, 0, len(n.ConfidenceBreakdown))
	for _, r := range n.ConfidenceBreakdown {
		codes = append(codes, r.Code)
	}
	return decisionSemantics{
		Status: n.Status, ConfidenceScore: n.ConfidenceScore, ConfidenceBand: n.ConfidenceBand,
		IntrinsicSeverity: n.Severity, EffectiveRisk: "", Policy: n.DecisionPolicy,
		Override: n.PolicyOverride, Reason: n.DecisionReason,
		Independent: n.IndependentSignals, SelfEvident: n.SelfEvidentSignals,
		Reachable: n.Reachable, BreakdownCodes: codes,
	}
}

func sarifSemantics(t *testing.T, f models.Finding) decisionSemantics {
	t.Helper()
	var buf bytes.Buffer
	if err := reporters.RenderSARIF(&buf, []models.Finding{f}, reporters.ScanMetadata{}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties struct {
					Status              string                    `json:"status"`
					ConfidenceScore     int                       `json:"confidence_score"`
					ConfidenceBand      string                    `json:"confidence_band"`
					IntrinsicSeverity   string                    `json:"intrinsic_severity"`
					EffectiveRisk       string                    `json:"effective_risk"`
					Reachable           bool                      `json:"reachable"`
					ConfidenceBreakdown []models.ConfidenceReason `json:"confidence_breakdown"`
					Decision            struct {
						Status         string   `json:"status"`
						Reason         string   `json:"reason"`
						Policy         string   `json:"policy"`
						PolicyOverride bool     `json:"policy_override"`
						Independent    []string `json:"independent_signals"`
						SelfEvident    []string `json:"self_evident_signals"`
					} `json:"decision"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("want 1 run with 1 result")
	}
	p := doc.Runs[0].Results[0].Properties
	codes := make([]string, 0, len(p.ConfidenceBreakdown))
	for _, r := range p.ConfidenceBreakdown {
		codes = append(codes, r.Code)
	}
	// SARIF publishes status in two places by design (properties.status for
	// flat readers, properties.decision.status for the auditable block). They
	// are the same fact, so disagreement is itself a contract break.
	if p.Status != p.Decision.Status {
		t.Errorf("SARIF disagrees with itself: properties.status=%q, decision.status=%q",
			p.Status, p.Decision.Status)
	}
	return decisionSemantics{
		Status: p.Decision.Status, ConfidenceScore: p.ConfidenceScore, ConfidenceBand: p.ConfidenceBand,
		IntrinsicSeverity: p.IntrinsicSeverity, EffectiveRisk: p.EffectiveRisk, Policy: p.Decision.Policy,
		Override: p.Decision.PolicyOverride, Reason: p.Decision.Reason,
		Independent: p.Decision.Independent, SelfEvident: p.Decision.SelfEvident,
		Reachable: p.Reachable, BreakdownCodes: codes,
	}
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stampOne runs the REAL production stamping path over one piece of evidence.
func stampOne(ev evidence.Evidence, failOn string, opts decision.Options) models.Finding {
	evs := []evidence.Evidence{ev}
	fs := evidence.ToFindings(evs)
	stampDecisions(fs, evidence.NewProvenanceIndex(evs), failOn, opts)
	return fs[0]
}

// contractCase is one scenario from the parity spec.
type contractCase struct {
	name       string
	ev         evidence.Evidence
	failOn     string
	opts       decision.Options
	wantStatus string
}

func contractCases() []contractCase {
	// The SHIPPED policy — both CLI flags default to true (see main.go), so a
	// bare Options{} would model a configuration nobody runs. Getting this
	// wrong is the exact trap the DeescalateTests dead-code incident came
	// from: unit tests that build Options{} opt OUT of the shipped behaviour.
	shipped := decision.Options{EnforceConfidence: true, DeescalateTests: true}
	return []contractCase{
		{
			// SCA deterministic BLOCK: vulnerable dependency, production code,
			// high-confidence deterministic detection.
			name: "sca_deterministic_block",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps",
				Confidence: models.ConfidenceHigh, Title: "Vulnerable dependency: django==3.2.0",
				Endpoint: "requirements.txt", Evidence: "django 3.2.0 is affected by CVE-2021-31542",
			},
			failOn: "HIGH", opts: shipped, wantStatus: "BLOCK",
		},
		{
			// SSRF with a proven, reachable source→sink flow.
			name: "ssrf_reachable_flow_block",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceCorrelated, Category: "injection",
				Confidence: models.ConfidenceHigh, Title: "SSRF via user-controlled URL",
				Endpoint: "GET /fetch", Reachable: true, RouteConfirmed: true, ProvenPath: true,
				TaintChain: []models.TaintLink{
					{File: "app/ssrf.py", Line: 9, Expr: "request.args.get(\"url\")"},
					{File: "app/ssrf.py", Line: 10, Expr: "requests.get(target)"},
				},
			},
			failOn: "HIGH", opts: shipped, wantStatus: "BLOCK",
		},
		{
			// SSRF sink only: a dynamic HTTP sink with no source proof.
			name: "ssrf_sink_only_warn",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "injection",
				Confidence: models.ConfidenceMedium, Title: "Dynamic HTTP sink",
				Endpoint: "GET /proxy",
			},
			failOn: "HIGH", opts: shipped, wantStatus: "WARN",
		},
		{
			// Fixture-shaped credential in test code: two benign signals agree.
			name: "fake_api_key_in_tests_info",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "secrets",
				Confidence: models.ConfidenceHigh, Title: "Hardcoded API key or token",
				Endpoint: "tests/test_client.py", InTest: true, Placeholder: true,
			},
			failOn: "HIGH", opts: shipped, wantStatus: "INFO",
		},
		{
			// A REAL provider-anchored credential in a test file gets no
			// fixture de-escalation: the value is not fixture-shaped.
			name: "real_provider_credential_in_tests",
			ev: evidence.Evidence{
				Severity: models.SeverityCritical, Source: models.SourceWhitebox, Category: "secrets",
				Confidence: models.ConfidenceHigh, Title: "Stripe live secret key hardcoded",
				Endpoint: "tests/test_billing.py", InTest: true, Placeholder: false,
			},
			failOn: "HIGH", opts: shipped, wantStatus: "WARN",
		},
		{
			// Vulnerable package installed, affected component positively
			// established as unused → de-escalated WARN.
			name: "sca_component_absent_warn",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps",
				Confidence: models.ConfidenceHigh, Title: "Vulnerable dependency: django==3.2.0",
				Endpoint: "requirements.txt", ComponentNotImported: true,
			},
			failOn: "HIGH", opts: shipped, wantStatus: "WARN",
		},
		{
			// Reachability unknown — absence of an import is NOT evidence of
			// non-reachability, so no de-escalation from absence.
			name: "sca_unresolved_import_no_deescalation",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "deps",
				Confidence: models.ConfidenceHigh, Title: "Vulnerable dependency: requests==2.19.1",
				Endpoint: "requirements.txt", ComponentNotImported: false,
			},
			failOn: "HIGH", opts: shipped, wantStatus: "BLOCK",
		},
		{
			// Relaxed policy: the same uncorroborated finding the shipped
			// policy holds at WARN blocks because the gate was switched off.
			name: "relaxed_policy_override_block",
			ev: evidence.Evidence{
				Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "auth",
				Confidence: models.ConfidenceMedium, Title: "Endpoint has no authentication requirement",
				Endpoint: "GET /api/health",
			},
			failOn: "HIGH", opts: decision.Options{}, wantStatus: "BLOCK",
		},
	}
}

// TestNativeAndSARIFAgreeOnDecision is the contract itself.
func TestNativeAndSARIFAgreeOnDecision(t *testing.T) {
	for _, tc := range contractCases() {
		t.Run(tc.name, func(t *testing.T) {
			f := stampOne(tc.ev, tc.failOn, tc.opts)
			if f.Status != tc.wantStatus {
				t.Fatalf("precondition: status = %s, want %s (%s)", f.Status, tc.wantStatus, f.DecisionReason)
			}
			nat := nativeSemantics(t, f)
			sar := sarifSemantics(t, f)

			if nat.Status != sar.Status {
				t.Errorf("status: native %q vs SARIF %q", nat.Status, sar.Status)
			}
			if nat.ConfidenceScore != sar.ConfidenceScore {
				t.Errorf("confidence_score: native %d vs SARIF %d", nat.ConfidenceScore, sar.ConfidenceScore)
			}
			if nat.ConfidenceBand != sar.ConfidenceBand {
				t.Errorf("confidence_band: native %q vs SARIF %q", nat.ConfidenceBand, sar.ConfidenceBand)
			}
			if nat.IntrinsicSeverity != sar.IntrinsicSeverity {
				t.Errorf("intrinsic severity: native %q vs SARIF %q", nat.IntrinsicSeverity, sar.IntrinsicSeverity)
			}
			if nat.Policy != sar.Policy {
				t.Errorf("policy: native %q vs SARIF %q", nat.Policy, sar.Policy)
			}
			if nat.Override != sar.Override {
				t.Errorf("policy_override: native %v vs SARIF %v", nat.Override, sar.Override)
			}
			if nat.Reason != sar.Reason {
				t.Errorf("decision reason:\n native %q\n SARIF  %q", nat.Reason, sar.Reason)
			}
			if !eqStrings(nat.Independent, sar.Independent) {
				t.Errorf("independent_signals: native %v vs SARIF %v", nat.Independent, sar.Independent)
			}
			if !eqStrings(nat.SelfEvident, sar.SelfEvident) {
				t.Errorf("self_evident_signals: native %v vs SARIF %v", nat.SelfEvident, sar.SelfEvident)
			}
			if nat.Reachable != sar.Reachable {
				t.Errorf("reachable: native %v vs SARIF %v", nat.Reachable, sar.Reachable)
			}
			if !eqStrings(nat.BreakdownCodes, sar.BreakdownCodes) {
				t.Errorf("confidence_breakdown codes: native %v vs SARIF %v", nat.BreakdownCodes, sar.BreakdownCodes)
			}
		})
	}
}

// TestEveryEnforcedBlockIsAuditableInSARIF is the P0 invariant: a BLOCK
// exported under the shipped policy must never reduce to {"status":"BLOCK"}.
// It has to carry a machine-readable reason AND at least one named signal
// saying which evidence class permitted blocking.
func TestEveryEnforcedBlockIsAuditableInSARIF(t *testing.T) {
	for _, tc := range contractCases() {
		if tc.wantStatus != "BLOCK" || !tc.opts.EnforceConfidence {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			sar := sarifSemantics(t, stampOne(tc.ev, tc.failOn, tc.opts))
			if sar.Reason == "" {
				t.Error("enforced BLOCK exported with no decision reason")
			}
			if sar.Policy == "" {
				t.Error("enforced BLOCK exported with no policy")
			}
			if len(sar.Independent)+len(sar.SelfEvident) == 0 {
				t.Error("enforced BLOCK names no evidence class that permitted blocking")
			}
		})
	}
}

// TestRelaxedBlockIsDistinguishableFromEnforcedBlock: an operator-relaxed gate
// must never look identical to an evidence-backed one.
func TestRelaxedBlockIsDistinguishableFromEnforcedBlock(t *testing.T) {
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Category: "auth",
		Confidence: models.ConfidenceMedium, Title: "Endpoint has no authentication requirement",
		Endpoint: "GET /api/health",
	}
	relaxed := sarifSemantics(t, stampOne(ev, "HIGH", decision.Options{}))
	enforced := sarifSemantics(t, stampOne(ev, "HIGH", decision.Options{EnforceConfidence: true}))

	if relaxed.Status != "BLOCK" {
		t.Fatalf("precondition: relaxed status = %s, want BLOCK", relaxed.Status)
	}
	if relaxed.Policy != "relaxed" {
		t.Errorf("relaxed BLOCK policy = %q, want \"relaxed\"", relaxed.Policy)
	}
	if !relaxed.Override {
		t.Error("relaxed BLOCK not marked policy_override — it is indistinguishable from an evidence-backed BLOCK")
	}
	if enforced.Status == "BLOCK" && enforced.Override {
		t.Error("enforced BLOCK wrongly marked as an override")
	}
}
