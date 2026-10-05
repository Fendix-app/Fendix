package reporters

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// RC-7 — SARIF collapses four independent concepts into one number.
//
//	intrinsic severity  how bad this KIND of issue is when it is real
//	confidence          how sure Fendix is that this instance is real
//	effective risk      the two combined: how much this alert deserves
//	decision            what Fendix DID about it (BLOCK / WARN / INFO)
//
// A synthetic FAKE_API_KEY scoring 25 in the LOW band and held at WARN was
// published to GitHub under a rule ranked High, with nothing in the result
// saying otherwise. Every one of the four has to be readable, and separately.

// placeholderSecret is the RC-7 reproduction case: a rule that is genuinely
// High when it fires for real, on an instance Fendix itself scores as LOW.
func placeholderSecret() models.Finding {
	return models.Finding{
		ID: "SEC-001", Fingerprint: "fp-placeholder",
		RuleID: "secrets/generic-api-key", Category: "secrets",
		Title:    "Hardcoded API key or token",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Endpoint: "tests/fixtures/conftest.py:12",
		Evidence: `FAKE_API_KEY = "[REDACTED len=32 sha256:deadbeef...]"`,
		Secret:   &models.SecretRef{Identifier: "FAKE_API_KEY", File: "tests/fixtures/conftest.py"},
		// What the engine actually concluded about this instance.
		Confidence:      models.ConfidenceLow,
		ConfidenceScore: 25,
		ConfidenceBand:  "LOW",
		Status:          "WARN",
		DecisionReason:  "placeholder credential in test fixture",
	}
}

func renderOne(t *testing.T, findings ...models.Finding) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderSARIF(&buf, findings, ScanMetadata{Version: "test"}); err != nil {
		t.Fatalf("RenderSARIF: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return raw["runs"].([]any)[0].(map[string]any)
}

// The rule keeps its INTRINSIC severity. security-severity is a rule-level
// property in SARIF, shared by every result under that rule, so it cannot
// honestly encode a per-instance confidence — and under-ranking the rule would
// hide the next instance of this rule that IS real.
func TestRuleSecuritySeverityStaysIntrinsic(t *testing.T) {
	run := renderOne(t, placeholderSecret())
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	props := rules[0].(map[string]any)["properties"].(map[string]any)

	if got := props["security-severity"]; got != "8.0" {
		t.Errorf("security-severity = %v, want 8.0 (HIGH intrinsic)", got)
	}
	if got := props["severity_model"]; got != "intrinsic" {
		t.Errorf("the rule must SAY which of the four concepts its score is; severity_model = %v", got)
	}
}

// The per-result concepts must each be readable on the result, so a consumer
// can see that Fendix ranked this instance far below its rule.
func TestResultCarriesTheFourSeverityConceptsSeparately(t *testing.T) {
	run := renderOne(t, placeholderSecret())
	res := run["results"].([]any)[0].(map[string]any)
	props, ok := res["properties"].(map[string]any)
	if !ok {
		t.Fatal("result has no properties")
	}

	for key, want := range map[string]any{
		"intrinsic_severity": "HIGH",
		"confidence_band":    "LOW",
		"confidence_score":   float64(25),
		"status":             "WARN",
		"effective_risk":     "LOW",
	} {
		if got := props[key]; got != want {
			t.Errorf("result property %s = %v, want %v", key, got, want)
		}
	}
}

// SARIF's own per-result priority field is `rank` (§3.27.16, 0.0–100.0).
// That is where effective risk belongs — it is the standard mechanism, so
// nothing non-standard needs inventing.
func TestResultRankCarriesEffectiveRisk(t *testing.T) {
	run := renderOne(t, placeholderSecret())
	res := run["results"].([]any)[0].(map[string]any)

	rank, ok := res["rank"].(float64)
	if !ok {
		t.Fatal("result has no rank — effective risk has nowhere standard to live")
	}
	if rank <= 0 || rank > 100 {
		t.Errorf("rank = %v, outside the SARIF 0.0–100.0 range", rank)
	}
	if rank >= 70 {
		t.Errorf("rank = %v: a LOW-confidence placeholder must not rank as a high-priority result", rank)
	}
}

// A high-confidence instance of the SAME rule must outrank the placeholder —
// otherwise rank is decoration rather than a ranking.
func TestRankSeparatesRealFromSynthetic(t *testing.T) {
	real := placeholderSecret()
	real.ID, real.Fingerprint = "SEC-002", "fp-real"
	real.Endpoint = "config/settings.py:3"
	real.Evidence = `STRIPE_SECRET_KEY = "[REDACTED len=41 sha256:cafebabe...]"`
	real.Secret = &models.SecretRef{Identifier: "STRIPE_SECRET_KEY", File: "config/settings.py"}
	real.Confidence, real.ConfidenceScore, real.ConfidenceBand = models.ConfidenceHigh, 95, "HIGH"
	real.Status, real.DecisionReason = "BLOCK", "deterministic pattern match in production source"

	run := renderOne(t, placeholderSecret(), real)
	results := run["results"].([]any)

	ranks := map[string]float64{}
	for _, r := range results {
		res := r.(map[string]any)
		props := res["properties"].(map[string]any)
		ranks[props["confidence_band"].(string)] = res["rank"].(float64)
	}
	if ranks["HIGH"] <= ranks["LOW"] {
		t.Errorf("a high-confidence instance ranked no higher than a synthetic one: HIGH=%v LOW=%v",
			ranks["HIGH"], ranks["LOW"])
	}
}

// GitHub renders security-severity, not rank, so the gap between the rule's
// intrinsic score and Fendix's own assessment has to be visible in the one
// field a human reads.
func TestMessageNamesADowngradedAssessment(t *testing.T) {
	run := renderOne(t, placeholderSecret())
	res := run["results"].([]any)[0].(map[string]any)
	msg := res["message"].(map[string]any)["text"].(string)

	if !bytes.Contains([]byte(msg), []byte("LOW confidence")) {
		t.Errorf("message hides that Fendix ranks this instance below its rule: %q", msg)
	}
}

// A finding whose confidence matches its severity must NOT gain the caveat —
// otherwise every alert carries it and it stops meaning anything.
func TestMessageStaysCleanWhenTheAssessmentAgrees(t *testing.T) {
	f := placeholderSecret()
	f.Confidence, f.ConfidenceScore, f.ConfidenceBand = models.ConfidenceHigh, 95, "HIGH"
	f.Status = "BLOCK"

	run := renderOne(t, f)
	res := run["results"].([]any)[0].(map[string]any)
	msg := res["message"].(map[string]any)["text"].(string)

	if bytes.Contains([]byte(msg), []byte("LOW confidence")) {
		t.Errorf("a high-confidence finding gained a downgrade caveat: %q", msg)
	}
}

// --- rule identity ------------------------------------------------------

// The SARIF rule id was "fendix.<category>.<title-slug>" — derived from
// presentation, exactly the mistake the v2 fingerprint removed from finding
// identity. Once titles follow the evidence (RC-6), one check's results would
// scatter across two rules the moment a taint chain was proven.
func TestRuleIdentitySurvivesAnEvidenceAwareRetitle(t *testing.T) {
	potential := models.Finding{
		ID: "SEC-001", Fingerprint: "fp-a", RuleID: "python.ssrf.taint",
		Category: "injection", Title: "Potential SSRF — dynamic URL passed to HTTP client",
		Severity: models.SeverityHigh, Source: models.SourceWhitebox,
		Endpoint: "app/views.py:10", Confidence: models.ConfidenceMedium,
	}
	proven := potential
	proven.ID, proven.Fingerprint = "SEC-002", "fp-b"
	proven.Title = "SSRF — user-controlled URL reaches HTTP client"
	proven.Endpoint = "app/views.py:40"
	proven.Reachable = true

	run := renderOne(t, potential, proven)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)

	if len(rules) != 1 {
		ids := []string{}
		for _, r := range rules {
			ids = append(ids, r.(map[string]any)["id"].(string))
		}
		t.Errorf("one check split into %d rules after an evidence-aware retitle: %v", len(rules), ids)
	}
}

// Two genuinely different checks must still be two rules.
func TestDistinctChecksRemainDistinctRules(t *testing.T) {
	ssrf := models.Finding{
		ID: "SEC-001", RuleID: "python.ssrf.taint", Category: "injection",
		Title: "Potential SSRF", Severity: models.SeverityHigh,
		Source: models.SourceWhitebox, Endpoint: "app/views.py:10",
	}
	path := ssrf
	path.ID, path.RuleID = "SEC-002", "python.pathtraversal.taint"
	path.Title = "Potential path traversal"

	run := renderOne(t, ssrf, path)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("two distinct checks collapsed into %d rule(s)", len(rules))
	}
}

// A finding with no RuleID (an older report, or an emitter that never set one)
// must still get a rule, via the existing category+title fallback.
func TestRuleIdentityFallsBackWhenNoRuleIDExists(t *testing.T) {
	f := models.Finding{
		ID: "SEC-001", Category: "headers", Title: "Missing CSP header",
		Severity: models.SeverityMedium, Source: models.SourceBlackbox,
		Endpoint: "GET /api/data",
	}
	run := renderOne(t, f)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected exactly one rule, got %d", len(rules))
	}
	if id := rules[0].(map[string]any)["id"].(string); id != "fendix.headers.missing-csp-header" {
		t.Errorf("fallback rule id changed: %q", id)
	}
}
