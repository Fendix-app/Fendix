package engine

import (
	"sort"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// These tests are the regression gate for the B3 "test-fixture de-escalation is
// dead code" defect: decision.DecideWithOptions and Options.DeescalateTests
// existed and were unit-tested, but stampDecisions called decision.DecideAll
// (which uses the option-less Decide), and no ScanConfig field could turn the
// rule on. BENCHMARKS.md nevertheless credited it with demoting fixture noise.
//
// Every test here drives the REAL finalization sequence the orchestrator runs
// between correlation and scoring, because that is the layer where the wiring
// was missing — a decision-package unit test passes either way.

// finalize reproduces orchestrator.Run steps 5.4 → 10.5 on a set of Evidence
// and returns the stamped findings. Keeping it in one place means these tests
// exercise the same ordering production does (escalate → dedup → consistency →
// sort → IDs/fingerprint → stamp), including the provenance index captured
// BEFORE the projection.
func finalize(evid []evidence.Evidence, failOn string, opts decision.Options) []models.Finding {
	return finalizeIndexed(evid, evidence.NewProvenanceIndex(evid), failOn, opts)
}

// finalizeIndexed is finalize with the provenance index supplied by the
// caller. A HYBRID scan runs CorrelateEvidence BEFORE building the index
// (orchestrator.go:539 then :552), and that ordering is exactly what the
// correlator's provenance restore has to survive — so a test covering it must
// be able to interpose. finalize is the code-only shorthand.
func finalizeIndexed(evid []evidence.Evidence, prov evidence.ProvenanceIndex, failOn string, opts decision.Options) []models.Finding {
	findings := evidence.ToFindings(evid)
	findings = escalateNonCorrelatedReachable(findings)
	findings = Deduplicate(findings)
	findings = enforceConsistency(findings)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Endpoint != findings[j].Endpoint {
			return findings[i].Endpoint < findings[j].Endpoint
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Title < findings[j].Title
	})
	for i := range findings {
		findings[i].Fingerprint = models.Fingerprint(findings[i])
	}
	stampDecisions(findings, prov, failOn, opts)
	return findings
}

// secretEvidence is a whitebox finding shaped like the native secrets scanner's
// output. HIGH severity + HIGH confidence keeps it at WARN (so the
// de-escalation has something to act on) and clear of enforceConsistency.
func secretEvidence(endpoint string) evidence.Evidence {
	return evidence.Evidence{
		Title:      "Hardcoded API key or token",
		Category:   "secrets",
		Endpoint:   endpoint,
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Confidence: models.ConfidenceHigh,
		Evidence:   `api_key = "sk-live-abc..."`,
		Fix:        "Move the credential to a secrets manager and rotate it.",
	}
}

func findByEndpoint(t *testing.T, findings []models.Finding, endpoint string) models.Finding {
	t.Helper()
	for _, f := range findings {
		if f.Endpoint == endpoint {
			return f
		}
	}
	t.Fatalf("no finding at endpoint %q in %+v", endpoint, findings)
	return models.Finding{}
}

// TestPipelineDeescalatesTestFindingWhenPolicyEnabled is the headline gate:
// with the policy on, a finding in test code reaches the report as INFO.
// Before the wiring fix this returned WARN no matter what the policy said.
func TestPipelineDeescalatesTestFindingWhenPolicyEnabled(t *testing.T) {
	evid := []evidence.Evidence{secretEvidence("app/tests/test_client.py:12")}

	got := finalize(evid, "", decision.Options{DeescalateTests: true})

	if got[0].Status != string(decision.StatusInfo) {
		t.Errorf("Status = %q, want INFO — the test-fixture de-escalation did not reach the finding",
			got[0].Status)
	}
	if !strings.Contains(strings.Join(got[0].ConfidenceReasons, "\n"), "test/fixture code") {
		t.Errorf("no reason line explains the de-escalation: %v", got[0].ConfidenceReasons)
	}
	// Rule 3: de-escalated, never deleted.
	if len(got) != 1 {
		t.Errorf("finding count = %d, want 1 — evidence must be preserved, not suppressed", len(got))
	}
	if got[0].Evidence == "" {
		t.Error("evidence text was dropped; de-escalation must preserve it")
	}
}

// TestPipelineKeepsTestFindingWhenPolicyDisabled proves the policy is actually
// consulted rather than the rule being unconditional.
func TestPipelineKeepsTestFindingWhenPolicyDisabled(t *testing.T) {
	evid := []evidence.Evidence{secretEvidence("app/tests/test_client.py:12")}

	got := finalize(evid, "", decision.Options{DeescalateTests: false})

	if got[0].Status != string(decision.StatusWarn) {
		t.Errorf("Status = %q, want WARN when --deescalate-tests=false", got[0].Status)
	}
	if strings.Contains(strings.Join(got[0].ConfidenceReasons, "\n"), "test/fixture code") {
		t.Errorf("de-escalation reason leaked in with the policy off: %v", got[0].ConfidenceReasons)
	}
}

// TestPipelineLeavesProductionFindingAlone — the rule must be targeted.
func TestPipelineLeavesProductionFindingAlone(t *testing.T) {
	evid := []evidence.Evidence{secretEvidence("app/services/client.py:12")}

	got := finalize(evid, "", decision.Options{DeescalateTests: true})

	if got[0].Status != string(decision.StatusWarn) {
		t.Errorf("production finding Status = %q, want WARN (unaffected)", got[0].Status)
	}
}

// TestPipelineDoesNotDeescalateMixedDedupGroup is the conservative-merge gate.
// Dedup collapses on (Title, Category, Severity), so one test occurrence and
// one production occurrence become a SINGLE finding. De-escalating that group
// would hide a real production finding behind a test-code exemption.
//
// Both orientations are exercised on purpose. Dedup picks its primary by the
// deterministic findingLess total order (endpoint first), so which occurrence
// ends up in Finding.Endpoint depends only on the endpoint strings. The
// "test path sorts FIRST" case is the discriminating one: an implementation
// that simply re-derived the flag from the primary endpoint — instead of
// folding the provenance across the whole group — passes the other case by
// luck and fails this one.
func TestPipelineDoesNotDeescalateMixedDedupGroup(t *testing.T) {
	cases := []struct {
		name         string
		testEndpoint string
		prodEndpoint string
		wantPrimary  string
	}{
		{
			name:         "test path sorts first (primary is the test occurrence)",
			testEndpoint: "app/tests/test_client.py:12",
			prodEndpoint: "src/services/client.py:22",
			wantPrimary:  "app/tests/test_client.py:12",
		},
		{
			name:         "production path sorts first (primary is the prod occurrence)",
			testEndpoint: "src/tests/test_client.py:12",
			prodEndpoint: "app/services/client.py:22",
			wantPrimary:  "app/services/client.py:22",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evid := []evidence.Evidence{
				secretEvidence(tc.testEndpoint),
				secretEvidence(tc.prodEndpoint),
			}

			got := finalize(evid, "", decision.Options{DeescalateTests: true})

			if len(got) != 1 {
				t.Fatalf("expected the two occurrences to dedup into 1 finding, got %d", len(got))
			}
			if len(got[0].AffectedEndpoints) != 2 {
				t.Fatalf("expected 2 affected endpoints, got %v", got[0].AffectedEndpoints)
			}
			// Guard the premise: if dedup's primary selection ever changes, the
			// discriminating orientation must be re-derived rather than silently lost.
			if got[0].Endpoint != tc.wantPrimary {
				t.Fatalf("dedup primary = %q, want %q — this test's premise no longer holds",
					got[0].Endpoint, tc.wantPrimary)
			}
			if got[0].Status != string(decision.StatusWarn) {
				t.Errorf("mixed test+production dedup group Status = %q, want WARN — a production\n"+
					"occurrence must not inherit a test-code exemption", got[0].Status)
			}
			if strings.Contains(strings.Join(got[0].ConfidenceReasons, "\n"), "test/fixture code") {
				t.Errorf("mixed group carried a test-fixture de-escalation reason: %v",
					got[0].ConfidenceReasons)
			}
		})
	}
}

// TestPipelineDeescalatesAllTestDedupGroup is the positive counterpart: when
// EVERY occurrence is test code the group does earn the de-escalation, so the
// conservative rule is not just "never de-escalate a group".
func TestPipelineDeescalatesAllTestDedupGroup(t *testing.T) {
	evid := []evidence.Evidence{
		secretEvidence("app/tests/test_client.py:12"),
		secretEvidence("app/tests/test_admin.py:44"),
	}

	got := finalize(evid, "", decision.Options{DeescalateTests: true})

	if len(got) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(got))
	}
	if got[0].Status != string(decision.StatusInfo) {
		t.Errorf("all-test dedup group Status = %q, want INFO", got[0].Status)
	}
}

// TestPipelineDeescalationIsOrderIndependent locks F-L6 for the new merge: the
// stamped result must be a pure function of the evidence SET, not of the order
// the worker pool happened to produce it in.
func TestPipelineDeescalationIsOrderIndependent(t *testing.T) {
	mixed := []evidence.Evidence{
		secretEvidence("app/tests/test_client.py:12"),
		secretEvidence("app/services/client.py:22"),
	}
	reversed := []evidence.Evidence{mixed[1], mixed[0]}
	opts := decision.Options{DeescalateTests: true}

	a := finalize(mixed, "", opts)
	b := finalize(reversed, "", opts)

	if len(a) != len(b) {
		t.Fatalf("finding count differs by input order: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Status != b[i].Status {
			t.Errorf("finding %d Status differs by input order: %q vs %q", i, a[i].Status, b[i].Status)
		}
		if a[i].ConfidenceScore != b[i].ConfidenceScore {
			t.Errorf("finding %d score differs by input order: %d vs %d",
				i, a[i].ConfidenceScore, b[i].ConfidenceScore)
		}
		if strings.Join(a[i].ConfidenceReasons, "|") != strings.Join(b[i].ConfidenceReasons, "|") {
			t.Errorf("finding %d reasons differ by input order:\n a=%v\n b=%v",
				i, a[i].ConfidenceReasons, b[i].ConfidenceReasons)
		}
		if a[i].Endpoint != b[i].Endpoint || a[i].Fingerprint != b[i].Fingerprint {
			t.Errorf("finding %d identity differs by input order: %q/%q vs %q/%q",
				i, a[i].Endpoint, a[i].Fingerprint, b[i].Endpoint, b[i].Fingerprint)
		}
	}
}

// TestOrchestratorPassesTheConfigPolicyToTheDecisionLayer closes the
// ScanConfig -> decision.Options hop. A mutation audit showed that rewriting
// orchestrator.go's `DeescalateTests: o.cfg.DeescalateTests` to a hardcoded
// `false` (or to its negation) left the whole suite green — every other test
// constructs decision.Options directly, so nothing observed the config field
// actually reaching the decision layer. This asserts on the orchestrator's own
// struct field.
func TestOrchestratorPassesTheConfigPolicyToTheDecisionLayer(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := &models.ScanConfig{DeescalateTests: enabled}
		o := &Orchestrator{cfg: cfg}

		// Guard the wiring itself, not a re-typed copy of it: o.decisionOptions()
		// is the exact expression Run passes to stampDecisions.
		if got := o.decisionOptions().DeescalateTests; got != enabled {
			t.Errorf("decisionOptions().DeescalateTests = %v, want %v — ScanConfig is not\n"+
				"reaching the decision layer", got, enabled)
		}

		evid := []evidence.Evidence{secretEvidence("app/tests/test_client.py:12")}
		prov := evidence.NewProvenanceIndex(evid)
		findings := evidence.ToFindings(evid)
		stampDecisions(findings, prov, o.cfg.FailOn, o.decisionOptions())

		want := string(decision.StatusWarn)
		if enabled {
			want = string(decision.StatusInfo)
		}
		if findings[0].Status != want {
			t.Errorf("DeescalateTests=%v produced Status %q, want %q — the ScanConfig field is\n"+
				"not reaching decision.Options", enabled, findings[0].Status, want)
		}
	}
}

// TestPipelineDemotesAnUncorroboratedBlockingTestFinding replaces the v1.1
// TestPipelineNeverDowngradesABlockingTestFinding, whose invariant FIX-09
// deliberately removes.
//
// The old rule ("--fail-on always wins over the test-fixture rule") sounded
// safe but was the exact hole that exempted the project's largest FP class from
// its own mitigation: 31 of the 35 catalogued false positives in
// tasks/FP_CORPUS.md are test fixtures, and a team with --fail-on set — i.e.
// everyone the demotion was meant to help — got none of it. The demotion is
// conditional on the ABSENCE of corroboration, so the safety property moved
// rather than disappeared; its other half is the test below.
func TestPipelineDemotesAnUncorroboratedBlockingTestFinding(t *testing.T) {
	evid := []evidence.Evidence{secretEvidence("app/tests/test_client.py:12")}

	got := finalize(evid, "HIGH", decision.Options{DeescalateTests: true})

	if got[0].Status != string(decision.StatusWarn) {
		t.Errorf("Status = %q, want WARN — an uncorroborated test-code match must not gate a build",
			got[0].Status)
	}
	if !strings.Contains(strings.Join(got[0].ConfidenceReasons, "\n"), "test/fixture code") {
		t.Errorf("no reason line explains the demotion: %v", got[0].ConfidenceReasons)
	}
	// Rule 3: de-escalated, never deleted.
	if len(got) != 1 {
		t.Errorf("finding count = %d, want 1 — evidence must be preserved, not suppressed", len(got))
	}
	if got[0].Evidence == "" {
		t.Error("evidence text was dropped; de-escalation must preserve it")
	}
}

// TestPipelineKeepsACorroboratedBlockingTestFinding is the other half, and the
// reason FIX-09 is a de-escalation rather than path suppression: a credential
// with an independent signal behind it — a proven taint path here — can still
// be a real leak wherever the file lives, and still exits 1. Provider-shaped
// syntax alone is not live validation.
func TestPipelineKeepsACorroboratedBlockingTestFinding(t *testing.T) {
	ev := secretEvidence("app/tests/test_client.py:12")
	ev.Reachable = true

	got := finalize([]evidence.Evidence{ev}, "HIGH", decision.Options{DeescalateTests: true})

	if got[0].Status != string(decision.StatusBlock) {
		t.Errorf("Status = %q, want BLOCK — a corroborated test-code finding must still gate",
			got[0].Status)
	}
	if len(got) != 1 || got[0].Evidence == "" {
		t.Errorf("Rule 3: expected 1 finding with intact evidence, got %+v", got)
	}
}

// TestOrchestratorPassesTheConfidencePolicyToTheDecisionLayer is the
// mutation-audit guard for the SECOND config hop, and it is not optional: the
// zero value of both ScanConfig.EnforceConfidence and Options.EnforceConfidence
// is false, so hardcoding decisionOptions() to drop the field would leave every
// other test in the module green. That is precisely how DeescalateTests shipped
// as dead code.
func TestOrchestratorPassesTheConfidencePolicyToTheDecisionLayer(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := &models.ScanConfig{EnforceConfidence: enabled, FailOn: "HIGH"}
		o := &Orchestrator{cfg: cfg}

		if got := o.decisionOptions().EnforceConfidence; got != enabled {
			t.Errorf("decisionOptions().EnforceConfidence = %v, want %v — ScanConfig is not\n"+
				"reaching the decision layer", got, enabled)
		}

		// An uncorroborated whitebox HIGH finding in PRODUCTION code, scored
		// without the deterministic-detection delta (Confidence MEDIUM, as a
		// graded static check emits): 35 base + 10 static = 45, MEDIUM band,
		// no corroborating signal.
		ev := secretEvidence("app/services/client.py:22")
		ev.Confidence = models.ConfidenceMedium
		evid := []evidence.Evidence{ev}
		prov := evidence.NewProvenanceIndex(evid)
		findings := evidence.ToFindings(evid)
		stampDecisions(findings, prov, o.cfg.FailOn, o.decisionOptions())

		want := string(decision.StatusBlock)
		if enabled {
			want = string(decision.StatusWarn)
		}
		if findings[0].Status != want {
			t.Errorf("EnforceConfidence=%v produced Status %q, want %q — the ScanConfig field is\n"+
				"not reaching decision.Options", enabled, findings[0].Status, want)
		}
	}
}

// TestPipelineStillBlocksARealProductionSecret is DECISIONS.md D1 driven
// through the real finalization sequence: the whole point of the
// deterministicDetection delta is that a genuine hardcoded credential in
// PRODUCTION code keeps failing the build under the new gate, on a code-only
// scan where no live corroboration is even possible.
//
// 35 base + 10 static + 30 deterministic detection = 75 → HIGH band → BLOCK.
// The fixture-shaped twin in tests/ is the contrast case: it loses the delta to
// the InTest gate, lands MEDIUM with nothing corroborating it, and is held at
// WARN.
func TestPipelineStillBlocksARealProductionSecret(t *testing.T) {
	opts := decision.Options{EnforceConfidence: true, DeescalateTests: true}

	prod, prodDecisions := finalizeDecisions(secretEvidence("app/services/client.py:22"), "HIGH", opts)
	if prod[0].Status != string(decision.StatusBlock) {
		t.Errorf("production secret Status = %q (score %d, band %q), want BLOCK — the confidence\n"+
			"gate must not stop a code-only scan from failing on a real credential",
			prod[0].Status, prod[0].ConfidenceScore, prod[0].ConfidenceBand)
	}
	if decision.ExitCode(prodDecisions) != 1 {
		t.Error("a real production secret no longer exits 1 — this is a security regression")
	}

	fixture, fixtureDecisions := finalizeDecisions(secretEvidence("app/tests/test_client.py:12"), "HIGH", opts)
	if fixture[0].Status != string(decision.StatusWarn) {
		t.Errorf("fixture secret Status = %q (score %d, band %q), want WARN",
			fixture[0].Status, fixture[0].ConfidenceScore, fixture[0].ConfidenceBand)
	}
	if decision.ExitCode(fixtureDecisions) != 0 {
		t.Error("a fixture-shaped secret still exits 1 — the FP mitigation did not reach the gate")
	}
}

// finalizeDecisions is finalize for one Evidence, additionally returning the
// decisions orchestrator.Run derives its process exit code from. Asserting on
// the status alone would miss a break between Decision.Status and ExitCode.
func finalizeDecisions(ev evidence.Evidence, failOn string, opts decision.Options) ([]models.Finding, []decision.Decision) {
	evid := []evidence.Evidence{ev}
	prov := evidence.NewProvenanceIndex(evid)
	findings := evidence.ToFindings(evid)
	return findings, stampDecisions(findings, prov, failOn, opts)
}

// TestPipelineDeescalationDistinguishesTwoFindings makes sure the flag is
// per-finding, not global: one test finding and one production finding with
// DIFFERENT titles (so they do not dedup) must get different verdicts in the
// same run.
func TestPipelineDeescalationDistinguishesTwoFindings(t *testing.T) {
	testEv := secretEvidence("app/tests/test_client.py:12")
	prodEv := secretEvidence("app/services/client.py:22")
	prodEv.Title = "Hardcoded database URL"

	got := finalize([]evidence.Evidence{testEv, prodEv}, "", decision.Options{DeescalateTests: true})

	if len(got) != 2 {
		t.Fatalf("expected 2 distinct findings, got %d", len(got))
	}
	if s := findByEndpoint(t, got, "app/tests/test_client.py:12").Status; s != string(decision.StatusInfo) {
		t.Errorf("test finding Status = %q, want INFO", s)
	}
	if s := findByEndpoint(t, got, "app/services/client.py:22").Status; s != string(decision.StatusWarn) {
		t.Errorf("production finding Status = %q, want WARN", s)
	}
}
