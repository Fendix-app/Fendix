package managedci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const (
	vectorsPath = "../../../contracts/managed-ci/v2/policy/finding-policy-1.0.0.vectors.json"
	specPath    = "../../../contracts/managed-ci/v2/policy/finding-policy-1.0.0.json"
	factsSchema = "../../../contracts/managed-ci/v2/schemas/evidence-facts.schema.json"
)

type vector struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	FailOn   string `json:"fail_on"`
	Facts    Facts  `json:"facts"`
}

type vectorFile struct {
	FindingPolicy string   `json:"finding_policy_version"`
	Options       string   `json:"options"`
	Vectors       []vector `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(vectorsPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return file
}

// evidenceFor is the canonical fact -> Evidence mapping, identical to the one
// the decision package's parity test uses to prove the vectors are what the
// engine decides. FactsFrom is its inverse, so round-tripping every vector
// through it proves the exporter reports exactly the observations the policy
// was written against.
func evidenceFor(v vector) evidence.Evidence {
	ev := evidence.Evidence{Severity: models.Severity(v.Severity), Category: v.Category}
	ev.Source = map[string]models.Source{
		"whitebox": models.SourceWhitebox, "blackbox": models.SourceBlackbox,
		"correlated": models.SourceCorrelated, "imported": models.SourceImported,
	}[v.Facts.ObservationSource]
	ev.Confidence = map[string]models.Confidence{
		"high": models.ConfidenceHigh, "medium": models.ConfidenceMedium, "low": models.ConfidenceLow,
	}[v.Facts.RulePrecision]
	ev.SourceTier = map[string]models.SourceTier{
		"native": models.TierNativeGo, "tree_sitter": models.TierTreeSitter,
		"semgrep": models.TierSemgrepShim, "unspecified": "",
	}[v.Facts.AnalyzerImplementation]
	ev.Reachable = v.Facts.ReachableTaintPath
	ev.RouteConfirmed = v.Facts.RouteConfirmed
	ev.ProvenPath = v.Facts.ProvenPath
	if v.Facts.PayloadValidated {
		ev.Payload, ev.Response = "probe", "predicted response"
	}
	ev.DirectObservation = v.Facts.DirectObservation
	ev.CrossToolCorroborated = v.Facts.CrossToolCorroborated
	ev.CorroboratingTools = v.Facts.CorroboratingTools
	ev.ResponseContext = map[string]string{
		"none": "", "client_error_4xx": "4xx", "static_asset": "static-asset",
	}[v.Facts.ResponseContext]
	ev.InTest = v.Facts.InTestCode
	ev.Placeholder = v.Facts.FixtureShapedValue
	ev.ProviderAnchored = v.Facts.ProviderAnchoredSecret
	switch v.Facts.DependencyApplicability {
	case "applicable":
		ev.Applicability = models.ApplicabilityApplicable
	case "evidence_against":
		ev.Applicability = models.ApplicabilityEvidenceAgainst
		ev.ComponentNotImported = true
	}
	ev.AuthExpectation = map[string]models.AuthExpectation{
		"unknown": models.AuthExpectationUnknown, "public": models.AuthExpectationPublic,
		"required": models.AuthExpectationRequired,
	}[v.Facts.AuthExpectation]
	ev.UnconfirmedByLiveScan = v.Facts.UnconfirmedByLiveScan
	return ev
}

// TestEveryPolicyVectorRoundTripsThroughTheExporter is the exporter half of
// the parity chain: engine == vectors == backend already holds, and this adds
// engine evidence -> exported facts == vector facts.
func TestEveryPolicyVectorRoundTripsThroughTheExporter(t *testing.T) {
	file := loadVectors(t)
	if file.Options != "managed_ci_default" {
		t.Fatalf("vectors use options %q", file.Options)
	}
	for _, v := range file.Vectors {
		got, err := FactsFrom(evidenceFor(v))
		if err != nil {
			t.Fatalf("%s: FactsFrom: %v", v.ID, err)
		}
		if !reflect.DeepEqual(got, v.Facts) {
			t.Errorf("%s: exported facts differ\n got: %+v\nwant: %+v", v.ID, got, v.Facts)
		}
		if err := got.Consistent(models.Severity(v.Severity)); err != nil {
			t.Errorf("%s: exported facts are not self-consistent: %v", v.ID, err)
		}
	}
	t.Logf("round-tripped %d policy vectors for finding policy %s", len(file.Vectors), file.FindingPolicy)
}

// The exporter must emit every fact the policy makes mandatory, under exactly
// the names the schema declares — no more, no fewer.
func TestExportedFactsAreTheDeclaredVocabulary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(factsSchema))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Properties           map[string]json.RawMessage `json:"properties"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("the facts schema must be closed")
	}
	encoded, err := json.Marshal(Facts{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var emitted map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &emitted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for name := range schema.Properties {
		if _, ok := emitted[name]; !ok {
			t.Errorf("fact %q is declared by the schema but never exported", name)
		}
	}
	for name := range emitted {
		if _, ok := schema.Properties[name]; !ok {
			t.Errorf("fact %q is exported but not declared by the schema", name)
		}
	}
}

func TestConclusionsAreNeverExported(t *testing.T) {
	// The scored/decided half of an Evidence must not reach the document.
	ev := evidence.Evidence{
		Severity: models.SeverityHigh, Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		Status: "BLOCK", ConfidenceScore: 95, ConfidenceBand: "HIGH",
		ConfidenceReasons: []string{"deterministic detection"},
	}
	facts, err := FactsFrom(ev)
	if err != nil {
		t.Fatalf("FactsFrom: %v", err)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, banned := range []string{"BLOCK", "95", "confidence", "band", "status", "tier", "decision"} {
		if containsFold(string(encoded), banned) {
			t.Errorf("exported facts leak a conclusion (%q): %s", banned, encoded)
		}
	}
}

func containsFold(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexFold(haystack, needle) >= 0
}

func indexFold(haystack, needle string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if lower(haystack[i+j]) != lower(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestUnmappableEngineStateFailsClosed(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh}
	cases := map[string]func(*evidence.Evidence){
		"observation_source":       func(e *evidence.Evidence) { e.Source = models.Source("telepathy") },
		"rule_precision":           func(e *evidence.Evidence) { e.Confidence = models.Confidence("VIBES") },
		"response_context":         func(e *evidence.Evidence) { e.ResponseContext = "teapot" },
		"auth_expectation":         func(e *evidence.Evidence) { e.AuthExpectation = models.AuthExpectation("maybe") },
		"dependency_applicability": func(e *evidence.Evidence) { e.Applicability = models.Applicability("perhaps") },
	}
	for field, mutate := range cases {
		ev := base
		mutate(&ev)
		if _, err := FactsFrom(ev); err == nil {
			t.Errorf("%s: unmappable engine state was exported anyway", field)
		}
	}
}

func TestPayloadValidationNeedsBothHalvesOfTheExchange(t *testing.T) {
	base := evidence.Evidence{Source: models.SourceBlackbox, Confidence: models.ConfidenceHigh}
	for name, ev := range map[string]evidence.Evidence{
		"neither":      base,
		"payload only": {Source: base.Source, Confidence: base.Confidence, Payload: "probe"},
		"response only": {
			Source: base.Source, Confidence: base.Confidence, Response: "predicted",
		},
	} {
		facts, err := FactsFrom(ev)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if facts.PayloadValidated {
			t.Errorf("%s: payload_validated must need both the probe and its reply", name)
		}
	}
	both := base
	both.Payload, both.Response = "probe", "predicted"
	facts, err := FactsFrom(both)
	if err != nil {
		t.Fatalf("both: %v", err)
	}
	if !facts.PayloadValidated {
		t.Error("a completed probe exchange must report payload_validated")
	}
	encoded, _ := json.Marshal(facts)
	if containsFold(string(encoded), "probe") || containsFold(string(encoded), "predicted") {
		t.Errorf("the probe exchange itself must never be exported: %s", encoded)
	}
}

func TestCorroboratingToolsAreDeterministicAndNeverNull(t *testing.T) {
	ev := evidence.Evidence{
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh,
		CrossToolCorroborated: true,
		CorroboratingTools:    []string{"semgrep", "", "bandit", "semgrep"},
	}
	facts, err := FactsFrom(ev)
	if err != nil {
		t.Fatalf("FactsFrom: %v", err)
	}
	if !reflect.DeepEqual(facts.CorroboratingTools, []string{"bandit", "semgrep"}) {
		t.Errorf("tools must be sorted and de-duplicated: %v", facts.CorroboratingTools)
	}
	empty, err := FactsFrom(evidence.Evidence{Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh})
	if err != nil {
		t.Fatalf("FactsFrom: %v", err)
	}
	encoded, _ := json.Marshal(empty)
	if containsFold(string(encoded), "null") {
		t.Errorf("an empty tool list must encode as [], not null: %s", encoded)
	}
}

// A producer that only set the superseded flag observed the same thing.
func TestSupersededComponentFlagStillReportsEvidenceAgainst(t *testing.T) {
	ev := evidence.Evidence{
		Source: models.SourceWhitebox, Confidence: models.ConfidenceHigh, ComponentNotImported: true,
	}
	facts, err := FactsFrom(ev)
	if err != nil {
		t.Fatalf("FactsFrom: %v", err)
	}
	if facts.DependencyApplicability != applicabilityEvidenceAgainst {
		t.Errorf("dependency_applicability = %q, want evidence_against", facts.DependencyApplicability)
	}
}

func TestSerializationIsDeterministic(t *testing.T) {
	file := loadVectors(t)
	for _, v := range file.Vectors[:16] {
		facts, err := FactsFrom(evidenceFor(v))
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		first, err := json.Marshal(facts)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		for i := 0; i < 8; i++ {
			again, err := json.Marshal(facts)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(again) != string(first) {
				t.Fatalf("%s: serialization is not byte-stable", v.ID)
			}
		}
		// Independently built evidence must produce identical bytes too.
		other, err := FactsFrom(evidenceFor(v))
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		repeat, _ := json.Marshal(other)
		if string(repeat) != string(first) {
			t.Fatalf("%s: equal observations produced different bytes", v.ID)
		}
	}
}
