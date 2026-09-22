package decision

// Managed-CI finding-policy parity (ADR-010, contract managed-ci/v2).
//
// The canonical contract carries a declarative specification of this
// package's policy (contracts/managed-ci/v2/policy/finding-policy-1.0.0.json)
// and a vector file generated FROM THIS PACKAGE. The backend classifies
// managed-CI evidence by interpreting that specification, and proves it
// reproduces every vector; this test proves the vectors are what the engine
// actually decides. Engine == vectors == backend is the parity chain.
//
// Normal runs VERIFY: every committed vector must reproduce exactly under
// DecideWithOptions with the managed-CI default options. To regenerate after
// an intentional policy change (which must also bump PolicyVersion and the
// specification), run:
//
//	FENDIX_WRITE_MANAGED_CI_VECTORS=1 go test ./internal/decision -run TestManagedCIPolicyVectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

const (
	managedCIVectorsPath = "../../../contracts/managed-ci/v2/policy/finding-policy-1.0.0.vectors.json"
	managedCISpecPath    = "../../../contracts/managed-ci/v2/policy/finding-policy-1.0.0.json"
	managedCIGenerated   = 320
	managedCISeed        = 20260922
)

// managedCIOptions is the managed-CI default profile named in the spec.
var managedCIOptions = Options{EnforceConfidence: true, DeescalateTests: true, BlockOnInapplicable: false}

type mcFacts struct {
	AnalyzerImplementation  string   `json:"analyzer_implementation"`
	AuthExpectation         string   `json:"auth_expectation"`
	CorroboratingTools      []string `json:"corroborating_tools"`
	CrossToolCorroborated   bool     `json:"cross_tool_corroborated"`
	DependencyApplicability string   `json:"dependency_applicability"`
	DirectObservation       bool     `json:"direct_observation"`
	FixtureShapedValue      bool     `json:"fixture_shaped_value"`
	InTestCode              bool     `json:"in_test_code"`
	ObservationSource       string   `json:"observation_source"`
	PayloadValidated        bool     `json:"payload_validated"`
	ProvenPath              bool     `json:"proven_path"`
	ProviderAnchoredSecret  bool     `json:"provider_anchored_secret"`
	ReachableTaintPath      bool     `json:"reachable_taint_path"`
	ResponseContext         string   `json:"response_context"`
	RouteConfirmed          bool     `json:"route_confirmed"`
	RulePrecision           string   `json:"rule_precision"`
	UnconfirmedByLiveScan   bool     `json:"unconfirmed_by_live_scan"`
}

type mcExpected struct {
	Score              int      `json:"score"`
	Band               string   `json:"band"`
	ScoreCodes         []string `json:"score_codes"`
	IndependentSignals []string `json:"independent_signals"`
	SelfEvidentSignals []string `json:"self_evident_signals"`
	Status             string   `json:"status"`
	RuleTrace          []string `json:"rule_trace"`
}

type mcVector struct {
	ID       string     `json:"id"`
	Severity string     `json:"severity"`
	Category string     `json:"category"`
	FailOn   string     `json:"fail_on"`
	Facts    mcFacts    `json:"facts"`
	Expected mcExpected `json:"expected"`
}

type mcVectorFile struct {
	SchemaVersion string     `json:"schema_version"`
	FindingPolicy string     `json:"finding_policy_version"`
	Options       string     `json:"options"`
	GeneratedBy   string     `json:"generated_by"`
	Vectors       []mcVector `json:"vectors"`
}

// toEvidence maps the contract vocabulary onto the engine's Evidence. Every
// fact has exactly one engine field; payload_validated stands for the
// Payload AND Response pair, which the contract never carries.
func (f mcFacts) toEvidence(severity, category string) evidence.Evidence {
	ev := evidence.Evidence{Severity: models.Severity(severity), Category: category}
	ev.Source = map[string]models.Source{
		"whitebox": models.SourceWhitebox, "blackbox": models.SourceBlackbox,
		"correlated": models.SourceCorrelated, "imported": models.SourceImported,
	}[f.ObservationSource]
	ev.Confidence = map[string]models.Confidence{
		"high": models.ConfidenceHigh, "medium": models.ConfidenceMedium, "low": models.ConfidenceLow,
	}[f.RulePrecision]
	ev.SourceTier = map[string]models.SourceTier{
		"native": models.TierNativeGo, "tree_sitter": models.TierTreeSitter,
		"semgrep": models.TierSemgrepShim, "unspecified": "",
	}[f.AnalyzerImplementation]
	ev.Reachable = f.ReachableTaintPath
	ev.RouteConfirmed = f.RouteConfirmed
	ev.ProvenPath = f.ProvenPath
	if f.PayloadValidated {
		ev.Payload, ev.Response = "probe", "predicted response"
	}
	ev.DirectObservation = f.DirectObservation
	ev.CrossToolCorroborated = f.CrossToolCorroborated
	ev.CorroboratingTools = f.CorroboratingTools
	ev.ResponseContext = map[string]string{"none": "", "client_error_4xx": "4xx", "static_asset": "static-asset"}[f.ResponseContext]
	ev.InTest = f.InTestCode
	ev.Placeholder = f.FixtureShapedValue
	ev.ProviderAnchored = f.ProviderAnchoredSecret
	switch f.DependencyApplicability {
	case "applicable":
		ev.Applicability = models.ApplicabilityApplicable
	case "evidence_against":
		// The only producer (scanner/deps/applicability) sets both together.
		ev.Applicability = models.ApplicabilityEvidenceAgainst
		ev.ComponentNotImported = true
	}
	ev.AuthExpectation = map[string]models.AuthExpectation{
		"unknown": models.AuthExpectationUnknown, "public": models.AuthExpectationPublic,
		"required": models.AuthExpectationRequired,
	}[f.AuthExpectation]
	ev.UnconfirmedByLiveScan = f.UnconfirmedByLiveScan
	return ev
}

var managedCIDecisionCodes = map[string]bool{
	"held_unconfirmed_by_live_scan":          true,
	"held_confidence_low":                    true,
	"held_uncorroborated":                    true,
	"held_medium_no_independent_signal":      true,
	"not_applicable_component_absent":        true,
	"deescalated_test_fixture":               true,
	"deescalated_test_fixture_threshold_met": true,
	"deescalated_test_fixture_corroborated":  true,
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// classify runs the PRODUCTION entry point and reports the result in the
// contract's vocabulary.
func (v mcVector) classify() mcExpected {
	d := DecideWithOptions(v.Facts.toEvidence(v.Severity, v.Category), v.FailOn, managedCIOptions)
	var scoreCodes, decisionCodes []string
	for _, r := range d.Score.Details {
		if managedCIDecisionCodes[r.Code] {
			decisionCodes = append(decisionCodes, r.Code)
		} else {
			scoreCodes = append(scoreCodes, r.Code)
		}
	}
	var trace []string
	switch {
	case d.aboveThreshold && len(decisionCodes) > 0 && strings.HasPrefix(decisionCodes[0], "held_"):
		trace = decisionCodes
	case d.aboveThreshold:
		trace = append([]string{"block_corroborated"}, decisionCodes...)
	case models.SeverityRank(models.Severity(v.Severity)) >= models.SeverityRank(models.SeverityMedium):
		trace = append([]string{"actionable_below_threshold"}, decisionCodes...)
	default:
		trace = append([]string{"informational"}, decisionCodes...)
	}
	return mcExpected{
		Score:              d.Score.Value,
		Band:               string(d.Score.Band),
		ScoreCodes:         nonNil(scoreCodes),
		IndependentSignals: nonNil(d.Corroboration.Independent),
		SelfEvidentSignals: nonNil(d.Corroboration.SelfEvident),
		Status:             string(d.Status),
		RuleTrace:          nonNil(trace),
	}
}

func baseFacts() mcFacts {
	return mcFacts{
		AnalyzerImplementation: "native", AuthExpectation: "unknown", CorroboratingTools: []string{},
		DependencyApplicability: "unknown", ObservationSource: "whitebox", ResponseContext: "none",
		RulePrecision: "medium",
	}
}

// namedVectors pin the cases the contract fixtures and ADR-010 name, each
// with the status the policy is INTENDED to produce. Intent is asserted
// independently of generation, so a regenerated file cannot quietly encode a
// behaviour change.
func namedVectors() []struct {
	v      mcVector
	intent string
} {
	f := func(mut func(*mcFacts)) mcFacts { x := baseFacts(); mut(&x); return x }
	type nv = struct {
		v      mcVector
		intent string
	}
	return []nv{
		{mcVector{ID: "high-medium-precision-uncorroborated", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {})}, "WARN"},
		{mcVector{ID: "high-deterministic-detection", Severity: "HIGH", Category: "secrets", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high" })}, "BLOCK"},
		{mcVector{ID: "high-cross-tool-corroborated", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.CrossToolCorroborated = true; x.CorroboratingTools = []string{"semgrep"} })}, "BLOCK"},
		{mcVector{ID: "high-reachable-taint", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.ReachableTaintPath = true; x.AnalyzerImplementation = "tree_sitter" })}, "BLOCK"},
		{mcVector{ID: "medium-below-threshold", Severity: "MEDIUM", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {})}, "WARN"},
		{mcVector{ID: "low-below-threshold", Severity: "LOW", Category: "headers", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {})}, "INFO"},
		{mcVector{ID: "info-severity", Severity: "INFO", Category: "headers", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {})}, "INFO"},
		{mcVector{ID: "low-precision-semgrep-uncorroborated", Severity: "MEDIUM", Category: "injection", FailOn: "MEDIUM",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "low"; x.AnalyzerImplementation = "semgrep" })}, "WARN"},
		{mcVector{ID: "fixture-shaped-low-band", Severity: "MEDIUM", Category: "secrets", FailOn: "MEDIUM",
			Facts: f(func(x *mcFacts) {
				x.RulePrecision = "low"
				x.AnalyzerImplementation = "semgrep"
				x.FixtureShapedValue = true
			})}, "WARN"},
		{mcVector{ID: "semgrep-high-precision-not-deterministic", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high"; x.AnalyzerImplementation = "semgrep" })}, "WARN"},
		{mcVector{ID: "secret-in-test-code-held", Severity: "HIGH", Category: "secrets", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high"; x.InTestCode = true })}, "WARN"},
		{mcVector{ID: "fixture-shaped-secret-in-test-code", Severity: "HIGH", Category: "secrets", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high"; x.InTestCode = true; x.FixtureShapedValue = true })}, "INFO"},
		{mcVector{ID: "provider-anchored-fixture-keeps-warn", Severity: "HIGH", Category: "secrets", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.RulePrecision = "high"
				x.InTestCode = true
				x.FixtureShapedValue = true
				x.ProviderAnchoredSecret = true
			})}, "WARN"},
		{mcVector{ID: "medium-in-test-code-below-threshold", Severity: "MEDIUM", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.InTestCode = true })}, "INFO"},
		{mcVector{ID: "dependency-not-applicable", Severity: "HIGH", Category: "deps", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.RulePrecision = "high"
				x.DependencyApplicability = "evidence_against"
			})}, "WARN"},
		{mcVector{ID: "dependency-applicable-blocks", Severity: "HIGH", Category: "deps", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high"; x.DependencyApplicability = "applicable" })}, "BLOCK"},
		{mcVector{ID: "critical-deterministic-under-critical-threshold", Severity: "CRITICAL", Category: "secrets",
			FailOn: "CRITICAL", Facts: f(func(x *mcFacts) { x.RulePrecision = "high" })}, "BLOCK"},
		{mcVector{ID: "unconfirmed-by-live-scan-held", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) { x.RulePrecision = "high"; x.UnconfirmedByLiveScan = true })}, "WARN"},
		{mcVector{ID: "live-header-direct-observation", Severity: "MEDIUM", Category: "headers", FailOn: "MEDIUM",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "blackbox"
				x.DirectObservation = true
				x.AnalyzerImplementation = "unspecified"
			})}, "BLOCK"},
		{mcVector{ID: "payload-validated-probe", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "blackbox"
				x.PayloadValidated = true
				x.AnalyzerImplementation = "unspecified"
			})}, "BLOCK"},
		{mcVector{ID: "contradicted-auth-requirement", Severity: "CRITICAL", Category: "auth", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "blackbox"
				x.RulePrecision = "high"
				x.AuthExpectation = "required"
				x.AnalyzerImplementation = "unspecified"
			})}, "BLOCK"},
		{mcVector{ID: "bare-dast-held", Severity: "CRITICAL", Category: "auth", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "blackbox"
				x.RulePrecision = "high"
				x.AnalyzerImplementation = "unspecified"
			})}, "WARN"},
		{mcVector{ID: "proven-path-correlated", Severity: "CRITICAL", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "correlated"
				x.RulePrecision = "high"
				x.AnalyzerImplementation = "tree_sitter"
				x.RouteConfirmed = true
				x.ReachableTaintPath = true
				x.ProvenPath = true
			})}, "BLOCK"},
		{mcVector{ID: "imported-high-precision", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "imported"
				x.RulePrecision = "high"
				x.AnalyzerImplementation = "unspecified"
			})}, "BLOCK"},
		{mcVector{ID: "imported-low-precision", Severity: "MEDIUM", Category: "injection", FailOn: "MEDIUM",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "imported"
				x.RulePrecision = "low"
				x.AnalyzerImplementation = "unspecified"
			})}, "WARN"},
		{mcVector{ID: "static-asset-context-penalty", Severity: "MEDIUM", Category: "headers", FailOn: "MEDIUM",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "blackbox"
				x.DirectObservation = true
				x.ResponseContext = "static_asset"
				x.AnalyzerImplementation = "unspecified"
			})}, "WARN"},
		{mcVector{ID: "imported-high-precision-in-test-code", Severity: "HIGH", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "imported"
				x.RulePrecision = "high"
				x.AnalyzerImplementation = "unspecified"
				x.InTestCode = true
			})}, "WARN"},
		{mcVector{ID: "corroborated-finding-in-test-code-still-blocks", Severity: "HIGH", Category: "secrets", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.RulePrecision = "high"
				x.InTestCode = true
				x.CrossToolCorroborated = true
				x.CorroboratingTools = []string{"gitleaks"}
			})}, "BLOCK"},
		{mcVector{ID: "score-ceiling", Severity: "CRITICAL", Category: "injection", FailOn: "HIGH",
			Facts: f(func(x *mcFacts) {
				x.ObservationSource = "correlated"
				x.RulePrecision = "high"
				x.AnalyzerImplementation = "tree_sitter"
				x.RouteConfirmed = true
				x.ReachableTaintPath = true
				x.ProvenPath = true
				x.PayloadValidated = true
				x.DirectObservation = true
				x.CrossToolCorroborated = true
				x.CorroboratingTools = []string{"codeql", "semgrep"}
			})}, "BLOCK"},
	}
}

var (
	mcSources      = []string{"whitebox", "blackbox", "correlated", "imported"}
	mcPrecisions   = []string{"high", "medium", "low"}
	mcImpls        = []string{"native", "tree_sitter", "semgrep", "unspecified"}
	mcContexts     = []string{"none", "client_error_4xx", "static_asset"}
	mcApplicable   = []string{"unknown", "applicable", "evidence_against"}
	mcAuth         = []string{"unknown", "public", "required"}
	mcSeverities   = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	mcFailOns      = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	mcCategories   = []string{"deps", "secrets", "injection", "auth", "headers"}
	mcToolSets     = [][]string{{"semgrep"}, {"codeql"}, {"codeql", "semgrep"}}
	mcSeverityCaps = map[string]string{"low": "MEDIUM", "medium": "HIGH", "high": "CRITICAL"}
)

// generatedVector draws one CONSISTENT fact set: every combination the
// specification's consistency rules would reject is repaired first, because
// the engine never produces those combinations and they are covered by the
// specification's own consistency vectors instead.
func generatedVector(r *rand.Rand, i int) mcVector {
	pick := func(xs []string) string { return xs[r.Intn(len(xs))] }
	coin := func(p float64) bool { return r.Float64() < p }
	x := mcFacts{
		ObservationSource: pick(mcSources), RulePrecision: pick(mcPrecisions),
		AnalyzerImplementation: pick(mcImpls), ResponseContext: pick(mcContexts),
		DependencyApplicability: pick(mcApplicable), AuthExpectation: pick(mcAuth),
		ReachableTaintPath: coin(0.3), RouteConfirmed: coin(0.2), ProvenPath: coin(0.1),
		PayloadValidated: coin(0.2), DirectObservation: coin(0.2), CrossToolCorroborated: coin(0.25),
		InTestCode: coin(0.25), FixtureShapedValue: coin(0.2), ProviderAnchoredSecret: coin(0.15),
		UnconfirmedByLiveScan: coin(0.15), CorroboratingTools: []string{},
	}
	if x.CrossToolCorroborated {
		x.CorroboratingTools = append([]string(nil), mcToolSets[r.Intn(len(mcToolSets))]...)
	}
	if x.ProvenPath {
		x.RouteConfirmed, x.ReachableTaintPath = true, true
		if x.AnalyzerImplementation == "semgrep" {
			x.AnalyzerImplementation = "tree_sitter"
		}
	}
	live := x.ObservationSource == "blackbox" || x.ObservationSource == "correlated"
	if !live {
		x.DirectObservation, x.PayloadValidated = false, false
	}
	severity := pick(mcSeverities)
	if models.SeverityRank(models.Severity(severity)) > models.SeverityRank(models.Severity(mcSeverityCaps[x.RulePrecision])) {
		severity = mcSeverityCaps[x.RulePrecision]
	}
	return mcVector{
		ID: fmt.Sprintf("generated-%03d", i), Severity: severity, Category: pick(mcCategories),
		FailOn: pick(mcFailOns), Facts: x,
	}
}

func buildManagedCIVectors(t *testing.T) mcVectorFile {
	t.Helper()
	var vectors []mcVector
	for _, n := range namedVectors() {
		v := n.v
		v.Expected = v.classify()
		if v.Expected.Status != n.intent {
			t.Fatalf("named vector %s: engine decides %s, intended %s — a policy change must be deliberate",
				v.ID, v.Expected.Status, n.intent)
		}
		vectors = append(vectors, v)
	}
	r := rand.New(rand.NewSource(managedCISeed))
	for i := 1; i <= managedCIGenerated; i++ {
		v := generatedVector(r, i)
		v.Expected = v.classify()
		vectors = append(vectors, v)
	}
	return mcVectorFile{
		SchemaVersion: "managed-ci-finding-policy-vectors/v1",
		FindingPolicy: PolicyVersion,
		Options:       "managed_ci_default",
		GeneratedBy:   "go/internal/decision/managed_ci_policy_vectors_test.go (DecideWithOptions)",
		Vectors:       vectors,
	}
}

// encodeVectors writes one vector per line so the committed file diffs
// readably and stays small.
func encodeVectors(file mcVectorFile) ([]byte, error) {
	var buf bytes.Buffer
	head, err := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		FindingPolicy string `json:"finding_policy_version"`
		Options       string `json:"options"`
		GeneratedBy   string `json:"generated_by"`
	}{file.SchemaVersion, file.FindingPolicy, file.Options, file.GeneratedBy})
	if err != nil {
		return nil, err
	}
	buf.Write(head[:len(head)-1])
	buf.WriteString(`,"vectors":[` + "\n")
	for i, v := range file.Vectors {
		line, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		if i < len(file.Vectors)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("]}\n")
	return buf.Bytes(), nil
}

func TestManagedCIPolicyVectors(t *testing.T) {
	want, err := encodeVectors(buildManagedCIVectors(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.FromSlash(managedCIVectorsPath)
	if os.Getenv("FENDIX_WRITE_MANAGED_CI_VECTORS") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed vectors: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: the engine no longer reproduces the committed managed-CI vectors. "+
			"If the policy change is intentional, bump PolicyVersion and the specification, then regenerate.", path)
	}
}

// TestManagedCIVectorsReplayThroughTheEngine re-decides every committed
// vector from its facts alone, independent of the generator above.
func TestManagedCIVectorsReplayThroughTheEngine(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(managedCIVectorsPath))
	if err != nil {
		t.Fatal(err)
	}
	var file mcVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.FindingPolicy != PolicyVersion {
		t.Fatalf("vectors are for finding policy %s, engine is %s", file.FindingPolicy, PolicyVersion)
	}
	if len(file.Vectors) < managedCIGenerated {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		if got := v.classify(); !reflect.DeepEqual(got, v.Expected) {
			t.Errorf("%s: engine %+v, vector %+v", v.ID, got, v.Expected)
		}
	}
}

// TestManagedCISpecificationNamesThisPolicyVersion binds the declarative
// specification to PolicyVersion: bumping one without the other fails.
func TestManagedCISpecificationNamesThisPolicyVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(managedCISpecPath))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		FindingPolicyVersion string                     `json:"finding_policy_version"`
		Options              map[string]map[string]bool `json:"options"`
		Facts                map[string]json.RawMessage `json:"facts"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.FindingPolicyVersion != PolicyVersion {
		t.Fatalf("specification is for %s, engine PolicyVersion is %s", spec.FindingPolicyVersion, PolicyVersion)
	}
	opts := spec.Options["managed_ci_default"]
	if opts["enforce_confidence"] != managedCIOptions.EnforceConfidence ||
		opts["deescalate_tests"] != managedCIOptions.DeescalateTests ||
		opts["block_on_inapplicable"] != managedCIOptions.BlockOnInapplicable {
		t.Fatalf("managed_ci_default options %v differ from the profile this test decides with", opts)
	}
	fields := reflect.TypeOf(mcFacts{})
	if fields.NumField() != len(spec.Facts) {
		t.Fatalf("specification declares %d facts, the engine mapping covers %d", len(spec.Facts), fields.NumField())
	}
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Tag.Get("json")
		if _, ok := spec.Facts[name]; !ok {
			t.Errorf("engine mapping has fact %q the specification does not declare", name)
		}
	}
}
