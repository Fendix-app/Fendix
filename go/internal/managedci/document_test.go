package managedci

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testContext() Context {
	base := "2222222222222222222222222222222222222222"
	pr := 17
	return Context{
		SchemaVersion: ContextSchemaVersion, ScanExecutionID: "33333333-3333-4333-8333-333333333333",
		TenantID: "11111111-1111-4111-8111-111111111111", AssetID: "22222222-2222-4222-8222-222222222222",
		Environment: "staging", Provider: "github", RepositoryID: "123456", RepositoryOwnerID: "7654321",
		Repository: "acme/payments", HeadSHA: "1111111111111111111111111111111111111111", BaseSHA: &base,
		PullRequest: &pr, WorkflowName: "Fendix managed scan",
		WorkflowRef: "acme/payments/.github/workflows/fendix.yml@refs/heads/main",
		RunID:       "987654", RunAttempt: 1, EventName: "pull_request",
	}
}

func cleanFacts() Facts {
	return Facts{
		AnalyzerImplementation: implNative, AuthExpectation: authUnknown, CorroboratingTools: []string{},
		DependencyApplicability: applicabilityUnknown, ObservationSource: sourceWhitebox,
		ResponseContext: contextNone, RulePrecision: precisionHigh,
	}
}

func testInput() Input {
	return Input{
		Context: testContext(),
		Engine: Engine{
			Version: "v3.4.1", BuildDigest: "sha256:" + strings.Repeat("a", 64),
			ReportSchemaVersion: 2, FindingPolicyVersion: "1.0.0",
		},
		Analyzers: []Analyzer{
			{AnalyzerID: "sast", AnalyzerVersion: "v3.4.1", Status: "completed", ReasonCode: "completed", Attempts: 1, FindingCount: 1},
			{AnalyzerID: "sca", AnalyzerVersion: "v3.4.1", Status: "completed", ReasonCode: "completed", Attempts: 1, FindingCount: 0},
		},
		Coverage: Coverage{ObservedAnalyzers: []string{"sast", "sca"}},
		Findings: []Finding{{
			AnalyzerID: "sast", Category: "secrets", EvidenceFacts: cleanFacts(),
			EvidenceHashes: []string{EvidenceHash("one")}, FindingID: "SEC-1",
			Fingerprint: strings.Repeat("e", 64), RuleID: "SEC-SECRET-001", Severity: "HIGH",
		}},
		GeneratedAt:          time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC),
		EvidenceSubmissionID: "44444444-4444-4444-8444-444444444444",
		ConfigurationInputs:  map[string]string{"code_scan": "true"},
	}
}

func TestBuildProducesTheSubmissionTheContractDescribes(t *testing.T) {
	submission, body, err := Build(testInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if submission.APIVersion != APIVersion || submission.Manifest.SchemaVersion != ManifestSchemaVersion {
		t.Errorf("wrong contract versions: %+v", submission.APIVersion)
	}
	want := "github:123456:987654:1:1111111111111111111111111111111111111111"
	if submission.IdempotencyKey != want {
		t.Errorf("idempotency key = %q, want %q", submission.IdempotencyKey, want)
	}
	if submission.Manifest.Sanitization.SourceExcerptsIncluded {
		t.Error("managed evidence must never carry source excerpts")
	}
	if !strings.HasPrefix(submission.Manifest.ArtifactHash, "sha256:") ||
		submission.Manifest.ArtifactHash == submission.Manifest.ConfigurationHash {
		t.Errorf("artifact and configuration hashes look wrong: %q / %q",
			submission.Manifest.ArtifactHash, submission.Manifest.ConfigurationHash)
	}
	if strings.Contains(string(body), "producer_diagnostics") {
		t.Error("managed evidence must not carry producer diagnostics")
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
}

// The same observations must produce the same bytes, or the backend's replay
// detection (same key + same artifact hash + same canonical digest) turns a
// retry into a conflict.
func TestBuildIsByteStable(t *testing.T) {
	_, first, err := Build(testInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for i := 0; i < 5; i++ {
		_, again, err := Build(testInput())
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("identical evidence produced different bytes")
		}
	}
}

// Input order must not change the document: the exporter sorts, so two runs
// that found the same things agree even if the scanners finished differently.
func TestBuildIsIndependentOfInputOrder(t *testing.T) {
	in := testInput()
	second := Finding{
		AnalyzerID: "sca", Category: "deps", EvidenceFacts: cleanFacts(),
		EvidenceHashes: []string{EvidenceHash("two")}, FindingID: "SEC-2",
		Fingerprint: strings.Repeat("b", 64), RuleID: "CVE-2026-1", Severity: "MEDIUM",
	}
	in.Findings = append(in.Findings, second)
	in.Analyzers[1].FindingCount = 1
	_, forward, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	reversed := testInput()
	reversed.Findings = []Finding{second, in.Findings[0]}
	reversed.Analyzers = []Analyzer{in.Analyzers[1], in.Analyzers[0]}
	_, backward, err := Build(reversed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if string(forward) != string(backward) {
		t.Error("the document depends on the order the scanners reported in")
	}
}

// The artifact hash identifies the EVIDENCE. A retry from a different
// workflow attempt carries the same evidence and must hash the same.
func TestArtifactHashCoversEvidenceNotIdentity(t *testing.T) {
	first, _, err := Build(testInput())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	other := testInput()
	other.Context.RunAttempt = 2
	other.EvidenceSubmissionID = "55555555-5555-4555-8555-555555555555"
	other.GeneratedAt = other.GeneratedAt.Add(time.Hour)
	second, _, err := Build(other)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if first.Manifest.ArtifactHash != second.Manifest.ArtifactHash {
		t.Error("the artifact hash changed although the evidence did not")
	}
	changed := testInput()
	changed.Findings[0].Severity = "CRITICAL"
	third, _, err := Build(changed)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if third.Manifest.ArtifactHash == first.Manifest.ArtifactHash {
		t.Error("different evidence produced the same artifact hash")
	}
}

func TestProvenanceRulesAreEnforcedBeforeSubmission(t *testing.T) {
	cases := map[string]func(*Input){
		"finding names an analyzer that never ran": func(in *Input) { in.Findings[0].AnalyzerID = "dast" },
		"analyzer count disagrees with findings":   func(in *Input) { in.Analyzers[0].FindingCount = 7 },
		"observed analyzer was never reported":     func(in *Input) { in.Coverage.ObservedAnalyzers = []string{"sast", "dast"} },
		"an analyzer is reported twice":            func(in *Input) { in.Analyzers = append(in.Analyzers, in.Analyzers[0]) },
		"a finding identifies no evidence":         func(in *Input) { in.Findings[0].EvidenceHashes = nil },
	}
	for name, mutate := range cases {
		in := testInput()
		mutate(&in)
		if _, _, err := Build(in); err == nil {
			t.Errorf("%s: the document was built anyway", name)
		}
	}
}

// A finding whose facts contradict each other could only ever be
// unclassifiable at the backend. The exporter refuses instead, and names the
// finding and the rule without quoting anything from the code.
func TestContradictoryFactsAreRefusedWithASafeMessage(t *testing.T) {
	in := testInput()
	in.Findings[0].EvidenceFacts.CrossToolCorroborated = true // with no tools listed
	_, _, err := Build(in)
	if err == nil {
		t.Fatal("contradictory facts were exported")
	}
	var inconsistent ErrInconsistent
	if !errors.As(err, &inconsistent) {
		t.Fatalf("error = %T, want ErrInconsistent", err)
	}
	if inconsistent.FindingID != "SEC-1" || inconsistent.Rule != RuleCrossToolFlagMatchesTools {
		t.Errorf("error does not name the finding and rule: %+v", inconsistent)
	}
}

func TestContextIsValidatedBeforeAnythingIsBuilt(t *testing.T) {
	cases := map[string]func(*Context){
		"wrong schema":     func(c *Context) { c.SchemaVersion = "managed-scan-context/v9" },
		"no repository id": func(c *Context) { c.RepositoryID = "" },
		"no head sha":      func(c *Context) { c.HeadSHA = "  " },
		"no run attempt":   func(c *Context) { c.RunAttempt = 0 },
	}
	for name, mutate := range cases {
		in := testInput()
		mutate(&in.Context)
		if _, _, err := Build(in); err == nil {
			t.Errorf("%s: the document was built anyway", name)
		}
	}
}

// Both ceilings are independent, and neither truncates.
func TestEvidenceOverEitherCeilingFailsClosed(t *testing.T) {
	in := testInput()
	in.Findings = make([]Finding, MaxFindings+1)
	for i := range in.Findings {
		in.Findings[i] = testInput().Findings[0]
	}
	in.Analyzers[0].FindingCount = len(in.Findings)
	_, _, err := Build(in)
	var tooLarge ErrTooLarge
	if !errors.As(err, &tooLarge) || tooLarge.Limit != "finding count" {
		t.Fatalf("error = %v, want a finding-count ceiling error", err)
	}

	big := testInput()
	huge := strings.Repeat("x", 4096)
	big.Findings = make([]Finding, 2400)
	for i := range big.Findings {
		finding := testInput().Findings[0]
		finding.FindingID = huge + string(rune('a'+i%26))
		big.Findings[i] = finding
	}
	big.Analyzers[0].FindingCount = len(big.Findings)
	_, _, err = Build(big)
	if !errors.As(err, &tooLarge) || tooLarge.Limit != "request body" {
		t.Fatalf("error = %v, want a request-body ceiling error", err)
	}
	if tooLarge.Max != MaxBodyBytes {
		t.Errorf("body ceiling = %d, want %d", tooLarge.Max, MaxBodyBytes)
	}
}

func TestLocationsAreRepositoryRelativeOrOmitted(t *testing.T) {
	cases := map[string]struct {
		endpoint  string
		workspace string
		ok        bool
		path      string
		line      int
	}{
		"relative with line": {"app/config.py:7", "", true, "app/config.py", 7},
		"workspace stripped": {"/work/repo/app/main.go:12", "/work/repo", true, "app/main.go", 12},
		"dot slash":          {"./src/index.ts", "", true, "src/index.ts", 0},
		"absolute":           {"/etc/passwd", "", false, "", 0},
		"home directory":     {"Users/asaied/secrets.py:3", "", false, "", 0},
		"parent traversal":   {"../../etc/shadow", "", false, "", 0},
		"windows drive":      {"C:/Users/dev/app.cs", "", false, "", 0},
		"empty":              {"", "", false, "", 0},
	}
	for name, tc := range cases {
		location, ok := RelativeLocation(tc.endpoint, tc.workspace)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", name, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if location.Path != tc.path {
			t.Errorf("%s: path = %q, want %q", name, location.Path, tc.path)
		}
		if tc.line > 0 && (location.StartLine == nil || *location.StartLine != tc.line) {
			t.Errorf("%s: line = %v, want %d", name, location.StartLine, tc.line)
		}
	}
}

func TestEvidenceHashNeverCarriesTheItem(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	hash := EvidenceHash(secret)
	if strings.Contains(hash, secret) || !strings.HasPrefix(hash, "sha256:") || len(hash) != 71 {
		t.Errorf("evidence hash is wrong: %q", hash)
	}
}
