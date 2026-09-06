package reporters

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestScannerReason_PairingWithState(t *testing.T) {
	skips := []ScannerReason{ReasonNotApplicable, ReasonDiffUnchanged, ReasonDisabledByFlag, ReasonDisabledOffline, ReasonDependencyMissing, ReasonUnsupportedTarget}
	fails := []ScannerReason{ReasonNetworkError, ReasonTimeout, ReasonExecutionError, ReasonMalformedOutput, ReasonTruncatedOutput, ReasonInputError, ReasonNoEndpoints}
	for _, r := range skips {
		if !r.IsSkip() || r.IsFail() || !r.Valid() {
			t.Errorf("%s must be a valid skip reason", r)
		}
	}
	for _, r := range fails {
		if !r.IsFail() || r.IsSkip() || !r.Valid() {
			t.Errorf("%s must be a valid fail reason", r)
		}
	}
	if ScannerReason("bogus").Valid() {
		t.Error("bogus must not validate")
	}
	if got := len(skips) + len(fails); got != 13 {
		t.Fatalf("contract version 1 defines 13 reasons, test lists %d", got)
	}
}

func TestScannerStatus_Class(t *testing.T) {
	for _, tc := range []struct {
		in   ScannerStatus
		want string
	}{
		{ScannerStatus{Name: "secrets", State: ScannerOK}, "ok"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonNotApplicable}, "not_applicable"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonDiffUnchanged}, "not_applicable"},
		{ScannerStatus{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag}, "disabled"},
		{ScannerStatus{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline}, "disabled"},
		{ScannerStatus{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDependencyMissing}, "unavailable"},
		{ScannerStatus{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget}, "unsupported"},
		{ScannerStatus{Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError}, "failed"},
		{ScannerStatus{Name: "pip", State: ScannerFailed}, "failed"},   // legacy failed entry, no reason
		{ScannerStatus{Name: "pip", State: ScannerSkipped}, "unknown"}, // legacy skip, no reason
		{ScannerStatus{Name: "pip", State: "weird"}, "unknown"},
		{ScannerStatus{Name: "pip", State: ScannerSkipped, Reason: ReasonNetworkError}, "unknown"}, // mismatched pairing
	} {
		if got := tc.in.Class(); got != tc.want {
			t.Errorf("%+v: Class() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBuildCoverage(t *testing.T) {
	status := []ScannerStatus{
		{Name: "dast", State: ScannerSkipped, Reason: ReasonNotApplicable},
		{Name: "secrets", State: ScannerOK},
		{Name: "semgrep", State: ScannerSkipped, Reason: ReasonDisabledByFlag, Detail: "--fast"},
		{Name: "pip", State: ScannerOK, Attempts: 2},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget, Detail: "package.json without package-lock.json"},
		{Name: "python-engine", State: ScannerOK},
		{Name: "python-engine/deps", State: ScannerSkipped, Reason: ReasonDependencyMissing, Detail: "No module named 'packaging'"},
	}
	got := BuildCoverage(status, []string{"semgrep", "python-engine"}, true)
	want := Coverage{
		ContractVersion:    1,
		Strict:             true,
		ConfiguredComplete: false,
		Gaps:               []string{"python-engine/deps"},
		Limitations:        []string{"npm: package.json without package-lock.json"},
		RequiredAnalyzers:  []string{"semgrep", "python-engine"},
		RequiredGaps:       []string{"semgrep"},
		Retried:            []string{"pip"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildCoverage mismatch\n got: %+v\nwant: %+v", got, want)
	}
	if got.StrictOK() {
		t.Error("StrictOK must be false when required_gaps is non-empty")
	}
}

func TestBuildCoverage_RequiredSatisfiedOnlyByOkOrNotApplicable(t *testing.T) {
	status := []ScannerStatus{
		{Name: "semgrep", State: ScannerOK},
		{Name: "pip", State: ScannerSkipped, Reason: ReasonNotApplicable},
		{Name: "npm", State: ScannerSkipped, Reason: ReasonUnsupportedTarget},
		{Name: "govulncheck", State: ScannerSkipped, Reason: ReasonDisabledOffline},
	}
	got := BuildCoverage(status, []string{"semgrep", "pip", "npm", "govulncheck", "textscan"}, true)
	want := []string{"npm", "govulncheck", "textscan"} // unsupported, disabled and missing do not satisfy an explicit requirement
	if !reflect.DeepEqual(got.RequiredGaps, want) {
		t.Fatalf("RequiredGaps = %v, want %v", got.RequiredGaps, want)
	}
	if !got.ConfiguredComplete {
		t.Error("no engine gap classes present, ConfiguredComplete must be true regardless of required_gaps")
	}
}

func TestBuildCoverage_EmptyListsAreArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(BuildCoverage(nil, nil, false)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"gaps":[]`, `"limitations":[]`, `"required_analyzers":[]`, `"required_gaps":[]`, `"retried":[]`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("encoded coverage must contain %s, got %s", key, buf.String())
		}
	}
	if !strings.Contains(buf.String(), `"configured_complete":true`) {
		t.Error("an empty status list is trivially complete")
	}
}

func TestScannerStatus_JSONOmitsEmptyReasonAndAttempts(t *testing.T) {
	b, _ := json.Marshal(ScannerStatus{Name: "secrets", State: ScannerOK})
	if strings.Contains(string(b), "reason") || strings.Contains(string(b), "attempts") {
		t.Fatalf("ok entry must omit reason and attempts: %s", b)
	}
	b, _ = json.Marshal(ScannerStatus{Name: "pip", State: ScannerOK, Attempts: 2})
	if !strings.Contains(string(b), `"attempts":2`) {
		t.Fatalf("attempts > 1 must be emitted: %s", b)
	}
}

func TestScanMetadata_CoverageRoundTripsThroughRenderJSON(t *testing.T) {
	cov := BuildCoverage([]ScannerStatus{{Name: "secrets", State: ScannerOK}}, nil, false)
	meta := ScanMetadata{Version: "dev", Mode: "whitebox", Coverage: &cov, PolicyVersion: "1.0.0"}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, nil, meta); err != nil {
		t.Fatal(err)
	}
	var back JSONReport
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Metadata.Coverage == nil || back.Metadata.Coverage.ContractVersion != 1 {
		t.Fatalf("coverage did not round-trip: %+v", back.Metadata.Coverage)
	}
	if back.Metadata.PolicyVersion != "1.0.0" {
		t.Fatalf("policy_version = %q", back.Metadata.PolicyVersion)
	}
	// A live scan never sets the backend passthrough fields; they must not appear.
	if strings.Contains(buf.String(), "release_decision") || strings.Contains(buf.String(), "coverage_state") {
		t.Fatalf("passthrough fields must be omitted when unset: %s", buf.String())
	}
}
