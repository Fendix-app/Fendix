package decision

import (
	"reflect"
	"testing"
)

// The v3.5.0-rc.2 isolated end to end showed one govulncheck finding
// (golang.org/x/text v0.3.5, GO-2021-0113, HIGH) as WARN in the local report
// and BLOCK in the backend's managed decision for a fail_on HIGH binding.
//
// That is a threshold difference, not a policy split. The managed scan runs
// with no --fail-on (action.yml, managed step), so the engine decides every
// finding through the below-threshold arm; the backend classifies the same
// facts against the binding's threshold. This test pins the exact facts the
// rc.2 engine exported for that finding and what the production decision path
// does with them at each threshold, in the contract's vocabulary, so the
// backend's twin test (managed_ci/tests/test_local_threshold_parity.py) and
// this one assert the same result.
//
// The committed vectors cover neighbouring fact sets
// (dependency-applicable-blocks is native + applicable) but not this one,
// which is what a real govulncheck finding carries today.
func TestRC2GovulncheckFindingClassifiesByThreshold(t *testing.T) {
	facts := mcFacts{
		AnalyzerImplementation:  "unspecified",
		AuthExpectation:         "unknown",
		CorroboratingTools:      []string{},
		CrossToolCorroborated:   false,
		DependencyApplicability: "unknown",
		DirectObservation:       false,
		FixtureShapedValue:      false,
		InTestCode:              false,
		ObservationSource:       "whitebox",
		PayloadValidated:        false,
		ProvenPath:              false,
		ProviderAnchoredSecret:  false,
		ReachableTaintPath:      false,
		ResponseContext:         "none",
		RouteConfirmed:          false,
		RulePrecision:           "high",
		UnconfirmedByLiveScan:   false,
	}
	scoring := mcExpected{
		Score:              75,
		Band:               "HIGH",
		ScoreCodes:         []string{"base_detection", "static_evidence", "deterministic_detection"},
		IndependentSignals: []string{},
		SelfEvidentSignals: []string{"deterministic detection in production code"},
	}
	with := func(status string, trace ...string) mcExpected {
		e := scoring
		e.Status, e.RuleTrace = status, trace
		return e
	}
	cases := []struct {
		name   string
		failOn string
		want   mcExpected
	}{
		// No --fail-on: what the managed scan's local report shows. There is no
		// managed counterpart; the backend refuses to classify without a
		// threshold.
		{"no threshold (local default)", "", with("WARN", "actionable_below_threshold")},
		// The binding's threshold in the rc.2 run, and the backend's default.
		{"HIGH", "HIGH", with("BLOCK", "block_corroborated")},
		{"CRITICAL", "CRITICAL", with("WARN", "actionable_below_threshold")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mcVector{Severity: "HIGH", Category: "deps", FailOn: tc.failOn, Facts: facts}.classify()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("fail_on %q:\n got  %+v\n want %+v", tc.failOn, got, tc.want)
			}
		})
	}
}
