package engine

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// Round 6, WS-E2: A-D5 engine half (PHASE1-GATE-PROPOSALS §1.3 B, §1.4b; gate
// G2.9). Required-probe coverage is complete only when every required probe was
// evaluated: no percentage threshold. Every planned probe is required (OR-23;
// the engine has no endpoint exclusion). The engine's own coverage
// statement (the active-probes scanner_status entry, and so
// coverage.configured_complete for the CLI, the Action and --require-analyzers)
// must agree, and must also never read complete when its counts do not add up
// or the group listing hit its ceiling.
//
// Assertions are on outcomes only (not ok, configured_complete false, a reason
// from the closed vocabulary): which closed reason the fix uses is its choice.

func wse2Records(evaluated int, extra ...scanner.ProbeRecord) []scanner.ProbeRecord {
	var r []scanner.ProbeRecord
	for i := 0; i < evaluated; i++ {
		r = append(r, scanner.ProbeRecord{Endpoint: "http://t.example/open", Method: "GET", ProbeType: scanner.ProbeSQLi, Status: 200})
	}
	return append(r, extra...)
}

func wse2Gated(n, status int, endpoints int) []scanner.ProbeRecord {
	var r []scanner.ProbeRecord
	for i := 0; i < n; i++ {
		r = append(r, scanner.ProbeRecord{Endpoint: fmt.Sprintf("http://t.example/g/%06d", i%endpoints), Method: "GET", ProbeType: scanner.ProbeSQLi, Status: status})
	}
	return r
}

func wse2Lost(n int, origin scanner.ProbeOrigin, reason scanner.ProbeReason) []scanner.ProbeRecord {
	var r []scanner.ProbeRecord
	for i := 0; i < n; i++ {
		r = append(r, scanner.ProbeRecord{Endpoint: "http://t.example/l", Method: "GET", ProbeType: scanner.ProbeXSS,
			Failure: &scanner.ProbeFailure{Origin: origin, Reason: reason, Evidence: "test"}})
	}
	return r
}

func wse2Phase(recs []scanner.ProbeRecord) checkPhaseOutcome {
	return checkPhaseOutcome{Attempted: len(recs), Probes: scanner.SummarizeProbes(recs, nil)}
}

// wse2Complete is the engine's coverage statement for a pass: the entry and
// whether BuildCoverage calls the scan configured-complete.
func wse2Complete(t *testing.T, phase checkPhaseOutcome) (reporters.ScannerStatus, bool) {
	t.Helper()
	st := activeEntry(t, phase)
	cov := reporters.BuildCoverage([]reporters.ScannerStatus{st}, nil, false)
	return st, cov.ConfiguredComplete
}

func wse2AssertNotComplete(t *testing.T, label string, phase checkPhaseOutcome) {
	t.Helper()
	st, complete := wse2Complete(t, phase)
	if st.State == reporters.ScannerOK || complete {
		t.Errorf("%s: active-probes %s (configured_complete %v), want not complete: %q", label, st.State, complete, st.Detail)
	}
	if st.State != reporters.ScannerOK && st.Reason != "" && !st.Reason.Valid() {
		t.Errorf("%s: reason %q is outside the closed vocabulary (no new enum)", label, st.Reason)
	}
}

// V2 (R5-07): 22 of 2,687 probes evaluated, the rest gated 403. Today: ok.
func TestRecordBlackbox_D5_R5_07ShapeIsNotComplete(t *testing.T) {
	wse2AssertNotComplete(t, "R5-07 2687/22/2665 gated 403", wse2Phase(wse2Records(22, wse2Gated(2665, 403, 533)...)))
}

// V3, V4 and the gated statuses alone: no threshold, so one unevaluated
// required probe is enough.
func TestRecordBlackbox_D5_OneUnevaluatedRequiredProbeIsNotComplete(t *testing.T) {
	wse2AssertNotComplete(t, "V3 999/1000, one gated 404", wse2Phase(wse2Records(999, wse2Gated(1, 404, 1)...)))
	wse2AssertNotComplete(t, "V4 7/10, three target timeouts", wse2Phase(wse2Records(7, wse2Lost(3, scanner.OriginTarget, scanner.ReasonTimeout)...)))
	for _, s := range models.GatedStatuses {
		wse2AssertNotComplete(t, fmt.Sprintf("9/10, one gated %d", s), wse2Phase(wse2Records(9, wse2Gated(1, s, 1)...)))
	}
	wse2AssertNotComplete(t, "9/10, one rate-limited (429)", wse2Phase(wse2Records(9, scanner.ProbeRecord{Endpoint: "http://t.example/r", Method: "GET", ProbeType: scanner.ProbeSQLi, Status: 429, Retries: 2})))
}

// Neighbours that must keep today's reading.
func TestRecordBlackbox_D5_UnchangedReadings(t *testing.T) {
	if st, complete := wse2Complete(t, wse2Phase(wse2Records(10))); st.State != reporters.ScannerOK || !complete {
		t.Errorf("V1 every probe evaluated: %s complete=%v, want ok/complete", st.State, complete)
	}
	// V6 and the B-17 total shape: partial and total unknown-origin loss both
	// stay not complete, and the counts that tell them apart are exact.
	for name, c := range map[string]struct{ ev, lost int }{"partial 10/8/2": {8, 2}, "total 10/0/10": {0, 10}} {
		phase := wse2Phase(wse2Records(c.ev, wse2Lost(c.lost, scanner.OriginUnknown, scanner.ReasonDNSFailure)...))
		wse2AssertNotComplete(t, name, phase)
		if p := phase.Probes; p.Attempted != 10 || p.Evaluated != c.ev || p.UnknownOrigin != c.lost {
			t.Errorf("%s: counts %d/%d/%d", name, p.Attempted, p.Evaluated, p.UnknownOrigin)
		}
	}
	wse2AssertNotComplete(t, "V9 all gated", wse2Phase(wse2Gated(2644, 403, 2644)))
	wse2AssertNotComplete(t, "V10 scanner failure", wse2Phase(wse2Records(9, wse2Lost(1, scanner.OriginScanner, scanner.ReasonInternalError)...)))
}

// Counts that do not add up are unreadable, so never complete (fail closed).
// Each of these reads ok today.
func TestRecordBlackbox_D5_InconsistentCountsAreNeverComplete(t *testing.T) {
	gated := func(total int, by map[string]int) models.ProbeGated {
		return models.ProbeGated{Total: total, ByStatus: by}
	}
	for name, cov := range map[string]models.ActiveProbeCoverage{
		"attempted below the sum": {Attempted: 10, Evaluated: 10, Inconclusive: 1,
			Reasons: map[string]map[string]int{"target": {"timeout": 1}}},
		"attempted above the sum (probes unaccounted)": {Attempted: 12, Evaluated: 10},
		"a negative count": {Attempted: 10, Evaluated: 11, Inconclusive: -1,
			Reasons: map[string]map[string]int{"target": {"timeout": -1}}},
		"a negative attempted":                {Attempted: -1, Evaluated: 1, Inconclusive: -2},
		"reasons do not add up to the origin": {Attempted: 10, Evaluated: 8, Inconclusive: 2, Reasons: map[string]map[string]int{"target": {"timeout": 1}}},
		"gated above inconclusive": {Attempted: 10, Evaluated: 9, Inconclusive: 1,
			Reasons: map[string]map[string]int{"target": {"gated": 1}}, Gated: gated(3, map[string]int{"403": 3})},
		"gated by status does not add up": {Attempted: 10, Evaluated: 8, Inconclusive: 2,
			Reasons: map[string]map[string]int{"target": {"gated": 2}}, Gated: gated(2, map[string]int{"403": 1})},
	} {
		t.Run(name, func(t *testing.T) {
			wse2AssertNotComplete(t, name, checkPhaseOutcome{Attempted: cov.Attempted, Probes: cov})
		})
	}
}

// Above the listing ceiling H the pass declares the overflow and cannot be
// complete; the declaration travels in the coverage JSON.
func TestRecordBlackbox_D5_CeilingReachedIsNotComplete(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 100,005 probe records")
	}
	const h = 100_000
	// 3 probes per group (review B6).
	phase := wse2Phase(wse2Records(10, wse2Gated(3*(h+5), 403, h+5)...))
	wse2AssertNotComplete(t, "listing ceiling reached", phase)
	blob, err := json.Marshal(phase.Probes)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	if v, _ := m["listing_ceiling_reached"].(bool); !v {
		t.Errorf("active_probes does not declare listing_ceiling_reached past H=%d groups", h)
	}
}
