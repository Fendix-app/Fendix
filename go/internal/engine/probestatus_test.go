package engine

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

func activeEntry(t *testing.T, phase checkPhaseOutcome) reporters.ScannerStatus {
	t.Helper()
	var l scannerStatusList
	recordBlackbox(&l, &models.ScanConfig{URL: "http://t", EnableActive: true}, 2, nil, nil, phase)
	return find(l, AnalyzerActiveProbes)
}

func reasons(target, unknown, scanner map[string]int) map[string]map[string]int {
	m := map[string]map[string]int{}
	if target != nil {
		m["target"] = target
	}
	if unknown != nil {
		m["unknown"] = unknown
	}
	if scanner != nil {
		m["scanner"] = scanner
	}
	return m
}

// The exact detail strings (contract C5.3).
func TestProbeDetail_ExactStrings(t *testing.T) {
	t.Run("ok, every probe evaluated", func(t *testing.T) {
		st := activeEntry(t, checkPhaseOutcome{Attempted: 10, Probes: models.ActiveProbeCoverage{Attempted: 10, Evaluated: 10}})
		if st.State != reporters.ScannerOK || st.Detail != "probe evaluation: 10 attempted, 10 evaluated, 0 inconclusive (target), 0 unknown-origin, 0 scanner-failed" {
			t.Fatalf("%s %q", st.State, st.Detail)
		}
	})
	t.Run("ok with confirmed target-side inconclusive probes", func(t *testing.T) {
		st := activeEntry(t, checkPhaseOutcome{Attempted: 10, Probes: models.ActiveProbeCoverage{Attempted: 10, Evaluated: 4, Inconclusive: 6,
			Reasons: reasons(map[string]int{"timeout": 3, "connection_reset": 1, "rate_limited": 2}, nil, nil)}})
		want := "probe evaluation: 10 attempted, 4 evaluated, 6 inconclusive (target), 0 unknown-origin, 0 scanner-failed; " +
			"inconclusive probes (target did not answer): timeout 3, connection_reset 1, rate_limited 2"
		if st.State != reporters.ScannerOK || st.Detail != want {
			t.Fatalf("%s %q", st.State, st.Detail)
		}
	})
	t.Run("failed, loss text first", func(t *testing.T) {
		st := activeEntry(t, checkPhaseOutcome{Attempted: 10, Probes: models.ActiveProbeCoverage{Attempted: 10, Evaluated: 4, Inconclusive: 1, UnknownOrigin: 3, ScannerFailed: 2,
			Reasons: reasons(map[string]int{"timeout": 1}, map[string]int{"dns_failure": 2, "unclassified": 1}, map[string]int{"not_sent": 2})}})
		want := "lost evaluation: 5 probe(s) not evaluated (3 unknown-origin, 2 scanner-failed); " +
			"probe evaluation: 10 attempted, 4 evaluated, 1 inconclusive (target), 3 unknown-origin, 2 scanner-failed; " +
			"and 3 more (see report metadata)"
		if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonExecutionError {
			t.Fatalf("%s/%s", st.State, st.Reason)
		}
		// Whatever does not fit 240 bytes is dropped whole and counted, never cut.
		if len(st.Detail) > detailMax || strings.HasSuffix(st.Detail, "…") {
			t.Fatalf("detail cut or over budget: %d %q", len(st.Detail), st.Detail)
		}
		if !strings.HasPrefix(st.Detail, "lost evaluation: 5 probe(s) not evaluated (3 unknown-origin, 2 scanner-failed); probe evaluation: 10 attempted") {
			t.Fatalf("loss must come first: %q", st.Detail)
		}
		if st.Detail != want {
			t.Fatalf("\n got %q\nwant %q", st.Detail, want)
		}
	})
	t.Run("failed, reason lists that do not fit are counted not cut", func(t *testing.T) {
		st := activeEntry(t, checkPhaseOutcome{Attempted: 3, Probes: models.ActiveProbeCoverage{Attempted: 3, Evaluated: 1, UnknownOrigin: 1, ScannerFailed: 1,
			Reasons: reasons(nil, map[string]int{"dns_failure": 1}, map[string]int{"not_sent": 1})}})
		want := "lost evaluation: 2 probe(s) not evaluated (1 unknown-origin, 1 scanner-failed); " +
			"probe evaluation: 3 attempted, 1 evaluated, 0 inconclusive (target), 1 unknown-origin, 1 scanner-failed; " +
			"unknown-origin probes (not evaluated): dns_failure 1; " +
			"scanner-failed probes (not evaluated): not_sent 1"
		// 240 bytes holds the loss and the counts; the reason lists that do not fit
		// are dropped whole and counted ("and N more"), the complete lists live in
		// metadata.coverage.active_probes.
		want = "lost evaluation: 2 probe(s) not evaluated (1 unknown-origin, 1 scanner-failed); " +
			"probe evaluation: 3 attempted, 1 evaluated, 0 inconclusive (target), 1 unknown-origin, 1 scanner-failed; " +
			"and 2 more (see report metadata)"
		if st.Detail != want {
			t.Fatalf("\n got %q\nwant %q", st.Detail, want)
		}
	})
	t.Run("deadline and budget keep their cause first and add the counts", func(t *testing.T) {
		// Round 5 (C4B-18): the limit is named as a scan limit with its value, so a
		// reader can tell a limit set for the scan from a failure. The round-4b text
		// read "--max-duration elapsed ..." with no value and no word for what it was.
		st := activeEntry(t, checkPhaseOutcome{Attempted: 5, Deadline: true, Probes: models.ActiveProbeCoverage{Attempted: 5, Evaluated: 5}})
		if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonTimeout ||
			!strings.HasPrefix(st.Detail, "scan limit --max-duration=0s elapsed before the probe pass completed; probe evaluation: 5 attempted") {
			t.Fatalf("%s/%s %q", st.State, st.Reason, st.Detail)
		}
		var l scannerStatusList
		recordBlackbox(&l, &models.ScanConfig{URL: "http://t", EnableActive: true, MaxRequests: 500}, 2, nil, nil,
			checkPhaseOutcome{Attempted: 5, Rejected: 25, Probes: models.ActiveProbeCoverage{Attempted: 5, Evaluated: 5}})
		st = find(l, AnalyzerActiveProbes)
		if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonExecutionError ||
			!strings.HasPrefix(st.Detail, "scan limit --max-requests=500 exhausted: 25 requests refused before the probe pass completed; probe evaluation: 5 attempted") {
			t.Fatalf("%s/%s %q", st.State, st.Reason, st.Detail)
		}
	})
	t.Run("gated probes sit inside inconclusive and get their own segment", func(t *testing.T) {
		st := activeEntry(t, gatedPhase(10, 4, map[int]int{403: 4, 404: 2}))
		want := "probe evaluation: 10 attempted, 4 evaluated, 6 inconclusive (target), 0 unknown-origin, 0 scanner-failed; " +
			"gated probes (target answered 401/403/404/410 so not evaluated): 403 4, 404 2"
		if st.State != reporters.ScannerOK || st.Detail != want {
			t.Fatalf("%s %q", st.State, st.Detail)
		}
	})
	t.Run("gated beside probes the target did not answer", func(t *testing.T) {
		cov := models.ActiveProbeCoverage{Attempted: 10, Evaluated: 4, Inconclusive: 6, Reasons: reasons(map[string]int{"timeout": 3, "gated": 3}, nil, nil),
			Gated: models.ProbeGated{Total: 3, ByStatus: map[string]int{"401": 3}}}
		st := activeEntry(t, checkPhaseOutcome{Attempted: 10, Probes: cov})
		want := "probe evaluation: 10 attempted, 4 evaluated, 6 inconclusive (target), 0 unknown-origin, 0 scanner-failed; " +
			"inconclusive probes (target did not answer): timeout 3; " +
			"gated probes (target answered 401/403/404/410 so not evaluated): 401 3"
		if st.State != reporters.ScannerOK || st.Detail != want {
			t.Fatalf("%s %q", st.State, st.Detail)
		}
	})
	t.Run("nothing evaluated: failed, target-owned reason, counts first-class", func(t *testing.T) {
		st := activeEntry(t, gatedPhase(22, 0, map[int]int{403: 22}))
		if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonNoEndpoints {
			t.Fatalf("%s/%s %q", st.State, st.Reason, st.Detail)
		}
		if !strings.HasPrefix(st.Detail, "no probe was evaluated: the target gave none of the 22 probes an evaluable answer; probe evaluation: 22 attempted, 0 evaluated, 22 inconclusive (target), 0 unknown-origin, 0 scanner-failed") {
			t.Fatalf("detail = %q", st.Detail)
		}
		if len(st.Detail) > detailMax {
			t.Fatalf("detail over budget: %d", len(st.Detail))
		}
	})
}

// A scan whose only non-answers are the target's keeps its scan-wide
// completeness AND states it: the entry never reads as "every probe was
// evaluated" when one was not. (Round 5, C4B-06: only while at least one probe
// was evaluated. The round-4b test pinned ok for 1 attempted, 0 evaluated; that
// pin is the CLI/backend contradiction, see
// TestProbeDetail_NothingEvaluatedIsNeverCompleteAndNeverSatisfiesARequirement.)
func TestProbeDetail_OkEntryAlwaysStatesCounts(t *testing.T) {
	st := activeEntry(t, checkPhaseOutcome{Attempted: 2, Probes: models.ActiveProbeCoverage{Attempted: 2, Evaluated: 1, Inconclusive: 1, Reasons: reasons(map[string]int{"timeout": 1}, nil, nil)}})
	if st.State != reporters.ScannerOK || !strings.Contains(st.Detail, "1 evaluated") || !strings.Contains(st.Detail, "1 inconclusive (target)") {
		t.Fatalf("%s %q", st.State, st.Detail)
	}
	var l scannerStatusList
	l.set(st)
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(l), nil, false)
	if !cov.ConfiguredComplete {
		t.Fatal("target-side non-responses beside an evaluated probe keep scan-wide completeness (decision 6)")
	}
}

// C4B-06: probes attempted, none evaluated, is never complete, whoever's doing
// that was, and never satisfies --require-analyzers active-probes. It is the
// backend's rule (probe_coverage.detail_reports_lost_evaluation: lost evaluation,
// or attempted > 0 with evaluated == 0): the same counts, the same verdict.
func TestProbeDetail_NothingEvaluatedIsNeverCompleteAndNeverSatisfiesARequirement(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phase checkPhaseOutcome
	}{
		{"target never answered", probePhase(22, 0, 22, 0, 0)},
		{"every probe gated", gatedPhase(22, 0, map[int]int{401: 22})},
		{"gated and not answered", checkPhaseOutcome{Attempted: 22, Probes: models.ActiveProbeCoverage{Attempted: 22, Inconclusive: 22,
			Gated: models.ProbeGated{Total: 10, ByStatus: map[string]int{"404": 10}}, Reasons: reasons(map[string]int{"timeout": 12, "gated": 10}, nil, nil)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := activeEntry(t, tc.phase)
			var l scannerStatusList
			l.set(st)
			cov := reporters.BuildCoverage([]reporters.ScannerStatus(l), []string{AnalyzerActiveProbes}, true)
			if cov.ConfiguredComplete || len(cov.Gaps) != 1 || cov.Gaps[0] != AnalyzerActiveProbes {
				t.Fatalf("coverage = %+v, want incomplete with active-probes a gap", cov)
			}
			if len(cov.RequiredGaps) != 1 || cov.StrictOK() {
				t.Fatalf("a required active-probes must not be satisfied: %+v", cov)
			}
		})
	}
	// One evaluated probe is enough for the entry to deliver, as it is for the backend.
	var l scannerStatusList
	l.set(activeEntry(t, probePhase(22, 1, 21, 0, 0)))
	if cov := reporters.BuildCoverage([]reporters.ScannerStatus(l), []string{AnalyzerActiveProbes}, true); !cov.StrictOK() {
		t.Fatalf("1 of 22 evaluated delivers the analyzer (the counts are stated beside it): %+v", cov)
	}
}

// C4B-35: the segment prefixes the engine writes are the contract the backend,
// the frontend and the corpus read, byte for byte. The unknown-origin segment is
// "unknown-origin probes (not evaluated): " (C11: not the invented
// "unknown-origin probes:" both readers once expected). The 240-byte detail may
// drop a reason segment whole ("and N more"), so the segments are checked as
// composed, before the budget.
func TestProbeDetail_ReasonSegmentPrefixesAreExact(t *testing.T) {
	cov := models.ActiveProbeCoverage{Attempted: 12, Evaluated: 2, Inconclusive: 6, UnknownOrigin: 2, ScannerFailed: 2,
		Reasons: reasons(map[string]int{"timeout": 2, "gated": 4}, map[string]int{"dns_failure": 2}, map[string]int{"not_sent": 2}),
		Gated:   models.ProbeGated{Total: 4, ByStatus: map[string]int{"403": 3, "410": 1}}}
	var got []string
	for _, seg := range probeSegs(cov, "") {
		got = append(got, seg(240))
	}
	want := []string{
		"probe evaluation: 12 attempted, 2 evaluated, 6 inconclusive (target), 2 unknown-origin, 2 scanner-failed",
		"inconclusive probes (target did not answer): timeout 2",
		"gated probes (target answered 401/403/404/410 so not evaluated): 403 3, 410 1",
		"unknown-origin probes (not evaluated): dns_failure 2",
		"scanner-failed probes (not evaluated): not_sent 2",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("\n got %q\nwant %q", got, want)
	}
	// No segment may hold the separator, or a reader that splits on "; " would cut it.
	for _, seg := range got {
		if strings.Contains(seg, "; ") {
			t.Fatalf("segment %q holds the separator", seg)
		}
	}
}
