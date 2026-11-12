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
		st := activeEntry(t, checkPhaseOutcome{Attempted: 5, Deadline: true, Probes: models.ActiveProbeCoverage{Attempted: 5, Evaluated: 5}})
		if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonTimeout ||
			!strings.HasPrefix(st.Detail, "--max-duration elapsed before the probe pass completed; probe evaluation: 5 attempted") {
			t.Fatalf("%s/%s %q", st.State, st.Reason, st.Detail)
		}
	})
}

// A scan whose only non-answers are the target's keeps its scan-wide
// completeness AND states it: the entry never reads as "every probe was
// evaluated" when one was not.
func TestProbeDetail_OkEntryAlwaysStatesCounts(t *testing.T) {
	st := activeEntry(t, checkPhaseOutcome{Attempted: 1, Probes: models.ActiveProbeCoverage{Attempted: 1, Inconclusive: 1, Reasons: reasons(map[string]int{"timeout": 1}, nil, nil)}})
	if st.State != reporters.ScannerOK || !strings.Contains(st.Detail, "0 evaluated") || !strings.Contains(st.Detail, "1 inconclusive (target)") {
		t.Fatalf("%s %q", st.State, st.Detail)
	}
	var l scannerStatusList
	l.set(st)
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(l), nil, false)
	if !cov.ConfiguredComplete {
		t.Fatal("target-side non-responses alone keep scan-wide completeness (decision 6)")
	}
}
