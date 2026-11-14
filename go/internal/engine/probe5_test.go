package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// Round 5, WS3 engine half (contract C11): the CLI, the Action and
// --require-analyzers read active-probe coverage with the backend's rule; a
// pass cut short by a limit says so; and the printed summary shows the probes'
// own account beside the verdict.

// resetTarget answers "/" with a page linking /item?id=1 and resets every
// other connection: a target that answers no probe at all (the C4B-06
// reproduction: 0 evaluated of N, previously "coverage: complete", exit 0).
func resetTarget(t *testing.T) *httptest.Server {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Discovery's own GETs are answered; every request that carries a probe
		// payload (or any path but the pages) is reset.
		if (r.URL.Path == "/" && r.URL.RawQuery == "") || (r.URL.Path == "/item" && r.URL.RawQuery == "id=1" && n.Add(1) == 1) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="/item?id=1">item</a></body></html>`)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		c.Close()
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestC4B06_TargetThatAnswersNoProbeIsNotCompleteAndFailsTheRequirement(t *testing.T) {
	srv := resetTarget(t)
	for _, tc := range []struct {
		name     string
		cfg      models.ScanConfig
		wantExit int
		complete bool
	}{
		{"no strict flag: exit by findings, coverage incomplete", models.ScanConfig{}, 0, false},
		{"--fail-on-coverage-gap", models.ScanConfig{FailOnCoverageGap: true}, 2, false},
		{"--require-analyzers active-probes", models.ScanConfig{RequiredAnalyzers: []string{AnalyzerActiveProbes}}, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.URL, cfg.AllowPrivate, cfg.Workers, cfg.Timeout, cfg.CrawlDepth, cfg.Format, cfg.EnableActive = srv.URL, true, 4, 3, 1, "json", true
			cfg.OutputPath = filepath.Join(t.TempDir(), "r.json")
			exit := NewOrchestrator(&cfg, "dev").Run(context.Background())
			rep := readReport(t, cfg.OutputPath)
			ap, st := probesOf(t, rep)
			if ap.Attempted == 0 || ap.Evaluated != 0 || ap.UnknownOrigin != 0 || ap.ScannerFailed != 0 {
				t.Fatalf("a target that resets everything: %+v", ap)
			}
			if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonNoEndpoints {
				t.Fatalf("active-probes = %s/%s %q, want failed/no_endpoints", st.State, st.Reason, st.Detail)
			}
			if rep.Metadata.Coverage.ConfiguredComplete {
				t.Fatalf("0 evaluated of %d must not read coverage: complete", ap.Attempted)
			}
			if exit != tc.wantExit {
				t.Fatalf("exit %d, want %d", exit, tc.wantExit)
			}
		})
	}
}

// The printed verdict is what the Action reads. It says incomplete, names the
// requirement as not delivered, and shows the probes' own account beside it.
func TestC4B06_PrintedSummaryAgreesWithTheBackendRule(t *testing.T) {
	var l scannerStatusList
	recordBlackbox(&l, &models.ScanConfig{URL: "http://t", EnableActive: true}, 2, nil, nil, gatedPhase(22, 0, map[int]int{403: 20, 404: 2}))
	cov := reporters.BuildCoverage([]reporters.ScannerStatus(l), []string{AnalyzerActiveProbes}, true)
	phase := gatedPhase(22, 0, map[int]int{403: 20, 404: 2})
	ap := phase.Probes
	cov.ActiveProbes = &ap
	var out bytes.Buffer
	printCoverageSummary(&out, l, cov, true)
	got := out.String()
	for _, want := range []string{
		"coverage: incomplete (active-probes)",
		"required: not delivered (active-probes)",
		"active probes: 22 attempted, 0 evaluated, 0 not answered by the target, 22 gated (403 20, 404 2), 0 unknown-origin, 0 scanner-failed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
	// The Action reads the last line starting "coverage: " / "required: ": the
	// probe line must start with neither.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "active probes: ") && (strings.HasPrefix(line, "coverage: ") || strings.HasPrefix(line, "required: ")) {
			t.Fatalf("probe line shadows the verdict: %q", line)
		}
	}
}

// The detail the engine writes is read by the backend and the frontend with the
// regular expressions below, which are the backend's
// (scanning/probe_coverage.py: _COUNTS_RE, _LOSS_RE) written out here. For every
// shape the engine can write, the backend's reading of the detail must give the
// verdict the engine recorded: entry delivered iff the backend would not call it
// lost evaluation.
func TestC4B06_BackendRuleAgreesWithTheEngineOnEveryShape(t *testing.T) {
	counts := regexp.MustCompile(`probe evaluation: (\d+) attempted, (\d+) evaluated, (\d+) inconclusive \(target\), (\d+) unknown-origin, (\d+) scanner-failed`)
	loss := regexp.MustCompile(`lost evaluation: (\d+) probe(?:\(s\)|s)? not evaluated \((\d+) unknown-origin, (\d+) scanner-failed\)`)
	backendLost := func(detail string) bool { // detail_reports_lost_evaluation, state ok
		var c, l []string
		for _, seg := range strings.Split(strings.TrimSpace(detail), "; ") {
			seg = strings.TrimSpace(seg)
			switch {
			case strings.HasPrefix(seg, "probe evaluation:"):
				c = counts.FindStringSubmatch(seg)
				if c == nil || len(counts.FindString(seg)) != len(seg) {
					return true
				}
			case strings.HasPrefix(seg, "lost evaluation:"):
				l = loss.FindStringSubmatch(seg)
				if l == nil || len(loss.FindString(seg)) != len(seg) {
					return true
				}
			}
		}
		if c == nil {
			return true
		}
		var a, e, i, u, f int
		fmt.Sscan(c[1], &a)
		fmt.Sscan(c[2], &e)
		fmt.Sscan(c[3], &i)
		fmt.Sscan(c[4], &u)
		fmt.Sscan(c[5], &f)
		if a != e+i+u+f {
			return true // counts that do not add up
		}
		return l != nil || u+f > 0 || (a > 0 && e == 0)
	}
	type shape struct {
		name  string
		phase checkPhaseOutcome
	}
	var shapes []shape
	for _, ev := range []int{0, 1, 7} {
		for _, gated := range []int{0, 3} {
			for _, other := range []int{0, 2} {
				for _, unk := range []int{0, 1} {
					for _, sc := range []int{0, 1} {
						n := ev + gated + other + unk + sc
						if n == 0 {
							continue
						}
						cov := models.ActiveProbeCoverage{Attempted: n, Evaluated: ev, Inconclusive: gated + other, UnknownOrigin: unk, ScannerFailed: sc,
							Reasons: map[string]map[string]int{}, Gated: models.ProbeGated{Total: gated, ByStatus: map[string]int{}}}
						tgt := map[string]int{}
						if gated > 0 {
							cov.Gated.ByStatus["403"] = gated
							tgt["gated"] = gated
						}
						if other > 0 {
							tgt["timeout"] = other
						}
						if len(tgt) > 0 {
							cov.Reasons["target"] = tgt
						}
						if unk > 0 {
							cov.Reasons["unknown"] = map[string]int{"dns_failure": unk}
						}
						if sc > 0 {
							cov.Reasons["scanner"] = map[string]int{"not_sent": sc}
						}
						shapes = append(shapes, shape{fmt.Sprintf("ev%d gated%d other%d unk%d sc%d", ev, gated, other, unk, sc), checkPhaseOutcome{Attempted: n, Probes: cov}})
					}
				}
			}
		}
	}
	for _, sh := range shapes {
		st := activeEntry(t, sh.phase)
		var delivered bool
		switch st.State {
		case reporters.ScannerOK:
			delivered = !backendLost(st.Detail)
			if !delivered {
				t.Errorf("%s: engine wrote ok but the backend rule calls %q lost evaluation", sh.name, st.Detail)
			}
		case reporters.ScannerFailed:
			// A failed entry is a gap on both sides. The backend must find the counts
			// in it, and the rule must hold for it too (nothing evaluated or lost).
			if !backendLost(st.Detail) {
				t.Errorf("%s: engine wrote failed but the backend rule would deliver %q", sh.name, st.Detail)
			}
		default:
			t.Errorf("%s: state %s", sh.name, st.State)
		}
		want := sh.phase.Probes.Evaluated > 0 && sh.phase.Probes.UnknownOrigin+sh.phase.Probes.ScannerFailed == 0
		if (st.State == reporters.ScannerOK) != want {
			t.Errorf("%s: state %s, want ok=%v", sh.name, st.State, want)
		}
		if len(st.Detail) > detailMax {
			t.Errorf("%s: detail over budget (%d)", sh.name, len(st.Detail))
		}
	}
}

// C4B-18: a pass ended by a limit set for the scan names the limit, its value
// and how many requests it turned away, and the probes it cut are never the
// target's doing.
func TestC4B18_RequestBudgetCutIsNamedAndNeverTheTargets(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/a?id=1">a</a> <a href="/b?id=1">b</a> <a href="/c?id=1">c</a></body></html>`)
	})
	for _, p := range []string{"/a", "/b", "/c"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "fine")
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{URL: srv.URL, AllowPrivate: true, Workers: 4, Timeout: 4, CrawlDepth: 1, Format: "json", OutputPath: out, EnableActive: true, MaxRequests: 30}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	rep := readReport(t, out)
	ap, st := probesOf(t, rep)
	if ap.CutShort == nil || ap.CutShort.Cause != "max_requests" || ap.CutShort.Limit != "--max-requests" || ap.CutShort.Configured != "30" || ap.CutShort.Refused <= 0 {
		t.Fatalf("cut_short = %+v, want max_requests, 30, refused > 0", ap.CutShort)
	}
	if st.State != reporters.ScannerFailed || !strings.HasPrefix(st.Detail, "scan limit --max-requests=30 exhausted: ") {
		t.Fatalf("state %s/%s %q", st.State, st.Reason, st.Detail)
	}
	if ap.Reasons["scanner"]["scan_cancelled"]+ap.Reasons["scanner"]["not_sent"] != ap.ScannerFailed {
		t.Fatalf("every probe the cap stopped is scanner-side: %+v", ap)
	}
	for _, e := range ap.NotEvaluatedChecks {
		if e.Origin == "scanner" && !strings.Contains(e.Evidence, "--max-requests") && !strings.Contains(e.Evidence, "never sent") {
			t.Fatalf("a scanner-side entry that does not name why: %+v", e)
		}
	}
}

func TestC4B18_DeadlineCutIsNamed(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="/item?id=1">item</a></body></html>`)
			return
		}
		<-release
	})
	srv := httptest.NewServer(mux)
	// Cleanups run last-in first-out: the stalled handlers are released before
	// the server waits for them.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{URL: srv.URL, AllowPrivate: true, Workers: 4, Timeout: 30, CrawlDepth: 1, Format: "json", OutputPath: out, EnableActive: true, MaxDuration: 4 * time.Second}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	rep := readReport(t, out)
	ap, st := probesOf(t, rep)
	if ap.CutShort == nil || ap.CutShort.Cause != "max_duration" || ap.CutShort.Limit != "--max-duration" || ap.CutShort.Configured != "4s" {
		t.Fatalf("cut_short = %+v", ap.CutShort)
	}
	if st.State != reporters.ScannerFailed || st.Reason != reporters.ReasonTimeout || !strings.HasPrefix(st.Detail, "scan limit --max-duration=4s elapsed before the probe pass completed") {
		t.Fatalf("state %s/%s %q", st.State, st.Reason, st.Detail)
	}
	// The probes the deadline cut in flight are the scanner's, never the target's.
	if ap.ScannerFailed > 0 && ap.Reasons["scanner"]["scan_deadline"] == 0 {
		t.Fatalf("a probe the deadline cut must read scan_deadline: %+v", ap.Reasons)
	}
}

// No limit, no cut_short.
func TestC4B18_NoLimitNoCutShort(t *testing.T) {
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	ap, _ := probesOf(t, rep)
	if ap.CutShort != nil {
		t.Fatalf("cut_short = %+v on a pass nothing cut", ap.CutShort)
	}
}
