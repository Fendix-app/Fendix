package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

func find(l scannerStatusList, name string) reporters.ScannerStatus {
	for _, s := range l {
		if s.Name == name {
			return s
		}
	}
	return reporters.ScannerStatus{}
}

func TestRecordBlackbox_Table(t *testing.T) {
	url := models.ScanConfig{URL: "http://t"}
	active := models.ScanConfig{URL: "http://t", EnableActive: true}
	for _, tc := range []struct {
		name         string
		cfg          models.ScanConfig
		endpoints    int
		discoveryErr error
		specErr      error
		phase        checkPhaseOutcome
		wantDAST     [2]string // state, reason
		wantSpec     [2]string
		wantProbes   [2]string
	}{
		{"code only", models.ScanConfig{CodePath: "x"}, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"url with endpoints, passive only", url, 3, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"url zero endpoints", url, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"failed", "no_endpoints"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"discovery error", url, 0, errors.New("dns"), nil, checkPhaseOutcome{},
			[2]string{"failed", "execution_error"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "disabled_by_flag"}},
		{"spec parsed", models.ScanConfig{URL: "http://t", SpecPath: "s.yaml"}, 2, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"ok", ""}, [2]string{"skipped", "disabled_by_flag"}},
		{"spec parse failure", models.ScanConfig{URL: "http://t", SpecPath: "s.yaml"}, 2, nil, errors.New("yaml: bad"), checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"failed", "input_error"}, [2]string{"skipped", "disabled_by_flag"}},
		{"active, probes completed with responses", active, 2, nil, nil, probePhase(40, 40, 0, 0, 0),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"ok", ""}},
		// A-D5 (Round 6): every planned probe is required, so a target-side unevaluated probe makes the entry failed/no_endpoints (target-owned), never ok.
		{"active, some probes inconclusive (target)", active, 2, nil, nil, probePhase(40, 37, 3, 0, 0),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "no_endpoints"}},
		// Round 5 (C4B-06): the round-4b row pinned ok here. 0 evaluated of N attempted
		// is no evidence at all, so it is never complete: the backend reads the same
		// counts as incomplete, and the CLI and the Action must agree with it. The
		// reason is the target-owned no_endpoints, never a scanner failure.
		{"active, every probe inconclusive (target never answers)", active, 2, nil, nil, probePhase(40, 0, 40, 0, 0),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "no_endpoints"}},
		{"active, every probe gated (401/403/404/410)", active, 2, nil, nil, gatedPhase(40, 0, map[int]int{403: 30, 404: 10}),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "no_endpoints"}},
		// A-D5 (Round 6): every planned probe is required, so a target-side unevaluated probe makes the entry failed/no_endpoints (target-owned), never ok.
		{"active, some probes gated, the rest evaluated", active, 2, nil, nil, gatedPhase(40, 30, map[int]int{403: 10}),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "no_endpoints"}},
		{"active, nothing evaluated and a scanner failure", active, 2, nil, nil, probePhase(40, 0, 39, 0, 1),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "execution_error"}},
		{"active, unknown-origin failures", active, 2, nil, nil, probePhase(40, 38, 0, 2, 0),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "execution_error"}},
		{"active, scanner-side failures", active, 2, nil, nil, probePhase(40, 39, 0, 0, 1),
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "execution_error"}},
		{"active, nothing probe-eligible", active, 2, nil, nil, checkPhaseOutcome{},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}},
		{"active without endpoints", active, 0, nil, nil, checkPhaseOutcome{},
			[2]string{"failed", "no_endpoints"}, [2]string{"skipped", "not_applicable"}, [2]string{"skipped", "not_applicable"}},
		{"request budget exhausted mid-pass", active, 2, nil, nil, checkPhaseOutcome{Attempted: 10, Rejected: 25},
			[2]string{"failed", "execution_error"}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "execution_error"}},
		{"duration cap hit mid-pass", active, 2, nil, nil, checkPhaseOutcome{Attempted: 10, Deadline: true},
			[2]string{"failed", "timeout"}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "timeout"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l scannerStatusList
			recordBlackbox(&l, &tc.cfg, tc.endpoints, tc.discoveryErr, tc.specErr, tc.phase)
			check := func(name string, want [2]string) {
				got := find(l, name)
				if string(got.State) != want[0] || string(got.Reason) != want[1] {
					t.Errorf("%s = %s/%s, want %s/%s", name, got.State, got.Reason, want[0], want[1])
				}
			}
			check(AnalyzerDAST, tc.wantDAST)
			check(AnalyzerSpec, tc.wantSpec)
			check(AnalyzerActiveProbes, tc.wantProbes)
		})
	}
	// Inconclusive probes stay visible in the detail, which still leads with
	// the counts (A-D5: the entry is failed/no_endpoints, target-owned).
	var l scannerStatusList
	recordBlackbox(&l, &active, 2, nil, nil, probePhase(40, 37, 3, 0, 0))
	if got := find(l, AnalyzerActiveProbes); got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonNoEndpoints ||
		!strings.HasPrefix(got.Detail, "probe evaluation: 40 attempted, 37 evaluated, 3 inconclusive (target)") {
		t.Fatalf("inconclusive probes must be named in detail, got %+v", got)
	}
}

// probePhase builds a check-phase outcome from probe counts. Reasons are filled
// so the detail lists have something to say.
func probePhase(attempted, evaluated, inconclusive, unknown, scannerFailed int) checkPhaseOutcome {
	cov := models.ActiveProbeCoverage{Attempted: attempted, Evaluated: evaluated, Inconclusive: inconclusive,
		UnknownOrigin: unknown, ScannerFailed: scannerFailed, Reasons: map[string]map[string]int{}}
	if inconclusive > 0 {
		cov.Reasons["target"] = map[string]int{"timeout": inconclusive}
	}
	if unknown > 0 {
		cov.Reasons["unknown"] = map[string]int{"dns_failure": unknown}
	}
	if scannerFailed > 0 {
		cov.Reasons["scanner"] = map[string]int{"not_sent": scannerFailed}
	}
	return checkPhaseOutcome{Attempted: attempted, Probes: cov}
}

// gatedPhase builds a check-phase outcome whose non-evaluated probes were all
// gated, by status. Gated probes sit inside inconclusive.
func gatedPhase(attempted, evaluated int, byStatus map[int]int) checkPhaseOutcome {
	cov := models.ActiveProbeCoverage{Attempted: attempted, Evaluated: evaluated, Reasons: map[string]map[string]int{},
		Gated: models.ProbeGated{ByStatus: map[string]int{}}}
	for code, n := range byStatus {
		cov.Gated.Total += n
		cov.Gated.ByStatus[strconv.Itoa(code)] = n
	}
	cov.Inconclusive = cov.Gated.Total
	if cov.Gated.Total > 0 {
		cov.Reasons["target"] = map[string]int{"gated": cov.Gated.Total}
	}
	return checkPhaseOutcome{Attempted: attempted, Probes: cov}
}

func TestSummarizeCheckPhase(t *testing.T) {
	records := []scanner.ProbeRecord{{Status: 200}, {Status: 0}, {Status: 500}, {Status: 0}}
	got := summarizeCheckPhase(context.Background(), records, 0)
	// Two probes with no HTTP response and no failure evidence are unknown-origin
	// (fail-closed), and a 500 is an evaluated response.
	if got.Attempted != 4 || got.Probes.Evaluated != 2 || got.Probes.UnknownOrigin != 2 || got.Rejected != 0 || got.Deadline {
		t.Fatalf("phase = %+v", got)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := summarizeCheckPhase(ctx, nil, 5); !got.Deadline || got.Rejected != 5 {
		t.Fatalf("deadline/rejected not captured: %+v", got)
	}
}

// A URL that accepts and immediately closes every connection yields zero
// endpoints. Before the contract that was exit 2 with no report; now the
// report is written first and exit 2 is kept.
func TestOrchestrator_ZeroEndpointsWritesReportThenExits2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{URL: "http://" + ln.Addr().String(), AllowPrivate: true, Workers: 1, Timeout: 1, CrawlDepth: 0, Format: "json", OutputPath: out}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 2 {
		t.Fatalf("exit %d, want 2 (unchanged CLI contract)", code)
	}
	report := readReport(t, out)
	s, ok := statusFor(report, AnalyzerDAST)
	if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonNoEndpoints {
		t.Fatalf("dast = %+v, want failed/no_endpoints", s)
	}
	if report.Metadata.Coverage == nil || report.Metadata.Coverage.ConfiguredComplete {
		t.Fatalf("coverage must be present and incomplete, got %+v", report.Metadata.Coverage)
	}
}

func TestRunPlugins_OutcomeRecorded(t *testing.T) {
	// No plugin roots exist in a temp HOME: not_applicable, never ok.
	t.Setenv("HOME", t.TempDir())
	var l scannerStatusList
	o := &Orchestrator{cfg: &models.ScanConfig{CodePath: t.TempDir()}}
	_, outcome := o.runPlugins(context.Background())
	recordPlugins(&l, o.cfg, outcome)
	if got := find(l, AnalyzerPlugins); got.State != reporters.ScannerSkipped || got.Reason != reporters.ReasonNotApplicable {
		t.Fatalf("plugins with none configured = %+v, want skipped/not_applicable", got)
	}
	l = nil
	recordPlugins(&l, &models.ScanConfig{NoPlugins: true}, pluginOutcome{})
	if got := find(l, AnalyzerPlugins); got.Reason != reporters.ReasonDisabledByFlag {
		t.Fatalf("--no-plugins = %+v, want disabled_by_flag", got)
	}
	l = nil
	recordPlugins(&l, &models.ScanConfig{}, pluginOutcome{Discovered: 2, Failed: []string{"custom-secret"}})
	if got := find(l, AnalyzerPlugins); got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonExecutionError || got.Detail == "" {
		t.Fatalf("plugin failure = %+v, want failed/execution_error naming the plugin", got)
	}
}
