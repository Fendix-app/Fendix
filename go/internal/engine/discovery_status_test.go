package engine

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
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
		{"active, probes completed with responses", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"ok", ""}},
		{"active, some probes got no response", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 3},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"ok", ""}},
		{"active, no probe got any response", active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 40},
			[2]string{"ok", ""}, [2]string{"skipped", "not_applicable"}, [2]string{"failed", "network_error"}},
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
	// Partial probe failures stay visible in the detail of an ok entry.
	var l scannerStatusList
	recordBlackbox(&l, &active, 2, nil, nil, checkPhaseOutcome{Attempted: 40, NoResponse: 3})
	if got := find(l, AnalyzerActiveProbes); !strings.Contains(got.Detail, "3 of 40") {
		t.Fatalf("partial failures must be named in detail, got %+v", got)
	}
}

func TestSummarizeCheckPhase(t *testing.T) {
	records := []scanner.ProbeRecord{{Status: 200}, {Status: 0}, {Status: 500}, {Status: 0}}
	got := summarizeCheckPhase(context.Background(), records, 0)
	if got.Attempted != 4 || got.NoResponse != 2 || got.Rejected != 0 || got.Deadline {
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
