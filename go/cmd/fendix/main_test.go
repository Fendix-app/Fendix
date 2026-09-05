package main

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/cli"
	"github.com/Abdel-RahmanSaied/Fendix/internal/metrics"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/spf13/cobra"
)

func TestClassifyResult(t *testing.T) {
	scan := &cobra.Command{Use: "scan"}
	other := &cobra.Command{Use: "version"}
	cases := []struct {
		name        string
		cmd         *cobra.Command
		err         error
		wantCode    int
		wantClass   string
		wantSuccess bool
	}{
		{"clean", scan, nil, 0, "", true},
		{"findings exit 1 is still a usable result", scan, cli.ExitWithCode(1, "findings"), 1, "", true},
		{"scan error", scan, cli.ExitWithCode(2, ""), 2, "scan-error", false},
		{"usage error buckets as usage", other, errors.New("unknown flag: --workrs"), 2, "usage", false},
		{"generic runtime error", other, errors.New("boom"), 2, "runtime", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, class, success := classifyResult(c.cmd, c.err)
			if code != c.wantCode || class != c.wantClass || success != c.wantSuccess {
				t.Errorf("classifyResult = (%d,%q,%v), want (%d,%q,%v)",
					code, class, success, c.wantCode, c.wantClass, c.wantSuccess)
			}
		})
	}
}

func TestIsUsageError(t *testing.T) {
	yes := []string{"unknown flag: --x", "unknown command \"scn\"", "required flag(s) \"url\" not set", "accepts 1 arg(s)"}
	for _, m := range yes {
		if !isUsageError(errors.New(m)) {
			t.Errorf("isUsageError(%q) = false, want true", m)
		}
	}
	if isUsageError(errors.New("scan failed: connection refused")) {
		t.Error("a runtime error was misclassified as usage")
	}
}

// TestRecordCLIMetric_FailureRecordsOneEvent is the B1 invariant: every
// invocation (here a failure) writes exactly one phase="cli" event.
func TestRecordCLIMetric_FailureRecordsOneEvent(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "true")
	t.Setenv(metrics.EnvPathFlag, path)

	recordCLIMetric("scan", 2, "scan-error", false, 1500*time.Millisecond)

	events, err := metrics.LoadEvents(path)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	cs := metrics.SummarizeCommands(events, 0)
	if cs.Total != 1 || cs.Success != 0 || cs.ByErrorClass["scan-error"] != 1 {
		t.Errorf("summary = %+v, want 1 total / 0 success / scan-error:1", cs)
	}
}

func TestRecordCLIMetric_DisabledWritesNothing(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "false") // opt-in: default off
	t.Setenv(metrics.EnvPathFlag, path)

	recordCLIMetric("version", 0, "", true, time.Millisecond)

	if events, _ := metrics.LoadEvents(path); len(events) != 0 {
		t.Errorf("metrics disabled but %d events written", len(events))
	}
}

// TestMetricsShow_RendersCLISuccessRate verifies the v0.25 rate line appears
// in `metrics show` and reads the env-configured path (ResolvePath).
func TestMetricsShow_RendersCLISuccessRate(t *testing.T) {
	path := t.TempDir() + "/events.ndjson"
	t.Setenv(metrics.EnvFlag, "true")
	t.Setenv(metrics.EnvPathFlag, path)
	// One success, one usage failure.
	recordCLIMetric("version", 0, "", true, time.Millisecond)
	recordCLIMetric("scan", 2, "usage", false, time.Millisecond)

	cmd := newMetricsShowCmd()
	var buf strings.Builder
	cmd.SetOut(&buf)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("show: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"CLI success rate:", "50.0%", "below target", "failures (usage): 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics show missing %q:\n%s", want, out)
		}
	}
}

func TestScanEmptyTargetTeachingError(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan"})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	err := root.Execute()
	if err == nil {
		t.Fatal("expected an error for scan with no target")
	}
	for _, want := range []string{"--code .", "--url", "--spec", "fendix demo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("teaching error missing %q:\n%s", want, err.Error())
		}
	}
}

func TestBadFlagIsUsageError(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"scan", "--workrs", "5"})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	err := root.Execute()
	if err == nil || !isUsageError(err) {
		t.Fatalf("bad flag should be a usage error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Context propagation.
//
// `scan` built its signal context from context.Background(), so a
// caller-supplied context (cmd.Context() / root.ExecuteContext) was silently
// dropped for the single most important command — an embedder could neither
// carry values down nor cancel the scan. `demo` and `benchmark` already
// derive from cmd.Context(); scan must match.
// ---------------------------------------------------------------------------

type testCtxKey string

func TestScanDerivesContextFromCommand(t *testing.T) {
	orig := runScan
	t.Cleanup(func() { runScan = orig })

	var got context.Context
	runScan = func(ctx context.Context, cfg *models.ScanConfig, version string) int {
		got = ctx
		return 0
	}

	key := testCtxKey("fendix-parent")
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), key, "carried"))
	defer cancel()

	root := newRootCmd()
	root.SetArgs([]string{"scan", "--code", t.TempDir()})
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	if err := root.ExecuteContext(parent); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got == nil {
		t.Fatal("scan never reached the orchestrator")
	}
	if v, _ := got.Value(key).(string); v != "carried" {
		t.Errorf("scan context is not derived from cmd.Context(): value = %q, want %q", v, "carried")
	}

	// And cancelling the caller's context must cancel the scan's.
	cancel()
	select {
	case <-got.Done():
	case <-time.After(5 * time.Second):
		t.Error("cancelling the caller's context did not cancel the scan context")
	}
}

// ---------------------------------------------------------------------------
// Command output plumbing.
// ---------------------------------------------------------------------------

// `version` printed via fmt.Printf straight to os.Stdout, so SetOut had no
// effect and the command was untestable through the normal cobra pattern.
func TestVersionWritesToCommandOut(t *testing.T) {
	cmd := newVersionCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(new(strings.Builder))
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	got := out.String()
	for _, want := range []string{"fendix version", Version, runtime.GOOS, runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("version output missing %q; got %q", want, got)
		}
	}
}

func TestRootHelpHasQuickstartAndGroups(t *testing.T) {
	root := newRootCmd()
	var out strings.Builder
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	help := out.String()
	for _, want := range []string{"Get started:", "fendix demo", "Core commands:", "scan", "init", "demo"} {
		if !strings.Contains(help, want) {
			t.Errorf("root help missing %q", want)
		}
	}
}

func TestValidateRequiredAnalyzers(t *testing.T) {
	if err := validateRequiredAnalyzers([]string{"semgrep", "python-engine/injection"}); err != nil {
		t.Fatalf("registered names must validate: %v", err)
	}
	err := validateRequiredAnalyzers([]string{"semgrep", "Semgrep"})
	if err == nil || !strings.Contains(err.Error(), `"Semgrep"`) || !strings.Contains(err.Error(), "dast") {
		t.Fatalf("unknown name must be rejected and the message must list the registry, got %v", err)
	}
}
