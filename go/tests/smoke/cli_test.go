// Package smoke exercises the fendix CLI end-to-end as a subprocess.
// These are regression guards on the public command surface: if a future
// change breaks --version, scan output, or a documented flag, a smoke test
// fails LOUDLY. They run without Docker or network (scans use --fast and a
// committed code fixture).
package smoke

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

const goFixture = "../fixtures/simple-go-project"

// run is a thin alias over the shared harness runner.
func run(t *testing.T, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	return harness.Run(t, args...)
}

func TestVersion(t *testing.T) {
	out, _, exit := run(t, "version")
	if exit != 0 {
		t.Fatalf("version exit = %d, want 0", exit)
	}
	if !strings.Contains(out, "fendix version") {
		t.Errorf("version output = %q, want to contain 'fendix version'", out)
	}
}

func TestHelpCommands(t *testing.T) {
	for _, args := range [][]string{
		{"--help"}, {"scan", "--help"}, {"benchmark", "--help"}, {"metrics", "--help"},
	} {
		_, _, exit := run(t, args...)
		if exit != 0 {
			t.Errorf("%v exit = %d, want 0", args, exit)
		}
	}
}

func TestScanRequiresTarget(t *testing.T) {
	_, stderr, exit := run(t, "scan")
	if exit == 0 {
		t.Error("scan with no target should exit non-zero")
	}
	if !strings.Contains(stderr, "required") {
		t.Errorf("stderr = %q, want a clear 'required' error", stderr)
	}
}

func TestScanFixtureJSON(t *testing.T) {
	out, _, exit := run(t, "scan", "--code", goFixture, "--fast", "--format", "json")
	if exit != 0 {
		t.Fatalf("scan exit = %d, want 0 (no --fail-on)", exit)
	}
	var report struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("scan --format json did not emit valid JSON: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Error("fixture scan produced no findings; expected the Dockerfile IaC finding")
	}
}

func TestScanFixtureSARIF(t *testing.T) {
	out, _, exit := run(t, "scan", "--code", goFixture, "--fast", "--format", "sarif")
	if exit != 0 {
		t.Fatalf("scan sarif exit = %d, want 0", exit)
	}
	var sarif struct {
		Version string           `json:"version"`
		Runs    []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &sarif); err != nil {
		t.Fatalf("--format sarif did not emit valid JSON: %v", err)
	}
	if len(sarif.Runs) == 0 {
		t.Error("SARIF output has no runs[]")
	}
}

func TestMetricsShowNoData(t *testing.T) {
	// In a clean checkout there is no events.jsonl; `metrics show` must
	// exit 0 with a friendly message, not crash.
	out, _, exit := run(t, "metrics", "show")
	if exit != 0 {
		t.Fatalf("metrics show exit = %d, want 0", exit)
	}
	if !strings.Contains(strings.ToLower(out), "metric") {
		t.Errorf("metrics show output = %q", out)
	}
}
