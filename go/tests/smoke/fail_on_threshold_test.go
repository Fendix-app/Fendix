package smoke

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// A --fail-on threshold is enforced whatever its case, and an unrecognised
// one refuses the run. `--fail-on high` used to warn "invalid --fail-on value"
// and then scan with NO threshold: the HIGH finding below warned and the run
// exited 0, so the gate the user asked for was silently off.

func scanWithThreshold(t *testing.T, bin, code, db, threshold string) (stderr string, exit int) {
	t.Helper()
	_, stderr, exit = harness.RunBin(t, bin, nil,
		"scan", "--code", code, "--offline", "--offline-db", db,
		"--format", "json", "--output", filepath.Join(t.TempDir(), "report.json"),
		"--fail-on", threshold)
	return stderr, exit
}

func TestFailOnBlocksAHighFindingInAnyCase(t *testing.T) {
	bin := harness.Fendix(t)
	code, db := vulnerableTree(t, bin, 1, 0)
	for _, threshold := range []string{"HIGH", "high", "High", "hIgH", " high "} {
		stderr, exit := scanWithThreshold(t, bin, code, db, threshold)
		if exit != 1 {
			t.Errorf("--fail-on %q: exit %d, want 1 (the HIGH finding must block)\n%s", threshold, exit, tail(stderr))
		}
		if strings.Contains(stderr, "invalid --fail-on") {
			t.Errorf("--fail-on %q was reported invalid:\n%s", threshold, tail(stderr))
		}
	}
}

func TestFailOnCriticalLetsTheHighFindingWarn(t *testing.T) {
	bin := harness.Fendix(t)
	code, db := vulnerableTree(t, bin, 1, 0)
	for _, threshold := range []string{"CRITICAL", "critical"} {
		if stderr, exit := scanWithThreshold(t, bin, code, db, threshold); exit != 0 {
			t.Errorf("--fail-on %q: exit %d, want 0 (HIGH is below CRITICAL)\n%s", threshold, exit, tail(stderr))
		}
	}
}

func TestAnUnrecognisedFailOnRefusesTheRun(t *testing.T) {
	bin := harness.Fendix(t)
	code, db := vulnerableTree(t, bin, 1, 0)
	for _, threshold := range []string{"severe", "INFO", "none", "hi"} {
		out := filepath.Join(t.TempDir(), "report.json")
		_, stderr, exit := harness.RunBin(t, bin, nil,
			"scan", "--code", code, "--offline", "--offline-db", db,
			"--format", "json", "--output", out, "--fail-on", threshold)
		if exit != 2 {
			t.Errorf("--fail-on %q: exit %d, want 2 (refused)\n%s", threshold, exit, tail(stderr))
		}
		if !strings.Contains(stderr, "invalid --fail-on") {
			t.Errorf("--fail-on %q: stderr does not name the bad threshold:\n%s", threshold, tail(stderr))
		}
		if strings.Contains(stderr, "Decision summary") {
			t.Errorf("--fail-on %q: the scan ran; it must be refused before scanning", threshold)
		}
	}
}

func TestAManagedScanLabelsItsLocalSummaryAsDiagnostic(t *testing.T) {
	bin := harness.Release(t)
	code, db := vulnerableTree(t, bin, 1, 0)
	stderr, exit, evidence := managedScan(t, bin, code, db, nil)
	if exit != 0 {
		t.Fatalf("managed scan exit %d\n%s", exit, tail(stderr))
	}
	if _, err := os.Stat(evidence); err != nil {
		t.Fatalf("managed evidence was not written: %v", err)
	}
	if !strings.Contains(stderr, "Local diagnostic summary (NOT the managed decision)") {
		t.Errorf("managed run does not label its local summary as diagnostic:\n%s", tail(stderr))
	}
	if !strings.Contains(stderr, "The authoritative decision is the Fendix backend's") {
		t.Errorf("managed run does not point at the backend's decision:\n%s", tail(stderr))
	}
	if strings.Contains(stderr, "\nDecision summary:") {
		t.Errorf("managed run still prints an unqualified decision summary:\n%s", tail(stderr))
	}
}

func TestALocalScanKeepsItsDecisionSummary(t *testing.T) {
	bin := harness.Fendix(t)
	code, db := vulnerableTree(t, bin, 1, 0)
	stderr, _ := scanWithThreshold(t, bin, code, db, "HIGH")
	if !strings.Contains(stderr, "\nDecision summary:") || strings.Contains(stderr, "Local diagnostic summary") {
		t.Errorf("a local run's summary changed:\n%s", tail(stderr))
	}
}
