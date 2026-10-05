//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// TestRealWorldMatcher_MiniFixtureRealScanScoresTP is the Task-0 regression
// for the Phase-A matcher defect (benchmarks/realworld/README.md): the
// orchestrator renumbers every finding ID to positional "SEC-NNN"
// (internal/engine/orchestrator.go:581), so a REAL scan of the committed
// mini fixture emitted its one genuine SSRF as ID "SEC-001" and the
// rule-keyed matcher scored it `unknown` instead of `tp`:
//
//	realworld/_minicheck: precision 0.0% over 0 labeled (0 tp, 0 fp), 1 unknown …
//	  UNKNOWN  SEC-001  app.py:7
//
// Post-fix, the matcher falls back to the finding's CWE references (rule
// identity that survives the orchestrator), so the same real scan must
// score 1 tp / 0 unknown. This runs the ACTUAL binary + Python engine —
// no synthetic findings — so a regression in either the emitted references
// or the harness matching chain trips it.
func TestRealWorldMatcher_MiniFixtureRealScanScoresTP(t *testing.T) {
	bin := fendixBinary(t)
	root := repoRoot(t)

	mini := filepath.Join(root, "go", "internal", "benchmark", "targets",
		"testdata", "realworld", "mini")
	out := filepath.Join(t.TempDir(), "report.json")

	t.Setenv("FENDIX_ENGINE", filepath.Join(root, "python"))
	cmd := exec.Command(bin,
		"scan",
		"--code", mini,
		"--python-engine",
		"--format", "json",
		"--output", out,
	)
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fendix scan --code mini failed: %v\n%s", err, o)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading scan output: %v", err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatalf("parsing scan output: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("real scan of the mini fixture produced no findings; expected the SSRF at app.py:7")
	}

	ls, err := benchmark.LoadLabelSet(filepath.Join(mini, "labels.yaml"))
	if err != nil {
		t.Fatalf("loading committed mini labels: %v", err)
	}
	r := benchmark.ScoreRealWorld("mini", ls, report.Findings, 12)
	if r.TruePos != 1 || r.Unknown != 0 {
		t.Fatalf("mini real-scan score tp=%d fp=%d unknown=%d fn=%d, want tp=1 unknown=0 — "+
			"the finding→label matcher does not match real production output (IDs: %v)",
			r.TruePos, r.FalsePos, r.Unknown, r.FalseNeg, findingIDs(report.Findings))
	}
}

func findingIDs(fs []models.Finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.ID+"@"+f.Endpoint)
	}
	return ids
}
