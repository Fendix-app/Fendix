package regression

import (
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// TestCommittedBaselineLoads verifies the committed baseline exists, parses,
// and contains the expected DAST targets at the recall they were captured
// at. This is the v0.20 exit-criterion guard: if the baseline file is
// deleted or corrupted, this fails. (The live regression COMPARISON against
// fresh scans runs in CI via `fendix benchmark compare`, which needs Docker.)
func TestCommittedBaselineLoads(t *testing.T) {
	path := filepath.Join(harness.RepoRoot(t), "benchmarks", "baselines", "baseline.json")
	base, err := benchmark.Load(path)
	if err != nil {
		t.Fatalf("loading committed baseline %s: %v", path, err)
	}
	for _, target := range []string{"dvwa", "juiceshop"} {
		r, ok := base.Results[target]
		if !ok {
			t.Errorf("baseline missing target %q", target)
			continue
		}
		if r.Recall() < 1.0 {
			t.Errorf("%s baseline recall = %.2f, want 1.00 (all labeled vulns caught)", target, r.Recall())
		}
	}
}

// TestRegressionDetection exercises the Compare machinery deterministically
// (no Docker): identical results never regress; a >10% recall drop does.
func TestRegressionDetection(t *testing.T) {
	base := &benchmark.Baseline{Results: map[string]benchmark.BenchmarkResult{
		"t": {Target: "t", TruePos: 100, FalsePos: 0, FalseNeg: 0},
	}}

	// Identical → no regression.
	same := []benchmark.BenchmarkResult{{Target: "t", TruePos: 100, FalsePos: 0, FalseNeg: 0}}
	if base.Compare(same).HasRegression() {
		t.Error("identical results must not regress")
	}

	// Recall 100% → 80% (>10% worse) → regression.
	worse := []benchmark.BenchmarkResult{{Target: "t", TruePos: 80, FalsePos: 0, FalseNeg: 20}}
	if !base.Compare(worse).HasRegression() {
		t.Error("a 20% recall drop must be flagged as a regression")
	}
}
