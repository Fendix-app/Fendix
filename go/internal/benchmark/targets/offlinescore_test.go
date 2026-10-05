package targets

import (
	"os"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// TestOfflineScore scores a persisted raw JSON report against a labels.yaml
// using the SAME ScoreRealWorld + TriageReport the realworld target uses —
// so a slow (~50 min) TWISCOPE scan is run once to JSON and scored offline
// as many times as needed (per Phase B fix, per label revision) without
// re-scanning. Opt-in via env; a no-op in normal test runs.
//
//	FENDIX_SCORE_JSON=<report.json> \
//	FENDIX_SCORE_LABELS=<labels.yaml> \
//	FENDIX_SCORE_SRC=<scanned tree, for KLOC> \
//	go test ./internal/benchmark/targets/ -run TestOfflineScore -v
func TestOfflineScore(t *testing.T) {
	jsonPath := os.Getenv("FENDIX_SCORE_JSON")
	labelsPath := os.Getenv("FENDIX_SCORE_LABELS")
	if jsonPath == "" || labelsPath == "" {
		t.Skip("set FENDIX_SCORE_JSON + FENDIX_SCORE_LABELS to score a persisted report")
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		t.Fatalf("parsing report: %v", err)
	}
	ls, err := benchmark.LoadLabelSet(labelsPath)
	if err != nil {
		t.Fatalf("loading labels: %v", err)
	}
	loc := 0
	if src := os.Getenv("FENDIX_SCORE_SRC"); src != "" {
		loc = countLOC(src)
	}
	rw := &RealWorld{entryName: os.Getenv("FENDIX_SCORE_NAME")}
	if rw.entryName == "" {
		rw.entryName = "offline"
	}
	rw.Result = benchmark.ScoreRealWorld(rw.Name(), ls, report.Findings, loc)
	t.Logf("total findings in report: %d", len(report.Findings))
	t.Logf("\n%s", rw.TriageReport())
}
