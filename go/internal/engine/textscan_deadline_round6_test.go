package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// Round 6, WS-E2: R5-19 at the orchestrator (review B2, OR-50). The unit tests in
// internal/scanner/textscan pin the ScanCoverage contract; this pins the
// wiring. A fix that adds the parameter but passes context.Background() at
// orchestrator.go:670 still overruns here, and the findings textscan found
// before the deadline must reach the report (today orchestrator.go:673-675
// keeps none of them when textscan returns an error).
//
// The slow tree is one 1 MiB JavaScript file hard-linked 400 times: 400 MiB to
// read, 1 MiB on disk. At f438bc3, `fendix scan --max-duration 2s` over it ran
// 21.4 s with textscan `ok` (secrets honoured the deadline: failed/timeout).
func TestRun_R5_19_TextscanHonoursMaxDurationAndKeepsItsFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("reads a 400 MiB hard-linked tree before the fix")
	}
	code := t.TempDir()
	// Walked first: a textscan-only finding (IAC_DOCKER_LATEST_TAG).
	if err := os.WriteFile(filepath.Join(code, "Dockerfile"), []byte("FROM alpine:latest\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	z := filepath.Join(code, "z")
	if err := os.MkdirAll(z, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `const q = "SELECT * FROM t WHERE id=" + req.query.id + " AND x=" + y; // ` + strings.Repeat("a", 40) + "\n"
	base := filepath.Join(z, "base.js")
	if err := os.WriteFile(base, []byte(strings.Repeat(line, 1_048_000/len(line))), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 400; i++ {
		if err := os.Link(base, filepath.Join(z, fmt.Sprintf("f%03d.js", i))); err != nil {
			t.Skip("hard links unavailable:", err)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	const deadline = time.Second
	cfg := &models.ScanConfig{
		CodePath:          code,
		Format:            "json",
		OutputPath:        out,
		MaxDuration:       deadline,
		Fast:              true,
		EnforceConfidence: true,
	}
	start := time.Now()
	NewOrchestrator(cfg, "test").Run(context.Background())
	elapsed := time.Since(start)

	// G2.5 allows 10 s on the 3.4 GB tree; here the remaining work after the
	// deadline is finalisation only.
	if elapsed > deadline+5*time.Second {
		t.Errorf("scan with --max-duration %s ran %s (overrun %s)", deadline, elapsed.Round(time.Millisecond), (elapsed - deadline).Round(time.Millisecond))
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	rep, err := reporters.ParseJSONReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ts *reporters.ScannerStatus
	for i := range rep.Metadata.ScannerStatus {
		if rep.Metadata.ScannerStatus[i].Name == AnalyzerTextscan {
			ts = &rep.Metadata.ScannerStatus[i]
		}
	}
	if ts == nil || ts.State != reporters.ScannerFailed || ts.Reason != reporters.ReasonTimeout {
		t.Errorf("textscan entry %+v, want failed/timeout", ts)
	}
	found := false
	for _, f := range rep.Findings {
		if f.RuleID == "IAC_DOCKER_LATEST_TAG" || strings.Contains(f.ID+f.Title, "latest") {
			found = true
		}
	}
	if !found {
		t.Error("the Dockerfile finding textscan made before the deadline is not in the report")
	}
}
