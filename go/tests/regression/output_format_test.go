// Package regression guards Fendix against silent behavior changes:
// scan-output drift, benchmark-baseline regressions, and performance
// regressions. It runs without Docker or network (scans use --fast against
// committed code fixtures).
package regression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/tests/harness"
)

// fixtures maps a fixture dir (relative to this package) to its committed
// snapshot file. Snapshots store a NORMALIZED projection of the findings
// (sorted "category|severity|title") so they are stable across runs — raw
// output carries timestamps/durations and would be flaky.
var fixtures = map[string]string{
	"../fixtures/simple-go-project":     "snapshots/simple-go-project.snap",
	"../fixtures/simple-python-project": "snapshots/simple-python-project.snap",
}

type jsonReport struct {
	Findings []struct {
		Category string `json:"category"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	} `json:"findings"`
}

// normalize renders a finding set to a stable, sorted snapshot string.
func normalize(out string) (string, error) {
	var r jsonReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return "", fmt.Errorf("scan output is not valid JSON: %w", err)
	}
	lines := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		lines = append(lines, fmt.Sprintf("%s|%s|%s", f.Category, f.Severity, f.Title))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n", nil
}

// TestOutputFormatSnapshots fails if a fixture's normalized scan output
// drifts from its committed snapshot. Regenerate intentionally with
// FENDIX_UPDATE_SNAPSHOTS=1.
func TestOutputFormatSnapshots(t *testing.T) {
	update := os.Getenv("FENDIX_UPDATE_SNAPSHOTS") != ""
	for fixture, snap := range fixtures {
		fixture, snap := fixture, snap
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			out, _, exit := harness.Run(t, "scan", "--code", fixture, "--fast", "--format", "json")
			if exit != 0 {
				t.Fatalf("scan exit = %d, want 0", exit)
			}
			got, err := normalize(out)
			if err != nil {
				t.Fatal(err)
			}
			if got == "\n" || got == "" {
				t.Fatalf("fixture %s produced no findings; expected the Dockerfile IaC finding", fixture)
			}
			if update {
				if err := os.MkdirAll(filepath.Dir(snap), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(snap, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated snapshot %s", snap)
				return
			}
			want, err := os.ReadFile(snap)
			if err != nil {
				t.Fatalf("reading snapshot %s (run with FENDIX_UPDATE_SNAPSHOTS=1 to create): %v", snap, err)
			}
			if got != string(want) {
				t.Errorf("scan output drifted from snapshot %s.\n--- want ---\n%s\n--- got ---\n%s", snap, want, got)
			}
		})
	}
}
