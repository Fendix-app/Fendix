// Package targets implements the concrete benchmark corpora for the v0.20
// baseline suite: OWASP Benchmark (white-box / SAST), DVWA, and OWASP
// Juice Shop (black-box / DAST). Each target knows how to run a Fendix
// scan against itself and how to score the result against ground truth.
//
// Honesty constraints (roadmap Rule 5 — "benchmark before marketing"):
//   - DAST targets (DVWA, Juice Shop) have no well-defined negative
//     corpus, so TrueNeg is 0 and FPRate is not meaningful for them; the
//     useful numbers are recall (did we catch the known bugs) and the
//     raw false-positive COUNT. OWASP Benchmark ships labeled true AND
//     false test cases, so its TN — and therefore FPRate — is real.
//   - Memory is NOT measured here (capturing a subprocess's peak RSS
//     portably is fragile); the memory baseline comes from `make bench`
//     (the in-process BenchmarkScan). These targets own accuracy + wall
//     time only.
package targets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// Target is a benchmark corpus that can both produce a Fendix ScanResult
// (running Docker / downloading the corpus as needed) and score it.
type Target interface {
	benchmark.BenchmarkTarget
	// Scan runs fendixBin against this target and returns the raw result.
	// Implementations are responsible for setup and teardown (containers,
	// downloads) and must respect ctx cancellation.
	Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error)
}

// All returns every registered benchmark target, including any committed
// real-world corpus entries discovered under benchmarks/realworld/.
func All() []Target {
	ts := []Target{NewOWASP(), NewDVWA(), NewJuiceShop()}
	for _, rw := range DiscoverRealWorld("") {
		ts = append(ts, rw)
	}
	return ts
}

// ByName returns the registered target with the given name, or an error
// listing the valid names.
func ByName(name string) (Target, error) {
	for _, t := range All() {
		if t.Name() == name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("unknown benchmark target %q (valid: owasp, dvwa, juiceshop, realworld/<name>, all)", name)
}

// ExpectedVuln is one ground-truth vulnerability the target is known to
// contain. Type is matched (case-insensitively, substring) against a
// finding's Category; Location against its Endpoint or Line.
type ExpectedVuln struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Location  string `json:"location"`
	Severity  string `json:"severity"`
	Confirmed bool   `json:"confirmed"`
}

// KnownSet is the ground-truth file for a target.
type KnownSet struct {
	Version         string         `json:"version"`
	Target          string         `json:"target"`
	Negatives       int            `json:"negatives,omitempty"`
	Vulnerabilities []ExpectedVuln `json:"vulnerabilities"`
}

// loadKnownSet reads a ground-truth file from path.
func loadKnownSet(path string) (*KnownSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading known-vuln file %s: %w", path, err)
	}
	var ks KnownSet
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("parsing known-vuln file %s: %w", path, err)
	}
	return &ks, nil
}

// score compares a target's findings against its ground truth and returns
// a BenchmarkResult. A known vuln counts as a true positive when at least
// one finding matches it; remaining unmatched findings are false
// positives; unmatched known vulns are false negatives. negatives feeds
// TrueNeg (0 when the target has no labeled safe cases).
func score(targetName string, ks *KnownSet, findings []models.Finding, dur time.Duration, now time.Time) *benchmark.BenchmarkResult {
	matchedFinding := make([]bool, len(findings))
	tp := 0
	for _, want := range ks.Vulnerabilities {
		hit := false
		for i, f := range findings {
			if findingMatches(want, f) {
				matchedFinding[i] = true
				hit = true
			}
		}
		if hit {
			tp++
		}
	}
	fn := len(ks.Vulnerabilities) - tp
	fp := 0
	for _, m := range matchedFinding {
		if !m {
			fp++
		}
	}
	return &benchmark.BenchmarkResult{
		Target:       targetName,
		TruePos:      tp,
		FalsePos:     fp,
		TrueNeg:      ks.Negatives,
		FalseNeg:     fn,
		ScanDuration: dur,
		Timestamp:    now,
	}
}

// findingMatches reports whether finding f corresponds to expected vuln w.
// Match = Type is a case-insensitive substring of the finding's Category
// (or vice-versa) AND, when Location is set, it appears in the finding's
// Endpoint or Line. Location-less expectations match on type alone.
func findingMatches(w ExpectedVuln, f models.Finding) bool {
	cat := strings.ToLower(f.Category)
	typ := strings.ToLower(w.Type)
	if typ != "" && !strings.Contains(cat, typ) && !strings.Contains(typ, cat) {
		return false
	}
	if w.Location == "" {
		return true
	}
	loc := strings.ToLower(w.Location)
	// Location may name an endpoint/path, a source line, OR a specific
	// signal in the title (e.g. a header name like "Content-Security-Policy"
	// that is reported in the title, not the endpoint).
	if strings.Contains(strings.ToLower(f.Endpoint), loc) {
		return true
	}
	if strings.Contains(strings.ToLower(f.Title), loc) {
		return true
	}
	if f.Line != nil && strings.Contains(strings.ToLower(*f.Line), loc) {
		return true
	}
	return false
}

// runFendixScan invokes the fendix binary with args, writing JSON output
// to a temp file, then parses it back into findings. It returns the parsed
// findings and the wall-clock scan duration.
func runFendixScan(ctx context.Context, fendixBin string, args []string) ([]models.Finding, time.Duration, error) {
	tmp, err := os.CreateTemp("", "fendix-bench-*.json")
	if err != nil {
		return nil, 0, fmt.Errorf("creating temp output: %w", err)
	}
	out := tmp.Name()
	tmp.Close()
	defer os.Remove(out)

	full := append([]string{"scan"}, args...)
	full = append(full, "--format", "json", "--output", out)

	start := time.Now()
	if err := runProcess(ctx, fendixBin, full...); err != nil {
		return nil, 0, fmt.Errorf("running fendix scan: %w", err)
	}
	dur := time.Since(start)

	data, err := os.ReadFile(out)
	if err != nil {
		return nil, 0, fmt.Errorf("reading scan output: %w", err)
	}
	report, err := reporters.ParseJSONReport(data)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing scan output: %w", err)
	}
	return report.Findings, dur, nil
}

// knownFilePath resolves a ground-truth file under benchmarks/targets/,
// relative to the current working directory (the engine repo root).
func knownFilePath(name string) string {
	return filepath.Join("benchmarks", "targets", name)
}
