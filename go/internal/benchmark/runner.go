// Package benchmark defines the interfaces and result types for Fendix's
// internal accuracy + performance benchmark suite (v0.20 — Establish
// Baselines).
//
// This is INTERNAL tooling. It never changes scan behavior, CLI flags, or
// output format. A BenchmarkTarget (OWASP Benchmark, DVWA, Juice Shop)
// scores a Fendix ScanResult against a known-vulnerable corpus, producing
// precision / recall / FP / FN plus scan duration and peak memory. Those
// numbers become the committed baseline (see baseline.go) that every
// future release is compared against — the v0.20 exit criterion.
package benchmark

import (
	"context"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ScanResult is the raw output of running Fendix against a benchmark
// target: the findings it produced plus the cost of producing them. It is
// deliberately decoupled from the reporters' on-disk report shape so the
// benchmark package never depends on output formatting (and so changing a
// report format can never silently move a baseline number).
type ScanResult struct {
	// Findings is everything the scan emitted for this target.
	Findings []models.Finding
	// ScanDuration is wall-clock time for the scan that produced Findings.
	ScanDuration time.Duration
	// MemoryPeakMB is the peak RSS observed during the scan, in MiB.
	MemoryPeakMB float64
}

// BenchmarkTarget is implemented by each benchmark corpus. Run scores an
// already-produced ScanResult against the target's ground truth. The scan
// itself (Docker spin-up, corpus download, invoking fendix) is the
// concern of the concrete target in internal/benchmark/targets — the
// interface keeps scoring separate from scan production so each half can
// be tested in isolation.
type BenchmarkTarget interface {
	// Name is the stable identifier used in output tables and as the key
	// under which this target's result is stored in the baseline
	// (e.g. "owasp", "dvwa", "juiceshop"). It must be lowercase and stable
	// across releases — renaming it orphans the stored baseline.
	Name() string

	// Run scores result against the target's known vulnerabilities and
	// returns the computed BenchmarkResult. Implementations MUST NOT
	// mutate result. Errors are wrapped with the target name for context.
	Run(ctx context.Context, result *ScanResult) (*BenchmarkResult, error)
}

// BenchmarkResult is the scored outcome of one target run. The four
// confusion-matrix counts are stored; the rate metrics (Precision, Recall,
// FPRate, FNRate, F1) are computed methods rather than stored fields so a
// result is always internally consistent and the persisted JSON stays
// compact and unambiguous.
type BenchmarkResult struct {
	Target       string        `json:"target"`
	TruePos      int           `json:"true_pos"`
	FalsePos     int           `json:"false_pos"`
	TrueNeg      int           `json:"true_neg"`
	FalseNeg     int           `json:"false_neg"`
	ScanDuration time.Duration `json:"scan_duration"`
	MemoryPeakMB float64       `json:"memory_peak_mb"`
	Timestamp    time.Time     `json:"timestamp"`
}

// Precision is TP / (TP + FP): of everything Fendix flagged, the fraction
// that was a real vulnerability. Returns 0 when nothing was flagged
// (TP+FP == 0), which is the conventional, regression-safe choice — an
// empty prediction set has no precision to brag about.
func (r *BenchmarkResult) Precision() float64 {
	denom := r.TruePos + r.FalsePos
	if denom == 0 {
		return 0
	}
	return float64(r.TruePos) / float64(denom)
}

// Recall is TP / (TP + FN): of every real vulnerability in the corpus, the
// fraction Fendix caught. Returns 0 when the corpus has no positives.
func (r *BenchmarkResult) Recall() float64 {
	denom := r.TruePos + r.FalseNeg
	if denom == 0 {
		return 0
	}
	return float64(r.TruePos) / float64(denom)
}

// FPRate is FP / (FP + TN): of every safe case, the fraction Fendix
// wrongly flagged. Returns 0 when the corpus has no negatives.
func (r *BenchmarkResult) FPRate() float64 {
	denom := r.FalsePos + r.TrueNeg
	if denom == 0 {
		return 0
	}
	return float64(r.FalsePos) / float64(denom)
}

// FNRate is FN / (FN + TP): of every real vulnerability, the fraction
// Fendix missed. Returns 0 when the corpus has no positives.
func (r *BenchmarkResult) FNRate() float64 {
	denom := r.FalseNeg + r.TruePos
	if denom == 0 {
		return 0
	}
	return float64(r.FalseNeg) / float64(denom)
}

// F1 is the harmonic mean of Precision and Recall — the single accuracy
// number the existing heavy-eval gate is expressed in, kept here so the
// new baseline and the old Track-4 thresholds speak the same language.
// Returns 0 when precision and recall are both 0.
func (r *BenchmarkResult) F1() float64 {
	p, rec := r.Precision(), r.Recall()
	if p+rec == 0 {
		return 0
	}
	return 2 * p * rec / (p + rec)
}
