package targets

import (
	"context"
	"errors"
	"fmt"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
)

// ErrTargetSkipped marks a target that cannot run in the current product
// version (as opposed to a real failure). The runner reports SKIPPED with
// the reason instead of failing the suite.
var ErrTargetSkipped = errors.New("benchmark target skipped")

// OWASP is the OWASP Benchmark target.
//
// IMPORTANT (roadmap honesty, Rule 5): OWASP Benchmark is a *Java* web
// application whose score depends on interprocedural, sanitizer-aware
// source→sink taint analysis (~half its ~2740 cases are deliberate sanitized
// false-positive twins, so a line-local matcher scores ~0 on the FP-penalized
// Youden metric). As of v0.27 Fendix ships Java *regex* SAST (line-local,
// TierNativeGo) — real coverage, but NOT the deep Java taint analysis this
// benchmark requires. Emitting a number now would be a garbage baseline, so
// this target loudly SKIPS in BOTH Scan() and Run() (defence in depth: no
// all-zero result can reach the baseline/Compare path). It un-SKIPS only when
// a real Java taint analyzer + a labeled owasp-known.json corpus exist (see
// NEXT_v029.md). The shipped DAST baseline is DVWA + Juice Shop.
type OWASP struct{}

// NewOWASP returns the OWASP Benchmark target.
func NewOWASP() *OWASP { return &OWASP{} }

// Name implements benchmark.BenchmarkTarget.
func (o *OWASP) Name() string { return "owasp" }

// owaspSkipReason is shared by Scan() and Run() so both layers report the same
// honest cause.
const owaspSkipReason = "owasp: %w — OWASP Benchmark needs interprocedural, sanitizer-aware Java taint analysis; Fendix v0.27 ships Java regex SAST only (line-local), which scores ~0 on its FP-penalized metric. SKIPPED until deep Java taint exists"

// Scan reports the target as skipped.
func (o *OWASP) Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error) {
	return nil, fmt.Errorf(owaspSkipReason, ErrTargetSkipped)
}

// Run also reports skipped. Previously it returned an all-zero BenchmarkResult
// "for interface completeness"; that was a latent Rule-5 landmine — a future
// refactor calling Run() without Scan() short-circuiting first would feed a
// 0.0-recall result into Compare() and flag a phantom regression. SKIP here too
// so a fabricated number can never be persisted (target_test.go pins this).
func (o *OWASP) Run(ctx context.Context, result *benchmark.ScanResult) (*benchmark.BenchmarkResult, error) {
	return nil, fmt.Errorf(owaspSkipReason, ErrTargetSkipped)
}
