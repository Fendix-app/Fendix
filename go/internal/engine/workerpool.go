package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
)

// progressSteps is how many "worker pool progress" lines one sweep emits, at
// most — one per 1/progressSteps of the work. 20 gives the UI a moving bar at
// 5% granularity while keeping the log (and the backend database write it
// triggers) bounded regardless of scan size.
const progressSteps = 20

// WorkerPool runs scanner checks concurrently across endpoints using a bounded goroutine pool.
type WorkerPool struct {
	workers int
	delayMs int
	checks  []scanner.Check
	// cc is the shared per-scan execution context handed to every Check.Run.
	// nil on the legacy []CheckFn path (NewWorkerPool) — runCheck builds an
	// ephemeral CheckContext per job in that case so the old engine tests,
	// which never construct a context, keep working.
	cc *scanner.CheckContext
}

// newPool is the shared constructor. workers is clamped to a minimum of 1.
func newPool(workers, delayMs int, checks []scanner.Check, cc *scanner.CheckContext) *WorkerPool {
	if workers < 1 {
		workers = 1
	}
	return &WorkerPool{
		workers: workers,
		delayMs: delayMs,
		checks:  checks,
		cc:      cc,
	}
}

// NewWorkerPool creates a pool from a legacy []scanner.CheckFn slice. Each fn is
// wrapped via scanner.AsCheck so the pool runs the new Check interface internally
// while the engine worker-pool tests (which pass []scanner.CheckFn) keep compiling.
// cc is left nil; runCheck builds an ephemeral CheckContext per job.
func NewWorkerPool(workers int, delayMs int, checks []scanner.CheckFn) *WorkerPool {
	wrapped := make([]scanner.Check, 0, len(checks))
	for _, fn := range checks {
		wrapped = append(wrapped, scanner.AsCheck("legacy", "engine", scanner.TierPassive, nil, fn))
	}
	return newPool(workers, delayMs, wrapped, nil)
}

// NewWorkerPoolChecks creates a pool from the new Check registry plus a shared
// per-scan CheckContext. The orchestrator uses this after filtering
// scanner.DefaultChecks() by Enabled(cfg).
func NewWorkerPoolChecks(workers int, delayMs int, checks []scanner.Check, cc *scanner.CheckContext) *WorkerPool {
	return newPool(workers, delayMs, checks, cc)
}

// scanJob represents a single endpoint+check combination to execute.
type scanJob struct {
	check    scanner.Check
	endpoint scanner.Endpoint
}

// Run executes all checks against all endpoints using the worker pool.
// Returns all collected findings.
//
// Channel sizing: a bounded buffer keeps memory linear in pool size,
// not in the N×M job matrix. Before: `make(chan ..., len(endpoints)*len(wp.checks))`
// — on a 10k-endpoint × 8-check scan that's 80k slots queued ahead of
// any worker draining. After: `wp.workers*4` is enough to keep all
// workers fed during a tail-end drain without amplifying memory under
// `--max-endpoints 0`.
//
// Context cancellation: the producer also selects on ctx.Done() so a
// long-running scan can be cancelled mid-flight; previously the
// producer relied on the over-sized buffer never blocking, masking
// the lack of a cancel path. Workers continue to honour ctx on each
// loop iteration.
// Run executes the pool and returns findings projected to models.Finding
// (back-compat for callers/tests on the Finding shape). New code that wants
// the richer Evidence should call RunEvidence.
func (wp *WorkerPool) Run(ctx context.Context, cfg *models.ScanConfig, endpoints []scanner.Endpoint) []models.Finding {
	return evidence.ToFindings(wp.RunEvidence(ctx, cfg, endpoints))
}

// RunEvidence executes the pool and returns the raw []evidence.Evidence so
// the orchestrator can keep provenance flowing through correlation (v0.22).
func (wp *WorkerPool) RunEvidence(ctx context.Context, cfg *models.ScanConfig, endpoints []scanner.Endpoint) []evidence.Evidence {
	bufSize := wp.workers * 4
	if bufSize < 1 {
		bufSize = 1
	}
	jobs := make(chan scanJob, bufSize)
	results := make(chan []evidence.Evidence, bufSize)

	// Unit of work = one check against one endpoint; the producer below emits
	// exactly this many jobs.
	totalJobs := int64(len(endpoints) * len(wp.checks))
	var completed atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < wp.workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				findings := runCheck(ctx, wp.cc, cfg, job, workerID)
				if len(findings) > 0 {
					select {
					case results <- findings:
					case <-ctx.Done():
						return
					}
				}

				// Report the sweep as it advances. Without this the pool logged
				// only on completion, so a consumer watching stderr saw nothing
				// between "scanning endpoints" and "worker pool complete" — the
				// longest stretch of a black-box scan, and longer still with
				// active probing. The backend interpolates these into the
				// progress it shows the user.
				//
				// Throttled to one line per PROGRESS_STEP of the sweep: a
				// 5,000-unit scan reports ~20 times, not 5,000. Each line costs
				// the backend a database write, so volume here is not free.
				done := completed.Add(1)
				if totalJobs > 0 {
					step := int64(progressSteps)
					// Emit when this unit crosses a step boundary, and always
					// on the final unit so the last line reads done == total.
					if done*step/totalJobs != (done-1)*step/totalJobs || done == totalJobs {
						slog.Info("worker pool progress", "done", done, "total", totalJobs)
					}
				}

				if wp.delayMs > 0 {
					select {
					case <-time.After(time.Duration(wp.delayMs) * time.Millisecond):
					case <-ctx.Done():
						return
					}
				}
			}
		}(i)
	}

	go func() {
		defer close(jobs)
		for _, ep := range endpoints {
			for _, check := range wp.checks {
				select {
				case jobs <- scanJob{check: check, endpoint: ep}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []evidence.Evidence
	for batch := range results {
		allFindings = append(allFindings, batch...)
	}

	slog.Info("worker pool complete", "endpoints", len(endpoints), "checks", len(wp.checks), "findings", len(allFindings))
	return allFindings
}

// runCheck invokes a single check with a per-job recover() so a panic in
// one check is contained to that job: it's logged, recorded as a synthetic
// INFO finding, and the worker moves on to the next job instead of letting
// the panic unwind the worker goroutine and abort the whole scan.
//
// Returning the panic as a finding (rather than swallowing it) keeps the
// failure visible in the report — operators see *which* check died on
// *which* endpoint, which is the support signal a silent skip would lose.
func runCheck(ctx context.Context, cc *scanner.CheckContext, cfg *models.ScanConfig, job scanJob, workerID int) (findings []evidence.Evidence) {
	defer func() {
		if r := recover(); r != nil {
			epLabel := fmt.Sprintf("%s %s", job.endpoint.Method, job.endpoint.Path)
			slog.Error("scanner check panicked — job contained, scan continues",
				"worker", workerID, "endpoint", epLabel, "check", job.check.Name(), "panic", r)
			findings = []evidence.Evidence{{
				// The rule is the CHECK that panicked, not "something
				// panicked": two different checks failing at one endpoint are
				// two incidents, and a shared identity would let suppressing
				// one hide the other.
				RuleID:     "scanstatus/check-panicked/" + job.check.Name(),
				Title:      "Scanner check panicked",
				Severity:   models.SeverityInfo,
				Source:     models.SourceBlackbox,
				Category:   job.check.Category(),
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("A scanner check panicked while scanning %s and was skipped: %v", epLabel, r),
				Confidence: models.ConfidenceLow,
			}}
		}
	}()

	// Legacy []CheckFn path (NewWorkerPool) leaves cc nil — build an ephemeral
	// context per job so the old engine tests, which never construct one, work.
	if cc == nil {
		cc = scanner.NewCheckContext(cfg)
	}

	// Per-(endpoint,check) deadline. The shared CheckContext clients set
	// Timeout:0, so the only place a scan-wide cfg.Timeout becomes a real
	// deadline is here — applied per job so connection reuse can't cap the
	// whole scan.
	jobCtx := ctx
	if cfg != nil && cfg.Timeout > 0 {
		var cancel context.CancelFunc
		jobCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.Timeout)*time.Second)
		defer cancel()
	}

	return job.check.Run(jobCtx, cc, job.endpoint)
}
