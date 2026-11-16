package engine

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	// The per-panic log lines of this pass are bounded in bytes, and the ones
	// not written are counted in one exact line when the pass ends (OR-13).
	panicLines.reset()
	defer panicLines.flush()
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
			// The endpoint label is the target's, so the line is cut and the
			// pass's lines are budgeted in bytes (OR-13, risk R-34): a worker
			// that panics on every endpoint of a hostile target must not fill
			// the host's memory with its own log.
			if panicLines.admit(len(epLabel), len(job.check.Name()), fmt.Sprint(r)) {
				slog.Error("scanner check panicked — job contained, scan continues",
					"worker", workerID, "endpoint", clipPanicField(epLabel), "check", job.check.Name(), "panic", clipPanicField(fmt.Sprint(r)))
			}
			// An active check that panicked did not finish its probes: record
			// that as a scanner-side failure so the active-probe account says so.
			if job.check.Tier() == scanner.TierActive {
				scanner.RecordScannerFailure(scanner.RuleFamilyOfCheck(job.check.Name()), job.endpoint.FullURL, scanner.ReasonInternalError,
					"a scanner check panicked before it finished its probes")
			}
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

// panicLogBudget is the bytes of per-panic log records a pass writes before it
// counts the rest instead; panicFieldMax cuts each target-controlled field of a
// record (OR-13, risk R-34).
const (
	panicLogBudget = 64 << 10
	panicFieldMax  = 256
	// panicRecordOverhead is what the log handler adds around the fields (time,
	// level, message, keys), rounded up.
	panicRecordOverhead = 160
)

func clipPanicField(s string) string {
	if len(s) <= panicFieldMax {
		return s
	}
	cut := panicFieldMax
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(" + strconv.Itoa(len(s)) + " bytes)"
}

// panicLimiter budgets the panic records of one pass.
type panicLimiter struct {
	mu      sync.Mutex
	bytes   int
	dropped int
}

var panicLines panicLimiter

func (l *panicLimiter) reset() {
	l.mu.Lock()
	l.bytes, l.dropped = 0, 0
	l.mu.Unlock()
}

// admit reports whether a record with these field sizes fits the budget, and
// counts it as dropped when it does not.
func (l *panicLimiter) admit(endpointLen, checkLen int, panicText string) bool {
	size := panicRecordOverhead + min(endpointLen, panicFieldMax+16) + checkLen + min(len(panicText), panicFieldMax+16)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bytes+size > panicLogBudget {
		l.dropped++
		return false
	}
	l.bytes += size
	return true
}

// flush writes the one exact line that counts the records not written.
func (l *panicLimiter) flush() {
	l.mu.Lock()
	n := l.dropped
	l.dropped = 0
	l.mu.Unlock()
	if n > 0 {
		slog.Error(fmt.Sprintf("%d further check panics not logged; each one is a finding in the report", n))
	}
}
