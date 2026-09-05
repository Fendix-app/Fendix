package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/decision"
	"github.com/Abdel-RahmanSaied/Fendix/internal/diagnostic"
	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/gitdiff"
	"github.com/Abdel-RahmanSaied/Fendix/internal/logagg"
	"github.com/Abdel-RahmanSaied/Fendix/internal/metrics"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/offline"
	"github.com/Abdel-RahmanSaied/Fendix/internal/plugin"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/sarifimport"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/govulncheck"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/secrets"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/semgrep"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/textscan"
)

// Orchestrator coordinates the full scan lifecycle:
// crawl endpoints → run checks → spawn Python → correlate → assign IDs → render report.
type Orchestrator struct {
	cfg     *models.ScanConfig
	spawner *PythonSpawner
	version string
	// engineErr records a failure to resolve the Python taint engine when
	// SAST was requested (cfg.PythonEngine). It is set in NewOrchestrator
	// and turned into a hard, non-zero exit at the top of Run — so a missing
	// engine can never silently degrade an explicit --code/--python-engine
	// scan to native-Go-only output (the silent no-op bug). nil when SAST was
	// not requested or the engine resolved cleanly.
	engineErr error
	// metrics is the opt-in product-metrics collector (v0.20). It is a
	// NoopCollector unless FENDIX_METRICS is set, so the scan path pays
	// nothing when metrics are disabled. nil only when an Orchestrator is
	// constructed directly in a test; recordScanMetric guards for that.
	metrics metrics.Collector
}

// NewOrchestrator creates an orchestrator from scan config.
//
// The Python engine directory is resolved lazily: only when --python-engine
// is set do we call EnsureEngine. Pre-TASK-118 we resolved eagerly and
// logged a WARN if no engine was found, but with the embedded distribution
// dropped that WARN now fires on every scan for the default path — exactly
// the "Python interpreter not required" promise broken at the log level.
// Skip the resolution entirely when the flag is off; runWhiteboxScan never
// gets called in that case so the spawner's empty engineDir is harmless.
func NewOrchestrator(cfg *models.ScanConfig, version string) *Orchestrator {
	engineDir := ""
	var engineErr error
	if cfg.PythonEngine {
		dir, err := EnsureEngine("", version)
		if err != nil {
			// Preserve the historical WARN (TASK-118 log contract). Whether
			// this becomes a hard exit depends on HOW SAST was requested:
			//   - EXPLICIT (--python-engine): record engineErr so Run aborts
			//     with exit 2 — the user asked for the AST taint engine by
			//     name and we have nowhere to run it; silently degrading to
			//     native-Go-only would be the silent-no-op bug.
			//   - IMPLICIT (auto-enabled by --code): leave engineErr nil and
			//     continue with the native-Go scanners. The user didn't opt
			//     into SAST by name, so a plugin/native-only --code scan must
			//     not be aborted just because the optional Python tree is
			//     absent (e.g. CI runners without a python/ on the scan CWD).
			slog.Warn("python engine not available — whitebox scanning disabled", "error", err)
			if cfg.PythonEngineExplicit {
				engineErr = err
			}
		} else {
			engineDir = dir
		}
	}

	return &Orchestrator{
		cfg:       cfg,
		spawner:   NewPythonSpawner("", engineDir),
		version:   version,
		engineErr: engineErr,
		metrics:   metrics.FromEnv(""),
	}
}

// NewOrchestratorWithSpawner creates an orchestrator with a custom Python spawner.
func NewOrchestratorWithSpawner(cfg *models.ScanConfig, spawner *PythonSpawner) *Orchestrator {
	return &Orchestrator{
		cfg:     cfg,
		spawner: spawner,
		metrics: metrics.FromEnv(""),
	}
}

// reportVersion is the version string stamped into report metadata
// (SARIF/PDF/JSON). Real builds inject it via NewOrchestrator (-ldflags
// -X main.Version); the WithSpawner test constructor leaves o.version
// empty, so fall back to "dev" there rather than emitting a blank
// version — empty would break Code Scanning provenance / audit
// reproducibility just as the hardcoded "dev" did (FENDIX_VC quality
// finding: report Version was hardcoded "dev").
func reportVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

// Run executes the full scan pipeline and returns an exit code.
// 0 = no findings above threshold, 1 = findings found, 2 = error.
func (o *Orchestrator) Run(ctx context.Context) int {
	startTime := time.Now()

	// Fail closed when SAST was requested EXPLICITLY but the Python taint
	// engine could not be resolved. NewOrchestrator sets o.engineErr only on
	// that path (cfg.PythonEngineExplicit — the user passed --python-engine by
	// name), so a non-nil engineErr means "the user asked for the AST taint
	// engine and we have nowhere to run it." Exit 2 (error) BEFORE any scanning
	// so we never render a report containing only the native-Go findings as if
	// the SAST engine had run (the silent no-op bug: WARN-then-1-finding-at-
	// exit-0). DAST-only / secrets-only scans, and IMPLICIT --code scans where
	// the engine auto-enabled but isn't present, never reach this branch —
	// engineErr is nil — so they keep the WARN+skip degrade path unchanged.
	if o.engineErr != nil {
		slog.Error("python taint engine could not be resolved and SAST was requested — aborting", "error", o.engineErr)
		fmt.Fprintln(os.Stderr, "fendix: "+o.engineErr.Error())
		return 2
	}

	// Reset per-check WARN aggregator. Real-world scans against unreliable
	// hosts can emit thousands of "request failed" lines without this — one
	// per endpoint per check. logagg caps the WARN volume per check and
	// surfaces the suppressed count via a single Info line at scan end.
	logagg.Reset()

	// Reset the scan-wide active-probe audit log so this run's records
	// don't include leftovers from a previous run in the same process
	// (long-running tests, future server mode).
	scanner.ResetGlobalAuditLog()

	// --debug-bundle wiring (TASK-102). Setup is a no-op when disabled.
	// When enabled, install a slog tee that captures DEBUG-and-above
	// records into the bundle's buffer alongside a fresh stderr text
	// handler. We restore the previous default before the function
	// returns so subsequent code outside Run sees the original handler.
	//
	// We deliberately install a fresh stderr handler instead of wrapping
	// slog.Default().Handler(). main() installs a concrete TextHandler at
	// process startup, but tests and embedders may construct an
	// Orchestrator directly without that prelude — in which case the
	// stdlib's uninstalled default (*slog.defaultHandler) bridges through
	// log.Default() back to slog.Default(), so wrapping it builds an
	// infinite loop on every log call and deadlocks the log mutex.
	// A fresh text handler is unconditionally safe.
	bundle := diagnostic.New(o.cfg.DebugBundlePath, o.cfg)
	if bundle.Enabled() {
		prevDefault := slog.Default()
		stderrLevel := slog.LevelInfo
		if o.cfg.Verbose {
			stderrLevel = slog.LevelDebug
		}
		stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: stderrLevel})
		slog.SetDefault(slog.New(bundle.LogHandler(stderrHandler)))
		defer slog.SetDefault(prevDefault)
	}

	// Apply scan budget controls (TASK-095). MaxDuration wraps the parent
	// context with a deadline immediately so discovery is also bounded by
	// it; MaxRequests is enforced by the budget package's RoundTripper +
	// one-shot ctx cancel and is intentionally armed AFTER discovery so
	// the cap reflects scan-phase requests only (otherwise a small cap
	// like --max-requests 20 would be exhausted by brute-force discovery
	// before any check ran). Both controls implement "soft-stop"
	// semantics: in-flight requests finish, no new ones start.
	budget.Reset()
	if o.cfg.MaxDuration > 0 {
		var cancelDeadline context.CancelFunc
		ctx, cancelDeadline = context.WithTimeout(ctx, o.cfg.MaxDuration)
		defer cancelDeadline()
	}
	ctx, cancelBudget := context.WithCancel(ctx)
	defer cancelBudget()
	defer budget.SetCancelFunc(nil) // unregister on Run return

	// 1. Discover endpoints. A hard discovery failure and a zero-endpoint
	// result both used to exit 2 before any report existed; the coverage
	// contract needs the evidence, so both now record `dast` and render the
	// report first. The exit code is unchanged (hardExit below).
	crawler := scanner.NewCrawler(o.cfg)
	endpoints, discoveryErr := crawler.CrawlEndpoints(ctx)
	if discoveryErr != nil {
		slog.Error("endpoint discovery failed — check --url is reachable and --spec is valid YAML/JSON", "error", discoveryErr)
		endpoints = nil
	}

	budget.Reset()
	budget.SetMaxRequests(o.cfg.MaxRequests)
	budget.SetCancelFunc(cancelBudget)

	hardExit := 0
	if discoveryErr != nil {
		hardExit = 2
	}
	if len(endpoints) == 0 && o.cfg.CodePath == "" {
		slog.Warn("no endpoints discovered — nothing to scan")
		fmt.Fprintln(os.Stderr, "fendix: no endpoints discovered. Provide --url, --spec, or --code.")
		hardExit = 2
	}
	if len(endpoints) > 0 {
		slog.Info("scanning endpoints", "count", len(endpoints))
	}

	// 2. Build check list from the registry. DefaultChecks() is the single
	// source of truth for ordering (configleak first so its CRITICAL
	// "exposed config file" finding lands before noisier per-endpoint checks
	// on the same path — TASK-133 / Phase 17d corpus signal D2) and for the
	// per-check Enabled(cfg) gate (auth needs cfg.Auth, idor needs AuthUser2,
	// injection needs cfg.EnableActive). The disclaimer fires iff any enabled
	// check is TierActive (i.e. sends attack payloads).
	all := scanner.DefaultChecks()
	var checks []scanner.Check
	active := false
	for _, c := range all {
		if !c.Enabled(o.cfg) {
			continue
		}
		checks = append(checks, c)
		if c.Tier() == scanner.TierActive {
			active = true
		}
	}
	if active {
		scanner.PrintDisclaimer()
	}

	// Build the shared per-scan CheckContext AFTER ResetGlobalAuditLog (above)
	// so CheckContext.Audit aliases this run's fresh currentAuditLog().
	cc := scanner.NewCheckContext(o.cfg)

	// 3. Run checks via worker pool
	pool := NewWorkerPoolChecks(o.cfg.Workers, o.cfg.DelayMs, checks, cc)
	evid := pool.RunEvidence(ctx, o.cfg, endpoints)

	// scanStatus accumulates the per-scanner outcome (F-L7/F-L13/F-L14).
	// Every code-scanner below records ok / skipped / failed here instead
	// of the old bare slog.Warn-and-continue, so failures land in
	// ScanMetadata.ScannerStatus, a scan-end summary line, the SARIF
	// invocations[].executionSuccessful flag, and (opt-in) the exit code.
	var scanStatus scannerStatusList

	// The black-box entries describe what the check pass did, not what was
	// configured: budget.Stats() covers the check phase because Reset() ran
	// after discovery, and the probe audit log holds every active probe sent.
	sent, rejected := budget.Stats()
	recordBlackbox(&scanStatus, o.cfg, len(endpoints), discoveryErr, crawler.SpecErr,
		summarizeCheckPhase(ctx, scanner.GlobalAuditRecords(), sent, rejected))

	// Validate --code once. An unreadable path is an input error for every
	// code analyzer (spec §4.4), recorded identically so a consumer sees one
	// cause, not six different scanner-specific messages. Doing this ONE
	// validation up front — instead of letting each of secrets/semgrep/
	// textscan/govulncheck/pip/npm independently stat the path and produce
	// its own execution_error wording — is what makes "input_error on every
	// code analyzer" an invariant rather than a coincidence of six error
	// messages happening to agree.
	codeConfigured := o.cfg.CodePath != ""
	var codeErr error
	if codeConfigured {
		codeErr = o.validateCodePath()
		if codeErr != nil {
			slog.Error("--code is not a readable directory", "path", o.cfg.CodePath, "error", codeErr)
			for _, name := range []string{AnalyzerSecrets, AnalyzerTextscan, AnalyzerSemgrep, AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
				scanStatus.fail(name, reporters.ReasonInputError, codeErr)
			}
		}
	}
	codeUsable := codeConfigured && codeErr == nil

	// --offline (F-M4/F-H4): load the air-gapped snapshot once. In offline
	// mode the orchestrator MUST NOT make any outbound call — pip/npm
	// consult this snapshot and govulncheck (which needs vuln.go.dev) is
	// recorded SKIPPED. A snapshot that won't load is a hard skip for the
	// dep scanners, NOT a silent fall-through to the network.
	var offlineSnap *offline.Snapshot
	if o.cfg.Offline {
		dbPath := o.cfg.OfflineDBPath
		if dbPath == "" {
			dbPath = offline.DefaultDBPath()
		}
		snap, err := offline.Read(dbPath)
		if err != nil {
			slog.Warn("offline mode: snapshot unavailable — dep-CVE scanners cannot run hermetically", "path", dbPath, "error", err)
		} else {
			offlineSnap = snap
			slog.Info("offline mode: loaded snapshot", "path", dbPath, "advisories", len(snap.Advisories))
		}
	}

	// 3.4. Resolve the diff-aware file allowlist (`fendix scan --diff`).
	// When --diff is set we ask git for the changed files under CodePath
	// and scope the whitebox scanners + SCA gate to that set. A nil
	// allowlist (the default, --diff off) means every scanner walks the
	// full tree, exactly as before — diff mode can only narrow the file
	// set, never change detection logic. If git fails (not a repo, bad
	// ref) we log and fall back to a full scan rather than failing closed:
	// a missing diff context should degrade to "scan everything", which is
	// safe, not "scan nothing", which would silently pass a dirty commit.
	var allow *gitdiff.Allowlist
	if o.cfg.Diff && o.cfg.CodePath != "" {
		changed, derr := gitdiff.ChangedFiles(ctx, gitdiff.Options{
			RepoRoot: o.cfg.CodePath,
			Ref:      o.cfg.DiffRef,
			Staged:   o.cfg.DiffStaged,
		})
		if derr != nil {
			slog.Warn("diff-aware scan: git diff failed — falling back to full scan",
				"error", derr, "ref", o.cfg.DiffRef, "staged", o.cfg.DiffStaged)
		} else {
			allow = gitdiff.NewAllowlist(o.cfg.CodePath, changed)
			slog.Info("diff-aware scan: scoped to changed files",
				"files", allow.Len(), "ref", o.cfg.DiffRef, "staged", o.cfg.DiffStaged)
		}
	}

	// Diff-aware short-circuit: an empty (non-nil) allowlist means the diff
	// matched zero scannable files, so the file-walking whitebox scanners
	// (secrets/semgrep/textscan) have nothing to look at. Skip them outright
	// instead of walking the whole tree to filter everything out — this turns
	// a no-code-change commit's scan into ~git-diff time.
	diffEmpty := o.cfg.CodePath != "" && allow != nil && allow.Empty()
	if diffEmpty {
		slog.Info("diff-aware scan: no changed files — skipping whitebox file scanners")
		scanStatus.skip(AnalyzerSecrets, reporters.ReasonDiffUnchanged, "diff: no changed files")
		scanStatus.skip(AnalyzerTextscan, reporters.ReasonDiffUnchanged, "diff: no changed files")
		if !o.cfg.Fast {
			scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDiffUnchanged, "diff: no changed files")
		}
	}

	// 3.5. Native dep-CVE scanners (TASK-119). Run in-process before
	// the Python whitebox engine spawns, so the Python deps.py path
	// can be retired in Phase 17b (TASK-118) without losing coverage.
	// Findings flow through the same dedup pipeline so the Python
	// output collapses with native output during the transition window.
	//
	// Go:   golang.org/x/vuln gives call-graph reachability.
	// PyPI: OSV.dev /v1/query per pinned (==) dep, cached 24h.
	// npm:  OSV.dev /v1/query per resolved version in package-lock.json
	//       v2/v3 (full transitive tree), cached 24h.
	//
	// Each ecosystem has an ErrNo... sentinel for silent-skip; other
	// errors are RECORDED (per-scanner status) and the scan continues so
	// a network blip doesn't stop a scan from reporting other findings.
	//
	// Explicit else branches (spec §10): --no-code, an unreadable --code,
	// --fast and --no-native-deps must each record all three dep
	// scanners with a reason rather than leaving no entry at all — that
	// used to be four different ways for govulncheck/pip/npm to go
	// missing from scanner_status with no trace of why.
	switch {
	case !codeConfigured:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonNotApplicable, "no --code")
		}
	case !codeUsable:
		// already recorded input_error above
	case o.cfg.Fast:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonDisabledByFlag, "--fast")
		}
	case o.cfg.NoNativeDeps:
		for _, name := range []string{AnalyzerGovulncheck, AnalyzerPip, AnalyzerNpm} {
			scanStatus.skip(name, reporters.ReasonDisabledByFlag, "--no-native-deps")
		}
	default:
		// govulncheck needs the live vuln.go.dev DB and a build of the
		// target module; it has no snapshot-only mode. In --offline we do
		// NOT call it (that would be a silent outbound call) — record it
		// SKIPPED and move on.
		if o.cfg.Offline {
			slog.Info("offline mode: skipping native go deps scan (govulncheck requires vuln.go.dev)")
			scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonDisabledOffline, "--offline: govulncheck requires vuln.go.dev")
		} else if !allow.ContainsBase("go.mod", "go.sum") {
			// Diff-aware: no Go manifest changed → nothing new to flag.
			slog.Debug("diff-aware scan: go.mod/go.sum unchanged, skipping govulncheck")
			scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonDiffUnchanged, "diff: go.mod/go.sum unchanged")
		} else {
			nativeFindings, err := govulncheck.Scan(ctx, o.cfg.CodePath)
			switch {
			case err == nil:
				slog.Info("native go deps scan complete", "findings", len(nativeFindings))
				evid = append(evid, nativeFindings...)
				scanStatus.ok("govulncheck")
			case errors.Is(err, govulncheck.ErrNoGoMod):
				slog.Debug("no go.mod at code path, skipping native go deps scan")
				scanStatus.skip(AnalyzerGovulncheck, reporters.ReasonNotApplicable, "no go.mod under --code")
			default:
				slog.Warn("native go deps scan failed", "error", err)
				scanStatus.fail(AnalyzerGovulncheck, classifyErr(err), err)
			}
		}

		// pip-audit walks the scan root recursively up to
		// pip.DefaultRecurseDepth levels to catch multi-service repos
		// where requirements.txt lives in a subdir. Track 4 heavy-eval
		// surfaced this on TwiScope-backend: 8 dep-CVEs were invisible
		// to a root-only scan because requirements.txt was at
		// Twiscope_Main_App/, not the repo root. Vendored / cache dirs
		// (.venv, node_modules, .git, etc.) are skipped regardless of
		// depth — see recurseSkipDirs in the pip package.
		//
		// In --offline the pip pass routes through the snapshot instead of
		// osv.dev; without a loadable snapshot it's SKIPPED (never the
		// network). --use-pip-audit is ignored offline because pip-audit
		// itself reaches out to osv.dev.
		var (
			pipFindings []evidence.Evidence
			pipErr      error
		)
		switch {
		case !allow.ContainsBase("requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml"):
			// Diff-aware: no Python manifest/lockfile changed → skip.
			slog.Debug("diff-aware scan: no python manifest changed, skipping pip scan")
			scanStatus.skip(AnalyzerPip, reporters.ReasonDiffUnchanged, "diff: no python manifest changed")
		case o.cfg.Offline && offlineSnap == nil:
			slog.Warn("offline mode: skipping native pypi deps scan (no usable snapshot)")
			scanStatus.skip(AnalyzerPip, reporters.ReasonDependencyMissing, "--offline: no usable snapshot at "+dbPathForLog(o.cfg))
		case o.cfg.Offline:
			slog.Debug("native pypi dep-CVE scan starting", "mode", "offline snapshot")
			pipFindings, pipErr = pip.ScanOffline(o.cfg.CodePath, pip.DefaultRecurseDepth, offlineSnap)
			o.recordDepScanResult(&scanStatus, "pip", "native pypi deps scan", &evid, pipFindings, pipErr)
		default:
			pipMode := "OSV.dev"
			if o.cfg.UsePipAudit {
				pipMode = "pip-audit subprocess"
			}
			slog.Debug("native pypi dep-CVE scan starting", "mode", pipMode)
			pipFindings, pipErr = pip.ScanRecursiveWithOptions(
				ctx, o.cfg.CodePath, pip.DefaultRecurseDepth,
				pip.Options{UsePipAudit: o.cfg.UsePipAudit},
			)
			o.recordDepScanResult(&scanStatus, "pip", "native pypi deps scan", &evid, pipFindings, pipErr)
		}

		// npm: same offline routing as pip.
		var (
			npmFindings []evidence.Evidence
			npmErr      error
		)
		switch {
		case !allow.ContainsBase("package-lock.json", "package.json"):
			// Diff-aware: no npm manifest/lockfile changed → skip.
			slog.Debug("diff-aware scan: no npm manifest changed, skipping npm scan")
			scanStatus.skip(AnalyzerNpm, reporters.ReasonDiffUnchanged, "diff: no npm manifest changed")
		case o.cfg.Offline && offlineSnap == nil:
			slog.Warn("offline mode: skipping native npm deps scan (no usable snapshot)")
			scanStatus.skip(AnalyzerNpm, reporters.ReasonDependencyMissing, "--offline: no usable snapshot at "+dbPathForLog(o.cfg))
		case o.cfg.Offline:
			npmFindings, npmErr = npm.ScanOffline(o.cfg.CodePath, offlineSnap)
			evid = o.recordNpmScanResult(&scanStatus, &evid, npmFindings, npmErr)
		default:
			npmFindings, npmErr = npm.Scan(ctx, o.cfg.CodePath)
			evid = o.recordNpmScanResult(&scanStatus, &evid, npmFindings, npmErr)
		}
	}

	// 3.6. Native secrets scan (TASK-115). Ported in-process from
	// python/analyzers/secrets.py; runs unconditionally when CodePath
	// is set, regardless of Python availability. Same SEC-* IDs as the
	// Python implementation so any overlap (e.g. user explicitly passes
	// --checks secrets) dedupes cleanly. No network access — runs in
	// offline mode unchanged.
	//
	// Explicit else branches (spec §10): no --code, an unreadable --code,
	// and an empty diff each record ONE reasoned entry instead of leaving
	// secrets absent from scanner_status.
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerSecrets, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
		// already recorded input_error above
	case diffEmpty:
		// recorded diff_unchanged above
	default:
		secretEvidence, err := secrets.ScanWithAllowlist(ctx, o.cfg.CodePath, allow)
		switch {
		case err == nil:
			slog.Info("native secrets scan complete", "findings", len(secretEvidence))
			// v0.22: secrets emits Evidence natively; project to Finding at the
			// accumulator boundary (provenance threads through once the
			// accumulator itself is flipped to Evidence in a later batch).
			evid = append(evid, secretEvidence...)
			scanStatus.ok("secrets")
		case errors.Is(err, secrets.ErrCodePathMissing):
			slog.Debug("code path missing — skipping native secrets scan")
			scanStatus.fail(AnalyzerSecrets, reporters.ReasonInputError, err)
		default:
			slog.Warn("native secrets scan failed", "error", err)
			scanStatus.fail(AnalyzerSecrets, classifyErr(err), err)
		}
	}

	// 3.7. Native semgrep scan (TASK-116). Shells out to the host's
	// installed `semgrep` binary with the bundled rule pack; if
	// semgrep isn't on $PATH, we log an install hint and continue —
	// graceful absence matches the existing posture for missing
	// Python. Same SEC-* IDs as the Python wrapper so dedup absorbs
	// any overlap when a user opts the Python path back in.
	//
	// Explicit else branches (spec §10). The diff short-circuit above
	// (allow != nil && allow.Empty()) already guards itself with
	// `if !o.cfg.Fast` before recording semgrep diff_unchanged, so the
	// o.cfg.Fast case here MUST come before diffEmpty: a fast run against
	// an empty diff records semgrep once, as disabled_by_flag, never twice.
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerSemgrep, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
		// already recorded input_error above
	case o.cfg.Fast:
		scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDisabledByFlag, "--fast")
	case diffEmpty:
		// recorded diff_unchanged above
	default:
		semgrepFindings, err := semgrep.ScanWithAllowlist(ctx, o.cfg.CodePath, allow)
		switch {
		case err == nil:
			slog.Info("native semgrep scan complete", "findings", len(semgrepFindings))
			evid = append(evid, semgrepFindings...)
			scanStatus.ok("semgrep")
		case errors.Is(err, semgrep.ErrSemgrepUnavailable):
			slog.Info("semgrep not installed — skipping (install with: pip install semgrep)")
			scanStatus.skip(AnalyzerSemgrep, reporters.ReasonDependencyMissing, "semgrep binary not installed")
		case errors.Is(err, semgrep.ErrCodePathMissing):
			slog.Debug("code path missing — skipping native semgrep scan")
			scanStatus.fail(AnalyzerSemgrep, reporters.ReasonInputError, err)
		default:
			slog.Warn("native semgrep scan failed", "error", err)
			scanStatus.fail(AnalyzerSemgrep, classifyErr(err), err)
		}
	}

	// 3.8. Native textscan (Sprints 04 / 05 / 06). Regex-based SAST
	// for Go, JS/TS, Dockerfile, and Kubernetes YAML. Pure stdlib,
	// no external tooling required. Fast (<1s on typical repos)
	// because it's filename-extension-routed line scanning.
	//
	// Explicit else branches (spec §10): no --code, an unreadable --code,
	// and an empty diff each record ONE reasoned entry instead of leaving
	// textscan absent from scanner_status.
	switch {
	case !codeConfigured:
		scanStatus.skip(AnalyzerTextscan, reporters.ReasonNotApplicable, "no --code")
	case !codeUsable:
		// already recorded input_error above
	case diffEmpty:
		// recorded diff_unchanged above
	default:
		textFindings, err := textscan.ScanWithAllowlist(o.cfg.CodePath, textscan.AllRules(), allow)
		switch {
		case err != nil:
			slog.Warn("native textscan failed", "error", err)
			scanStatus.fail(AnalyzerTextscan, classifyErr(err), err)
		default:
			if len(textFindings) > 0 {
				slog.Info("native textscan complete", "findings", len(textFindings))
				evid = append(evid, textFindings...)
			}
			scanStatus.ok("textscan")
		}
	}

	// 4. Spawn Python engine for white-box analysis. Default off as of
	// TASK-118 — secrets (TASK-115) + semgrep (TASK-116) now run in
	// native Go and the embedded Python distribution is no longer
	// bundled. Set --python-engine to re-enable the Python auth /
	// injection / deps checks; requires a usable Python source tree
	// resolvable via EnsureEngine (local python/ or explicit FENDIX_ENGINE).
	if o.cfg.PythonEngine && (o.cfg.CodePath != "" || o.cfg.SpecPath != "") {
		pyStatus := CheckPython(o.spawner.pythonBin)
		if !pyStatus.Available {
			slog.Warn("python not available — skipping whitebox analysis")
			fmt.Fprintln(os.Stderr, "fendix: "+PythonRequiredMessage())
		} else {
			slog.Info("python available", "version", pyStatus.Version, "binary", pyStatus.Binary)
			bundle.SetPythonVersion(pyStatus.Version)
			wbFindings := o.runWhiteboxScan(ctx)
			evid = append(evid, wbFindings...)
		}
	}

	// 4.5. Run out-of-tree plugins (TASK-113). Plugin findings flow
	// through the same correlation/dedup/sort/ID pipeline as embedded
	// engine findings, so a custom-secret-pattern plugin can correlate
	// against a blackbox auth check exactly like the built-in secrets
	// analyzer does.
	var pluginsOut pluginOutcome
	if !o.cfg.NoPlugins {
		var pluginEvid []evidence.Evidence
		pluginEvid, pluginsOut = o.runPlugins(ctx)
		evid = append(evid, pluginEvid...)
	}
	recordPlugins(&scanStatus, o.cfg, pluginsOut)

	// 4.8. SARIF imports (`scan --import`): parse + normalize findings from
	// other scanners and append them to the evidence stream BEFORE any
	// correlation, so the cross-tool pass in finalize can weigh them.
	// Fail-closed on a malformed file (exit 2): silently importing half a
	// document would misrepresent coverage.
	var importedTools []reporters.ImportedTool
	if len(o.cfg.ImportPaths) > 0 {
		imp, tools, err := loadImports(o.cfg.ImportPaths)
		if err != nil {
			slog.Error("failed to load SARIF import — the file must be a SARIF 2.1.0 document", "error", err)
			fmt.Fprintln(os.Stderr, "fendix: "+err.Error())
			return 2
		}
		evid = append(evid, imp...)
		importedTools = tools
	}

	// 5. Correlate black-box and white-box evidence. v0.22: the whole scan
	// now accumulates []evidence.Evidence, so correlation runs natively on
	// Evidence (Correlation Service V2) — provenance + lineage thread through
	// end-to-end for the future confidence engine. Imported evidence is
	// fenced out of this correlator (see correlateWithMarks) and handled by
	// the cross-tool pass inside finalize. The finalize call projects to
	// models.Finding for the downstream pipeline (escalate → dedup →
	// consistency → sort → IDs → ignore/baseline → render); that projection
	// is byte-identical to the legacy output.
	findings := evidence.ToFindings(evid)
	if hasWhitebox(findings) && hasBlackbox(findings) {
		evid = CorrelateEvidence(evid)
	}

	duration := time.Since(startTime)

	// Temporary placeholder (spec §10): python-engine is a base analyzer
	// that must appear exactly once on every scan, but its real recording
	// logic isn't wired yet — Task 5 records its actual outcome (protocol
	// result / not-requested / engine-unavailable). plugins now records
	// itself above via recordPlugins. Guarded with has() so this is a
	// no-op once Task 5 lands its own scanStatus.set/skip/ok calls earlier
	// in Run.
	if !scanStatus.has(AnalyzerPythonEngine) {
		scanStatus.skip(AnalyzerPythonEngine, reporters.ReasonNotApplicable, "recorded in Task 5")
	}

	// Determine scan mode for metadata
	scanMode := "blackbox"
	if (o.cfg.CodePath != "" || o.cfg.SpecPath != "") && o.cfg.URL != "" {
		scanMode = "hybrid"
	} else if o.cfg.CodePath != "" || o.cfg.SpecPath != "" {
		scanMode = "whitebox"
	}

	// Build list of check names that were run, derived from the same filtered
	// registry slice the worker pool executed — so metadata can't drift from
	// what actually ran. (The old hand-built list OMITTED "configleak" even
	// though it always ran; the derived list now correctly includes it.)
	checksRun := make([]string, 0, len(checks)+3)
	for _, c := range checks {
		checksRun = append(checksRun, c.Name())
	}
	// Derived from the recorded per-scanner status, NOT from the presence of
	// a code path: a configured scanner that never ran (missing binary,
	// absent manifest, crash) must not be published as a check that ran.
	checksRun = append(checksRun, codeScannerLabels(scanStatus)...)

	meta := reporters.ScanMetadata{
		Target:    o.cfg.URL,
		StartedAt: startTime,
		Duration:  duration.Round(time.Millisecond).String(),
		Version:   reportVersion(o.version),
		// The algorithm these findings' fingerprints were stamped with. Set
		// here rather than left to RenderJSON, because the SARIF renderer
		// keys partialFingerprints off it too — and an unset value means
		// "archived v1 report", which a live scan is not.
		FingerprintAlgorithm: models.FingerprintAlgorithm,
		Mode:                 scanMode,
		EndpointsCount:       len(endpoints),
		EndpointsDiscovered:  crawler.Discovered,
		EndpointsTruncated:   crawler.Discovered > len(endpoints),
		ActiveProbes:         o.cfg.EnableActive,
		ChecksRun:            checksRun,
		ScannerStatus:        []reporters.ScannerStatus(scanStatus.sorted()),
		Imports:              importedTools,
	}

	// Steps 5.2–12 (cross-tool correlation → escalate → collapse → dedup →
	// consistency → sort → IDs/fingerprints → ignore → baseline →
	// save-baseline → decisions → sanitize → render) are shared with
	// RunImport and live in finalize, so the two entry points cannot drift.
	findings, decisions, ec := o.finalize(evid, meta)
	if ec != 0 {
		return ec
	}

	// Opt-in product metric for this scan (FENDIX_METRICS). NoopCollector
	// when disabled — no I/O, negligible overhead.
	o.recordScanMetric(duration, len(findings))

	// Surface aggregated WARN suppression counts so operators can tell at a
	// glance how many transient errors were silenced (vs. the visible cap
	// emissions). One Info line per scan; empty when no events occurred.
	if attrs := logagg.Summary(); len(attrs) > 0 {
		slog.Info("warning summary", attrs...)
	}

	// F-L7/F-L13: surface a one-line scanner-status summary at scan end so
	// a degraded run (a scanner that errored or was skipped) is visible
	// without grepping the WARN stream. Only emitted when at least one
	// code scanner ran.
	if len(scanStatus) > 0 {
		var ok, skipped, failed int
		for _, s := range scanStatus {
			switch s.State {
			case reporters.ScannerOK:
				ok++
			case reporters.ScannerSkipped:
				skipped++
			case reporters.ScannerFailed:
				failed++
			}
		}
		args := []any{"ok", ok, "skipped", skipped, "failed", failed}
		if failed > 0 {
			args = append(args, "failed_scanners", strings.Join(scanStatus.failedNames(), ","))
		}
		slog.Info("scanner status summary", args...)
	}

	// Surface scan-budget telemetry whenever a cap was set, regardless of
	// whether it fired. This makes "did we run out of budget?" trivially
	// auditable in CI and gives operators a feedback loop for tuning
	// --max-requests / --max-duration to their target scan size.
	if o.cfg.MaxRequests > 0 || o.cfg.MaxDuration > 0 {
		sent, rejected := budget.Stats()
		slog.Info("budget summary",
			"requests_sent", sent,
			"requests_rejected", rejected,
			"max_requests", o.cfg.MaxRequests,
			"max_duration", o.cfg.MaxDuration,
		)
	}

	// Write the diagnostic tarball before the fail-on check so that even a
	// non-zero exit produces the bundle (a CI failure is exactly when an
	// operator wants to attach a bug-report bundle).
	if bundle.Enabled() {
		bundle.SetFindings(findings)
		bundle.SetMetadata(meta)
		bundle.SetProbes(scanner.GlobalAuditRecords())
		if err := bundle.Write(o.version); err != nil {
			slog.Error("failed to write debug bundle — check that the path is writable",
				"path", o.cfg.DebugBundlePath,
				"error", err,
			)
		} else {
			slog.Info("debug bundle written", "path", o.cfg.DebugBundlePath)
		}
	}

	// F-L7/F-L13/F-L14: --fail-on-scanner-error makes any recorded
	// scanner failure force a non-zero exit, independent of the --fail-on
	// severity threshold. A scanner crash is a coverage gap, not a clean
	// run, and CI should be able to treat it as a build failure. Skipped
	// scanners (missing manifest, offline govulncheck) do NOT trip this —
	// only scanners that ran and errored. Exit 2 (error) so it's
	// distinguishable from the exit-1 "findings at/above threshold" path.
	if o.cfg.FailOnScannerError && scanStatus.hasFailure() {
		slog.Error("scanner failure recorded and --fail-on-scanner-error set — exiting non-zero",
			"failed_scanners", strings.Join(scanStatus.failedNames(), ","))
		fmt.Fprintf(os.Stderr, "fendix: scanner(s) failed and --fail-on-scanner-error is set: %s\n", strings.Join(scanStatus.failedNames(), ", "))
		return 2
	}

	// A hard discovery failure or a zero-endpoint result already rendered
	// the report above (finalize ran unconditionally); this returns the
	// unchanged exit-2 contract now that the evidence exists to explain it.
	if hardExit != 0 {
		return hardExit
	}

	// 8. Check fail-on threshold
	// v0.24: exit code derives from the decision layer. Byte-identical to the
	// legacy checkFailOn (locked by decision.TestExitCodeMatchesLegacyCheckFailOn)
	// because `decisions` were built from the same finalized findings + FailOn.
	return decision.ExitCode(decisions)
}

// finalize is the shared post-evidence pipeline for Run and RunImport:
// cross-tool correlation, reachable escalation, duplicate-location collapse,
// dedup, severity↔confidence consistency, deterministic sort, ID +
// fingerprint stamping, ignore rules, baseline diff, save-baseline,
// decisions, credential sanitization, and report rendering.
//
// Returns the finalized findings, their decisions, and a hard-error exit
// code: 0 on success, 2 when a fail-closed step failed (message already
// printed). The caller derives the process exit from the decisions.
func (o *Orchestrator) finalize(evid []evidence.Evidence, meta reporters.ScanMetadata) ([]models.Finding, []decision.Decision, int) {
	// 5.2. Cross-tool correlation (SARIF import): stamps strong
	// corroboration (independent tool + same normalized CWE + same
	// normalized location) and collapses imported duplicates into their
	// corroborated native representatives. Runs AFTER the blackbox↔whitebox
	// correlator (imported evidence is fenced out of that one) and BEFORE
	// the provenance index below, so the corroboration flags are captured
	// for scoring. No-op when no imported evidence is present.
	evid, collapsedByTool := CorrelateCrossTool(evid)
	// Fold the collapsed counts into the per-tool import accounting so a
	// report can explain why N uploaded findings produced fewer than N rows.
	// meta.Imports is a slice, so mutating its elements is visible to
	// renderReport below even though meta itself is passed by value.
	// sarifimport.Normalize + loadImports guarantee exactly one block per
	// tool, so each count has an unambiguous home.
	for i := range meta.Imports {
		if n, ok := collapsedByTool[meta.Imports[i].Tool]; ok {
			meta.Imports[i].Corroborated = n
		}
	}
	findings := evidence.ToFindings(evid)

	// The projection above is lossy BY DESIGN (models.Finding is the frozen
	// public shape), but several confidence rules — payload-validated (+10),
	// the B4 HTTP-response-context de-escalation (-15), the lineage
	// "evidence chain" reason, and the cross-tool corroboration signal —
	// read fields that live only on Evidence. Scoring the projected Finding
	// made them dead code. Capture the internal half here, keyed by the
	// render-stable finding identity, so the decision step can score the
	// FULL evidence. Nothing in this index is ever serialized, so the
	// public JSON/SARIF contract is untouched.
	prov := evidence.NewProvenanceIndex(evid)

	// 5.4. Escalate non-correlated reachable findings (TASK-125).
	// The correlator already bumps correlated-reachable findings via
	// mergeFindings's second escalateSeverity call. This step catches
	// the pure-whitebox case: an AST-proven taint chain on a finding
	// that didn't correlate to a blackbox match. Per docs/example_plan.md
	// §3.5 the multiplier is 1.5x; on the discrete severity scale that's
	// ~one level up. Saturates at CRITICAL. Imported findings never carry
	// Reachable, so this step cannot touch them.
	findings = escalateNonCorrelatedReachable(findings)

	// 5.45. Collapse cross-analyzer duplicates at a shared source location.
	// Several static engines cover the same constructs, and Deduplicate groups
	// on Title — so two engines describing one sink in different words never
	// merged and the user saw the same vulnerability two or three times. Runs
	// before Deduplicate, while each finding is still one (endpoint, title).
	findings = CollapseDuplicateLocations(findings)

	// 5.5. Deduplicate identical findings across endpoints (TASK-088).
	// Runs after correlation so correlated findings are grouped too.
	// "Missing CSP × 21 endpoints" → 1 finding with AffectedEndpoints[21].
	findings = Deduplicate(findings)

	// 5.6. Enforce severity↔confidence consistency (TASK-092). LOW confidence
	// caps severity at MEDIUM; MEDIUM confidence caps at HIGH. Mismatched
	// findings get their severity downgraded so the public JSON schema's
	// consistency rule holds for every emitted report.
	findings = enforceConsistency(findings)

	// 6. Sort findings deterministically by endpoint+category for stable ID assignment
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Endpoint != findings[j].Endpoint {
			return findings[i].Endpoint < findings[j].Endpoint
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Title < findings[j].Title
	})

	// 7. Assign sequential IDs + stamp the run-stable fingerprint. The
	// fingerprint (content hash of Category|Endpoint|Title) is computed here,
	// BEFORE the ignore/baseline steps, so a `fingerprint:` ignore rule can
	// match it. Unlike the positional SEC-NNN ID it does not drift between
	// runs, so it is the durable key for suppressions.
	for i := range findings {
		findings[i].ID = fmt.Sprintf("SEC-%03d", i+1)
		models.StampIdentity(&findings[i])
	}

	// 8. Apply ignore rules from .fendix-ignore.
	//
	// F-L14: an explicit-but-unparseable --ignore file is a HARD error
	// (exit 2), consistent with --config policy parse failures in
	// main.go. Pre-fix this logged at ERROR and continued — which meant a
	// typo'd suppression file silently scanned with zero suppressions, the
	// opposite of fail-closed for a security control.
	if o.cfg.IgnorePath != "" {
		ignoreFile, err := ParseIgnoreFile(o.cfg.IgnorePath)
		if err != nil {
			slog.Error("failed to parse ignore file — check YAML syntax and file path", "path", o.cfg.IgnorePath, "error", err)
			fmt.Fprintf(os.Stderr, "fendix: cannot parse --ignore file %s: %v\n", o.cfg.IgnorePath, err)
			return nil, nil, 2
		}
		findings = ApplyIgnoreRules(findings, ignoreFile.Ignore)
	}

	// 9. Apply baseline diff if --baseline provided.
	//
	// Fail-closed on a CORRUPT baseline (exit 2), consistent with the --ignore
	// handling above: an explicit-but-unparseable baseline is a
	// misconfiguration, and silently scanning without the diff would let every
	// already-known finding re-block the gate (or, with --fail-on, flip a
	// green run red for the wrong reason). A MISSING baseline is NOT an error —
	// it's the legitimate first run before --save-baseline has written one.
	if o.cfg.BaselinePath != "" {
		diffed, err := ApplyBaselineDiffStrict(findings, o.cfg.BaselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fendix: cannot parse --baseline file %s: %v\n", o.cfg.BaselinePath, err)
			return nil, nil, 2
		}
		findings = diffed
	}

	// 10. Save baseline if requested (before sanitization, so credentials
	// are available for future diff).
	//
	// F-L14: a requested-but-failed --save-baseline is a HARD error (exit
	// 2). Pre-fix this logged at ERROR and continued, so a CI job that
	// asked to capture a baseline could exit 0 having silently written
	// nothing — the next diff run would then report every finding as
	// "new". Consistent with the --ignore parse-failure handling above.
	if o.cfg.SaveBaselinePath != "" {
		if err := SaveBaseline(findings, o.cfg.SaveBaselinePath); err != nil {
			slog.Error("failed to save baseline — check that the directory exists and is writable", "error", err)
			fmt.Fprintf(os.Stderr, "fendix: cannot save --save-baseline to %s: %v\n", o.cfg.SaveBaselinePath, err)
			return nil, nil, 2
		}
	}

	// 10.5. v0.24 Decision Reports: derive a decision + deterministic
	// confidence score for every FINAL finding (post escalate/dedup/
	// consistency/sort/IDs/ignore/baseline), and stamp them onto the findings
	// so all reporters + the exit code read one source of truth.
	//
	// This runs BEFORE sanitization, not after: the provenance index is keyed
	// on the finding's (Category, Endpoint, Title) identity and sanitization
	// can redact a credential out of Title, which would silently break the
	// lookup. Scoring off the pre-redaction projection cannot leak anything —
	// the Evidence it scores is internal and never serialized, only the
	// status/score/band/reasons are stamped back, and SanitizeFindings copies
	// those four fields through unchanged.
	if o.cfg.FailOn != "" && models.SeverityRank(models.Severity(o.cfg.FailOn)) == 0 {
		// Preserve the legacy invalid-threshold WARN (was in checkFailOn).
		slog.Warn("invalid --fail-on value — use CRITICAL, HIGH, or MEDIUM", "value", o.cfg.FailOn)
	}
	decisions := stampDecisions(findings, prov, o.cfg.FailOn, o.decisionOptions())

	// 11. Sanitize credentials from findings before rendering
	findings = reporters.SanitizeFindings(findings, o.cfg.Auth, o.cfg.AuthUser2)

	// 12. Render report
	if err := o.renderReport(findings, meta); err != nil {
		slog.Error("report rendering failed — check --output path is writable and --format is json/html/sarif", "error", err)
		return nil, nil, 2
	}

	counts := reporters.CountSeverities(findings)
	slog.Info("scan complete",
		"duration", meta.Duration,
		"total", len(findings),
		"critical", counts.Critical,
		"high", counts.High,
		"medium", counts.Medium,
		"low", counts.Low,
		"info", counts.Info,
	)

	// v0.24: human-readable decision summary — engineers see decisions, not
	// just findings. STDERR only, so stdout stays a pure machine-readable
	// report (`fendix scan | jq` and SARIF-upload pipelines are unaffected).
	// Reads the same CountStatuses the JSON/SARIF reports use, so the blocking
	// count is consistent with the exit code.
	sc := reporters.CountStatuses(findings)
	fmt.Fprintf(os.Stderr,
		"\nDecision summary: %d findings — %d blocking, %d warning, %d informational (%d high-confidence)\n",
		sc.Total, sc.Blocking, sc.Warning, sc.Informational, sc.Confirmed)

	return findings, decisions, 0
}

// RunImport is the standalone `fendix import` entry point: normalize the
// configured SARIF files into imported evidence and run the STANDARD
// finalization chain — cross-tool correlation, dedup, ignore/baseline,
// confidence-gated --fail-on decisions, reporters — with no scanning. The
// exit contract matches Run: 0 clean, 1 when a decision BLOCKs, 2 on error.
func (o *Orchestrator) RunImport(ctx context.Context) int {
	startTime := time.Now()

	if len(o.cfg.ImportPaths) == 0 {
		fmt.Fprintln(os.Stderr, "fendix: import requires at least one SARIF file (or '-' for stdin)")
		return 2
	}
	evid, importedTools, err := loadImports(o.cfg.ImportPaths)
	if err != nil {
		slog.Error("failed to load SARIF import — the file must be a SARIF 2.1.0 document", "error", err)
		fmt.Fprintln(os.Stderr, "fendix: "+err.Error())
		return 2
	}
	if ctx.Err() != nil {
		return 2
	}

	meta := reporters.ScanMetadata{
		// Target is the optional --target label — an import has no scanned
		// target of its own.
		Target:    o.cfg.URL,
		StartedAt: startTime,
		// Imported findings go through the same fingerprint pass as a scan's.
		FingerprintAlgorithm: models.FingerprintAlgorithm,
		Duration:             time.Since(startTime).Round(time.Millisecond).String(),
		Version:              reportVersion(o.version),
		Mode:                 "import",
		Imports:              importedTools,
	}

	_, decisions, ec := o.finalize(evid, meta)
	if ec != 0 {
		return ec
	}
	return decision.ExitCode(decisions)
}

// loadImports reads, parses and normalizes every configured SARIF file.
// "-" reads stdin. Any failure aborts the WHOLE import (the caller exits 2):
// silently importing half a document would misrepresent coverage.
func loadImports(paths []string) ([]evidence.Evidence, []reporters.ImportedTool, error) {
	var evid []evidence.Evidence
	// Consolidate ACROSS files by normalized tool identity. Normalize already
	// folds runs within one document; attaching the same tool twice must not
	// reintroduce the duplicate-block ambiguity a per-tool corroborated count
	// cannot resolve.
	byTool := map[string]*reporters.ImportedTool{}
	var order []string
	for _, p := range paths {
		var data []byte
		var err error
		if p == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(p)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading SARIF import %s: %w", p, err)
		}
		doc, err := sarifimport.Parse(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		evs, stats, err := sarifimport.Normalize(doc)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		evid = append(evid, evs...)
		for _, t := range stats.Tools {
			cur, seen := byTool[t.Tool]
			if !seen {
				cur = &reporters.ImportedTool{Tool: t.Tool, Version: t.Version}
				byTool[t.Tool] = cur
				order = append(order, t.Tool)
			} else if cur.Version != t.Version {
				// Same tool, different versions across files — the tool name
				// carries the provenance, so drop the ambiguous version.
				cur.Version = ""
			}
			cur.Results += t.Results
			cur.Suppressed += t.Suppressed
			cur.NoLocation += t.NoLocation
		}
	}
	tools := make([]reporters.ImportedTool, 0, len(order))
	for _, id := range order {
		tools = append(tools, *byTool[id])
	}
	return evid, tools, nil
}

// decisionOptions projects the scan config onto the decision layer's policy.
//
// It exists as a named seam rather than an inline struct literal at the call
// site so the config→decision wiring is a testable unit. A mutation audit
// showed an inline literal could be rewritten to a constant without any
// engine-package test noticing: every test built decision.Options itself, so
// nothing observed the two being connected.
func (o *Orchestrator) decisionOptions() decision.Options {
	return decision.Options{
		DeescalateTests:     o.cfg.DeescalateTests,
		EnforceConfidence:   o.cfg.EnforceConfidence,
		BlockOnInapplicable: o.cfg.BlockOnInapplicable,
	}
}

// recordScanMetric emits one structural MetricEvent for the completed scan.
// It is a no-op when metrics are disabled (NoopCollector) or the collector
// is nil (direct test construction). PRIVACY: only counts and timings are
// recorded — never paths, hosts, or finding content. Recording failures are
// logged at DEBUG and never affect the scan result.
func (o *Orchestrator) recordScanMetric(dur time.Duration, findingCount int) {
	if o.metrics == nil {
		return
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	ev := metrics.MetricEvent{
		Version:      o.version,
		Phase:        "scan",
		DurationMs:   dur.Milliseconds(),
		FindingCount: findingCount,
		MemoryMB:     metrics.MemoryMB(ms.HeapAlloc),
		Timestamp:    time.Now().UTC(),
	}
	if err := o.metrics.Record(ev); err != nil {
		slog.Debug("metrics record failed", "error", err)
	}
	if err := o.metrics.Flush(); err != nil {
		slog.Debug("metrics flush failed", "error", err)
	}
}

// renderReport writes the scan report to the configured output.
func (o *Orchestrator) renderReport(findings []models.Finding, meta reporters.ScanMetadata) error {
	var w io.Writer = os.Stdout
	if o.cfg.OutputPath != "" {
		f, err := os.Create(o.cfg.OutputPath)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", o.cfg.OutputPath, err)
		}
		defer f.Close()
		w = f
	}

	switch o.cfg.Format {
	case "html":
		return reporters.RenderHTMLOpts(w, findings, meta, reporters.HTMLOptions{Lang: o.cfg.Lang})
	case "sarif":
		return reporters.RenderSARIF(w, findings, meta)
	case "pdf":
		return reporters.RenderPDF(w, findings, meta, reporters.PDFOptions{})
	case "json", "":
		return reporters.RenderJSON(w, findings, meta)
	default:
		return fmt.Errorf("unsupported format %q — use json, html, sarif, or pdf", o.cfg.Format)
	}
}

// pluginOutcome is what runPlugins observed, for the `plugins` entry.
type pluginOutcome struct {
	Discovered  int
	Failed      []string
	DiscoverErr error
}

// runPlugins discovers plugins under the configured roots and runs
// every plugin whose Mode is compatible with the current scan
// (blackbox plugins only run when a target URL is set; whitebox
// plugins only run when --code or --spec is set; hybrid plugins
// run whenever either condition holds). Plugin failures are logged
// at WARN and the scan continues — a broken plugin must not
// interrupt the embedded engines. The returned pluginOutcome feeds
// recordPlugins, which records the single aggregate `plugins` entry.
func (o *Orchestrator) runPlugins(ctx context.Context) ([]evidence.Evidence, pluginOutcome) {
	var outcome pluginOutcome
	cwd, _ := os.Getwd()
	// Repo-local plugins (<cwd>/.fendix/plugins) are opt-in (F-H2): the
	// scanned repo is attacker-controlled in CI, so a `.fendix/plugins/`
	// from a hostile PR must not auto-execute. The user-global root is
	// always searched.
	roots := plugin.DefaultRoots(cwd, o.cfg.AllowRepoLocalPlugins)
	plugins, err := plugin.Discover(roots)
	if err != nil {
		slog.Warn("plugin discovery failed", "error", err)
		outcome.DiscoverErr = err
		return nil, outcome
	}
	outcome.Discovered = len(plugins)
	if len(plugins) == 0 {
		return nil, outcome
	}

	hasBlackboxTarget := o.cfg.URL != ""
	hasWhiteboxTarget := o.cfg.CodePath != "" || o.cfg.SpecPath != ""

	var out []models.Finding
	for _, p := range plugins {
		switch p.Mode {
		case plugin.ModeBlackbox:
			if !hasBlackboxTarget {
				slog.Debug("plugin skipped (no blackbox target)", "plugin", p.Name)
				continue
			}
		case plugin.ModeWhitebox:
			if !hasWhiteboxTarget {
				slog.Debug("plugin skipped (no whitebox target)", "plugin", p.Name)
				continue
			}
		case plugin.ModeHybrid:
			if !hasBlackboxTarget && !hasWhiteboxTarget {
				slog.Debug("plugin skipped (no target)", "plugin", p.Name)
				continue
			}
		}

		// Resolve filesystem paths to absolutes before sending to the
		// plugin. The plugin runs with cwd=plugin-dir, so a relative
		// "./repo" from the scan caller's cwd would resolve under
		// the plugin directory and find nothing.
		req := plugin.ScanRequest{
			Mode:       p.Mode,
			URL:        o.cfg.URL,
			Spec:       absPathOrEmpty(o.cfg.SpecPath),
			CodePath:   absPathOrEmpty(o.cfg.CodePath),
			Categories: p.Categories,
			Verbose:    o.cfg.Verbose,
		}
		if o.cfg.Auth != nil {
			req.Auth = o.cfg.Auth.Value
			req.AuthType = string(o.cfg.Auth.Type)
		}

		slog.Info("running plugin", "plugin", p.Name, "version", p.Version, "mode", p.Mode)
		findings, err := p.Run(ctx, req)
		if err != nil {
			slog.Warn("plugin failed (continuing)", "plugin", p.Name, "error", err)
			// A plugin that exited non-zero may still have emitted findings
			// before the failure; preserve them.
			outcome.Failed = append(outcome.Failed, p.Name)
		}
		slog.Info("plugin complete", "plugin", p.Name, "findings", len(findings))
		out = append(out, findings...)
	}
	// External plugins emit Finding-shaped protocol JSON; adapt to Evidence
	// at this ingestion boundary (v0.22). No native provenance to add — the
	// wire format carries only Finding fields.
	return evidence.FromFindings(out), outcome
}

// recordPlugins records the aggregate plugins entry (spec §4.4): plugins
// are one entry regardless of how many individual plugins ran, so a
// consumer sees "plugins failed" rather than N scanner-shaped rows for one
// out-of-tree extension point.
func recordPlugins(status *scannerStatusList, cfg *models.ScanConfig, outcome pluginOutcome) {
	switch {
	case cfg.NoPlugins:
		status.skip(AnalyzerPlugins, reporters.ReasonDisabledByFlag, "--no-plugins")
	case outcome.DiscoverErr != nil:
		status.fail(AnalyzerPlugins, reporters.ReasonExecutionError, outcome.DiscoverErr)
	case outcome.Discovered == 0:
		status.skip(AnalyzerPlugins, reporters.ReasonNotApplicable, "no plugins configured")
	case len(outcome.Failed) > 0:
		status.failDetail(AnalyzerPlugins, reporters.ReasonExecutionError, "plugin(s) failed: "+strings.Join(outcome.Failed, ", "))
	default:
		status.ok(AnalyzerPlugins)
	}
}

// validateCodePath reports why --code cannot be scanned: missing, not a
// directory, or unreadable. nil means every code analyzer may walk it.
func (o *Orchestrator) validateCodePath() error {
	info, err := os.Stat(o.cfg.CodePath)
	if err != nil {
		return fmt.Errorf("code path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("code path %q is not a directory", o.cfg.CodePath)
	}
	if _, err := os.ReadDir(o.cfg.CodePath); err != nil {
		return fmt.Errorf("code path: %w", err)
	}
	return nil
}

// checkPhaseOutcome is what the black-box check pass observably did: how
// many active probes were sent, how many got no HTTP response at all, how
// many requests the --max-requests budget refused, and whether the
// --max-duration deadline cut the pass short.
type checkPhaseOutcome struct {
	Attempted  int
	NoResponse int
	Rejected   int64
	Deadline   bool
}

// summarizeCheckPhase derives the outcome from the probe audit log (every
// active check records each probe it sends; Status 0 means no HTTP response
// came back), the budget counters, and the context.
func summarizeCheckPhase(ctx context.Context, records []scanner.ProbeRecord, sent, rejected int64) checkPhaseOutcome {
	out := checkPhaseOutcome{Attempted: len(records), Rejected: rejected, Deadline: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	for _, r := range records {
		if r.Status == 0 {
			out.NoResponse++
		}
	}
	_ = sent // reported in the budget summary line; not a coverage signal on its own
	return out
}

// recordBlackbox records dast, spec and active-probes (spec §4.4) once the
// check pass has finished. `ok` means the pass ran to completion: nothing
// cut it short and, for probes, at least one probe got an HTTP response.
func recordBlackbox(status *scannerStatusList, cfg *models.ScanConfig, endpoints int, discoveryErr, specErr error, phase checkPhaseOutcome) {
	switch {
	case cfg.URL == "":
		status.skip(AnalyzerDAST, reporters.ReasonNotApplicable, "no --url")
	case discoveryErr != nil:
		status.fail(AnalyzerDAST, classifyErr(discoveryErr), discoveryErr)
	case endpoints == 0:
		status.failDetail(AnalyzerDAST, reporters.ReasonNoEndpoints, "URL configured, discovery found zero endpoints")
	case phase.Deadline:
		status.failDetail(AnalyzerDAST, reporters.ReasonTimeout, "--max-duration elapsed before the check pass completed")
	case phase.Rejected > 0:
		status.failDetail(AnalyzerDAST, reporters.ReasonExecutionError, fmt.Sprintf("--max-requests exhausted: %d requests refused before the check pass completed", phase.Rejected))
	default:
		status.ok(AnalyzerDAST)
	}
	switch {
	case cfg.SpecPath == "":
		status.skip(AnalyzerSpec, reporters.ReasonNotApplicable, "no --spec")
	case specErr != nil:
		status.fail(AnalyzerSpec, reporters.ReasonInputError, specErr)
	default:
		status.ok(AnalyzerSpec)
	}
	switch {
	case !cfg.EnableActive:
		status.skip(AnalyzerActiveProbes, reporters.ReasonDisabledByFlag, "--enable-active not set")
	case endpoints == 0:
		status.skip(AnalyzerActiveProbes, reporters.ReasonNotApplicable, "no endpoints to probe")
	case phase.Deadline:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonTimeout, "--max-duration elapsed before the probe pass completed")
	case phase.Rejected > 0:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonExecutionError, fmt.Sprintf("--max-requests exhausted: %d requests refused before the probe pass completed", phase.Rejected))
	case phase.Attempted == 0:
		status.skip(AnalyzerActiveProbes, reporters.ReasonNotApplicable, "no probe-eligible parameters on the discovered endpoints")
	case phase.NoResponse == phase.Attempted:
		status.failDetail(AnalyzerActiveProbes, reporters.ReasonNetworkError, fmt.Sprintf("%d probe requests sent, none received an HTTP response", phase.Attempted))
	case phase.NoResponse > 0:
		status.okDetail(AnalyzerActiveProbes, fmt.Sprintf("%d of %d probe requests received no HTTP response", phase.NoResponse, phase.Attempted))
	default:
		status.ok(AnalyzerActiveProbes)
	}
}

// absPathOrEmpty resolves p to an absolute path. Returns "" for an
// empty input (so unset flags don't become spurious paths). Failures
// fall back to the original value rather than dropping the field —
// the plugin can still run, even if relative-path resolution is
// imperfect.
func absPathOrEmpty(p string) string {
	if p == "" {
		return ""
	}
	// URLs must not be passed through filepath.Abs — it collapses the
	// double-slash in "https://" to a single slash and prepends cwd.
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// dbPathForLog names the offline snapshot path a skip detail refers to.
func dbPathForLog(cfg *models.ScanConfig) string {
	if cfg.OfflineDBPath != "" {
		return cfg.OfflineDBPath
	}
	return offline.DefaultDBPath()
}

// runWhiteboxScan spawns the Python engine and collects whitebox findings.
//
// "secrets" and "semgrep" are no longer in the default check set as of
// TASK-115 / TASK-116 — the native Go scanners at internal/scanner/secrets/
// and internal/scanner/semgrep/ run in-process before this call. Users can
// still pass --checks secrets,semgrep to opt the Python paths back in
// (matching SEC-* IDs mean dedup collapses any overlap), but they aren't
// on by default. The Python files stay in-tree for one release window in
// case of rollback; TASK-118 deletes them.
func (o *Orchestrator) runWhiteboxScan(ctx context.Context) []evidence.Evidence {
	checks := []string{"auth", "injection", "deps"}
	if len(o.cfg.Checks) > 0 {
		checks = o.cfg.Checks
	}

	// Resolve code_path + spec to absolute paths before handing to the
	// Python subprocess. The spawner sets cmd.Dir = engineDir (the
	// python/ tree), so a relative path from the caller's cwd would
	// resolve under engineDir instead — the same family of bug as
	// the spawner's enginePath fix (TASK-134). Surfaces as the
	// Python engine reporting 0 findings on a real codebase because
	// it never finds the source files.
	req := ScanRequest{
		Mode:     "whitebox",
		Spec:     absPathOrEmpty(o.cfg.SpecPath),
		CodePath: absPathOrEmpty(o.cfg.CodePath),
		Checks:   checks,
		Verbose:  o.cfg.Verbose,
	}

	result := o.spawner.Run(ctx, req)
	if result.Err != nil {
		slog.Error("python engine failed — ensure Python 3 is installed and python/requirements.txt dependencies are available", "error", result.Err)
		// Return whatever findings we collected before the error
		return evidence.FromFindings(result.Findings)
	}

	slog.Info("whitebox scan complete", "findings", len(result.Findings))
	return evidence.FromFindings(result.Findings)
}

// stampDecisions scores every FINAL finding and stamps the verdict (status,
// confidence score, band, reason breakdown) onto it in place, returning the
// decisions so the caller can derive the exit code from the same objects.
//
// The scored Evidence is the finding projection with its internal provenance
// re-attached from prov. That is the whole point of the index: confidence.Score
// reads Payload/Response/ResponseContext/Lineage, none of which survive
// Evidence→Finding, so scoring the bare projection left the payload-validated
// bonus, the B4 HTTP-response-context penalty and the lineage reason line
// permanently dead. Restoring them here fires the rules without adding a
// single field to the frozen public Finding shape.
//
// The same Restore call is what makes the B3 test-fixture de-escalation
// reachable: decision.DecideWithOptions reads Evidence.InTest, which the index
// carries (and merges conservatively across a dedup group) because
// models.Finding has no field for it either.
//
// A finding whose identity is not in the index simply scores off the projected
// fields (the pre-fix behaviour) — a miss degrades, it never invents evidence.
func stampDecisions(findings []models.Finding, prov evidence.ProvenanceIndex, failOn string, opts decision.Options) []decision.Decision {
	if len(findings) == 0 {
		return nil
	}
	decisions := decision.DecideAllWithOptions(prov.Restore(evidence.FromFindings(findings)), failOn, opts)
	for i := range decisions {
		d := decisions[i]
		findings[i].Status = string(d.Status)
		findings[i].ConfidenceScore = d.Score.Value
		findings[i].ConfidenceBand = string(d.Score.Band)
		findings[i].ConfidenceReasons = d.Score.Reasons
		// The same breakdown in machine-readable form. Stamped from the SAME
		// Result, never re-derived by parsing the strings — parsing the
		// presentation form is exactly the fragility the structured one exists
		// to remove.
		findings[i].ConfidenceBreakdown = d.Score.Details
		// The decision justification. Stamped from the Decision the gate
		// actually produced — never re-derived — so the exported explanation
		// cannot disagree with the verdict it explains.
		findings[i].DecisionReason = d.Reason
		findings[i].DecisionPolicy = string(d.Policy)
		findings[i].PolicyOverride = d.PolicyOverride
		findings[i].IndependentSignals = d.Corroboration.Independent
		findings[i].SelfEvidentSignals = d.Corroboration.SelfEvident
		// d.Evidence is post-Restore, so this is the merged group's declared
		// expectation, not whichever duplicate became the primary.
		findings[i].AuthExpectation = d.Evidence.AuthExpectation
		findings[i].Applicability = evidence.ApplicabilityOf(d.Evidence)
		// d.Evidence is post-Restore, so these carry the PROOF-UNION value
		// over the dedup group — not whichever duplicate became the primary.
		// See the field docs on models.Finding for why this must be stamped
		// here rather than projected by evidence.ToFinding.
		findings[i].CrossToolCorroborated = d.Evidence.CrossToolCorroborated
		findings[i].CorroboratingTools = d.Evidence.CorroboratingTools
	}
	return decisions
}

// escalateNonCorrelatedReachable bumps severity by one level on findings
// where the engine proved a reachable taint chain (Finding.Reachable=true)
// but no blackbox match was correlated. The correlator already bumps the
// correlated-reachable case in mergeFindings; this catches the pure-
// whitebox slice that misses correlation (no live HTTP target, or no
// matching blackbox endpoint).
//
// TASK-125 / docs/example_plan.md §3.5: reachable adds a 1.5× multiplier
// which on the discrete severity scale lands as ~one level up. Saturates
// at CRITICAL. Findings with Reachable=false are unchanged.
//
// Confidence cap (enforceConsistency, step 5.6) runs after this, so a
// MEDIUM-confidence finding escalated to CRITICAL gets capped back to
// HIGH — the reachable bump amplifies what the confidence allows; it
// can't override the cap.
func escalateNonCorrelatedReachable(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}
	escalated := 0
	for i, f := range findings {
		if !f.Reachable {
			continue
		}
		if f.Source == models.SourceCorrelated {
			// Correlator already applied this bump in mergeFindings.
			// Re-applying here would double-bump and exceed the cap.
			continue
		}
		bumped := escalateSeverity(f.Severity)
		if bumped != f.Severity {
			slog.Debug("reachable severity escalation (non-correlated)",
				"id", f.ID, "title", f.Title,
				"original_severity", f.Severity, "new_severity", bumped)
			findings[i].Severity = bumped
			escalated++
		}
	}
	if escalated > 0 {
		slog.Info("reachable findings escalated", "count", escalated)
	}
	return findings
}

// enforceConsistency walks every finding through models.EnforceSeverityConsistency
// and logs a single aggregated WARN summarising any downgrades. Cap rules are
// owned by the models package; the orchestrator only orchestrates.
func enforceConsistency(findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}
	downgraded := 0
	for i, f := range findings {
		out, changed := models.EnforceSeverityConsistency(f)
		if changed {
			downgraded++
			slog.Debug("severity downgraded for confidence consistency",
				"id", f.ID,
				"title", f.Title,
				"confidence", f.Confidence,
				"original_severity", f.Severity,
				"new_severity", out.Severity,
			)
		}
		findings[i] = out
	}
	if downgraded > 0 {
		slog.Warn("severity↔confidence consistency: downgraded findings", "count", downgraded)
	}
	return findings
}

// hasWhitebox returns true if any finding has source=whitebox.
func hasWhitebox(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Source == models.SourceWhitebox {
			return true
		}
	}
	return false
}

// hasBlackbox returns true if any finding has source=blackbox.
func hasBlackbox(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Source == models.SourceBlackbox {
			return true
		}
	}
	return false
}
