package models

import "time"

// AuthContext holds authentication credentials for scan requests.
// Credentials are masked as [REDACTED] in all report output.
type AuthContext struct {
	Type   string // bearer | apikey | basic | cookie
	Value  string
	Header string // default: Authorization
}

// ScanConfig holds all configuration for a scan run.
// It is populated from CLI flags and passed to the orchestrator.
type ScanConfig struct {
	URL      string
	SpecPath string
	CodePath string
	// ImportPaths lists SARIF 2.1.0 files from OTHER scanners to normalize
	// and merge into the evidence stream (`fendix scan --import`, repeatable)
	// or to ingest standalone (`fendix import`, via Orchestrator.RunImport).
	// "-" means stdin. A malformed file is a hard error (exit 2) — importing
	// half a document would misrepresent coverage.
	ImportPaths  []string
	Auth         *AuthContext
	AuthUser2    *AuthContext
	EnableActive bool
	// MaxProbesPerEndpoint caps the number of active probes sent to a single
	// endpoint. Zero means "use the scanner's default" (currently 20).
	MaxProbesPerEndpoint int
	Workers              int
	Timeout              int
	DelayMs              int
	Checks               []string
	Verbose              bool
	IgnorePath           string
	BaselinePath         string
	SaveBaselinePath     string
	OutputPath           string
	Format               string
	FailOn               string
	// WordlistPath overrides the built-in CommonPaths brute-force list.
	// Plain text, one path per line; lines starting with `#` and blank lines
	// are ignored; a leading `/` is added if missing.
	WordlistPath string
	// CrawlDepth controls recursive HTML link following from --url.
	// 0 disables HTML crawl; 1 (default) follows links from the home page.
	// Values >1 follow links from those pages too. Same-host only; visited
	// set prevents loops; --max-endpoints caps total discovery.
	CrawlDepth int
	// MaxEndpoints caps the total endpoint count after dedupe. 0 means
	// "no cap"; default is 500. Prevents runaway scans on large sites.
	MaxEndpoints int
	// MaxRequests caps the total HTTP request count across all checks for
	// the entire scan. 0 (default) means "no cap". When the cap is hit, the
	// scan soft-stops: in-flight requests finish, no new jobs are scheduled,
	// and the orchestrator emits a `budget summary` line with sent/rejected
	// counts. Enforced by an http.RoundTripper wrapper plus a worker-pool
	// ctx cancel; see internal/budget.
	MaxRequests int64
	// MaxDuration is the hard upper bound on scan wall-clock time. 0
	// (default) means "no cap". When set, the orchestrator wraps the run
	// context with `context.WithTimeout(parent, MaxDuration)`; deadline
	// expiry triggers the same soft-stop path as MaxRequests.
	MaxDuration time.Duration
	// RespectRobots controls how robots.txt Disallow directives are
	// interpreted. Default false: disallowed paths are queued as endpoint
	// hints (the security-tool default — those paths are exactly the URLs
	// operators don't want exposed). When true: disallowed paths are
	// filtered out of the discovered endpoint list, matching the
	// polite-crawler convention required for scanning third-party
	// production targets.
	RespectRobots bool
	// DebugBundlePath, when set, writes a redacted .tar.gz at scan end
	// containing the scan config (auth values masked), environment
	// versions, probe audit log, buffered DEBUG slog stream, and findings.
	// Empty disables the bundle. See internal/diagnostic.
	DebugBundlePath string
	// NoPlugins disables out-of-tree plugin discovery and execution
	// (TASK-113). When false (default), the orchestrator walks
	// ~/.fendix/plugins/ (and, only when AllowRepoLocalPlugins is set,
	// the repo-local .fendix/plugins/) after the embedded
	// blackbox/whitebox checks and feeds plugin findings through the
	// same correlation/dedup pipeline.
	NoPlugins bool
	// AllowRepoLocalPlugins opts in to discovering repo-local plugins
	// under <scan-cwd>/.fendix/plugins/ (F-H2). Default false: the
	// scanned repository is attacker-controlled in the poisoned-pipeline
	// threat model, so a `.fendix/plugins/` directory committed by a
	// malicious PR must NOT auto-execute in CI. The user-global
	// ~/.fendix/plugins/ root the operator populated by hand is always
	// trusted and searched regardless of this flag. Enable only when the
	// scanned tree is trusted (e.g. a first-party repo on a protected
	// branch), never on untrusted PRs.
	AllowRepoLocalPlugins bool
	// NoNativeDeps disables the in-process Go dep-CVE scanner
	// (TASK-119 / internal/scanner/deps/govulncheck). When false
	// (default), the orchestrator runs the native scanner against any
	// go.mod found under CodePath before spawning the Python whitebox
	// engine; native findings flow through the same dedup pipeline so
	// the transitional Python deps.py output collapses into one entry
	// per OSV. Set true to skip the native path (debugging, or when
	// the vuln DB is unreachable and the Python fallback is preferred).
	NoNativeDeps bool
	// UsePipAudit, when true, makes the Python dep-CVE pass shell out
	// to the pip-audit binary instead of using the native OSV.dev
	// /v1/query client. Falls back to OSV.dev with a stderr warning
	// if pip-audit is not on PATH (never fails-closed silently).
	// Surfaced by Sprint 01 of the enterprise-readiness plan to close
	// the audit's §15.5 trust gap (pip-audit naming vs. implementation).
	UsePipAudit bool
	// PythonEngine opts in to spawning the Python whitebox engine
	// (TASK-118). Default false — Phase 17b moved the secrets and
	// semgrep checks to native Go (TASK-115/TASK-116) and dropped the
	// embedded Python distribution from the binary, so the default
	// scan path is Python-free. Set true to re-enable the auth /
	// injection / deps Python checks; requires either a local
	// `python/` source tree or an explicit FENDIX_ENGINE env var
	// pointing at one (the binary no longer carries an embedded copy).
	PythonEngine bool

	// PythonEngineExplicit is true only when the user passed --python-engine
	// directly (not when --code auto-enabled PythonEngine). It controls how a
	// missing engine is handled: an EXPLICIT request that can't be resolved is
	// a hard exit-2 error (the user asked for the AST taint engine and we have
	// nowhere to run it); an IMPLICIT one (auto-enabled by --code) degrades to
	// a WARN + native-Go-only scan, because the user didn't opt into SAST by
	// name and shouldn't have a plugin/native-only --code scan aborted just
	// because the optional Python tree isn't present. Default false.
	PythonEngineExplicit bool

	// Lang controls the HTML reporter's language (Sprint 10). Today's
	// values: "en" (default) and "ar". Other formats (JSON, SARIF) stay
	// English because they're machine-consumed. Unknown values fall
	// back to English at render time; the CLI wrapper warns when a
	// passed --lang isn't a supported translation.
	Lang string

	// AllowPrivate disables the SSRF egress guard (internal/netguard) so the
	// scanner may connect to private/loopback/link-local addresses and the
	// cloud metadata IP. Default false: those addresses are refused at dial
	// time (anti-SSRF / anti-DNS-rebinding) and redirects into them are
	// re-blocked per hop. The scan command sets this from
	// --allow-private-targets and auto-enables it when the operator's own
	// --url target already resolves to a private/loopback IP (scanning your
	// own internal/staging/localhost target must keep working).
	AllowPrivate bool

	// Offline puts the dep-CVE scanners (govulncheck / pip / npm) into
	// air-gapped mode (F-M4/F-H4). When true the orchestrator MUST NOT
	// make any outbound call: pip/npm consult the local offline snapshot
	// at OfflineDBPath instead of osv.dev, and any scanner that cannot
	// run hermetically (govulncheck needs vuln.go.dev) is recorded as
	// SKIPPED in ScanMetadata rather than silently hitting the network.
	// See internal/offline (the snapshot is produced by `fendix db`).
	Offline bool
	// OfflineDBPath is the path to the offline-db snapshot consulted in
	// --offline mode. Empty falls back to offline.DefaultDBPath()
	// (~/.fendix/offline-db.json). Only effective with Offline=true.
	OfflineDBPath string

	// FailOnScannerError makes any recorded per-scanner failure
	// (F-L7/F-L13/F-L14) force a non-zero exit, regardless of the
	// --fail-on severity threshold. Opt-in for CI pipelines that want a
	// scanner crash (govulncheck/pip/npm/secrets/semgrep/textscan) to
	// fail the build instead of silently degrading coverage. Skipped
	// scanners (e.g. govulncheck in offline mode) do not count as
	// failures — only scanners that ran and errored.
	FailOnScannerError bool
	// FailOnCoverageGap exits 2 when metadata.coverage.configured_complete
	// is false: an analyzer this run was configured to execute was
	// unavailable or failed. Disabled, not-applicable and unsupported never
	// trip it. Off by default (coverage contract v1).
	FailOnCoverageGap bool
	// ManagedEvidencePath, when set, writes the managed-CI submission
	// document (contract managed-ci/v2) for the runner to POST. It needs
	// ManagedContextPath, and any failure to produce it fails the scan:
	// a managed run that cannot produce evidence must never look like one
	// that produced clean evidence.
	ManagedEvidencePath string
	// ManagedContextPath is the runner-supplied CI identity for that
	// document (managed-scan-context/v1 plus the submission id).
	ManagedContextPath string

	// RequiredAnalyzers names analyzers that must be delivered — recorded ok
	// or not_applicable — for the run to exit 0. Stricter than
	// FailOnCoverageGap: a disabled or unsupported required analyzer exits 2,
	// because the operator asked for it by name. Names are validated
	// against engine.Registry before the scan starts.
	RequiredAnalyzers []string

	// Diff enables diff-aware scanning: the whitebox scanners
	// (secrets/textscan/semgrep) are scoped to only the files git reports
	// as changed, and the dep-CVE scanners run only when their manifest
	// changed. This is the engine half of `fendix scan --diff[=ref]
	// --staged` — the "runs on every commit" developer-workflow feature.
	// When false (default) every scanner sees the full CodePath tree,
	// exactly as before. Diff mode can only narrow the file set, never
	// alter detection logic, so it does not move the heavy-eval F1 score.
	Diff bool
	// DiffRef is the git ref the diff is computed against (a branch, tag,
	// or commit-ish like "origin/main" or "HEAD~1"). Empty diffs against
	// HEAD. Only meaningful when Diff is true.
	DiffRef string
	// DiffStaged restricts the diff to staged changes (`git diff
	// --cached`) — the set a pre-commit hook scans. Only meaningful when
	// Diff is true.
	DiffStaged bool

	// DeescalateTests drops findings whose sink lives in test / fixture code
	// from WARN to INFO in the decision layer (v1.1 B3, fp_class
	// "test-fixture"). Evidence is preserved, never suppressed (Rule 3), and a
	// finding at or above --fail-on still BLOCKs — the gate a team explicitly
	// asked for is never silently downgraded.
	//
	// Default TRUE (the CLI flag defaults to true; a zero-valued ScanConfig
	// built directly in a test opts out). Real-world corpora showed 98-100% of
	// clean-library SAST noise lives in tests/, so demoting it is the
	// right default; teams that DO want to gate on test-code findings pass
	// --deescalate-tests=false or set scan.deescalate_tests in .fendix.yaml.
	DeescalateTests bool

	// EnforceConfidence gates the --fail-on threshold on the deterministic
	// confidence band: at or above the threshold a finding BLOCKs only when its
	// band supports the claim (HIGH always; MEDIUM with at least one
	// corroborating signal — live observation, cross-engine agreement,
	// deterministic detection in production code, a confirmed route, a
	// reachable taint path, a payload-validated probe; LOW never), and a
	// finding the correlator marked unconfirmed-by-live-scan never blocks on
	// its own. Evidence is preserved, never suppressed (Rule 3) — only
	// enforcement moves. (v1.2.2 FIX-08.)
	//
	// Default TRUE (the CLI flag defaults to true; a zero-valued ScanConfig
	// built directly in a test opts out — the same trap that left
	// DeescalateTests dead code, so a test that means to exercise the shipped
	// gate must set this explicitly). --enforce-confidence=false restores the
	// legacy severity-only mapping byte-for-byte; it does NOT also disable the
	// test-fixture rule, which is gated on DeescalateTests.
	EnforceConfidence bool

	// BlockOnInapplicable makes a dependency finding gate the build even when
	// Fendix has credible evidence its vulnerable component is unused. Default
	// false: such a finding is preserved in full and held at WARN. Set by
	// --block-on-inapplicable for teams whose policy is "no vulnerable version
	// ships, applicable or not".
	BlockOnInapplicable bool

	// Fast runs only the instant native scanners (secrets + textscan),
	// skipping semgrep (whose process startup is ~1.5s) and the dep-CVE
	// scanners (which make network calls). This is the <1s budget the
	// pre-commit hook needs: on a real monorepo a staged diff scan in fast
	// mode completes in tens of milliseconds. Detection logic is unchanged
	// — fast mode only drops the two slow scanners, so it never alters the
	// findings the remaining scanners would have produced.
	Fast bool
}
