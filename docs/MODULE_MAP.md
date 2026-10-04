# fendix-engine — Module Map

> Generated from a deep source read of the codebase. Categorizes every Go package and
> Python analyzer into coherent modules, traces the scan data flow, and documents the
> dependency graph.
>
> **Staleness note.** The bulk of this map was written against a ~22.6K-LOC / 25-package
> tree. The current tree is ~31K non-test Go LOC across 38 internal packages plus ~10K
> Python LOC. §2.1 (the v0.22–v0.24 Evidence → Confidence → Decision scoring pipeline) has
> been added; the `benchmark`, `metrics` and `e2e` clusters are still undocumented here.
> Read a section as accurate for what it covers, not as a complete inventory.

## Architecture Overview

**fendix-engine** is a hybrid API/code security scanner: a **Go core** plus a **Python
whitebox analysis layer**. It ships **two binaries**:

- **`fendix`** — the one-shot CLI scanner that crawls a target, runs DAST/SCA/SAST checks,
  correlates findings, and renders reports.
- **`fendix-app`** — a long-running HTTP server implementing the Fendix **GitHub App**:
  clones PRs, scans them in an isolated sandbox, and posts results back as PR comments +
  SARIF.

The Go side owns orchestration, black-box scanning, dependency/secret/static analysis,
reporting, and integrations. The Python side (spawned as a subprocess over an **NDJSON IPC
contract**) provides AST taint analysis and Proven-Path route binding. Everything converges
on a single shared `models.Finding` type that round-trips across the Go↔Python boundary and
into every report format.

---

## 1. Entrypoints & CLI

The user-facing command tree. `cmd/fendix/main.go` is the Cobra root that registers every
subcommand; each subcommand package implements one verb.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/cmd/fendix/main.go` | Cobra root command + CLI entry point | `cobra.Command` (root) | Init slog (TextHandler, no recursion); register stable subcommands (scan, report, import, verify, init, demo, notify, jira, db, engine, plugins, ignore, hook, benchmark, metrics, version) plus the development-only managed-CI command; map `ExitError` → CI exit codes |
| `go/cmd/fendix/db.go` | Offline CVE-snapshot management (air-gapped) | `cobra.Command` (db tree) | `db list/update/verify`: ingest OSV exports (array or `{advisories}` wrapper), SHA-256 integrity check |
| `go/cmd/fendix/engine.go` | Python whitebox-engine lifecycle | `cobra.Command` (engine tree) | `engine info` (resolve path: `--dir`→`FENDIX_ENGINE`→pinned→optional custom embed→`./python`), `engine sync` (pin to `~/.fendix/config`); official standalone releases carry no embedded tree |
| `go/cmd/fendix/jira.go` | Idempotent findings → Jira sync (CI step) | `cobra.Command` (jira) | Read findings JSON, create Bug issues above severity floor, `fendix-id:<id>` idempotency labels, strict/lenient modes |
| `go/cmd/fendix/notify.go` | Slack/Teams webhook alerts (CI step) | `cobra.Command` (notify) | Post Block Kit / Adaptive Card alerts above floor, per-finding dedup window, tolerate per-sink failures |
| `go/internal/cli/exit.go` | CI-friendly custom exit codes | `ExitError` | Let Cobra `RunE` return non-1 codes (0=resolved, 1=still-present, 2=unknown) for build scripting |
| `go/internal/hookcmd` | Git pre-commit hook management | `cobra.Command` (hook tree) | `install/uninstall/status`; install diff-aware fast staged scan; sentinel comment, honor `core.hooksPath`/worktrees, refuse to clobber non-fendix hooks |
| `go/internal/verifycmd` | Re-test a single finding by ID | `Status`, `Result` | Re-issue DAST request / re-scan SAST file / re-run dep scanner; emit still-present/resolved/unknown/not-found with CI exit-code mapping |
| `go/internal/initcmd` | Generate CI workflow + policy + ignore starters | `Options`, `File`, `ErrFileExists`, `ErrUnsupportedCI` | Auto-detect CI (github/gitlab/circleci), emit workflow + `.fendix.yaml` + `.fendix-ignore`, `--force`/`--print` |
| `go/internal/democmd` | `fendix demo`: scan OWASP Juice Shop in Docker | `Options`, `dockerCmd`, `ErrDockerMissing`/`ErrPortInUse` | Pull+run Juice Shop, poll health, run scan, render HTML, optionally open browser, clean up container |
| `go/internal/ignorecmd` | Inspect/maintain `.fendix-ignore` suppressions | `cobra.Command` (ignore tree) | `list` (expiry status), `validate` (schema/date/match errors), `prune` (drop expired, rewrite) |
| `go/internal/pluginscmd` | `fendix plugins` list/install tree | `cobra.Command`, URL allowlist regexes | List discovered plugins; install by git URL (transport allowlist blocks `file://`/`ext::`, CVE-2017-1000117), derive safe dir name, validate manifest, `0o700` root |
| `go/internal/policy` | Load/apply `.fendix.yaml` committable policy | `Policy`, `ScanSection`, `CrawlerSection`, `BudgetsSection`, `AuthSection`, `CLISet` | Parse + known-fields validate, version-gate (reject > v1), 3-level precedence (Cobra default < policy < CLI flag) via `ApplyTo` setter callbacks |

*(`policy` is the CLI-config surface; by design it has zero compile-time coupling to
`models`, feeding scan-command setters via callbacks.)*

---

## 2. Engine Orchestration

The conductor. Turns a `ScanConfig` into a rendered report by sequencing discovery, all
scanners, the Python bridge, and the post-processing pipeline.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/engine` | End-to-end scan lifecycle orchestration | `Orchestrator`, `WorkerPool`, `PythonSpawner`, `SpawnResult`, `ScanRequest`, `ScannerStatus`, `IgnoreFile`, `IgnoreRule`, `correlationKey` | Run pipeline (crawl → blackbox worker pool → native Go scanners → Python whitebox → correlate → dedup → baseline → ignore → assign IDs → render); bounded panic-contained worker pool; 4-tier black/white correlation + Proven-Path escalation; deterministic dedup; baseline diffing; `.fendix-ignore` rule application; per-scanner health status (`--fail-on-scanner-error`); diagnostic bundle hook |

The orchestrator is intentionally thin — matching/dedup/baseline/ignore logic is factored
into focused sub-files (`correlator.go`, `dedup.go`, `baseline.go`, `ignore.go`), keeping
`Run()` a high-level pipeline. It depends on nearly every other cluster: `scanner`,
`models`, `reporters`, `budget`, `logagg`, `diagnostic`, `plugin`, `offline`, `gitdiff`,
`embedded`.

---

## 2.1 Scoring Pipeline — Evidence → Confidence → Decision

The v0.22–v0.24 layers the orchestrator runs *between* correlation and reporting. Together
they are why Fendix can defend a confidence claim rather than merely print one.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/evidence` | Domain object + provenance carrier | `Evidence`, `ScoringProvenance`, `ProvenanceIndex` | `Evidence` is a SUPERSET of `models.Finding`: a "render block" that projects 1:1 onto the public Finding, plus internal-only provenance (`RuleID`, `Payload`, `Response`, `DetectedAt`, `Lineage`, `ResponseContext`, `InTest`, `DirectObservation`, `UnconfirmedByLiveScan`, `Placeholder`, `ComponentNotImported`) that is never serialized. Only `InTest` has an endpoint-derived fallback (`models.IsTestPath`); the other four are producer-set, so a dropped hop is permanent and silent. `ProvenanceIndex` captures that internal half keyed on the render-stable `(Category, Endpoint, Title)` identity **before** the projection and re-attaches it **before** scoring, so scoring rules that read internal fields are not silently dead. Merges across a dedup group with an "agree or drop" meet (`agreementOr` / `agreementOrBool`) — commutative, associative, idempotent, hence order-independent (F-L6) and conservative |
| `go/internal/confidence` | Deterministic 0–100 confidence scorer | `Result` | Fixed, documented rule deltas (base 35, cross-engine agreement +25, reachable taint +10, payload validated +10, direct observation +30, deterministic detection +30, tier bump/penalty ±5, HTTP/static context −15, placeholder credential −20, advisory component not imported −10); bands at 70/40; one plain-text reason line per rule that fired, and an explicit cap line when corroboration exceeds 100 so the reasons always reconcile with the value. **No AI in this path** (Constitution Rule 8) |
| `go/internal/decision` | BLOCK / WARN / INFO verdict | `Decision`, `Status`, `Options`, `corroborations` | `Decide` is the frozen LEGACY mapping (severity + `--fail-on` only), byte-compatible with `checkFailOn` and kept as the `--enforce-confidence=false` lock. `DecideWithOptions` is the production path: `Options.EnforceConfidence` gates BLOCK on band plus evidence (HIGH needs an independent or self-evident signal; MEDIUM needs an independent signal; LOW never; a correlator-marked `UnconfirmedByLiveScan` finding never blocks without independent support), and `Options.DeescalateTests` demotes `Evidence.InTest` findings — WARN→INFO, and an uncorroborated BLOCK→WARN. Every demotion appends a 0-delta reason line so it is explainable, and a finding that crossed `--fail-on` never sinks below WARN. `ExitCode` derives the process exit code from the same objects the report is stamped from |

Orchestrator wiring: `stampDecisions` (orchestrator.go) is the single junction — it restores
provenance onto the projected findings, decides, and stamps `status` / `confidence_score` /
`confidence_band` / `confidence_reasons` back onto each finding. It runs **before**
sanitization on purpose: redaction can rewrite `Title`, which would break the provenance
identity key.

Classification helpers are shared, not duplicated: `models.IsTestPath` (mirrors the Python
analyzer's `_is_test_path` markers) and `scanner.responseContextFor` /
`scanner.isStaticAssetPath` (one regex behind the `"4xx"` and `"static-asset"` contexts,
used by the header, CORS and rate-limit checks alike).

---

## 3. Scanning — Web / DAST

Black-box HTTP scanning: discover endpoints, then run passive + active probes against the
live target.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/scanner` | Black-box web discovery + ordered 15-check registry | `Check`, `Tier`, `Endpoint`, `Crawler`, `ProbeAuditLog`, `ProbeRecord`, `CheckContext` | **Discovery** (6 layered strategies: OpenAPI spec → robots → sitemap → JS → HTML crawl → wordlist brute-force, with dedup/cap/path-template substitution); `DefaultChecks()` registers `configleak`, `headers`, `cors`, `exposure`, `ratelimit`, `cookie-flags`, `auth`, `idor`, `injection`, `open-redirect`, `xss`, `ssrf`, `host-header`, `graphql`, `method-tamper`, classified as passive/active/auth/multiuser; uniform SSRF + budget via `guardedClient`; scan-wide probe audit log |

**Notable:** built-in Go DAST discovery and check requests go through a
`guardedClient` (netguard SSRF policy + budget counter);
`MaxIdleConnsPerHost=32` avoids port exhaustion on brute-force; and
`TargetIsPrivate` auto-allows localhost/staging targets. Python remote-spec
fetching, dependency-tool traffic, and out-of-tree plugins are separate paths
and do not inherit this client.

**FP context vs. skip (`responsecontext.go`).** The checks draw a deliberate line between
"there is no security signal here" and "the signal is real but the context lowers trust":

- **Skip** — headers skips 404/410/5xx (framework-controlled noise); rate-limit skips
  static assets, because rate limiting a CDN-served file is not an app-layer control, so
  there is no observation to preserve.
- **De-escalate** — header and CORS findings carry `ResponseContext` `"4xx"` (auth-gated
  response) or `"static-asset"`, and the confidence scorer applies a −15 penalty with a
  reason line. The header genuinely IS absent / the origin genuinely IS reflected, so the
  finding survives (Rule 3); only its confidence drops. `responseContextFor` resolves both
  from one shared classifier, with 4xx taking precedence.

---

## 4. Scanning — Dependencies / SCA

Software-composition analysis across three ecosystems. All converge on `SEC-DEPS-<slug>`
Finding IDs and OSV.dev/advisory lookup semantics for cross-ecosystem dedup parity.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/scanner/deps` | Namespace grouping the three SCA scanners | — | No coordinator file; pure namespace. Orchestrator calls each ecosystem's `Scan`/`ScanOffline` independently |
| `go/internal/scanner/deps/govulncheck` | In-process Go module CVE scanning via upstream govulncheck | `vulnMessage`, `osvRecord`, `vulnFinding`, `traceFrame` | Locate `go.mod` (`ErrNoGoMod`), shell real govulncheck `-json`, parse NDJSON, **filter to reachable vulns** (trace frames with non-empty `Function`), build HIGH/whitebox/deps findings, extract first fix version |
| `go/internal/scanner/deps/npm` | npm CVE scanning vs `package-lock.json` v2/v3 + offline | `resolvedPackage`, `lockfileV2(Package)`, `osvVuln`/`osvPackage`/`osvQueryResponse`, `pkgWithManifest` | Parse flat v2/v3 packages map (resolve `@scope/name`), query OSV `/v1/querybatch` (100/req, 4 concurrent, serial fallback), 24h cache, manifest stamping for monorepos, `ScanOffline` (zero-network snapshot); `ErrNoLockfile`/`ErrLockfileMissingButPackageJsonPresent` |
| `go/internal/scanner/deps/pip` | Python CVE scanning: requirements/poetry/Pipfile + pip-audit + offline | `pinnedPackage`, `pkgWithManifest`, `osv*` types | Single-level + recursive (maxDepth, skip-dirs) scans; parse 3 manifest formats; OSV querybatch + cache; optional `UsePipAudit` subprocess (graceful OSV fallback); manifest-relative stamping; `ScanOffline`; `ErrNoRequirements`; `SetOSVAPIBaseForTest` seam |
| `go/internal/scanner/deps/applicability` | Import-level applicability for dependency findings | `Component`, `Lang`, `packageRule` | Curated advisory→component catalog as Go literals (`byAdvisory` keyed by OSV id/alias; `byPackage` gated on the advisory's own summary matching a regex, so a rule cannot mis-scope an advisory that never names the component); ONE `filepath.WalkDir` for all tokens with a per-language compiled alternation, short-circuiting to ZERO filesystem cost when no finding maps to a component; sets `Evidence.ComponentNotImported` and appends an explanatory sentence. **De-escalation only (Rule 3)** — the finding is never dropped, and a walk that overruns `importGrepMaxFiles` fails OPEN at full confidence |
| `go/internal/scanner/deps/pip/poetrylock.go` | Hand-written TOML/JSON parsers for full transitive closures | `pinnedPackage` | `parsePoetryLock` (line-by-line `[[package]]` walk, no TOML lib), `parsePipfileLock` (JSON default+develop sections); both expose the full transitive tree (sub-dep CVEs invisible in requirements.txt) |

---

## 5. Scanning — Static / Secrets / SAST

In-binary Go static analysis (no Python needed for these): hardcoded-secret regex, native
textscan rules, and an optional semgrep shim.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/scanner/secrets` | Hardcoded-secret detection (17 general patterns + `ENV_SECRET`) | `pattern` (private), `models.Finding` | Walk codePath (skip vendor/build dirs + non-scanned exts), apply 18 detectors, 1MB cap, skip >500-char minified lines, redact credential material at CAPTURE time (`[REDACTED len=N sha256:…]`) over the union of every pattern's value spans on the line, classify fixture-shaped values onto `Evidence.Placeholder`, manual boundary validation (RE2 lacks lookarounds), diff-aware via `gitdiff.Allowlist` |
| `go/internal/scanner/textscan` | Unified regex SAST: Go + JS/TS + Java + Docker/K8s IaC | `Rule` (ID/Severity/Confidence/CWE/Pattern/NegPattern/Applies) | `AllRules`/`GoRules`(4)/`JSRules`(6)/`JavaRules`(11)/`IaCRules`(8), 29 total; line-by-line walk with `Applies()` routing; skip 1MB+/symlinks/build dirs; binary sniff (NUL byte); NegPattern exclusions; whole-file pre-passes for `IAC_DOCKER_RUNS_AS_ROOT` (any USER directive, whole-file channel) and Dockerfile stage aliases (per-LINE channel, feeding `IAC_DOCKER_LATEST_TAG` suppression + `IAC_DOCKER_FLOATING_TAG`'s digest-pin judgement); truncate evidence to 200 runes; diff-aware; `SourceTier=TierNativeGo` |
| `go/internal/scanner/semgrep` | Shim to host semgrep binary + bundled YAML rule pack | `semgrepResult`, `semgrepExtra`, `semgrepOutput` | `go:embed` 4 YAML rules → temp dir; invoke semgrep `--config --json --no-git-ignore`; map `check_id`→`SEC-*`, `fendix_severity` high-trust override else ERROR/WARNING/INFO mapping; resolve confidence/category/CWE; 120s timeout; gracefully absent (`ErrSemgrepUnavailable`); `SourceTier=TierSemgrepShim` (lowest trust until F1≥0.95 gate) |

---

## 6. Python Analysis Layer

The whitebox engine, spawned by `internal/engine.PythonSpawner` as a subprocess over the
NDJSON IPC contract. Each analyzer implements `.run(emit_fn)`.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `python/analyzers/ast_analyzer.py` | AST taint analysis for Python/JS (injection, RCE, auth-bypass, traversal) | `_PythonSecurityVisitor`, `ASTAnalyzer` | Walk the Python AST for dangerous sinks (dynamic eval/exec, shell-command execution, `shell=True`, SQLi, XSS, SSRF, path traversal, open-redirect); trace taint source→sink (≤50 hops, assignment-bomb protection); recognize sanitiser idioms; bind to routes for Proven Path v1; per-file error isolation (RecursionError/SyntaxError/OSError); JS via regex |
| `python/analyzers/route_extractor.py` | Extract HTTP routes (Django/Flask/FastAPI) for Proven-Path binding | `Route`, `RouteTable`, `_DecoratorRouteVisitor`, `_DjangoUrlpatternsVisitor` | Parse `path()/re_path()/url()` + `@app.route`/`@app.get`/`@router.post`; build function-name→Route index; best-effort, emits NO findings, failure never blocks detection; skips `include()`/CBVs in v1 |
| `python/analyzers/spec_parser.py` | OpenAPI 2.0/3.x auth/transport analysis | `SpecParser`, `_HTTPSOnlyRedirectHandler` | Load specs from file or https URL (50MB cap, F-L9), YAML/JSON, detect missing global security, HTTP/plaintext schemes (CWE-319), anonymous endpoints, HTTP Basic (CWE-522); refuse `http://` sources; emit `SEC-SPEC-PARSE` on unparseable, never propagate |
| `python/analyzers/deps.py` | Python-side dep CVE scan (PyPI/npm/Go) with hardcoded fallback | `DepsAnalyzer`, `_KnownVuln` | pip-audit/npm audit/govulncheck primary, local `_KNOWN_*_VULNS` fallback on tool absence (no longer silently swallows failures); 4MB manifest cap; govulncheck `raw_decode` loop; called-vs-vendored distinction |
| `python/analyzers/__init__.py` | Analyzer interface contract docstring | — | Documents the `.run(emit_fn)` → Finding-dict interface only |
| `python/rules` | Legacy YAML rule definitions (secrets/injection/auth) | — | Reference metadata (CWE/severity mappings); actual detection lives in `ast_analyzer.py` + Go secrets/semgrep; Python secrets/semgrep wrappers deleted in TASK-118 |

---

## 7. Reporting & Output

Single rendering cluster: one set of findings + metadata → JSON / HTML / PDF / SARIF, with
security-aware sanitization.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/reporters` | Render findings to JSON/HTML/PDF/SARIF + sanitize | `JSONReport`, `ScanMetadata`, `ScannerStatus`, `SeverityCounts`, `SourceCounts`, `SARIFLog/Run/Result`, `PDFOptions`, `HTMLOptions`, `i18n.Strings` | Format dispatch; JSON (machine, re-ingestible via `ParseJSONReport` with 2-layer SARIF-misfeed detection); HTML (interactive, i18n en/ar-RTL); PDF (pure-Go fpdf executive report, classification banner); SARIF 2.1.0 (rules deduped by category+title, Proven-Path codeFlows, `executionSuccessful=false` on scanner failure); **sanitization** (redact Bearer/Basic creds; `NeutralizeText` strips Trojan-Source bidi/zero-width/control chars from all human-facing fields before rendering); `CountSeverities`/`CountSources` |

Depends on `models`, `i18n`, and `github.com/go-pdf/fpdf` (pure-Go, no CGo). Report-format
dispatch is invoked from `cmd/fendix/main.go`'s `fendix report` subcommand.

---

## 8. GitHub App / CI Service

The second binary. A webhook daemon that authenticates as the App, clones PRs, scans
untrusted code in a sandbox, and posts results.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/cmd/fendix-app` | Webhook server binary (entry point) | `config` (App ID, secret, listen addr, API URL, max scans) | 12-factor env config; HTTP startup + graceful shutdown (SIGINT/SIGTERM); route `/webhook` + `/healthz`; wire credentials/token source/handler; two-phase drain (30s HTTP + scan-drain timeout) |
| `go/internal/ghapp` | App auth, webhook routing, PR scan orchestration, worker pool | `Handler`, `Server`, `scanPool`, `AppCredentials`, `TokenSource`, `InstallationToken`, `FendixScanner`, `Sandbox`, `ScanRequest`, `ScanResult`, `Context`, `EventRouter` | HMAC-SHA256 sig verify (reject sha1/missing); route pull_request/push/check_run; App-as-bot RS256 JWT → single-flighted installation tokens; **sandbox** (Linux userns+netns, token scrubbed from env; best-effort elsewhere); shallow SHA-targeted clone via `http.extraheader` (token never persisted); async ack + bounded pool (default 2, dedup by delivery UUID or repo+SHA); adversarially-resilient PR comments (escaped, backtick-safe, dynamic fences); gzip+base64 SARIF upload to Code Scanning; graceful shutdown |

`fendix-app` deliberately shells out to the `fendix` binary on PATH rather than importing
`internal/scanner`, so the daemon upgrades independently of the scanner's dependency graph.
The sandbox security model (defense against fork-PR malware) is the cluster's critical
innovation.

---

## 9. Integrations (Jira / Slack / Teams)

Outbound finding delivery to ticketing and chat. Both are env-configured (12-factor) and
invoked by the `jira`/`notify` CLI subcommands.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/integrations/jira` | Idempotent finding→Jira-issue sync | `Client`, `Config`, `SyncResult`, `SyncError` | Load creds from env; severity floor (`FENDIX_JIRA_MIN_SEVERITY`, default HIGH); idempotent create via JQL `fendix-id:<id>` label; REST API 3 (`POST /search/jql`); validate IDs `[A-Za-z0-9._-]+` (label-injection guard at package boundary); HTTP Basic; redact creds; `ErrEmptyConfig`/`ErrUnsafeFindingID` |
| `go/internal/integrations/notify` | Slack/Teams webhook alerting | `Notifier`, `Config`, `SinkResult` | Load webhook URLs; severity floor (default CRITICAL); in-memory dedup window (mutex-guarded, atomic check-and-claim TOCTOU-safe); POST Block Kit + Adaptive Card 1.3 independently (continue on sink failure); redact webhook secrets from errors; per-sink per-finding `SinkResult` |

Both note: persistent dedup / auto-resolution deferred pending SQLite (Sprint 14.5/15.5).

---

## 10. Plugin System

Out-of-tree extension via the same NDJSON IPC contract as the Python engine
(ADR-002).

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/plugin` | Discover/load/invoke out-of-tree plugins | `Plugin`, `Spec`, `ScanRequest`, `Mode`, `doneMessage` | Discover in `~/.fendix/plugins` (trusted) + repo-local `.fendix/plugins` (opt-in, `--allow-repo-local-plugins`); load+validate `plugin.yaml` (KnownFields=true; reject symlinks/absolute/`..` entrypoints/world-writable); spawn with redacted env allowlist; marshal `ScanRequest`→stdin, read NDJSON Findings→`doneMessage`; tag source, validate required fields, timeout (30s default, 5min cap); Unix TOCTOU pre-exec re-validation (`checkEntrypointSafe`) |
| `go/internal/pluginscmd` *(also under CLI)* | `fendix plugins` list/install CLI | `cobra.Command` tree, URL allowlist regexes | Thin `git clone` wrapper, no registry; URL transport allowlist (CVE-2017-1000117 family); safe dir-name derivation; manifest validation + cleanup on failure; `0o700` root |

Security-critical themes: symlink-attack prevention (F-H2), env-var allowlist to prevent
credential leakage to third-party code, opt-in repo-local discovery to defend against
poisoned PRs.

---

## 11. Domain Model & Policy

The shared vocabulary. `models` is the IPC contract and the type every other cluster
imports.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/models` | Core domain types shared across Go/Python | `Finding`, `Severity`, `Confidence`, `Source`, `SourceTier`, `Route`, `TaintLink`, `ScanConfig` (50+ fields), `AuthContext` | Define `Finding` with full metadata + Proven-Path proof (Route, TaintChain, Reachable, ProvenPath); dedup metadata (`AffectedEndpoints`); retain the legacy/reference `CalculateSeverity` helper (not the live scanner decision path); enforce severity/confidence consistency; auth resolution (CLI→env→profile) + `Redacted()` masking; `SourceTier` provenance enforcement |
| `go/internal/policy` *(see CLI table)* | `.fendix.yaml` committable scan config | `Policy`, `CLISet`, `ApplyTo` | Cross-listed under Entrypoints & CLI |

`models.Finding` is the IPC contract — every field must round-trip through JSON/NDJSON
between the Go black-box and Python whitebox engines.

---

## 12. Supporting / Infra

Cross-cutting utilities consumed by the scanner and orchestrator: SSRF egress guarding,
request budgeting, diff scoping, offline DB, optional legacy/custom embedded-engine
compatibility, log capping, diagnostics.

| Path | Purpose | Key Types | Key Responsibilities |
|---|---|---|---|
| `go/internal/netguard` | SSRF-filtering transport/dialer (DNS-rebinding resistant) | `Config`, `blockedError` | Block RFC1918/loopback/link-local/metadata(169.254.169.254)/ULA/multicast; validate every resolved IP **at connect time**; clone `http.Transport` with guarded DialContext; 10-hop redirect limit re-applying policy; IPv4-mapped-IPv6 normalization; `TargetIsPrivate` auto-allow; `AllowPrivate` opt-out |
| `go/internal/budget` | Global `--max-requests` / `--max-duration` enforcement | `budgetTransport`, atomic sent/rejected counters | Soft-cap request counter (count every attempt once, refuse over-cap), fire cancel-on-cap exactly once, `Stats()` for budget summary, nil-safe `WrapTransport`, compose with netguard (`WrapTransportGuarded`: budget OUTER, guard INNER DialContext); duration timeout lives in orchestrator context |
| `go/internal/gitdiff` | Changed-file resolution + path Allowlist for diff-aware scanning | `Options`, `Allowlist`, `execCommand` seam | Shell `git diff --name-only -z` (avoids go-git); scopes: full/staged/vs-ref; exclude deletions; sorted repo-relative paths; nil-safe absolute-path `Allowlist` (nil=full scan, empty=matched nothing); `ContainsBase` SCA gate (did go.mod/lockfile change?) |
| `go/internal/offline` | Air-gapped CVE snapshot format + loader | `Snapshot`, `Advisory`, `PackageRef`, `Range` | Read/Decode/Write/Verify snapshot JSON (200MiB + 5M-advisory caps, schema-version check, SHA-256 integrity, atomic temp-then-rename); OSV.dev wire-format subset; `LookupByPackage`/`LookupVulnerable` with best-effort SemVer; `DefaultDBPath` (`~/.fendix/offline-db.json`) |
| `go/internal/embedded` | Optional legacy/custom Python payload compatibility | `embed.FS EngineFS` | `HasEngine()`, `ExtractEngine(dest)` (preserve modes, strip `engine/` prefix), `EngineDir()` (`~/.fendix/engine/`); official Makefile `embed-engine` resets to a placeholder, so official standalone binaries return `HasEngine()=false` |
| `go/internal/logagg` | Cap per-check WARN volume during scans | `entry` (warned/suppressed) | Per-key cap (default 3): first N at Warn, rest at Debug; `SetCap`/`Reset`/`Warn`/`Summary`/`Stats`; goroutine-safe mutex (worker pool concurrency); sorted slog-friendly summary |
| `go/internal/diagnostic` | Redacted bug-report tarball of a single scan | `Bundle`, `redactedConfig`, `redactedAuth`, `fanoutHandler`, `lockedWriter` | Nil-receiver-safe (disabled when path empty); collect config/env/metadata/findings/probes/DEBUG slog; redact all credential surfaces (`[REDACTED]`), preserve header names + URLs; fanout slog handler tees to user + buffer; write tar.gz (README + JSONs + probes.jsonl + debug.log), atomic temp-then-rename, PAX format for reproducibility |

---

## Data Flow

A single `fendix scan` traced end-to-end:

1. **CLI invocation** — `cmd/fendix/main.go` → `scan` subcommand parses flags.
   `policy.Load`/`ApplyTo` merges `.fendix.yaml` under CLI overrides (`CLISet.Has` ensures
   explicit flags win). Result is a `models.ScanConfig`.
2. **Orchestrator entry** — `engine.NewOrchestrator(cfg, version)` → `Orchestrator.Run(ctx)`.
   It first resolves the Python engine path (fail-closed only if `--python-engine` is
   explicit but unavailable; lazy eval avoids spurious WARNs). `budget.SetMaxRequests`/
   `SetCancelFunc` arm the request cap; `logagg.Reset` clears per-scan log state; if
   `--debug-bundle`, `diagnostic.New` installs a fanout slog handler.
3. **Discovery** — `scanner.NewCrawler` + `Crawler.CrawlEndpoints` run the 6-strategy
   pipeline (spec → robots → sitemap → JS → HTML → wordlist), producing deduped
   `[]Endpoint`. Every request rides `budget.TransportGuarded` (→ `netguard` SSRF policy).
4. **Black-box checks** — the orchestrator filters the ordered 15-entry
   `DefaultChecks()` registry (`configleak` first for noise ordering) and fans
   enabled checks across endpoints as bounded `scanJob`s; workers recover
   panics and continue. Probes accumulate in `scanner.ProbeAuditLog`.
5. **Native Go scanners (sequential, post-pool)** — `deps/govulncheck`, `deps/npm`,
   `deps/pip` (SCA), `secrets`, `textscan`, and `semgrep` each run, scoped by
   `gitdiff.Allowlist` when diff-aware. Each records `ScannerStatus` (ok/skip/fail)
   independently — failures surface at the end, they don't abort. Offline mode routes the
   native pip/npm SCA through `offline.Snapshot` and skips native govulncheck.
6. **Python whitebox bridge** — when `cfg.PythonEngine` is true and a CodePath/SpecPath
   exists. The CLI auto-enables it for `--code` unless `--python-engine=false` is
   explicit. `PythonSpawner.Run` resolves the engine dir (explicit → env → pinned →
   optional custom `embedded.ExtractEngine` → `./python`), spawns the subprocess, writes a `ScanRequest`
   JSON to stdin, and streams NDJSON Findings + a DoneMessage from stdout. Inside Python,
   `route_extractor` pre-passes to build the route index, then `ast_analyzer`,
   `spec_parser`, and `deps.py` emit findings; cancellation kills the process.
   Current product defect: offline state is absent from `ScanRequest`, so the
   Python deps check may invoke networked tools even when the CLI has
   `--offline`.
7. **Plugins (optional)** — `plugin.Discover`/`Run` invoke installed plugins over the
   same NDJSON contract. An empty source is defaulted, but an explicit unknown
   source is currently retained; that can violate the closed report enum and
   source counters and is tracked as a product defect.
8. **Correlation** — `Correlate(findings)` (correlator.go) merges black-box + white-box via
   4-tier matching (route-pattern Proven-Path → exact endpoint+category → path suffix →
   fuzzy segment); escalates severity/confidence (`enforceConsistency`), and forces
   CRITICAL "Proven Path" when a route-confirmed reachable match exists.
   `models.EnforceSeverityConsistency` defends the cap.
9. **Deduplicate** — `Deduplicate(findings)` groups by (Title, Category, Severity), picks a
   deterministic primary via total order, and merges `AffectedEndpoints`/confidence/source.
10. **Baseline & ignore** — `ApplyBaselineDiff(current, baselinePath)` suppresses findings
    present in a prior scan; `ApplyIgnoreRules` (from `ParseIgnoreFile`) drops
    `.fendix-ignore` matches and expired rules. Findings are sorted deterministically and
    assigned `SEC-*` IDs.
11. **Reporting** — the orchestrator hands findings + `ScanMetadata` (carrying
    `scanner_status[]`) to `reporters`. `NeutralizeText`/`SanitizeFindings` strip
    bidi/zero-width/control chars and redact credentials, then `RenderJSON`/`RenderHTML`/
    `RenderPDF`/`RenderSARIF` emit the chosen format. SARIF marks
    `executionSuccessful=false` if any scanner failed.
12. **Output & integrations** — JSON output feeds downstream CI steps: `fendix jira`
    (`integrations/jira.SyncFindings`) and `fendix notify`
    (`integrations/notify.NotifyAll`) re-ingest the report and push to Jira/Slack/Teams.
    Finding-level `Decision` objects drive exit 1. Scanner-error, coverage-gap
    and required-analyzer policies can instead produce exit 2; Cobra carries
    the selected code through `cli.ExitError`.

**GitHub App variant**: `fendix-app` receives a webhook → `ghapp.Handler.HandlePullRequest`
verifies the signature, mints an installation token, clones the head SHA into a `Sandbox`,
and shells out to the `fendix` binary (steps 2–11 above) → renders SARIF + a PR comment,
then `UploadSARIF` + `PostPRComment`.

---

## Dependency Relationships

- **`models` is the universal root.** Nearly every Go package imports it for
  `Finding`/`Severity`/`ScanConfig`/`AuthContext`. It is the JSON/NDJSON IPC contract that
  the Python analyzers also conform to. `models` itself has no internal dependencies.
  (`policy` is the deliberate exception — it decouples via `ApplyTo` setter callbacks to
  avoid compile-time coupling to `models`.)
- **`engine` is the top of the dependency graph.** It imports every scanner (`scanner`,
  `deps/*`, `secrets`, `textscan`, `semgrep`), the post-processing it owns internally
  (correlator/dedup/baseline/ignore), plus `reporters`, `budget`, `logagg`, `diagnostic`,
  `plugin`, `offline`, `gitdiff`, and `embedded`. Nothing imports `engine` except the CLI
  commands (`engine.go`, `ignorecmd`) and indirectly `fendix-app` via subprocess.
- **Scanner clusters depend downward only.** Web/DAST (`scanner`) → `budget`, `netguard`,
  `logagg`, `models`. SCA (`deps/*`) → `offline` + `models`. Static (`secrets`, `textscan`,
  `semgrep`) → `gitdiff` + `models`. None depend on `engine` or on each other (SCA scanners
  are siblings under the `deps` namespace).
- **Infra is leaf-level.** `netguard`, `offline`, `embedded`, `logagg`, `gitdiff` have
  **zero internal dependencies**. `budget` depends only on `netguard` (for
  `WrapTransportGuarded` composition). `diagnostic` depends on `models` + `scanner` (for
  `ProbeRecord`).
- **Reporting depends on `models` + `i18n` + external `fpdf`.** Consumed by `engine` and by
  the `fendix report` / `fendix verify` paths.
- **Integrations and CLI are top-level consumers.** `integrations/jira` and
  `integrations/notify` depend only on `models`; their CLI wrappers (`jira.go`, `notify.go`)
  bridge them. `verifycmd` reaches into `models`, `scanner` (dep scanners), and `reporters`.
- **Plugin system bridges two ways.** `plugin` depends only on `models` (reuses the NDJSON
  engine contract); `pluginscmd` depends on `plugin`.
- **GitHub App wraps the engine indirectly.** `ghapp` has **no internal dependencies** in
  the graph — it shells out to the `fendix` binary on PATH rather than importing
  `internal/scanner`/`internal/engine`. `cmd/fendix-app` depends only on `ghapp`. This keeps
  the daemon's dependency graph decoupled from the scanner so binary upgrades don't require
  rebuilding `fendix-app`.
- **Python layer:** `ast_analyzer` depends on `route_extractor`; `spec_parser`, `deps.py`,
  and the analyzers are otherwise independent and connected to Go only through the
  `engine.PythonSpawner` subprocess boundary.

---

## Module Inventory

LOC tier inferred from public-API surface, responsibility count, and notable complexity
(heavy = large multi-concern package; medium = focused but substantial; light = thin
wrapper / namespace / docstring).

| Package | Category | LOC Tier |
|---|---|---|
| `go/internal/scanner` | Scanning — Web/DAST | Heavy |
| `go/internal/engine` | Engine Orchestration | Heavy |
| `go/internal/reporters` | Reporting & Output | Heavy |
| `go/internal/ghapp` | GitHub App / CI Service | Heavy |
| `go/internal/models` | Domain Model & Policy | Heavy |
| `go/internal/scanner/deps/pip` | Scanning — SCA | Medium |
| `go/internal/scanner/deps/npm` | Scanning — SCA | Medium |
| `go/internal/scanner/deps/govulncheck` | Scanning — SCA | Medium |
| `go/internal/scanner/secrets` | Scanning — Static/Secrets | Medium |
| `go/internal/scanner/textscan` | Scanning — Static/SAST | Medium |
| `go/internal/scanner/semgrep` | Scanning — Static/SAST | Medium |
| `go/internal/netguard` | Supporting/Infra | Medium |
| `go/internal/diagnostic` | Supporting/Infra | Medium |
| `go/internal/plugin` | Plugin System | Medium |
| `go/internal/offline` | Supporting/Infra | Medium |
| `go/internal/budget` | Supporting/Infra | Medium |
| `go/internal/gitdiff` | Supporting/Infra | Medium |
| `go/internal/policy` | Domain Model & Policy / CLI | Medium |
| `go/internal/integrations/jira` | Integrations | Medium |
| `go/internal/integrations/notify` | Integrations | Medium |
| `go/internal/democmd` (`run.go`) | Entrypoints & CLI | Medium |
| `go/internal/initcmd` (`init.go`) | Entrypoints & CLI | Medium |
| `go/internal/verifycmd` | Entrypoints & CLI | Medium |
| `go/internal/pluginscmd` | Entrypoints & CLI / Plugin | Medium |
| `python/analyzers/ast_analyzer.py` | Python Analysis Layer | Heavy |
| `python/analyzers/spec_parser.py` | Python Analysis Layer | Medium |
| `python/analyzers/deps.py` | Python Analysis Layer | Medium |
| `python/analyzers/route_extractor.py` | Python Analysis Layer | Medium |
| `go/internal/scanner/deps/pip/poetrylock.go` | Scanning — SCA | Light |
| `go/internal/scanner/deps` | Scanning — SCA | Light (namespace) |
| `go/internal/embedded` | Supporting/Infra | Light |
| `go/internal/logagg` | Supporting/Infra | Light |
| `go/internal/hookcmd` | Entrypoints & CLI | Light |
| `go/internal/ignorecmd` | Entrypoints & CLI | Light |
| `go/internal/cli/exit.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix/main.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix/db.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix/engine.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix/jira.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix/notify.go` | Entrypoints & CLI | Light |
| `go/cmd/fendix-app` | GitHub App / CI Service | Light |
| `python/analyzers/__init__.py` | Python Analysis Layer | Light |
| `python/rules` | Python Analysis Layer | Light |

---

## Notable / Architecturally Interesting

- **`models.Finding` is the single IPC contract** between the Go black-box and Python
  white-box engines — every field must round-trip through JSON/NDJSON, and the same contract
  is reused for third-party plugins (ADR-002).
- **`SourceTier` provenance enforcement (TASK-125)** prevents confidence escalation via
  correlated findings when the whitebox source is low-trust (semgrep regex vs. AST taint
  analyzer); semgrep findings are pinned to `TierSemgrepShim` until a rule pack clears the
  F1≥0.95 gate.
- **Proven Path v1** is the highest-fidelity proof: a route binding + traced taint chain in
  code + a live DAST hit on the matching route forces CRITICAL — synthesized by the
  orchestrator's 4-tier correlator from the Python `route_extractor` index and the live
  scanner.
- **DNS-rebinding-resistant SSRF guard** (`netguard`) validates every resolved IP at connect
  time (not lookup time), re-applies policy on each of up to 10 redirects, and explicitly
  blocks the cloud metadata IP and IPv6 ULA prefix.
- **Layered budget+SSRF composition**: the budget counter is the OUTER transport wrapper (so
  every attempt is counted exactly once, even cap-hit refusals) and the netguard guard is
  the INNER DialContext — soft-stop semantics with a clean sent-vs-rejected distinction.
- **GitHub App sandbox** is the security centerpiece: on Linux it scrubs the token from the
  environment, runs under an unprivileged user namespace, and uses an empty network
  namespace to contain fork-PR malware; PR comments are adversarially hardened (escaped,
  backtick-safe inline code, dynamically-sized fences).
- **`fendix-app` shells out to the `fendix` binary** rather than importing the scanner
  packages — decoupling daemon deployment from the scanner dependency graph so engine
  upgrades need no app rebuild.
- **Trojan-Source defense in reporting**: `NeutralizeText` strips bidi-reordering,
  zero-width, and control characters from all human-facing fields *before* html/template
  auto-escaping or fpdf rendering, across every output format.
- **Diff-aware scanning** (`gitdiff.Allowlist` + `ContainsBase` SCA gate) scopes
  native white-box analyzers to changed files and skips native dep-CVE scans
  unless a manifest basename changed. The generated hook also passes `--fast`,
  but `--code` currently auto-enables Python unless explicitly disabled, so the
  native-only latency claim requires `--python-engine=false`; the missing
  implication is tracked as a product defect.
- **Native offline mode**: native pip/npm scanners share a `ScanOffline` path
  against an `offline.Snapshot` (OSV.dev wire-format subset, SHA-256 verified
  for sneakernet), while native govulncheck is skipped. The Python deps check
  does not yet receive offline state; see the product defect in step 6.
- **Optional embedded-engine compatibility** remains for custom/legacy builds.
  Official standalone releases embed only a placeholder; Docker supplies the
  Python tree at `/opt/fendix/python/`, and source builds can resolve `./python`.
- **Hand-written `poetry.lock` TOML parser** (no external TOML library) keeps the scanner's
  footprint minimal while still exposing the full transitive dependency closure — CVEs three
  levels deep that `requirements.txt` can't see.
- **Govulncheck's call-trace filter**: the Go SCA scanner runs the real govulncheck and
  reports only vulns whose vulnerable symbols are actually called (non-empty trace
  `Function`), filtering out vendored-but-uncalled CVEs.
- **Plugin TOCTOU defense**: Unix `checkEntrypointSafe` re-validates the entrypoint (symlink
  containment, no world-writable components, ownership) immediately before exec; manifests
  use `KnownFields=true` for fail-closed typo detection.
- **Nil-receiver-safe `diagnostic.Bundle`**: disabled when path is empty so the orchestrator
  calls its methods unconditionally; a separate `logMu` avoids deadlock between
  late-goroutine slog writes and metadata writes.
