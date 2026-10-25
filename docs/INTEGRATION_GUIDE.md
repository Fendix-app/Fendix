# Fendix Integration Guide

The authoritative guide for integrating **Fendix** — an API/code security scanner — into a project through its supported public surfaces. It covers the local CLI, CI/CD, reports, SARIF, and customer-hosted runner setup. TwiScope (a Django/DRF backend) is used as the scanning target in worked examples where helpful.

Everything here is drawn from verified source reads of the Fendix engine (Go + Python), the GitHub Action, and the pre-commit hook. See the [engine contract reconciliation](../audits/engine-contract-reconciliation-2026-10-03.md) for the exhaustive CLI inventory. The hosted Fendix backend and its OpenAPI document are private service contracts used by Fendix applications; they are not supported public developer APIs.

---

## 1. Overview

Fendix has **three supported integration paths**. They share the same engine and report semantics, so teams can move from local evaluation to CI and then to a hosted workspace without changing the underlying security model.

| Path | What it is | Who runs it | Output |
|---|---|---|---|
| **Path 1 — Local CLI** | The `fendix` Go binary run by hand or in a script | A developer / a shell | JSON / HTML / SARIF / PDF report, exit code |
| **Path 2 — CI/CD gate** | The same binary (or official container) run on every push/PR | A CI runner | SARIF, job summary, artifacts, build decision |
| **Path 3 — Hosted workspace** | The Fendix product for persistent history, decisions, organization workspaces, and approved customer-hosted runners | A team through supported product setup | Dashboard history, governed decisions, private-target coverage |

### Quick decision guide

- **"I just want to scan something once."** → Path 1. Run the local CLI.
- **"I want every PR gated and findings in the GitHub Security tab."** → Path 2. Use the Fendix Action (§3.1); the reference workflow (§3.2) runs the official container directly.
- **"I want persistent history, organization workspaces, and governed release decisions."** → Use the hosted workspace and its documented product integrations.
- **"My target is inside a private network / behind a VPN."** → Use the Enterprise customer-hosted runner through Fendix onboarding. It executes inside your network and connects outward to the hosted workspace.

### The one safety rule that spans all levels

A white-box `--code` scan over a **working tree** reads gitignored files too.
Secret values are redacted at capture time, but findings still reveal that a
credential-shaped value exists, along with its safe identifier and file
location. Review a working-tree report before sharing it. Prefer a fresh CI
checkout containing only the files you intend to scan, and review any
out-of-tree plugin because it is executable code with its own output behavior.
See §5.

---

## 2. Level 1 — Local CLI

### 2.1 Install

```bash
# Install script (served from the official Homebrew compatibility host)
curl -fsSL https://get.fendix.dev/install.sh | sh

# Pin the current stable version
curl -fsSL https://get.fendix.dev/install.sh | FENDIX_VERSION=v3.7.0 sh

# Verify
fendix version          # → fendix version <Version> (<GOOS>/<GOARCH>)
```

Or run the published Docker image (bundles Python + all static-analysis deps, so hybrid mode works out of the box):

```bash
docker run --rm fendixapp/fendix:3.7.0 scan --url https://example.com
```

> **Note:** `get.fendix.dev` is served from the official `Fendix-app/homebrew-fendix` repository. Its root page redirects clients to the canonical documentation, while `/install.sh` remains the stable installer endpoint.

### 2.2 The subcommands

Root command is `fendix` (cobra). It prints its own errors (`SilenceUsage`/`SilenceErrors`). The subcommands that matter for integration:

| Subcommand | Purpose |
|---|---|
| `fendix scan` | Run a scan (black-box / white-box / hybrid). The workhorse. |
| `fendix report` | Re-render a saved JSON report to HTML/SARIF/PDF **without re-scanning**. |
| `fendix init` | Scaffold a CI workflow + `.fendix.yaml` policy + `.fendix-ignore`. |
| `fendix hook` | Install/uninstall/status the git pre-commit hook. |
| `fendix db` | Manage the native dependency-advisory snapshot. |
| `fendix verify <id>` | Re-run a single finding from a saved baseline. |
| `fendix engine` | Manage the Python whitebox (taint) engine location. |
| `fendix plugins` / `fendix ignore` / `fendix version` | Plugin discovery, ignore-file management, version print. |

#### `fendix scan`

At least one of `--url` / `--spec` / `--code` is required. The **mode is derived** from which you pass:

- `--url` only → `blackbox` (runtime HTTP probes against a live target)
- `--code` and/or `--spec` only → `whitebox` (static analysis of a source tree)
- `--url` + (`--code` or `--spec`) → `hybrid`

```bash
# Black-box DAST against a live API
fendix scan --url https://api.example.com --format json --output findings.json

# White-box SAST + SCA over a source tree
fendix scan --code . --format json --output findings.json

# Hybrid — correlate runtime + static
fendix scan --url https://api.example.com --code . --spec openapi.yaml -o findings.json

# Gate the run: exit 1 if any HIGH+ finding
fendix scan --code . --fail-on HIGH

# Authenticated DAST + IDOR (two users)
fendix scan --url https://api.example.com \
  --auth "Bearer token-user1" \
  --auth-user2 "Bearer token-user2"

# Active injection probes (SQLi/cmd/CRLF) — ONLY on targets you control; prints a legal disclaimer
fendix scan --url https://staging.example.com --enable-active
```

**Precedence for flags:** cobra default → `.fendix.yaml` policy → explicit CLI flag (CLI always wins). The policy file is applied only to fields you did **not** pass explicitly. `--config` resolution: an explicit path wins; otherwise `.fendix.yaml` in the cwd is auto-picked if present. An explicit `--config` pointing at a missing file is a hard error; an implicitly-detected missing `.fendix.yaml` is not.

#### `fendix report` — re-render without re-scanning

```bash
# JSON report → polished HTML (note: report defaults to html, scan defaults to json)
fendix report --input findings.json --format html  --output report.html

# JSON report → SARIF (for code-scanning upload)
fendix report --input findings.json --format sarif --output results.sarif

# JSON report → PDF with a classification banner on every page
fendix report --input findings.json --format pdf --output report.pdf --classification "CONFIDENTIAL"

# Arabic (RTL) HTML report
fendix report --input findings.json --format html --lang ar --output report-ar.html
```

`--input` is required. Input is validated by the JSON parser, which **rejects SARIF files and non-Fendix JSON** (it requires `metadata.version` and/or `metadata.mode`).

#### `fendix init` — scaffold CI + policy

```bash
fendix init                 # auto-detect CI from .github/ / .gitlab-ci.yml / .circleci/ (default github)
fendix init --ci gitlab
fendix init --print         # print generated content instead of writing
fendix init --force         # overwrite existing files
```

Files written:

- `github` → `.github/workflows/fendix.yml` + `.fendix.yaml` + `.fendix-ignore`
- `gitlab` → `.gitlab-ci.fendix.yml` + `NEXT-STEPS-fendix.md` + policy/ignore
- `circleci` → `.circleci/fendix-config.yml` + `NEXT-STEPS-fendix.md` + policy/ignore

Each generated CI file pins `FENDIX_VERSION` to the release of the `fendix`
binary that wrote it and installs that release with the official installer,
`scripts/install.sh` fetched at `FENDIX_INSTALLER_COMMIT`, the commit that
release was built from (a tag could be moved to serve another script; a
commit cannot). The installer verifies the checksum; every generated file
also installs cosign (the CircleCI one downloads a cosign release checked
against pinned SHA-256 values, since `cimg/base` has none) and runs the
installer with `FENDIX_REQUIRE_SIGNATURE=1`, so a missing cosign or a missing
or invalid signature fails the job. Set the optional `FENDIX_SHA256`
to bind a job to one exact binary. A build that is not a release, or that
does not know its commit (a dirty tree, a local Docker build), writes a
placeholder the install step rejects, so set real values before committing.

**Known product defect:** the generated workflows install the standalone
release binary, which carries no Python analyzer tree, and do not install
Semgrep, so their scans record both analyzers as unavailable and report
coverage as incomplete. The GitLab file also declares SARIF under
`artifacts:reports:sast`, which expects GitLab's own SAST JSON schema. For full
analyzer coverage use the checked-in pinned-container reference workflow or an
equivalent container job. The generated policy and ignore starters remain
independently usable.

#### `fendix hook` — git pre-commit gate

```bash
fendix hook install                  # default --fail-on HIGH
fendix hook install --fail-on MEDIUM
fendix hook status                   # installed / not installed / present-but-not-fendix-managed
fendix hook uninstall
```

The installed hook runs `fendix scan --code . --staged --fast --fail-on <severity>`. `--fast` skips semgrep and the native dependency passes, but it does not currently suppress the Python engine auto-enabled by `--code`; add `--python-engine=false` to a manual invocation when native-only latency is required. The generated hook does not yet add that flag, so its sub-second claim is an unresolved product defect. A finding at/above `--fail-on` aborts the commit only when it reaches `BLOCK`; bypass once with `git commit --no-verify`. The hook honours `core.hooksPath` and worktrees, refuses to clobber a non-fendix hook without `--force`, and is recognized by a sentinel comment `# fendix-managed-pre-commit-hook`.

#### `fendix db` — native offline dependency-advisory snapshot

```bash
# Build a snapshot from an OSV-shaped JSON export (top-level array or {"advisories":[...]})
fendix db update --source osv-export.json          # → ~/.fendix/offline-db.json
fendix db list                                     # print snapshot metadata
fendix db verify                                   # sha256 <hash>  <path>

# Native-only hermetic scan: snapshot-backed pip/npm; govulncheck is SKIPPED.
# --no-plugins excludes third-party executable code.
fendix scan --code . --offline --python-engine=false --no-plugins
```

**Known product defect:** `--offline` is not propagated into the Python deps
check that `--code` auto-enables. With the default check set, that phase may
invoke `pip-audit`, `npm audit`, or `govulncheck`. To retain the Python AST
checks in a hermetic run, use
`--offline --checks auth,injection --no-plugins`; use the command above for a
native-only run. This is current behavior, not the intended offline contract.

#### `fendix verify <finding-id>` — re-test one finding

```bash
fendix verify SEC-014 --baseline findings.json --url https://api.example.com --json
```

Has **its own exit-code scheme**: `0` = resolved, `1` = still present (CI should fail), `2` = unknown or not found in baseline.

### 2.3 Common `fendix scan` flags

This section explains commonly integrated flags. The running binary's
`fendix scan --help` output is authoritative and exhaustive; the stable/current
inventory is recorded in
[`../audits/engine-contract-reconciliation-2026-10-03.md`](../audits/engine-contract-reconciliation-2026-10-03.md).

#### Target

| Flag | Type | Default | Description |
|---|---|---|---|
| `--url` | string | `""` | Target API base URL (black-box). |
| `--spec` | string | `""` | Path to OpenAPI/Swagger YAML/JSON spec (local path or http(s) URL). |
| `--code` | string | `""` | Path to source code directory (white-box). |

#### Scope (diff / budget / limits)

| Flag | Type | Default | Description |
|---|---|---|---|
| `--diff` | string | `""` (bare = `HEAD`) | Diff mode vs a git ref. `--diff=origin/main` = vs that ref. The native secrets, text and Semgrep scanners read only the changed files (whole files); dep-CVE scanners run only when a manifest changed; the Python engine, DAST and plugins scan the full target. Falls back to a full scan if `git diff` fails. |
| `--staged` | bool | `false` | Diff over staged changes (`git diff --cached`). Implies `--diff`. What the pre-commit hook runs. |
| `--fast` | bool | `false` | Skip semgrep and native dep-CVE scanners. It does not suppress Python auto-enabled by `--code`; add `--python-engine=false` for the native-only path. |
| `--max-endpoints` | int | `500` | Cap discovered endpoints (0 = no cap). |
| `--max-requests` | int64 | `0` | Soft-cap on total HTTP requests (0 = no cap). Armed after discovery. |
| `--max-duration` | duration | `0` | Soft-cap on wall-clock time, e.g. `5m` (0 = no cap). |
| `--max-probes-per-endpoint` | int | `20` | Max active probes/endpoint (only with `--enable-active`). |

#### Auth

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auth` | string | `""` | Auth header value, e.g. `"Bearer token123"`. |
| `--auth-type` | string | `""` (auto) | `bearer` / `apikey` / `apikey-query` / `basic` / `cookie`. |
| `--auth-header` | string | `Authorization` | Header name; in `apikey-query` mode this is the query-parameter name. Pass `api_key` explicitly for the conventional CLI value. |
| `--auth-user2` | string | `""` | Second user for IDOR checks. |
| `--profile` | string | `""` | Auth profile from `~/.fendix/profiles/<name>.yaml`. |

Credentials are masked as `[REDACTED]` in all report output.

#### Behavior

| Flag | Type | Default | Description |
|---|---|---|---|
| `--enable-active` | bool | `false` | Enable active injection probes (SQLi/cmd/header injection). Prints a legal disclaimer. |
| `--fail-on` | string | `""` | Severity floor: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. Exit 1 when a finding at or above it reaches `BLOCK`; since v2.0 the confidence/evidence policy also applies, see [3.4](#34---fail-on-gating-and-exit-codes). **Since v3.5.0:** a threshold is accepted in any case, and an invalid value (`INFO` included) is rejected before scanning with exit 2. v3.4.1 only warned and ran with no threshold, which silently disabled the gate. |
| `--enforce-confidence` | bool | `true` | **v2.0.** `BLOCK` only when the deterministic confidence band and evidence support the claim: `HIGH` needs an independent or self-evident signal, `MEDIUM` needs an independent signal, and `LOW` never blocks. `false` restores the pre-2.0 severity-only gate byte-for-byte. |
| `--deescalate-tests` | bool | `true` | Findings in test/fixture code report as `INFO` instead of `WARN`, and an **uncorroborated** one at or above `--fail-on` is held at `WARN` instead of blocking. Evidence is always preserved. Independent of `--enforce-confidence`. |
| `--fail-on-scanner-error` | bool | `false` | Exit 2 if any scanner ran and errored. Skipped scanners don't count. Checked before `--fail-on`. |
| `--ignore` | string | `""` | Path to `.fendix-ignore`. An unparseable file is a hard error (exit 2). |
| `--config` | string | `""` | Path to `.fendix.yaml` (default: auto-detect in cwd). |
| `-w, --workers` | int | `10` | Concurrent HTTP workers. |
| `--delay` | int | `100` | Milliseconds between HTTP requests. |
| `--timeout` | int | `10` | HTTP timeout (seconds). |
| `--crawl-depth` | int | `1` | HTML link crawl depth (0 disables). |
| `--baseline` | string | `""` | Previous findings JSON for diff mode (report only new). |
| `--save-baseline` | string | `""` | Save current findings to this path. |
| `--wordlist` | string | `""` | Brute-force wordlist; overrides built-in CommonPaths. |
| `--respect-robots` | bool | `false` | Treat robots.txt Disallow as a hard restriction. |
| `--allow-private-targets` | bool | `false` | Allow private/loopback/link-local + cloud-metadata IP (disables SSRF egress guard). Auto-enabled when `--url` already resolves private. |
| `-v, --verbose` | bool | `false` | Print all requests and raw findings. |
| `--debug-bundle` | string | `""` | Write a redacted diagnostic tarball at scan end. |

#### Output

| Flag | Type | Default | Description |
|---|---|---|---|
| `-o, --output` | string | `""` (stdout) | Output file path. |
| `-f, --format` | string | `json` | `json` / `html` / `sarif` / `pdf`. (Note: `report` defaults to `html`.) |
| `--lang` | string | `en` | HTML report language: `en` / `ar` (Arabic, RTL). Other formats stay English. Unsupported → WARN + English. |

#### Offline / native-deps

| Flag | Type | Default | Description |
|---|---|---|---|
| `--offline` | bool | `false` | Native scanners consult the local snapshot and native govulncheck is recorded `SKIPPED`. Known defect: the Python deps check does not receive this flag; use `--checks auth,injection` or `--python-engine=false`, plus `--no-plugins`, for hermetic execution. |
| `--offline-db` | string | `""` (falls back to `~/.fendix/offline-db.json`) | Snapshot path. Only effective with `--offline`. Cobra's registered default is empty; the `~/.fendix/offline-db.json` path is the runtime fallback when unset. |
| `--no-native-deps` | bool | `false` | Disable the in-process Go dep-CVE scanner. |
| `--use-pip-audit` | bool | `false` | Shell out to `pip-audit` instead of native OSV.dev for Python. Falls back to OSV.dev with a warning if absent. |
| `--python-engine` | bool | `false` | Spawn the Python whitebox engine. Auto-enabled implicitly when `--code` is set unless disabled. Explicit `--python-engine` makes a missing engine a fatal exit-2; the implicit `--code` path degrades to native-Go-only with a WARN. |

#### Plugins

| Flag | Type | Default | Description |
|---|---|---|---|
| `--no-plugins` | bool | `false` | Disable out-of-tree plugin discovery in `.fendix/plugins/` + `~/.fendix/plugins/`. |
| `--allow-repo-local-plugins` | bool | `false` | Run repo-local plugins under `<scan-dir>/.fendix/plugins/` (UNSAFE on untrusted PRs). |

### 2.4 What the engine actually scans

Three surfaces, each driven by a flag:

**Black-box / DAST (`--url`)** — 15 ordered checks. Passive ones are always on; auth-tiered ones need `--auth`; multiuser ones need `--auth` + `--auth-user2`; active ones need `--enable-active`.

- **Passive (always on):** `configleak` (CRITICAL — `.env/.git/.aws/.ssh/...` exposed), `headers` (HSTS/CSP/X-Frame-Options/...), `cors`, `exposure` (secrets/PII/stack traces in response bodies), `ratelimit`, `cookie-flags`.
- **Auth-tiered (needs `--auth`):** `auth` — missing-auth observations are
  CRITICAL when the specification declares authentication required, MEDIUM
  when no requirement is known, and INFO when the operation is declared
  public; confirmed malformed/expired/`alg:none` JWT acceptance is CRITICAL.
- **Multiuser (needs `--auth-user2`):** `idor` — two-user response compare, HIGH.
- **Active (`--enable-active`):** `injection` (time/error/boolean SQLi across 5 DB engines, command injection, CRLF), `xss`, `open-redirect`, `ssrf` (in-band), `host-header`, `graphql`, `method-tamper`.

**White-box / SAST + SCA (`--code`)** — run natively in Go, regardless of `--python-engine`. `--enable-active` is irrelevant (no runtime probing):

- **Secrets** — 17 general patterns + `ENV_SECRET` (AWS/GitHub/Stripe/Anthropic/OpenAI/GCP/npm keys → CRITICAL; generic keys/passwords/JWT/DB strings → HIGH).
- **textscan / IaC** — 29 rules: Go (4), JS/TS (6), Java (11), and IaC (Dockerfile/Kubernetes, 8).
- **semgrep** — shim to host `semgrep` binary (4 embedded rule packs). Gracefully absent → skipped with an install hint.
- **SCA / dependency CVEs (backed by OSV.dev):** Go (`go.mod` via govulncheck, reachable-only), npm (`package-lock.json` via OSV.dev), Python (`requirements.txt`/`poetry.lock`/`Pipfile.lock` via OSV.dev; `--use-pip-audit` to shell out).

**OpenAPI spec (`--spec`)** — always feeds endpoint discovery through the Go
crawler. Python `spec_parser` adds white-box checks for missing security,
HTTP/plaintext schemes, anonymous endpoints and HTTP Basic only when the Python
phase runs. `--code` auto-enables that phase; a spec-only invocation currently
requires explicit `--python-engine` and a resolvable engine tree.

For a remote spec, the current Go/Python fetch behavior is not uniform. Go
accepts HTTP(S) through its guarded client; when Python runs it refetches HTTPS
through `urllib` without inheriting the Go private-IP guard and rejects
plaintext HTTP. This is a product defect. Prefer a reviewed local spec file
when that network boundary matters.

**Endpoint discovery priority (black-box):** spec > robots.txt > sitemap.xml > JavaScript source > HTML link crawl > common-path brute-force.

### 2.5 The JSON report schema

`fendix scan --format json` (default) and `fendix report --format json` emit this shape (2-space indent). `findings` is **always a JSON array** — never `null`.

```json
{
  "metadata": {
    "schema_version": 2,
    "target": "https://api.example.com",
    "started_at": "2026-06-20T10:00:00Z",
    "duration": "4.521s",
    "version": "3.7.0",
    "mode": "blackbox",
    "endpoints_scanned": 42,
    "active_probes": false,
    "checks_run": ["configleak", "headers", "cors", "exposure", "ratelimit", "cookie-flags"],
    "scanner_status": [
      { "name": "dast", "state": "ok" },
      { "name": "spec", "state": "skipped", "reason": "not_applicable", "detail": "no --spec" },
      { "name": "active-probes", "state": "skipped", "reason": "disabled_by_flag", "detail": "--enable-active not set" },
      { "name": "secrets", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "textscan", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "semgrep", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "govulncheck", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "pip", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "npm", "state": "skipped", "reason": "not_applicable", "detail": "no --code" },
      { "name": "python-engine", "state": "skipped", "reason": "not_applicable", "detail": "no --code or --spec" },
      { "name": "plugins", "state": "skipped", "reason": "not_applicable", "detail": "no plugins configured" }
    ],
    "policy_version": "1.0.0",
    "coverage": {
      "contract_version": 1,
      "strict": false,
      "configured_complete": true,
      "gaps": [],
      "limitations": [],
      "required_analyzers": [],
      "required_gaps": [],
      "retried": []
    }
  },
  "summary": { "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0 },
  "sources": { "blackbox": 1, "whitebox": 0, "correlated": 0 },
  "total": 1,
  "findings": [
    {
      "id": "SEC-014",
      "title": "Missing HSTS header",
      "severity": "MEDIUM",
      "source": "blackbox",
      "category": "headers",
      "endpoint": "https://api.example.com/login",
      "affected_endpoints": [],
      "evidence": "...",
      "fix": "...",
      "references": ["CWE-319"],
      "confidence": "HIGH",
      "line": null,
      "status": "WARN",
      "confidence_score": 100,
      "confidence_band": "HIGH",
      "decision_policy": "enforced"
    }
  ]
}
```

Key facts:

- **`metadata.schema_version`** is the contract version, currently `2`, and is present on every report a current build writes. An **absent** key means the report predates the field — treat that as "pre-versioned", not as invalid. An **unrecognised** value means the report is newer than your integration: warn and keep parsing rather than failing automatically; inspect the migration note because a version bump can represent an incompatible field meaning such as the v1 → v2 fingerprint change.
- **`metadata.mode`** ∈ `blackbox` / `whitebox` / `hybrid` / `import`.
- **`scanner_status`** carries one entry per analyzer (`dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, its `python-engine/*` children when reported, `plugins`) with `state` ∈ `ok`/`skipped`/`failed` and a closed `reason` on every non-ok entry. **`metadata.coverage.configured_complete`** answers "did everything this run was configured to execute run?"; **`coverage.required_gaps`** answers "did `--require-analyzers` get what it asked for?". Only `failed` feeds `--fail-on-scanner-error` — that check itself is unchanged, but from v3.4.0 the set of analyzers that can record `failed` grew from six (`govulncheck`/`pip`/`npm`/`secrets`/`semgrep`/`textscan`) to the full registry above, so `dast`, `spec`, `active-probes`, `plugins` and the python-engine (and its checks) can now trip the flag too; `--fail-on-coverage-gap` also trips on `skipped/dependency_missing`. From v3.7.0, `semgrep` is `ok` only when Semgrep itself reports success: a fatal run (an invalid config, a rule that does not parse, the engine killed or out of memory) is `failed/execution_error` even when Semgrep printed a JSON envelope, and per-file problems (a file that does not parse, a per-file timeout) stay `ok` with their count in `detail` ([`docs/checks/semgrep.md`](checks/semgrep.md#what-ok-means-from-v370)).
- **`findings[].severity`** ∈ `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`. Severity rank used by `--fail-on`: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0. `rank(finding) >= rank(threshold)` is **necessary but not sufficient** since v2.0 — the gate then reads `findings[].confidence_band` and `findings[].status`. Read `status == "BLOCK"` (or `decisions.blocking`) to know what actually fails the build; `confidence_reasons` names the rule behind any demotion.
- **`findings[].source`** ∈ `blackbox`/`whitebox`/`correlated`/`imported`. **`confidence`** ∈ `HIGH`/`MEDIUM`/`LOW`. The legacy top-level `sources` counters omit `imported`; use `metadata.imports` for import accounting.
- **`line`** is a nullable pointer — serialized even when `null` (no omitempty).
- White-box extras: `taint_chain[]` (AST dataflow source→sink), `reachable`, `source_tier` (`native_go`/`tree_sitter_sidecar`/`semgrep_shim`), `route`, `route_confirmed`, and `proven_path` (set only when `route_confirmed` AND `reachable` — forces CRITICAL).

---

## 3. Level 2 — CI/CD gate

Goal: fail the build when a scan finds something at/above a severity threshold, and surface the findings to reviewers.

> **GitHub Actions: use the Fendix Action, `uses: Fendix-app/Fendix@v1` with an explicit `version` (§3.1).** For high-assurance or reproducible pipelines, and for v3.7.0's fail-closed required analyzers until `v1` is moved, pin it to the full commit of the validated release instead. The digest-pinned reference workflow (§3.2) is a tested alternative. Never reference `@main`; it changes without review.

The engine runs in CI as the composite GitHub Action (§3.1), or from the official container image (§3.2, §3.4).

<a id="32-the-composite-github-action"></a>
<a id="32-the-composite-github-action--do-not-use-v1"></a>

### 3.1 Recommended — the composite GitHub Action

Use the Fendix Action ([Fendix Security Scan on GitHub Marketplace](https://github.com/marketplace/actions/fendix-security-scan)) with `@v1` and an explicit `version`:

```yaml
permissions:
  contents: read
  security-events: write    # SARIF upload
  actions: read             # SARIF upload in a private or internal repository

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0      # diff mode compares against the PR base ref
      - uses: Fendix-app/Fendix@v1
        with:
          version: v3.6.2
          code: .
          fail-on: HIGH
```

`@v1` follows compatible stable releases of the v1 Action. `version` pins the Fendix release the Action installs. **`@v1` still resolves to the v3.6.2 Action code** (release commit `b9e1fad`) until `v1` is moved, so it does not have the items marked **v3.7.0** below. For those, and for high-assurance or reproducible pipelines, pin the Action to the full commit of the validated v3.7.0 release, which is immutable (or use `@v1` once it is moved):

```yaml
      - uses: Fendix-app/Fendix@90adf6a5082be0661b4156566a3a99609ed4792d # v3.7.0
        with:
          version: v3.7.0
```

Never reference `@main`; it changes without review. On a private repository without GitHub Code Security, set `upload-sarif: 'false'`: the scan and the gate still run. The v3.7.0 release commit with `version: v3.7.0` was tested end to end in a public repository on 2026-10-25 (`Fendix-app/fendix-action-e2e-public`, runs 40225358870 to 40225440001). The v3.6.2 Action, by its release commit and as literal `@v1`, passed the external-user end-to-end matrix in public and private repositories on 2026-10-16. Until then `v1` pointed to the June 2026 revision `d59a901`; a workflow pinned to that revision should move to `@v1` or to a release commit.

This section documents the Action as shipped in v3.6.2, which `@v1` resolves to until it is moved. Items marked **v3.7.0** describe the Action at the v3.7.0 release commit `90adf6a`, and `@v1` once it is moved there.

A **composite** action. Its steps, in order:

1. **Validate managed-mode inputs** (managed mode only).
2. **Install cosign** (`sigstore/cosign-installer`, pinned), for every caller.
3. **Install Fendix.** One exact release from `Fendix-app/Fendix`: `version: latest` is resolved once to an exact tag. The installer bundled with the Action revision, never fetched live, runs with the signature required, in an environment stripped of every inherited `FENDIX_*` variable. It verifies the release's checksum, then its cosign signature, and only then installs and first runs the binary, in a private temporary directory under `RUNNER_TEMP` (no `sudo`, nothing written to `/usr/local/bin`). The binary must report exactly the requested release; only then is the directory added to `PATH`. There is no checksum-only fallback.
4. **Set up Python 3.11** without changing the rest of the job's environment (`update-environment: false`).
5. **Prepare the Python engine** (below). **v3.7.0:** wheels only, and `require-analyzers` is resolved here.
6. **v3.7.0: Preflight required analyzers.** A required Semgrep runs, offline, on a bundled rule and file and must report their one match (below).
7. **Run `fendix scan`**, recording whether a report was written and the exit code. **v3.7.0:** with `--require-analyzers` set to the required list.
8. **Upload SARIF** to code scanning, only when the scan wrote one (`upload-sarif`, `format: sarif`). **v3.7.0:** only when the scan also finished (exit 0 or 1); a partial report from a failed scan would close every alert missing from it.
9. **Gate:** `0` passes, `1` is a policy `BLOCK`, `2` a scan error (**v3.7.0:** or a required analyzer not delivered). A setup failure before the scan, or any other value, fails closed with `2`. **v3.7.0:** a pass prints the clean-scan line only when coverage was complete and enforced; otherwise it is a warning, and the job summary states the requirement and the coverage.

**Python engine.** With `engine_path` empty, the Python source is fetched at the commit the release's signed build record names, and the installed binary's hash must appear in that record. From v3.6.1 its dependencies are installed only from the release's hash-locked `python/requirements.lock`, with `--require-hashes`. Releases up to v3.6.0 ship no lock, so they keep `requirements.txt` with a `pydantic<2.14` compatibility bound, and a later release without a lock is refused. A caller-managed `engine_path` must contain `engine.py` and `requirements.txt`; its `requirements.txt` is installed with the same bound (a lock inside it is not used), and matching it to the binary is the caller's responsibility. Both install into an isolated venv whose `bin/`, with `FENDIX_ENGINE`, stays available to later steps of the job. **v3.7.0:** both install wheels only (`--only-binary=:all:`), as the official image does. A package with no wheel for the runner stops preparation with exit 2, naming the package, the runner's C library and version, its architecture and the supported floor, and nothing is built from source: a Semgrep built from its source distribution has no `semgrep-core` and cannot scan.

**Required analyzers (v3.7.0).** The `require-analyzers` input says which analyzers must run for the gate to pass. They fail closed twice: before the scan, by a functional preflight, and during it, because the list is passed to the engine as `--require-analyzers`, which exits 2 unless each one is recorded `ok` or `not_applicable`.

| `require-analyzers` | Required | When it cannot run |
|---|---|---|
| `auto` (default) | `semgrep` whenever `code` is set; nothing for a URL-only scan, where the engine records Semgrep `not_applicable` | Setup fails with exit 2 and an error naming Semgrep |
| `semgrep,secrets,...` | Exactly those engine analyzer names (the registry: `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, `python-engine/auth`, `python-engine/injection`, `python-engine/deps`, `plugins`); an unknown name fails setup | Semgrep: setup fails. Every analyzer: the scan exits 2 if it is not delivered |
| `none` | Nothing: the explicit opt-out | A Semgrep with no wheel is left out with a warning; the scan records it unavailable, and the gate warns that coverage is not enforced |

- **The preflight** runs the Semgrep the scan will run, from the prepared venv, with `--metrics=off --disable-version-check`, a 90 s bound and JSON output, and requires the probe's one known match. A missing executable, a Semgrep without `semgrep-core`, a damaged install that reports nothing, a startup crash, a binary for another architecture and a hang each fail with their own message. It needs no network. Analyzers without a probe are enforced by the engine at scan time.
- **`extra-args` cannot cancel a requirement.** The Action's `--require-analyzers` comes first; a repeated `--require-analyzers` only adds names, and a flag that disables a required analyzer (such as `--fast` for `semgrep`) is a contradiction the engine exits 2 on. To use `--fast`, set `require-analyzers` to `none` or to a list without `semgrep`.
- **Managed mode** takes only `auto`: the binding's backend policy decides what is required, and the runner may not narrow it. Semgrep must still pass its preflight before evidence is submitted.

**Required analyzers, by integration.**

| Integration | Semgrep | How to require it |
|---|---|---|
| GitHub Action (v3.7.0) | Required by default for code scans (`require-analyzers: auto`) | Default; `none` opts out |
| Native CLI | Optional by default: without `semgrep` on `PATH` it is recorded `unavailable` (`dependency_missing`) and coverage incomplete, and the exit code is decided by the analyzers that ran | `--require-analyzers semgrep` (exit 2 unless delivered), or `--fail-on-coverage-gap` for any configured analyzer |
| Official image | Always present. From v3.7.0 the image build runs the same preflight and fails if Semgrep cannot scan; the release smoke also requires `semgrep` `ok` in a scan | `--require-analyzers semgrep` in the `fendix scan` command, as for the CLI |
| Managed CI (preview) | The evidence carries every analyzer's execution and the observed coverage; the backend's binding policy requires the `sast` and `sca` families. A failed member fails its family, which makes the decision `INCOMPLETE`; a Semgrep absent from the runner leaves `sast` completed by its other members | The binding's policy. The Action in managed mode still requires Semgrep's preflight |

**Requirements.**

- **Signed releases only.** Only releases published with a cosign signature can be installed. Automatic Python preparation needs a signed build record, published from v3.5.0.
- **Network.** Outbound HTTPS to GitHub (release downloads, and the API for `latest`) and to Sigstore (its TUF root and Rekor) for the signature check; the Python engine also needs `codeload.github.com` and PyPI. Without Sigstore access the install fails. Proxies work through the standard `HTTPS_PROXY` and `NO_PROXY` variables; a `~/.curlrc` is ignored.
- **Linux runners: glibc 2.34 or later for Semgrep, from v3.6.5.** The Semgrep that v3.6.5 and later lock (1.182.1) publishes Linux wheels only for glibc 2.34 or later and musl 1.2 or later, on x86_64 or aarch64. Older glibc includes Ubuntu 20.04, Debian 11, RHEL 8 and its rebuilds, and Amazon Linux 2. GitHub-hosted runners and the official image are not affected.
  - **v3.7.0 Action:** a code scan on such a runner fails at setup with exit 2, and the error names Semgrep, the runner's glibc and architecture, the floor, and the remedies. Use the official image as a container job (§3.4), or a runner with glibc 2.34 or later (Ubuntu 22.04+, Debian 12+, RHEL 9+, Amazon Linux 2023). `require-analyzers: none` scans without Semgrep, with coverage not enforced.
  - **v3.6.2 Action (`@v1` until it is moved):** with `version: v3.6.5`, pip builds Semgrep from source without `semgrep-core`. Preparation succeeds, but the scan records `semgrep` as `failed` (`execution_error`) and coverage as incomplete, and the gate is decided by the analyzers that ran. Add `extra-args: --require-analyzers semgrep` to fail the job, with exit 2, instead. `version: v3.6.4` keeps Semgrep 1.141.0 but gives up v3.6.5's fixes; the v3.6.5 Upgrading notes in [`CHANGELOG.md`](../CHANGELOG.md) list what it keeps.
- **Permissions.**

  | Repository | `permissions:` |
  |---|---|
  | Public | `contents: read`, `security-events: write` |
  | Private or internal | also `actions: read`, and GitHub Code Security enabled on the repository |
  | Any, with `upload-sarif: 'false'` | `contents: read` |

  The Action uses the job token only for the SARIF upload. Pull requests from forks get a read-only token and no secrets, so the upload cannot succeed there and a secret-based DAST URL is empty.
- **Diff mode** (`diff: auto` on `pull_request`). The native secrets, text and Semgrep scanners read only the changed files, whole files, so existing issues in them are reported. Dependency checks run when a manifest changed and then report the manifest's full set. The Python engine and DAST always scan the full target. If the diff cannot be computed, or a changed file cannot be placed under `code`, the scan falls back to a full scan. Use a baseline to report only new findings. With `code` set to a subdirectory of the repository, the changed paths, which git reports from the repository root, cannot yet be placed under it, so from v3.6.2 the scan falls back to a full scan of `code` and logs a warning; diff scoping for a subdirectory is planned for a later release.

```yaml
name: Fendix Security Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload
  actions: read            # SARIF upload in a private or internal repository

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
        with:
          fetch-depth: 0      # diff mode compares against the PR base ref
      # @v1, or the full release commit for reproducibility; never @main.
      - uses: Fendix-app/Fendix@v1
        with:
          version: "v3.6.2"
          code: "."           # white-box SAST/secrets/SCA (default ".")
          url: ""             # optional: black-box DAST target
          spec: ""            # optional: OpenAPI spec to seed discovery
          fail-on: "HIGH"     # CRITICAL | HIGH | MEDIUM | LOW; empty never fails
          diff: "auto"        # auto = diff mode on pull_request, full scan otherwise
          format: "sarif"     # sarif (Security tab) | json | html | pdf
          output: "fendix-results.sarif"
          upload-sarif: "true"
          extra-args: ""      # raw args appended to `fendix scan`
```

**Action inputs:**

| Input | Default | Meaning |
|---|---|---|
| `code` | `.` | White-box source path. Empty to skip. |
| `url` | `""` | Black-box target. Empty skips DAST. |
| `spec` | `""` | OpenAPI spec to seed discovery. |
| `fail-on` | `HIGH` | Severity floor considered by release policy; exit 1 only when a finding reaches `BLOCK`. Empty disables blocking. |
| `diff` | `auto` | `auto` = diff mode on `pull_request` events (native secrets, text and Semgrep scanners read only changed files; the Python engine and DAST scan everything); `true` = diff mode on every event, against `HEAD` when there is no PR base ref; `false` = always full. |
| `format` | `sarif` | `sarif` / `json` / `html` / `pdf`. |
| `output` | `fendix-results.sarif` | Report path. |
| `upload-sarif` | `true` | Upload SARIF to code scanning, when `format=sarif` and the scan wrote a report. A private or internal repository needs `actions: read` and GitHub Code Security. |
| `version` | `latest` | Exact release tag, or `latest` (resolved once to an exact tag). Only signed releases install; automatic Python preparation needs v3.5.0 or later. |
| `extra-args` | `""` | Raw args appended to `fendix scan`. **v3.7.0:** they cannot cancel a required analyzer. |
| `require-analyzers` | `auto` | **v3.7.0.** Analyzers that must run for the gate to pass: `auto` (`semgrep` whenever `code` is set), a comma-separated list of engine analyzer names, or `none` (opt out; the gate warns that coverage is not enforced). Managed mode takes only `auto`. |
| `engine_path` | `""` | Caller-managed Python engine dir, installed from its `requirements.txt`. Empty: the release's own source, from its signed build record, with its hash-locked `requirements.lock` from v3.6.1. |

**Outputs:** `report` (path to the generated report), `exit-code` (0 no blocking decision / 1 at least one `BLOCK` / 2 error).

Outside the Action, the same verification is available to any workflow: install cosign first and run the installer with `FENDIX_REQUIRE_SIGNATURE=1` and an exact `FENDIX_VERSION`.

<a id="31-recommended--the-reference-workflow-at-a-fixed-commit"></a>

### 3.2 Alternative — the digest-pinned reference workflow

[`examples/github-actions/fendix-scan.yml`](https://github.com/Fendix-app/Fendix/blob/5ddfd88bde0e24d67d23be7f0d0302cfb29789f5/examples/github-actions/fendix-scan.yml) at commit `5ddfd88bde0e24d67d23be7f0d0302cfb29789f5` is an alternative for teams that want the container-based path and to own the workflow file directly. It runs the official v3.7.0 image by immutable digest and pins every third-party Action to a full commit SHA.

Install it from that commit, not from `main`:

```bash
mkdir -p .github/workflows
curl -fsSL -o .github/workflows/fendix-scan.yml \
  https://raw.githubusercontent.com/Fendix-app/Fendix/5ddfd88bde0e24d67d23be7f0d0302cfb29789f5/examples/github-actions/fendix-scan.yml
echo "1125f8ed0031da3cd2bdce839aacb73e6cc3bb06400ea0dda4ec1d6a9b688ca5  .github/workflows/fendix-scan.yml" | sha256sum -c -
```

On macOS, use `shasum -a 256 -c -` in place of `sha256sum -c -`.

The workflow runs on pull requests to `main` and on pushes to `main`. Each run:

1. scans the checkout with the pinned image (`--code ./ --fail-on HIGH`), restoring and saving a baseline through `actions/cache`;
2. re-renders the JSON report as SARIF and uploads it to code scanning (private repositories: see below);
3. posts a summary comment on the pull request;
4. ends with a gate step that decides the check from the scan's exit code.

**The gate.** The final step runs even when an earlier step failed, and it reads only the scan's exit code:

| Scan exit code | Gate |
|---|---|
| `0` | passes |
| `1` | fails: a finding reached `BLOCK` |
| `2` | fails: the scan did not complete |
| missing, or any other value | fails closed |

A failing reporting step (SARIF upload, PR comment) still fails the job, but it cannot skip the gate or turn a `BLOCK` or a scan error into a pass.

**Permissions.**

| Permission | Why |
|---|---|
| `actions: read` | SARIF upload on a private repository (`upload-sarif` reads the workflow run) |
| `contents: read` | checkout |
| `security-events: write` | SARIF upload to code scanning |
| `pull-requests: write` | the PR comment. Without it, the comment step fails with "Resource not accessible by integration" and the job fails; the gate still reports the scan result. |

**Private repositories and GitHub Code Security.** Code scanning on a private repository requires GitHub Code Security. Without it, GitHub rejects the upload with "Advanced Security must be enabled for this repository to use code scanning".

- **Public repository:** SARIF is uploaded, and findings appear in the Security tab and as PR annotations.
- **Private repository without Code Security:** the workflow skips the upload and writes a notice. The scan, the PR comment and the gate run as usual, and the comment says that no SARIF was uploaded.
- **Private repository with Code Security:** set the repository variable `FENDIX_UPLOAD_SARIF` to `true` (Settings → Secrets and variables → Actions → Variables) to upload. This path has not yet been verified end to end.

This file, at commit `5ddfd88bde0e24d67d23be7f0d0302cfb29789f5`, is the version tested at commit `41da3ae48fc17412893112061175120958b8b91e` with only two lines changed: the image digest, now v3.7.0 `sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015`, and the comment that names it. That content was tested end to end on 2026-10-25 in round r5 of `Fendix-app/fendix-action-e2e-public` (commit `7fe98164e596a9e2f6e5bb62aeee81fe6dea1d55`, a byte-identical copy) in a public repository: a push to `main` and pull requests with a `BLOCK` finding, a scan error, no `pull-requests` permission, no `security-events` permission and a held `WARN` finding, all six matching the previous round on outcome, exit code, SARIF upload, PR comment and findings (runs 40226953419, 40227084070, 40227089397, 40227093383, 40227099121 and 40227105157). The version at commit `41da3ae48fc17412893112061175120958b8b91e`, with the v3.6.2 image `sha256:7a8234194fa963f894e1fb77f2b728272230ab9b1ac5c05ffd75c0ab10ea2529`, was tested end to end on 2026-10-16, installed with the commands of that version in fresh public and private repositories (the private one without Code Security), against scans with no findings, a held `WARN` finding, a `BLOCK` finding and a scan error, on GitHub-hosted `ubuntu-24.04` runners. The scan with no findings uploaded its SARIF as the engine wrote it, with `"rules": []`. The previous version of this file (commit `7cf1960f321c497e0b15da7e5e1f02d87988743e`: the v3.6.0 image and a temporary step that rewrote a `null` rules value) also passed the core scenarios on `ubuntu-26.04`, the image `ubuntu-latest` moves to from 2026-10-19 (public: no findings, `WARN`, `BLOCK`, scan error; private: no findings, `BLOCK`). This version has not yet run there; the workflow stays on `ubuntu-latest`. Not yet tested: a private repository with Code Security, and pull requests from forks.

### 3.3 Public Action availability

The Action is listed on GitHub Marketplace as [Fendix Security Scan](https://github.com/marketplace/actions/fendix-security-scan), published from the v3.6.2 release. The engine source repository (`Fendix-app/Fendix`) is public, so the Action resolves from public and private consumers. Use `@v1`, which resolves to the validated v3.6.2 release until it is moved, or pin a release's full commit for reproducibility; v3.7.0's fail-closed required analyzers need its release commit `90adf6a` until `v1` is moved (§3.1). Never reference `@main`.

The canonical Docker Hub image is public and can be pulled anonymously. The previous GHCR image remains a compatibility path for existing consumers.

### 3.4 The Docker image, invoked directly

Bypass `uses:` and run the public image. It bundles Python + all static-analysis deps, so hybrid/white-box work out of the box.

```yaml
name: Fendix Security Scan (Docker direct)
on: [pull_request, push]

permissions:
  contents: read

jobs:
  fendix:
    runs-on: ubuntu-latest
    container:
      # Pin by digest for reproducibility / supply-chain integrity
      image: fendixapp/fendix@sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015
      # The image runs as uid 1000, and the runner's workspace and command
      # files belong to the runner user, so checkout fails with EACCES
      # unless the job runs as root.
      options: --user 0
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      # git rejects a workspace owned by another user ("detected dubious
      # ownership"), so diff mode falls back to a full scan; actions/checkout
      # v6 and later trust the workspace only during their own step. The
      # official image ships no git, so here the step does nothing; it
      # matters in a job image that has git.
      - name: Trust the workspace for git
        run: if command -v git >/dev/null; then git config --global --add safe.directory "$GITHUB_WORKSPACE"; fi
      - name: Run Fendix
        run: |
          set +e
          fendix scan --code . --format json --output findings.json --fail-on HIGH
          echo "FENDIX_EXIT=$?" >> "$GITHUB_ENV"
      - name: Surface findings (job summary, no Code Security needed)
        if: always()
        run: |
          fendix report --input findings.json --format html >> "$GITHUB_STEP_SUMMARY" || true
      - name: Enforce gate
        if: always()
        # No recorded exit code means the scan never finished: fail closed.
        run: exit "${FENDIX_EXIT:-2}"
```

Or as a one-shot `docker run` step (e.g. from a non-container job):

```bash
docker run --rm -v "$PWD:/src" -w /src \
  fendixapp/fendix@sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015 \
  scan --code . --format json --output findings.json --fail-on HIGH
```

- **No git in the image.** `actions/checkout` downloads the tree through the REST API, and `--diff` falls back to a full scan with a warning. For diff mode, use the Action (§3.1) or a job image that has git.
- **Version v3.7.0 image digest:** `sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015` (public, anonymously pullable; multi-arch `linux/amd64` + `linux/arm64`).
- **Pin by digest** (not a floating tag) for reproducible, tamper-evident builds — this is the form the release workflow itself signs and references.

### 3.5 `--fail-on` gating and exit codes

The build pass/fail is driven entirely by the exit code:

| Exit code | Meaning |
|---|---|
| `0` | Completed; nothing reached status `BLOCK` (or no `--fail-on` set). |
| `1` | At least one finding reached status `BLOCK`. |
| `2` | Scan error (engine unresolvable, discovery failed, render failure), `--fail-on-scanner-error` with a failed analyzer, `--fail-on-coverage-gap` with `configured_complete=false`, or `--require-analyzers` with an undelivered name. From v3.4.0 a URL scan that discovers zero endpoints still exits 2 but now writes the report first, with `dast` recorded `failed/no_endpoints`. |

**Since v2.0, `BLOCK` is not "severity ≥ `--fail-on`".** Meeting the threshold is
necessary but no longer sufficient: under the default `--enforce-confidence` a
finding also needs its deterministic band and evidence to support the claim —
`HIGH` needs an independent or self-evident signal, `MEDIUM` needs an
independent signal, and `LOW` never blocks. Independent signals include
cross-engine agreement, confirmed route, reachable taint path, proven path and
payload-validated probe; self-evident signals include a direct response read or
deterministic production-code detection. A finding
the correlator marked unconfirmed-by-live-scan never blocks uncorroborated.
Separately, `--deescalate-tests` holds an uncorroborated test-code finding at
`WARN` even when it meets the threshold.

> **A pipeline upgraded from 1.x can exit 0 where it exited 1.** The largest
> affected class is chainless static findings — a whitebox finding scores
> `35 base + 10 static = 45` (MEDIUM) and, absent a high-confidence pattern
> match in production code or a proven taint path, nothing corroborates it, so
> shape-match SAST (semgrep-shim tier included) no longer gates on its own.
> Direct or payload-validated DAST evidence can still block, while a bare
> status/shape observation without support is held at WARN. A deterministic
> hardcoded-credential detection in production code still bands `HIGH` and
> exits 1. `--enforce-confidence=false` (or
> `scan.enforce_confidence: false`) restores the pre-2.0 mapping byte-for-byte.

In a custom workflow, run the scan under `set +e`, capture `$?`, surface the report, **then** re-raise the exit code in a final `if: always()` step so the report is uploaded/posted even on a failing gate. Treat a missing exit code as a failure (the scan never finished), never as a pass.

### 3.6 Surfacing findings without GitHub Code Security

**Live-verified:** code scanning on a **private** repository requires GitHub Code Security (part of GitHub Advanced Security). Without it, `upload-sarif` fails with "Advanced Security must be enabled for this repository to use code scanning"; without `actions: read` it fails earlier with "Resource not accessible by integration". The GitHub App's SARIF upload has the same requirement. The reference workflow therefore skips the upload on a private repository unless it opts in (§3.2). Two alternatives that need no Code Security:

1. **Job summary** — render the HTML report into `$GITHUB_STEP_SUMMARY` (shown above). Always works, no permissions.
2. **PR comment** — the engine ships a byte-for-byte-identical PR-comment recipe in both the reference workflow (`actions/github-script@v7`) and the GitHub App. The comment has a `## Fendix scan: N finding(s)` header, a Mode/Endpoints/Duration line, a severity×source table, a `_No new findings vs. baseline. ✅_` line when clean, else a "Top findings" list of the top 5. The App version additionally emits a one-click `.fendix-ignore` suppression snippet under each finding. Requires `pull-requests: write`.

The checked-in reference workflow at `examples/github-actions/fendix-scan.yml` uses permissions `actions: read`, `contents: read`, `security-events: write`, `pull-requests: write`; it caches a baseline via `actions/cache` (key `fendix-baseline-${{ github.run_id }}`, restore-keys `fendix-baseline-`), runs the JSON scan + `--save-baseline`, re-renders SARIF via `fendix report`, uploads it unless the repository is private and has not opted in, and decides the job in a final gate step that fails closed. Cache save runs after any successful eligible job, including PR jobs; cache scope determines visibility, and this key does not guarantee that a restored baseline was produced by `main`.

### 3.7 `.fendix-ignore` — suppressing false positives

Scaffolded by `fendix init`. Top-level `ignore: []`. **Each rule suppresses findings matching ALL specified fields; omitted fields match everything.** `reason` is optional to the engine but should be required by review. Matchable dimensions are `fingerprint`, `id`, `endpoint`, and `category`; endpoint globs support `*` only:

```yaml
ignore:
  - fingerprint: a53e0be81c80617f5a6aa84cc8dd78954f78a7c2
    reason: "Accepted risk reviewed in JIRA-1234"
  - endpoint: "GET /health"
    category: headers
    reason: "Health endpoint intentionally header-light"
  - id: SEC-014
    until: 2026-12-31          # optional expiry; rule stops applying after
    reason: "Tracked in JIRA-1234, fix scheduled"
  - endpoint: "GET /api/public/*"   # globs supported
    category: auth
    reason: "Public API by design"
```

> **SEC-NNN IDs are positional and unstable across scans.** Prefer the report's
> versioned `fingerprint` for one exact durable finding. Use `endpoint` +
> `category` only for an intentionally broad semantic suppression. `id:` with
> `until:` is supported for one-run triage but is not a long-lived key.

### 3.8 `.fendix.yaml` — repo-committed scan policy

Sets team defaults (CLI flags still override). Precedence: cobra defaults < `.fendix.yaml` < explicit CLI flags.

```yaml
version: 1
fail_on: HIGH                 # mirrors --fail-on; "" = warn-only
ignore_path: .fendix-ignore   # mirrors --ignore, relative to repo root
scan:
  enable_active: false        # SQLi/CMDi/CRLF probes — only for targets you control
  # workers: 10
  # timeout: 10
  # delay_ms: 100
  # format: json
crawler:
  # crawl_depth: 1
  # max_endpoints: 500
  # wordlist_path: ""
  # respect_robots: false
budgets:
  # max_requests: 0
  # max_duration: ""
auth:
  # profile: my-staging       # points at ~/.fendix/profiles/<name>.yaml (creds out of source control)
```

The policy file can set exactly: `fail_on`, `ignore_path`,
`scan.{enable_active,workers,timeout,delay_ms,format,deescalate_tests,enforce_confidence}`,
`crawler.{crawl_depth,max_endpoints,wordlist_path,respect_robots}`,
`budgets.{max_requests,max_duration}`, and `auth.profile`.

### 3.9 Pre-commit hook for developers

```bash
fendix hook install --fail-on HIGH
```

Runs `fendix scan --code . --staged --fast --fail-on <severity>` on every
commit. `--fast` skips Semgrep and native SCA but currently leaves the Python
phase auto-enabled; use a manual invocation with `--python-engine=false` when
native-only latency is required. The generated hook's missing flag is the
known defect documented above. It aborts only when a finding reaches `BLOCK`;
`git commit --no-verify` bypasses once.

---

## 4. Hosted workspace and customer-runner boundary

The hosted Fendix workspace adds persistent scan history, organization access,
release decisions, evidence review, and reporting. Its browser application and
backend services are one product. The backend HTTP routes, authentication
mechanisms, raw OpenAPI document, and generated Swagger/ReDoc pages are private
service contracts. They are not a supported public developer API, compatibility
promise, or client-generation surface.

Supported automation remains explicit and portable:

- run the CLI locally or in CI;
- configure policy in `.fendix.yaml` and suppressions in `.fendix-ignore`;
- consume documented exit codes;
- preserve JSON, HTML, PDF, and SARIF reports;
- publish SARIF through supported CI-provider integrations; and
- use supported hosted-workspace integrations exposed in the product and its
  public documentation.

### 4.1 Customer-hosted runners

An Enterprise customer-hosted runner lets Fendix scan targets that are reachable
only inside a customer network. Setup is intentionally product-facing:

1. arrange Enterprise runner access through Fendix onboarding;
2. register the runner from the organization workspace;
3. store the one-time setup credential in the approved secret store;
4. deploy the supported runner package inside the permitted network boundary;
5. verify runner health and launch the scan from the workspace.

The runner connects outward over HTTPS. Fendix does not require an inbound
connection to the customer network. The raw claim, heartbeat, result, token, and
job schemas are an internal wire protocol between the supported runner and the
hosted control plane. They are not a public extension API and must not be copied
into customer integration code.

Runner jobs use the same engine report model and decision semantics documented
for local and CI scans. Missing required analyzer coverage still produces
`INCOMPLETE`; finding severity, disposition, and the release decision remain
separate facts.

### 4.2 Managed CI and release authorization

Managed CI and hosted release authorization are product capabilities available
only through explicitly documented Fendix integrations and approved onboarding.
Teams should not call backend routes directly or generate clients from the
backend OpenAPI schema. Until Fendix publishes a named, versioned integration,
the CLI, report artifacts, SARIF, and supported provider setup remain the public
automation contract.
---

## 5. Security & gotchas (consolidated)

1. **Working-tree scope and report disclosure.** A `--code` scan over a **working tree** reads gitignored files too. Secret values are redacted at capture time, but the report can still reveal that a credential-shaped value exists along with its safe identifier, file location, and surrounding security structure. Review a report before publishing it. A fresh CI checkout narrows the scan to checked-out content; it is the preferred input for white-box reports you intend to upload.

2. **SSRF egress guard (`netguard`) on private targets.** The engine protects *its own* outbound requests: it blocks loopback, link-local (incl. the cloud-metadata IP `169.254.169.254`), IPv6 ULA, and RFC1918 ranges, re-validating the concrete IP at connect time (DNS-rebinding-resistant) on up to 10 redirect hops. To scan a private/localhost/staging target, pass `--allow-private-targets` (auto-enabled when `--url` already resolves private). Hosted scans also validate targets. Approved customer-hosted runners execute inside the customer's network boundary for private-target coverage.

3. **SEC-NNN finding-ID instability.** `SEC-NNN` IDs reassign across scans. Use the report's versioned `fingerprint` for baselines, `fingerprint:` ignore rules, and persistent mappings. Current builds emit `fendix/v2` semantic fingerprints; line/column coordinates and evidence wording do not re-key a finding.

4. **The Python taint engine resolution.** The flag default is false, but `--code` auto-enables the Python engine unless `--python-engine=false` is explicit. Official v3.7.0 standalone binaries **do not bundle** the tree: the release runs `make embed-engine`, whose current target intentionally resets the embedded directory to a placeholder. Resolution order is explicit dir → `FENDIX_ENGINE` → the pin in `~/.fendix/config` → optional legacy/custom embedded payload → `./python`. A missing tree on the implicit `--code` path is recorded as `python-engine: skipped/dependency_missing` and the native analyzers continue; a missing tree after explicitly passing `--python-engine` is fatal (exit 2). The official Docker image ships `/opt/fendix/python/` and sets the engine environment, so hybrid/white-box works there. The v3.6.0 Action ran `fendix engine sync` unconditionally when `engine_path` was empty, which failed the job; from v3.6.1 the Action prepares the engine from the release's signed build record (§3.1).

5. **SARIF upload differs by repository.** Upload to code scanning needs `security-events: write`, plus `actions: read` on a private repository, and a private repository also needs GitHub Code Security. Where Code Security is unavailable, skip the upload and rely on the PR comment or a `$GITHUB_STEP_SUMMARY` report, as the reference workflow does (§3.2). Never let a failed upload skip the gate.

6. **Exit codes (memorize these for CI):** `0` = clean / nothing reached `BLOCK`; `1` = `--fail-on` gate tripped (severity **and**, since v2.0, a confidence band that supports the claim — `--enforce-confidence=false` restores the old severity-only gate); `2` = scan error (engine unresolvable, discovery failed, render failure, or `--fail-on-scanner-error` + a scanner failed), or `--fail-on-coverage-gap` (`configured_complete=false`) / `--require-analyzers` (an undelivered name). `fendix verify` uses its own scheme: `0` resolved, `1` still-present, `2` unknown/not-found — `2` now also covers a partial dependency lookup failure (`pip`/`npm` return a lookup error rather than a silent resolve), a fail-closed change from earlier builds that could answer "resolved" on the same partial failure.

7. **`--enable-active` sends real attack payloads.** SQLi/command-injection/CRLF probes only run with this flag, and it prints a legal disclaimer. **Only target systems you own/control.** It is off by default in `.fendix.yaml` too.

8. **Runner setup secrets are one-time values.** Store any credential shown during supported runner onboarding in the approved secret store. Rotate or revoke it from the workspace if it may have been exposed.

---

## 6. Appendix

### 6.1 `fendix scan` flag quick reference

| Flag | Default | One-liner |
|---|---|---|
| `--url` | `""` | Black-box target (→ blackbox/hybrid) |
| `--spec` | `""` | OpenAPI spec (→ whitebox/hybrid) |
| `--code` | `""` | Source dir (→ whitebox/hybrid; implicitly enables Python engine) |
| `--diff` | `""` (bare=HEAD) | Native secrets/text/Semgrep scanners read only files changed vs a git ref; the Python engine scans all |
| `--staged` | `false` | Staged-only diff (implies `--diff`) |
| `--fast` | `false` | Skips semgrep/native SCA; add `--python-engine=false` for native-only |
| `--fail-on` | `""` | Severity floor for the gate: CRITICAL/HIGH/MEDIUM/LOW (evidence gate also applies) |
| `--enforce-confidence` | `true` | v2.0 confidence gate; `false` = pre-2.0 severity-only |
| `--deescalate-tests` | `true` | Test-code findings demoted; uncorroborated ones held at WARN |
| `--fail-on-scanner-error` | `false` | Exit 2 if a scanner errored |
| `--enable-active` | `false` | Active attack probes (own targets only) |
| `--auth` / `--auth-type` / `--auth-header` | `""` / auto / `Authorization` | Credentials for authed checks |
| `--auth-user2` | `""` | Second user for IDOR |
| `--profile` | `""` | Auth profile from `~/.fendix/profiles/` |
| `-f, --format` | `json` (scan) / `html` (report) | `json`/`html`/`sarif`/`pdf` |
| `-o, --output` | stdout | Output file |
| `--lang` | `en` | `en`/`ar` (HTML only) |
| `-w, --workers` | `10` | Concurrent HTTP workers |
| `--delay` | `100` | ms between requests |
| `--timeout` | `10` | HTTP timeout (s) |
| `--crawl-depth` | `1` | HTML crawl depth (0 disables) |
| `--max-endpoints` | `500` | Endpoint cap |
| `--max-requests` | `0` | Request soft-cap |
| `--max-duration` | `0` | Wall-clock soft-cap (e.g. `5m`) |
| `--max-probes-per-endpoint` | `20` | With `--enable-active` |
| `--baseline` / `--save-baseline` | `""` | Diff vs / save prior findings |
| `--ignore` | `""` | `.fendix-ignore` path (unparseable → exit 2) |
| `--config` | `""` | `.fendix.yaml` (explicit missing → error) |
| `--wordlist` | `""` | Brute-force wordlist |
| `--respect-robots` | `false` | robots.txt Disallow = hard restriction |
| `--allow-private-targets` | `false` | Disable SSRF egress guard (auto-on for private `--url`) |
| `--offline` / `--offline-db` | `false` / `""` (→ `~/.fendix/offline-db.json`) | Native offline SCA; Python deps limitation described in §2.2 |
| `--no-native-deps` | `false` | Disable in-process Go SCA |
| `--use-pip-audit` | `false` | Shell out to `pip-audit` for Python |
| `--python-engine` | `false` | Flag default false; `--code` auto-enables it unless explicitly false (explicit true → fatal if missing) |
| `--no-plugins` / `--allow-repo-local-plugins` | `false` / `false` | Plugin discovery controls |
| `-v, --verbose` / `--debug-bundle` | `false` / `""` | Verbose output / redacted diagnostic tarball |

### 6.2 GitHub Action input quick reference

These inputs belong to the composite Action (§3.1).

| Input | Default | One-liner |
|---|---|---|
| `code` | `.` | White-box source (empty to skip) |
| `url` | `""` | Black-box target (empty skips DAST) |
| `spec` | `""` | OpenAPI spec |
| `fail-on` | `HIGH` | Severity floor: CRITICAL/HIGH/MEDIUM/LOW (empty never fails). Confidence-gated since engine v2.0. |
| `diff` | `auto` | auto/true/false; native file scanners only, the Python engine always scans in full |
| `format` | `sarif` | sarif/json/html/pdf |
| `output` | `fendix-results.sarif` | Report path |
| `upload-sarif` | `true` | SARIF → code scanning, when a report was written (a private repository needs `actions: read` and GitHub Code Security) |
| `version` | `latest` | Exact signed release tag, or `latest` resolved once |
| `extra-args` | `""` | Raw args appended to `fendix scan`; from v3.7.0 they cannot cancel a required analyzer |
| `require-analyzers` | `auto` | v3.7.0: analyzers that must run (`auto` = `semgrep` for code scans; a list; `none` opts out, coverage not enforced) |
| `engine_path` | `""` | Caller-managed Python engine dir; empty uses the release's own source and, from v3.6.1, its hash lock |

**Pinned image (v3.7.0):** `fendixapp/fendix@sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015`

---

### Worked-example note (TwiScope)

TwiScope is a Django/DRF backend, so the natural integration is: (1) a developer `fendix hook install --fail-on HIGH` for commit-time secret/IaC gating; (2) a CI job using the public GitHub Action (`Fendix-app/Fendix`), which resolves for public and private repositories, or the canonical Docker Hub image, running `fendix scan --code . --fail-on HIGH` against a fresh checkout and surfacing findings through `$GITHUB_STEP_SUMMARY`; and, if internal/staging API targets must be scanned, (3) an Enterprise-org **runner** inside the network performing `mode=hybrid` scans (`--url` staging + `--code` repo) and POSTing results back so they land in the dashboard with full TrackedFinding lifecycle. Use the Fendix Action (§3.1), `@v1` (the validated v3.6.2 Action until it is moved) or the v3.7.0 release commit, or the reference workflow (§3.2); the older v3.6.0 Action needs a version-matched Python engine tree through `engine_path`. SARIF upload from a private repository needs GitHub Code Security, but its absence does not stop the scan or the gate. A fresh checkout narrows the scanned files; review the report before publishing it because secret values are redacted at capture time while file locations, safe identifiers, and security structure remain visible.
