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
- **"I want every PR gated and findings in the GitHub Security tab."** → Path 2. Use the public Action or official container.
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
curl -fsSL https://get.fendix.dev/install.sh | FENDIX_VERSION=v3.4.1 sh

# Verify
fendix version          # → fendix version <Version> (<GOOS>/<GOARCH>)
```

Or run the published Docker image (bundles Python + all static-analysis deps, so hybrid mode works out of the box):

```bash
docker run --rm fendixapp/fendix:3.4.1 scan --url https://example.com
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

**Known product defect:** the generated CI workflows are historical and are
not current drop-ins. The GitHub file installs mutable source and supplies no
Python analyzer tree; GitLab and CircleCI pin obsolete v0.13.0
personal-namespace release assets with placeholder checksums while their
next-step files name a different version. The GitLab file also declares SARIF
under `artifacts:reports:sast`, which expects GitLab's own SAST JSON schema.
Use the checked-in pinned-container reference workflow or author an equivalent
current container job until the generator is corrected. The generated policy
and ignore starters remain independently usable.

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
| `--diff` | string | `""` (bare = `HEAD`) | Diff-aware scan: only changed files vs a git ref. `--diff=origin/main` = vs that ref. Whitebox scanners scoped to changed files; dep-CVE scanners run only when a manifest changed. |
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
| `--fail-on` | string | `""` | Severity floor: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`. Exit 1 when a finding at or above it reaches `BLOCK`; since v2.0 the confidence/evidence policy also applies, see [3.4](#34---fail-on-gating-and-exit-codes). **Stable v3.4.1:** an invalid value warns and effectively disables the gate. **Development/RC:** invalid values are rejected before scanning with exit 2. |
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
    "version": "3.4.1",
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
- **`scanner_status`** carries one entry per analyzer (`dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, its `python-engine/*` children when reported, `plugins`) with `state` ∈ `ok`/`skipped`/`failed` and a closed `reason` on every non-ok entry. **`metadata.coverage.configured_complete`** answers "did everything this run was configured to execute run?"; **`coverage.required_gaps`** answers "did `--require-analyzers` get what it asked for?". Only `failed` feeds `--fail-on-scanner-error` — that check itself is unchanged, but from v3.4.0 the set of analyzers that can record `failed` grew from six (`govulncheck`/`pip`/`npm`/`secrets`/`semgrep`/`textscan`) to the full registry above, so `dast`, `spec`, `active-probes`, `plugins` and the python-engine (and its checks) can now trip the flag too; `--fail-on-coverage-gap` also trips on `skipped/dependency_missing`.
- **`findings[].severity`** ∈ `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`. Severity rank used by `--fail-on`: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0. `rank(finding) >= rank(threshold)` is **necessary but not sufficient** since v2.0 — the gate then reads `findings[].confidence_band` and `findings[].status`. Read `status == "BLOCK"` (or `decisions.blocking`) to know what actually fails the build; `confidence_reasons` names the rule behind any demotion.
- **`findings[].source`** ∈ `blackbox`/`whitebox`/`correlated`/`imported`. **`confidence`** ∈ `HIGH`/`MEDIUM`/`LOW`. The legacy top-level `sources` counters omit `imported`; use `metadata.imports` for import accounting.
- **`line`** is a nullable pointer — serialized even when `null` (no omitempty).
- White-box extras: `taint_chain[]` (AST dataflow source→sink), `reachable`, `source_tier` (`native_go`/`tree_sitter_sidecar`/`semgrep_shim`), `route`, `route_confirmed`, and `proven_path` (set only when `route_confirmed` AND `reachable` — forces CRITICAL).

---

## 3. Level 2 — CI/CD gate

Goal: fail the build when a scan finds something at/above a severity threshold, and surface the findings to reviewers. There are **two supported ways to invoke the engine in CI**: the public GitHub Action and the public container image.

### 3.1 Option A — The GitHub Action (`uses: Fendix-app/Fendix@v1`)

A **composite** action that installs Fendix, syncs the Python taint engine, runs `fendix scan`, uploads SARIF, then enforces the fail-on gate. It needs `actions/checkout@v4` with `fetch-depth: 0` because diff mode needs git history.

**Known v3.4.1 defect:** the standalone release binary has no embedded Python
payload, while the Action's default `engine_path: ""` still runs `fendix engine
sync` as if one existed. A default invocation therefore fails before scanning
unless the workflow supplies a version-matched `python/` tree. The example
below assumes one is prepared at `vendor/fendix-python`. The official container
is the out-of-box path until the Action is corrected.

```yaml
name: Fendix Security Scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # for SARIF upload to the Security tab

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # required: diff mode needs history
      - uses: Fendix-app/Fendix@v1
        with:
          code: "."           # white-box SAST/secrets/SCA (default ".")
          engine_path: ${{ github.workspace }}/vendor/fendix-python
          url: ""             # optional: black-box DAST target
          spec: ""            # optional: OpenAPI spec to seed discovery
          fail-on: "HIGH"     # CRITICAL | HIGH | MEDIUM | LOW; empty never fails
          diff: "auto"        # auto = PR-changed files on pull_request, full scan otherwise
          format: "sarif"     # sarif (Security tab) | json | html | pdf
          output: "fendix-results.sarif"
          upload-sarif: "true"
          version: "v3.4.1"
          extra-args: ""      # raw args appended to `fendix scan`
```

**Action inputs:**

| Input | Default | Meaning |
|---|---|---|
| `code` | `.` | White-box source path. Empty to skip. |
| `url` | `""` | Black-box target. Empty skips DAST. |
| `spec` | `""` | OpenAPI spec to seed discovery. |
| `fail-on` | `HIGH` | Severity floor considered by release policy; exit 1 only when a finding reaches `BLOCK`. Empty disables blocking. |
| `diff` | `auto` | `auto` = scope to PR-changed files on `pull_request`; `true` = force diff vs base ref; `false` = always full. |
| `format` | `sarif` | `sarif` / `json` / `html` / `pdf`. |
| `output` | `fendix-results.sarif` | Report path. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Only when `format=sarif`. |
| `version` | `latest` | Fendix version to install. |
| `extra-args` | `""` | Raw args appended to `fendix scan`. |
| `engine_path` | `""` | Python engine dir. In v3.4.1, the empty default fails at `engine sync` because the standalone binary has no embedded payload. |

**Outputs:** `report` (path to the generated report), `exit-code` (0 no blocking decision / 1 at least one `BLOCK` / 2 error).

What the steps do: install via `curl … get.fendix.dev/install.sh | sh` → `fendix engine sync` (**fails loudly here if the SAST engine can't be resolved**, rather than silently degrading) → `fendix scan` under `set +e` (capturing exit code, deliberately exiting 0 so SARIF upload runs first) → `github/codeql-action/upload-sarif@v3` → a final `if: always()` step that re-raises the failure (`exit 1` on findings, `exit <code>` on error).

### 3.2 Public Action availability

The engine source repository (`Fendix-app/Fendix`) is public, so `uses: Fendix-app/Fendix@v1` resolves from public and private consumers. Pin the Action to a full commit SHA in high-assurance workflows and update the pin deliberately.

The canonical Docker Hub image is public and can be pulled anonymously. The previous GHCR image remains a compatibility path for existing consumers.

### 3.3 Option B — The Docker image, invoked directly

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
      image: fendixapp/fendix@sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Fendix
        run: |
          set +e
          fendix scan --code . --format json --output findings.json --fail-on HIGH
          echo "FENDIX_EXIT=$?" >> "$GITHUB_ENV"
      - name: Surface findings (job summary — no GHAS needed)
        if: always()
        run: |
          fendix report --input findings.json --format html >> "$GITHUB_STEP_SUMMARY" || true
      - name: Enforce gate
        if: always()
        run: exit "${FENDIX_EXIT:-0}"
```

Or as a one-shot `docker run` step (e.g. from a non-container job):

```bash
docker run --rm -v "$PWD:/src" -w /src \
  fendixapp/fendix@sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a \
  scan --code . --format json --output findings.json --fail-on HIGH
```

- **Version v3.4.1 image digest:** `sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a` (public, anonymously pullable; multi-arch `linux/amd64` + `linux/arm64`).
- **Pin by digest** (not a floating tag) for reproducible, tamper-evident builds — this is the form the release workflow itself signs and references.

### 3.4 `--fail-on` gating and exit codes

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

In a custom workflow, run the scan under `set +e`, capture `$?`, surface the report, **then** re-raise the exit code in a final `if: always()` step so the report is uploaded/posted even on a failing gate.

### 3.5 Surfacing findings WITHOUT GitHub Advanced Security

**Live-verified gotcha:** SARIF → Security-tab upload requires **GitHub Advanced Security (GHAS)**. On a **private repo without GHAS**, `upload-sarif` (and the App's SARIF upload) **403s**. Two GHAS-free alternatives:

1. **Job summary** — render the HTML report into `$GITHUB_STEP_SUMMARY` (shown above). Always works, no permissions.
2. **PR comment** — the engine ships a byte-for-byte-identical PR-comment recipe in both the reference workflow (`actions/github-script@v7`) and the GitHub App. The comment has a `## Fendix scan: N finding(s)` header, a Mode/Endpoints/Duration line, a severity×source table, a `_No new findings vs. baseline. ✅_` line when clean, else a "Top findings" list of the top 5. The App version additionally emits a one-click `.fendix-ignore` suppression snippet under each finding. Requires `pull-requests: write`.

The checked-in reference workflow at `examples/github-actions/fendix-scan.yml` uses permissions `contents: read`, `security-events: write`, `pull-requests: write`; it caches a baseline via `actions/cache@v4` (key `fendix-baseline-${{ github.run_id }}`, restore-keys `fendix-baseline-`), runs the JSON scan + `--save-baseline`, re-renders SARIF via `fendix report`, and defers the fail-on gate to a final step. Cache save runs after any successful eligible job, including PR jobs; cache scope determines visibility, and this key does not guarantee that a restored baseline was produced by `main`.

### 3.6 `.fendix-ignore` — suppressing false positives

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

### 3.7 `.fendix.yaml` — repo-committed scan policy

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

### 3.8 Pre-commit hook for developers

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

4. **The Python taint engine resolution.** The flag default is false, but `--code` auto-enables the Python engine unless `--python-engine=false` is explicit. Official v3.4.1 standalone binaries **do not bundle** the tree: the release runs `make embed-engine`, whose current target intentionally resets the embedded directory to a placeholder. Resolution order is explicit dir → `FENDIX_ENGINE` → the pin in `~/.fendix/config` → optional legacy/custom embedded payload → `./python`. A missing tree on the implicit `--code` path is recorded as `python-engine: skipped/dependency_missing` and the native analyzers continue; a missing tree after explicitly passing `--python-engine` is fatal (exit 2). The official Docker image ships `/opt/fendix/python/` and sets the engine environment, so hybrid/white-box works there. The v3.4.1 Action's unconditional `engine sync` with an empty `engine_path` is the known defect described in §3.1.

5. **SARIF permissions differ by repository.** The public `Fendix-app/Fendix@v1` Action resolves cross-repository. SARIF upload to the Security tab still needs `security-events: write` and may require GitHub Advanced Security for a private consumer repository; where it is unavailable, publish a `$GITHUB_STEP_SUMMARY` table or a PR comment instead.

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
| `--diff` | `""` (bare=HEAD) | Scan only files changed vs git ref |
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

| Input | Default | One-liner |
|---|---|---|
| `code` | `.` | White-box source (empty to skip) |
| `url` | `""` | Black-box target (empty skips DAST) |
| `spec` | `""` | OpenAPI spec |
| `fail-on` | `HIGH` | Severity floor: CRITICAL/HIGH/MEDIUM/LOW (empty never fails). Confidence-gated since engine v2.0. |
| `diff` | `auto` | auto/true/false |
| `format` | `sarif` | sarif/json/html/pdf |
| `output` | `fendix-results.sarif` | Report path |
| `upload-sarif` | `true` | SARIF → code scanning (needs GHAS on private repos) |
| `version` | `latest` | Engine version |
| `extra-args` | `""` | Raw args appended to `fendix scan` |
| `engine_path` | `""` | Python engine dir; v3.4.1's empty default fails because the release binary has no embedded tree |

**Pinned image (v3.4.1):** `fendixapp/fendix@sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a`

---

### Worked-example note (TwiScope)

TwiScope is a Django/DRF backend, so the natural integration is: (1) a developer `fendix hook install --fail-on HIGH` for commit-time secret/IaC gating; (2) a CI job using the public Marketplace Action, which resolves for public and private repositories, or the canonical Docker Hub image, running `fendix scan --code . --fail-on HIGH` against a fresh checkout and surfacing findings through `$GITHUB_STEP_SUMMARY`; and, if internal/staging API targets must be scanned, (3) an Enterprise-org **runner** inside the network performing `mode=hybrid` scans (`--url` staging + `--code` repo) and POSTing results back so they land in the dashboard with full TrackedFinding lifecycle. The v3.4.1 Action requires a version-matched Python engine tree through `engine_path`; use the container when that tree is unavailable. Private repositories need GitHub Advanced Security for SARIF upload, but that does not prevent the Action itself from running. A fresh checkout narrows the scanned files; review the report before publishing it because secret values are redacted at capture time while file locations, safe identifiers, and security structure remain visible.
