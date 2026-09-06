# Fendix Integration Guide

The authoritative guide for integrating **Fendix** — an API/code security scanner — into any project. It covers three integration levels, from a one-shot local CLI scan to a full SaaS dashboard wired through customer-hosted runners. TwiScope (a Django/DRF backend) is used as the worked example where helpful.

Everything here is drawn from verified source reads of the Fendix engine (Go + Python), the GitHub Action, the pre-commit hook, and the Fendix backend (Django REST). Flags, endpoints, and fields not listed here do not exist or were out of scope — do not assume otherwise.

---

## 1. Overview

Fendix has **three distinct integration surfaces**. They share the same engine and the same JSON report schema, so you can mix and match.

| Level | What it is | Who runs it | Output |
|---|---|---|---|
| **Level 1 — Local CLI** | The `fendix` Go binary run by hand or in a script | A developer / a shell | JSON / HTML / SARIF / PDF report, exit code |
| **Level 2 — CI/CD gate** | The same binary (or GHCR image) run on every push/PR, failing the build on findings | A CI runner (GitHub Actions, GitLab CI, CircleCI) | SARIF → Security tab / PR comment / job summary, build pass-fail |
| **Level 3 — SaaS API + dashboard** | The Fendix backend (Django REST) that stores scans, aggregates findings, and accepts externally-run results from customer **runners** | Your app/CI calls the API; runners push results | Persisted scans, dashboard, multi-tenant org workspaces |

### Quick decision guide

- **"I just want to scan something once."** → Level 1. `fendix scan --url ...` or `--code .`.
- **"I want every PR gated and findings in the GitHub Security tab."** → Level 2. Use the GitHub Action, or the GHCR image directly if the action can't resolve (private-repo gotcha, see §3.2).
- **"I want a persistent history, a dashboard, org workspaces, and to scan private/internal targets from CI."** → Level 3. Drive the SaaS API; use the **runner protocol** to get CI/white-box scans into the dashboard.
- **"My target is inside a private network / behind a VPN."** → Level 3 runner (it runs in-network and submits results back), because the SaaS backend itself enforces SSRF egress protection.

### The one safety rule that spans all levels

A white-box `--code` scan over a **working tree** reads gitignored files too. If your repo has local secret files (`.env`, `firebase_cred.json`, service-account keys), their **credential evidence ends up in the report**. **Never publish a working-tree report to the SaaS.** A CI checkout is a *fresh clone of tracked files only*, so it is inherently safe. See §5.

---

## 2. Level 1 — Local CLI

### 2.1 Install

```bash
# Install script (routes through the public homebrew-fendix mirror)
curl -fsSL https://get.fendix.dev/install.sh | sh

# Pin a specific version
curl -fsSL https://get.fendix.dev/install.sh | sh -s -- --version v0.19.0

# Verify
fendix version          # → fendix version <Version> (<GOOS>/<GOARCH>)
```

Or run the published Docker image (bundles Python + all static-analysis deps, so hybrid mode works out of the box):

```bash
docker run --rm ghcr.io/abdel-rahmansaied/fendix scan --url https://example.com
```

> **Note:** `get.fendix.dev` is a CNAME to the public `Abdel-RahmanSaied/homebrew-fendix` mirror (served via GitHub Pages). The mirror exists because the engine source repo is private — anonymous users can't pull from a private Releases page, so all install paths route through the mirror.

### 2.2 The subcommands

Root command is `fendix` (cobra). It prints its own errors (`SilenceUsage`/`SilenceErrors`). The subcommands that matter for integration:

| Subcommand | Purpose |
|---|---|
| `fendix scan` | Run a scan (black-box / white-box / hybrid). The workhorse. |
| `fendix report` | Re-render a saved JSON report to HTML/SARIF/PDF **without re-scanning**. |
| `fendix init` | Scaffold a CI workflow + `.fendix.yaml` policy + `.fendix-ignore`. |
| `fendix hook` | Install/uninstall/status the git pre-commit hook. |
| `fendix db` | Manage the offline CVE-database snapshot (air-gapped mode). |
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

#### `fendix hook` — git pre-commit gate

```bash
fendix hook install                  # default --fail-on HIGH
fendix hook install --fail-on MEDIUM
fendix hook status                   # installed / not installed / present-but-not-fendix-managed
fendix hook uninstall
```

The installed hook runs `fendix scan --code . --staged --fast --fail-on <severity>` — staged-only, fast mode (secrets + textscan natively, no semgrep, no network dep calls), so commit-time budget is tens of milliseconds. A finding at/above `--fail-on` aborts the commit; bypass once with `git commit --no-verify`. It honours `core.hooksPath` and worktrees, refuses to clobber a non-fendix hook without `--force`, and is recognized by a sentinel comment `# fendix-managed-pre-commit-hook`.

#### `fendix db` — offline CVE snapshot (air-gapped)

```bash
# Build a snapshot from an OSV-shaped JSON export (top-level array or {"advisories":[...]})
fendix db update --source osv-export.json          # → ~/.fendix/offline-db.json
fendix db list                                     # print snapshot metadata
fendix db verify                                   # sha256 <hash>  <path>

# Then scan offline (zero outbound calls; pip+npm consult the snapshot; govulncheck is SKIPPED)
fendix scan --code . --offline
```

#### `fendix verify <finding-id>` — re-test one finding

```bash
fendix verify SEC-014 --baseline findings.json --url https://api.example.com --json
```

Has **its own exit-code scheme**: `0` = resolved, `1` = still present (CI should fail), `2` = unknown or not found in baseline.

### 2.3 `fendix scan` flag reference

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
| `--fast` | bool | `false` | Run only instant native scanners (secrets + textscan); skip semgrep + network dep-CVE scanners. Sub-second. |
| `--max-endpoints` | int | `500` | Cap discovered endpoints (0 = no cap). |
| `--max-requests` | int64 | `0` | Soft-cap on total HTTP requests (0 = no cap). Armed after discovery. |
| `--max-duration` | duration | `0` | Soft-cap on wall-clock time, e.g. `5m` (0 = no cap). |
| `--max-probes-per-endpoint` | int | `20` | Max active probes/endpoint (only with `--enable-active`). |

#### Auth

| Flag | Type | Default | Description |
|---|---|---|---|
| `--auth` | string | `""` | Auth header value, e.g. `"Bearer token123"`. |
| `--auth-type` | string | `""` (auto) | `bearer` / `apikey` / `basic` / `cookie`. |
| `--auth-header` | string | `Authorization` | Custom auth header name. |
| `--auth-user2` | string | `""` | Second user for IDOR checks. |
| `--profile` | string | `""` | Auth profile from `~/.fendix/profiles/<name>.yaml`. |

Credentials are masked as `[REDACTED]` in all report output.

#### Behavior

| Flag | Type | Default | Description |
|---|---|---|---|
| `--enable-active` | bool | `false` | Enable active injection probes (SQLi/cmd/header injection). Prints a legal disclaimer. |
| `--fail-on` | string | `""` | Severity floor for the build gate: `CRITICAL` / `HIGH` / `MEDIUM`. Exit 1 when a finding at or above it reaches status `BLOCK` — since v2.0 that also requires the confidence band to support the claim, see [3.4](#34---fail-on-gating-and-exit-codes). Invalid value → WARN + no gate (exit 0). |
| `--enforce-confidence` | bool | `true` | **v2.0.** `BLOCK` only when the deterministic confidence band supports the claim: `HIGH` always, `MEDIUM` with ≥ 1 corroborating signal, `LOW` never. `false` restores the pre-2.0 severity-only gate byte-for-byte. |
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
| `--offline` | bool | `false` | Air-gapped: consult local offline-db snapshot for dep CVEs. govulncheck recorded SKIPPED. Zero outbound calls. |
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
- **Auth-tiered (needs `--auth`):** `auth` — missing authentication + JWT bypasses (malformed/expired/`alg:none`), all CRITICAL.
- **Multiuser (needs `--auth-user2`):** `idor` — two-user response compare, HIGH.
- **Active (`--enable-active`):** `injection` (time/error/boolean SQLi across 5 DB engines, command injection, CRLF), `xss`, `open-redirect`, `ssrf` (in-band), `host-header`, `graphql`, `method-tamper`.

**White-box / SAST + SCA (`--code`)** — run natively in Go, regardless of `--python-engine`. `--enable-active` is irrelevant (no runtime probing):

- **Secrets** — 15 provider patterns + `ENV_SECRET` (AWS/GitHub/Stripe/Anthropic/OpenAI/GCP keys → CRITICAL; generic keys/passwords/JWT/DB strings → HIGH).
- **textscan / IaC** — Go (4), JS (6), and IaC (Dockerfile/k8s, 7) regex rules.
- **semgrep** — shim to host `semgrep` binary (4 embedded rule packs). Gracefully absent → skipped with an install hint.
- **SCA / dependency CVEs (backed by OSV.dev):** Go (`go.mod` via govulncheck, reachable-only), npm (`package-lock.json` via OSV.dev), Python (`requirements.txt`/`poetry.lock`/`Pipfile.lock` via OSV.dev; `--use-pip-audit` to shell out).

**OpenAPI spec (`--spec`)** — feeds endpoint discovery (Go crawler) and is analyzed white-box (Python `spec_parser`: no global security, HTTP/plaintext schemes, anonymous endpoints, HTTP Basic).

**Endpoint discovery priority (black-box):** spec > robots.txt > sitemap.xml > JavaScript source > HTML link crawl > common-path brute-force.

### 2.5 The JSON report schema

`fendix scan --format json` (default) and `fendix report --format json` emit this shape (2-space indent). `findings` is **always a JSON array** — never `null`.

```json
{
  "metadata": {
    "schema_version": 1,
    "target": "https://api.example.com",
    "started_at": "2026-06-20T10:00:00Z",
    "duration": "4.521s",
    "version": "0.18.0",
    "mode": "blackbox",
    "endpoints_scanned": 42,
    "active_probes": false,
    "checks_run": ["headers", "cors", "secrets", "semgrep", "deps"],
    "scanner_status": [
      { "name": "govulncheck", "state": "ok" },
      { "name": "semgrep", "state": "skipped", "reason": "dependency_missing", "detail": "binary not found" }
    ],
    "policy_version": "1.0.0",
    "coverage": {
      "contract_version": 1,
      "strict": false,
      "configured_complete": false,
      "gaps": ["semgrep"],
      "limitations": [],
      "required_analyzers": [],
      "required_gaps": [],
      "retried": []
    }
  },
  "summary": { "critical": 1, "high": 3, "medium": 5, "low": 2, "info": 4 },
  "sources": { "blackbox": 10, "whitebox": 5, "correlated": 0 },
  "total": 15,
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
      "taint_chain": [{ "file": "app.py", "line": "42", "expr": "..." }],
      "reachable": true,
      "source_tier": "native_go",
      "route": { "method": "POST", "pattern": "/login", "handler": "...", "file": "...", "line": "..." },
      "route_confirmed": true,
      "proven_path": true
    }
  ]
}
```

Key facts:

- **`metadata.schema_version`** is the contract version, currently `1`, and is present on every report a current build writes. An **absent** key means the report predates the field — treat that as "pre-versioned", not as invalid. An **unrecognised** value means the report is newer than your integration: warn and keep parsing rather than failing, since the versioned keys are additive by policy.
- **`metadata.mode`** ∈ `blackbox` / `whitebox` / `hybrid`.
- **`scanner_status`** carries one entry per analyzer (`dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, its `python-engine/*` children when reported, `plugins`) with `state` ∈ `ok`/`skipped`/`failed` and a closed `reason` on every non-ok entry. **`metadata.coverage.configured_complete`** answers "did everything this run was configured to execute run?"; **`coverage.required_gaps`** answers "did `--require-analyzers` get what it asked for?". Only `failed` feeds `--fail-on-scanner-error` — that check itself is unchanged, but from v3.4.0 the set of analyzers that can record `failed` grew from six (`govulncheck`/`pip`/`npm`/`secrets`/`semgrep`/`textscan`) to the full registry above, so `dast`, `spec`, `active-probes`, `plugins` and the python-engine (and its checks) can now trip the flag too; `--fail-on-coverage-gap` also trips on `skipped/dependency_missing`.
- **`findings[].severity`** ∈ `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`. Severity rank used by `--fail-on`: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0. `rank(finding) >= rank(threshold)` is **necessary but not sufficient** since v2.0 — the gate then reads `findings[].confidence_band` and `findings[].status`. Read `status == "BLOCK"` (or `decisions.blocking`) to know what actually fails the build; `confidence_reasons` names the rule behind any demotion.
- **`findings[].source`** ∈ `blackbox`/`whitebox`/`correlated`. **`confidence`** ∈ `HIGH`/`MEDIUM`/`LOW`.
- **`line`** is a nullable pointer — serialized even when `null` (no omitempty).
- White-box extras: `taint_chain[]` (AST dataflow source→sink), `reachable`, `source_tier` (`native_go`/`tree_sitter_sidecar`/`semgrep_shim`), `route`, `route_confirmed`, and `proven_path` (set only when `route_confirmed` AND `reachable` — forces CRITICAL).

> The README's "Output Formats" JSON example shows an older illustrative shape; the schema above (from `json.go`) is the actual emitted shape.

---

## 3. Level 2 — CI/CD gate

Goal: fail the build when a scan finds something at/above a severity threshold, and surface the findings to reviewers. There are **two ways to invoke the engine in CI**, and which you use hinges on a private-repo gotcha.

### 3.1 Option A — The GitHub Action (`uses: abdel-rahmansaied/fendix@v1`)

A **composite** action that installs Fendix, syncs the Python taint engine, runs `fendix scan`, uploads SARIF, then enforces the fail-on gate. It needs `actions/checkout@v4` with `fetch-depth: 0` because diff mode needs git history.

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
      - uses: abdel-rahmansaied/fendix@v1
        with:
          code: "."           # white-box SAST/secrets/SCA (default ".")
          url: ""             # optional: black-box DAST target
          spec: ""            # optional: OpenAPI spec to seed discovery
          fail-on: "HIGH"     # CRITICAL | HIGH | MEDIUM; empty never fails
          diff: "auto"        # auto = PR-changed files on pull_request, full scan otherwise
          format: "sarif"     # sarif (Security tab) | json | html
          output: "fendix-results.sarif"
          upload-sarif: "true"
          version: "latest"   # or v0.19.0
          extra-args: ""      # raw args appended to `fendix scan`
          engine_path: ""     # path to Python engine dir; empty = auto
```

**Action inputs:**

| Input | Default | Meaning |
|---|---|---|
| `code` | `.` | White-box source path. Empty to skip. |
| `url` | `""` | Black-box target. Empty skips DAST. |
| `spec` | `""` | OpenAPI spec to seed discovery. |
| `fail-on` | `HIGH` | Fail at/above this severity. Empty never fails. |
| `diff` | `auto` | `auto` = scope to PR-changed files on `pull_request`; `true` = force diff vs base ref; `false` = always full. |
| `format` | `sarif` | `sarif` / `json` / `html`. |
| `output` | `fendix-results.sarif` | Report path. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Only when `format=sarif`. |
| `version` | `latest` | Fendix version to install. |
| `extra-args` | `""` | Raw args appended to `fendix scan`. |
| `engine_path` | `""` | Python engine dir. Empty = auto-resolution. |

**Outputs:** `report` (path to the generated report), `exit-code` (0 clean / 1 findings at/above fail-on / 2 error).

What the steps do: install via `curl … get.fendix.dev/install.sh | sh` → `fendix engine sync` (**fails loudly here if the SAST engine can't be resolved**, rather than silently degrading) → `fendix scan` under `set +e` (capturing exit code, deliberately exiting 0 so SARIF upload runs first) → `github/codeql-action/upload-sarif@v3` → a final `if: always()` step that re-raises the failure (`exit 1` on findings, `exit <code>` on error).

### 3.2 GOTCHA: the engine repo is private — the Action may be unresolvable

**This is the single most important CI fact.** The engine source repo (`Abdel-RahmanSaied/Fendix`) is **private**. Consequently, `uses: abdel-rahmansaied/fendix@v1` **cannot be resolved cross-repo from another private repo's runner** — that is the documented and *live-verified* failure mode.

The resolvable alternative is the **public GHCR image, pulled directly**. The GHCR package is published with **public visibility**, so it can be pulled anonymously (no registry auth needed in CI).

### 3.3 Option B — The GHCR image, invoked directly (the robust path)

Bypass `uses:` and run the public image. It bundles Python + all static-analysis deps, so hybrid/white-box work out of the box.

```yaml
name: Fendix Security Scan (GHCR direct)
on: [pull_request, push]

permissions:
  contents: read

jobs:
  fendix:
    runs-on: ubuntu-latest
    container:
      # Pin by digest for reproducibility / supply-chain integrity
      image: ghcr.io/abdel-rahmansaied/fendix@sha256:163ca22b8d36b6649a45161efa1daa51677bcd6565158e97f393dd89ec8e703d
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
  ghcr.io/abdel-rahmansaied/fendix@sha256:163ca22b8d36b6649a45161efa1daa51677bcd6565158e97f393dd89ec8e703d \
  scan --code . --format json --output findings.json --fail-on HIGH
```

- **Version v0.19.0 image digest:** `sha256:163ca22b8d36b6649a45161efa1daa51677bcd6565158e97f393dd89ec8e703d` (public, anonymously pullable; multi-arch linux/amd64 + linux/arm64).
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
finding also needs its deterministic band to support the claim — `HIGH` always
blocks, `MEDIUM` blocks only with at least one corroborating signal (cross-engine
agreement, live runtime observation, direct observation of a live response,
deterministic detection in production code, confirmed route, reachable taint
path, proven path, payload-validated probe), `LOW` never blocks — and a finding
the correlator marked unconfirmed-by-live-scan never blocks uncorroborated.
Separately, `--deescalate-tests` holds an uncorroborated test-code finding at
`WARN` even when it meets the threshold.

> **A pipeline upgraded from 1.x can exit 0 where it exited 1.** The largest
> affected class is chainless static findings — a whitebox finding scores
> `35 base + 10 static = 45` (MEDIUM) and, absent a high-confidence pattern
> match in production code or a proven taint path, nothing corroborates it, so
> shape-match SAST (semgrep-shim tier included) no longer gates on its own. Pure
> DAST findings are unaffected, and a real hardcoded credential in production
> code still bands `HIGH` and still exits 1. `--enforce-confidence=false` (or
> `scan.enforce_confidence: false`) restores the pre-2.0 mapping byte-for-byte.

In a custom workflow, run the scan under `set +e`, capture `$?`, surface the report, **then** re-raise the exit code in a final `if: always()` step so the report is uploaded/posted even on a failing gate.

### 3.5 Surfacing findings WITHOUT GitHub Advanced Security

**Live-verified gotcha:** SARIF → Security-tab upload requires **GitHub Advanced Security (GHAS)**. On a **private repo without GHAS**, `upload-sarif` (and the App's SARIF upload) **403s**. Two GHAS-free alternatives:

1. **Job summary** — render the HTML report into `$GITHUB_STEP_SUMMARY` (shown above). Always works, no permissions.
2. **PR comment** — the engine ships a byte-for-byte-identical PR-comment recipe in both the reference workflow (`actions/github-script@v7`) and the GitHub App. The comment has a `## Fendix scan: N finding(s)` header, a Mode/Endpoints/Duration line, a severity×source table, a `_No new findings vs. baseline. ✅_` line when clean, else a "Top findings" list of the top 5. The App version additionally emits a one-click `.fendix-ignore` suppression snippet under each finding. Requires `pull-requests: write`.

The reference workflow scaffolded by `fendix init` uses permissions `contents: read`, `security-events: write`, `pull-requests: write`; it caches a baseline via `actions/cache@v4` (key `fendix-baseline-${{ github.run_id }}`, restore-keys `fendix-baseline-`), runs the JSON scan + `--save-baseline`, re-renders SARIF via `fendix report`, and defers the fail-on gate to a final step.

### 3.6 `.fendix-ignore` — suppressing false positives

Scaffolded by `fendix init`. Top-level `ignore: []`. **Each rule suppresses findings matching ALL specified fields; omitted fields match everything.** `reason` is an optional field (the engine does not enforce it — a reason-less rule still parses and suppresses) but documenting *why* is a strong convention; keep it required by review. Three matchable dimensions, in any combination:

```yaml
ignore:
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

> **SEC-NNN IDs are UNSTABLE across scans.** Prefer matching on **`endpoint` + `category`** — that's the actual suppression key the matcher uses, and what the PR-comment one-click suppression always emits (`- {endpoint: ..., category: ...}  # fp-<hash>`). `id:` with `until:` is supported, but don't rely on it long-term.

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

The policy file can set: `fail-on`, `enable-active`, `workers`, `timeout`, `delay`, `format`, `crawl-depth`, `max-endpoints`, `wordlist`, `respect-robots`, `max-requests`, `max-duration`, `ignore-path`, `auth-profile`.

### 3.8 Pre-commit hook for developers

```bash
fendix hook install --fail-on HIGH
```

Runs `fendix scan --code . --staged --fast --fail-on <severity>` on every commit (staged files only, native scanners only — tens of ms). Aborts the commit on a HIGH+ finding; `git commit --no-verify` bypasses once.

---

## 4. Level 3 — SaaS API + dashboard

The Fendix backend is a **Django REST Framework** app mounted under `/api`. All routers use `trailing_slash=False`, so **endpoints have NO trailing slash** (`POST /api/scans`, not `/api/scans/`).

Local dev base: `http://localhost:8000/api`. Swagger UI: `http://localhost:8000/api/docs/`. Health: `http://localhost:8000/health-check/`.

### 4.1 Auth — JWT vs X-API-Key

The DRF auth chain, in order: `APIKeyAuthentication` → `CookieJWTAuthentication` → `CsrfExemptSessionAuthentication`. Default permission `IsAuthenticated`. A request authenticates via **either** an `X-API-Key` header **or** a JWT (Bearer header or cookie). API key is tried first; if its header is absent it abstains and JWT runs.

#### A. JWT (RS256) — primary for humans / SPA

```bash
# Register (201) or login (200)
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"hunter2"}'
```

Returns (and also sets httpOnly `access_token` + `refresh_token` cookies, SameSite=Strict):

```json
{ "token": "<access JWT>", "refresh": "<refresh JWT>", "user": {"id": "...", "name": "...", "email": "..."} }
```

- **Lifetimes:** access 15 min, refresh 7 days. `ROTATE_REFRESH_TOKENS=True` + `BLACKLIST_AFTER_ROTATION=True` — after a refresh, the submitted refresh token is blacklisted, so **clients MUST persist the newly-returned `refresh`**.
- **Use the token:** `Authorization: Bearer <access JWT>` (or rely on the `access_token` cookie for browsers).
- **Refresh:** `POST /api/auth/refresh` with `{"refresh":"<token>"}` (cookie clients send no body) → `{"access": ...}` and (for body clients) the rotated `{"refresh": ...}`.
- **MFA:** if a confirmed TOTP device exists, login returns `{"mfa_required": true, "mfa_token": "..."}`; complete via `POST /api/auth/mfa/challenge` with `{mfa_token, otp}`.
- **Other:** `POST /api/auth/logout` (blacklists refresh, clears cookies, `205`), `GET /api/auth/me` (`{id, name, email}`), `POST /api/auth/password-reset` + `/password-reset/confirm`.
- JWT/cookie sessions are **unscoped** — a human does whatever their plan/role allows.

#### B. X-API-Key (`fx_` prefix) — programmatic, Pro+ gated

```bash
# Create a key (Pro plan or higher required: api_key_access feature)
curl -X POST http://localhost:8000/api/auth/api-keys/create \
  -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-key","scopes":["scan:write","findings:read"],"expires_at":"2026-12-31T00:00:00Z","allowed_ips":["203.0.113.0/24"]}'
```

Returns `201` with `{id, name, key_prefix, scopes, expires_at, allowed_ips, created_at, key}` — **`key` is the raw value returned only once at creation** (stored only as a SHA-256 hash; cannot be retrieved again).

```bash
# Use it
curl http://localhost:8000/api/scans -H "X-API-Key: fx_..."
```

- **Format:** `fx_<secret>`. **Gating:** create/list/revoke need the `api_key_access` feature (Pro/Team/Enterprise = yes, Free = no).
- **List:** `GET /api/auth/api-keys` (paginated; raw key not included). **Revoke:** `DELETE /api/auth/api-keys/{key_id}` → soft-delete, `204`.
- **Scopes** (least-privilege; `"*"` = full): `scan:read/write`, `findings:read/write`, `reports:read`, `issues:write`, `audit:read`, `integrations:read/write`, `runners:read/write`, `orgs:read/write`. Enforced **only for API-key callers**; a key lacking a scope → `403 API_SCOPE_DENIED`.
- **Expiry / IP:** expired key → `401`; source IP not in `allowed_ips` (CIDR-matched against `X-Forwarded-For`/`REMOTE_ADDR`) → `403 API_IP_DENIED`. Empty `allowed_ips` = any source.

### 4.2 Launch a scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "X-API-Key: fx_..." \
  -H 'Content-Type: application/json' \
  -d '{
        "mode": "blackbox",
        "url": "https://api.example.com",
        "auth": "Bearer target-token",
        "auth_type": "bearer",
        "fail_on": "high"
      }'
```

`POST /api/scans` (scope `scan:write`) → `201` with a `ScanMeta` shape. `ScanViewSet` supports only GET/POST/DELETE (scans are immutable). New scans start `queued` (reported as `"running"` in the API).

**Fields** (`LaunchScanSerializer`):

| Field | Type / choices | Notes |
|---|---|---|
| `mode` | **required** — `blackbox` / `whitebox` / `hybrid` | blackbox/hybrid require `url`; whitebox/hybrid require `code` or `git_url`. |
| `url` | str ≤2048 | SSRF-validated unless a runner is set. |
| `code` | str ≤2048 | host code path; jailed. Mutually exclusive with `git_url`. |
| `spec` | str ≤2048 | OpenAPI spec (URL SSRF-validated, or jailed file path). |
| `auth` / `auth_user2` | str ≤4096 | encrypted at rest (Fernet, `fenc:` prefix). |
| `auth_type` | `bearer`/`apikey`/`basic`/`cookie`/`apikey-query` | |
| `auth_header` | str ≤128 | |
| `fail_on` | str ≤64 | severity gate. |
| `active_probing` | bool default false | requires `active_probes` feature (Pro+). |
| `organization` | UUID | launch into an org workspace (member+ role; quota/features resolve against the org). |
| `runner` | UUID | self-hosted runner (org-only; `self_hosted_runners` feature); skips SSRF screen; waits for runner not Celery. |
| `baseline` / `save_baseline` / `ignore` / `wordlist` | str ≤2048 | host-FS paths jailed to per-tenant artifact dir. |
| `delay` | int 0–60000 | ms. |
| `crawl_depth` | int 0–10 | |
| `max_endpoints` | int 0–100000 | |
| `max_probes_per_endpoint` | int 1–10000 | |
| `max_requests` | int 0–10_000_000 | |
| `max_duration` | Go duration string (`5m`,`90s`,`2m30s`,`1h`) ≤32 | |
| `respect_robots` | bool default false | |
| `workers` | int 1–50 | |
| `http_timeout` | int 1–120 | engine `--timeout`. |
| `no_native_deps` | bool default false | |
| `use_pip_audit` | bool default false | |
| `git_url` | URL ≤2048 | HTTPS GitHub/GitLab only; mutually exclusive with `code`. |
| `git_branch` | str ≤256 default "" | |
| `git_token` | str ≤512 | PAT for private repos; encrypted, injected into clone URL. |

Deliberately **NOT exposed**: `--profile`, `--debug-bundle`, `--no-plugins`, `--config`, `--output`, `--verbose`, `--python-engine`, `--lang` (a report concern), `--offline`, `--format` (the backend hardcodes `--format json`).

On create, quota debit + concurrency cap + persist happen atomically; a broker-down dispatch failure refunds quota, marks the scan FAILED, and returns `503 dispatch_failed`.

### 4.3 Poll and retrieve

```bash
# List (paginated). Scoped to ONE workspace: ?organization=<uuid> OR personal scans.
curl "http://localhost:8000/api/scans?organization=$ORG" -H "X-API-Key: fx_..."

# Retrieve one — returns a {scan, findings} envelope
curl "http://localhost:8000/api/scans/$SCAN_ID" -H "X-API-Key: fx_..."
```

`GET /api/scans/{id}` returns:

```json
{
  "scan": {
    "id": "...", "target": "...", "timestamp": "...", "duration_ms": 4521,
    "status": "completed", "mode": "blackbox", "total_findings": 15,
    "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 2, "INFO": 4},
    "by_source": {...}, "endpoints_scanned": 42, "active_probes": false,
    "checks_run": [...], "error": null
  },
  "findings": [
    {
      "id": "...", "scan_id": "...", "finding_id": "SEC-014", "title": "...",
      "severity": "MEDIUM", "source": "blackbox", "category": "headers",
      "endpoint": "...", "evidence": "...", "fix": "...", "references": [...],
      "confidence": "HIGH", "line": null, "affected_endpoints": [],
      "taint_chain": [...], "reachable": true, "route": {...},
      "route_confirmed": true, "proven_path": true, "compliance": {...}
    }
  ]
}
```

Detail routes work over the caller's full accessible set (personal + all orgs they belong to), so deep links work without `?organization=`. Build the verify URL `POST /api/scans/{scan_id}/findings/{id}/verify` from these.

Other reads: `GET /api/findings` (flat list, scope `findings:read`), `GET /api/scans/{id}/compliance` (OWASP/ASVS/PCI), `GET /api/scans/{id}/diff?against=<id>` (new/fixed/persisting by fingerprint), `POST /api/scans/{id}/findings/{fid}/verify` (`202` + pollable `GET /api/verifications/{id}`).

### 4.4 Fetch reports

`GET|POST /api/scans/{id}/report` (scope `reports:read`). `format` ∈ `html`/`sarif`/`pdf` (else `400 invalid_format`). Optional `lang` ∈ `{en, ar}` (only HTML honours it; unknown → `400 invalid_lang`).

```bash
# Synchronous — returns the report bytes inline
curl "http://localhost:8000/api/scans/$SCAN_ID/report?format=html" \
  -H "X-API-Key: fx_..." -o report.html

# Async generation — idempotent get_or_create on (scan, format)
curl -X POST "http://localhost:8000/api/scans/$SCAN_ID/report" \
  -H "X-API-Key: fx_..." -H 'Content-Type: application/json' \
  -d '{"format":"pdf"}'
# → 200 if already READY (cache hit), 202 if queued
```

- **GET** is synchronous (cache hit if a READY artifact exists, else generated inline). `Content-Type` per format, `Content-Disposition: attachment; filename="fendix-<scanid>.<ext>"` (`html`/`sarif.json`/`pdf`), `Cache-Control: private, no-store`.
- **POST** queues async generation. Returns `200` (already ready) or `202` (queued). Async only supports default lang (`lang=ar` async → `400 lang_not_supported_async`; use GET instead). Poll `GET /api/reports/{id}` until `status=='ready'`, then the response carries a **5-minute signed `download_url`** (open directly, no auth header) — or `GET /api/reports/{id}/download?token=...`.

### 4.5 The dashboard aggregate

```bash
curl "http://localhost:8000/api/dashboard?organization=$ORG" -H "X-API-Key: fx_..."
```

`GET /api/dashboard` (scope `scan:read`). Scoped to ONE workspace via `?organization=<uuid>` (viewer+, member-checked, Http404 for non-members) OR the caller's personal scans when absent.

```json
{
  "total_scans": 128,
  "total_findings": 542,
  "scans_this_week": 7,
  "by_severity": { "CRITICAL": 3, "HIGH": 21, "MEDIUM": 88, "LOW": 200, "INFO": 230 },
  "by_category": { "headers": 120, "auth": 40, "Other": 12 },
  "recent_scans": [ /* 5 most recent ScanMeta, -timestamp */ ],
  "trend": [ { "week_start": 1718064000, "findings": 12 } /* 8 weekly buckets, oldest→newest */ ]
}
```

`by_category` is server-aggregated (correct past page size; blanks folded into `"Other"`). `trend` is an 8-week weekly finding count, oldest→newest; `week_start` is the Unix timestamp (seconds) of the start of each rolling 7-day window, anchored to the current request time — **not** calendar-Monday aligned (the buckets are computed in Python precisely to avoid `TruncWeek`'s Monday alignment, so each boundary shares the request's weekday/time-of-day).

### 4.6 The runner protocol — push externally-run scans into the dashboard

A **Runner** is a customer-hosted agent that reaches **private targets** inside the customer's network and submits results back to Fendix. It is the canonical path for getting **CI / white-box `--code` reports** into the dashboard. Runners are **org-only** and gated behind the **Enterprise** plan's `self_hosted_runners` feature (live-verified: white-box `--code` ingestion landed a scan with 258 findings on an Enterprise org).

Two separate auth paths:

1. **Management** (JWT, org admin+): register / list / revoke runners (DRF-scoped via `HasScope`).
2. **Protocol** (`X-Runner-Token` header, deliberately unscoped `AllowAny`): heartbeat / claim / result.

#### Step A — Register a runner (one-time token)

```bash
# organization MUST be in the BODY, not the query string (see gotcha below)
curl -X POST http://localhost:8000/api/runners \
  -H "Authorization: Bearer $JWT_ADMIN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci-runner-1","organization":"<org-uuid>"}'
```

Gates, in order: `organization` resolved (404 hides existence) → caller must be **ADMIN or OWNER** (members/viewers → `403 ROLE_DENIED`; non-members → `404`) → `require_feature(organization, "self_hosted_runners")` (Enterprise only, else `403 {code: FEATURE_RESTRICTED, plan: <slug>}`).

Response `201` includes `data["token"] = "fxr_..."` — **the only time the token leaves the server** (stored as a SHA-256 hash; subsequent reads expose only `token_prefix`).

```bash
# List (scope runners:read; ADMIN/OWNER orgs only) — here ?organization is a QUERY param
curl "http://localhost:8000/api/runners?organization=<org-uuid>" -H "Authorization: Bearer $JWT_ADMIN"

# Revoke (ADMIN; hard-delete)
curl -X DELETE http://localhost:8000/api/runners/<runner-uuid> -H "Authorization: Bearer $JWT_ADMIN"
```

#### Step B — Create a runner-bound scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"mode":"whitebox","code":"/repo","organization":"<org-uuid>","runner":"<runner-uuid>"}'
```

Validation: `runner` set but `organization` None → `400 "Runner scans require an organization workspace."`; runner must belong to the same org and be active → else `400 "No active runner with that id in this workspace."`; `require_feature(... self_hosted_runners)` again. **Runner scans skip SSRF validation** (private targets are the point). The view returns `201` immediately and **never dispatches to Celery** — the scan stays `QUEUED`, waiting for the agent.

#### Step C — The runner loop (`X-Runner-Token` header)

```bash
TOKEN="fxr_..."

# Heartbeat → how many jobs are waiting for me
curl -X POST http://localhost:8000/api/runners/heartbeat \
  -H "X-Runner-Token: $TOKEN" -H 'Content-Type: application/json' \
  -d '{"version":"1.0.0"}'
# → {"pending": 1}

# Claim the next job (atomic; two agents on the same token can't both win) → or 204 No Content
curl -X POST http://localhost:8000/api/runners/claim -H "X-Runner-Token: $TOKEN"
# → {"scan_id":"...","mode":"whitebox","target":"...","config":{"code":"/repo", ...decrypted creds...}}

# Run the engine locally, then submit the report
fendix scan --code /repo --format json --output report.json
curl -X POST "http://localhost:8000/api/runners/jobs/$SCAN_ID/result" \
  -H "X-Runner-Token: $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @report.json
# → {"scan_id":"...","status":"completed"}
```

- **heartbeat:** `runner.touch(version)` stamps `last_seen_at`; returns `{pending}`. Silent > 15 min = offline.
- **claim:** iterates up to 5 oldest QUEUED scans; the conditional `UPDATE ... WHERE status=QUEUED` is the lock. Decrypts `auth`/`auth_user2` for transport (TLS). Returns `200 {scan_id, mode, target, config}` or `204`.
- **result:** scan must belong to this runner (else `404 not_found`) and be RUNNING/QUEUED (else `409 job_finished`). Body is the **engine's single-document JSON report** (`{findings, metadata}`) or `{"error":"..."}` for a failed run.

#### Step D — Ingest → dashboard

`ingest_runner_report` keys only on generic `report["findings"]` / `report["metadata"]` / `report["error"]`, so it is **format-agnostic** — a white-box `--code` report ingests identically to a DAST one (`source` accepts `whitebox`/`correlated`; `taint_chain`/`reachable`/`route`/`proven_path` all carried through; a code-only scan keys to a `REPO` asset). It runs the same finding sanitizer + fingerprint as the local engine, `bulk_create`s the rows in one transaction, sets status `COMPLETED` (or `FAILED` if error and no findings), clears encrypted creds at rest, and calls `sync_tracked_findings` so **a runner scan is indistinguishable from a locally-run one** in the dashboard, findings/issues/assets, and cross-scan lifecycle.

**Stale-claim recovery:** a RUNNING runner scan whose runner has been silent > 15 min is re-QUEUED **once**; a second failure marks it terminally failed.

#### GOTCHA 1 — Enterprise plan required

`self_hosted_runners` is enabled **only on the Enterprise plan**. Plan matrix:

| Plan | slug | self_hosted_runners | max scans/mo | concurrent |
|---|---|---|---|---|
| Free | `free` | ✗ | 5 | 1 |
| Pro | `pro` | ✗ | 100 | 3 |
| Team | `team` | ✗ | 500 | 10 |
| **Enterprise** | `enterprise` | ✓ | 0 (unlimited) | 0 (unlimited) |

`require_feature` raises `403 {code: FEATURE_RESTRICTED, plan: <slug>}` for free/pro/team. (`0` is the unlimited sentinel for scan/concurrency limits.)

#### GOTCHA 2 — `organization` must be in the BODY for mutating actions

For **runner registration** and **upgrade requests**, `organization` is a serializer **body** field — but the two behave **asymmetrically** when you wrongly pass `?organization=<id>` as a query string:

- **Upgrade request** (`POST /api/subscriptions/upgrade-request`): its serializer field is `required=False, default=None`, so a query-string org is silently ignored → `organization` resolves to `None` → the request **silently scopes to your personal subscription** (this is the bug that cost us a round-trip: the approval upgraded the personal sub, not the org). Put `organization` in the **body**.
- **Runner registration** (`POST /api/runners`): its serializer field is **required with no default**, so a query-string org (omitted from the body) **hard-fails with a 400 `"organization": ["This field is required."]`** before any org resolution — it does *not* silently personal-scope (a personal-scoped runner is impossible anyway: `Runner.organization` is a non-nullable FK).

(Asymmetry on the read side: list endpoints like `GET /api/runners?organization=`, `GET /api/scans?organization=`, `GET /api/subscriptions/current?organization=` *do* read it from the query string — only the two mutating actions above need it in the body.)

#### Upgrading an org to Enterprise (no Stripe wired)

```bash
# organization in BODY (gotcha above); caller must be OWNER of the org
curl -X POST http://localhost:8000/api/subscriptions/upgrade-request \
  -H "Authorization: Bearer $JWT_OWNER" -H 'Content-Type: application/json' \
  -d '{"plan_slug":"enterprise","organization":"<org-uuid>","company_name":"Acme","contact_email":"ops@acme.com","message":"Need runners"}'
# → 202 PENDING; a Fendix admin approves it in the Django admin (approve_selected action)
```

Approval (admin-only) flips the org's plan to the requested plan, sets `status=ACTIVE`, and resets the monthly scan limit, in one transaction. Only PENDING requests may be approved.

---

## 5. Security & gotchas (consolidated)

1. **Secret-evidence exfiltration (the cardinal rule).** A `--code` scan over a **working tree** reads gitignored files too. Local secret files (`.env`, `firebase_cred.json`, service-account keys) and their **credential evidence end up in the report**. *Live-verified.* **Never publish a working-tree report to the SaaS or a public artifact.** A CI checkout is a fresh clone of *tracked files only*, so it is inherently safe — this is the right place for white-box scans you intend to upload.

2. **SSRF egress guard (`netguard`) on private targets.** The engine protects *its own* outbound requests: it blocks loopback, link-local (incl. the cloud-metadata IP `169.254.169.254`), IPv6 ULA, and RFC1918 ranges, re-validating the concrete IP at connect time (DNS-rebinding-resistant) on up to 10 redirect hops. To scan a private/localhost/staging target, pass `--allow-private-targets` (auto-enabled when `--url` already resolves private). The SaaS backend enforces SSRF at scan-create time too — which is exactly why **runner scans skip the SSRF screen** (they run in-network on purpose).

3. **SEC-NNN finding-ID instability.** `SEC-NNN` IDs reassign across scans. For `.fendix-ignore` suppressions and any persistent mapping, key on **`endpoint` + `category`**, not the ID — that's what the matcher and the PR-comment one-click suppression both use.

4. **The Python taint engine resolution.** `--python-engine` is off by default. The **released standalone Go binary DOES bundle the embedded Python engine** (`//go:embed all:engine`; every `v*` release runs `make embed-engine` before the build), extracted to `~/.fendix/engine` on first use. White-box secrets + semgrep + textscan + native SCA always run in pure Go regardless. The deeper **AST taint analysis** (Proven-Path route binding, interprocedural taint) needs the `python/` engine, resolved in order: `--dir` → `FENDIX_ENGINE` → `~/.fendix/config` (set by `fendix engine sync`) → **embedded payload** → `./python`. **Coverage note:** the published **Docker/GHCR image ships the engine source tree at `/opt/fendix/python/`** (`FENDIX_PYTHON_ENGINE` set) — but the engine binary inside the image is built **without** the embedded payload, so if that path isn't mounted/synced the implicit `--code` path **degrades to native-Go-only with a WARN** (this is the gap our CI run hit: `python engine not available — whitebox scanning disabled`). A missing engine is **fatal (exit 2) only if `--python-engine` was passed by name**; otherwise it degrades. In the GitHub Action, `fendix engine sync` **fails loudly** if the engine can't be resolved.

5. **Private engine repo → Action may not resolve; SARIF may 403.** *Live-verified.* The engine repo is private, so `uses: abdel-rahmansaied/fendix@v1` is **unresolvable cross-repo from another private repo's runner** → use the **public GHCR image directly** (pin by digest). SARIF → Security-tab upload needs **GitHub Advanced Security**; on a private repo without GHAS it **403s** → use a `$GITHUB_STEP_SUMMARY` table or a PR comment instead.

6. **Exit codes (memorize these for CI):** `0` = clean / nothing reached `BLOCK`; `1` = `--fail-on` gate tripped (severity **and**, since v2.0, a confidence band that supports the claim — `--enforce-confidence=false` restores the old severity-only gate); `2` = scan error (engine unresolvable, discovery failed, render failure, or `--fail-on-scanner-error` + a scanner failed), or `--fail-on-coverage-gap` (`configured_complete=false`) / `--require-analyzers` (an undelivered name). `fendix verify` uses its own scheme: `0` resolved, `1` still-present, `2` unknown/not-found — `2` now also covers a partial dependency lookup failure (`pip`/`npm` return a lookup error rather than a silent resolve), a fail-closed change from earlier builds that could answer "resolved" on the same partial failure.

7. **`--enable-active` sends real attack payloads.** SQLi/command-injection/CRLF probes only run with this flag, and it prints a legal disclaimer. **Only target systems you own/control.** It is off by default in `.fendix.yaml` too.

8. **API key & runner token are shown once.** `fx_...` API keys and `fxr_...` runner tokens are returned only at creation (stored as SHA-256 hashes). Capture them immediately; they cannot be retrieved again.

9. **Refresh-token rotation.** After `POST /api/auth/refresh`, the old refresh token is blacklisted. Clients must persist the newly-returned `refresh` or the next refresh fails.

10. **No trailing slashes.** Every SaaS API resource uses `trailing_slash=False`. `POST /api/scans` is correct; `POST /api/scans/` is not.

---

## 6. Appendix

### 6.1 Endpoint quick reference (SaaS API, base `/api`, no trailing slash)

| Method | Path | Auth/Scope | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | none | Register → JWT + cookies (201) |
| POST | `/api/auth/login` | none | Login → JWT + cookies (200) or MFA challenge |
| POST | `/api/auth/mfa/challenge` | none | Complete MFA with `{mfa_token, otp}` |
| POST | `/api/auth/refresh` | none | Rotate access token |
| POST | `/api/auth/logout` | JWT | Blacklist refresh, clear cookies (205) |
| GET | `/api/auth/me` | JWT | `{id, name, email}` |
| POST | `/api/auth/password-reset` `/confirm` | none | Reset password |
| POST | `/api/auth/api-keys/create` | JWT, Pro+ | Create `fx_` key (raw key once, 201) |
| GET | `/api/auth/api-keys` | JWT, Pro+ | List keys (no raw) |
| DELETE | `/api/auth/api-keys/{id}` | JWT, Pro+ | Revoke (204) |
| POST | `/api/scans` | `scan:write` | Launch scan (201, immutable) |
| GET | `/api/scans` | `scan:read` | List (paginated; `?organization=`) |
| GET | `/api/scans/{id}` | `scan:read` | `{scan, findings}` envelope |
| DELETE | `/api/scans/{id}` | `scan:write` | Delete |
| GET\|POST | `/api/scans/{id}/report` | `reports:read` | Download/queue report (`format=html\|sarif\|pdf`) |
| GET | `/api/scans/{id}/compliance` | `scan:read` | OWASP/ASVS/PCI coverage |
| GET | `/api/scans/{id}/diff?against=<id>` | `scan:read` | new/fixed/persisting |
| POST | `/api/scans/{id}/findings/{fid}/verify` | `scan:write` | Re-test (202, pollable) |
| GET | `/api/findings` | `findings:read` | Flat finding list |
| GET | `/api/reports/{id}` | `reports:read` | Poll async report |
| GET | `/api/reports/{id}/download?token=...` | signed token | Download (no Bearer) |
| GET | `/api/verifications/{id}` | `findings:read` | Poll a verify job |
| GET | `/api/dashboard` | `scan:read` | Aggregate overview (`?organization=`) |
| POST | `/api/runners` | JWT ADMIN+, Enterprise | Register runner — **org in BODY** → `fxr_` token (once) |
| GET | `/api/runners?organization=<id>` | `runners:read` | List (ADMIN/OWNER) |
| DELETE | `/api/runners/{id}` | JWT ADMIN | Revoke |
| POST | `/api/runners/heartbeat` | `X-Runner-Token` | `{pending}` |
| POST | `/api/runners/claim` | `X-Runner-Token` | `{scan_id, mode, target, config}` or 204 |
| POST | `/api/runners/jobs/{scan_id}/result` | `X-Runner-Token` | Submit engine JSON report |
| POST | `/api/subscriptions/upgrade-request` | JWT OWNER (org) | Request plan upgrade — **org in BODY** (202) |
| GET | `/api/docs/` · `/api/redoc/` · `/api/schema/` | — | Swagger / Redoc / OpenAPI |
| GET | `/health-check/` · `/health/` | — | Health |

### 6.2 `fendix scan` flag quick reference

| Flag | Default | One-liner |
|---|---|---|
| `--url` | `""` | Black-box target (→ blackbox/hybrid) |
| `--spec` | `""` | OpenAPI spec (→ whitebox/hybrid) |
| `--code` | `""` | Source dir (→ whitebox/hybrid; implicitly enables Python engine) |
| `--diff` | `""` (bare=HEAD) | Scan only files changed vs git ref |
| `--staged` | `false` | Staged-only diff (implies `--diff`) |
| `--fast` | `false` | Native scanners only (secrets+textscan); sub-second |
| `--fail-on` | `""` | Severity floor for the gate: CRITICAL/HIGH/MEDIUM (band must also support it) |
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
| `--offline` / `--offline-db` | `false` / `""` (→ `~/.fendix/offline-db.json`) | Air-gapped dep-CVE lookups |
| `--no-native-deps` | `false` | Disable in-process Go SCA |
| `--use-pip-audit` | `false` | Shell out to `pip-audit` for Python |
| `--python-engine` | `false` | Spawn Python taint engine (explicit → fatal if missing) |
| `--no-plugins` / `--allow-repo-local-plugins` | `false` / `false` | Plugin discovery controls |
| `-v, --verbose` / `--debug-bundle` | `false` / `""` | Verbose output / redacted diagnostic tarball |

### 6.3 GitHub Action input quick reference

| Input | Default | One-liner |
|---|---|---|
| `code` | `.` | White-box source (empty to skip) |
| `url` | `""` | Black-box target (empty skips DAST) |
| `spec` | `""` | OpenAPI spec |
| `fail-on` | `HIGH` | Severity floor: CRITICAL/HIGH/MEDIUM (empty never fails). Confidence-gated since engine v2.0. |
| `diff` | `auto` | auto/true/false |
| `format` | `sarif` | sarif/json/html |
| `output` | `fendix-results.sarif` | Report path |
| `upload-sarif` | `true` | SARIF → code scanning (needs GHAS on private repos) |
| `version` | `latest` | Engine version |
| `extra-args` | `""` | Raw args appended to `fendix scan` |
| `engine_path` | `""` | Python engine dir (empty = auto) |

**Pinned image (v0.19.0):** `ghcr.io/abdel-rahmansaied/fendix@sha256:163ca22b8d36b6649a45161efa1daa51677bcd6565158e97f393dd89ec8e703d`

---

### Worked-example note (TwiScope)

TwiScope is a Django/DRF backend, so the natural integration is: (1) a developer `fendix hook install --fail-on HIGH` for commit-time secret/IaC gating; (2) a CI job using the **GHCR image directly** (TwiScope's repos are private, so the marketplace action won't resolve), running `fendix scan --code . --fail-on HIGH` against the fresh checkout (safe — tracked files only) and surfacing findings via `$GITHUB_STEP_SUMMARY` (no GHAS); and, if internal/staging API targets must be scanned, (3) an Enterprise-org **runner** inside the network performing `mode=hybrid` scans (`--url` staging + `--code` repo) and POSTing results back so they land in the dashboard with full TrackedFinding lifecycle. **Never** run a working-tree `--code` scan that gets published — TwiScope-style repos carry local `.env`/credential files that would be exfiltrated into the report.
