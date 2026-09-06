# Fendix

**DAST + SAST in one PR check. Fails only when the evidence backs the finding.**

Fendix runs a runtime probe and a static analyzer on every scan. When both engines independently flag the same vulnerability at the same endpoint the finding becomes `correlated` — the strongest signal Fendix produces. As of **v2.0** cross-engine agreement is no longer the only thing that can fail a build, and severity on its own is no longer enough: a finding at or above `--fail-on` blocks only when a deterministic confidence band supports the claim. Everything else is still reported, just downgraded, so your triage queue stays small and every build failure means something.

- **Confidence-gated builds.** A finding blocks only when its deterministic band supports it — `HIGH` always, `MEDIUM` with a corroborating signal, `LOW` never. See [`--enforce-confidence`](#scan-flags).
- **Single binary.** Drop into CI in 30 seconds. Active probes off by default; opt in with `--enable-active`.
- **Signed and silent.** Releases signed via [cosign keyless](#verifying-signed-releases) (Sigstore Fulcio). [No telemetry](#what-fendix-sends-to-the-network) — verify with `tcpdump`.
- **Open source under MIT.** Read the source, audit the wedge, fork it, ship plugins. See [ADR-007](docs/adr/ADR-007-open-source.md) for the strategic posture.

---

## Accuracy

Reproducible numbers, re-run on the current binary (`v2.0.1`, 2026-08-24):

| Track | P / R / F1 | Reproduce |
|---|---|---|
| Python taint engine (51 cases, 0 known-gap, CI-gated) | 1.000 / 1.000 / 1.000 | `cd python && PYTHONPATH=. python3 benchmark/run_benchmark.py` |
| SAST synthetic corpus (full binary, 38 TP / 0 FP / 0 FN / 18 TN) | 1.000 / 1.000 / **1.000** | `python3 scripts/accuracy/run.py --python-engine bin/fendix` |
| DAST DVWA / Juice Shop (regression coverage) | 13 found · 0 FP / 12 found · 0 FP | `fendix benchmark run --target all` |

The synthetic-corpus F1 is **1.000 — reproduced on the current binary and
CI-gated** (the one multi-hop SSRF case v0.26 disclosed as a false negative was
fixed in v0.27), not the stale v0.11.0 claim. Full methodology, caveats, and the
OWASP/Java omission are in **[BENCHMARKS.md](BENCHMARKS.md)**. Every number there
is re-runnable; a non-reproducing number is a bug.

Juice Shop's precision changed with this re-run, and the number moved for a real
reason rather than a relabel. The 2026-06-28 capture recorded 17 findings — 12
legitimate and 5 false positives, where the config-file-exposure check flagged
`/.env`, `/.git/HEAD`, `/.htaccess` and friends because Juice Shop's Express SPA
answers **any** unknown path with HTTP 200 and a byte-identical body. On v2.0.1
that scan returns 12 findings and no false positives. The committed baseline had
simply not been re-run since June. `fendix benchmark compare` does gate
precision — the same delta in the opposite direction is a −29.4% move that trips
its 10% threshold — but an improvement correctly never fails a gate, so a stale
baseline stays stale until somebody runs it. The baseline was re-captured on
v2.0.1 at the same time as this table.

---

## What Fendix sends to the network

The trust statement, before anything else.

| When | Outbound traffic |
|---|---|
| **Default scan** (`fendix scan --url ...`) | Only HTTP requests to the URL you passed. Nothing to `fendix.dev`, nothing to a vendor. |
| **Active probing** (`--enable-active`) | Probe payloads to the same target, only. Audit-logged. Off by default. |
| **`fendix scan --code ...` (white-box only)** | Reads source from disk. For dependency-CVE detection it queries **`api.osv.dev`** (Python/`requirements.txt` and npm/`package-lock.json`) and **`vuln.go.dev`** (Go modules, via govulncheck) by default. Everything else (secrets, semgrep, textscan) is local. Pass `--no-native-deps` to skip the Go dep scanner, or `--offline` to consult a local snapshot and make **zero** outbound calls. |
| **Air-gapped scan** (`--offline`) | Zero outbound. The pip and npm dep-CVE scanners read the local snapshot at `--offline-db` (default `~/.fendix/offline-db.json`, built with `fendix db update`); the Go dep scanner needs `vuln.go.dev` and is recorded as `SKIPPED` rather than silently reaching the network. |
| **`fendix scan` with no flags** | Errors out — there's no work to do. Zero outbound. |
| **Telemetry / phone-home / usage stats** | None. There is no telemetry code. Verify with `tcpdump`, or read [`go/internal/`](go/internal/) — there's nothing to find. |

Dependency-CVE lookups are the only non-target traffic Fendix makes, they only happen when you pass `--code` (or `--spec`), and `--offline` turns them off entirely. If a future release adds anything else that talks to a non-target host, it'll be opt-in, documented in this section, and named in the CHANGELOG. That's the contract.

---

## Quick Start

```bash
# 1. Install (downloads the latest release binary for your platform)
curl -fsSL https://get.fendix.dev/install.sh | sh

# 2. Run your first scan
fendix scan --url https://api.example.com --format html --output report.html

# 3. Open the report
open report.html
```

That's it. Fendix scans the API for missing security headers, CORS misconfigurations, authentication bypasses, sensitive data exposure, and rate limiting issues — all without sending any destructive payloads.

---

## Runs on every commit

Fendix is fast enough to run on the diff, not the repo. Scope a scan to just the files you changed and it finishes in milliseconds — fast enough for a pre-commit hook.

```bash
# Scan only what changed vs HEAD (working tree)
fendix scan --code . --diff

# Scan only what's staged — what a commit is about to introduce
fendix scan --code . --staged --fast      # secrets + textscan, sub-second

# Scan what changed in a PR vs the base branch
fendix scan --code . --diff=origin/main
```

`--diff` scopes the white-box scanners (secrets, textscan, semgrep) to the changed files and runs the dependency-CVE scanners only when a manifest changed. `--fast` drops semgrep (≈1.5 s startup) and the network dep lookups, leaving the instant native scanners — a staged scan of a 200-file monorepo completes in tens of milliseconds.

### Pre-commit hook

```bash
fendix hook install        # writes .git/hooks/pre-commit
fendix hook status
fendix hook uninstall
```

The hook runs `fendix scan --code . --staged --fast --fail-on HIGH` on every commit and aborts the commit if a HIGH-or-worse finding (e.g. a hardcoded secret) is staged. Bypass a single commit with `git commit --no-verify`. It honours `core.hooksPath` and refuses to clobber a pre-existing non-Fendix hook (pass `--force` to replace it).

---

## Installation

> Engine source lives in this private repo; install artifacts (binaries, Homebrew formula, install script) are published to the public mirror at [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix). All install paths below pull from the mirror.

### Homebrew (macOS / Linux)

```bash
brew tap Abdel-RahmanSaied/fendix
brew install fendix
```

### curl (macOS / Linux)

```bash
curl -fsSL https://get.fendix.dev/install.sh | sh
```

Downloads the latest release binary, verifies its sha256 checksum, and installs to `/usr/local/bin/fendix`. Override the install directory with `FENDIX_DIR=$HOME/.local/bin` and the version with `FENDIX_VERSION=v2.0.1`.

`get.fendix.dev` is the engine repo's short URL — it's a CNAME to the [`homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix) mirror, served via GitHub Pages. To inspect the script before piping to a shell:

```bash
curl -fsSL https://get.fendix.dev/install.sh | less
```

If `get.fendix.dev` is ever unreachable, the `raw.githubusercontent.com` URL is the documented fallback — see [`docs/install.md`](docs/install.md#install-script-curl--sh).

### Debian / Ubuntu (.deb)

```bash
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
VERSION=v2.0.1
URL="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${ARCH}.deb"
curl -fsSL -o fendix.deb "${URL}"
sudo dpkg -i fendix.deb && sudo apt-get install -f
```

Pulls in `python3` automatically; recommends `semgrep` for deeper static
analysis. Uninstall with `sudo apt-get remove fendix`.

### RHEL / Fedora / CentOS (.rpm)

```bash
case "$(uname -m)" in
  x86_64)  PKG_ARCH=amd64 ;;
  aarch64) PKG_ARCH=arm64 ;;
esac
VERSION=v2.0.1
sudo dnf install \
  "https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${PKG_ARCH}.rpm"
```

### Docker

```bash
docker pull ghcr.io/abdel-rahmansaied/fendix:latest
docker run --rm ghcr.io/abdel-rahmansaied/fendix scan --url https://api.example.com
```

The Docker image includes Python and all static analysis dependencies, so hybrid mode works out of the box. Available from **v0.4.1 onwards** (the v0.4.0 release predates the Docker publish workflow).

### Manual binary download

Pick a binary for your platform from the [latest release](https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/latest) (linux/amd64, darwin/amd64, darwin/arm64), verify the matching `.sha256` file, and place it on your PATH:

```bash
curl -fsSL -o fendix https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/v2.0.1/fendix-v2.0.1-darwin-arm64
shasum -a 256 fendix  # compare against the .sha256 alongside the binary
chmod +x fendix && sudo mv fendix /usr/local/bin/fendix
```

### Build from Source

Requires Go 1.21+ and Python 3.9+.

```bash
git clone https://github.com/Abdel-RahmanSaied/Fendix.git
cd Fendix
make build
./bin/fendix version
```

For white-box analysis, install Python dependencies:

```bash
pip install -r python/requirements.txt
```

---

## Verifying signed releases

Every release artifact (binary, `.deb`, `.rpm`, multi-arch Docker manifest) ships with a `.crt` + `.sig` sidecar produced by [cosign](https://docs.sigstore.dev/cosign/overview/) keyless signing — Sigstore Fulcio anchors the signature to the GitHub Actions OIDC identity that built the release. No static public key, no rotation surface, no key-loss recovery story to maintain.

Verify a binary:

```bash
VERSION=v2.0.1
ASSET=fendix-${VERSION}-linux-amd64
BASE="https://github.com/Abdel-RahmanSaied/homebrew-fendix/releases/download/${VERSION}"

curl -fsSL -o "$ASSET"     "$BASE/$ASSET"
curl -fsSL -o "$ASSET.crt" "$BASE/$ASSET.crt"
curl -fsSL -o "$ASSET.sig" "$BASE/$ASSET.sig"

cosign verify-blob \
  --certificate "$ASSET.crt" \
  --signature   "$ASSET.sig" \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer     "https://token.actions.githubusercontent.com" \
  "$ASSET"
# → Verified OK
```

Same pattern verifies a `.deb`, `.rpm`, or Docker image — swap the asset name. For Docker, use `cosign verify` (not `verify-blob`) against the image reference:

```bash
cosign verify ghcr.io/abdel-rahmansaied/fendix:v2.0.1 \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer     "https://token.actions.githubusercontent.com"
```

Releases cut before cosign signing was activated (any tag earlier than `v0.6.0-rc2`) won't have sidecar files — fall back to the `.sha256` companion in those cases. See [`SECURITY.md`](SECURITY.md) for the broader artifact-trust policy and supported-versions table.

---

## Usage Examples

### Black-box scan (HTTP probing only)

Point Fendix at a live API. No source code needed.

```bash
fendix scan --url https://api.example.com
```

This runs all passive checks: security headers, CORS, authentication bypass, sensitive data exposure, and rate limiting.

### White-box scan (static analysis only)

Analyze source code without making any network requests.

```bash
fendix scan --code ./src --spec openapi.yaml
```

This runs secrets detection, Semgrep rules, AST analysis, OpenAPI spec checks, and dependency CVE scanning.

### Hybrid scan (maximum coverage)

Run both engines and cross-correlate findings for highest confidence.

```bash
fendix scan \
  --url https://api.example.com \
  --code ./src \
  --spec openapi.yaml \
  --format html \
  --output report.html
```

When the black-box scanner and static analyzer both identify the same vulnerability, Fendix merges them into a single `correlated` finding with elevated confidence.

### Import findings from other scanners

Normalize SARIF 2.1.0 from CodeQL, Semgrep, Trivy, or another scanner and run
it through Fendix's fingerprinting, confidence, dedup, baseline, ignore, gate,
and reporting pipeline:

```bash
# Foreign findings only
fendix import codeql.sarif --fail-on HIGH --format json

# Merge one or more foreign reports into a native scan
fendix scan --code . --import codeql.sarif --import trivy.sarif --fail-on HIGH
```

`fendix import` accepts multiple files and `-` for stdin. It exits `0` when
nothing blocks, `1` when a confidence-backed finding reaches `--fail-on`, and
`2` when any input is unreadable, malformed, or not SARIF 2.1.0. A malformed
file fails the entire import so partial coverage is never presented as complete.

Imported findings remain external evidence: they carry `source: "imported"`
and never gain native reachability, taint-chain, route, or analyzer-tier claims.
An import can corroborate a native result only when a genuinely independent
tool reports the exact same CWE at the same normalized location (within five
lines). Titles, categories, fingerprints, and duplicate runs do not establish
corroboration.

### Authenticated scan

Provide credentials to test endpoints behind authentication.

```bash
# Bearer token
fendix scan --url https://api.example.com --auth "Bearer eyJhbG..."

# API key with custom header
fendix scan --url https://api.example.com \
  --auth "sk-live-abc123" \
  --auth-type apikey \
  --auth-header "X-API-Key"

# Basic auth
fendix scan --url https://api.example.com \
  --auth "admin:password" \
  --auth-type basic
```

Auth credentials are **always masked as `[REDACTED]`** in all report output.

### Active injection testing (opt-in)

Test for SQL injection, command injection, and header injection. **Off by default** — requires explicit consent.

```bash
fendix scan --url https://api.example.com --enable-active
```

A legal disclaimer is printed when active probing is enabled. Only use this against systems you own or have written authorization to test.

### CI/CD gating

Fail the pipeline if critical or high severity findings are detected.

```bash
fendix scan \
  --url https://api.staging.example.com \
  --code ./src \
  --fail-on HIGH \
  --format sarif \
  --output results.sarif
```

Exit code `1` means at least one finding reached status `BLOCK`. Exit code `0` means the scan passed.

> **Upgrading a pipeline from 1.x?** In v2.0 `--fail-on` stopped gating on
> severity alone — a finding blocks only when its deterministic confidence band
> supports the claim. **Builds that used to fail may now pass**, most often for
> shape-match SAST findings with no corroborating signal. A real hardcoded
> credential in production code still bands `HIGH` and still exits 1.
> `--enforce-confidence=false` restores the pre-2.0 severity-only mapping
> byte-for-byte. Full rule table in the [CHANGELOG](CHANGELOG.md).

### Baseline diff mode

Only report **new** findings compared to a previous scan. Ideal for PR workflows.

```bash
# Save a baseline
fendix scan --url https://api.example.com --save-baseline baseline.json

# Later, compare against it
fendix scan --url https://api.example.com --baseline baseline.json
```

### Re-render a report

Convert a saved JSON findings file to HTML or SARIF without re-scanning.

```bash
fendix report --input findings.json --format html --output report.html
```

---

## CLI Reference

### Commands

| Command | Description |
|---|---|
| `fendix scan` | Run a security scan against an API, source code, or both |
| `fendix import <file.sarif>...` | Normalize and gate on third-party SARIF 2.1.0 findings |
| `fendix report` | Re-render a saved JSON findings file to another format |
| `fendix verify <id>` | Re-run a single finding by ID to verify it still exists |
| `fendix demo` | Spin up OWASP Juice Shop in Docker and scan it — a real report in <60s |
| `fendix init` | Generate CI workflow + `.fendix.yaml` + `.fendix-ignore` starters |
| `fendix hook` | Manage the git pre-commit hook (`install` / `status` / `uninstall`) |
| `fendix ignore` | Inspect and maintain `.fendix-ignore` (`list` / `validate` / `prune`) |
| `fendix plugins` | List and install out-of-tree plugins (`list` / `install <git-url>`) |
| `fendix db` | Manage the offline CVE snapshot for air-gapped scans (`update` / `list` / `verify`) |
| `fendix engine` | Inspect or pin the Python whitebox engine (`info` / `sync`) |
| `fendix benchmark` | Run the vulnerable-app benchmark targets and score against baselines |
| `fendix notify` | Post findings above a severity floor to Slack / Teams (CI step) |
| `fendix jira` | Idempotently sync findings to Jira issues (CI step) |
| `fendix metrics` | Show locally-recorded scan metrics (opt-in via `FENDIX_METRICS`) |
| `fendix version` | Print version, OS, and architecture information |

Run `fendix <command> --help` for the flags of any subcommand.

### Scan Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--url` | string | | Target API base URL (black-box scanning) |
| `--spec` | string | | Path to OpenAPI/Swagger YAML or JSON spec |
| `--code` | string | | Path to source code directory (white-box scanning) |
| `--import` | list | | Merge a third-party SARIF 2.1.0 report into this scan (repeatable) |
| `--auth` | string | | Auth header value, e.g. `"Bearer token123"` |
| `--auth-type` | string | auto-detect | Auth type: `bearer`, `apikey`, `basic`, `cookie` |
| `--auth-header` | string | `Authorization` | Custom auth header name |
| `-o, --output` | string | stdout | Output file path |
| `-f, --format` | string | `json` | Output format: `json`, `html`, `sarif`, `pdf` |
| `--fail-on` | string | | Exit 1 if a **corroborated** finding is at this severity: `CRITICAL`, `HIGH`, `MEDIUM`. Confidence gating applies — see `--enforce-confidence`. |
| `--fail-on-scanner-error` | bool | `false` | Exit 2 if any recorded analyzer — any entry in `metadata.scanner_status`, the full registry (`dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `plugins`, the python-engine and its checks) — ran and errored. CI-friendly: turns a silent coverage gap into a build failure. Skipped entries don't count. |
| `--fail-on-coverage-gap` | bool | `false` | Exit 2 when an analyzer this run was configured to execute was unavailable or failed (`metadata.coverage.configured_complete=false`). Disabled, not-applicable and unsupported analyzers never trip it. |
| `--require-analyzers` | list | | Analyzers that must be delivered (recorded `ok` or `not_applicable`) for exit 0; anything else exits 2. Stricter than `--fail-on-coverage-gap`: `--fast --require-analyzers semgrep` is a contradiction and exits 2. |
| `--deescalate-tests` | bool | `true` | Report findings in test/fixture code (`tests/`, `test_*.py`, `*_test.py`, `conftest`, `fixtures/`) as `INFO` instead of `WARN`. The finding and its evidence are still emitted — this changes triage status, not visibility. A finding at or above `--fail-on` still blocks **when a corroborating signal backs it** (e.g. a proven taint path or a provider-validated live credential); an uncorroborated test-code match is held at `WARN`. Pass `--deescalate-tests=false` to treat test-code findings like production ones. |
| `--enforce-confidence` | bool | `true` | Only `BLOCK` a finding at or above `--fail-on` when the deterministic confidence band supports it: `LOW` band warns instead of blocking, `MEDIUM` blocks only with a corroborating signal (live observation, cross-engine agreement, deterministic detection in production code, confirmed route, reachable taint path, payload-validated probe), `HIGH` always blocks. Evidence is never suppressed, and every demotion is named in `confidence_reasons`. Pass `--enforce-confidence=false` to restore the legacy severity-only gate. |
| `--baseline` | string | | Path to previous findings JSON for diff mode |
| `--save-baseline` | string | | Save current findings to this path |
| `--enable-active` | bool | `false` | Enable active injection probes |
| `--checks` | list | `auth,injection,deps` | Override which checks the Python whitebox engine runs. Only effective with `--python-engine`; the native Go scanners always run when `--code` is set. |
| `--offline` | bool | `false` | Air-gapped mode: read dep CVEs from a local snapshot instead of `api.osv.dev`/`vuln.go.dev`. Makes zero outbound calls; the Go dep scanner is recorded `SKIPPED`. |
| `--offline-db` | string | `~/.fendix/offline-db.json` | Path to the offline-db snapshot (build it with `fendix db update`). Only effective with `--offline`. |
| `-w, --workers` | int | `10` | Concurrent HTTP workers |
| `--timeout` | int | `10` | HTTP timeout in seconds |
| `--delay` | int | `100` | Milliseconds between HTTP requests |
| `--ignore` | string | | Path to `.fendix-ignore` suppression file (an unparseable file is a hard error: exit 2) |
| `-v, --verbose` | bool | `false` | Print all requests and raw findings |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, nothing reached status `BLOCK` |
| `1` | Scan completed, at least one finding reached status `BLOCK` |
| `2` | Scan error (network failure, invalid config, etc.) |

`BLOCK` means "at or above `--fail-on` **and** the confidence band supports the
claim" — see `--enforce-confidence` above, and the rule table in the CHANGELOG.
Pass `--enforce-confidence=false` for the pre-2.0 severity-only mapping.

---

## Output Formats

### JSON (default)

Machine-readable findings with scan metadata.

```json
{
  "scan": {
    "target": "https://api.example.com",
    "timestamp": "2026-03-14T10:30:00Z",
    "duration_ms": 4521,
    "total_findings": 3,
    "by_severity": {
      "CRITICAL": 1,
      "HIGH": 1,
      "MEDIUM": 1,
      "LOW": 0,
      "INFO": 0
    }
  },
  "findings": [
    {
      "id": "SEC-001",
      "title": "Missing authentication on endpoint",
      "severity": "CRITICAL",
      "source": "correlated",
      "category": "auth",
      "endpoint": "GET /api/users",
      "evidence": "HTTP 200 returned without Authorization header",
      "fix": "Require Bearer token. Return 401 for unauthenticated requests.",
      "references": ["CWE-306", "OWASP-A01"],
      "confidence": "HIGH",
      "line": "src/routes/users.py:42"
    }
  ]
}
```

### HTML (self-contained)

A single-file HTML report with no external dependencies. Includes:

- Executive summary with severity breakdown
- Color-coded findings table (sortable by severity)
- Expandable rows with evidence and remediation
- Print-friendly CSS

```bash
fendix scan --url https://api.example.com --format html --output report.html
```

### SARIF 2.1.0 (CI/CD integration)

Standard format for static analysis results. Compatible with GitHub Code Scanning, Azure DevOps, and other CI platforms.

```bash
fendix scan --code ./src --format sarif --output results.sarif
```

**Result `level` follows the decision verdict, not raw severity** — `BLOCK` →
`error`, `WARN` → `warning`, `INFO` → `note` — so an annotation's colour
reflects what actually gates the build. A finding with no verdict stamped (a
scan with no `--fail-on`) falls back to the severity mapping below, which is
also what a *rule*'s `defaultConfiguration.level` uses:

| Fendix Severity | SARIF Level | `security-severity` |
|---|---|---|
| CRITICAL | `error` | `9.5` |
| HIGH | `error` | `8.0` |
| MEDIUM | `warning` | `5.5` |
| LOW | `note` | `3.0` |
| INFO | `note` | `1.0` |

Since v2.0 the SARIF output also carries three things GitHub Code Scanning
needs:

- `result.partialFingerprints["fendix/v1"]` — the same `sha1(Category|Endpoint|Title)`
  token `.fendix-ignore` fingerprint rules pin to, so a re-ordered scan updates
  alerts instead of closing and reopening them. Emitted only when the finding
  carries a real engine fingerprint.
- `rule.properties["security-severity"]` — the CVSS-style score GitHub ranks by
  (table above). Without it GitHub files every alert as "medium". It is a pure
  function of severity and never of confidence.
- `run.automationDetails.id` = `"fendix/scan"` — the analysis category, so two
  tools uploading SARIF for the same commit don't overwrite each other's alerts.
  Treat the value as a one-way door: changing it re-partitions existing alerts.

A rule shared by findings at several severities takes the **maximum** of them
for `defaultConfiguration.level` (v2.0; it was first-seen before). A result's
message is a description of the finding — `Hardcoded secret at src/config.py:14`
— with the raw evidence line moved to `region.snippet.text` and preserved
verbatim in `result.properties.evidence`.

---

## CI/CD Integration

Fendix's `init` command generates drop-in templates for three CI
systems:

```bash
fendix init                 # auto-detect (looks for .github/, .gitlab-ci.yml, .circleci/)
fendix init --ci github     # explicit
fendix init --ci gitlab     # writes .gitlab-ci.fendix.yml + NEXT-STEPS-fendix.md
fendix init --ci circleci   # writes .circleci/fendix-config.yml + NEXT-STEPS-fendix.md
```

For gitlab/circleci, the NEXT-STEPS file explains how to wire the
snippet into your main CI config (GitLab via `include:`, CircleCI by
merging into your single `config.yml`).

### GitHub Actions

The fastest path is the [Fendix Action](action.yml) from the Marketplace. On pull requests it runs a **diff-aware** scan (only PR-changed files) and uploads SARIF so findings land in the Security tab and as PR annotations:

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write    # required for the SARIF upload

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0      # diff-aware scanning needs git history

      - uses: abdel-rahmansaied/fendix@v1
        with:
          code: .
          url: ${{ secrets.STAGING_API_URL }}   # optional — adds DAST
          spec: openapi.yaml                     # optional
          fail-on: HIGH
```

<details>
<summary>Or wire it by hand (install script + raw CLI)</summary>

```yaml
      - uses: actions/checkout@v4
      - name: Install Fendix
        run: curl -fsSL https://get.fendix.dev/install.sh | sh
      - name: Run scan
        run: |
          fendix scan \
            --url ${{ secrets.STAGING_API_URL }} \
            --code . \
            --spec openapi.yaml \
            --fail-on HIGH \
            --format sarif \
            --output results.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

</details>

### Baseline diff in PRs

Run baseline diffs to only flag **new** vulnerabilities introduced in a PR:

```yaml
      - name: Download baseline
        run: gh release download --pattern baseline.json || echo '[]' > baseline.json

      - name: Scan with baseline
        run: |
          fendix scan \
            --code . \
            --baseline baseline.json \
            --fail-on MEDIUM
```

---

## Configuration

### .fendix-ignore

Suppress known findings or exempt endpoints from scanning. Place as `.fendix-ignore` in your project root or pass via `--ignore`.

```yaml
# Suppress by finding ID
ignore:
  - id: SEC-014
    reason: "Rate limiting handled at API gateway level"
    until: 2026-12-01  # optional expiry date

  # Suppress entire endpoint
  - endpoint: GET /health
    reason: "Public health check endpoint by design"

  # Suppress by category on specific endpoints
  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints intentionally unauthenticated"
```

See [.fendix-ignore.example](.fendix-ignore.example) for a full template.

---

## Architecture

Fendix is a hybrid scanner with two engines communicating via newline-delimited JSON over stdin/stdout:

```
User CLI Command
       |
       v
+------------------+
|   Go Binary      |
|  - CLI (cobra)   |
|  - HTTP Scanner  |  <-- Black-box: sends real HTTP requests
|  - Secrets       |  <-- White-box, native Go (TASK-115)
|  - Semgrep       |  <-- White-box, native Go: shells out to the
|  - Deps (CVE)    |      host `semgrep` with the embedded rule pack
|  - Orchestrator  |
|  - Correlator    |
|  - Reporters     |
+--------+---------+
         |
         | JSON over stdin/stdout (opt-in: --python-engine)
         |
+--------+---------+
|  Python Engine   |
|  - Spec Parser   |  <-- White-box: analyzes specs and source code
|  - AST Analyzer  |
|  - Deps Checker  |
+------------------+
```

Secrets and Semgrep were rewritten in native Go (TASK-115 / TASK-116) and their
Python wrappers were deleted in TASK-118. They now run from the Go binary
whenever `--code` is set — secrets fully in-process, Semgrep by shelling out to
the host's `semgrep` binary with a rule pack embedded via `//go:embed` (skipped
with an install hint if `semgrep` isn't on `$PATH`). Neither goes through the
Fendix Python engine, which is opt-in behind `--python-engine` and carries only
the spec parser, the AST taint analyzer, and its dependency checker.

**Why two languages?**

- **Go** excels at concurrent HTTP scanning, compiles to a single binary, and provides fast CLI startup. It now also owns the secrets scan and the Semgrep shell-out, which is what removed the Python boot tax from the default path.
- **Python** still has the strongest AST/dataflow tooling for the taint analyzer and OpenAPI spec parsing, so those analyzers stayed there.

The **correlator** is the core differentiator. When the black-box scanner confirms a vulnerability that the static analyzer also flagged, the finding is elevated to `correlated` source with `HIGH` confidence. Since v2.0 that elevation is one of eight corroborating signals the build gate reads rather than the gate itself — see [`--enforce-confidence`](#scan-flags) for the full list. (We describe this as a mechanism, not a measured false-positive reduction: no benchmark yet isolates the correlation effect — see [BENCHMARKS.md](BENCHMARKS.md).)

**How severity is determined:**

Severity is assigned discretely, then escalated and capped — not computed from
a formula at report time:

1. **The check assigns it.** Each check emits its own severity (e.g. wildcard
   CORS origin *with credentials* → CRITICAL).
2. **Correlation escalates it.** A correlated finding goes up one level; up a
   second level when the white-box half proved a reachable taint chain; and
   straight to CRITICAL for a [Proven Path](#architecture) (route-confirmed +
   reachable). Semgrep-tier findings are excluded from both escalations until
   their rule pack clears the F1 gate.
3. **Reachability escalates the pure-SAST case** one level when an AST taint
   chain is proven but nothing correlated.
4. **Confidence caps it.** `LOW` confidence caps severity at MEDIUM, `MEDIUM`
   caps at HIGH; only `HIGH` confidence may carry CRITICAL. Enforced on every
   finding before any report is written.

Separately, every finding carries a **deterministic 0–100 confidence score**
(`confidence_score`) with a per-rule plain-text breakdown in
`confidence_reasons` — base 35, cross-engine agreement +25, reachable taint
+10, route confirmed +10, validated probe payload +10, direct observation of a
live response +30, deterministic pattern match in production source +30,
analyzer tier ±5, low-trust HTTP context −15, placeholder-shaped
credential −20, advisory's affected component never imported −10. There is no
AI anywhere in that path; the same evidence always yields the same score.

<details>
<summary>Reference scoring model (spec, not the runtime path)</summary>

`go/internal/models/scoring.go` also carries the multiplicative model the
confidence cap in step 4 is derived from. It is the published spec and is
unit-tested, but **no scanner calls it** — severity comes from steps 1–4 above.

```
Score = ImpactBase[category] x ConfidenceMult[confidence] x SourceMult[source]

CRITICAL  >= 9.0    |  ImpactBase:         ConfidenceMult:   SourceMult:
HIGH      >= 7.0    |    auth_bypass: 10.0   HIGH:   1.0      correlated: 1.1
MEDIUM    >= 4.0    |    injection:    9.5   MEDIUM: 0.75     blackbox:   1.0
LOW       >= 1.0    |    secrets:      9.0   LOW:    0.5      whitebox:   0.9
INFO      <  1.0    |    idor:         8.5
                    |    data_exposure: 7.0
                    |    cors:          6.5
                    |    headers:       4.0
                    |    info_disclosure: 2.0
```

</details>

For full architectural rationale, see [ADR-001](docs/adr/ADR-001-go-python-hybrid.md) and [ADR-002](docs/adr/ADR-002-ndjson-ipc.md).

---

## Security Checks

### Black-box (HTTP Scanner)

| Check | What It Detects | Default Severity |
|---|---|---|
| **Security Headers** | Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, server version disclosure | MEDIUM - INFO |
| **CORS** | Wildcard origins with credentials, reflected origins, permissive methods | CRITICAL - LOW |
| **Authentication** | Missing auth, malformed JWT accepted, expired JWT accepted, alg:none bypass | CRITICAL |
| **Data Exposure** | Passwords/secrets/tokens in responses, stack traces, internal IPs, sequential IDs | CRITICAL - INFO |
| **Rate Limiting** | No rate limiting detected on endpoints | MEDIUM |
| **SQL Injection** | Time-based blind SQLi (MySQL, Postgres, MSSQL) | HIGH |
| **Command Injection** | Echo canary detection (safe, non-destructive) | CRITICAL |
| **Header Injection** | CRLF injection in response headers | HIGH |

Injection checks (last 3 rows) require `--enable-active`.

### White-box (Static Analysis)

| Check | What It Detects |
|---|---|
| **Secrets** | AWS keys, private keys, hardcoded passwords, API keys, JWT secrets, DB URLs, bearer tokens |
| **Semgrep Rules** | 23 bundled rules across auth (Flask/Django/FastAPI missing decorators, JWT verification disabled), injection (SQL, command, eval/exec, Django ORM raw, SSTI, pickle.loads, yaml.load), secrets (hardcoded credentials/DB URLs, AWS keys, GCP service accounts, Slack webhooks, PEM private keys), and crypto (MD5/SHA1 for passwords, legacy ciphers, `random` used for token generation) |
| **Spec Parser** | Missing security schemes in OpenAPI spec, API keys in query params, unauthenticated endpoints |
| **AST Analysis** | Python and JavaScript security-relevant patterns via AST parsing |
| **Dependencies** | Known CVEs in PyPI (`requirements.txt`, `poetry.lock`, `Pipfile.lock`), npm (`package-lock.json`) and Go modules. Since v2.0 alias-linked advisories merge into **one finding per vulnerability**, named after the canonical id (`CVE-*` > `GHSA-*` > `PYSEC-*`) — see [`docs/checks/deps.md`](docs/checks/deps.md) |

---

## Performance

Fendix is designed to keep scanner overhead well under the network latency
floor — even on a localhost target, a 1000-endpoint scan finishes in under
35 ms of pool/coordination cost.

Numbers below are from `make bench` on an Apple M1 (8 cores, Go 1.21).
Each row reflects the cost of running the worker pool against an
`httptest` server with N endpoints × 3 checks per endpoint (3N total real
HTTP roundtrips) at a fixed pool size of 32 workers.

| Endpoints | Roundtrips | Wall time | Memory   | Allocs    | Peak goroutines |
|----------:|-----------:|----------:|---------:|----------:|----------------:|
|        10 |         30 |    0.8 ms |  336 KB  |   2,896   |             130 |
|       100 |        300 |    5.1 ms |  2.6 MB  |  24,345   |             143 |
|       500 |       1500 |   19.0 ms | 12.4 MB  | 119,453   |             175 |
|      1000 |       3000 |   31.7 ms | 24.7 MB  | 238,256   |             166 |

Reading the numbers:

- **Throughput scales linearly** with endpoint count — Fendix's pool
  coordination is not the bottleneck, the HTTP transport is.
- **Memory is bounded.** ~25 KB per endpoint at 1000 endpoints, including
  finding allocation, slog formatting, and HTTP response buffers. A
  scan against 10,000 endpoints would still fit in well under 256 MB.
- **Goroutine count is bounded** by `--workers` plus a small fixed
  overhead (HTTP transport idle pool, slog handler, the test fixture's
  goroutine-tracking probe). The pool clamps to your worker budget no
  matter how many endpoints get crawled — verified by TASK-097's
  fuzzed cancellation test and the 1000-endpoint `-race` job.

Reproduce locally:

```sh
make bench                    # default, 5 iterations per size
make bench BENCHTIME=2s        # longer runs, more stable numbers
```

Real-world scans against remote targets are network-bound, not
Fendix-bound — expect the per-endpoint wall time to be dominated by
the round-trip latency to your target, plus `--delay` (default
100 ms) between requests. Use `--max-requests` and `--max-duration`
to bound total work.

For component-level micro-benchmarks (correlator, JSON parser, severity
scoring, reporters), run `cd go && go test -bench . -benchmem ./...`.

---

## How to Add a Check

Fendix is designed to be extensible. Here's how to add a new security check:

### Adding a black-box check (Go)

1. Create a new file in `go/internal/scanner/` (e.g., `mycheck.go`)
2. Implement the `CheckFn` signature:

```go
package scanner

import (
    "context"
    "github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// CheckMyThing scans for [describe what it checks].
func CheckMyThing(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []models.Finding {
    var findings []models.Finding

    // 1. Send HTTP request(s) to endpoint.FullURL
    // 2. Analyze response
    // 3. If issue found, append to findings

    return findings
}
```

3. Write table-driven tests in `mycheck_test.go` using `net/http/httptest`
4. Register the check in the orchestrator (`go/internal/engine/orchestrator.go`)
5. Document the check in `docs/checks/mycheck.md`

### Adding a white-box check

**Pick the layer first.** Not every white-box check belongs in Python:

| Kind of check | Where it goes |
|---|---|
| Secret / credential patterns | Go — `go/internal/scanner/secrets/` (native since TASK-115) |
| A Semgrep rule | Go — `go/internal/scanner/semgrep/rules/` (embedded pack; see below) |
| Dependency CVEs | Go — `go/internal/scanner/deps/` |
| AST / taint analysis, OpenAPI spec analysis | Python — `python/analyzers/` (runs only under `--python-engine`) |

`python/analyzers/secrets.py` and `python/analyzers/semgrep_runner.py` were
deleted in TASK-118; asking the Python engine for `secrets` or `semgrep` is a
no-op that logs a notice. Do not add either kind of check there.

#### Python analyzer (AST / spec)

1. Create a new analyzer in `python/analyzers/` (e.g., `myanalyzer.py`)
2. Implement the analyzer class:

```python
class MyAnalyzer:
    """Describe what this analyzer detects."""

    def __init__(self, code_path: str) -> None:
        self.code_path = code_path

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        # Walk files, analyze, call emit_fn with Finding dicts
        emit_fn({
            "title": "Issue found",
            "severity": "HIGH",
            "source": "whitebox",
            "category": "mycategory",
            "endpoint": "file.py:42",
            "evidence": "what was found",
            "fix": "how to fix it",
            "references": ["CWE-XXX"],
            "confidence": "MEDIUM",
            "line": "file.py:42"
        })
```

3. Write pytest tests in `python/tests/test_myanalyzer.py`
4. Register the analyzer in `python/engine.py`

### Adding a Semgrep rule

Add a YAML rule file to `go/internal/scanner/semgrep/rules/` (the
embedded rule pack — //go:embed picks up every `.yaml` at build time):

```yaml
rules:
  - id: my-custom-rule
    pattern: dangerous_function($INPUT)
    message: "Potentially unsafe use of dangerous_function"
    severity: WARNING
    languages: [python]
    metadata:
      cwe: CWE-XXX
      category: mycategory
```

Semgrep rules are automatically picked up by the Semgrep runner.

---

## Project Structure

```
fendix/
├── go/                          # Go layer — CLI, HTTP scanner, orchestrator
│   ├── cmd/fendix/main.go       # CLI entrypoint (cobra)
│   ├── internal/
│   │   ├── scanner/             # Black-box checks + native white-box scanners
│   │   │   ├── secrets/         # Native Go secrets scan (TASK-115)
│   │   │   ├── semgrep/         # Semgrep shell-out (TASK-116)
│   │   │   │   └── rules/       # Bundled Semgrep YAML pack (//go:embed) — THE live pack
│   │   │   └── deps/            # Dependency CVE scanners
│   │   ├── engine/              # Orchestrator + correlator
│   │   ├── models/              # Finding, ScanConfig, severity scoring
│   │   └── reporters/           # JSON, HTML, SARIF renderers
│   ├── go.mod
│   └── go.sum
├── python/                      # Python layer — opt-in via --python-engine
│   ├── engine.py                # Entrypoint: reads stdin, streams findings
│   ├── analyzers/               # Spec parser, AST taint analyzer, deps
│   ├── rules/                   # Legacy YAML rules — read by NO code; see CONTRIBUTING.md
│   └── tests/                   # pytest test suite
├── docs/
│   ├── adr/                     # Architecture Decision Records
│   └── checks/                  # One page per check explaining detection logic
├── scripts/                     # Build and install scripts
├── .github/workflows/           # CI/CD workflows
├── Makefile                     # make build, test, lint, clean
└── Dockerfile                   # Multi-stage build
```

---

## Development

### Prerequisites

- Go 1.21+
- Python 3.9+
- Make

### Build and test

```bash
make build          # Build Go binary to bin/fendix
make test           # Run Go and Python tests
make lint           # Run gofmt, go vet, ruff, black
make clean          # Remove build artifacts and caches
```

### Running tests individually

```bash
# Go tests
cd go && go test -race -v ./...

# Python tests
cd python && python -m pytest tests/ -v
```

---

## Documentation

- [Install reference](docs/install.md) — every install path (Homebrew, apt/dnf, Docker, source) with cosign verification.
- [5-minute walkthrough — OWASP Juice Shop](docs/walkthrough-juice-shop.md) — try a real hybrid scan in under 5 minutes.
- [CI/CD integration](docs/ci-cd-integration.md) — drop-in GitHub Actions workflow with SARIF upload and PR comment.
- [Triage workflow](docs/triage-workflow.md) — what to do when a report lands.
- [JSON schema reference](docs/schema.md) — every field of the JSON output, with stability guarantees.
- [Semgrep rule guide](docs/semgrep-rules.md) — write project-specific static-analysis rules.
- [Per-check reference](docs/checks/) — one page per built-in check.
- [Architecture decision records](docs/adr/) — why Fendix is built the way it is.
- [Trust Center](docs/trust-center.md) — one index for security posture, HIGH-finding status, signing/verification, and how to reproduce every claim.
- [Privacy & data handling](docs/privacy.md) — what Fendix reads, sends (nothing but opt-in CVE lookups), and stores. No telemetry.
- [Security policy](SECURITY.md) and [active-scanner threat model](docs/threat-model.md).

---

## Responsible Use

Fendix is a security testing tool designed for **authorized use only**.

- **Always get written permission** before scanning systems you do not own
- **Active probing** (`--enable-active`) sends payloads that may trigger alerts or affect system behavior — use only in controlled environments
- **Never use Fendix against production systems** without explicit authorization from the system owner
- Fendix is intended for security professionals, developers testing their own APIs, and CI/CD pipelines scanning pre-deployment code

Misuse of security scanning tools may violate applicable laws. The authors assume no liability for unauthorized use.

## License

MIT License. See [LICENSE](LICENSE) for details.
