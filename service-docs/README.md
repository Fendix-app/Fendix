# Fendix — Service Documentation

> **Fendix** is a hybrid API and code security scanner that combines black-box HTTP probing with white-box static analysis to find vulnerabilities before attackers do.
>
> ⚠️ **Partially superseded — verify before relying on it.** Large parts of this
> document were written pre-v0.5 and describe an architecture that has since
> moved. Corrected in this pass: the Semgrep rule catalog and its location, and
> the Project Status table and the inline "Phase 4 — future" annotations (Phase 4
> shipped long ago). **Still unreviewed:** the per-check descriptions and the
> hardcoded CVE tables.
>
> Current sources of truth:
> [`README.md`](../README.md) (user-facing behaviour + architecture),
> [`docs/schema.md`](../docs/schema.md) (JSON output contract),
> [`docs/MODULE_MAP.md`](../docs/MODULE_MAP.md) (what each package does),
> [`CHANGELOG.md`](../CHANGELOG.md) (what shipped when),
> [`tasks/PHASES.md`](../tasks/PHASES.md) (roadmap status).
> Current release: **v1.1.0**.

---

## Table of Contents

1. [What Fendix Is](#what-fendix-is)
2. [Architecture Overview](#architecture-overview)
3. [Quick Start](#quick-start)
4. [Installation](#installation)
5. [CLI Reference](#cli-reference)
6. [Scan Modes](#scan-modes)
7. [Black-Box Checks (Go)](#black-box-checks-go)
8. [White-Box Analyzers (Python)](#white-box-analyzers-python)
9. [Semgrep Rules](#semgrep-rules)
10. [Authentication](#authentication)
11. [Output Formats](#output-formats)
12. [Severity Scoring Model](#severity-scoring-model)
13. [CI/CD Integration](#cicd-integration)
14. [IPC Data Contract](#ipc-data-contract)
15. [Configuration Files](#configuration-files)
16. [Safety and Constraints](#safety-and-constraints)
17. [Project Status](#project-status)

---

## What Fendix Is

Fendix is a developer-first security scanner with two engines:

| Engine | Language | Type | What It Does |
|--------|----------|------|--------------|
| **Black-box** | Go | Live HTTP probing | Sends requests to a running API and detects vulnerabilities from responses |
| **White-box** | Python | Static analysis | Analyzes source code, OpenAPI specs, and dependencies without making network requests |
| **Hybrid** | Both | Correlated findings | When both engines detect the same vulnerability, the finding becomes `correlated` with HIGH confidence |

One CLI, two engines, one unified report.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                  fendix scan                     │
│              (Go CLI — cobra)                    │
├─────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────────┐   ┌──────────────────┐    │
│  │  Black-box Engine │   │  White-box Engine │    │
│  │      (Go)         │   │    (Python)        │    │
│  │                    │   │                    │    │
│  │  • Auth checks     │   │  • Secrets regex   │    │
│  │  • CORS checks     │   │  • AST analysis    │    │
│  │  • Header checks   │   │  • Semgrep rules   │    │
│  │  • Exposure checks │   │  • OpenAPI parser   │    │
│  │  • Rate limit      │   │  • Dep CVE checker  │    │
│  │  • IDOR checks     │   │                    │    │
│  └────────┬───────────┘   └────────┬───────────┘    │
│           │                         │                │
│           └─────────┬───────────────┘                │
│                     ▼                                │
│           ┌──────────────────┐                       │
│           │   Correlator      │  (shipped — Phase 4) │
│           │  Merge + dedupe   │                       │
│           └────────┬─────────┘                       │
│                    ▼                                 │
│           ┌──────────────────┐                       │
│           │   Reporter        │                       │
│           │  JSON / HTML      │                       │
│           └──────────────────┘                       │
└─────────────────────────────────────────────────┘
```

**Key decisions:**

| Decision | Choice | Reason |
|----------|--------|--------|
| Black-box engine | Go | Speed, concurrency, single binary |
| White-box engine | Python | Best security tooling ecosystem (Semgrep, Bandit, detect-secrets) |
| IPC | Newline-delimited JSON over stdin/stdout | Simple, debuggable, no infrastructure required |
| CLI framework | cobra | Industry standard |
| Active probes | Off by default | Never damage a target without explicit `--enable-active` |
| Credentials in reports | Always `[REDACTED]` | Reports safe to share |

---

## Quick Start

### Scan a live API (black-box)

```bash
fendix scan --url https://api.example.com
```

### Scan with authentication

```bash
fendix scan --url https://api.example.com --auth "Bearer eyJ..."
```

### Scan source code (white-box)

```bash
echo '{"mode":"whitebox","code_path":"./src","checks":["secrets","injection","deps"]}' \
  | python python/engine.py
```

### Scan both (hybrid) — with HTML report

```bash
fendix scan \
  --url https://api.example.com \
  --spec ./openapi.yaml \
  --code ./src \
  --auth "Bearer token" \
  --format html \
  --output report.html
```

### Fail CI if CRITICAL findings

```bash
fendix scan --url https://api.example.com --fail-on CRITICAL
# Exit code 1 if any CRITICAL findings, exit code 0 otherwise
```

---

## Installation

### Build from source

```bash
git clone https://github.com/Fendix-app/Fendix.git
cd fendix
make build
# Binary at: ./bin/fendix
```

### Requirements

- **Go 1.21+** — for the CLI and black-box engine
- **Python 3.10+** — for the white-box engine
- **pip packages:** `pyyaml` (required), `semgrep` (optional, enables Semgrep rules)

### Install Python dependencies

```bash
pip install pyyaml
# Optional: pip install semgrep  (enables Semgrep rule scanning)
```

### Verify installation

```bash
fendix version
# fendix version dev (darwin/arm64)

make test
# Runs go test + python pytest — all tests must pass
```

---

## CLI Reference

### Commands

| Command | Description | Status |
|---------|-------------|--------|
| `fendix scan` | Run a security scan | Implemented |
| `fendix version` | Print version and platform | Implemented |
| `fendix report` | Re-render saved findings to HTML/SARIF | Implemented |
| `fendix verify [id]` | Re-test a specific finding | Implemented (`go/cmd/fendix/main.go` — `verify [finding-id]`) |

> This table is **not exhaustive** — it predates several command groups
> (`demo`, `init`, `plugins`, `benchmark`, `db`, `engine`, `metrics`, `jira`,
> `notify`). Run `fendix --help` for the authoritative list.

### Scan Flags

#### Target flags (at least one required)

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Target API base URL (enables black-box scanning) |
| `--spec` | — | Path to OpenAPI/Swagger YAML or JSON spec |
| `--code` | — | Path to source code directory (enables white-box scanning) |

#### Authentication flags

| Flag | Default | Description |
|------|---------|-------------|
| `--auth` | — | Auth header value, e.g. `"Bearer token123"` |
| `--auth-type` | auto-detect | Auth type: `bearer`, `apikey`, `basic`, `cookie` |
| `--auth-header` | `Authorization` | Custom auth header name |
| `--auth-user2` | — | Second user credentials for IDOR detection |
| `--profile` | — | Auth profile name from `~/.fendix/profiles/<name>.yaml` |

#### Output flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | stdout | Output file path |
| `--format` | `-f` | `json` | Output format: `json`, `html`, `sarif` |
| `--fail-on` | — | — | Exit 1 if findings at severity: `CRITICAL`, `HIGH`, `MEDIUM` |
| `--baseline` | — | — | Path to previous findings JSON for diff mode |
| `--save-baseline` | — | — | Save current findings to this path |

#### Behavior flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--enable-active` | — | `false` | Enable active injection probes (SQL injection, etc.) |
| `--workers` | `-w` | `10` | Concurrent HTTP workers |
| `--timeout` | — | `10` | HTTP timeout in seconds |
| `--delay` | — | `100` | Milliseconds delay between HTTP requests |
| `--ignore` | — | — | Path to `.fendix-ignore` suppression file |
| `--verbose` | `-v` | `false` | Print all requests and raw findings |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no findings at `--fail-on` threshold (or no threshold set) |
| `1` | Scan complete, findings found at or above `--fail-on` threshold |
| `2` | Scan error (no endpoints found, invalid input, etc.) |

---

## Scan Modes

### Black-box only (live API)

```bash
fendix scan --url https://api.example.com --auth "Bearer token"
```

What happens:
1. **Crawl endpoints**: Parse OpenAPI spec (if `--spec`), extract paths from JavaScript, brute-force common paths
2. **Run passive checks**: Headers, CORS, Exposure, Rate Limiting on every discovered endpoint
3. **Run auth checks**: Unauthenticated access, JWT bypass (malformed/expired/alg:none) if `--auth` is provided
4. **Run IDOR check**: Two-account comparison if both `--auth` and `--auth-user2` are provided
5. **Render report**: JSON or HTML with credential masking

### White-box only (static analysis)

```bash
echo '{"mode":"whitebox","code_path":"./src","checks":["secrets","injection","deps"]}' \
  | python python/engine.py
```

What happens:
1. **Secrets scan**: Regex patterns for 7 secret types (AWS keys, passwords, JWTs, etc.)
2. **AST analysis**: Python `ast` module + JS regex heuristics for dangerous patterns
3. **Semgrep rules**: Custom rules for auth, injection, secrets (if semgrep installed)
4. **Dependency check**: Known CVE matching against requirements.txt / package.json
5. **Spec analysis**: OpenAPI auth checks (if `--spec` provided)

### Hybrid (both engines)

```bash
fendix scan --url https://api.example.com --spec openapi.yaml --code ./src
```

The correlator (shipped in Phase 4) correlates findings from both engines. When both the HTTP scanner and static analysis agree on the same issue, the finding becomes `correlated` with elevated confidence.

---

## Black-Box Checks (Go)

All checks are in `go/internal/scanner/`. Each check sends real HTTP requests and interprets responses.

### Authentication Checks (`auth.go`)

Requires `--auth` flag. Detects 4 vulnerabilities:

| Finding | Severity | CWE | How It Works |
|---------|----------|-----|--------------|
| Missing authentication on endpoint | CRITICAL | CWE-306 | Sends request without Authorization header; flags if server returns 200 |
| JWT not validated (malformed) | CRITICAL | CWE-287 | Sends a corrupted JWT; flags if server still accepts it |
| Expired JWT accepted | CRITICAL | CWE-613 | Generates an HS256 JWT with `exp` in the past; flags if accepted |
| JWT algorithm confusion (alg:none) | CRITICAL | CWE-327 | Sends JWT with `alg:none` and no signature; flags if accepted |

**Note:** JWT checks only run when the auth value looks like a JWT (3-part dot-separated string).

### CORS Checks (`cors.go`)

Sends OPTIONS preflight from `evil.example.com`:

| Finding | Severity | CWE | Condition |
|---------|----------|-----|-----------|
| CORS wildcard origin with credentials | CRITICAL | CWE-942 | `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` |
| CORS allows any origin | MEDIUM | CWE-942 | `Access-Control-Allow-Origin: *` without credentials |
| CORS reflects arbitrary origin | HIGH | CWE-942 | Server echoes the attacker's Origin header back |
| CORS allows non-standard method | LOW | CWE-942 | `Access-Control-Allow-Methods` includes unusual HTTP methods |

### Security Headers (`headers.go`)

| Finding | Severity | CWE | Expected Value |
|---------|----------|-----|----------------|
| Missing Strict-Transport-Security | MEDIUM | CWE-319 | Present with valid `max-age` |
| Missing/incorrect X-Content-Type-Options | LOW | CWE-693 | `nosniff` |
| Missing/incorrect X-Frame-Options | LOW | CWE-1021 | `DENY` or `SAMEORIGIN` |
| Missing Content-Security-Policy | MEDIUM | CWE-693 | Present with valid directives |
| Server version disclosed | INFO | CWE-200 | No version number in `Server` header |
| X-Powered-By discloses technology | INFO | CWE-200 | Header should not exist |

### Sensitive Data Exposure (`exposure.go`)

Scans response bodies (up to 1 MB) for:

| Finding | Severity | CWE | Pattern |
|---------|----------|-----|---------|
| Password exposed in response | CRITICAL | CWE-200 | `"password": "..."` |
| Secret/API key exposed | CRITICAL | CWE-200 | `"secret"`, `"api_key"`, `"api_secret"` with 8+ char values |
| Token exposed in response | HIGH | CWE-200 | `"token"`, `"access_token"`, `"refresh_token"` with 20+ char values |
| Stack trace in error response | MEDIUM | CWE-209 | Python traceback, Java/Go stack trace patterns |
| Internal IP address disclosed | LOW | CWE-200 | RFC1918 addresses (10.x, 172.16-31.x, 192.168.x) |
| Software version string | INFO | CWE-200 | `version: X.Y.Z` patterns |

### Rate Limit Detection (`ratelimit.go`)

| Finding | Severity | CWE | How |
|---------|----------|-----|-----|
| No rate limiting detected | MEDIUM | CWE-770 | Sends 20 rapid requests; flags if no 429 status or rate-limit headers seen |

Monitors headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`, `RateLimit-*`.

### IDOR Detection (`idor.go`)

Requires both `--auth` and `--auth-user2`:

| Finding | Severity | CWE | How |
|---------|----------|-----|-----|
| Identical responses for different users | HIGH | CWE-639 | Sends same request with two user credentials; flags if responses are identical (status + body) |

### Endpoint Crawler (`crawler.go`)

Discovers endpoints via three strategies:

1. **OpenAPI spec parsing** — Supports Swagger 2.0 and OpenAPI 3.x (YAML/JSON)
2. **JavaScript source analysis** — Extracts `/api/...` paths from HTML and JS files
3. **Common path brute-force** — Tests ~40 paths: `/api`, `/api/v1`, `/health`, `/swagger.json`, `/graphql`, etc.

Results are deduplicated by method+path.

---

## White-Box Analyzers (Python)

All analyzers are in `python/analyzers/`. Each is independently unit tested and runnable without Go.

### Secrets Analyzer (`secrets.py`)

Detects 7 hardcoded secret pattern types:

| Pattern | Severity | CWE | Example Match |
|---------|----------|-----|---------------|
| AWS Access Key ID | CRITICAL | CWE-798 | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Access Key | CRITICAL | CWE-798 | `aws_secret_key = "wJalrXUt..."` |
| Private key (PEM) | CRITICAL | CWE-321 | `-----BEGIN RSA PRIVATE KEY-----` |
| Generic API key/token | HIGH | CWE-798 | `api_key = "sk-live-abcdef..."` |
| Hardcoded password | HIGH | CWE-259 | `password = "hunter2"` |
| JWT token | HIGH | CWE-798 | `eyJhbGci...` (3-part base64) |
| Database connection string | HIGH | CWE-214 | `postgresql://admin:pass@host/db` |

**Skipped directories:** `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, `dist`, `build`
**Max file size:** 1 MB
**Scanned extensions:** `.py`, `.js`, `.ts`, `.go`, `.java`, `.rb`, `.php`, `.env`, `.yaml`, `.json`, `.tf`, `.sh`, and more
**Safety:** Evidence is truncated; secret values are never shown in full.

### AST Analyzer (`ast_analyzer.py`)

#### Python (stdlib `ast` module — deep analysis)

| Finding | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `SEC-PY_EVAL` | HIGH | CWE-95 | `eval(variable)` / `exec(variable)` — only flags dynamic args, not string literals |
| `SEC-PY_OS_SYSTEM` | HIGH | CWE-78 | `os.system(cmd)` — any usage flagged |
| `SEC-PY_SUBPROCESS_SHELL` | HIGH | CWE-78 | `subprocess.run(cmd, shell=True)` and variants |
| `SEC-PY_SQL_INJECTION` | CRITICAL | CWE-89 | `cursor.execute(f"... {var} ...")` or `"..." % var` — parameterized queries NOT flagged |

**Smart filtering:**
- `eval("1 + 1")` with a string literal is NOT flagged (safe)
- `cursor.execute("SELECT ... WHERE x = %s", (val,))` parameterized query is NOT flagged (safe)

#### JavaScript (regex heuristics)

| Finding | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `SEC-JS_EVAL` | HIGH | CWE-95 | `eval(...)` usage |
| `SEC-JS_INNER_HTML` | HIGH | CWE-79 | `.innerHTML = ...` assignment (XSS) |
| `SEC-JS_DOCUMENT_WRITE` | MEDIUM | CWE-79 | `document.write(...)` usage (XSS) |
| `SEC-JS_SQL_TEMPLATE` | HIGH | CWE-89 | SQL in template literals: `` `SELECT ... ${var}` `` |

Minified JS lines (>500 chars) are skipped.

### OpenAPI Spec Parser (`spec_parser.py`)

Supports both **OpenAPI 3.x** and **Swagger 2.0** in YAML or JSON:

| Finding | Severity | CWE | Condition |
|---------|----------|-----|-----------|
| `SEC-SPEC-NO-GLOBAL-AUTH` | MEDIUM | CWE-306 | Spec defines security schemes but no top-level `security` field |
| `SEC-SPEC-HTTP-SCHEME` | HIGH | CWE-319 | Swagger 2.0 includes `http` in `schemes` array |
| `SEC-SPEC-HTTP-SERVER` | HIGH | CWE-319 | OpenAPI 3.x server URL starts with `http://` |
| `SEC-SPEC-NO-AUTH` | HIGH | CWE-306 | Endpoint has no `security` field and no global security |
| `SEC-SPEC-OPEN-ENDPOINT` | MEDIUM/HIGH | CWE-306 | Endpoint has `security: []` (explicitly public) |
| `SEC-SPEC-BASIC-AUTH` | MEDIUM | CWE-522 | Spec uses HTTP Basic authentication scheme |
| `SEC-SPEC-PARSE` | MEDIUM | — | Spec file could not be parsed (invalid YAML/JSON) |

### Dependency CVE Checker (`deps.py`)

Scans `requirements.txt` (PyPI) and `package.json` (npm):

**Detection methods (priority order):**
1. `pip-audit` for PyPI / `npm audit` for npm (if installed — network-enabled)
2. Local known-vulnerable version list (offline fallback)

**Known PyPI CVEs (local fallback):**

| Package | Vulnerable Below | CVE | Severity |
|---------|-----------------|-----|----------|
| pyyaml | 5.1 | CVE-2017-18342 | CRITICAL |
| pillow | 9.0.1 | CVE-2022-22817 | CRITICAL |
| requests | 2.20.0 | CVE-2018-18074 | HIGH |
| urllib3 | 1.26.5 | CVE-2021-33503 | HIGH |
| cryptography | 41.0.0 | CVE-2023-23931 | HIGH |
| django | 3.2.19 | CVE-2023-31047 | HIGH |
| flask | 2.3.2 | CVE-2023-30861 | HIGH |
| werkzeug | 3.0.3 | CVE-2024-34069 | HIGH |
| jinja2 | 3.1.3 | CVE-2024-22195 | MEDIUM |
| paramiko | 3.4.0 | CVE-2023-48795 | MEDIUM |

**Known npm CVEs (local fallback):**

| Package | Vulnerable Below | CVE | Severity |
|---------|-----------------|-----|----------|
| minimist | 1.2.6 | CVE-2021-44906 | CRITICAL |
| lodash | 4.17.21 | CVE-2021-23337 | HIGH |
| axios | 0.21.1 | CVE-2020-28168 | MEDIUM |
| node-forge | 1.3.0 | CVE-2022-0122 | MEDIUM |

**Unpinned dependencies** (e.g. `pyyaml>=5.0`) with known CVEs emit an `INFO` advisory.

---

## Semgrep Rules

The live rule pack is **`go/internal/scanner/semgrep/rules/`**, embedded into
the Go binary with `//go:embed rules/*.yaml` and extracted to a temp dir on the
first scan. Requires `semgrep` installed (`pip install semgrep`); if the binary
is not on `$PATH` the scanner returns `ErrSemgrepUnavailable` and the
orchestrator logs an install hint and continues.

> `python/rules/` is **dead** — no code reads it. The Python semgrep wrapper was
> deleted in TASK-118. A rule added there never runs. See `CONTRIBUTING.md` →
> "Adding a Semgrep rule".

**23 rules** across four files.

### auth.yaml (5 rules)

| Rule ID | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `flask-missing-login-required` | HIGH | CWE-306 | Flask `@app.route()` without `@login_required` |
| `django-view-missing-login-required` | MEDIUM | CWE-306 | Django view class without `LoginRequiredMixin` |
| `fastapi-route-missing-auth-dependency` | MEDIUM | CWE-306 | FastAPI route without `Depends(...)` |
| `python-jwt-decode-no-verification` | CRITICAL | CWE-347 | `jwt.decode()` with `verify_signature=False` or `algorithms=["none"]` |
| `flask-route-no-auth-decorator` | MEDIUM | CWE-306 | Flask route with no auth-style decorator at all (`@login_required`, `@requires_auth`, `@jwt_required`, …) |

### crypto.yaml (4 rules)

| Rule ID | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `python-md5-used-for-password` | HIGH | CWE-327 | `hashlib.md5()` on a password-shaped variable |
| `python-sha1-used-for-password` | HIGH | CWE-327 | `hashlib.sha1()` on a password-shaped variable |
| `python-legacy-cipher-import` | HIGH | CWE-327 | Legacy/broken symmetric cipher imported (DES, 3DES, RC4, ARC2, Blowfish) |
| `python-random-for-token-generation` | HIGH | CWE-338 | `random` used inside a function whose name implies a security-sensitive value |

### injection.yaml (8 rules)

| Rule ID | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `python-sql-injection-string-format` | CRITICAL | CWE-89 | `cursor.execute("..." % val)` or f-string SQL |
| `python-command-injection-shell-true` | CRITICAL | CWE-78 | `subprocess.run(cmd, shell=True)`, `os.system()`, `os.popen()` |
| `python-eval-injection` | CRITICAL | CWE-95 | `eval(x)` / `exec(x)` with dynamic arguments |
| `django-orm-raw-sql` | HIGH | CWE-89 | Django ORM raw SQL with a non-literal argument |
| `flask-render-template-string-injection` | HIGH | CWE-94 | `render_template_string()` with a non-literal template (SSTI) |
| `python-subprocess-shell-true-with-variable` | CRITICAL | CWE-78 | `subprocess` with `shell=True` and a non-literal command |
| `python-pickle-loads-untrusted` | HIGH | CWE-502 | `pickle.loads()` on a non-literal byte string |
| `python-yaml-load-unsafe` | HIGH | CWE-502 | `yaml.load()` without `SafeLoader` |

### secrets.yaml (6 rules)

| Rule ID | Severity | CWE | What It Catches |
|---------|----------|-----|-----------------|
| `python-hardcoded-secret-assignment` | CRITICAL | CWE-798 | `password = "value"`, `api_key = "value"`, etc. |
| `python-hardcoded-db-url` | HIGH | CWE-214 | `DB_URL = "postgresql://user:pass@host/db"` |
| `python-gcp-service-account-inline` | CRITICAL | CWE-798 | Inline GCP service-account JSON |
| `python-aws-access-key-id-literal` | CRITICAL | CWE-798 | AWS access-key ID literal |
| `python-slack-webhook-url-literal` | HIGH | CWE-798 | Hardcoded Slack incoming-webhook URL |
| `python-pem-private-key-literal` | CRITICAL | CWE-798 | PEM-encoded private key literal |

---

## Authentication

### Auth Resolution Priority

Fendix resolves authentication from three sources in priority order:

```
1. CLI flag:  --auth "Bearer token"
2. Env var:   FENDIX_AUTH=Bearer token
3. Profile:   ~/.fendix/profiles/<name>.yaml
```

### Auto-Detection

If `--auth-type` is not specified, Fendix auto-detects:

| Value Pattern | Detected Type |
|--------------|---------------|
| `Bearer ...` | `bearer` |
| `Basic ...` | `basic` |
| `key=value` | `cookie` |
| Anything else | `bearer` |

### Auth Types

| Type | Header | Example |
|------|--------|---------|
| `bearer` | `Authorization: Bearer <token>` | `--auth "Bearer eyJ..."` |
| `apikey` | `<custom-header>: <key>` | `--auth "sk-live-abc" --auth-type apikey --auth-header X-API-Key` |
| `basic` | `Authorization: Basic <b64>` | `--auth "Basic dXNlcjpwYXNz"` |
| `cookie` | `Cookie: <value>` | `--auth "session=abc123" --auth-type cookie` |

### Profile Files

Store credentials in `~/.fendix/profiles/<name>.yaml`:

```yaml
auth:
  type: bearer
  value: "eyJhbGciOiJIUzI1NiIs..."
  header: "Authorization"
```

Usage:

```bash
fendix scan --url https://api.example.com --profile production
# Loads ~/.fendix/profiles/production.yaml
```

### IDOR Testing (Two-Account)

To test for Insecure Direct Object Reference, provide credentials for two users:

```bash
fendix scan --url https://api.example.com \
  --auth "Bearer user1-token" \
  --auth-user2 "Bearer user2-token"
```

Fendix sends the same request with both credentials and flags endpoints where responses are identical (broken access control).

### Credential Safety

**All credentials are masked as `[REDACTED]` in every report output.** This is enforced at the orchestrator level via `SanitizeFindings()` — a defense-in-depth measure that runs before any reporter renders output.

---

## Output Formats

### JSON (default)

```bash
fendix scan --url https://api.example.com --format json -o report.json
```

Structure:

```json
{
  "metadata": {
    "target": "https://api.example.com",
    "started_at": "2026-03-16T10:00:00Z",
    "duration": "4.2s",
    "version": "0.1.0"
  },
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 2
  },
  "total": 13,
  "findings": [
    {
      "id": "SEC-001",
      "title": "Missing authentication on endpoint",
      "severity": "CRITICAL",
      "source": "blackbox",
      "category": "auth_bypass",
      "endpoint": "GET /api/admin/users",
      "evidence": "HTTP 200 returned without Authorization header",
      "fix": "Add authentication middleware to this endpoint",
      "references": ["CWE-306"],
      "confidence": "HIGH",
      "line": null
    }
  ]
}
```

### HTML

```bash
fendix scan --url https://api.example.com --format html -o report.html
```

Features:
- Self-contained single file (no external CSS/JS dependencies)
- Dark theme with color-coded severity badges
- Summary statistics cards (CRITICAL/HIGH/MEDIUM/LOW/INFO counts)
- Collapsible finding cards with expand/collapse
- Evidence displayed in monospace font
- Print-friendly CSS
- Scan metadata footer (timestamp, duration, version)

### SARIF (Phase 6 — not yet implemented)

```bash
fendix scan --url https://api.example.com --format sarif -o results.sarif
```

Will produce GitHub-compatible SARIF 2.1.0 output for PR annotations.

---

## Severity Scoring Model

```
Score = ImpactBase[category] × ConfidenceMult[confidence] × SourceMult[source]
```

### Impact Base Scores

| Category | Base Score |
|----------|-----------|
| `auth_bypass` | 10.0 |
| `injection` | 9.5 |
| `secrets` | 9.0 |
| `idor` | 8.5 |
| `data_exposure` | 7.0 |
| `cors` | 6.5 |
| `headers` | 4.0 |
| `info_disclosure` | 2.0 |

### Multipliers

| Confidence | Multiplier |
|-----------|------------|
| HIGH | 1.0 |
| MEDIUM | 0.75 |
| LOW | 0.5 |

| Source | Multiplier |
|--------|------------|
| `correlated` | 1.1 (bonus for both engines agreeing) |
| `blackbox` | 1.0 |
| `whitebox` | 0.9 |

### Severity Thresholds

| Severity | Score Range |
|----------|------------|
| CRITICAL | >= 9.0 |
| HIGH | >= 7.0 |
| MEDIUM | >= 4.0 |
| LOW | >= 1.0 |
| INFO | < 1.0 |

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  fendix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build Fendix
        run: make build

      - name: Run security scan
        run: |
          ./bin/fendix scan \
            --url ${{ secrets.API_URL }} \
            --auth "Bearer ${{ secrets.API_TOKEN }}" \
            --format json \
            --output findings.json \
            --fail-on HIGH
        # Exit code 1 will fail the workflow if HIGH+ findings are found

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: findings.json
```

### Exit Code Behavior

Use `--fail-on` to gate your CI pipeline:

```bash
# Fail on any CRITICAL finding
fendix scan --url ... --fail-on CRITICAL

# Fail on HIGH or CRITICAL
fendix scan --url ... --fail-on HIGH

# Fail on MEDIUM, HIGH, or CRITICAL
fendix scan --url ... --fail-on MEDIUM
```

---

## IPC Data Contract

The Go and Python engines communicate via newline-delimited JSON on stdin/stdout.

### ScanRequest (Go → Python, single JSON line on stdin)

```json
{
  "mode": "whitebox",
  "spec": "./openapi.yaml",
  "code_path": "./src/",
  "language": "python",
  "checks": ["secrets", "auth", "injection", "semgrep", "deps"],
  "verbose": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | Scan mode (`whitebox`) |
| `spec` | string | Path to OpenAPI spec (optional) |
| `code_path` | string | Directory to scan (optional) |
| `language` | string | Hint for analyzers: `python`, `javascript` |
| `checks` | string[] | Which analyzers to run |
| `verbose` | bool | Enable diagnostic logging to stderr |

### Available Check Names

| Check | Analyzer | What It Does |
|-------|----------|--------------|
| `secrets` | SecretsAnalyzer | 7 secret pattern types |
| `auth` | SpecParser | OpenAPI auth issue detection |
| `semgrep` | SemgrepRunner | Custom Semgrep rule execution |
| `injection` | ASTAnalyzer | Python AST + JS heuristic injection detection |
| `deps` | DepsAnalyzer | Dependency CVE checking |

### Finding (Python → Go, one JSON object per line on stdout)

```json
{
  "id": "SEC-AWS_ACCESS_KEY",
  "title": "AWS Access Key ID hardcoded",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "AWS_ACCESS_KEY_ID = \"AKIA...",
  "fix": "Remove the hardcoded credential. Store secrets in environment variables.",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

### Stream Terminator (final line from Python)

```json
{"done": true, "total": 12}
```

On error:

```json
{"done": true, "total": 0, "error": "invalid ScanRequest JSON: ..."}
```

### Error Handling

- **Analyzer crash:** Each analyzer runs in isolation. If one crashes, the engine logs to stderr and continues with the remaining checks.
- **Invalid JSON input:** Engine exits with code 2 and emits a done terminator with `"error"` field.
- **Verbose logging:** All diagnostic messages go to stderr only — stdout is reserved for clean JSON findings.

---

## Configuration Files

### Auth Profiles (`~/.fendix/profiles/<name>.yaml`)

```yaml
auth:
  type: bearer
  value: "your-token-here"
  header: "Authorization"
```

### `.fendix-ignore` (suppression file — shipped in Phase 4)

```
# Suppress by rule ID
SEC-HEADERS-001
SEC-CORS-002

# Suppress by path
GET /health
GET /status
```

---

## Safety and Constraints

1. **Active probes require `--enable-active`** — Injection tests NEVER run without explicit opt-in
2. **Every HTTP request respects `--delay`** — Default 100ms between requests to avoid overwhelming targets
3. **Credentials always `[REDACTED]` in output** — `SanitizeFindings()` runs before any reporter
4. **Python engine independently runnable** — No Go binary required for white-box analysis
5. **Deterministic output** — Same input produces same findings in same order
6. **HTML report is self-contained** — Single file, no external CSS/JS/CDN dependencies
7. **Build must always pass** — `go build ./...`, `go test ./...`, `python -m pytest` — zero tolerance for broken builds
8. **Python crash never crashes Go** — Engine errors are caught and logged, scan continues

---

## Project Status

Phases 0–9 all shipped. Phase 4 — **Orchestration & Correlation** — is the
product's wedge, not a future item: `go/internal/engine/orchestrator.go` and
`correlator.go` / `correlator_v2.go` are the core of every hybrid scan.

| Phase | Name | Status |
|-------|------|--------|
| 0 | Foundation | ✅ Complete |
| 1 | Passive Scanner | ✅ Complete |
| 2 | Auth Scanner | ✅ Complete |
| 3 | Python Engine | ✅ Complete |
| 4 | Orchestration & Correlation | ✅ Complete — **the shipped wedge** |
| 5 | Active Scanner | ✅ Complete |
| 6 | Reporting (SARIF) | ✅ Complete |
| 7 | Distribution | ✅ Complete |
| 8 | Documentation | ✅ Complete |
| 9 | Hardening | ✅ Complete |

Phases 10–17 (post-v0.2 roadmap through v1.1) are tracked in
[`tasks/PHASES.md`](../tasks/PHASES.md); shipped scope per release is in
[`CHANGELOG.md`](../CHANGELOG.md).

Test counts are not reproduced here — they drift on every commit. Run
`make test` (or read the CI run for the tag you care about) for the live number.

### What Phase 4 delivered

All of the following shipped and are documented above:

- Go spawns the Python engine as a subprocess (now opt-in via `--python-engine`
  since TASK-118 — the default path is native Go)
- Stdin/stdout NDJSON IPC wired end-to-end (ADR-002)
- Correlator merges black-box + white-box findings
- Correlated findings get elevated confidence (1.1× source multiplier)
- `.fendix-ignore` suppression file (`go/internal/engine/ignore.go`)
- Baseline diff mode (`--baseline`, `--save-baseline`)
- `--fail-on` exit code logic (the 0/1/2 contract)
- End-to-end integration tests with fixture projects
