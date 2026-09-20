# Fendix — Open Source Launch Post

> Draft for HN / r/devops / r/golang / r/netsec.
> Adapt tone per platform. HN version first (Show HN format).
> **Updated for the 90-day cut (2026-06-12): diff-aware scans, pre-commit hook, Proven Path v1, poetry/Pipfile SCA.**

---

## The 90-day wedge (lead with this for the API-first ICP)

Three things turn Fendix from a CI scanner into a tool you run on every commit:

1. **Diff-aware scans.** `fendix scan --code . --staged --fast` scans only the files a commit touches. On a 200-file monorepo that's **~18 ms** — fast enough to be a pre-commit hook, not a CI-only gate.
2. **Pre-commit hook.** `fendix hook install` drops a hook that blocks a commit the moment a secret (or any HIGH+ finding) is staged. `git commit --no-verify` is the escape hatch.
3. **Proven Path v1.** For Python/Django/Flask/FastAPI, a confirmed SQLi now ships as a single SARIF `codeFlow`: **route → handler → source→sink taint chain**, with a `source_tier` provenance tag so a regex-tier finding can never ride correlation up to CRITICAL. GitHub renders the step-through inline in the Security tab — the proof, not just the alert:

   ```
   GET /users  →  list_users()
     L7  uid = request.args.get("id")        ← source
     L8  q = "SELECT ... id = " + uid          ← taint
     L9  cursor.execute(q)                     ← sink
   ```

Plus **transitive SCA**: `poetry.lock` and `Pipfile.lock` are parsed as the full resolved closure, so a CVE three dependencies deep is no longer invisible the way it is with `requirements.txt` alone.

---

## Show HN: Fendix — DAST + SAST in one PR check, F1 = 1.000 on the labeled corpus (MIT, single Go binary)

**Link:** https://github.com/Fendix-app/Fendix

**Text:**

Hi HN,

I built Fendix because I was tired of running three separate security tools in CI and still drowning in false positives.

**The problem:** SAST tools find patterns that look dangerous but might be dead code. DAST tools confirm exploitability but can't tell you which line to fix. Running both means two reports, two triage workflows, and no connection between them.

**The solution:** Fendix runs DAST, SAST, and SCA in a single `fendix scan` invocation and cross-correlates compatible evidence. Independent corroboration raises confidence, but it is not universally required: a strong deterministic single-source finding can block, while a medium-confidence finding may require corroboration. Release policy decides the gate, and missing required coverage produces `INCOMPLETE` rather than proof that the release is clean.

**What it does:**
- **Black-box:** auth bypass, SQLi (time/error/boolean-based), CORS, headers, secrets in responses, rate-limit detection, exposed config files (.env / .git / .htaccess at known paths)
- **White-box:** 15 secret patterns (native Go, no Python required) + 7 reachable taint-chain sink classes — SQLi, SSRF, open-redirect, XSS (`Markup` / `mark_safe` / `render_template_string`), cmd-injection (`os.system` / `subprocess(shell=True)` / `os.popen`), path-traversal (`open` / `pathlib.Path` / `send_file` / `send_from_directory`), insecure deserialization
- **Dependency CVEs:** native Go scanners against `go.mod` (call-graph reachability via `golang.org/x/vuln`), `requirements.txt` (OSV.dev), `package-lock.json` (OSV.dev, full transitive)
- **Correlation:** matching findings get elevated confidence; reachability-proven findings get double severity escalation
- **Output:** JSON, HTML (self-contained single file), SARIF (GitHub Code Scanning compatible)

**Numbers (v0.11.0):**

| Metric | Value | What it means |
|---|---:|---|
| Default cold start | **6.1 ms p50** | Process spawn → JSON-on-stdout. 82× under our internal exit gate (<500 ms). |
| Labeled-corpus F1 | **1.000** | 38/38 expected TPs, 0 FPs, 0 FNs across 7 detection categories on a 56-case synthetic corpus (CI-gated; v0.26's disclosed SSRF FN fixed in v0.27). Reproduce + caveats in BENCHMARKS.md. |
| Juice Shop scan | 12 findings, 27 s | 5 CRITICAL (exposed config files), 4 MEDIUM, 2 LOW, 1 INFO. +5 CRITICALs vs v0.6.1. |
| PyGoat scan | 147 findings, 17 s | Every OWASP Top 10 class PyGoat advertises was detected. 1 CRITICAL (pickle), 9 injection patterns, 133 real CVE-tagged deps. |
| Binary | **single Go binary**, ~19 MB | No Python required by default. `--python-engine` opt-in for legacy AST/spec auth checks. |

**How to use it:**
```
brew install fendix
cd your-repo
fendix scan --code ./ --url https://your-api.dev --format html --output report.html
```

Or install the GitHub App for zero-config PR scanning.

**Technical details:**
- **Pure Go default path** — secrets, semgrep (shells out to host), and dep-CVE scanning all run in-process. v0.9 dropped the embedded Python distribution; v0.11 made the orchestrator default Python-free.
- **Plugin system** — drop a script in `~/.fendix/plugins/` (or `<repo>/.fendix/plugins/`), receive ScanRequest on stdin, emit findings on stdout. NDJSON contract; same wire format the engine's own IPC uses. 5 reference plugins under `examples/plugins/` covering Python (×2), Bash (×1), Node (×1), Ruby (×1) — proves the contract is language-agnostic. `fendix plugins install <git-url>` clones from a URL with manifest validation.
- **Communication** — newline-delimited JSON over stdin/stdout (no gRPC, no sockets) for both the optional Python engine and every plugin
- **Architecture** — Go for CLI + HTTP scanner + orchestrator + 4 native scanners; Python is opt-in via `--python-engine` for AST taint analysis on `auth` / `injection` / `deps` checks against the source tree

**What it's NOT:**
- Not a SaaS. Self-hosted only. No telemetry, no cloud dependency, no phone-home.
- Not a container scanner (Trivy does that better).
- Not a compliance dashboard.
- Not trying to replace Burp Suite for manual pentesting.

**Read-only AI explanation** is the only cloud-side feature on the roadmap (planned for Q1 in a separate `fendix-backend`); ADR-008 documents the rationale and the permanent ban on LLM calls from the OSS engine binary. Auto-PR generation is explicitly forbidden.

MIT licensed. ADR-007 documents the strategic rationale for open-sourcing — TL;DR: closed-source protects nothing at this stage and costs trust + contributions + auditability.

I'd love feedback on the correlation approach and the plugin contract. Is NDJSON in/out too minimal for real-world custom checks, or is the simplicity the point?

---

## r/devops version (shorter)

**Title:** We open-sourced our security scanner — DAST + SAST in one PR check, F1 = 1.000 on the labeled corpus, no Python required to install

Fendix is a hybrid API and code security scanner that runs both a black-box probe and static analysis in a single invocation, then cross-correlates the results.

The key insight: independent evidence can escalate severity and confidence, while deterministic evidence can stand on its own when policy permits. The gate evaluates severity, confidence, evidence quality, and release policy; required coverage gaps remain a separate `INCOMPLETE` outcome. (We do not claim a false-positive reduction without an isolating benchmark.)

**Headline numbers (v0.11.0):**
- 6.1 ms p50 cold start (no Python required in the default path)
- F1 = 1.000 on the labeled accuracy corpus (38 TPs / 0 FPs / 0 FNs across 7 categories; reproduced + CI-gated)
- +5 CRITICALs on Juice Shop vs the v0.6.1 baseline (every classic config-leak surface flagged)
- 147 findings in 17 s on PyGoat (every OWASP Top 10 category covered)

**Quick start:**
```
brew install fendix
fendix scan --code ./ --url https://your-staging-api.dev
```

Or install the GitHub App → zero-config, automatic PR comments + SARIF annotations.

- MIT licensed, fully open source
- Single Go binary (~19 MB); `--python-engine` opt-in if you want the AST taint-analysis path
- Plugin system for custom checks (5 reference plugins across Python / Bash / Node / Ruby)
- `fendix plugins install <git-url>` for git-hosted plugins
- `fendix ignore list/validate/prune` to manage suppression files without manual YAML editing
- No telemetry, no cloud dependency

GitHub: https://github.com/Fendix-app/Fendix

Feedback welcome — especially on the correlation approach and whether the plugin contract (NDJSON stdin/stdout) is too minimal.

---

## r/golang version (technical focus)

**Title:** Fendix: Hybrid security scanner in Go — 22 packages race-clean, F1 = 1.000 on labeled corpus, no embedded Python (MIT)

Built a security scanner where Go handles the entire default path: HTTP scanning, secret detection, dependency CVEs, plugin orchestration, output rendering. Python is opt-in (`--python-engine`) for the AST taint-analysis path; v0.11 dropped the embedded Python distribution entirely so the binary works on machines without Python installed.

**Interesting Go patterns used:**
- `//go:embed` for the (optional) bundled Semgrep rule pack — extracted to a per-process temp dir on first scan via `sync.Once`
- NDJSON over stdin/stdout as the IPC contract for both the optional Python engine and every plugin — no gRPC, no sockets, just `bufio.Scanner`
- Plugin system that walks `<scan-cwd>/.fendix/plugins/` + `~/.fendix/plugins/` with shadow precedence; `os.Stat` to follow symlinks
- `sync.Once` + atomic counter for scan budget enforcement (`--max-requests N`) across goroutines
- Worker pool with fuzz-tested cancellation (native Go fuzzer, 4000+ corpus entries)
- Single-flight token cache for GitHub App installation tokens
- 22 packages, race-clean across the whole tree

**What it does:** DAST + SAST + SCA in one `fendix scan`, correlates supporting evidence, applies confidence-aware release policy, and outputs SARIF for Code Scanning. Strong deterministic evidence can block without correlation; medium-confidence evidence may require independent corroboration.

**v0.11 highlights:**
- Native Go secrets scanner (15 patterns, byte-for-byte parity with the deprecated Python wrapper)
- Native Go config-leak detector (32 patterns covering .env / .git/* / .htaccess / .htpasswd / etc.)
- 7 reachable taint-chain sink classes including the new path-traversal sink (TASK-134)
- `fendix plugins list / install <git-url>` subcommand tree
- `fendix ignore list / validate / prune` for .fendix-ignore lifecycle management

The labeled accuracy corpus (`scripts/accuracy/corpus/`) scores F1 = 1.000 on the current binary — reproduced and CI-gated (v0.26 disclosed one multi-hop SSRF false negative; v0.27 fixed the taint engine, see BENCHMARKS.md); the harness (`scripts/accuracy/run.py`) is reproducible and produces JSON for CI gating. Three Go bugs surfaced during the evaluation: `_is_open_redirect` was missing taint-chain posture (0/3 recall → 3/3 after fix), cmdi was firing on literal-string args (0.833 precision → 1.000), orchestrator code_path was relative when the spawner cwd was elsewhere (silent zero-finding bug on real codebases).

https://github.com/Fendix-app/Fendix

Would love feedback on the NDJSON IPC approach vs alternatives (gRPC, Unix sockets, Wasm). We chose NDJSON for debuggability (`| jq .`) and language-agnostic plugin authoring; the 5 reference plugins (Python / Bash / Node / Ruby) demonstrate the contract is genuinely minimal.

---

## r/netsec version (offensive-security framing)

**Title:** Fendix v0.11 — open-source DAST+SAST scanner, taint chains across 7 sink classes, MIT

Built a security scanner I'd actually use for my own audit work. Open-sourcing it because closed-source protects nothing at this stage.

**Detection surface (v0.11.0):**

| Class | How fendix catches it |
|---|---|
| SQLi | Active probing (time-based / error-based / boolean-based across MySQL / Postgres / MSSQL / SQLite / Oracle) AND AST taint chains from `request.*` to `cursor.execute` / SQLAlchemy `text()` |
| SSRF | AST taint from `request.*` to `requests.get` / `urllib.urlopen` / `httpx` |
| Open redirect | AST taint to `flask.redirect` / `HttpResponseRedirect` |
| XSS (server-side) | AST taint to `Markup` / `mark_safe` / `render_template_string` |
| Cmd-injection | AST taint to `os.system` / `subprocess(shell=True)` / `os.popen` |
| Path-traversal | AST taint to `open` / `pathlib.Path` / `send_file` / `send_from_directory` |
| Insecure deserialization | `pickle.loads` / `yaml.unsafe_load` patterns |
| Hardcoded credentials | 15 native-Go regex patterns covering AWS / GitHub / Stripe / Slack / Google / Anthropic / OpenAI / npm / GCP / generic API keys / DB connection strings / JWTs / private keys / .env files |
| Exposed config files | Native scanner for `.env*` / `.git/*` / `.htaccess` / `.htpasswd` / `.npmrc` / `.aws/*` / `.ssh/*` at 32 known paths |
| CORS misconfigurations | Probe + classify (allow-credentials + wildcard, reflected origin, etc.) |
| Auth bypass | JWT none-alg, missing-decorator detection via Semgrep + Spec parser |
| Dep CVEs | govulncheck (call-graph reachable), OSV.dev for PyPI and npm |

**On a real third-party API (TwiScope deepin, public spec, with operator authorization):** 803 endpoints, 23,242 active-probe requests, 5 unique deduped findings (CORS-allow-any-origin + no-rate-limiting, both on all 803 endpoints; 3 disclosure findings on the auth-free OAuth callback). Caveat: the API authenticates 99% of endpoints with JWT, so probes hit 401 before reaching vulnerable code paths — real coverage requires `--auth "Bearer <token>"`.

**On juice-shop (vulnerable-by-design):** 12 findings in 27 s. 5 CRITICAL config-leak detections (CWE-538). Caveat: juice-shop's SPA returns 200 for unknown paths, so the CRITICALs could be SPA-fallback responses — still a real issue (cache poisoning, WAF confusion).

**On PyGoat (Django, vulnerable-by-design):** 147 findings in 17 s. Every OWASP Top 10 class PyGoat advertises: pickle deserialization (CRITICAL), eval, subprocess(shell), yaml.unsafe_load, SSRF, innerHTML XSS, open-redirect (9 sites), hardcoded JWT/password/API key, 133 real CVE-tagged dependencies.

MIT, self-hosted, no telemetry. Plugin contract is NDJSON over stdin/stdout — write a custom check in any language with 30 lines of code, drop it in `~/.fendix/plugins/`, it runs alongside the embedded engines and participates in correlation + dedup + ID assignment.

https://github.com/Fendix-app/Fendix

Feedback welcome on the taint-chain shapes and the corpus methodology. Adversarial inputs especially appreciated.
