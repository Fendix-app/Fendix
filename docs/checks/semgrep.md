# Semgrep Rules Check

**Engine:** Go (white-box) — `go/internal/scanner/semgrep/`, native since TASK-116
**Category:** `semgrep` (rules carry `metadata.category`: `auth`, `injection`, `secrets`, `xss`, `crypto`)
**Default severity:** Varies by rule (`metadata.fendix_severity`)
**Active probing:** No (static analysis)

## What It Detects

Security-relevant code patterns using custom Semgrep rules. Semgrep performs pattern matching on the abstract syntax tree (AST) of source code, catching issues that simple regex cannot.

## Built-in Rules

**74 rules across thirteen files**: the 23 Python rules in the four files
below, and the JavaScript/TypeScript (17), Java (15) and Go (19) taint packs in
nine more, which [`docs/semgrep-rules.md`](../semgrep-rules.md) documents. They
are embedded into the Go binary from
`go/internal/scanner/semgrep/rules/` via `//go:embed rules/*.yaml`. The count is
pinned by `rulepackTotalCount` in `scanner_rulepack_test.go` — that test is the
authority if this page and the pack ever disagree.

The JavaScript/TypeScript, Java and Go taint findings are reported as
warnings, not blocking: a blind evaluation on 70 production repositories
measured their precision at 0.077, 0.111 and 0.091, below the 0.80 the
taint gate requires (`semgrep.ReachabilityLanguages` is empty, ADR-011).

### auth.yaml — Missing Authentication (4 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `django-view-missing-login-required` | Django views without `LoginRequiredMixin` | Python |
| `fastapi-route-missing-auth-dependency` | FastAPI routes without a `Depends()`/`Security()` parameter or `dependencies=[...]`, written as a default, inline `Annotated[...]`, a same-file `Annotated` alias, or an alias imported from a `deps`/`dependencies` module. A dependency-free route whose parameter is any name imported from such a module is not reported (false negative) | Python |
| `python-jwt-decode-no-verification` | `jwt.decode()` with verification disabled / `alg:none` | Python |
| `flask-route-no-auth-decorator` | Flask route with no auth-style decorator below `@app.route(...)`; one placed above it does not protect the route | Python |

### crypto.yaml — Weak Cryptography (5 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `python-md5-used-for-password` | `hashlib.md5()` on a password-shaped variable | Python |
| `python-sha1-used-for-password` | `hashlib.sha1()` on a password-shaped variable | Python |
| `python-legacy-cipher-import` | DES / 3DES / RC4 / ARC2 / Blowfish imported | Python |
| `python-random-for-token-generation` | `random` (`random()`, `choice`, `choices`, `randint`, `randrange`, `sample`, `shuffle`, `getrandbits`, `randbytes`) used in a function whose name has a security-sensitive word (`token`, `password`, `secret`, `nonce`, `salt`, `session`, `otp`, `reset`, `csrf`, `api_key`, `access_key`) at the start of a name segment: `issue_api_key`, not `footprint` | Python |
| `python-random-token-assignment` | The same `random` calls assigned to a variable or attribute whose name has such a word (`token = "".join(random.choices(...))`), in a function the rule above does not match or at module level, so one call is one finding | Python |

### injection.yaml — Injection Patterns (8 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `python-sql-injection-string-format` | SQL queries built by string formatting | Python |
| `python-command-injection-shell-true` | Command execution with user-controlled input | Python |
| `python-eval-injection` | `eval()` / `exec()` with a dynamic argument | Python |
| `django-orm-raw-sql` | Django ORM raw SQL with a non-literal argument | Python |
| `flask-render-template-string-injection` | `render_template_string()` with a non-literal template (SSTI) | Python |
| `python-subprocess-shell-true-with-variable` | `subprocess(..., shell=True)` with a non-literal command | Python |
| `python-pickle-loads-untrusted` | `pickle.loads()` on a non-literal byte string | Python |
| `python-yaml-load-unsafe` | `yaml.load()` without `SafeLoader` | Python |

### secrets.yaml — Hardcoded Secrets (6 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `python-hardcoded-secret-assignment` | Variable named `secret`/`password`/`key` assigned a string literal | Python |
| `python-hardcoded-db-url` | Database URLs with embedded username:password | Python |
| `python-gcp-service-account-inline` | Inline GCP service-account JSON | Python |
| `python-aws-access-key-id-literal` | AWS access-key ID literal | Python |
| `python-slack-webhook-url-literal` | Hardcoded Slack incoming-webhook URL | Python |
| `python-pem-private-key-literal` | PEM-encoded private key literal | Python |

## How It Works

1. On the first scan of a process, `ensureRules()` extracts the embedded pack to a temp dir (cached in a `sync.Once` for the process lifetime)
2. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet --disable-version-check --dataflow-traces --timeout 30 --exclude node_modules --exclude dist --exclude build --exclude .next --exclude target --exclude vendor --exclude '*.min.js' <code_path>`, with a 300 s default deadline layered onto the caller's context. `--timeout 30` bounds one rule on one file; a rule that hits it loses only its matches in that file, and Semgrep's `--timeout-threshold` (3) skips the remaining rules on a file after three such timeouts. Each timeout is logged; the findings of the run are kept, and the `semgrep` entry in `scanner_status` is `failed` with reason `timeout` and a detail naming each rule and file, so `--fail-on-scanner-error` and the coverage gates see the partial run. The excludes skip build output, installed dependencies and vendored code at any depth below `<code_path>`, for every language, Python's `dist/` and `build/` included
3. Classifies the run (below), then maps the JSON results to Fendix Finding format (`SEC-<RULE_ID>`)
4. Severity resolution prefers `metadata.fendix_severity`; falls back to Semgrep's own `ERROR`→`HIGH` / `WARNING`→`MEDIUM` / `INFO`→`LOW`; ultimate default `MEDIUM`
5. If `semgrep` is not on `$PATH`, returns `ErrSemgrepUnavailable` — the orchestrator logs an install hint at INFO, records `scanner_status: {"name":"semgrep","state":"skipped","reason":"dependency_missing"}`, and continues

## What `ok` means (from v3.7.0)

`semgrep` is recorded `ok` only when Semgrep itself would call the run
successful. The rule follows Semgrep 1.182.1's own contract (its
`error.py`, `output.py` and `core_output.py`) and recorded runs of the real
binary, kept as fixtures in `go/internal/scanner/semgrep/testdata/runs`:

| Run | Recorded |
|---|---|
| Exit 0, JSON envelope, no error of level `error` | `ok` |
| Per-file problems of level `warn`: a file that does not fully parse (`PartialParsing`, syntax or lexical error), a per-file `OutOfMemory` | `ok`, with the count by type in `detail` (never the message, which can quote source) |
| A rule `Timeout` (a rule Semgrep stopped on a file after `--timeout 30`), also level `warn` | `failed` / `timeout`, `detail` naming each rule and file: the rule's matches in that file are missing, so the run is not called complete. This is stricter than Semgrep's own contract, on purpose |
| A non-zero exit other than 1, or death by a signal: an invalid or missing config (exit 7), a rule that does not parse (exit 2), the engine killed or crashed mid-run, out of memory included (exit 2, "the engine was killed") | `failed` / `execution_error`, `detail` naming the first error |
| Exit 0 with any entry of level `error`: Semgrep sets its exit code from its last error only, so a rule parse error followed by per-file warnings exits 0 | `failed` / `execution_error` |
| Exit 0 with no JSON results envelope | `failed` / `malformed_output` |

Only the error's `level` is read, never its `code`: a per-file `Timeout` has
`code` 2 at level `warn`. Findings Semgrep still printed in a failed run are
kept in the report. Until v3.6.5 any parseable envelope was `ok` whatever the
exit code, so an engine killed by the kernel for memory recorded `semgrep ok`
with no findings, and a required Semgrep passed `--require-analyzers semgrep`.

## Adding Custom Rules

Place YAML rule files in **`go/internal/scanner/semgrep/rules/`**. The `//go:embed`
glob picks up every `.yaml` in that directory at build time.

> ⚠️ `python/rules/` is **dead** — it is read by no code. The Python semgrep
> wrapper was deleted in TASK-118, and `python/engine.py` treats a `semgrep`
> check request as a no-op. A rule added there will never run.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the rule template, the required
`metadata` fields, and the two counters you must bump in the same commit.

## Example Finding

```json
{
  "title": "SQL query uses string formatting",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "injection",
  "endpoint": "src/db.py:23",
  "evidence": "query = \"SELECT * FROM users WHERE id = %s\" % user_id",
  "fix": "Use parameterized queries instead of string formatting.",
  "references": ["CWE-89"],
  "line": "src/db.py:23"
}
```

## References

- [Semgrep Documentation](https://semgrep.dev/docs/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: Command Injection](https://cwe.mitre.org/data/definitions/78.html)
