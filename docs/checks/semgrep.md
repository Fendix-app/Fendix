# Semgrep Rules Check

**Engine:** Go (white-box) — `go/internal/scanner/semgrep/`, native since TASK-116
**Category:** `semgrep` (rules carry `metadata.category`: `auth`, `injection`, `secrets`)
**Default severity:** Varies by rule (`metadata.fendix_severity`)
**Active probing:** No (static analysis)

## What It Detects

Security-relevant code patterns using custom Semgrep rules. Semgrep performs pattern matching on the abstract syntax tree (AST) of source code, catching issues that simple regex cannot.

## Built-in Rules

**23 rules across four files**, embedded into the Go binary from
`go/internal/scanner/semgrep/rules/` via `//go:embed rules/*.yaml`. The count is
pinned by `rulepackTotalCount` in `scanner_rulepack_test.go` — that test is the
authority if this page and the pack ever disagree.

### auth.yaml — Missing Authentication (5 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `flask-missing-login-required` | Flask routes without `@login_required` | Python |
| `django-view-missing-login-required` | Django views without `LoginRequiredMixin` | Python |
| `fastapi-route-missing-auth-dependency` | FastAPI routes without `Depends()` auth | Python |
| `python-jwt-decode-no-verification` | `jwt.decode()` with verification disabled / `alg:none` | Python |
| `flask-route-no-auth-decorator` | Flask route with no auth-style decorator at all | Python |

### crypto.yaml — Weak Cryptography (4 rules)

| Rule ID | Pattern | Languages |
|---|---|---|
| `python-md5-used-for-password` | `hashlib.md5()` on a password-shaped variable | Python |
| `python-sha1-used-for-password` | `hashlib.sha1()` on a password-shaped variable | Python |
| `python-legacy-cipher-import` | DES / 3DES / RC4 / ARC2 / Blowfish imported | Python |
| `python-random-for-token-generation` | `random` used in a security-sensitive function | Python |

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
2. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet --disable-version-check <code_path>`, with a 120 s default deadline layered onto the caller's context
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
| Per-file problems of level `warn`: a file that does not fully parse (`PartialParsing`, syntax or lexical error), a per-file or per-rule `Timeout`, a per-file `OutOfMemory` | `ok`, with the count by type in `detail` (never the message, which can quote source) |
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
