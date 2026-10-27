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
2. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet <code_path>`, with a 120 s default deadline layered onto the caller's context
3. Parses Semgrep JSON output and maps to Fendix Finding format (`SEC-<RULE_ID>`)
4. Severity resolution prefers `metadata.fendix_severity`; falls back to Semgrep's own `ERROR`→`HIGH` / `WARNING`→`MEDIUM` / `INFO`→`LOW`; ultimate default `MEDIUM`
5. If `semgrep` is not on `$PATH`, returns `ErrSemgrepUnavailable` — the orchestrator logs an install hint at INFO, records `scanner_status: {"name":"semgrep","state":"skipped"}`, and continues

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
