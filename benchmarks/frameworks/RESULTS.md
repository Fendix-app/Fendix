# Framework parity results: Fendix v3.6.3

This report measures how well the engine detects the same vulnerability in
different web frameworks. It uses one labelled corpus, the released binary and
nine frameworks.

## Setup

- **Corpus v2** (as defined in [SPEC.md](SPEC.md)):
  - **522 cases**: 324 vulnerable and 198 safe.
  - **58 cases per framework:**
    - The 28 original cases: 7 classes × direct / indirect / safe / safe_lookalike.
    - 16 cases in 4 new classes, with the same 4 variants.
    - 14 harder vulnerable cases: `cross_file` and `alt_api` for each original class.
  - The original 252 cases were fingerprinted before the extension and are byte-identical. Their results match corpus v1 exactly.
- **Engine:** `fendix-v3.6.3-darwin-arm64` from the GitHub release.
  - SHA-256 `bc03bf6d…ce34`, checked against the release `.sha256` and `build-record.json`. The cosign signature was not checked.
  - Python engine from the `v3.6.3` tag.
  - Semgrep 1.141.0 and Python 3.11.
- **Command:** `fendix scan --code <dir> --format json --offline --fail-on HIGH`, with default confidence gating.
- **Raw data:**
  - [results/v3.6.3-corpus-v2.json](results/v3.6.3-corpus-v2.json): this report.
  - [results/v3.6.3-corpus-v1.json](results/v3.6.3-corpus-v1.json): the original 252 cases alone.
- **Reproduce:** see the header of [run_parity.py](run_parity.py).

## Scoring

Scoring is per case:

| Case | Outcome |
|---|---|
| Vulnerable case with a finding of the same class in its file(s) | **detected** (TP) |
| Vulnerable case without one | **missed** (FN) |
| Safe case with a finding of the same class in its file(s) | **false positive** (FP) |
| Safe case without one | **correct** (TN) |

- A `cross_file` case owns both its sink file and its handler file.
- **Blocks** means the finding's status is `BLOCK`, so it would fail the PR check. It is measured with `--isolate`: every case is scanned in its own tree. The engine groups same-titled findings across files, so in a full-corpus scan a case can inherit `BLOCK` from a proven sibling. Four cases did (Django and Flask SQLi `indirect` and `cross_file`); detection and false-positive counts are the same either way.
- Each finding is mapped to a class by its `rule_id`. Findings without a `rule_id` are mapped by title and reported separately.

## Headline

| Framework | Language | Detected | Recall | Blocks (of vulnerable) | False positives (of safe) | Safe code that blocks | F1 |
|---|---|---|---|---|---|---|---|
| Django | Python | 29/36 | **81%** | 42% | 3/22 (14%) | 2 | 0.85 |
| Flask | Python | 30/36 | **83%** | 42% | 3/22 (14%) | 2 | 0.87 |
| FastAPI | Python | 24/36 | **67%** | 11% | 3/22 (14%) | 0 | 0.76 |
| Express | JS | 7/36 | 19% | 19% | 1/22 (5%) | 1 | 0.32 |
| NestJS | TS | 7/36 | 19% | 19% | 1/22 (5%) | 1 | 0.32 |
| Next.js | TS | 7/36 | 19% | 19% | 1/22 (5%) | 1 | 0.32 |
| Spring Boot | Java | 12/36 | 33% | 8% | 2/22 (9%) | 0 | 0.48 |
| net/http | Go | 13/36 | 36% | 11% | 2/22 (9%) | 0 | 0.51 |
| Gin | Go | 13/36 | 36% | 11% | 2/22 (9%) | 0 | 0.51 |

By language family:

| Family | Detected | Recall | Precision | F1 | Blocks |
|---|---|---|---|---|---|
| Python | 83/108 | 77% | 90% | 0.83 | 31% |
| Go | 26/72 | 36% | 87% | 0.51 | 11% |
| Java | 12/36 | 33% | 86% | 0.48 | 8% |
| JS/TS | 21/108 | 19% | 88% | 0.32 | 19% |
| **All** | **142/324** | **44%** | 89% | 0.59 | 22% |

## Coverage by class

Each cell shows `detected/vulnerable`, then the number that block (`b`), then `+n` for false positives on safe cases. `—` means nothing was detected.

| Framework | SQLi | Cmd inj. | XSS | SSRF | Path trav. | Redirect | Secrets | Weak hash | JWT no-verify | Weak random | SSTI |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Django | 4/4 (2b) +1 | 4/4 (2b) | 1/4 (1b) | 4/4 (2b) +1 | 4/4 (2b) +1 | 4/4 (2b) | 4/4 (4b) | 2/2 | 2/2 | — | — |
| Flask | 4/4 (2b) +1 | 4/4 (2b) | 1/4 (1b) | 4/4 (2b) +1 | 4/4 (2b) +1 | 3/4 (1b) | 4/4 (4b) | 2/2 | 2/2 | — | 2/2 (1b) |
| FastAPI | 4/4 +1 | 4/4 | 1/4 | 4/4 +1 | 3/4 +1 | — | 4/4 (4b) | 2/2 | 2/2 | — | — |
| Express | 3/4 (3b) +1 | — | — | — | — | — | 4/4 (4b) | — | — | — | — |
| NestJS | 3/4 (3b) +1 | — | — | — | — | — | 4/4 (4b) | — | — | — | — |
| Next.js | 3/4 (3b) +1 | — | — | — | — | — | 4/4 (4b) | — | — | — | — |
| Spring Boot | 1/4 | 4/4 +1 | — | — | — | — | 3/4 (3b) | 2/2 +1 | — | 2/2 | — |
| net/http | 4/4 +1 | 3/4 +1 | — | — | — | — | 4/4 (4b) | 2/2 | — | — | — |
| Gin | 4/4 +1 | 3/4 +1 | — | — | — | — | 4/4 (4b) | 2/2 | — | — | — |

The four new classes only `WARN`, with one exception: Flask's `render_template_string` template injection blocks once. Across all frameworks, 22 of their 72 vulnerable cases are detected.

## Harder variants

Recall and blocking rate by variant, per language family:

| Family | direct | indirect | cross_file | alt_api |
|---|---|---|---|---|
| Python | 73% / 42% | 73% / 9% | 81% / 14% | 86% / 67% |
| JS/TS | 18% / 18% | 18% / 18% | 29% / 29% | 14% / 14% |
| Java | 36% / 9% | 36% / 9% | 29% / 14% | 29% / 0% |
| Go | 36% / 9% | 36% / 9% | 43% / 14% | 29% / 14% |

The `direct` and `indirect` columns include the new classes.

- **Python follows taint into another module, but cannot prove it.**
  - Detection holds at 81% for `cross_file`, because the sink shape alone is enough to report.
  - Almost nothing in the helper variants proves reachability: 9% block for same-file helpers, 14% for cross-file. The one-hop interprocedural check (`_param_is_tainted_via_caller`) proves only when the request expression is passed inline, as in `helper(request.GET.get("x"))`. The common shape, `x = request.GET.get("x"); helper(x)`, never proves, because the caller's local bindings are not visible while the helper is visited. This is the same defect for every class.
- **Python handles a second API well.** `os.system`, `Markup`/`mark_safe`, `urllib.request.urlopen`, `send_file`/`FileResponse`, `HttpResponseRedirect` and SQLAlchemy `text(f"...")` are all found, and most block.
  - FastAPI is the exception: its findings warn.
  - Two forms are missed: a raw `Location` header redirect in Flask and FastAPI, and FastAPI `FileResponse(path)`.
- **Regex rules depend on one exact shape.**
  - JS SQL is found only as a template literal. mysql2 `"..." + name` concatenation is missed.
  - Spring SQL is found only through `Statement.executeQuery`. `JdbcTemplate` is missed.
  - Go command injection is missed when the call has a nested parenthesis before the shell arguments. `exec.CommandContext(c.Request.Context(), "sh", "-c", ...)` fails because the rule's `[^)]*` stops at `Context()`.

## Findings

### Secrets are the one class at parity

- 35 of 36 vulnerable secret cases are detected, all of them blocking, with no false positive.
- The single miss is Spring's idiomatic JDBC URL: `jdbc:postgresql://...?user=app&password=...`. The connection-string detector only knows `scheme://user:password@host`.

### Python is deep but incomplete

- **XSS through ordinary HTML responses is missed in all three frameworks.** `HttpResponse(f"<h1>{name}</h1>")`, `make_response` and `HTMLResponse` are not modelled. Only `Markup`, `mark_safe` and `render_template_string` are, and those cases are caught.
- **Template injection is found only in Flask.** `render_template_string` is modelled. Django `Template(src)` and `jinja2.Template(src)` are not.
- **Weak random tokens are missed everywhere.** The bundled rule lists `random.choice`, but not `random.choices`, the most common token idiom.
- **FastAPI findings almost never block.** Typed handler parameters are not proven reachable. The same SQLi scores 90 (HIGH, BLOCK) in Flask and 50 (MEDIUM, WARN) in FastAPI. FastAPI's `RedirectResponse` and manual `Location` headers are not redirect sinks.
- **Correct fixes still block (4 cases).**
  - The cases are a `urlparse(url).hostname` allowlist for SSRF, and a `realpath` + `commonpath` check for path traversal, in Django and Flask.
  - The engine recognises only a membership check on the tainted name itself. The request-to-sink flow inside the handler proves, the guard is not recognised, so the fixed code blocks on its own, with no sibling involved (confirmed under `--isolate`).
  - Closed after v3.6.3 for SSRF: a dominating `urlparse(url).hostname` or `.netloc` allowlist now counts as an SSRF and open-redirect guard, so the Django, Flask and FastAPI `ssrf-safe` cases score TN. The two path-traversal cases still block. See `CHANGELOG.md`, `[Unreleased]`.
- **Weak password hashing and unverified JWTs are found, but only warn,** even when the token comes from the request and the claims are trusted.
- **Route-auth noise:** every one of the 58 Flask routes gets two "missing auth" findings (`flask-route-no-auth-decorator` and `flask-missing-login-required`). Every FastAPI route gets one. Django gets none.

### JavaScript/TypeScript catches template-literal SQL and secrets, nothing else

- **SQL** is found only when written as a template literal (direct, indirect and cross-file). That detection comes from the Python engine's JS pattern check.
  - Its findings carry **no `rule_id`** yet `BLOCK`. (Update, 2026-10-25: they now carry `rule_id: SEC-JS_*`; this measurement predates that change.)
  - It also blocks on a template literal that interpolates a constant.
- **Nothing else is found:**
  - command injection, through any of `promisify(exec)`, destructured `exec` or `execSync`;
  - XSS, SSRF, path traversal and open redirect;
  - MD5 password hashing, `jwt.decode`, `Math.random` tokens and `ejs.render` of a request template.
- Express, NestJS and Next.js score identically.

### Java (Spring Boot): the rules expect Servlet code

- **SQL injection is missed through `jdbcTemplate`** and found only through `Statement.executeQuery`.
- **SSRF, XSS and path traversal are missed.** These rules require `request.getParameter(...)` on the same line, but Spring passes input as `@RequestParam` parameters.
- **Detected, warn only:**
  - command injection, which also fires on a constant argument;
  - MD5 password hashing, which also fires on an MD5 ETag;
  - `java.util.Random` tokens.
- **Not detected:** `JWT.decode` and Freemarker templates built from a request string.

### Go: SQL, command injection and weak hashing, warn-only

- **Detected, warn only:**
  - `db.Query`/`db.QueryRow` with `fmt.Sprintf`;
  - `exec.Command("sh", "-c", ...)`;
  - `md5.Sum` of a password.
- **False positives:** the SQL and command rules also fire when the argument is a constant.
- **No rules** for XSS, SSRF, path traversal, open redirect, `ParseUnverified` JWTs, `math/rand` tokens or `text/template` injection.

### Outside Python, the PR gate is effectively secrets-only

Regex-tier findings never reach the corroboration needed to block, by design. For Java and Go, the only findings that fail a PR are secrets. For JS/TS, it is secrets plus template-literal SQL.

### Catalog gaps

- At v3.6.3, `docs/security-catalog-contract.json` lists 85 checks.
- It omits the Python engine's own rules, which produce most Python detections: `PY_SQL_INJECTION`, `PY_SSRF`, `PY_PATH_TRAVERSAL`, `PY_OPEN_REDIRECT`, `PY_XSS_HTML_SINK`, `PY_WEAK_CRYPTO_PASSWORD`, `PY_JWT_WEAK` and others.
- It also omits the four JS pattern checks.
- Closed after v3.6.3: the catalog lists the Python engine's 16 AST checks and its four JS pattern checks, 105 checks in all. They are listed under the `rule_id` their findings carry, for example `python.ast/PY_SQL_INJECTION` and `SEC-JS_SQL_TEMPLATE`. The engine's spec-parser checks (`SEC-SPEC-*`) are not catalogued yet. See `CHANGELOG.md`, `[Unreleased]`.

## Speed

Measurement conditions:

- Median of 3 runs on an Apple M4 (10 cores, 16 GB).
- Static analysis only, with `--offline`, so there were no OSV or govulncheck network calls and no DAST.
- "1×" is the corpus as written. "20×" is 20 copies of it scanned as one project.

| Framework | 1× (files / lines) | 1× time | 20× lines | 20× time | Throughput (20×) |
|---|---|---|---|---|---|
| Django | 74 / 954 | 1.12 s | 19,080 | 2.26 s | 8.4 kLOC/s |
| Flask | 68 / 1,000 | 1.22 s | 20,000 | 4.40 s | 4.5 kLOC/s |
| FastAPI | 68 / 1,058 | 1.19 s | 21,160 | 3.60 s | 5.9 kLOC/s |
| Express | 66 / 1,004 | 0.96 s | 20,080 | 1.36 s | 14.7 kLOC/s |
| NestJS | 67 / 1,042 | 0.97 s | 20,840 | 1.49 s | 14.0 kLOC/s |
| Next.js | 65 / 690 | 0.98 s | 13,800 | 1.66 s | 8.3 kLOC/s |
| Spring Boot | 66 / 1,747 | 1.01 s | 34,940 | 2.15 s | 16.3 kLOC/s |
| net/http | 66 / 1,472 | 0.97 s | 29,440 | 1.37 s | 21.6 kLOC/s |
| Gin | 66 / 1,568 | 0.97 s | 31,360 | 1.32 s | 23.7 kLOC/s |

- Every scan carries about one second of fixed start-up cost.
- Python costs roughly 3–5× more per line than Go or Java, because it is the only language with Semgrep rules and taint analysis.
- Speed is not a constraint at these sizes for any language.
- Real projects will be slower: larger files, networked dependency checks and DAST all add time.

## Limits of this measurement

- **Small cells.** Each framework × class cell has 2–4 vulnerable cases and 2 safe ones. Read cells as "covered or not", not as precise rates.
- **One idiom per variant.** For example, JS `alt_api` command injection uses `execSync`, so a different idiom can change a cell. Real codebases also have longer flows and framework helpers.
- **Independence.** The cases were written by authors who did not read the engine's rules or see any results. The original 252 cases were frozen before the extension.
- **Static analysis only.** DAST is framework-agnostic and not measured here.
