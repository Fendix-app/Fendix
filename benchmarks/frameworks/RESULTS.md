# Framework parity results: Fendix v3.6.3, with the development figures of the current build

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
- **Which figures are current.** The Headline, family, coverage-by-class and
  harder-variant tables below, and every figure marked "now" in the Findings,
  are the development figures of the integrated `[Unreleased]` build. They are
  recomputed from [baseline.json](baseline.json) with the definitions under
  "Scoring", for all nine frameworks, Python included. `make parity` on commit
  `8b78364` with Semgrep 1.182.1 reproduced that baseline with no regression.
  The command and corpus are the same, with `--isolate`. The v3.6.3 measurement
  above is what the "Closed after v3.6.3" notes in the Findings are counted
  from; its raw data is in `results/`.
- **The JavaScript/TypeScript, Java and Go taint findings warn and do not
  block.** Their taint gate (ADR-011) is closed. A blind real-world evaluation
  measured their precision at 0.077 (JS/TS), 0.111 (Java) and 0.091 (Go), at
  commit `6901cf7` on Semgrep 1.141.0 ([REALWORLD.md](REALWORLD.md)).

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
| Django | Python | 36/36 | **100%** | 94% | 0/22 (0%) | 0 | 1.00 |
| Flask | Python | 36/36 | **100%** | 94% | 0/22 (0%) | 0 | 1.00 |
| FastAPI | Python | 36/36 | **100%** | 94% | 0/22 (0%) | 0 | 1.00 |
| Express | JS | 32/36 | **89%** | 19% | 0/22 (0%) | 0 | 0.94 |
| NestJS | TS | 32/36 | **89%** | 19% | 0/22 (0%) | 0 | 0.94 |
| Next.js | TS | 32/36 | **89%** | 19% | 0/22 (0%) | 0 | 0.94 |
| Spring Boot | Java | 36/36 | **100%** | 11% | 0/22 (0%) | 0 | 1.00 |
| net/http | Go | 36/36 | **100%** | 11% | 0/22 (0%) | 0 | 1.00 |
| Gin | Go | 36/36 | **100%** | 11% | 0/22 (0%) | 0 | 1.00 |

By language family:

| Family | Detected | Recall | Precision | F1 | Blocks |
|---|---|---|---|---|---|
| Python | 108/108 | 100% | 100% | 1.00 | 94% |
| Go | 72/72 | 100% | 100% | 1.00 | 11% |
| Java | 36/36 | 100% | 100% | 1.00 | 11% |
| JS/TS | 96/108 | 89% | 100% | 0.94 | 19% |
| **All** | **312/324** | **96%** | 100% | 0.98 | 42% |

These are figures on the development corpus, which the rules were tuned against. They are not a claim about arbitrary code: the blind-holdout recall is lower for every language, and is the figure to quote (see [docs/accuracy.md](../../docs/accuracy.md)).

## Coverage by class

Each cell shows `detected/vulnerable`, then the number that block (`b`), then `+n` for false positives on safe cases. `—` means nothing was detected.

| Framework | SQLi | Cmd inj. | XSS | SSRF | Path trav. | Redirect | Secrets | Weak hash | JWT no-verify | Weak random | SSTI |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Django | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 2/2 (2b) | 2/2 (2b) | 2/2 | 2/2 (2b) |
| Flask | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 2/2 (2b) | 2/2 (2b) | 2/2 | 2/2 (2b) |
| FastAPI | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 4/4 (4b) | 2/2 (2b) | 2/2 (2b) | 2/2 | 2/2 (2b) |
| Express | 4/4 (3b) | 4/4 | 4/4 | 2/4 | 2/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |
| NestJS | 4/4 (3b) | 4/4 | 4/4 | 2/4 | 2/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |
| Next.js | 4/4 (3b) | 4/4 | 4/4 | 2/4 | 2/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |
| Spring Boot | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |
| net/http | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |
| Gin | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 (4b) | 2/2 | 2/2 | 2/2 | 2/2 |

No safe case is a false positive in any framework, so no cell carries a `+n`.

All 72 vulnerable cases of the four new classes are detected. 18 of them block: 6 in each Python framework (every new class except weak random tokens, which warns). None blocks in the other six frameworks, whose taint findings warn (ADR-011).

- Closed after v3.6.3 for JavaScript/TypeScript, Java and Go, for detection only. The Semgrep taint packs cover the new classes, and their taint findings warn: the taint gate is closed (ADR-011).
  - Express, NestJS, Next.js, Spring Boot, net/http and Gin each detect all 8 of their new-class cases, and none blocks.

## Harder variants

Recall and blocking rate by variant, per language family:

| Family | direct | indirect | cross_file | alt_api |
|---|---|---|---|---|
| Python | 100% / 91% | 100% / 91% | 100% / 100% | 100% / 100% |
| JS/TS | 100% / 18% | 82% / 18% | 71% / 29% | 100% / 14% |
| Java | 100% / 9% | 100% / 9% | 100% / 14% | 100% / 14% |
| Go | 100% / 9% | 100% / 9% | 100% / 14% | 100% / 14% |

The `direct` and `indirect` columns include the new classes.

The Python rows are the current development figures: every Python case is detected, and the only ones that do not block are the weak-random-token cases. The JS/TS, Java and Go rows are measured with the taint gate closed, so only secrets and template-literal SQL (JS/TS) block. Their `cross_file` cells are the weakest for detection, because a helper in another file is reported by a shape rule: the cases are detected (71% for JS/TS, 100% for Java and Go), and block in 29% (JS/TS), 14% (Java) and 14% (Go), the secrets and template-literal SQL cases.

- **Python follows taint into another module, but cannot prove it.**
  - Detection holds at 81% for `cross_file`, because the sink shape alone is enough to report.
  - Almost nothing in the helper variants proves reachability: 9% block for same-file helpers, 14% for cross-file. The one-hop interprocedural check (`_param_is_tainted_via_caller`) proves only when the request expression is passed inline, as in `helper(request.GET.get("x"))`. The common shape, `x = request.GET.get("x"); helper(x)`, never proves, because the caller's local bindings are not visible while the helper is visited. This is the same defect for every class.
    - Closed after v3.6.3 for same-file helpers. The check now traces the argument through the caller's own assignments before the call. The Django and Flask `indirect` cases for SQLi, command injection, SSRF, path traversal and open redirect, and Flask's `ssti` `indirect` case, now block.
    - FastAPI's `indirect` cases still warned: the caller passes a typed handler parameter, which was not a request source. Closed after v3.6.3 too: a route handler's parameters are now request sources, and FastAPI's `indirect` cases for SQLi, command injection, SSRF and path traversal block.
    - Cross-file helpers are unchanged.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **Python handles a second API well.** `os.system`, `Markup`/`mark_safe`, `urllib.request.urlopen`, `send_file`/`FileResponse`, `HttpResponseRedirect` and SQLAlchemy `text(f"...")` are all found, and most block.
  - FastAPI is the exception: its findings warn.
    - Closed after v3.6.3. With handler parameters as request sources, FastAPI's `alt_api` cases for SQLi, command injection, SSRF and XSS block.
  - Two forms are missed: a raw `Location` header redirect in Flask and FastAPI, and FastAPI `FileResponse(path)`.
    - Closed after v3.6.3 for the `Location` header. A `Location` header on a framework response with a redirect status is now an open-redirect sink, set in the constructor's headers, assigned afterwards, or returned in a Flask `(body, status, headers)` tuple. The Flask and FastAPI `alt_api` open-redirect cases are detected and block.
    - The FastAPI case, `FileResponse(os.path.join(REPORTS_DIR, filename))`, is detected and blocks after v3.6.3 through the inner `os.path.join`, which is reported once the flow is proven. `FileResponse` itself is still not a sink.
    - Closed after v3.6.3 for `FileResponse` too. Starlette's and FastAPI's `FileResponse(path)` is now a path-traversal sink of its own, so the case is also reported on the `FileResponse` call. Its outcome does not change: it was already detected and blocking.
- **Regex rules depend on one exact shape.**
  - JS SQL is found only as a template literal. mysql2 `"..." + name` concatenation is missed.
    - Closed after v3.6.3. `js-sqli-taint` follows request input into the query of `query`, `execute` and `raw`, however it is built. All four SQLi cases are detected in Express, NestJS and Next.js, and three block (the template-literal cases the Python engine's pattern check already blocked); the rest warn, because the taint gate is closed (ADR-011).
  - Spring SQL is found only through `Statement.executeQuery`. `JdbcTemplate` is missed.
    - Closed after v3.6.3. `java-sqli-taint` covers `JdbcTemplate`, `NamedParameterJdbcTemplate`, JDBC `Statement` and `Connection`, JPA and Hibernate. All four SQLi cases are detected, and none blocks, because the taint gate is closed (ADR-011).
  - Go command injection is missed when the call has a nested parenthesis before the shell arguments. `exec.CommandContext(c.Request.Context(), "sh", "-c", ...)` fails because the rule's `[^)]*` stops at `Context()`.
    - Closed after v3.6.3. `go-cmdi-taint` does not depend on the argument's text. All four command-injection cases are detected in net/http and Gin, and none blocks, because the taint gate is closed (ADR-011).

## Findings

### Secrets are the one class at parity

- All 36 vulnerable secret cases are detected now, every one blocking, with no false positive.
- At v3.6.3 the single miss was Spring's idiomatic JDBC URL, `jdbc:postgresql://...?user=app&password=...`: the connection-string detector only knew `scheme://user:password@host`. Closed after v3.6.3: `DB_CONNECTION_STRING` has a second shape for it (see `CHANGELOG.md`, `[Unreleased]`).

### Python is deep but incomplete

- **XSS through ordinary HTML responses is missed in all three frameworks.** `HttpResponse(f"<h1>{name}</h1>")`, `make_response` and `HTMLResponse` are not modelled. Only `Markup`, `mark_safe` and `render_template_string` are, and those cases are caught.
  - Closed after v3.6.3. The body of an HTML response is now an XSS sink: Django `HttpResponse`, Flask `make_response` and `Response`, and Starlette and FastAPI `HTMLResponse` and `Response`, unless the response declares a non-HTML content type.
    - The `direct` and `indirect` XSS cases block in all three frameworks, and the `cross_file` cases are detected and warn. No safe case is flagged.
    - The Python frameworks detect 93 of 108 vulnerable cases, up from 84, and block on 64, up from 58. FastAPI blocks on 19, Django on 22 and Flask on 23.
    - See `CHANGELOG.md`, `[Unreleased]`.
  - A string a Flask or Quart view returns (`return f"<p>{name}</p>"`) is now an HTML response body too, judged by the same rules as `make_response(...)`. No corpus case returns a string from a view, so these numbers do not change.
- **Template injection is found only in Flask.** `render_template_string` is modelled. Django `Template(src)` and `jinja2.Template(src)` are not.
  - Closed after v3.6.3. A template compiled from a string is now a sink of its own rule, `python.ast/PY_SSTI`: `jinja2.Template`, `from_string` on a Jinja2 environment (a sandboxed one too) or a Django `engines[...]` backend, `django.template.Template` and Mako's `Template`. Flask's `render_template_string` keeps `python.ast/PY_XSS_HTML_SINK`.
    - The Django and FastAPI `direct` and `indirect` SSTI cases are detected and block. No safe case is flagged.
    - The Python frameworks detect 97 of 108 vulnerable cases, up from 93, and block on 68, up from 64. Django blocks on 24, FastAPI on 21 and Flask on 23.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **Weak random tokens are missed everywhere.** The bundled rule lists `random.choice`, but not `random.choices`, the most common token idiom.
  - Closed after v3.6.3 for Python. `python-random-for-token-generation` now also reports `random.choices`, `randrange` and `randbytes`. It matches a security-sensitive word at the start of any segment of the function's name. Semgrep anchored the rule's regex at the start of the name, so `create_api_key` and `_generate_api_key` never matched. A new rule, `python-random-token-assignment`, reports the same calls assigned to a token-named variable.
    - The Django, Flask and FastAPI `direct` and `indirect` weak-random-token cases are detected and warn. No safe case is flagged.
    - The Python frameworks detect all 108 vulnerable cases, up from 102, and block on 72.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **FastAPI findings almost never block.** Typed handler parameters are not proven reachable. The same SQLi scores 90 (HIGH, BLOCK) in Flask and 50 (MEDIUM, WARN) in FastAPI. FastAPI's `RedirectResponse` and manual `Location` headers are not redirect sinks.
  - Closed after v3.6.3 for handler parameters. A route handler's parameters are now request sources: FastAPI query, path, header, cookie and body parameters, and Flask and Django URL variables. Dependencies (`Depends(...)`, `Security(...)`, a type from a `deps` module), injected objects such as `Request`, fixed-value types (`int`, `UUID`, `Literal[...]`, a same-file Enum) and Flask or Django parameters their URL pattern does not name are not.
    - Every FastAPI SQLi, command-injection, SSRF, path-traversal and XSS case the engine detects now blocks, except the four `cross_file` ones. FastAPI blocks on 17 of 36 vulnerable cases, up from 4. No safe case is flagged or blocks.
    - Django blocks on 20 and Flask on 21. FastAPI's remaining gap to Django is its three blocking redirect cases: `RedirectResponse` is still not a redirect sink.
    - See `CHANGELOG.md`, `[Unreleased]`.
  - Closed after v3.6.3 for redirects too. Starlette's and FastAPI's `RedirectResponse` and Django's `HttpResponsePermanentRedirect` are now redirect sinks, resolved through the file's imports.
    - FastAPI's four open-redirect cases are detected, and all but `cross_file` block. FastAPI now blocks on as many vulnerable cases as Django and Flask.
    - The Python frameworks detect 102 of 108 vulnerable cases, up from 97, and block on 72, up from 68. Django, FastAPI and Flask each block on 24.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **Correct fixes still block (4 cases).**
  - The cases are a `urlparse(url).hostname` allowlist for SSRF, and a `realpath` + `commonpath` check for path traversal, in Django and Flask.
  - The engine recognises only a membership check on the tainted name itself. The request-to-sink flow inside the handler proves, the guard is not recognised, so the fixed code blocks on its own, with no sibling involved (confirmed under `--isolate`).
  - Closed after v3.6.3 for SSRF, partly by correcting the cases. Their `hostname` allowlist could itself be bypassed with a backslash in the authority, so the three `ssrf-safe` cases now check `netloc` instead (see [Corrections](SPEC.md#corrections) in SPEC.md).
    - The engine now counts a dominating `urlparse(url).netloc` allowlist as an SSRF and open-redirect guard, and the corrected Django, Flask and FastAPI cases score TN.
    - A `hostname` allowlist is still reported.
    - See `CHANGELOG.md`, `[Unreleased]`.
  - Closed after v3.6.3 for path traversal. The engine now treats it as a guard when the handler resolves the path (`os.path.realpath` or `Path.resolve()`), checks that it is under a fixed base directory, and exits when it is not. The check can be `commonpath`, `startswith` with a trailing separator, `is_relative_to` or `relative_to`. The Django, Flask and FastAPI `path_traversal-safe` cases now score TN.
    - A `startswith` without a separator, and a path that is only joined or `abspath`-ed, are still reported.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **SQLi false positives on a constant table name (3 cases).**
  - The Django, Flask and FastAPI `sqli-safe_lookalike` cases put a module constant into an f-string query: `cursor.execute(f"SELECT ... FROM {USERS_TABLE} ...")`. The Semgrep rule `python-sql-injection-string-format` reported them. They are the SQLi `+1` in the Python rows of the coverage table.
  - Closed after v3.6.3. The rule now skips an f-string interpolation that Semgrep's constant propagation resolves to a string literal, and the three cases score TN.
    - An f-string with any other interpolation is still reported. So is a constant rebound from input before the call: in the function, at module level, by a `global` write, through `nonlocal`, or after a lambda that reads it is defined.
    - A module constant that an import of the same name replaces is no longer reported.
    - See `CHANGELOG.md`, `[Unreleased]`.
- **Where this leaves the Python frameworks.** All 108 vulnerable cases are detected now, and 102 block (34 in each framework; the two that warn are its weak-random-token cases). None of the 66 safe cases is flagged.
- **Weak password hashing and unverified JWTs are found, but only warn,** even when the token comes from the request and the claims are trusted. (At v3.6.3. Closed since: the Python frameworks' weak-hash and JWT cases block now, as the coverage table shows.)
- **Route-auth noise:** every one of the 58 Flask routes gets two "missing auth" findings (`flask-route-no-auth-decorator` and `flask-missing-login-required`). Every FastAPI route gets one. Django gets none.
  - Closed after v3.6.3. `flask-missing-login-required` is removed (ADR-012), so each Flask route gets one, from `flask-route-no-auth-decorator`. See `CHANGELOG.md`, `[Unreleased]`.

### JavaScript/TypeScript catches template-literal SQL and secrets, nothing else

- **SQL** is found only when written as a template literal (direct, indirect and cross-file). That detection comes from the Python engine's JS pattern check.
  - Its findings carry **no `rule_id`** yet `BLOCK`. (Update, 2026-10-25: they now carry `rule_id: SEC-JS_*`; this measurement predates that change.)
  - It also blocks on a template literal that interpolates a constant.
- **Nothing else is found:**
  - command injection, through any of `promisify(exec)`, destructured `exec` or `execSync`;
  - XSS, SSRF, path traversal and open redirect;
  - MD5 password hashing, `jwt.decode`, `Math.random` tokens and `ejs.render` of a request template.
- Express, NestJS and Next.js score identically.
- Closed after v3.6.3, for detection. The JavaScript/TypeScript Semgrep taint pack (Express, NestJS and Next.js) follows request input to a sink within one function, and its findings warn: they do not block (ADR-011).
  - 96 of 108 vulnerable cases are detected (89%, up from 19%), and 21 block (19%, unchanged). Each framework detects 32 of 36, and blocks on 7: the four secrets and three template-literal SQL cases.
  - The pack met the corpus gate (precision 0.97 when it was added, 1.000 on the current baseline) but not the real-world one: a blind evaluation on 70 production repositories (commit `6901cf7`, Semgrep 1.141.0) found 1 true positive in 13 taint findings (precision 0.077), so they are reported as warnings.
  - Still missed: SSRF and path traversal through a helper in the same or another file (12 cases, 4 per framework).
  - Safe code that blocks: none now. At v3.6.3 the three `sqli-safe_lookalike` cases did, from the Python engine's `SEC-JS_SQL_TEMPLATE`, not from the pack; the check no longer fires on a tagged template or a constant. No safe case is a false positive in any of the three frameworks.

### Java (Spring Boot): the rules expect Servlet code

- **SQL injection is missed through `jdbcTemplate`** and found only through `Statement.executeQuery`.
- **SSRF, XSS and path traversal are missed.** These rules require `request.getParameter(...)` on the same line, but Spring passes input as `@RequestParam` parameters.
- **Detected, warn only:**
  - command injection, which also fires on a constant argument;
  - MD5 password hashing, which also fires on an MD5 ETag;
  - `java.util.Random` tokens.
- **Not detected:** `JWT.decode` and Freemarker templates built from a request string.
- Closed after v3.6.3, for detection. The Spring Semgrep taint pack follows `@RequestParam`, `@PathVariable`, `@RequestBody` and servlet request input to a sink within a method, plus one call into a method of the same class, and its findings warn: they do not block (ADR-011).
  - All 36 vulnerable cases are detected now (100%, up from 33%), and 4 block (11%): the secrets. The secret in a `jdbc:postgresql://...?user=app&password=...` URL, the one miss when the pack was added, is detected since the secrets scanner learned that shape.
  - Every taint case detects and warns.
  - The pack met the corpus gate (precision 0.946 when it was added, 1.000 on the current baseline) but not the real-world one: a blind evaluation on 70 production repositories (commit `6901cf7`, Semgrep 1.141.0) found 1 true positive in 10 Java taint findings (precision 0.111), so they are reported as warnings.
  - None of the 22 safe cases is a false positive now. When the pack was added, two were, both textscan's (command injection on a constant argument, and an MD5 ETag), and neither blocked.

### Go: SQL, command injection and weak hashing, warn-only

- **Detected, warn only:**
  - `db.Query`/`db.QueryRow` with `fmt.Sprintf`;
  - `exec.Command("sh", "-c", ...)`;
  - `md5.Sum` of a password.
- **False positives:** the SQL and command rules also fire when the argument is a constant.
- **No rules** for XSS, SSRF, path traversal, open redirect, `ParseUnverified` JWTs, `math/rand` tokens or `text/template` injection.
- Closed after v3.6.3, for detection. The Go Semgrep taint packs (net/http, gorilla/mux, chi and Gin) follow request input to a sink within a function, plus one call into a function of the same file, and their findings warn: they do not block (ADR-011).
  - 72 of 72 vulnerable cases are detected in net/http and Gin (100%, up from 36%), and 8 block (11%, unchanged): the secrets.
  - Every taint case detects and warns.
  - The packs met the corpus gate (precision 0.947 when they were added, 1.000 on the current baseline) but not the real-world one: a blind evaluation on 70 production repositories (commit `6901cf7`, Semgrep 1.141.0) found 1 true positive in 11 Go taint findings (precision 0.091), so they are reported as warnings.
  - None of the 44 safe cases is a false positive now. When the packs were added, 4 were, textscan's SQL and command-injection rules on the `safe_lookalike` cases, and none blocked.

### Outside Python, the PR gate is effectively secrets-only

Regex-tier findings never reach the corroboration needed to block, by design. For Java and Go, the only findings that fail a PR are secrets. For JS/TS, it is secrets plus template-literal SQL.

- Not closed for JS/TS, Java and Go. A Semgrep taint finding would be reachable and block (ADR-011), but the taint gate is closed for these languages: the packs' real-world precision was 0.077 (JS/TS), 0.111 (Java) and 0.091 (Go) on a blind evaluation of 70 production repositories, below the 0.80 required. Their taint findings are reported as warnings, so the PR gate stays secrets-only for Java and Go and secrets plus template-literal SQL for JS/TS: block recall is 19% (JS/TS), 11% (Java) and 11% (Go).

### Catalog gaps

- At v3.6.3, `docs/security-catalog-contract.json` lists 85 checks.
- It omits the Python engine's own rules, which produce most Python detections: `PY_SQL_INJECTION`, `PY_SSRF`, `PY_PATH_TRAVERSAL`, `PY_OPEN_REDIRECT`, `PY_XSS_HTML_SINK`, `PY_WEAK_CRYPTO_PASSWORD`, `PY_JWT_WEAK` and others.
- It also omits the four JS pattern checks.
- Closed after v3.6.3: the catalog lists the Python engine's AST checks and its four JS pattern checks, 105 checks in all. That counts the 16 AST checks it first listed, `python.ast/PY_SSTI` added since, and the removal of `flask-missing-login-required`. With the Semgrep rule `python-random-token-assignment` added since, it lists 106. They are listed under the `rule_id` their findings carry, for example `python.ast/PY_SQL_INJECTION` and `SEC-JS_SQL_TEMPLATE`. The engine's spec-parser checks (`SEC-SPEC-*`) are not catalogued yet. See `CHANGELOG.md`, `[Unreleased]`.
- Closed after v3.6.3 for the new packs too: the JavaScript/TypeScript, Java and Go Semgrep packs add 51 `semgrep` checks (17, 15 and 19), so the catalog now lists 157.

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
- These timings predate the JavaScript/TypeScript, Java and Go Semgrep packs, so "the only language with Semgrep rules" no longer holds. A full `make parity` run on the integrated build took 1,350 s for 531 scans, the slowest scan taking 2.8 s (`spring`); this table was not re-measured.
- Real projects will be slower: larger files, networked dependency checks and DAST all add time.

## Limits of this measurement

- **Small cells.** Each framework × class cell has 2–4 vulnerable cases and 2 safe ones. Read cells as "covered or not", not as precise rates.
- **One idiom per variant.** For example, JS `alt_api` command injection uses `execSync`, so a different idiom can change a cell. Real codebases also have longer flows and framework helpers.
- **Independence.** The cases were written by authors who did not read the engine's rules or see any results. The original 252 cases were frozen before the extension.
- **Static analysis only.** DAST is framework-agnostic and not measured here.
