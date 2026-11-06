# Framework parity corpus: authoring spec

This corpus measures how well the engine detects the same vulnerability in
different web frameworks. Its value depends on one property: **every
framework gets the same cases, written the way a normal developer in that
framework would write them.** It must never be tuned to what the engine
happens to detect.

## Ground rules for authors

1. **Do not read the engine's rules or analyzers** (`go/`, `python/`, or any
   `rules` directory in this repository) while writing cases. Write idiomatic
   framework code from your own knowledge.
2. Use the **mainstream API** a developer in that framework reaches for first,
   not an obscure one, and not a contrived one. Examples are listed per class
   below. They are suggestions only; idiom wins.
3. **One case per file.** A case file contains exactly one request handler and
   exactly one marked line. Support files (app bootstrap, routing tables,
   `package.json`, `pom.xml`, `go.mod`, `urls.py`, settings) are allowed but
   must contain **no sink** of any class.
4. Mark the sink line with a trailing comment on that same line:
   - vulnerable cases: `EVAL-SINK` (`# EVAL-SINK` in Python, `// EVAL-SINK` elsewhere)
   - safe cases: `EVAL-SAFE` on the line that is the safe counterpart of the sink
5. Paths must not contain a `test`, `tests`, `testing`, `conftest`, `fixture` or
   `fixtures` segment, and file names must not look like test files
   (`test_*.py`, `*_test.py`, `*_test.go`, `*.spec.ts`, `*.test.ts`). The
   engine treats those as test code.
6. Code should be plausible and close to compilable or importable. Nothing is
   executed, so no dependency needs to be installed, but imports, routing and
   types should be real.
7. **Never write a real-looking credential.** For the secret class, write the
   placeholder tokens below verbatim. The harness substitutes synthetic,
   format-valid values only in a temporary copy at scan time:
   - `__EVAL_AWS_ACCESS_KEY_ID__`
   - `__EVAL_AWS_SECRET_ACCESS_KEY__`
   - `__EVAL_GITHUB_TOKEN__`

## Frameworks and roots

Each framework lives in `benchmarks/frameworks/<framework>/` with its own
`manifest.json`:

| framework | language | routing idiom |
|---|---|---|
| `django` | Python | function views; `urls.py` lists every case view |
| `flask` | Python | `@app.route` / blueprint decorators |
| `fastapi` | Python | `@app.get` / `APIRouter` decorators |
| `express` | JavaScript (CommonJS or ESM) | `app.get` / `router.post` |
| `nestjs` | TypeScript | `@Controller` + `@Get`/`@Post` |
| `nextjs` | TypeScript | App Router route handlers: `app/api/<case>/route.ts` |
| `spring` | Java | `@RestController` + `@GetMapping`/`@PostMapping` |
| `nethttp` | Go | `http.HandleFunc` / `http.ServeMux` |
| `gin` | Go | `gin.Default()` + `r.GET` |

## Classes (7) and variants (4)

Every class has these four variants in every framework, giving 28 cases per
framework.

| variant | vulnerable | meaning |
|---|---|---|
| `direct` | yes | request input reaches the sink in the handler, within a few lines |
| `indirect` | yes | request input is passed to a helper function **in the same file**, and the sink sits in the helper |
| `safe` | no | same handler shape, with the canonical fix applied |
| `safe_lookalike` | no | the same sink API is called, but its argument is **not** request-controlled (a constant, or a server-side value) |

For `hardcoded_secret`, "request input" doesn't apply. The variants are:

- `direct`: an AWS access key ID and secret assigned to module-level constants.
- `indirect`: a GitHub token in a config dict or object that a helper then uses in an `Authorization` header.
- `safe`: the same credentials read from environment variables.
- `safe_lookalike`: a long, high-entropy literal that is not a credential, such as a SHA-256 build digest constant named `BUILD_DIGEST`.

| class | vulnerable pattern | canonical safe fix | mainstream API examples |
|---|---|---|---|
| `sqli` | a query string built from request input | a parameterized query | Python `cursor.execute(f"...")` / Django `raw()`; Node `pg`/`mysql2` `query("..." + x)`; Java `JdbcTemplate`/`Statement.executeQuery`; Go `db.Query(fmt.Sprintf(...))` |
| `cmdi` | a shell command built from request input | an argv list with no shell, or an allowlist | Python `subprocess.run(..., shell=True)` / `os.system`; Node `child_process.exec`; Java `Runtime.getRuntime().exec(String)`; Go `exec.Command("sh", "-c", ...)` |
| `xss` | request input written into an HTML response unescaped | escaped output, or a framework template with autoescape | Python `HttpResponse`/`make_response`/`HTMLResponse` with f-string HTML; Node `res.send("<p>" + x)`; Next.js `new Response(html, {headers: text/html})`; Java `@ResponseBody` returning an HTML string; Go `fmt.Fprintf(w, "<p>%s", x)` with `text/html` |
| `ssrf` | an outbound HTTP request to a request-supplied URL | a host allowlist checked before the request | Python `requests.get`; Node `fetch`/`axios`; Java `RestTemplate`/`HttpClient`; Go `http.Get` |
| `path_traversal` | a file read from a path joined with request input | resolve the path, then check it stays under the base directory | Python `open(os.path.join(base, x))`; Node `fs.readFile(path.join(base, x))`; Java `Files.readAllBytes(Paths.get(base, x))`; Go `os.ReadFile(filepath.Join(base, x))` |
| `open_redirect` | a redirect to a request-supplied URL | allow only relative paths, or an allowlist of hosts | Python `redirect(x)` / `RedirectResponse(x)`; Node `res.redirect(x)`; Next.js `NextResponse.redirect(x)`; Java `"redirect:" + x` or `sendRedirect`; Go `http.Redirect(w, r, x, ...)` |
| `hardcoded_secret` | see above | see above | n/a |

## Extension 1: four more classes and two harder variants

Version 2 of the corpus adds **30 cases per framework**, for 58 in total. The
original 28 cases are **frozen**: never edit, rename or remove them, or their
manifest entries. The only exception is a case whose label is wrong, for
example a `safe` case that can be exploited. Such a case is corrected in place
and recorded under [Corrections](#corrections).

### New classes (4 classes × the same 4 variants = 16 cases)

| class | vulnerable pattern | canonical safe fix | `safe_lookalike` (same API, not a security use) | mainstream API examples |
|---|---|---|---|---|
| `weak_password_hash` | a password from the request hashed with MD5 or SHA-1 for storage or comparison | bcrypt, argon2, scrypt or PBKDF2 | MD5/SHA-1 of file contents or a cache key (ETag, dedup) | Python `hashlib.md5`; Node `crypto.createHash("md5")`; Java `MessageDigest.getInstance("MD5")`; Go `md5.Sum` |
| `jwt_no_verify` | a bearer token from the request decoded and trusted **without** verifying its signature | decode **with** a key and an explicit algorithm list | read only the unverified *header* (e.g. `kid`) to pick a key, then verify | PyJWT `jwt.decode(..., options={"verify_signature": False})`; `jsonwebtoken.decode`; jjwt or auth0 java-jwt `JWT.decode`; golang-jwt `ParseUnverified` |
| `weak_random_token` | a password-reset, session or API token generated with a non-cryptographic RNG | the CSPRNG | the non-crypto RNG used for something harmless (shuffling, retry jitter) | Python `random`; `Math.random`; `java.util.Random`; Go `math/rand` |
| `ssti` | a **template string** taken from the request and rendered | a fixed template, with the request value passed only as a variable | the same render API called with a constant template string | Jinja2 `render_template_string` / `Template(x)` / Django `Template(x)`; `ejs.render` / `pug.compile` / `handlebars.compile`; Velocity/Freemarker/Thymeleaf from a string; Go `text/template` `Parse(x)` |

### Harder variants of the original 7 classes (7 classes × 2 = 14 cases, all vulnerable)

| variant | meaning |
|---|---|
| `cross_file` | the handler reads request input and passes it to a function in **another file**. The sink lives in that other file. Each `cross_file` case gets its **own** helper file, used by no other case. |
| `alt_api` | the same vulnerability through a **second mainstream API**, request input to sink directly in the handler. Examples: SQL with `Statement.executeQuery` (Java), `connection.query("..." + x)` with concatenation (Node), `session.execute(text(f"..."))` (SQLAlchemy), `db.QueryRow`/`db.Exec` (Go); command injection with `os.system` (Python), callback `exec(cmd, cb)` or `execSync` (Node), `ProcessBuilder("sh", "-c", ...)` (Java); SSRF with `urllib.request.urlopen`/`httpx`, `axios`, `new URL(x).openConnection()`/`HttpClient`, `http.NewRequest` + `client.Do`; path traversal with `send_file`/`FileResponse`, `res.sendFile`, `FileInputStream`, `http.ServeFile`; open redirect with `HttpResponseRedirect`, `res.writeHead(302, {Location})`, `ResponseEntity...location(...)`, `w.Header().Set("Location", x)`; XSS with `Markup`/`mark_safe`, `res.write`, `response.getWriter().write`, Go `template.HTML(x)` |

For `hardcoded_secret`:

- `cross_file` puts the AWS pair in a separate config module that the handler imports.
- `alt_api` is a **database connection URL with an embedded password**, using the placeholder `__EVAL_DB_PASSWORD__`. For example `postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app`.

### Multi-file cases

A `cross_file` case has two files:

- `file` is the file with the sink and the marker.
- `entry_file` is the handler file. It has no marker and no sink.

Both files belong to that case only.

### New placeholder

- `__EVAL_DB_PASSWORD__`

Write it verbatim, like the other placeholders.

## Manifest

`benchmarks/frameworks/<framework>/manifest.json`:

```json
{
  "framework": "flask",
  "language": "python",
  "cases": [
    {"id": "flask-sqli-direct", "class": "sqli", "variant": "direct", "vulnerable": true, "file": "app/sqli_direct.py"}
  ]
}
```

- `id` is `<framework>-<class>-<variant>`.
- `file` is relative to the framework root.
- A `cross_file` case adds `"entry_file": "<handler file>"`.
- The manifest lists exactly 58 cases: the 28 original cases, unchanged, plus the 30 from Extension 1.
- Each case file contains exactly one line with `EVAL-SINK` (vulnerable) or `EVAL-SAFE` (safe).

## Corrections

Changes to frozen cases, newest first. Each keeps the case's id, label, file
and marker line.

- **2026-10-25: `django-ssrf-safe`, `flask-ssrf-safe`, `fastapi-ssrf-safe`.**
  - **What was wrong:** these `safe` cases could be exploited. Their guard was
    `parsed.hostname not in ALLOWED_FETCH_HOSTS`, and a `urlparse` hostname
    allowlist can be bypassed with a backslash in the authority. For
    `https://169.254.169.254\@api.example.com/`, `urlparse(...).hostname` is
    `api.example.com`, but requests (through urllib3) connects to
    `169.254.169.254`. Browsers read `\` as `/` and do the same with a
    redirect.
  - **The fix:** the guard line now checks `parsed.netloc`, the whole
    authority. An exact match against a set of bare hosts leaves no room for
    userinfo, a backslash or a port. Nothing else in the files changed.
  - **Comparability:** results for these three cases before and after this date
    are not comparable.
  - **Provenance:** the correction was made during engine work by someone who
    had read the analyzers, against ground rule 1. The new guard is the form
    the Python engine recognises.
  - **For authors:** to write a host allowlist in Python, compare `netloc` (or
    the host after rejecting `\` and `@`), not `hostname`.
