# Semgrep Rule Guide

Fendix's white-box engine bundles 55 Semgrep rules across ten files:
23 Python rules in four (auth, injection, secrets, crypto), 17
JavaScript/TypeScript rules in three (javascript-injection, javascript-web,
javascript-crypto) and 15 Java rules in three (java-injection, java-web,
java-crypto). It extracts them to a per-process temp directory at
scan time. This guide explains the metadata Fendix
expects, how rules are mapped into the Finding model, and the conventions
to follow when writing project-specific rules.

For an introduction to Semgrep itself, see the upstream
[Semgrep docs](https://semgrep.dev/docs/).

---

## How Fendix runs Semgrep

The Semgrep runner lives at
[`go/internal/scanner/semgrep/scanner.go`](../go/internal/scanner/semgrep/scanner.go)
(post-TASK-116 this is native Go, not Python). At scan time it:

1. Calls `exec.LookPath("semgrep")`. If Semgrep isn't on `$PATH`, the
   runner returns `ErrSemgrepUnavailable` and the orchestrator logs an
   "install semgrep for X% more checks" notice — the rest of the
   white-box scan continues.
2. Extracts the embedded `//go:embed rules/*.yaml` pack to a per-process
   temp directory on the first scan call.
3. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet
   --dataflow-traces --timeout 30 --exclude node_modules --exclude dist
   --exclude build --exclude .next --exclude target --exclude vendor
   --exclude '*.min.js' <code_path>`, with a 300-second deadline on the
   whole run. A run that exceeds the deadline fails, and the scan has no
   Semgrep findings.
4. Parses the JSON output and maps each result to a Fendix `Finding` via
   `resolveSeverity`, `resolveConfidence`, `resolveCategory`,
   `resolveCWE`.

`<rules_dir>` is the temp extraction of
[`go/internal/scanner/semgrep/rules/`](../go/internal/scanner/semgrep/rules/);
every `.yaml` file in that directory is loaded.

**Per-rule timeouts.** `--timeout 30` lets one rule run for up to 30
seconds on one file. Semgrep's default, 5 seconds, can cut a taint rule off
on a large file, and no bound at all would let one pathological file use up
the whole deadline. When a rule hits the bound, Semgrep skips that rule on
that file, keeps going, and lists the pair in its output's `errors` as a
`Timeout`. Fendix logs each one with the rule and the file, keeps the
findings the run did produce, and records the `semgrep` entry in
`scanner_status` as `failed` with reason `timeout` and a detail naming the
rules and files: the run delivered only part of its findings, like a pass
cut short by Fendix's own deadline. `--fail-on-scanner-error` and the
coverage gates see it. Semgrep's `--timeout-threshold` (3 by default) also
applies: after three rules time out on one file, it skips the remaining
rules on that file.

**Build output and vendored code are not scanned.** The `--exclude`
patterns skip `node_modules/`, `dist/`, `build/`, `.next/`, `target/` and
`vendor/` at any depth, and every `*.min.js` file, for every language.
`dist/` and `build/` are also where Python packaging writes its output.
A directory of the project's own source that has one of these names, such
as a Python package called `build` or `vendor`, is skipped too. textscan
skips the same directories, and the secrets scanner all of them but
`.next/` and `target/`. The patterns match paths relative to the scanned
directory: a repository checked out under `/srv/build/` is scanned, and so
is a file named `build.py`. A `--diff` scan that changes only files under these
directories gets no Semgrep findings from them. Semgrep skips most of
these directories by itself, but only in a project that has no
`.semgrepignore` of its own, and never `.next/` or `target/`.

> **Install Semgrep for full coverage.** Without it, only the
> [AST analyzer](./checks/ast-analyzer.md) and
> [secrets scanner](./checks/secrets.md) run on the white-box side.
> Install with `pip install semgrep`.

---

## Rule shape

Every rule is a YAML object inside the top-level `rules:` array of a file
in `go/internal/scanner/semgrep/rules/`. Below is the canonical shape
Fendix expects:

```yaml
rules:
  - id: my-organisation-flask-no-csrf
    patterns:
      - pattern: |
          @$APP.route(...)
          def $FUNC(...):
              ...
      - pattern-not: |
          @csrf_protect
          def $FUNC(...):
              ...
    message: >
      Flask route '$FUNC' is missing CSRF protection.
      Wrap it with @csrf_protect or use Flask-WTF's CSRFProtect.
    languages: [python]
    severity: ERROR
    metadata:
      category: auth
      cwe: CWE-352
      confidence: HIGH
      fendix_severity: HIGH
      fendix_title: Flask route is missing CSRF protection.
      fendix_remediation: >-
        Flask route is missing CSRF protection. Wrap it with @csrf_protect
        or use Flask-WTF's CSRFProtect.
```

The mandatory keys are the standard Semgrep ones: `id`, `patterns` (or
`pattern`), `message`, `languages`, `severity`. The `metadata` block is
where Fendix-specific information lives.

### `metadata` keys Fendix reads

| Key | Type | Required | Used to populate |
|---|---|---|---|
| `category` | string enum | yes | `Finding.category`: one of `injection`, `xss`, `crypto`, `auth`, `secrets` (see below). Defaults to `code` when unset. |
| `cwe` | string or list | yes | `Finding.references`, in the form `CWE-89`. Multiple CWEs may be passed as a list. |
| `confidence` | string enum | yes | `Finding.confidence` (`HIGH` / `MEDIUM` / `LOW`). Defaults to `MEDIUM`. A taint rule declares `MEDIUM`. |
| `fendix_severity` | string enum | yes | `Finding.severity` (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`). When unset, Fendix falls back to mapping Semgrep's own `severity` (`ERROR`→`HIGH`, `WARNING`→`MEDIUM`, `INFO`→`LOW`). |
| `fendix_title` | string | yes | The check's title in the public security catalog (`docs/security-catalog-contract.json`). Static text without metavariables. A finding's own title is the first line of `message`. |
| `fendix_remediation` | string | yes | The check's remediation in the security catalog. Static text without metavariables. A finding's fix text is `message`. |
| `fendix_reachability` | `taint` | taint rules only | Asks for a `mode: taint` rule's matches to count as reachability (ADR-011). Only a taint rule may set it, and every taint rule does. |

Every rule in the bundled pack carries all six required keys, and its
`languages` are drawn from `python`, `javascript`, `typescript`, `java` and
`go`. `TestEveryRuleCarriesFendixMetadata` in
[`scanner_rulepack_test.go`](../go/internal/scanner/semgrep/scanner_rulepack_test.go)
fails otherwise. It also holds two naming rules:

- **Taint rules** (`mode: taint`) are named `<lang>-<class>-taint`, such as
  `js-sqli-taint`, and declare `confidence: MEDIUM` and
  `fendix_reachability: taint`.
- **Shape rules** that report a non-constant argument reaching a sink are
  named `<lang>-<class>-sink`. Each one excludes a fully literal argument
  with a `pattern-not` (`"..."`), and a module constant with a
  `pattern-not-inside` for the language's constant binding: `const $X = ...`
  in JavaScript and TypeScript, `static final String $X = ...` in Java, and
  both `const $X = ...` and a `const ( ... )` block in Go.

### The Java packs

`java-injection.yaml`, `java-web.yaml` and `java-crypto.yaml` hold ten
taint rules (`java-sqli-taint`, `java-cmdi-taint`, `java-ssti-taint`,
`java-xss-taint`, `java-ssrf-taint`, `java-path_traversal-taint`,
`java-open_redirect-taint`, `java-weak_password_hash-taint`,
`java-jwt_no_verify-taint`, `java-weak_random_token-taint`) and five shape
rules (`java-sqli-sink`, `java-xss-sink`, `java-ssrf-sink`,
`java-path_traversal-sink`, `java-open_redirect-sink`).

- **Request sources.** A Spring handler parameter annotated
  `@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
  `@CookieValue`, `@ModelAttribute`, `@RequestPart` or `@MatrixVariable`,
  or a plain `String` parameter of a request-mapping method; never a
  number, boolean, date, UUID or framework object. `HttpServletRequest`'s
  `getParameter`, `getParameterValues`, `getHeader`, `getQueryString`,
  `getInputStream` and `getReader`.
- **One call deep.** Open-source Semgrep follows taint within one method.
  So a parameter of a method of the same class is a source too, when a
  handler calls it with the same number of arguments (one to three) and
  passes, at that position, the request value itself, a getter of it, or a
  concatenation or `String.format` of such values. Only the class's own
  methods count, not a nested class's, and a value the handler sanitised in
  the call or reassigned before it is not followed. Taint then follows that
  method's body, and the finding is reported at the sink inside it.
- **Guards.** A host allowlist (on the host itself), a path containment
  check or a local-path redirect check (both halves, each with its
  polarity) makes a value safe only when the branch taken on a failing
  check ends with a direct `return` or `throw` (for a redirect, also a
  direct assignment of a literal), not under an `&&`; or when the use is in
  the then-branch of a passing check with no `else`. The taint rules
  apply them as sanitizers to the uses after (or inside) the check;
  `java-ssrf-sink` and `java-open_redirect-sink` apply the same guards as
  negations, and `TestJavaSinkRulesShareTheirTaintRulesBlocks` keeps the
  copies equal.
- **Shape rules** cover a sink in another class: a non-private method
  whose own `String` parameter is concatenated into SQL or HTML, is the
  URL of a request or a redirect, or is a file name joined to a directory.
  They prove no flow, so they never count as reachable.
- **The crypto rules' sources** are the weak value itself: a value named
  like a password, a JWT decoded without verification, a
  `java.util.Random`. The flow to where it is trusted is the finding.
- **Java is enabled in the taint gate** (`ReachabilityLanguages`, ADR-011):
  a Java taint match is reachable, escalated one severity level, and can
  block at or above `--fail-on`. A shape rule's finding only warns.
- Semgrep cannot share a block between rules, so the request sources are
  repeated in every taint rule of `java-injection.yaml` and
  `java-web.yaml`; `TestJavaTaintRulesShareTheirBlocks` keeps the copies
  equal. The tests are `ruletests/java-*.java`.

### Why `fendix_severity` exists separately from `severity`

Semgrep's `severity` (`ERROR`/`WARNING`/`INFO`) describes how the rule
behaves in Semgrep's own UI — it's primarily a CI-failure signal. Fendix's
severity scale has five buckets and is tied to a numeric scoring formula
(see [`docs/adr/ADR-003-severity-scoring.md`](./adr/ADR-003-severity-scoring.md)).
The two scales don't map cleanly. `fendix_severity` lets a rule say "I'm
a Semgrep `ERROR` for CI gating, but in Fendix's vocabulary I'm a
`CRITICAL`" — JWT bypass is the canonical example.

---

## Categories

A rule in the bundled pack uses one of five categories.
`TestEveryRuleCarriesFendixMetadata` rejects any other.

| Category | Use for |
|----------|---------|
| `injection` | Input reaching an interpreter or a resource: SQL, command, code (`eval`), template (SSTI) and deserialization, and also SSRF, path traversal and open redirect. |
| `xss` | Input written into an HTML response. |
| `auth` | Missing or bypassable authentication: an unprotected route, a JWT decoded without verifying its signature. |
| `secrets` | Hardcoded credentials, keys and certificates. The bundled Python rules for weak password hashing, legacy ciphers and non-cryptographic random tokens also use it. |
| `crypto` | Weak cryptography. textscan's weak-crypto checks use it, and so do the JavaScript/TypeScript and Java rules for weak password hashing and weak random tokens, so a finding of both on one line collapses into one. |

There is no separate category for SSRF, path traversal, open redirect or
SSTI. The engine collapses two findings on one line only when their
categories match, and textscan reports these as `injection`. A Semgrep rule
with its own category would be reported a second time beside textscan's
finding for the same code.

---

## The JavaScript and TypeScript pack

`javascript-injection.yaml`, `javascript-web.yaml` and
`javascript-crypto.yaml` cover Express, NestJS and Next.js (App Router).
Every rule runs on both `.js` and `.ts` files. Each has tests in
[`ruletests/`](../go/internal/scanner/semgrep/ruletests/).

**Request sources**, the same in every taint rule:

- Express: `req.query`, `req.params`, `req.body`, `req.headers`,
  `req.cookies`, `req.get(...)` and `req.header(...)`, on a request named
  `req` or `request`.
- NestJS: a parameter bound by `@Query()`, `@Param()`, `@Body()` or
  `@Headers()`, and the same accessors on a `@Req()` parameter of any name.
- Next.js: `request.nextUrl.searchParams`, `request.json()`,
  `request.formData()`, `request.text()` and `request.headers` (on the
  request of a `GET`, `POST`, ... route handler, of any name), and the
  `params` of its context argument.

**Taint rules** (`-taint`) report a source reaching a sink inside one
function:

| Rule | Sinks | Not a finding |
|---|---|---|
| `js-sqli-taint` | the query text of `query`, `execute`, `raw` (and knex's `*Raw`), `$queryRawUnsafe`, `$executeRawUnsafe`, and the `text` of a pg config object, inline or bound to a name first | a values array; a value made only of constants: a repeated literal (`'?,'.repeat(n)`), a list mapped to literals or to its index (`ids.map(() => '?')`, `ids.map((_, i) => '$' + (i + 1))`), `Array(n).fill('?')` and `Array.from({ length: n }, () => '?')`, the `length` of a real array (map, filter or split output, an array literal, or a name bound from one; not of request data, whose `length` can be a string), a lookup in a const object of literals with a literal fallback (`SORT_MAP[s] ?? 'id'`), or a call to a same-file helper, declared before the call, that is exactly that one lookup (`function col(s) { return SORT_MAP[s] ?? 'id'; }`; a helper with any other body, such as a `switch` of literal returns, is not recognised); an identifier allowlist (a constant name or an array literal of string literals: `ALLOWED.has(v)`, `['asc', 'desc'].includes(v)`) that rejects with a direct `return` or `throw` (alone or an operand of `\|\|`, never under `&&`), resets the value to a literal, or picks a literal in a ternary; a config object passed inline or by name (its `values` are bound; a GraphQL client's options are not SQL); an SQL builder's tagged template, always parameterized, when the tag is named `sql` (any case, on any object): `` sql`...${id}` `` (postgres.js, drizzle), slonik's `sql`, `sql.type(...)`, `sql.unsafe`, `sql.typeAlias(...)` and `sql.fragment`, `Prisma.sql`, `` prisma.$queryRaw`...` ``, sql-template-strings' `SQL`. A project's own tag (`buildSql`, `rawSql`, `sqlConcat`), `String.raw`, `sql.raw(...)` and an aliased import (`import { sql as q }`) are not |
| `js-cmdi-taint` | `child_process` `exec` and `execSync` (as a member, destructured, imported or promisified); `spawn`/`execFile` with `shell: true`; `spawn("sh", ["-c", cmd])` | `execFile` or `spawn` with an argument array and no shell |
| `js-ssti-taint` | the template argument of `ejs.render`, `pug.compile`/`render`, `Handlebars.compile`, `nunjucks.renderString` and similar | a fixed template with the input in its data |
| `js-xss-taint` | `res.send`/`write`/`end` of a string built with markup or of a value named like HTML, anything sent after the response is typed as HTML, and a `Response`/`NextResponse` typed `text/html` | an HTML escaper: `escapeHtml`/`escape` (escape-html), `he.encode`/`he.escape`, lodash and validator `escape`, `DOMPurify.sanitize`, `sanitizeHtml`, `xss`/`filterXSS`, `encodeURI`, `encodeURIComponent` (not a decoder such as `unescape` or `he.decode`, nor `_.escapeRegExp`); the output of an engine rendering a fixed template (`nunjucks.render('page.njk', ...)`, `ejs.renderFile(...)`) that does not write a value raw (ejs `<%-`, Mustache and Handlebars `{{{`, nunjucks `\| safe`, pug `!=`), or of React's `renderToString`; a non-HTML response |
| `js-ssrf-taint` | the URL of `fetch`, `axios`, `got`, `http(s).get`/`request`, `undici.request` | a host allowlist that rejects: `if (!ALLOWED.has(<host>)) return` or `throw`, the check alone or an operand of `\|\|` (never under `&&`), the `return` or `throw` a direct statement of the body (not inside a callback, an inner `if` or a loop), with the host read off a URL object, off `new URL(url)`, or destructured from it (the URL object and the string it parsed are both clean afterwards; a denylist or a check that does not leave is not one); a URL whose literal start fixes the scheme and host (`https://api.example.com/users/${id}`), built inline or in a variable first, or that begins with a constant base |
| `js-path-traversal-taint` | the path of `readFile`, `readFileSync`, `createReadStream` (also `fs.promises`), `res.sendFile`, `res.download` | `path.basename(...)`; `res.sendFile`/`res.download` with a `root` option; a containment check that rejects, with the same rules as the SSRF allowlist: `if (!p.startsWith(BASE + path.sep)) return` or `throw` on a path bound from `path.resolve(...)` (on raw input or a concatenation, `/srv/files/../../etc/passwd` passes a prefix check), or `rel = path.relative(BASE, p); if (rel.startsWith('..') \|\| path.isAbsolute(rel)) return` (a bare `startsWith(BASE)` is not containment) |
| `js-open-redirect-taint` | `res.redirect`, `res.location`, a `Location` header, `NextResponse.redirect` (also of `new URL(target, base)`), Next.js `redirect()`, a `Response` with a `Location` header | a guard that checks both halves and leaves, with the same rules as the SSRF allowlist: `if (!target.startsWith('/') \|\| target.startsWith('//')) return`; the ternary `isLocal ? target : "/"` with `isLocal = target.startsWith('/') && !target.startsWith('//')`; a target whose literal start is a same-site path segment (`/settings/${tab}`), built inline or in a variable first. Checking only `//` is not enough: `https://evil.com` passes it |
| `js-weak-password-hash-taint` | `createHash("md5"/"sha1").update(pw)` where `pw` is named `pass(word)?` or `pwd` (`pass`, `userPass`, `passwd`, `newPassword`), or comes from a request field named that way | `bcrypt`, `scrypt`, `argon2`, PBKDF2, SHA-256 |
| `js-jwt-no-verify-taint` | `jwt.decode(token)` of a request token, and `decode(token, { complete: true })` when its `payload` is read | `jwt.verify`; reading only the header of a complete decode, or decoding to choose a key that `jwt.verify` then checks |
| `js-weak-random-token-taint` | `Math.random()` output assigned to a variable, property or key whose last name segment is a token word, optionally followed by `Id`, `Value`, `Hash`, `Str` or `String` (`resetToken`, `sessionId`, `apiKey`, `otp`, `csrfToken`, `RESET_TOKEN`), or returned by a function named that way | `crypto.randomBytes`, `randomUUID`, `getRandomValues`; `Math.random()` for jitter or shuffling, even when the name starts with a token word (`resetDelayMs`, `sessionTimeout`, `tokenRefreshJitter`) |

**Test code.** No rule of the pack reports in test, mock or fixture code:
every rule has `paths: exclude:` for `**/__tests__/**`, `**/__mocks__/**`,
`**/__fixtures__/**`, `**/mocks/**`, `**/mock/**`, `**/fixtures/**`,
`**/test/**`, `**/tests/**`, `**/spec/**`, `**/e2e/**`, `**/cypress/**`,
`*.test.*`, `*.spec.*`, `*.e2e-spec.*` and `*.cy.*`. Semgrep matches them
against paths relative to the scan root, so a repository checked out under a
directory named `test` is still scanned.

**Shape rules** (`-sink`) report the same sink reached through a call,
which Semgrep CE's intraprocedural taint does not follow: a helper whose
parameter is the query text (`js-sqli-sink`), the command line
(`js-cmdi-sink`), the template (`js-ssti-sink`), the HTML markup
(`js-xss-sink`), the redirect target (`js-open-redirect-sink`) or the token
it decodes without verifying (`js-jwt-no-verify-sink`); and a value named
like a password hashed with MD5 or SHA-1 (`js-weak-password-hash-sink`). A shape finding never counts as reachability.
SSRF and path traversal have no shape rule: helpers that fetch a URL or
read a file by a parameter are too common in clean code.

The taint rules' matches count as reachability only for a language enabled
in `semgrep.ReachabilityLanguages`
([ADR-011](./adr/ADR-011-semgrep-taint-reachability.md)). JavaScript and
TypeScript are: the pack's precision on the framework-parity development set
is 0.97, and it adds no finding to the clean `node-express-realworld`
application. A taint finding is therefore reachable, in the
`semgrep_taint` tier, and blocks at or above `--fail-on` on its reachable
path. A shape finding stays a `semgrep_shim` finding that warns. The
`fendix_severity` of `js-sqli-taint`, `js-cmdi-taint` and `js-ssti-taint`
is `HIGH` and the others' `MEDIUM`. A reachable finding is escalated one
level, and a taint rule's `MEDIUM` confidence caps severity at `HIGH`, so
every proven finding of the pack reports `HIGH`.

---

## Severity guidance

Use `fendix_severity` consistently with the project's scoring model:

- **`CRITICAL`** — directly exploitable on its own. Hardcoded production
  credential. JWT signature verification disabled. SQL injection in a
  string-format query. Reserve for "fix this before lunch."
- **`HIGH`** — exploitable with a precondition or access. SSRF on a
  non-public endpoint. Missing auth on a sensitive route.
- **`MEDIUM`** — defence-in-depth violation, or a heuristic with real
  false-positive risk. Open-redirect candidates. Permissive CORS without
  credentials. Pattern-only matches that need eyeballs.
- **`LOW`** — informational with mild impact. Non-secret hardcoded
  identifier. Out-of-date dependency without a known CVE.
- **`INFO`** — diagnostic only. Reserve for rules you want in the report
  but never want a `--fail-on` to fire on.

Fendix enforces a consistency rule: a finding with `confidence: LOW`
cannot have `severity` higher than `MEDIUM`. The orchestrator will
downgrade and warn. Tune `confidence` to match the rule's true precision —
don't over-claim `HIGH` for pattern matches that have known false positives.

> **Since v2.0, severity alone will not fail a build from a semgrep rule.** The
> semgrep-shim tier is excluded from the `deterministic detection` confidence
> bonus — it is a documented false-positive class — so a shape-match finding
> scores `35 base + 10 static − 5 tier = 40`, lands in the `MEDIUM` band (which
> starts at 40), and with no corroborating signal is held at `WARN` rather than
> `BLOCK`. **A semgrep HIGH
> with no taint chain no longer gates on its own.** What lifts one back to
> blocking is corroboration: a proven taint path, a confirmed route, or
> cross-engine agreement with the live scan. `--enforce-confidence=false`
> restores the pre-2.0 severity-only gate for the whole scan, but that is a
> blunt instrument — prefer writing rules whose findings can be corroborated.

---

## Worked examples

### Auth — JWT decoded without signature verification

Source: [`go/internal/scanner/semgrep/rules/auth.yaml`](../go/internal/scanner/semgrep/rules/auth.yaml)

```yaml
- id: python-jwt-decode-no-verification
  patterns:
    - pattern: jwt.decode($TOKEN, options={"verify_signature": False, ...}, ...)
    - pattern: jwt.decode($TOKEN, algorithms=["none"], ...)
  message: >
    JWT decoded with signature verification disabled.
    This allows an attacker to forge tokens.
    Remove options={"verify_signature": False} and specify a strong algorithm.
  languages: [python]
  severity: ERROR
  metadata:
    category: auth
    cwe: CWE-347
    confidence: HIGH
    fendix_severity: CRITICAL
```

Why it's CRITICAL: a rule that triggers means an attacker can forge any
token. There's no second precondition.

### Injection — SQL via string formatting

Source: [`go/internal/scanner/semgrep/rules/injection.yaml`](../go/internal/scanner/semgrep/rules/injection.yaml)

```yaml
- id: python-sql-injection-string-format
  patterns:
    - pattern-either:
        - pattern: $CURSOR.execute("..." % ..., ...)
        - pattern: $CURSOR.execute("..." + ..., ...)
        - patterns:
            - pattern: $CURSOR.execute(f"...{$VAR}...", ...)
            - metavariable-pattern:
                metavariable: $VAR
                patterns:
                  - pattern: $PART
                  - pattern-not: '"..."'
        - patterns:
            - pattern: $CURSOR.execute(f"...{$VAR}...", ...)
            - pattern-either:
                - pattern-inside: |
                    def $INNER(...):
                      ...
                      nonlocal $VAR
                      ...
                    ...
                - pattern-inside: |
                    lambda $...PARAMS: $BODY
        - pattern: $CURSOR.execute("...".format(...), ...)
    - pattern-not: $CURSOR.execute("..." % "...", ...)
    - pattern-not: $CURSOR.execute("..." + "...", ...)
  message: >
    SQL query built via string formatting — SQL injection risk.
    Use parameterized queries: cursor.execute("SELECT ... WHERE x = %s", (value,))
  languages: [python]
  severity: ERROR
  metadata:
    category: injection
    cwe: CWE-89
    confidence: HIGH
    fendix_severity: CRITICAL
```

The alternatives sit under `pattern-either`: sibling `pattern:` entries
under `patterns:` must all match at once, so they never fire. The first
f-string branch fires only on an interpolation that is not a string
constant. Semgrep's constant propagation lets `"..."` match a name whose
value is a known string literal, so `f"SELECT id FROM {USERS_TABLE}"` with
`USERS_TABLE = "users"` at module level is not reported. Each interpolation
is checked on its own, so `f"SELECT {COLS} FROM users WHERE n = '{name}'"`
fires on `name`. The propagation follows a rebinding in the same function,
at module level and by a `global` write, so a constant rebound from input
there still fires.

It works one function at a time, so it misses a rebinding through
`nonlocal` and one made after a lambda is defined. The second f-string
branch covers both: it fires on a name that a nested function declares
`nonlocal`, and on every f-string inside a lambda. One gap remains: a module
literal replaced by an import of the same name (`TABLE = "users"`, then
`from settings import TABLE`, or the import inside the function) keeps the
literal's value and is not reported.

### Secrets — hardcoded password / key assignment

Source: [`go/internal/scanner/semgrep/rules/secrets.yaml`](../go/internal/scanner/semgrep/rules/secrets.yaml)

```yaml
- id: python-hardcoded-secret-assignment
  patterns:
    - pattern: $KEY = "$VALUE"
    - metavariable-regex:
        metavariable: $KEY
        regex: (?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|client_secret|private_key)
    - metavariable-regex:
        metavariable: $VALUE
        regex: .{6,}
  pattern-not: $KEY = ""
  message: >
    Hardcoded secret found in assignment to '$KEY'.
    Move secrets to environment variables or a secrets manager.
    Rotate the exposed credential immediately.
  languages: [python]
  severity: ERROR
  metadata:
    category: secrets
    cwe: CWE-798
    confidence: HIGH
    fendix_severity: CRITICAL
```

`pattern-not: $KEY = ""` excludes the empty-string idiom that often
appears in placeholder code. Use `pattern-not` aggressively — false
positives erode trust faster than missed findings.

---

## Writing your own rule

1. **Find the smallest pattern that matches your concern.** A two-line
   pattern is easier to maintain than a 20-line one.
2. **Add `pattern-not` for known-good idioms.** Skim a real codebase for
   the patterns you'd never want to flag, then add a `pattern-not` for
   each.
3. **Pick `confidence` honestly.** If your rule's pattern matches more
   than the actual issue, downgrade to `MEDIUM` or `LOW`.
4. **Audit the rule pack.**
   [`go/internal/scanner/semgrep/scanner_rulepack_test.go`](../go/internal/scanner/semgrep/scanner_rulepack_test.go)
   checks every rule against the metadata contract above
   (`TestEveryRuleCarriesFendixMetadata`), and that no two rules share an
   `id`. When you add a rule, bump `rulepackTotalCount` in the same commit
   so the count assertion stays green.
5. **Write rule tests.** A pack for a language other than Python has a
   test file per rule file:
   [`go/internal/scanner/semgrep/ruletests/<stem>.<ext>`](../go/internal/scanner/semgrep/ruletests/README.md)
   tests `rules/<stem>.yaml`, with a `ruleid:` and an `ok:` line for every
   rule. Run them with
   `semgrep --test --config go/internal/scanner/semgrep/rules go/internal/scanner/semgrep/ruletests`.
6. **Run the suite locally.**

   ```bash
   make test                                            # full suite
   cd go && go test ./internal/scanner/semgrep/...      # just the Semgrep package
   ```

7. **Verify the rule resolves cleanly.** Semgrep itself will warn on
   pattern syntax errors:

   ```bash
   semgrep --config go/internal/scanner/semgrep/rules/ --validate
   ```

   The `TestRulepack_ValidatesViaSemgrepCLI` test runs this
   automatically when `semgrep` is on `$PATH`; it skips otherwise so
   contributors without semgrep installed aren't blocked.

### Project-local rule files

The Fendix engine runs Semgrep against the rules directory bundled inside
the binary. To use project-specific rules today, layer them in by either
(a) running Semgrep directly alongside Fendix and folding the JSON results
into your CI report, or (b) building Fendix from source with your rule
files added to `go/internal/scanner/semgrep/rules/`.

A `--semgrep-rules` flag for layering external rule directories at scan
time is on the backlog — track progress in the GitHub issue tracker.

---

## Mapping reference (cheat sheet)

| Semgrep result | → | Fendix Finding field |
|---|---|---|
| `metadata.category` | → | `category` |
| `metadata.cwe` | → | `references[]` |
| `metadata.confidence` | → | `confidence` |
| `metadata.fendix_severity` | → | `severity` |
| `extra.severity` (fallback) | → | `severity` (mapped: ERROR→HIGH, WARNING→MEDIUM, INFO→LOW) |
| `check_id` | → | `title` |
| `extra.message` | → | `evidence` (truncated to 200 chars) |
| `path` + `start.line` | → | `endpoint`, `line` ("path:line") |

See [`go/internal/scanner/semgrep/scanner.go`](../go/internal/scanner/semgrep/scanner.go)
for the implementation.

---

## Further reading

- [Semgrep pattern syntax](https://semgrep.dev/docs/writing-rules/pattern-syntax)
- [Semgrep metavariables](https://semgrep.dev/docs/writing-rules/pattern-syntax#metavariables)
- [Fendix scoring model — ADR-003](./adr/ADR-003-severity-scoring.md)
- [Fendix Semgrep check overview](./checks/semgrep.md)
