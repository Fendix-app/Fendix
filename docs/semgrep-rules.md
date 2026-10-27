# Semgrep Rule Guide

Fendix's white-box engine bundles 23 Semgrep rules across four files
(auth, injection, secrets, crypto) and extracts them to a per-process
temp directory at scan time. This guide explains the metadata Fendix
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
| `crypto` | Weak cryptography. textscan's weak-crypto checks use it. |

There is no separate category for SSRF, path traversal, open redirect or
SSTI. The engine collapses two findings on one line only when their
categories match, and textscan reports these as `injection`. A Semgrep rule
with its own category would be reported a second time beside textscan's
finding for the same code.

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
