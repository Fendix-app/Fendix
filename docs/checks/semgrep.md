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
measured their precision at 0.077, 0.111 and 0.091 (at commit `6901cf7`, Semgrep 1.141.0), below the 0.80 the
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

1. On the first scan of a process, `ensureRules()` extracts the embedded pack to a temp dir (cached in a `sync.Once` for the process lifetime). The extracted copy has every rule's `paths.exclude` removed (`rulepaths.go`, decision D6'): the embedded pack carries test, mock and fixture path filters, which made every rule of a language skip such a file, and no source file is left out of a scan for its path. `paths.include` is kept
2. Decides the scope from the tree before it runs Semgrep (`go/internal/scanner/semgrep/targets.go`, `go/internal/scope`): it lists the in-scope files Semgrep is meant to evaluate and what is declared out of scope (a symbolic link and, by policy, a recognised lockfile; see "Scope (decisions D6 and D5-2)" below). `--code` that is itself a symbolic link is resolved first: `<code_path>` below is the directory it resolves to, because Semgrep does not follow a linked scanning root; links below it are never followed.
3. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet --disable-version-check --time --max-target-bytes 1048576 --disable-nosem --dataflow-traces --timeout 30 --jobs <n> --max-memory <MiB> --project-root <code_path> --x-ignore-semgrepignore-files [--exclude /.git] [--exclude <anchored unreadable entry> ...] [--include=<changed file> ...] -- <absolute target> ...`, inside a wall budget (see "Runtime and memory budget"). Each option does one thing:
   - `--timeout 30` bounds one rule on one file; a rule that hits it loses its matches in that file, and Semgrep's `--timeout-threshold`, left at its default of 3, skips every remaining rule on a file after three such timeouts. Semgrep reports a taint rule that ran out of its fixpoint budget on a function only in the run's profile (`time.fixpoint_timeouts`), never in `errors`; v3.7.0 never read that profile, so those matches vanished with no error. Semgrep 1.182.1 writes the profile with or without `--time`; `--time` is passed so that a release which writes it only on request does too, and detection does not depend on it: a document without a `fixpoint_timeouts` list is recorded as a gap (below). Any of these is lost rule evaluation: the findings of the run are kept, and the `semgrep` entry in `scanner_status` is `failed` (see "What `ok` means" below), because the rule's matches in that file are missing.
   - `--max-target-bytes 1048576` is the size cap every Go analyzer shares, passed explicitly so that a Semgrep whose default differs skips exactly the files the engine lists as too large.
   - `--disable-nosem` stops Semgrep dropping a result whose line carries a `nosemgrep` comment; the engine applies the comment itself and reports what it suppressed (see "`nosemgrep`").
   - `--x-ignore-semgrepignore-files` stops Semgrep reading the scanned tree's `.semgrepignore` files and, when the tree has none at its root, its own built-in default ignore list (which drops `tests/` and `test/` at any depth, `*.min.js` and more): what is scanned is the engine's decision, the same for every project, never the repository's. A Python `tests/` directory is therefore scanned.
   - `--exclude /.git` is passed only when `<code_path>/.git` has a real layout (see "Scope"). The only other excludes are an anchored `--exclude` for each entry the engine itself could not open (a file with no read permission, a directory it cannot list; at most 512 per run): Semgrep's own listing of the root would otherwise exit 2 with `Failed to obtain target files from semgrep-core` and every readable file would lose its Semgrep evaluation (recorded by the round-5 engine owner before the change: a mode-000 `hidden.py`, `hidden.js` and directory made the whole run `failed` / `execution_error`; after it Semgrep evaluated `app.py` and the detail read `lost evaluation: 3 in-scope files not read: 3 unreadable (hidden.js, hidden.py, secret/)`). Such an entry is still lost evaluation, named in the detail; the exclude only keeps it from taking the rest of the run down. When a large language group isolates its heaviest files ("Isolating heavy files", below), the bulk run carries an anchored `--exclude` for exactly those files and each of them runs under one anchored `--include=/<rel>`. No name, marker, banner or appearance removes a file from the evaluation: an isolated file is evaluated in an invocation of its own.
   - `--include=<changed file>` is added for each changed file of a `--diff` scan, as one argument, so a file called `-x.py` is a value and never an option.
   - `--` ends the options. Every target after it is an absolute path (a relative `--code` is made absolute first), so no file or directory name, and not the scan root's, can be read by Semgrep as an option (a file called `--config=x.mts` reaches it as a path). Semgrep rejects both `-x.py` and `--include -x.py` as unknown options, which is why the engine writes `--include=<rel>` and `--`.
   - `--scan-unknown-extensions` is added only to the extensions pass and to the retry of a file it ran (see "The extensions pass").
   - `--project-root <code_path>` makes the scan target the project root, so a target inside a git work tree (`<gitroot>/fixtures/repo`) is not filtered by the git root's `fixtures/` exclusion.
   - `--jobs` and `--max-memory` are the budget's (below).
   A host Semgrep older than the release that added an option is run without it, and a warning is logged. Fendix reads `semgrep --version` once per binary, with `SEMGREP_ENABLE_VERSION_CHECK=0` and `SEMGREP_SEND_METRICS=off` so the probe never touches the network, bounded to 10 s, and before the run's deadline starts. A probe that failed (no answer within 10 s, a binary that did not run) is remembered for the life of the process, so the next scan does not wait again; a probe cut short because the scan was cancelled is not remembered. An unreadable version is taken to be a current one: every option is passed, and if the run then fails, its error ends `(semgrep --version could not be read: <why>, so every option was passed)`. Fendix drops `--project-root` before 1.111.0, `--x-ignore-semgrepignore-files` before 1.96.0, `--dataflow-traces` before 0.107.0, `--timeout` before 0.17.0, `--jobs` and `--max-memory` before 1.0.0 and `--exclude` before 0.12.0, and records the run by what the missing option costs:
   - **`--project-root` (lossy).** Without it Semgrep matches the packs' `paths.exclude` against the enclosing git root, so every file of a target under `<gitroot>/fixtures/` can be excluded without an error. The run is `failed` / `execution_error`, with a detail such as `semgrep 1.100.0: dropped --project-root (needs 1.111.0); files may be skipped: the packs' path filters need --project-root` (every dropped option is listed before the `;`).
   - **`--x-ignore-semgrepignore-files` (lossy).** Without it the tree's `.semgrepignore` files, or Semgrep's default ignore list, decide what is skipped. The run is `failed` / `execution_error`, with a detail such as `semgrep 1.45.0: dropped --project-root (needs 1.111.0), --x-ignore-semgrepignore-files (needs 1.96.0); files may be skipped: the packs' path filters need --project-root; Semgrep's default ignore list and the tree's .semgrepignore files apply`.
   - **`--dataflow-traces`, `--timeout`, `--jobs`, `--max-memory`, `--exclude` (not lossy).** A trace only explains a finding; without `--timeout`, Semgrep's own per-rule bound applies and every timeout is still reported and recorded as lost evaluation; without `--jobs` and `--max-memory` Semgrep runs with its own defaults (the behaviour before the budget); without the excludes more is scanned, never less. The run stays `ok`, with a detail such as `semgrep 0.100.0: dropped --dataflow-traces (needs 0.107.0)`.

   Fendix checks a host Semgrep as far back as 1.45.0, and ships 1.182.1. A host Semgrep older than 1.111.0 is therefore always recorded `failed`; upgrading Semgrep is the fix. (The 1.96.0 floor for `--x-ignore-semgrepignore-files` was read from `semgrep/commands/scan.py` in the published wheels: absent in 1.95.0 and earlier, present in 1.96.0, 1.97.0, 1.99.0, 1.100.0, 1.110.0, 1.118.0..1.120.0, 1.125.0, 1.141.0 and 1.182.1.)
4. Classifies the run (below), applies `nosemgrep` comments, then maps the JSON results to Fendix Finding format (`SEC-<RULE_ID>`)
5. Severity resolution prefers `metadata.fendix_severity`; falls back to Semgrep's own `ERROR`→`HIGH` / `WARNING`→`MEDIUM` / `INFO`→`LOW`; ultimate default `MEDIUM`
6. If `semgrep` is not on `$PATH`, returns `ErrSemgrepUnavailable` — the orchestrator logs an install hint at INFO, records `scanner_status: {"name":"semgrep","state":"skipped","reason":"dependency_missing"}`, and continues

## Runtime and memory budget

Semgrep's defaults are sized from the host, not the container. Inside a two-CPU container on a ten-core VM, `--jobs` defaulted to nine threads; there was no `--max-memory`, so the only memory bound was the kernel's out-of-memory killer, which ends Semgrep whole (no JSON document, so every finding of the run is lost); and there was one deadline for the whole tree. The stage is now bounded (`go/internal/scanner/semgrep/budget.go`, `plan.go`):

- **CPUs and jobs.** The CPU allowance is the tightest cgroup CPU quota along the process's cgroup path (v2 `cpu.max`, or v1 `cpu.cfs_quota_us`), intersected with the process's CPU affinity. `--jobs` is `floor(0.85 x CPUs + 0.5)`, at least 1: Semgrep's own recommendation applied to the allowance (2 CPUs give 2 jobs, 4 give 3).
- **Memory.** The memory budget is the cgroup memory limit (capped by the host's `MemTotal`). With no cgroup limit it is half the host's memory divided among the scans that share the host: `FENDIX_SCAN_CONCURRENCY` says how many, and when it is unset the engine assumes 2 (a 3.8 GB host gives 3.8 GiB x 50% / 2 = about 950 MiB per scan). **Production runs the scan worker at concurrency 2 with no container memory limit on a 2-CPU, 3.8 GB host with no swap** (observed read-only on 2026-11-12, backend `DEPLOY_RUNBOOK.md` 8.5); the budget therefore assumes no container cap, at most 2 CPUs per scan (a 10-core VM gets the same plan as the 2-CPU host) and two scans at once. The backend does not pass `FENDIX_SCAN_CONCURRENCY` to engine children, so a hosted worker runs on the default of 2 whatever its `--concurrency` is; at a worker concurrency of 1 that is the cautious direction (more per-file out-of-memory gaps, never an out-of-memory kill), and passing the worker's own concurrency is an open item for the backend. `--max-memory` is split per `semgrep-core` job: `(budget - 384 MiB) x 90%`, never below 256 MiB, and a job is given at least 512 MiB, so when the budget cannot give every job that much the run uses fewer jobs (the round-5 budget owner measured `--jobs 2 --max-memory 720` for a 950 MiB share on a 7.9 GB host, and `--jobs 1 --max-memory 509` under a 950 MiB cgroup). 384 MiB is held back for Semgrep's Python wrapper, the engine and the page cache, and Semgrep's documentation says the limit "will be exceeded before it gets detected", so a tenth is margin. With the limit exceeded Semgrep reports a per-file `Out of memory` naming the file (the engine does not die, and findings of other files are kept), which is recorded `failed` / `execution_error`. With no memory information, none is passed.
- **Wall budget.** 300 s for the whole stage, every invocation and retry together, shrunk to leave 90 s of the run's own remaining time for the analyzers that run after Semgrep when the run has a deadline, never below 20 s. A hosted scan's own deadline is minutes above it, so the engine has time left to write its report.
- **The log line.** Each stage logs its budget at INFO, for example `semgrep: stage budget budget="jobs=2 max-memory=1004MiB wall=5m0s (cgroup v2, cpu quota 2.00, memory limit 1500 MiB)"`.
- **Settings.** `FENDIX_SEMGREP_JOBS` (1 to 256), `FENDIX_SEMGREP_MAX_MEMORY_MIB` (0 for none, otherwise at least 256), `FENDIX_SEMGREP_BUDGET_SECONDS` (30 to 3600) and `FENDIX_SEMGREP_SPLIT_BYTES` (-1 never splits), `FENDIX_SCAN_CONCURRENCY` (1 to 64: how many scans share the memory budget), `FENDIX_SEMGREP_CHUNK_BYTES` (the group size from which heavy files are isolated, default 3 MiB, -1 never) and `FENDIX_SEMGREP_HEAVY_FILE_BYTES` (a positive size, default 192 KiB) override the derived values; a value that is not an integer in range is ignored with a warning and never turns into an unbounded run. `models.ScanConfig` carries `SemgrepJobs`, `SemgrepMaxMemoryMiB` (negative: pass none) and `SemgrepWallBudget`; there is no command-line flag. A service that builds each engine child's environment by default-deny (the hosted backend does) never passes the variables on, so a hosted worker is sized by its container's limits.

### One invocation, or one per language group

A tree in a single language group, or a small one, is one invocation with every pack, as it always was. A tree with in-scope files in at least two language groups (`python`, `javascript` with `typescript`, `java`, `go`) and at least 4 MiB of in-scope source is split into one invocation per group, cheapest first, each loading only its own packs. The deadlines are static offsets from the start of the stage, computed from file sizes and the budget only, so a slow group borrows what an earlier one left and cannot starve the groups after it. A group that reaches its deadline is killed and loses only its own findings (Semgrep prints its JSON once, at the end); the finished groups' findings are kept. The stage ends `failed` / `timeout` with one segment that is never cut: `semgrep: timed out after 1m0s; not evaluated: java 3 files`. The unevaluated files are not in `paths.scanned`, so they are also named as not evaluated. Killing an invocation takes down its whole process tree and leaves Semgrep in the engine's own process group, so a caller that ends a timed-out engine by process group still ends Semgrep. The tree is frozen first (the parent and every descendant found are stopped with SIGSTOP, repeated until no new one appears), then the descendants are killed, then the parent: killing descendants first let a wrapper that waits for its worker print a document and exit 0 inside the gap. An invocation whose deadline fired is `timedOut` whatever its exit status was: the engine no longer accepts a document from a run that finished after its deadline, so the unit is listed as not evaluated and the stage is `failed` / `timeout`. Before this, a timed-out Semgrep left `semgrep-core` running, using CPU and memory for the next analyzer and the next scan.

### Isolating heavy files (round 5)

What exhausts the stage budget on a repository that commits minified or installed code is a few big files, not many small ones. Measured by the round-5 budget owner (real Semgrep 1.182.1, one run, not re-run for these notes): on the `gogs` repository one 461 KB single-function bundle (`openjpeg_nowasm_fallback.js`) alone took more than 160 s, five of the 17 JavaScript taint rules taking more than 100 s each on it, while the other 223 JavaScript files of the group finished in 13 s. Semgrep also resolves every explicit file target with its own `semgrep-core` process (about 0.14 s per file: the 819-file tree of the backend repository took 6.9 s as a directory and 121 s as explicit targets), so chunking a tree into file lists is slower, not faster.

So a group (or an unsplit tree) of at most 3 MiB (`FENDIX_SEMGREP_CHUNK_BYTES`) is one root run, as before. A larger one gives up its heaviest files only: the isolable files of at least 192 KiB (`FENDIX_SEMGREP_HEAVY_FILE_BYTES`), the 8 largest of the stage. Each runs alone under one anchored `--include=/<rel>`; the rest of the group runs once with those files `--exclude`d by anchored pattern. Units run bulk first, then heavy files smallest first, each with its own share of the stage budget. The choice is by size alone; a name that cannot be written safely as a pattern (glob characters, braces, a leading `!` or `#`, blanks at either end, non-ASCII) is never isolated and stays in the root run. A unit that hits its deadline loses only its own files, which fall out of `paths.scanned` and are named as lost evaluation; the findings of the units that finished are kept, and a result printed by two units is reported once. Nothing is excluded from analysis, and no scope, status, reason or schema changes: the stage still ends `failed` / `timeout` with `semgrep: timed out after 5m0s; not evaluated: javascript 1 file`. Whether to optimise the rules instead (the five slow taint rules carry two TypeScript-only source clauses that also run on every `.js` file; the real fix is to run them only on TypeScript files, a change to rule packaging that is public contract) is an open owner decision; no rule was changed.

### The extensions pass

Source files of a pack language that Semgrep does not select by their
extension (`APP.JS` and `Server.Py` in another case, `.cts`, `.mts`, `.es6`,
`.vue`) are in scope: a file name is not evidence (decision D6'). After the
first pass they are handed to Semgrep by absolute path in a further pass, one
invocation per language group with only that group's packs (an explicit file of
an unselected extension is parsed as every language of every rule it runs with,
and a Python rule would report a JavaScript file as a syntax error), with
`--scan-unknown-extensions` and the same `--timeout`, `--jobs` and
`--max-memory`, inside what is left of the stage budget. A retry of such a file
passes the same option. A file this pass does not report is lost evaluation
(`not evaluated by semgrep`), and a pass that does not finish names `extensions
<group> <n> files` among what was not evaluated. Semgrep cannot parse a Vue
single-file component as JavaScript, so a `.vue` file always ends as lost
evaluation: a repository with Vue components reads `semgrep` `failed`
(`execution_error`), which is true, since their script was not analysed.

### Retrying a file that lost evaluation to time

The files that lost evaluation to time in the first pass (a rule timeout, the three-timeout threshold, a taint fixpoint timeout in the profile or in `errors`, an interfile timeout) are re-run one at a time, alone: `--jobs 1`, no `--include` and no declared `--exclude`, the same `--max-memory`, in deterministic order (size ascending, then path), at most 12 files, each with a per-rule timeout of twice the first pass plus one second per 32 KiB of the file (at most 8 times the first pass), an attempt bounded by three times that timeout plus 20 s and by what is left of the stage budget (none starts with less than 15 s left). The retry decides one thing. A file is resolved only when the re-run exited clean with no fatal error, reports the file in `paths.scanned`, has a `fixpoint_timeouts` list, and has no time-class entry and no other lost-evaluation entry for the file (a partial parse is the only tolerated note). Then the first pass's time-class entries for the file are removed. A re-run that lost the file to memory or to a parse failure resolves nothing. Findings are unioned (de-duplicated by rule, path, line, column and text) whether or not the file resolved: a re-run's findings are evidence and are never dropped. A retry therefore never worsens a verdict and never turns a loss into a clean file without a complete, reported re-evaluation of that file. Every retry stays on the record in `metadata.coverage.limitations`, a resolved one included: `semgrep: retried alone after losing evaluation to time in the first pass: a.js (resolved, evaluated in full when run alone), b.js (still lost: timed out again)`; a file past the cap or the budget reads `still lost: not retried: over the cap of 12 files`.

What it fixes is a verdict that followed host speed: a rule-file pair that costs about its time bound read `ok` on one run and `failed` / `timeout` on the next, with the same binary and the same bytes. What it cannot fix: a pair that costs more than the retry bound (about 60 to 90 s alone on two CPUs) still ends `failed` / `timeout`, and a pair near the retry bound can still differ between runs, because Semgrep's time bounds are wall-clock and its taint fixpoint budget is internal and not configurable. The completion rate and wall times measured for this change were taken on a work tree, are in the notes of that round and not in this repository, and are pending re-measurement at the release commit; none is quoted here.

## What `ok` means

`semgrep` is recorded `ok` only when Semgrep itself would call the run
successful, no selected rule lost its evaluation on any scanned file, and no
in-scope file was left unread. The
rule follows Semgrep 1.182.1's own contract (its `error.py`, `output.py` and
`core_output.py`; `is_scan_failure` lists the error types that mean "the file
was detected but could not be fully scanned") and recorded runs of the real
binary, kept as fixtures in `go/internal/scanner/semgrep/testdata/runs`.
v3.7.0 recorded a rule timeout and a per-file out of memory `ok`, counted
in the detail; earlier unreleased work also recorded a dropped
`--project-root` `ok`, a file Semgrep could not parse `ok`, and a file over
the size cap `ok`; and no released engine requested `--time`, so none
saw a taint fixpoint timeout at all.

| Run | Recorded |
|---|---|
| Exit 0, JSON envelope, no error of level `error`, no lost evaluation, every in-scope file reported scanned | `ok` |
| A partial parse (`PartialParsing`) whose skipped line spans are all reported, lie inside the file, and **every line they touch is blank or a whole-line comment** (`#` for Python; `//`, or a one-line `/* ... */`, for JavaScript, TypeScript, Java and Go), judged by the engine from the file itself on the **language's own lines** (Round 6, DE5-07: Semgrep numbers lines by `\n` alone, but a bare `\r` ends a Python, JavaScript or Java line, U+2028 and U+2029 also end a JavaScript one, and a Go line ends at `\n` only), and only a line that starts in plain code can be a comment line: a line that starts inside a template literal, an f-string field or string, JSX text, a Java text block or a block comment is code, whatever it begins with. The scanner that tells is conservative: where the language is ambiguous (a `/` that may begin a regular expression, a `<` that may begin JSX, an unterminated string, an f-string field it cannot close, a Vue template, a language it has no lexer for) it stops trusting itself and every later line reads as code, which costs a file its `ok`, never a skipped line of code its "inert" (decisions D1' and C4B-27: the engine must be able to show that the skipped spans hold no analysable code) | `ok`, with the count by type in `detail` (never the message, which can quote source): `<n> non-fatal per-file problem(s) reported by semgrep (PartialParsing <n>); findings in those files may be incomplete`, then the lines: `partial parse, <n> files with skipped lines: a.py 4, b.js 10-12` (`1 file` for one) |
| A file Semgrep could not parse at all (`Syntax error`, `Lexical error`, `Other syntax error`, `AST builder error`, and the constructor spellings `ParseError`, `LexicalError`, `OtherParseError`, `AstBuilderError`), or a partial parse that skipped **any line of code, however few lines or small the share**, with no usable span, or with a span outside the file (the round-4 allowance of `min(max(3, 5%), lines - 1)` skipped lines is gone: a skipped long line can hold the handler), or a Python file (`.py`, `.pyw`, `.pyi`) whose bytes are not the program Semgrep reads (Round 6, R5-01, R6-E1, R6-E6: one predicate, `scope.ClassifyPythonSource`, shared by Semgrep's target selection, the secrets scan, `fendix verify` and the Python engine, and pinned by the same generated vectors in Go and Python). It reads a PEP 263 cookie the way CPython does: on line 1, or on line 2 when line 1 is blank or a comment, lines ending at `\r\n`, `\r` or `\n` with no byte limit, and, for `python -x`, which skips line 1 up to its `\n`, a cookie on line 2 whatever line 1 holds. The name goes through CPython's own normalisation and codec registry, read from a table measured on CPython 3.14.5 (all 454 names; no alias list is written by hand). A file with no cookie, or one whose cookie is a takeover-immune spelling of `utf-8`, `latin-1`/`iso-8859-1` or `ascii` (D2-A, below; matched in any letter case), is read as UTF-8 and stays `ok`. **A codec CPython knows that is not such a spelling** (`utf-7`, `utf-16`, `cp037`, `iso2022_jp`, and the aliases and legacy code pages D2-A reads as foreign: `utf`, `u8`, `cp65001`, `latin`, `cp1252`, `euc-jp`, ...), **a name no codec answers to in a fresh interpreter** (only a run-time registration could supply one: there is no UTF-8 fallback), a cookie only `python -x` reads, and a prefix too short to decide are lost evaluation. A file CPython itself refuses (a byte order mark with a cookie other than utf-8) is not a gap on its own and never costs another file its analysis. *The codec policy is the owner's D2-A, ruled and implemented in the Release Closure Sprint: only the takeover-immune spellings of `utf-8` (`utf-8`, `utf_8`, `utf8`, `utf-8-*`), `latin-1` (`latin-1`, `latin1`, `latin_1`, `iso-8859-1`, `iso8859-1`, `iso8859_1`, `iso_8859_1`, `iso_8859_1_1987`, `iso-latin-1`, `latin-1-*`) and `ascii` (`ascii`, `us-ascii`, `us_ascii`) read as UTF-8, because any module of a scanned repository can redefine any other codec name at run time and run a program every analyzer reads only as a comment. It is one compiled-in constant (`codecPolicy` in `go/internal/scope/pysource.go`, `PEP263_POLICY` in `python/analyzers/scope_evidence.py`, both D2-A); decision D2 as first approved (every ASCII-transparent codec counts as UTF-8) is superseded. The immune set is the same on CPython 3.8 to 3.14. Customer remedy: save the file as UTF-8 and declare `utf-8`, or drop the declaration.* For a foreign codec CPython decodes the file with that codec while Semgrep reads the bytes as UTF-8 and sees text that is not the program, and in the other lost cases the program cannot be determined, so in every one the engine cannot show the code was evaluated (round 5, redteam5-10: before the change the verifier recorded `semgrep` `ok` for a `# coding: utf-7` file holding `subprocess.call(input(), shell=True)`). **Two more content cases are named the same way (Release Closure Sprint):** a JavaScript or TypeScript file (`.js`, `.jsx`, `.mjs`, `.cjs`, `.es6`, `.ts`, `.tsx`, `.mts`, `.cts`) in which an identifier is written as a unicode escape, which the runtime reads as the name it spells and the rules read as written (R6-E7a; an escape in a string, template text, a regular expression, a comment or JSX text does not count, and a regular expression is told apart from a division by the token before it, both readings being tried where that cannot decide), and a Java file with a unicode escape that translates to a line break, a quote, a backslash, a slash or an asterisk, which Java translates before it parses the file (R6-E7b; proved against a real JDK). Both stay targets, so what Semgrep finds in them is kept; the customer remedy is to write the identifier, or the character, in plain form. A file that this check and Semgrep's own parse report both name is listed once | `failed` / `execution_error`, `<k> not parsed by semgrep (<path>, ...)` in the `lost evaluation:` segment; findings kept |
| Lost evaluation where every loss is a timeout: a rule `Timeout` (a rule Semgrep stopped on a file after `--timeout 30`), the rest of a file's rules skipped after 3 rule timeouts (`--timeout-threshold`), a taint `Fixpoint timeout`, a `Timeout during interfile analysis` | `failed` / `timeout`, `detail` starting `lost evaluation:` (format below); findings kept |
| Any other lost evaluation: a per-file `Out of memory`, `Stack overflow`, `OOM during interfile analysis`, `Internal matching error`, `Too many matches`, `Missing plugin`, `Fatal error`, `SemgrepWarning`, or any per-file type not listed as a parse problem above, in either Semgrep's spelling or the constructor name (`OutOfMemory`, `MatchingError`, ...), since a type Fendix does not know cannot be shown to have cost nothing; an `errors` entry that could not be decoded at all, or an `errors` that is not a list; a loss-type entry whose fields could not be read (it is decoded leniently, and any count beyond what was decoded is reported); rules Semgrep lists in `skipped_rules`; a profile whose `fixpoint_timeouts` is missing, `null` or not a list; a dropped `--project-root` or `--x-ignore-semgrepignore-files`; an in-scope file over 1048576 bytes, unreadable, not parsed, or absent from Semgrep's `paths.scanned` (decision D6, below); or a timeout mixed with any of these | `failed` / `execution_error`, `detail` as above; findings kept |
| Files declared out of scope (decisions D6 and D5-2): a symbolic link, and a recognised lockfile (the policy; no analyzer applies it in this tree, see "Scope"). A source file is never declared out of scope for what it looks like, its name, extension or path: a minified, vendored, generated, compiled, test or fixture file, one in `node_modules` or a virtualenv, `APP.JS` and `.mts` are evaluated, and a `.vue` file is lost evaluation (below) | `ok`, with the paths named in `detail` (below); never a gap |
| A `nosemgrep` comment removed one or more results | `ok`, with `nosemgrep suppressed <n> result(s) (<rule> <path>:<line>, ...)` in `detail`; never silent |
| The stage past its wall budget | `failed` / `timeout`; `semgrep: timed out after <budget>; not evaluated: <group> <n> files`; the findings of the groups that finished are kept (a single invocation keeps none) |
| A non-zero exit other than 1, or death by a signal: an invalid or missing config (exit 7), a rule that does not parse (exit 2), the engine killed or crashed mid-run, out of memory included (exit 2, "the engine was killed") | `failed` / `execution_error`, `detail` naming the first error |
| Exit 0 with any entry of level `error`: Semgrep sets its exit code from its last error only, so a rule parse error followed by per-file warnings exits 0 | `failed` / `execution_error` |
| Exit 0 with no JSON results envelope | `failed` / `malformed_output` |

The detail of a run (`recordSemgrepRun` in
`go/internal/engine/scannerstatus.go`) is segments joined with a semicolon and
a space (decision C1/C2), in this order, each present only when it applies,
composed within 240 bytes so that no segment is ever cut: the loss segments
first, then the notes, then the declared exclusions. When the budget runs out
the entries named per segment are shortened first (counts are kept); then whole
trailing segments are dropped and the detail ends `and <N> more (see report
metadata)`, `N` being the number of segments dropped (not of files), so a note
or an exclusion is dropped before a loss. The complete
lists are always in `metadata.coverage.limitations`.

Loss segments:

1. `lost evaluation:`, a space, and the counts that are not zero, joined with
   a comma and a space:
   - `<N> rule timeouts on <F> files`
   - `every other rule skipped on <F> files after 3 rule timeouts`
   - `<N> taint fixpoint timeouts on <F> files`
   - `<N> per-file errors (<Type> <n>, ...)`
   - `<N> rules skipped by semgrep`

   Each noun is singular for 1: `1 rule timeout on 1 file`. Then, as its own
   part, `first: <path> (<item>, <item>); <path> (<item>)`, at most three
   items: a rule id, `taint fixpoint at line <L>, <K> taint rules from <rule>`,
   `<Type>` or `<Type> running <rule>`, or `skipped rules (<id>, ...)`.
2. When Semgrep counted lost-evaluation entries the decoders could not read:
   `<N> lost-evaluation entries semgrep reported could not be read
   (<Type> <n>, ...)` (`entry` for 1; the type of an entry that could not be
   decoded at all is `undecodable`, of one whose type could not be read
   `unknown`).
3. For in-scope files left unread (decisions D6, D1' and D5-2): `lost evaluation: <N>
   in-scope files not read: <k> over 1048576 bytes (<path>, <path>, <path> +<m>
   more), <k> unreadable (<path>), <k> not evaluated by semgrep (<path>), <k>
   not parsed by semgrep (<path>)`, each kind present only when it applies,
   at most three paths each. A source file over the cap is **always** under `over
   1048576 bytes`, whatever it looks like (a minified or generated file over the
   cap is no longer "declared out of scope"). The `lost evaluation:` lead is what
   the hosted backend reads to keep such a loss from being refunded as a scanner
   crash (a repository-caused gap, `scanning/services.py` `_LOST_FILES_RE`), so
   do not reword it. The complete lists in `metadata.coverage.limitations` read
   `semgrep: lost evaluation, over 1048576 bytes: <names>`, `semgrep: lost
   evaluation, not parsed by semgrep: <names>`, `semgrep: lost evaluation, not
   evaluated by semgrep: <names>` and `semgrep: lost evaluation, unreadable:
   <names>`.
4. `semgrep reported no taint fixpoint timeouts list (--time), so a taint rule that ran out of time would be silent`
5. The lossy dropped-options note, followed by `; files may be skipped: ` and what each lossy option costs, joined with `; `: `the packs' path filters need --project-root`, `Semgrep's default ignore list and the tree's .semgrepignore files apply`.

Notes:

6. The non-fatal per-file problem count of the `ok` row above.
7. `partial parse, <n> files with skipped lines: <path> <lines>, ...` (`1 file` for one; measured: `partial parse, 1 file with skipped lines: src/partial.js 41`)
8. The dropped-options note when nothing lossy was dropped.
9. `nosemgrep suppressed <n> results (<rule> <path>:<line>, ...)`.

Exclusions:

10. `declared out of scope, not scanned: <reason> <n> (<name>, <name>, <name> +<m> more), <reason> <n> (...)`, one entry per reason in the order each was first used. The only reasons written are `symbolic link` (a directory link is named with a trailing `/`) and `lockfile` (never written in this tree, see "Scope").

A run that has rule errors keeps a detail of its own, `<n> rule errors, rules
not loaded: ...`, and appends `; <n> rule timeout(s) as well` and `; <n> taint
fixpoint timeout(s) as well`; it is `failed` / `execution_error` and is cut at
240 bytes if it is longer.

Two details from real offline scans with Semgrep 1.182.1, an Express router
of 1,000 inline handlers and a Gin `main()` of 400 inline closures, each with
an SSRF after the padding that Semgrep did not report:
`lost evaluation: 1 taint fixpoint timeout on 1 file; first: routes/api.js (taint fixpoint at line 1, 2 taint rules from js-sqli-taint)`
and
`lost evaluation: 1 taint fixpoint timeout on 1 file; first: main.go (taint fixpoint at line 13, 2 taint rules from go-ssrf-taint)`,
both `failed` / `timeout`, with `semgrep` among the coverage gaps.

Two details from scans of small trees on this tree with Semgrep 1.182.1
(round 5, `review/engine-dev:pr145`, one run each):
`lost evaluation: 3 in-scope files not read: 1 over 1048576 bytes (big.js), 1 not evaluated by semgrep (src/Comp.vue), 1 not parsed by semgrep (src/whole.js); and 3 more (see report metadata)`
(`failed` / `execution_error`: a file of 1,100,007 bytes, a Vue component, and a
two-line file a partial parse skipped whole; the three segments that did not fit
the budget are counted in `and 3 more` and listed in
`metadata.coverage.limitations`) and
`lost evaluation: 1 in-scope file not read: 1 not parsed by semgrep (src/partial.js); 1 non-fatal per-file problem(s) reported by semgrep (PartialParsing 1); findings in those files may be incomplete; nosemgrep suppressed 1 result`
(`failed` / `execution_error`: a JavaScript file of 80 lines with one line,
`const bad = @@@;`, that Semgrep skipped. That is one skipped line of code out of
80, which round 4 allowed to stay `ok`; it is lost evaluation now, because the
engine cannot show the skipped line holds no analysable code). The same detail
with a symbolic link reads
`declared out of scope, not scanned: symbolic link 1 (src/linkdir/)`.

A taint fixpoint timeout depends on load, so the same file can lose its taint
matches on one run and not on the next; the run that lost them says so, and the
retry pass (above) re-runs the file alone before it is recorded lost.

### Scope (decisions D6 and D5-2)

Semgrep's JSON names the files it evaluated (`paths.scanned`) and nothing
about the ones it did not. Fendix therefore lists the files the run was meant
to evaluate itself (`go/internal/scanner/semgrep/targets.go`): every regular
file under `<code_path>`, or every changed file of a `--diff` scan, with an
extension of the packs' languages in any letter case (`.py`, `.pyi`, `.js`,
`.jsx`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.java`, `.go`, which Semgrep 1.182.1
selects when written in lower case, and `.cts`, `.mts`, `.es6`, `.vue`, which
it does not select: those are run in the extensions pass), except the root
`.git` directory (below) and what is reached through a link. It then compares
that list with `paths.scanned`:

- **Every supported file at or below 1048576 bytes is evaluated, whatever it
  looks like.** Minified, vendored, generated, compiled, source-map, test and
  fixture code are in scope, and so is code under `node_modules`, a virtualenv,
  `site-packages`, `vendor`, `target`, `build`, `dist` or `.next`. Nothing is
  excluded for a banner or header (`/*! jQuery v3.6.0 */`, `@generated`, `Code
  generated ... DO NOT EDIT.`), for a file or directory name (`*.min.js`,
  `node_modules`), for a marker file (`pyvenv.cfg`, `conda-meta`,
  `.yarn-integrity`, `.package-lock.json`, `modules.txt`, a `*.dist-info` with a
  `RECORD`), for a large literal, for line statistics, or for how the code looks.
  A file's head, banner or name can be written by anyone who can commit to the
  repository, and a first-party handler can sit beside or inside any of them, so
  none is evidence about the rest of the file. This supersedes the round-4 rule
  (decision D6'), which classified such files by evidence and left them unread.
- An over-cap or unreadable in-scope file is lost evaluation for Semgrep: a file
  over 1048576 bytes, one that cannot be opened, a directory that cannot be
  listed, a file Semgrep could not parse (decision D1' and C4B-27), and a file
  absent from `paths.scanned`. Semgrep is recorded `failed` / `execution_error`
  with the files named (the findings of the rest of the run are kept). A document
  with no `paths.scanned` list loses every file it was meant to evaluate. Nothing
  is dropped silently.

**What is declared out of scope.** Two things only, listed by name with their
reason in the `ok` detail and, complete, in `metadata.coverage.limitations`:

| Reason | Rule |
|---|---|
| `symbolic link` | a link to a directory, or to a source file of a pack language, which Semgrep never follows. A directory link is listed with a trailing `/`: `declared out of scope, not scanned: symbolic link 1 (linked/x.py)` |
| `lockfile` | a recognised lockfile: its exact base name is on a closed list **and** its whole content parses as that format (below). |

The `lockfile` list is closed: `package-lock.json`, `npm-shrinkwrap.json`,
`yarn.lock` (classic and Berry), `pnpm-lock.yaml`, `poetry.lock`,
`Pipfile.lock`, `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`. The
recognizer (`go/internal/scope/lockfile.go`, `scope.ClassifyFile`) reads to the end
of the file, up to 32 MiB, and accepts only the format's own keys, sections and line
shapes with values limited to the characters package names, versions, URLs and
hashes are written in; a file with a listed name that starts like a lockfile and
holds source code or an unknown key after it is not a lockfile and is in scope.
Ten other names round 4 accepted (`bun.lockb`, `deno.lock`, `pdm.lock`,
`uv.lock`, `mix.lock`, `pubspec.lock`, `Podfile.lock`, `packages.lock.json`,
`gradle.lockfile`, `flake.lock`) are no longer recognised and are scanned,
because none has a strict whole-content grammar here. Limits: a package name, a
version or a URL is free text within its character set, so a secret written as a
package name inside an otherwise well-formed lockfile would still be skipped if an
analyzer applied the exclusion. **In this tree no analyzer calls the recognizer**
(a lockfile has no pack-language extension, so the Semgrep planner never targets
one, and the secrets scanner and textscan read it like any other file): the
`lockfile` reason is a documented policy and a tested function, and it is never
written today. Whether the secrets scanner and textscan apply it is an open owner
decision.

**The `.git` directory.** `<code_path>/.git` is not source and is skipped, but only
when its layout is real: a regular `HEAD` file plus `objects/` and `refs/`
directories, all probed with `Lstat` only (nothing is opened, no link is followed).
The skip is quiet (it is not listed in any detail) and Semgrep is told with one
anchored `--exclude /.git`. A `.git` or an `objects` directory anywhere else, a
`.git` whose layout is forged or incomplete (a `HEAD` alone, a link for `objects`),
and a `.git` that is a file or a link are ordinary content and are scanned. An
uploaded archive can still carry a real-layout `.git` at its root, whose contents
are then not analysed (accepted, decision D5-2).

**Probing never blocks and never leaves the root.** The readability probe of every
target, the read of a partially parsed file and of a finding's evidence line use
`scope.OpenRegular`: `O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` and an `fstat` that must say
regular file (on other platforms `Lstat` plus `SameFile`). A named pipe or special
file is unreadable, so it is lost evaluation and the scan completes; a link is not
followed out of the scan root.

**What no longer appears.** The reasons `minified`, `vendored library`,
`generator header`, `compiled output`, `source map`, `test/fixture path`,
`extension not selected`, `installed npm packages`, `python virtualenv`,
`installed python packages`, `go vendor tree`, `composer vendor tree`, `cargo
build output`, `maven build output`, `gradle build output`, `next.js build
output`, `npm cache`, `setuptools build output`, `generated artifact` and
`vendored/build dir` are never written. A consumer must still tolerate them inside
a declared segment, which it never reads for loss, because a report from an older
engine can carry them.

**No installed dependency tree is excluded (owner amendment A1).** The owner
allowed excluding installed third-party code only on independently verified
provenance, and a first attempt (a Go module directory excluded when its files
hashed to the `go.sum` `h1:` line, listed as `verified go module (lockfile hash)`)
was removed before any release: `go.sum`, `package-lock.json`, a dist-info
`RECORD` and `vendor/modules.txt` are all written by the repository being scanned,
so a self-consistent forged pin (a `third_party/example.com/lib@v1.0.0/` directory
holding a credential and a SQL injection, plus its own `h1:` hash in `go.sum`)
hid first-party code and the scan read complete (measured by the round-5 engine
owner on the deps5 tree: 0 findings, exit 0; after the removal 4 findings, exit
1). An offline scan has no authority outside the repository to check a pin
against, so nothing is excluded: a Go module cache, `node_modules` and a
virtualenv are analysed in full. The text `verified go module (lockfile hash)`
never appears in a report. An online scheme (a checksum-database lookup, or
re-fetching the tarball or wheel by its lockfile integrity hash and comparing file
by file) would need network access on the hosted worker and a new coverage reason,
and is an open owner decision.

**Cost, measured.** With no exclusion Semgrep evaluates every minified bundle and
installed dependency tree in scope. The round-5 budget owner measured it with real
Semgrep 1.182.1 on a VM shared with other jobs, one run each, at `--cpus=2`
(these figures are theirs, in `review-reports/fendix-remediation/work/budget5.md`
with the raw outputs; they were not re-run for these notes, and a 2x difference is
real while a few seconds are noise). Round-4b checkpoint (exclusions) versus this
tree: WebGoat 21 to 33 s became 63 to 70 s and its Semgrep status `ok` became
`failed` / `execution_error` (a skipped line of code in a minified bundle, below);
`gogs` 50 to 55 s became 305 s, `failed` / `timeout`, with 1 JavaScript file
(the pathological bundle) named lost after heavy-file isolation, where before the
isolation 230 files, a first-party `gogs.js` among them, were lost with it; the
backend repository 22 s became 36 s, `ok` became `failed` / `execution_error` for
the same reason; juice-shop 34 s became 50 s; a synthetic tree of 6,196 first-party
and installed JavaScript and TypeScript files (92 MB) took 313 s and ended `failed` / `timeout` with
657 extension-pass files named lost; and the whole frontend checkout with
`node_modules` and `.next` (3.4 GB, 100,000 files) took 533 s, peak 2.7 GiB, with 31,955
JavaScript files named lost (the root run of the group did not finish in its
share of the stage). Two scans at once in one cgroup of 2 CPUs and no memory
limit (the production shape) peaked at 1,076 MiB; no run in the matrix was killed
by the kernel for memory. **A scan of a repository that commits or installs a
large JavaScript tree can therefore read `semgrep` `failed` (`timeout`), and the
loss is named, never silent.** The owner decides whether to raise the budget,
optimise the five slow JavaScript taint rules, or accept the cost; no exclusion
was added.

The segment is written within what is left of the 240 bytes, naming fewer files
and keeping the counts, and an `ok` detail is never cut with `…`, which the
backend and the frontend read as lost evaluation. The segment starts with the
exact words `declared out of scope, not scanned:`, and a consumer never reads
loss patterns inside it, so a file named like a loss message cannot change a
verdict; every file name in a detail is sanitised (`;`, `…`, control characters
and bidirectional controls become `?`, and a name is cut to 80 bytes).

In a `--diff` scan the same rules apply to the changed files: a changed file
reached through a link is listed.

### `nosemgrep`

Semgrep drops a result whose line carries a `nosemgrep` comment and says
nothing. A repository's author could therefore remove a finding from a scan
unseen. The run passes `--disable-nosem`, so Semgrep reports every match, and
the engine applies the comment itself (`go/internal/scanner/semgrep/nosem.go`),
a subset of Semgrep's reading checked against the real binary: a result is
suppressed when its first line holds ` nosem` or ` nosemgrep` (a blank before
it, any case), optionally followed by `:` or `=` and a comma-separated list of
rule ids, or when the line before the match is only a comment that does so (a
match on any later line of the match does not count). A listed id suppresses the
rule it equals or ends, at a dot, with (`js-sqli-taint` suppresses
`tmp.fendix-semgrep-rules-1.js-sqli-taint`); a bare `nosemgrep` suppresses every
rule. Where Semgrep would suppress a result and the engine cannot be sure, the
result is kept as a finding. A suppressed result is removed from the findings
and listed twice: in the detail, `nosemgrep suppressed 2 results (js-sqli-taint
routes.js:12, ...)`, and in full in `metadata.coverage.limitations`, `semgrep:
nosemgrep suppressed: python-yaml-load-unsafe app.py:10`. The comment is read
for Semgrep results only. It is not read for the other analyzers (the Python
engine still reported `PY_YAML_UNSAFE_LOAD` on a line whose Semgrep result a
`nosemgrep` suppressed). The detail is a note, not a gap: the scan is
complete, and the suppression is on the record.

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
