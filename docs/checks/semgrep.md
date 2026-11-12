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
2. Decides the scope from the tree before it runs Semgrep (`go/internal/scanner/semgrep/targets.go`, `go/internal/scope`): it lists the in-scope files Semgrep is meant to evaluate and the paths declared out of scope on evidence (see "Scope (decisions D6 and D6')" below). `--code` that is itself a symbolic link is resolved first: `<code_path>` below is the directory it resolves to, because Semgrep does not follow a linked scanning root; links below it are never followed.
3. Invokes `semgrep --config <rules_dir> --json --no-git-ignore --quiet --disable-version-check --time --max-target-bytes 1048576 --disable-nosem --dataflow-traces --timeout 30 --jobs <n> --max-memory <MiB> --project-root <code_path> --x-ignore-semgrepignore-files [--exclude /<path> ...] [--include <changed file> ...] <code_path>`, inside a wall budget (see "Runtime and memory budget"). Each option does one thing:
   - `--timeout 30` bounds one rule on one file; a rule that hits it loses its matches in that file, and Semgrep's `--timeout-threshold`, left at its default of 3, skips every remaining rule on a file after three such timeouts. Semgrep reports a taint rule that ran out of its fixpoint budget on a function only in the run's profile (`time.fixpoint_timeouts`), never in `errors`; v3.7.0 never read that profile, so those matches vanished with no error. Semgrep 1.182.1 writes the profile with or without `--time`; `--time` is passed so that a release which writes it only on request does too, and detection does not depend on it: a document without a `fixpoint_timeouts` list is recorded as a gap (below). Any of these is lost rule evaluation: the findings of the run are kept, and the `semgrep` entry in `scanner_status` is `failed` (see "What `ok` means" below), because the rule's matches in that file are missing.
   - `--max-target-bytes 1048576` is the size cap every Go analyzer shares, passed explicitly so that a Semgrep whose default differs skips exactly the files the engine lists as too large.
   - `--disable-nosem` stops Semgrep dropping a result whose line carries a `nosemgrep` comment; the engine applies the comment itself and reports what it suppressed (see "`nosemgrep`").
   - `--x-ignore-semgrepignore-files` stops Semgrep reading the scanned tree's `.semgrepignore` files and, when the tree has none at its root, its own built-in default ignore list (which drops `tests/` and `test/` at any depth, `*.min.js` and more): what is scanned is the engine's decision, the same for every project, never the repository's. A Python `tests/` directory is therefore scanned.
   - `--exclude /<path>` is one anchored pattern for each path the engine declared out of scope on evidence (at most 1000 per run; a path past that is scanned). There is no name-based exclude list.
   - `--include <changed file>` is added for each changed file of a `--diff` scan.
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
- **Memory.** The memory budget is the cgroup memory limit (capped by the host's `MemTotal`); with no cgroup limit it is half the host's memory (a 3.8 GB host gives 1900 MiB, the share of one scan worker at concurrency 1). `--max-memory` is `(budget - 384 MiB) x 90%`, never below 256 MiB: 384 MiB is held back for Semgrep's Python wrapper, the engine and the page cache, and Semgrep's documentation says the limit "will be exceeded before it gets detected", so a tenth is margin. 1900 MiB gives 1364; 3800 MiB gives 3074. With the limit exceeded Semgrep reports a per-file `Out of memory` naming the file (the engine does not die, and findings of other files are kept), which is recorded `failed` / `execution_error`. With no memory information, none is passed.
- **Wall budget.** 300 s for the whole stage, every invocation and retry together, shrunk to leave 90 s of the run's own remaining time for the analyzers that run after Semgrep when the run has a deadline, never below 20 s. A hosted scan's own deadline is minutes above it, so the engine has time left to write its report.
- **The log line.** Each stage logs its budget at INFO, for example `semgrep: stage budget budget="jobs=2 max-memory=1004MiB wall=5m0s (cgroup v2, cpu quota 2.00, memory limit 1500 MiB)"`.
- **Settings.** `FENDIX_SEMGREP_JOBS` (1 to 256), `FENDIX_SEMGREP_MAX_MEMORY_MIB` (0 for none, otherwise at least 256), `FENDIX_SEMGREP_BUDGET_SECONDS` (30 to 3600) and `FENDIX_SEMGREP_SPLIT_BYTES` (-1 never splits) override the derived values; a value that is not an integer in range is ignored with a warning and never turns into an unbounded run. `models.ScanConfig` carries `SemgrepJobs`, `SemgrepMaxMemoryMiB` (negative: pass none) and `SemgrepWallBudget`; there is no command-line flag. A service that builds each engine child's environment by default-deny (the hosted backend does) never passes the variables on, so a hosted worker is sized by its container's limits.

### One invocation, or one per language group

A tree in a single language group, or a small one, is one invocation with every pack, as it always was. A tree with in-scope files in at least two language groups (`python`, `javascript` with `typescript`, `java`, `go`) and at least 4 MiB of in-scope source is split into one invocation per group, cheapest first, each loading only its own packs. The deadlines are static offsets from the start of the stage, computed from file sizes and the budget only, so a slow group borrows what an earlier one left and cannot starve the groups after it. A group that reaches its deadline is killed and loses only its own findings (Semgrep prints its JSON once, at the end); the finished groups' findings are kept. The stage ends `failed` / `timeout` with one segment that is never cut: `semgrep: timed out after 1m0s; not evaluated: java 3 files`. The unevaluated files are not in `paths.scanned`, so they are also named as not evaluated. Killing an invocation takes down its whole process tree (descendants are read from `/proc` and killed, then the wrapper) and leaves Semgrep in the engine's own process group, so a caller that ends a timed-out engine by process group still ends Semgrep. Before this, a timed-out Semgrep left `semgrep-core` running, using CPU and memory for the next analyzer and the next scan.

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
| A partial parse (`PartialParsing`) whose skipped line spans are reported, are at most the larger of 3 lines and 5% of the file's lines, and are fewer than all of its lines (the allowance is `min(max(3, 5%), lines - 1)`, decision D1') | `ok`, with the count by type in `detail` (never the message, which can quote source): `<n> non-fatal per-file problem(s) reported by semgrep (PartialParsing <n>); findings in those files may be incomplete`, then the lines: `partial parse, <n> files with skipped lines: a.py 4, b.js 10-12` (`1 file` for one) |
| A file Semgrep could not parse at all (`Syntax error`, `Lexical error`, `Other syntax error`, `AST builder error`, and the constructor spellings `ParseError`, `LexicalError`, `OtherParseError`, `AstBuilderError`), or a partial parse with no usable span, with more lines skipped than above, or that skipped every line of the file (decision D1': the analysed scope must be known, so a file Semgrep skipped whole is never "a few lines") | `failed` / `execution_error`, `<k> not parsed by semgrep (<path>, ...)` in the `lost evaluation:` segment; findings kept |
| Lost evaluation where every loss is a timeout: a rule `Timeout` (a rule Semgrep stopped on a file after `--timeout 30`), the rest of a file's rules skipped after 3 rule timeouts (`--timeout-threshold`), a taint `Fixpoint timeout`, a `Timeout during interfile analysis` | `failed` / `timeout`, `detail` starting `lost evaluation:` (format below); findings kept |
| Any other lost evaluation: a per-file `Out of memory`, `Stack overflow`, `OOM during interfile analysis`, `Internal matching error`, `Too many matches`, `Missing plugin`, `Fatal error`, `SemgrepWarning`, or any per-file type not listed as a parse problem above, in either Semgrep's spelling or the constructor name (`OutOfMemory`, `MatchingError`, ...), since a type Fendix does not know cannot be shown to have cost nothing; an `errors` entry that could not be decoded at all, or an `errors` that is not a list; a loss-type entry whose fields could not be read (it is decoded leniently, and any count beyond what was decoded is reported); rules Semgrep lists in `skipped_rules`; a profile whose `fixpoint_timeouts` is missing, `null` or not a list; a dropped `--project-root` or `--x-ignore-semgrepignore-files`; an in-scope file over 1048576 bytes, unreadable, not parsed, or absent from Semgrep's `paths.scanned` (decision D6, below); or a timeout mixed with any of these | `failed` / `execution_error`, `detail` as above; findings kept |
| Files declared out of scope left unread on evidence (decision D6'): a directory of installed or built code, a minified or vendored-library bundle, a lockfile, source map, generated or compiled file over the cap, and a symbolic link. A source file is never declared out of scope for its name, extension or path: `APP.JS`, `.mts`, a test or fixture file are evaluated, and a `.vue` file is lost evaluation (below) | `ok`, with the paths named in `detail` (below); never a gap |
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
3. For in-scope files left unread (decisions D6 and D1'): `lost evaluation: <N>
   in-scope files not read: <k> over 1048576 bytes (<path>, <path>, <path> +<m>
   more), <k> unreadable (<path>), <k> not evaluated by semgrep (<path>), <k>
   not parsed by semgrep (<path>)`, each kind present only when it applies,
   at most three paths each.
4. `semgrep reported no taint fixpoint timeouts list (--time), so a taint rule that ran out of time would be silent`
5. The lossy dropped-options note, followed by `; files may be skipped: ` and what each lossy option costs, joined with `; `: `the packs' path filters need --project-root`, `Semgrep's default ignore list and the tree's .semgrepignore files apply`.

Notes:

6. The non-fatal per-file problem count of the `ok` row above.
7. `partial parse, <n> files with skipped lines: <path> <lines>, ...` (`1 file` for one; measured: `partial parse, 1 file with skipped lines: src/partial.js 41`)
8. The dropped-options note when nothing lossy was dropped.
9. `nosemgrep suppressed <n> results (<rule> <path>:<line>, ...)`.

Exclusions:

10. `declared out of scope, not scanned: <reason> <n> (<name>, <name>, <name> +<m> more), <reason> <n> (...)`, one entry per reason in the order each was first used.

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

Two details from scans of a small tree on this tree with Semgrep 1.182.1
(round 4):
`lost evaluation: 2 in-scope files not read: 2 not parsed by semgrep (src/big.js, tiny.js); 2 non-fatal per-file problem(s) reported by semgrep (PartialParsing 2); findings in those files may be incomplete; and 3 more (see report metadata)`
(`failed` / `execution_error`; a JavaScript class with one broken member, which
Semgrep reported as a `Syntax error` for the whole file, and a two-line file
that a partial parse skipped whole) and
`nosemgrep suppressed 1 result (python-yaml-load-unsafe app.py:10); declared out of scope, not scanned: minified 1 (lib/jquery.min.js), installed npm packages 1 (node_modules/)`
(`ok`). The first shows the budget at work: the three segments that did not fit
are counted in `and 3 more` and listed in `metadata.coverage.limitations`.

A taint fixpoint timeout depends on load, so the same file can lose its taint
matches on one run and not on the next; the run that lost them says so, and the
retry pass (above) re-runs the file alone before it is recorded lost.

### Scope (decisions D6 and D6')

Semgrep's JSON names the files it evaluated (`paths.scanned`) and nothing
about the ones it did not. Fendix therefore lists the files the run was meant
to evaluate itself (`go/internal/scanner/semgrep/targets.go`): every regular
file under `<code_path>`, or every changed file of a `--diff` scan, with an
extension of the packs' languages in any letter case (`.py`, `.pyi`, `.js`,
`.jsx`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.java`, `.go`, which Semgrep 1.182.1
selects when written in lower case, and `.cts`, `.mts`, `.es6`, `.vue`, which
it does not select: those are run in the extensions pass), outside `.git/`, not
reached through a link. It then compares that list with `paths.scanned`:

- a file over 1048576 bytes (`--max-target-bytes`) that nothing in it shows to
  be generated, one that cannot be opened, a directory that cannot be listed,
  a file Semgrep could not parse (decision D1'), and a file absent from
  `paths.scanned` is lost evaluation, recorded `failed` / `execution_error`
  with the files named (the findings of the rest of the run are kept). A
  document with no `paths.scanned` list loses every file it was meant to
  evaluate;
- a path declared out of scope on evidence (decision D6', below) is never a
  gap: it is listed by name, with its reason, in the `ok` detail and,
  complete, in `metadata.coverage.limitations`.

**Evidence, never a name.** A directory is left out only when it holds the
markers of installed or built code (`go/internal/scope/dirs.go`), whatever it
is called, and a directory merely called `node_modules`, `vendor`, `dist`,
`build`, `target` or `.next` is walked. The reasons, each in the `declared out
of scope` segment:

| Reason | Evidence read from the directory |
|---|---|
| `installed npm packages` | a `node_modules/` with `.package-lock.json`, `.yarn-integrity` or `.modules.yaml`; or `node_modules/<pkg>` (or `@scope/<pkg>`) whose `package.json` names exactly that package and a version |
| `python virtualenv` | `pyvenv.cfg` with a `home =` line, or `conda-meta/history`, under any directory name |
| `installed python packages` | `site-packages` or `dist-packages` with a `*.dist-info` holding `RECORD` and `METADATA` |
| `go vendor tree` | `vendor/modules.txt` |
| `composer vendor tree` | `vendor/composer/installed.json` and `vendor/autoload.php` |
| `cargo build output` | `target/CACHEDIR.TAG` with Cargo's signature |
| `maven build output` | `target/` beside a `pom.xml`, holding `maven-status`, `maven-archiver` or `surefire-reports` |
| `gradle build output` | `build/` beside a `build.gradle`, `build.gradle.kts`, `settings.gradle` or `settings.gradle.kts`, holding `classes`, `libs`, `tmp`, `reports`, `generated`, `intermediates` or `kotlin` |
| `next.js build output` | `.next/` with `BUILD_ID` and `build-manifest.json` |
| `npm cache` | `.npm/_cacache` |
| `setuptools build output` | `build/` beside `setup.py` or `pyproject.toml`, holding `lib` and a `bdist.*` or `temp.*` directory |

A file is left out only on content read from it (`go/internal/scope/classify.go`).
Only a JavaScript or TypeScript file under the size cap whose verdict is
`minified` or `vendored library` is skipped (one `--exclude` each); a
`generator header` or `compiled output` file under the cap is still scanned, so
that excluding more than before never weakens detection. A file over the cap
with any of these verdicts is declared out of scope instead of lost:

| Reason | Evidence read from the file |
|---|---|
| `lockfile` | a package manager's exact lockfile name (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock`, `composer.lock`, `Gemfile.lock`, ...) **and** content that parses as that lockfile's format |
| `source map` | a `*.map` file that is a version-3 source map with a string `mappings` |
| `minified` | JavaScript, TypeScript or CSS in which at least 90% of the bytes lie in lines over 250 bytes, those lines hold at least 1024 bytes, at least one byte in twenty of them is `;`, `{`, `}`, `(`, `)` or `=`, and at most 40 other lines are non-blank |
| `vendored library` | all three of: a leading comment whose **subject** is a known library with a version (`jQuery v3.6.0`, `Bootstrap v3.1.1`, `Lodash <https://lodash.com/>`; the table has jQuery, Bootstrap, Underscore, lodash, Backbone, Moment, Angular, React, Vue, D3, Chart.js, Popper, highlight.js, Hammer, Zepto, Modernizr, Handlebars, Select2, DataTables, Leaflet, Knockout, Highcharts, Socket.IO, and the three.js, Ace and pdf.js builds); the library's own identifier at least three times in the 64 KiB after the banner; and a size of at least 8 KiB whose body reads no HTTP request (`req.query`, `request.body`, ...) and imports none of `express`, `koa`, `fastify`, `http`, `child_process`. A header that only mentions a library, an SPDX line, or any `/*!` banner with a version is not that, and neither is a library the table does not list: those files are in scope |
| `generator header` | in the first 25 lines, comment lines only: `// Code generated ... DO NOT EDIT.`, `@generated`, the protocol buffer compiler's header or a `protoc-gen-` plugin, "do not edit" beside "generated", `Generated by <tool> <version>`, Thrift, OpenAPI Generator and swagger-codegen headers |
| `compiled output` | a trailing `sourceMappingURL` comment or a webpack bootstrap |

A file called `app.min.js` that is ordinary source, or `package-lock.json` that
is not a lockfile, has no such evidence and is scanned. The minified thresholds
were measured on 26,272 JavaScript, TypeScript and CSS files (mostly the
installed packages of four projects) and 1,175 first-party files; the
measurement is in
`go/internal/scope/classify.go`, and `FENDIX_SCOPE_CORPUS` in `corpus_test.go`
re-runs it on a tree.

One more kind is listed, not judged:

- `symbolic link`: a link to a directory, or to a source file of a pack
  language, which Semgrep never follows.

Two things that were once listed here are no longer left out at all. A test or
fixture file used to be listed as `test/fixture path`, because every rule of its
language excluded it by the pack's `paths.exclude`; the engine now strips those
filters from the packs it runs (see "How It Works"), so such a file is
evaluated, and `test/fixture path` is no longer written. A source file whose
extension Semgrep does not select (`APP.JS`, `.mts`) used to be listed as
`extension not selected`; it is evaluated in the extensions pass, and
`extension not selected` is no longer written. (A consumer must still tolerate
both inside a declared segment, which it never reads.)

The segment is written within what is left of the 240 bytes, naming fewer files
and keeping the counts, and an `ok` detail is never cut with `…`, which the
backend and the frontend read as lost evaluation. The segment starts with the
exact words `declared out of scope, not scanned:`, and a consumer never reads
loss patterns inside it, so a file named like a loss message cannot change a
verdict; every file name in a detail is sanitised (`;`, `…`, control characters
and bidirectional controls become `?`, and a name is cut to 80 bytes).

In a `--diff` scan the same classification applies to the changed files: a
changed file under such a directory, or reached through a link, is listed.

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
