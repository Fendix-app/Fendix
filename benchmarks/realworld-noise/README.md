# Real-world noise baseline

How many findings does the engine report on real applications, per thousand lines
of source? The framework parity corpus (`benchmarks/frameworks/`) measures recall
on labelled snippets; it cannot show a rule pack flooding real code with findings.
This directory can.

`run.py` fetches each application in `targets.json` at its pinned commit, runs
`fendix scan --code <dir> --format json --offline`, and writes `noise.json`:

```
{name: {"kloc": float, "findings": int, "per_kloc": float, "by_rule": {rule_id: int}}}
```

`v3.6.4.json` is that file for engine v3.6.4. It is the baseline every later
engine is compared with.

## Noise budget

On the **clean applications** below, a new rule pack may add at most **2 findings
per kLOC** over the recorded baseline. Before Phase 4 ships, someone triages 20
sampled new findings per language and records the true-positive rate in the PR.

How to apply it:

1. Run the current engine (see Running) and compare its `noise.json` with
   `v3.6.4.json` for each clean application. The pack's cost on an application is
   `(new findings - baseline findings) / kloc`; it must be 2.0 or less.
2. Leave the dependency-advisory findings out of both sides (see Caveats). They are
   the rules named `deps.*` and the advisory ids `CVE-*`, `GHSA-*` and `PYSEC-*`.
   A rule pack does not change them, and they change on their own.
3. Sample 20 of the new findings per language (new = a `rule_id` whose count went
   up; against `v3.6.4.json`, leave out the `SEC-JS_*` rules, see What is counted),
   judge each as a true or false positive by reading the code, and put
   `true positives / 20` in the PR description. Clean applications are not
   vulnerable by design, so most hits there need an explanation.

The vulnerable applications are not part of the budget. They show whether a pack
finds what it should (the count should go up) and how it scales on large code.

## Targets

Every target is pinned to a full commit SHA, so a baseline stays reproducible
however the upstream repository moves. `run.py` refuses a target whose `sha` is not
40 lowercase hex digits and fails if the fetched commit differs from it.

Vulnerable by design (the OWASP-style training applications):

| Name | Repository | Language | Notes |
|---|---|---|---|
| `juice-shop` | `juice-shop/juice-shop` | ts | Express and Angular; also holds the `data/static/codefixes` snippets |
| `nodegoat` | `OWASP/NodeGoat` | js | Express |
| `webgoat` | `WebGoat/WebGoat` | java | Spring Boot |
| `govwa` | `0c34/govwa` | go | `net/http` |
| `pygoat` | `adeyosemanputra/pygoat` | python | Django |

Clean (not vulnerable by design), one per language. These carry the noise budget:

| Name | Repository | Language | Why this one |
|---|---|---|---|
| `node-express-realworld` | `gothinkster/node-express-realworld-example-app` | ts | The RealWorld reference implementation on Express and Prisma. 3.8k stars. The last push was May 2024, but RealWorld is a frozen specification, so the app is finished rather than abandoned |
| `full-stack-fastapi-template` | `fastapi/full-stack-fastapi-template` | python | The FastAPI project's own template (46k stars, pushed October 2026), with real JWT login, password hashing and SQLModel. Only `backend/` is scanned, so its TypeScript frontend does not count towards a Python row |
| `spring-petclinic` | `spring-projects/spring-petclinic` | java | The Spring team's reference application (9.6k stars, pushed September 2026) |
| `golang-gin-realworld` | `gothinkster/golang-gin-realworld-example-app` | go | The RealWorld reference implementation on Gin (2.7k stars, pushed August 2026) |

To re-pin, resolve the default branch with `git ls-remote https://github.com/<repo>.git HEAD`,
put the full SHA in `targets.json`, and record a new `v<engine version>.json`.
Do not overwrite an existing baseline file.

## Running

The scan needs the same environment as `make parity`: a `python3` and `semgrep` on
`PATH`, and `FENDIX_ENGINE` pointing at the Python engine. Build the binary from
source first.

```
make parity-prereqs PARITY_VENV=<venv with semgrep>
PATH=<venv>/bin:$PATH FENDIX_ENGINE=$PWD/python \
    python3 benchmarks/realworld-noise/run.py --fendix bin/fendix-parity --out <dir>
```

It needs network access to github.com (and, for the dependency rows, the advisory
services) and takes a minute or two. Useful flags:
`--only name,name` runs a subset, `--keep-clones` keeps the fetched trees (they go
under `$TMPDIR`) to look at a result, `--timeout` bounds each scan. A target that
cannot be fetched or scanned is reported on stderr and left out of `noise.json`;
the other targets still run and the exit status is 1. Never commit a `noise.json`
that is missing a target.

A scan that finishes is still rejected when an analyzer it depends on did not run.
The engine records a crashed or missing analyzer in `metadata.scanner_status` and
exits 0 anyway, with fewer findings, which would make a rule pack look quieter than
it is. So `secrets`, `textscan`, `semgrep` and `python-engine` must each report state
`ok`, or the target is an error that names the scanner, its state and its reason
(for example `semgrep state='skipped' reason=dependency_missing` when `semgrep` is
not on `PATH`, or `python-engine ... engine tree not found` when `FENDIX_ENGINE` is
wrong). A report with no `scanner_status` is rejected too. Every other analyzer may
be skipped or unavailable, because `--offline` and a source-only scan switch them off:
`dast`, `spec`, `active-probes`, `govulncheck`, `pip`, `npm`, `plugins` and the
`python-engine/*` sub-checks. `noise.json` carries no health field: a target that
fails the check is absent, so a file with every target in it is healthy by
construction.

`run.py` uses only the standard library and works on Python 3.9 and later.
`python/tests/test_realworld_noise.py` covers its pure parts and its git and scan
plumbing without network access or a real engine.

## What is counted

- **kLOC** is the number of lines in `.py .js .mjs .cjs .ts .tsx .jsx .java .go`
  files, in thousands, under the target's `code_dir`. Directories named
  `node_modules`, `vendor`, `dist`, `build`, `.git`, `target` and `.next` are
  skipped at any depth, and symbolic links are not followed. Blank lines and
  comments count. It is lines, not bytes: a minified bundle is one line, so a
  repository that commits one scores few kLOC for a lot of scanned text.
- **findings** is the length of the `findings` array of the JSON report, after the
  engine's own de-duplication. A finding the report carries no `rule_id` for is
  counted under `(no rule_id)`. From the engine change after v3.6.4 that gave the
  Python engine's JavaScript and TypeScript pattern checks a `rule_id`, those checks
  are counted under `SEC-JS_EVAL`, `SEC-JS_INNER_HTML`, `SEC-JS_DOCUMENT_WRITE` and
  `SEC-JS_SQL_TEMPLATE` instead, and the `(no rule_id)` bucket no longer holds them.
  `v3.6.4.json` predates that change, so its `(no rule_id)` counts include these
  checks. Against it, a drop in `(no rule_id)` with a matching rise in the `SEC-JS_*`
  buckets is a relabel of the same findings. The sampling step under Noise budget
  must not count `SEC-JS_*` as new on that account. The Semgrep rule
  `flask-missing-login-required` was removed after v3.6.4 because
  `flask-route-no-auth-decorator` reports the same routes, so against
  `v3.6.4.json` its count drops to zero (64 in `pygoat`). From the same change,
  `flask-route-no-auth-decorator` also reports a route whose auth decorator
  sits above `@app.route(...)`, which can raise its count. After v3.6.4,
  `fastapi-route-missing-auth-dependency` also counts a parameter typed with
  a name imported from a `deps` or `dependencies` module as a dependency.
  That drops its count on `full-stack-fastapi-template` from 16 to 1: the 15
  routes that take `CurrentUser` or `SessionDep` from `app.api.deps` are no
  longer reported. 11 of them are authenticated; 4 are public routes with
  only a database session. The one left is the `health-check` route.
- **per_kloc** is `findings / kloc` computed before rounding; `kloc` and `per_kloc`
  are rounded to three decimals.

## Caveats

- **Dependency advisories are not offline.** `--offline` skips the engine's native
  dependency scanners when no snapshot exists at `~/.fendix/offline-db.json`, but
  the Python engine's own dependency check (`python/analyzers/deps.py`) ignores the
  flag. It runs `npm audit` when `npm` is installed, which queries the npm registry,
  and `pip-audit` and `govulncheck` when those are installed; otherwise it falls
  back to a short curated list of CVEs. On the recording machine `npm` was
  installed and the other two were not. So `nodegoat` (146 of 154 findings) and
  `node-express-realworld` (49 of 51) are mostly `deps.npm-audit/*` rows from live
  data, and `pygoat`'s four `CVE-*` rows come from the curated list. The npm rows
  move when advisories are published and with the tools installed on the machine, so
  dependency findings are not part of the budget. `per_kloc` in the committed file
  includes them; subtract them as described under Noise budget.
- **One build, one machine.** `v3.6.4.json` was produced by a source build of the
  v3.6.4 engine (`make parity-prereqs`; `fendix version` prints `dev`) with semgrep
  1.141.0 on Python 3.11. Two consecutive runs were byte-identical.
- **The corpora are small.** The clean applications are 2 to 4 kLOC each, so one
  finding moves `per_kloc` by 0.2 to 0.4 and the 2.0 budget allows only 4 to 8 new
  findings per application. Read a failing budget by rule, not by the ratio alone.
