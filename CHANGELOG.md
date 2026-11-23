# Changelog

All notable changes to Fendix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Per-binary SLSA provenance can now be verified on its own (#90).** Up to
  v3.8.1 each binary's `.intoto.jsonl` was a bare in-toto statement with no
  signature, so no cosign command could verify it. Each binary now ships
  `fendix-vX.Y.Z-<os>-<arch>.sigstore.json`, a Sigstore bundle holding the
  signed provenance, its certificate and the Rekor proof, verified with
  `cosign verify-blob-attestation --bundle` as shown in `SECURITY.md`. The
  release workflow runs that recipe on every binary before publishing, and a
  regression test keeps the recipe and the workflow in step. The
  `.intoto.jsonl` statement is still published. Releases up to v3.8.1 are not
  re-signed and have no bundle.

## [3.8.1] - 2026-11-20

### Security

- Build release binaries and both container images with Go 1.27.4, and ship
  that toolchain for govulncheck. This fixes CVE-2026-97054 (GO-2026-6859)
  in the bundled standard library. The builder image is pinned by digest.
- No scanner source, report schema, finding identity or decision-policy change.

## [3.8.0] - 2026-11-19

v3.8.0 is the remediation release: a scan says what it did not read, a finding
is graded on its own evidence, and no recogniser can turn a real finding into a
clean scan. It is a minor release under SemVer: the report schema, SARIF
structure, exit-code meanings and CLI flags are unchanged; what changes is what
a scan reports.

What a customer will see:

- **More scans read `incomplete`.** A file an analyzer could not read (over a
  size cap, unreadable, a Python file whose PEP 263 cookie is not a
  takeover-immune spelling of UTF-8, Latin-1 or ASCII, a JavaScript, TypeScript
  or Java file whose unicode escapes change what the analyzers see) is recorded
  as lost evaluation under the existing reasons. The findings of the file are kept.
- **Findings are graded on their own evidence.** Different constructs on one
  line stay separate findings; occurrences group only with occurrences of the
  same evidence, so positional ids (`SEC-nnn`) and finding counts change, and
  fingerprints of constructs that used to be merged into another appear again.
  Occurrence fingerprints do not change.
- **Credentials in test code and documentation warn.** A credential in a test
  path or a documentation file holds at `WARN` unless it is provable offline (a
  checksum-valid GitHub token, a parseable private key, an AWS key pair); it is
  still reported. A value is judged a sample only when the whole value is a
  sample form, so a real secret written next to a published example keeps
  v3.7.0's status.
- **`eval` and path-traversal guards lower, never remove.** `SEC-JS_EVAL`
  reports every site v3.7.0's line pattern matched; one in a comment, string or
  regular expression is reported at a grade that warns. A path-traversal sink
  behind a recognised guard is reported at `WARN`.

Known limitations, accepted for this release (owner rulings OR-85 to OR-90):
the PEP 263 rule assumes the interpreter's environment is not controlled by the
scanned repository (script mode with a reachable `sitecustomize` is out of
scope); password assignments inside JSON members, unquoted `.env`/YAML values
and similar forms are not read by any release; Semgrep's stage on a single
line of a megabyte or more can take tens of seconds and records lost
evaluation when it times out; crafted syntax that makes a complete JavaScript
reading wrong can lower a v3.7.0 `BLOCK` on `eval` to `WARN`.

The entries below record each change by remediation round.

**Round 5 of the remediation program (2026-11-13) changed what this section
says in these places; the entries below are updated where they would otherwise
mislead:**

- **Source scope (D5-2):** every supported file at or below the size cap is
  analysed whatever it looks like (minified, vendored, generated, test,
  `node_modules`, virtualenv code included); nothing is excluded for a banner,
  header, name, marker, large literal or appearance. Only a symbolic link, a
  recognised lockfile (policy; no analyzer applies it yet) and a real root `.git`
  are left out. This costs scan time; no exclusion was added. See "Source scope:
  everything under the cap is analysed" under Security.
- **Semgrep partial parse (C4B-27):** stays `ok` only when every skipped line is
  blank or a whole-line comment.
- **`fendix verify` (D5-3):** *superseded by Round 6 (D4 Option A, below): `verify`
  never answers `resolved`.* As written in Round 5, `resolved` was allowed only for a
  secrets-scanner finding whose whole scope was read and decoded; an HTTP status never
  resolves anything; the encodings, the unreadable-content rule and the
  `<root>/.git/objects`-only history rule are in "`fendix verify` says `resolved` only
  when the whole scope was read and decoded" under Security, which keeps the search
  that decides `still-present`.
- **Active probes (D5-6):** 401/403/404/410 answers are gated and not evaluated, and
  a pass that evaluated nothing is a coverage gap that `--require-analyzers
  active-probes` refuses (exit 2); `gated` and `cut_short` are additive
  `coverage.active_probes` fields. See "Probes the target answered 401, 403, 404 or
  410 are gated" under Changed.
- **Python engine:** an ambiguous branch or `try` binding is lost evaluation, a
  generator body runs where it is consumed, a star import must agree.
- **Budgets:** production runs the scan worker at concurrency 2 with no container
  memory limit on a 2-CPU, 3.8 GB host with no swap (backend `DEPLOY_RUNBOOK.md`
  8.5); the Semgrep budget assumes at most 2 CPUs per scan, no memory cap and two
  scans at once (`FENDIX_SCAN_CONCURRENCY`, default 2), and the source-scope change
  raises scan time on repositories with large front-end or installed-dependency
  trees. A Semgrep group over 3 MiB now runs its 8 heaviest files of 192 KiB or more
  in invocations of their own, so one pathological bundle loses only itself
  (measured: `gogs` lost 230 JavaScript files to a stage timeout before, 1 after).
- **Installed dependencies (owner amendment A1):** no installed-dependency tree is
  excluded. A first scheme (a Go module directory excluded when its files hashed to
  the `go.sum` `h1:` line) was removed before release because a repository can write
  both the directory and its own pin; `node_modules`, `vendor` and virtualenvs are
  analysed in full, and the cost is stated under "Source scope: everything under the
  cap is analysed".
- **`fendix verify` (continuation):** wrapped, split and escaped-break base64, base32
  and base64 of UTF-16 are searched; a passive URL finding and a dependency finding
  are `unknown`, never `resolved`; a CORS re-test sends the attacker `Origin`; a
  forged media header no longer turns the opaque-binary rule off.
- **`fendix import`:** `metadata.imports[]` records the producer's own run
  (`execution_successful`, `error_notifications`, `analyzed_paths`), so a consumer
  can tell a run that failed or never covered a file from a clean one; the import
  report's `coverage.limitations` names a failed run. Absent keys mean *not recorded*.
  `docs/schema.json` (`ImportedTool`, `additionalProperties: false`) lists the three keys
  from Round 6 (R5-08); a failed or partial run is now also a coverage gap (below).
- **Smaller fixes:** a deadline that fired is never trusted even if the process
  exited 0, and the process tree is frozen before it is killed; the strongest
  non-Semgrep confidence wins when findings at one location collapse (`eval` of a
  non-literal now blocks at HIGH/HIGH in `.js`, `.mts` and `.cts` whenever the
  Python engine's rule also reports it, where the textscan finding's MEDIUM won and it
  warned; a release-note item, approved by the owner with release documentation (D20),
  whose final wording is the `SEC-JS_EVAL` item of the Release Closure Sprint below); a file
  Semgrep cannot list no longer fails the whole Semgrep run; a named pipe called
  `*.js` no longer hangs the scan; a Python file with a PEP 263 coding line that is not
  a takeover-immune spelling of UTF-8, Latin-1 or ASCII is lost Semgrep evaluation (first
  written for non-ASCII-transparent codecs; narrowed by D2-A, below).

**Round 6 of the remediation program (2026-11-15), engine verify, coverage and
contracts (WS-E2). Nothing here is released; every item has a failing test that
was written first (`*_round6_test.go`, `*_wse2_test.go`).**

- **`fendix verify` never answers `resolved` (D4 Option A, R-010).** Not finding a
  credential in an enumerated list of representations cannot prove it is gone, so
  the answer is `still-present` when the problem is seen again and `unknown`
  otherwise, for every finding, every occurrence of a grouped finding and the fold
  over a group (`verifycmd.go`'s two former `resolved` paths, the no-marker
  provider-anchored path R6-E3 and the grouped fold included). `verify` never exits
  0: the CLI maps a stray `resolved` to exit 2. `StatusResolved` stays in the output
  vocabulary for consumers that know it. `fendix verify --help`, its `Short` line, its
  CI example and `docs/cli-contract.json` no longer promise `resolved` or exit 0 and no
  longer list URL, dependency or correlated findings as supported shapes; the help is a
  reviewed golden (`cmd/fendix/testdata/verify_help.golden`, C4B-21). Upgrading: a
  script that treats exit 0 as "the finding is gone" now never sees 0; re-run
  `fendix scan` and diff against the baseline. Existing tests that pinned `resolved`
  were updated to `unknown` (12 in `internal/verifycmd` and one e2e test), none
  deleted.
- **A probe pass reads complete only when every planned probe was evaluated (A-D5,
  policy 2.6.0 engine half).** There is no percentage threshold: a gated (401, 403,
  404, 410) or unanswered probe is not evaluated, is target-owned, and still makes
  `active-probes` `failed` / `no_endpoints` (R5-07 read `ok` with 22 of 2,687
  evaluated). Counts that do not add up read `failed` / `malformed_output`. The
  evidence is bounded and exact whatever the probe count: `not_evaluated_counts`
  (one row per origin, reason and HTTP status), at most 200 `not_evaluated_groups`,
  `groups_total`, `inline_truncated`, `listing_ceiling_reached` and `listing_overflow`
  (a listing ceiling of 100,000 groups, with the overflow counted), all additive in
  `coverage.active_probes`. The probe log keeps 10,000 records (long fields cut to
  1 KiB), an exact streaming ledger and 64-bit endpoint-hash counts (a collision can
  only make the per-endpoint budget stricter: the count only grows, the 64-bit hash
  is keyed per process so a target cannot choose colliding endpoints, and no verdict
  reads those counts); per-probe stderr lines stop at a 1 MiB budget and one exact line
  counts the rest (`--verbose` restores every line). The paging transport for groups
  past the inline bound is not part of this change (held for M-2). Existing engine
  tests that pinned the old rule were updated, none deleted (listed in the
  Round 6 report).
- **A producer's failed or partial run is a coverage gap (R5-09, D6).**
  `executionSuccessful: false`, an exit signal, a non-zero `exitCode` with no success
  recorded, and error-level `toolExecutionNotifications` or
  `toolConfigurationNotifications`, in any invocation, run or file of a tool, add an
  `import/<tool>` entry to `coverage.gaps` and make `configured_complete` false; with
  two producers only the failed one is a gap. `fendix import --fail-on` then exits 2 (a
  coverage exit, before the findings exit 1), and `scan --import` reports the same gap.
  A run with no `invocations` is not a gap, and a non-zero `exitCode` beside an explicit
  `executionSuccessful: true` is read as neither failure nor success. An error count
  above zero is no longer lost when another run of the tool records nothing. The import
  goldens changed (`python/tests/fixtures/report_schema/engine`).
- **The report schema covers everything the engine writes (R5-08).**
  `docs/schema.json` gains the `ImportedTool` run record and the D5 keys, with their
  minimums, and `docs/schema.md` says so; a reflective test walks the report root and
  fails on any serialised field the schema lacks, and a Python test validates real
  engine, corpus and v3.7.0 reports with a JSON Schema validator
  (`python/tests/test_report_schema.py`).
- **textscan honours `--max-duration` (R5-19).** `textscan.ScanCoverage` takes the
  run's context and stops within one entry's work of the deadline, on the full walk and
  the diff-allowlist path, returning the findings it made (which now reach the report)
  and the context's error (`failed/timeout`). The stage is given a 2 s floor when an
  earlier stage spent the deadline, so it still delivers what it finds first; the
  overrun it adds is at most that floor.
- **Bounded output (OR-13).** The `--debug-bundle` holds at most 10,000 probe records
  and 8 MiB of them, says so in `probes.summary.json` with the exact total, and keeps
  at most 16 MiB of `debug.log`; the pip scanner's per-package stderr lines stop at 32
  KiB and one exact line counts the rest; the worker pool's per-panic log lines stop at
  64 KiB per pass and one line at the end of the pass counts the rest.
- **Python source encoding is read as CPython reads it (WS-E1, R5-01, R6-E1, R6-E2,
  R6-E6, DE5-07).** One predicate (`scope.ClassifyPythonSource`, with the same one in
  `python/analyzers/scope_evidence.py`) serves Semgrep's target selection, the secrets
  scan, the `fendix verify` re-test and the Python engine: the cookie is read from line
  1 or 2 with CPython's line model (`\r\n`, `\r`, `\n`, no byte limit, `python -x`),
  the name is resolved through a codec table measured on CPython 3.14.5, and a file whose
  codec is not a takeover-immune spelling (D2-A, below), whose name only a run-time registration could supply,
  or whose cookie only `python -x` reads is lost evaluation in every reader. The Python
  engine no longer falls back to UTF-8, and no codec error aborts the tree. Semgrep's
  partial-parse judge reads the language's own lines. **The codec policy is the owner's
  D2-A, ruled and implemented in the Release Closure Sprint (below): only the
  takeover-immune spellings of UTF-8, Latin-1 and ASCII read as UTF-8, because a scanned
  repository can rebind any other name at run time. It is behind one compiled-in constant
  (`codecPolicy` in `go/internal/scope/pysource.go`, `PEP263_POLICY` in the Python
  module). Round 6 first shipped decision D2 as approved (every ASCII-transparent codec
  reads as UTF-8) behind the same constant; that reading is superseded.**
  `docs/checks/semgrep.md` and `docs/checks/ast-analyzer.md` describe it.
- **Media framing is stricter (R5-11, R5-12, OR-14).** An ISO-BMFF file needs an `ftyp`
  box of whole four-letter brands followed by boxes of the types a base media file
  carries, with consistent sizes and zero-filled padding (an `ftyp` box followed by
  noise read as video in 1.9 % of seeded runs, and always for a hand-typed `free`
  box); a GIF needs a well-formed screen, extensions and images inside the screen, a
  comment that is text, and a trailer that is the last byte (a forged header over noise
  read as a picture in 8 of 1,000 seeded runs). A container can still carry a payload
  in `mdat`, an application extension or image data: the check recognises framing.

**Release Closure Sprint (2026-11-17): scope, scoring and analyzer corrections,
under the owner's rulings of the closure sprint. Nothing here is released. Every
behaviour change below has a failing test that was written first (the `conditional_escape`
item documents an earlier change and adds none), and the three scope items (source
encodings and the two unicode-escape cases) were also run end to end on a binary built
from this tree. The finding-decision policy version stays `1.0.0` in this build (last
item).**

- **Python source encodings: only the takeover-immune spellings read as UTF-8
  (D2-A, ruled and implemented).** The predicate described under Round 6 above
  now runs under the owner's D2-A ruling, which replaces decision D2 as first
  approved. A Python file whose PEP 263 cookie names `utf-8`, `latin-1` or
  `iso-8859-1`, or `ascii`, in the spellings the generated table measures as
  immune, is still read as UTF-8; matching is case-insensitive: `utf-8`, `utf_8`,
  `utf8`, `utf-8-*`; `latin-1`, `latin1`, `latin_1`, `iso-8859-1`, `iso8859-1`,
  `iso8859_1`, `iso_8859_1`, `iso_8859_1_1987`, `iso-latin-1`, `latin-1-*`; `ascii`,
  `us-ascii`, `us_ascii`. **Every other cookie is foreign:** Semgrep and the
  secrets scan record the file as lost evaluation (`<k> not parsed by semgrep`,
  `<k> unreadable`), the scan reads incomplete, and the Python engine still decodes
  the file with the codec the cookie names. That now includes aliases of those same
  codecs (`utf`, `u8`, `cp65001`, `latin`, `l1`, `cp819`, `646`) and the legacy
  code pages (`cp1252`, `euc-jp`, `koi8-r`). That includes the non-text transform codecs (`hex`, `base64`, `zlib`, `uu`, `bz2`,
  `quopri`, `rot13`, `undefined` and their aliases): CPython refuses them from its own
  registry, but the registry is what a module in the scanned repository rewrites, so a
  file that names one is lost evaluation like any other foreign cookie. A byte order mark
  beside another codec is refused by the tokenizer and stays a refusal (not lost). **Why:** a module in the scanned
  repository can redefine any other codec name at run time and run a program that
  every analyzer reads only as a comment; D2 as first approved left that as a
  documented false clean. **Customer remedy:** save the file as UTF-8 and declare
  `utf-8`, or remove the declaration; the report names each file. **Measured:** the
  immune set is the same on CPython 3.8 to 3.14 (1,473 spellings measured on each),
  and in the 106-repository corpus one file in one repository changes (a `utf`
  cookie in flaskbb). The policy is still one compiled-in constant per language
  (`codecPolicy` in `go/internal/scope/pysource.go`, `PEP263_POLICY` in
  `python/analyzers/scope_evidence.py`, both D2-A); the 51 hijacked-name vectors
  that were expected failures under D2 are ordinary assertions now, and
  `FENDIX_PEP263_POLICY=d2` asserts the superseded readings in the tests only.
- **JavaScript and TypeScript files with an identifier written as a unicode escape
  are not fully evaluated (R6-E7a).** The runtime reads an identifier spelled with
  `\u` escapes as the name it spells, but Semgrep's patterns, textscan's regular
  expressions and the Python engine's JavaScript checks match names as written. A
  file in which an identifier (a name, a property, a label) is written that way is
  now lost evaluation, under the existing reasons and with no new enum or schema
  change: Semgrep `<k> not parsed by semgrep (<path>)`, textscan `<k> unreadable
  (<path> (identifier escape))`, and `python-engine/injection` `lost evaluation, not
  fully analysed: <path> (unreadable: an identifier spelled with a unicode escape,
  ...)`. The scan reads incomplete and the findings of the file are kept. An escape
  inside a string, the text of a template literal (code inside `${...}` is code), a
  regular expression literal, a comment or JSX text is not an identifier and costs
  nothing; a regular expression literal is told apart from a division by the token
  before it, and where that token cannot decide the lexer reads the spot both ways
  and reports the file when either reading finds an escape; where a `<` could open a type parameter list (`<T,>(x) => x`, `<T extends U>(x) => x`,
  `<const T,>(x) => x`, Flow's `<T>(x) => x`) it reads the text as an element and as a
  comparison, and a generic JSX element's type arguments (`<Select<string> />`) are
  skipped, so an escape in code that either reading finds makes the file lost evaluation. **The lexer
  fails closed:** a type argument list is read to its end whatever its length (a union of 40,000 members is
  valid), and when the lexer cannot decide a file (a template with a substitution inside a type argument
  list, nesting past 20,000 levels, or more readings or work than its budget allows) it gives up and the
  file is lost evaluation; no limit ever makes it resume a reading that can skip code (verifier finding
  R3-SEC-A2, owner ruling OR-88). A list that nothing closes is in no valid file: its reading ends, as an
  unterminated comment ends one, and the other reading of a doubtful `<` is still read. It covers `.js`, `.jsx`, `.mjs`, `.cjs`,
  `.es6`, `.ts`, `.tsx`, `.mts` and `.cts` in any letter case; a `.vue` file was
  already lost evaluation. **Customer remedy:** write the identifier in plain
  characters; for a generated bundle, emit identifiers as UTF-8 text (for example
  esbuild's `charset: "utf8"`). **Measured:** the rule is checked against the
  TypeScript scanner as ground truth (196 vectors, all from its token stream, 27 of
  them also run in Node; a 27,000-program differential run found no valid program
  the rule read as clean while the scanner saw an escape); on the 106-repository
  corpus 1 of 27,382 JavaScript and TypeScript files is reported (a bundled
  library whose object keys are escaped), against 249 files in 48 repositories for a
  rule that does not tell a regular expression from a division.
- **Java files with a unicode escape that changes the file's structure are not fully
  evaluated (R6-E7b).** Java translates unicode escapes before it parses a file, so
  an escape can end a comment, a string or a character literal, and what follows is
  then code that the analyzers, which read the text as written, take for a comment.
  A Java file that holds, anywhere, a unicode escape (one or more `u`, four hex digits
  in either case, the backslash not itself escaped by an odd run of backslashes)
  that translates to a line break, a quote, a backslash, a slash or an asterisk is now
  lost evaluation for Semgrep (`<k> not parsed by semgrep`) and textscan (`<k>
  unreadable (<path> (unicode escape))`): the scan reads incomplete, findings kept.
  The rule follows the language specification (section 3.3) and was proved against a
  real JDK (Temurin 21) before it was written: 36 vectors, each compiled and run, 13
  of which execute a statement that the text-level view takes for a comment.
  **Customer remedy:** write the character itself, or the ordinary Java escape
  (`\n`, `\"`), instead of the unicode escape. **Measured:** none of the 14,172 Java
  files of the 106-repository corpus holds such an escape. An escape for any other
  character is not covered by this rule; on the Semgrep release this build pins, a
  file that spells a name or punctuation that way already reads as partially parsed,
  which is incomplete.
- **A file named as not parsed by two sources is one file.** The engine's own
  per-file check (a foreign source encoding, an identifier written as an escape) and
  Semgrep's report that it could not parse the file both name the file under "not
  parsed"; it is now counted and listed once instead of as two in-scope files.
- **A credential is dropped as a reference only when its own value is one (NEW-E1).**
  The secrets scanner's reference check read the whole line: a credential was not
  reported when anything else on its line carried a secret-manager or key-service
  resource name (for example a link to a project board), so a real credential on such
  a line read as clean. The check now reads the credential's own value and nothing
  else on the line, and a value is a reference only when the **whole value** is a
  well-formed one: an AWS ARN of Secrets Manager, SSM Parameter Store or KMS (the
  partitions `aws`, `aws-cn` and `aws-us-gov`, with a region, a 12-digit account and the
  service's own resource form), an RDS-managed secret name (`rds!db-<uuid>` or
  `rds!cluster-<uuid>`), or a GCP Secret Manager resource name
  (`projects/<id>/secrets/<name>`, optionally with a location and a version). A value
  that only contains one of these, starts like one and carries other text, or has one
  glued to its front is reported as the credential it is. A value that is itself such a
  reference is still not reported as a credential. Credentials that were not reported
  before are now reported, so a scan can find more.
- **Findings from different analyzers on one line merge only when they describe the
  same construct (RC-9).** The cross-analyzer collapse used to fold every finding at
  one `file:line` into the most trusted one, so two different constructs on a line
  (an `eval` and a `require`, in a minified file) became one finding that carried
  one title, one rule and one fingerprint, and that was graded on the evidence of the
  other. Findings now merge only when they describe the same construct (the
  reviewed rule families first, then the CWE ids they cite, then an identical title);
  a finding that none of these identifies is never merged. Different constructs stay
  separate findings, each with its own title, rule, fingerprint and confidence, and
  neither takes the other's confidence or proof. **Fingerprints of constructs that were
  previously merged into another finding appear again**, so a baseline can see them as
  new findings once; same-construct findings (the secrets scanner and Semgrep on one
  hardcoded password) still merge.
- **Occurrences group only with occurrences of the same evidence (RC-9e).** Findings
  that share a title are grouped into one finding with several endpoints. A group's
  status was computed from the whole group (the highest confidence, the union of
  proof), so one file's evidence set the status of every other file's occurrence: a
  `require()` graded MEDIUM blocked because another file's was HIGH, and hundreds of
  test-file passwords blocked because a few production ones did. The group key now
  includes the part of an occurrence's own evidence that decides its status (the
  confidence its analyzer asserted, its proof, its analyzer tier, and whether its file
  is test code or documentation), so each occurrence is reported under the status its
  own evidence earns. Occurrences are also kept apart when the scanner's own judgement of
  their value differs: a fixture-shaped value, a demonstrably synthetic value, a value that
  can be shown real offline, or a provider-signed value, and an imported SARIF result's cross-tool corroboration
  counts only for the occurrence it was found on. A placeholder or synthetic
  credential occurrence therefore never shares a finding, or a status, with a stronger
  one (a sample password in a form's field map is its own finding), and the synthetic and
  offline-provable judgements now also survive correlation in hybrid (`--url` with
  `--code`) scans. **Positional finding ids (`SEC-nnn`) and finding counts change** (a
  group with many test-file occurrences and a few production ones is now two findings);
  **occurrence fingerprints do not.**
- **A credential in documentation is not a deterministic detection unless it can be
  shown real from the file alone (RC-10b).** Documentation shows credentials to be
  read, and a pattern match there is far more often a sample than a secret. A file is
  documentation by its own form and not by a directory name: prose markup (Markdown,
  reStructuredText, AsciiDoc, MDX) anywhere, text files under a docs directory or
  named like documentation (README, CHANGELOG, NOTES), and HTML pages under a docs
  directory that are not in a served root. A deployable file under `docs/` (YAML,
  properties, JSON, scripts, a compose file) and a file named for what it holds
  (`credentials.txt`) are not documentation and keep their weight. A credential in
  documentation no longer earns the deterministic-detection weight unless it can be
  shown real offline: a GitHub token whose checksum is valid, a private key whose body
  parses, or an AWS key id with its secret beside it. Those keep their status (BLOCK
  when otherwise warranted); any other real-format credential there is WARN, and one
  whose value is also demonstrably synthetic (a placeholder, a published example, a
  sequence, a template, or a common sample password such as `password123`) is INFO.
  The finding, its id, severity, endpoint and redacted evidence are kept; only the
  status moves. The synthetic-value classifier and the common-placeholder list now
  apply in every file, not only documentation. A provider token is judged on its own
  value: a value that carries a Slack, npm, Google, GitHub, Stripe, OpenAI, Anthropic
  or AWS key id is classed synthetic only when every token in it is, so a real token
  with a digit run or other junk appended in the same string literal keeps the status
  v3.7.0 gave it (a real Slack, npm or Google key had been lowered from BLOCK to WARN,
  exit 1 to 0, by the judgement of the generic password rule's value), and a provider
  finding that a generic or Semgrep finding at the same place absorbs is never graded
  below what its own value earns, and neither is a real generic value that a sample
  token is folded with: a folded finding is a sample only when every credential it
  covers is one. A sample token keeps its sample status, and a real value beside a
  published sample token (`password = "<real>"; tok = "<sample>"`, or one literal that
  holds both) keeps BLOCK: findings bound to different names are never folded, and a
  credential value is a sample (a published example, a sequence, a repeated or periodic
  body, a template, a placeholder, a common sample password) only when the WHOLE literal
  value is that form: the value is the full string the scanner extracted, quotes
  stripped, not the provider pattern's match, and each of those signals is anchored to
  all of it, so a match on part of a longer value makes nothing synthetic (the
  placeholder-word, repeated-character and short-value signals v3.7.0 already had read
  the value exactly as they did). The only text allowed
  beside a sample form is a closed list: a placeholder word the scanner already lists, a
  template marker, or one run of separators between two such parts. A value with
  anything else in it, of any length (a short password, a real token glued to a sample,
  real characters that continue a sample's own sequence, a separator before or after the
  sample), keeps the status v3.7.0 gave it, so it can BLOCK where the previous release
  candidate warned. A sample token on a line that also holds a credential-named JSON
  member whose whole value is not a sample form or closed-list junk
  (`{"password": "<real>", "tok": "<sample>"}`, which no pattern reads) keeps v3.7.0's
  BLOCK. Which of two otherwise identical findings
  represents a location no longer depends on the order they arrive in.
- **More test-code conventions are recognised, in Go and Python together (RC-10 (a)).**
  The path convention for test code (`models.IsTestPath` and the Python analyzer's
  `_is_test_path`, kept in lockstep and pinned by one shared vector file) used to know
  only `test/`, `tests/`, `testing`, `conftest`, Python `test_*.py` and `*_test.py` and
  `fixtures/`, so JavaScript, TypeScript, Go and JVM test code arrived at full severity.
  It now also recognises fixture, mock, spec, e2e, cypress and testdata directories; the
  JavaScript and TypeScript `__tests__`, `__mocks__` and `__fixtures__` directories and
  test-utils helpers; `*.test`, `*.spec`, `*.cy` and `*.e2e` script files; Go
  `*_test.go`; Ruby `*_spec.rb` and `*_test.rb`; and the JVM `*Test`, `*Tests`, `*IT`
  and `*ITCase` classes and `Test<Name>` helpers. A name must be a whole path segment
  (or the file suffix itself), so `specification`, `mockups` and `Testimonial` are
  code. This remains a demotion by path and never an exclusion: the file is analysed,
  the finding is kept, and the decision layer only holds an uncorroborated one at WARN
  (`--deescalate-tests`); a vulnerable handler placed under such a directory stays
  visible but cannot block a confidence-gated scan. The owner decision that was open
  for this demotion is closed: kept, and extended.
- **`SEC-JS_EVAL` grades a real `eval` HIGH and reports every other `eval(` at reduced
  confidence, never not at all (E-1, OR-88), and the Python engine records an
  escaped-identifier file as lost.** The Python engine's JavaScript `eval` check used
  to match the text `eval(` on every line, so it also fired, at HIGH, in comments,
  strings, template text, regular expressions, Angular's `scope.$eval(...)` and any
  `x.eval(...)` member call, and the collapse let that grade vouch for another rule's
  finding on the line. It now reads the file as tokens, and the tokens decide only the
  **grade**: every line the v3.7.0 pattern `\beval\s*\(` matches is reported. A call a
  complete reading puts in code, bare `eval(` (also `eval (x)`, with a comment or line
  break before the parenthesis), `window.eval(`, `globalThis.eval(`, `self.eval(` and
  `global.eval(`, `eval?.(`, `(0, eval)(` and `(eval)(`, or an identifier that spells
  `eval` through escapes, stays HIGH/HIGH; every other match (the word in a comment, a
  string, template or JSX text or a regular expression, `$eval`, `x.eval(`) that a
  complete reading of the file puts outside code is reported at MEDIUM severity and LOW
  confidence, a WARN under every `--fail-on` that earns no deterministic-detection delta
  and lends no confidence to another finding. **When the lexer gives up** (no reading of
  the file completes, its budget is spent, or it crashes) it has decided nothing, and every
  match of the old pattern is reported at HIGH/HIGH as before: a doubt reports, and a
  budget an adversary can exhaust is no way to lower a BLOCK. Its id, rule id and title are the confirmed finding's, so
  no fingerprint or baseline entry moves, and its `fix` text says the call could not be
  confirmed. This replaces a recogniser that decided whether a site was reported at all:
  two rounds of independent verification found eleven shapes (an HTML-like comment, a
  hashbang ended by U+2028, a division after a function or class expression, a regular
  expression after `extends`, `default` or `for await`, `</`, JSX text with an apostrophe,
  a URL or a backtick) that made it read executed code as text and drop the call, a
  regression from v3.7.0 that scanned clean. Now each is at least a WARN; the accepted
  residual is that crafted syntax that makes a complete reading wrong can lower a v3.7.0
  BLOCK `eval` to a WARN. **A call in
  one of the newly matched forms whose only argument is a plain string literal, or a
  template literal with no substitution, is not reported** (a constant, nothing to inject;
  the newly matched forms and this exemption sit on top of the floor and never touch a
  site the old pattern matched); a plain `eval(` is reported whatever its argument, as
  before. Where a construct has two readings (a `/` that may start a regular expression or
  divide, a `<!--` or `-->` that may be a comment), both are followed and an `eval` that
  any complete reading puts in code is confirmed. Measured on 95,000 generated programs
  with V8 as ground truth, no executed `eval` call is without a finding. The check reads
  `.js .jsx .mjs .cjs .ts .tsx .mts .cts`; an `eval` in `.es6` or `.vue` is reported by
  textscan alone and, with RC-9e, warns. A lexer that raises (this one or the
  identifier-escape lexer) makes the file lost evaluation instead of aborting the walk.
  `python-engine/injection` also records a JavaScript or TypeScript file with an
  escaped identifier as lost evaluation (see the JavaScript item above).
  **`eval` of a non-literal still blocks at HIGH/HIGH where textscan and the Python
  engine both report the same real `eval`** (owner decision D20, approved with this
  release note); the word `eval` in a comment, a string or `$eval` no longer lends its
  grade to anything.
- **A path-traversal guard is recognised by what a project helper does, and lowers a finding to a WARN, never removes it (RC-11 G, OR-88).** A
  reachable path-traversal finding used to block correctly guarded code when the guard
  was a project-local helper (`if not _path_is_within(base, target): return` inside a
  `try`), because the analyzer looked for a guard only among a function's top-level
  statements and accepted only an inline `realpath` and `commonpath` against a
  constant base. A helper now counts by its body and never by its name: it must resolve
  both sides (`realpath` or `Path.resolve`, never `abspath`) and test containment
  separator-safely (`commonpath` equality, `startswith` with a separator,
  `is_relative_to`, or `relative_to` in a `try`). The guard must dominate the sink on
  every path, check the value that reaches the sink, check it against the base the path
  was built from (or a narrower one), and not take that base from request input; a
  helper the module rebinds (`_path_is_within = lambda *a: True`), a module that
  patches `os`, `os.path` or `pathlib`, a module with a `from m import *`, and a helper
  with a parameter named like a name its module imports (`realpath`) are no guard;
  anything else keeps reporting. **A sink a recognised guard covers is reported, not
  dropped:** the recognisers may lower a finding, never remove it, because a recogniser
  that can be fooled (a guard rebound through `setattr`, `globals()` or `exec`, patched
  from another module, rooted at a parent directory or at a symlink) turned a
  vulnerable package into a clean scan in the first release candidates. Such a sink is
  reported as `Potential unsafe dynamic filesystem path` at MEDIUM severity and
  MEDIUM confidence with no taint chain, a WARN that never blocks, and its `fix` text
  starts `A path-containment guard (<the guard>, line N) covers this path`; a sink no
  guard is recognised for is reported exactly as before. The finding appears where the
  unguarded code would have been reported, so a safe package with a correct guard now
  shows a WARN where it used to show nothing. Measured at engine level on 164 packages
  (the 52 adversarial packages, 23 hold-outs, and the independent verifier's 50 and 39
  decoys and controls, each judged by a runtime oracle that tries hostile inputs against
  a real directory tree): vulnerable or conditional packages with no finding fall from
  24 to 2 (the two v3.7.0 never reported either); vulnerable packages that block
  stay or rise (90 to 92); safe packages that block stay 9 of 46 (6 of 27 and 0 of 7 on
  the two original sets). `scanning/validators.py:701` of this repository is now a WARN
  naming `_path_is_within`.
- **Django's `conditional_escape` is an HTML escaper (G1.7-U, commit `6ae2418`).** The
  sanitiser typing by sink class that is described under "Python sanitisers count only
  for the sink they protect" lists `django.utils.html.conditional_escape` as an HTML
  escaper, so `mark_safe(f'<pre>{value}</pre>')` after `value` went through
  `conditional_escape` is no longer reported as an XSS sink (v3.7.0 matched the escape
  only by a name list that did not hold it, and warned). Like `html.escape`, it is
  treated as protecting every HTML context, an unquoted attribute and a `javascript:`
  URL included, so it does not protect those; a `mark_safe` with no escape, or with
  request input, is still reported (`WARN` and `BLOCK` respectively).
- **The finding-decision policy version stays `1.0.0` in this build.** RC-9, RC-9e,
  RC-10 and RC-10b change which status some findings earn, which would normally be a
  bump of `decision.PolicyVersion` and of `metadata.policy_version`. The managed-CI
  contract records the finding policy version of the producer, so the bump is held for
  the owner's decision on that contract; until it is taken this build reports `1.0.0`
  and `docs/DECISION_POLICY.md` describes the behaviour it has. The report schema does
  not change.

### Added

- **A language and framework support matrix, and a scope rule for accuracy figures.** `README.md`, `docs/accuracy.md` and `BENCHMARKS.md` now list, for the nine parity frameworks, which vulnerability classes are covered, whether a proven flow blocks, and which rows need Semgrep (every non-Python row), with blind-holdout recall beside the development-corpus figures. `scripts/check-public-claims.sh` now fails an `F1`, precision, recall or percentage accuracy figure in `README.md` or `docs/` that names no language or corpus in its sentence; existing unscoped figures in `docs/accuracy.md`, `docs/benchmarks.md`, ADR-011 and two triage reports were scoped.
- **The secrets scanner detects passwords embedded in JDBC URLs.**
  `DB_CONNECTION_STRING` gains a second shape under the same rule id (no
  existing fingerprint moves): `jdbc:postgresql://h/app?user=u&password=...`
  and `jdbc:sqlserver://h:1433;databaseName=a;user=u;password=...`. Evidence
  keeps the URL readable and redacts the password only. As first written the
  redaction stopped at the first `;`, `&`, quote or space, so the rest of a
  braced, quoted or spaced password stayed in evidence and SARIF; it now covers
  the whole value (see "Connection-string passwords are redacted to the end of
  their property" under Security). An interpolated
  `password=${DB_PASSWORD}` does not fire, and a placeholder such as
  `password=changeme` is reported and marked a placeholder, as for any other
  secret. As first written the scanner read only files whose extension was on
  a list that did not include `.properties`; it now reads every text file, so
  a `.properties` file is scanned (see "The secrets scanner reads every text
  file and every line" under Security).
- **Java password hashing is reported apart from general MD5 use.** A new
  textscan rule `JAVA_WEAK_HASH_PASSWORD` (CWE-916, `crypto`, HIGH) fires when
  a password-named value (`password`, `userPassword`, `pwd`, `passphrase`) is
  passed to `digest()` or `update()` of a MessageDigest-style receiver (`md`,
  `md5`, `sha1`, `digest`, `messageDigest` or a `MessageDigest.getInstance(...)`
  chain) in a file that asks for an MD5 or SHA-1 `MessageDigest`, as `GO_WEAK_HASH_PASSWORD` does in Go. `JAVA_WEAK_CRYPTO` is
  unchanged (MD5/SHA-1 anywhere, MEDIUM), so an MD5 ETag still gets that
  hygiene note but is no longer counted as a weak password hash by the parity
  harness. The catalog contract lists the new check.
- **The security catalog now lists the Python engine's AST and JavaScript
  pattern checks.** `docs/security-catalog-contract.json` gains the 16 Python
  AST checks (`python.ast/PY_SQL_INJECTION`, `python.ast/PY_SSRF`,
  `python.ast/PY_PATH_TRAVERSAL` and the rest) and the four
  JavaScript/TypeScript pattern checks (`SEC-JS_EVAL`, `SEC-JS_INNER_HTML`,
  `SEC-JS_DOCUMENT_WRITE`, `SEC-JS_SQL_TEMPLATE`), under the
  `python-engine/injection` analyzer: 20 checks more than the 85 of v3.6.4.
  Later entries add more; the catalog's size at this release, and how it is
  counted, is under "The security catalog count" in Security below. The
  engine's spec-parser checks (`SEC-SPEC-*`) are not catalogued yet. As
  for every other analyzer, each check's `id` is the `rule_id` its findings
  carry, and its `finding_id` is the finding's own id
  (`SEC-PY_SQL_INJECTION`, `SEC-JS_SQL_TEMPLATE`).
  - **Severity and confidence.** `default_severity` is the severity the
    analyzer declares for an unproven finding, before any escalation on a
    proven flow (`python.ast/PY_PATH_TRAVERSAL`: MEDIUM, HIGH when proven).
    `confidence` is the confidence that unproven finding carries. The
    engine's confidence cap then applies, as it does for Semgrep checks:
    MEDIUM confidence caps severity at HIGH. So an unproven
    `python.ast/PY_SQL_INJECTION`, listed as CRITICAL with MEDIUM confidence,
    reports HIGH.
  - Detection does not change.
- **A Python route handler's parameters are now request sources.** FastAPI
  query, path, header, cookie, form and body parameters, and Flask and Django
  URL variables, reach a handler without any `request.` expression, so a sink
  they reached was reported but never proven. FastAPI was hit hardest: the
  same f-string SQL query blocked in Flask and only warned in FastAPI. The
  engine now treats such a parameter as request input where it enters, at the
  handler's `def` line. A finding it reaches is marked reachable and carries a
  taint chain that starts with the parameter's name. Like any proven finding,
  it takes the rule's proven title and severity where it has one, the engine
  escalates it one level as reachable, and it may now block.
  - **Only route handlers.** A parameter counts only in the def a Flask or
    FastAPI route decorator sits on, or in the module-level view a Django
    `path()`, `re_path()` or `url()` names.
    - The view's module is resolved through the urlconf's imports
      (`from app.views import a; path("x/", a.search)` is `app/views/a.py`).
      One re-export hop is followed when that module does not define the
      view itself: `from .items import show` (with `as`) or
      `from .items import *` in the module, or in its `__init__.py` for a
      package.
    - When no scanned file is the resolved module because the scan root is
      inside the package (scanning `app/` for `app.views`), the scanned
      module `views` stands in for it. This needs two things: the module it
      stands in for is a proper trailing suffix, and the prefix that suffix
      drops (`app`) is the directories the scan root sits in. Nothing stands
      in for a view whose head no import binds (`self.handler`, a local
      variable), or for a module of a package outside the scan
      (`from django.views.static import serve`). Such a route binds no
      function, so a project function that only shares the view's name is
      never treated as the view.
    - A decorator route's first argument must start with `/` (or be `""`,
      which FastAPI allows under a prefixed router), and a `unittest.mock`
      or `mock` receiver is never a route, so `@mock.patch("os.getenv")` is
      not a PATCH route.
    - Parameters of any other function are not sources.
  - **Flask, Quart, Sanic and Django pass only the URL variables their
    pattern names.** Such a view's parameter is a source only when one of its
    routes' patterns names it:
    - `<x>`, or `<path:x>` (Sanic writes `<x:str>`; the word that is a
      parameter of the handler is the name);
    - a regex group `(?P<x>...)`;
    - for a Django regex with no named group, the unnamed groups, in order
      after `request`.

    Values the developer sets are not sources: a plain default
    (`def report(fmt="pdf")` on `/report`), a Flask `defaults=` value, and a
    Django urlconf extra-kwargs value. The request object is never a source
    either, because no URL pattern names it.
    - FastAPI and Django Ninja read a parameter the path does not name from
      the query string, so every parameter of theirs that the rules below
      leave is a source.
    - A decorator route's framework is decided in this order:
      1. the file's imports: `fastapi`, `starlette` or `ninja` mean FastAPI,
         and `flask`, `quart` or `sanic` mean Flask;
      2. its pattern: `{x}` means FastAPI, `<x>` means Flask;
      3. `.route(...)`, which is Flask's;
      4. the framework most of the project's files import, so a blueprint
         file that imports only its blueprint takes the project's Flask.

      A route that none of these places, including one in a project whose
      files import no framework or import two equally often, is treated as
      FastAPI, as before.
  - **Dependencies and injected objects are not sources:**
    - `self`, and a first positional parameter named `request` or `req`;
    - a parameter annotated `Request`, `Response`, `BackgroundTasks`,
      `WebSocket`, `HTTPConnection` or `Session`;
    - a parameter defaulted to `Depends(...)` or `Security(...)`, or
      annotated `Annotated[..., Depends(...)]`;
    - a parameter annotated with a module-level alias of such a dependency
      in the same file (`CurrentUser = Annotated[User, Depends(get_current_user)]`);
    - a parameter annotated with a type imported from a module with a `deps`
      or `dependencies` path segment, by name
      (`from app.api.deps import CurrentUser`, `from .deps import SessionDep as S`)
      or through the module (`from app.api import deps`, then
      `deps.CurrentUser`);
    - `*args` and `**kwargs`.

    Annotations are recognised bare, under `Optional[...]`/`X | None`, or as
    the first argument of `Annotated[...]`. A type imported from any other
    module (`from app.models import User`) stays a source.
  - **Fixed-value types are not sources.** FastAPI and pydantic validate
    these before the handler runs, so the value cannot carry free text:
    - `int`, `float`, `bool`, `UUID`, `datetime`, `date`, `time`,
      `timedelta` and `Decimal`;
    - the pydantic constrained numbers `conint(...)`, `confloat(...)`,
      `condecimal(...)`, `PositiveInt`, `NegativeInt`, `NonNegativeInt`,
      `NonPositiveInt`, `PositiveFloat`, `NegativeFloat`,
      `NonNegativeFloat`, `NonPositiveFloat`, `StrictInt`, `StrictFloat`
      and `StrictBool`;
    - `Literal[...]`, the safe way to accept a dynamic `ORDER BY` direction;
    - an Enum class defined in the same file, with a base of `Enum`,
      `IntEnum` or `StrEnum` or of another such class
      (`class Sort(str, Enum)`);
    - a container of these: `list[int]`, `set[UUID]`, `tuple[int, ...]`,
      `list[Sort]`.

    Each counts bare, under `Optional[...]`/`X | None`, or as the first
    argument of `Annotated[...]`. Flask `<int:...>`, `<float:...>` and
    `<uuid:...>` and Django `<int:...>` and `<uuid:...>` URL variables are
    coerced the same way. A variable that another of the view's routes passes
    as a string stays a source.

    These stay sources: `str`, `list[str]`, a regex-constrained string
    (`constr(pattern=...)`, `Path(pattern=...)`, a Django regex group), a
    pydantic model, an Enum imported from another module, an unannotated
    parameter, and the `path` converter.
  - **Sanitisers apply as they do to a `request.args` value.** A sanitiser
    leaves the finding unreported or unproven exactly as it would for a value
    read from the request, and only for the sink class it protects: escaping
    for HTML sinks, a constant `urlparse(...).netloc` allowlist for a whole
    URL, path containment for path sinks, `shlex.quote` for shell sinks; a
    constant allowlist lookup or membership guard for any class. As first
    written any of them counted for every sink, so `html.escape` or `quote`
    hid SSRF and open redirect, and `basename` hid command injection (see
    "Python sanitisers count only for the sink they protect" under Security).
  - **Route parameters and safe downloads.** With route parameters as
    sources, Flask's `send_from_directory(<constant dir>, <path:filename>)`
    and joins whose request part is reduced by `basename` or
    `secure_filename` were proven and blocked, though Werkzeug's `safe_join`
    and the reduction contain them. They no longer are (see "Safe Python
    download idioms no longer block" under Security).
  - **Same-file helpers.** A handler that passes its parameter to a helper in
    the same file proves the helper's sink, through the one-hop check. The
    chain starts at the handler's `def` line, then the call. Caller-side
    sanitisers still apply. A helper in another module is followed too, one
    hop (see "A Python sink in a helper is now proven when a view in another
    module passes it request input" below).
  - **Identity.** A finding this change proves can change identity once. A
    baseline entry or a `.fendix-ignore` `fingerprint:` rule for it stops
    matching, and it is reported as new once.
    - The command-injection rules (`python.ast/PY_OS_SYSTEM`,
      `python.ast/PY_OS_POPEN`, `python.ast/PY_SUBPROCESS_SHELL`) and
      `python.ast/PY_SQL_INJECTION` name their sink only when the flow is
      proven, so such a finding is identified by its sink instead of its
      evidence line.
    - A proven finding bound to a route is identified by the route's file.
      A Flask or FastAPI route is declared in the handler's own file, so
      nothing moves. A Django route is declared in the urlconf, so a Django
      view's finding that this change proves through a URL variable is
      identified by the urlconf's file instead of the view's, whatever the
      rule.
    - Otherwise SSRF, open-redirect, path-traversal and XSS findings keep
      their identity.
  - **New findings where a sink is reported only when proven.** A handler
    parameter reaching `os.path.join(...)` (or `abspath`, `expanduser`,
    `expandvars`) or an LLM prompt now reports it. So
    `open(os.path.join(BASE, filename))` in a FastAPI handler reports both
    calls, and `FileResponse(os.path.join(BASE, filename))` is now reported
    through the join. `FileResponse(path)` itself is still not a sink.
  - **A route binds only the function it was declared for.** The route table
    is keyed on the bare function name, project-wide. A function that only
    shared a handler's name, in another file or as a method, got that
    handler's route, and Django views with one name in several modules all
    got the first one's route. Each finding now carries its own view's route,
    or none. A finding whose route changes is identified by its new route's
    file, or by its own file when it has none, once.
  - **Not covered:**
    - routes registered without a route decorator or a urlconf entry:
      `app.add_api_route(...)`, `app.add_url_rule(...)` and class-based
      views;
    - a view wrapped in the urlconf, as in
      `path("x/", login_required(views.show))`;
    - a re-export chain longer than one hop.
  - **Framework parity:** FastAPI's `direct`, `indirect` and `alt_api` cases
    for SQL injection, command injection and SSRF, its `direct` and
    `indirect` path-traversal cases and its `alt_api` XSS case now block, and
    its `alt_api` path-traversal case is detected and blocks. FastAPI blocks on
    17 of 36 vulnerable cases, up from 4. No development-corpus safe case is flagged or blocks.
- **Python HTML responses are now XSS sinks.** `HttpResponse(f"<h1>{name}</h1>")`
  writes request input into a page with no template, so nothing escapes it,
  and it was not reported. The engine now reports request text reaching the
  body of an HTML response constructor, under the existing
  `python.ast/PY_XSS_HTML_SINK` rule: Django `HttpResponse`, Flask
  `make_response` and `Response`, and Starlette and FastAPI `HTMLResponse` and
  `Response`. As for `Markup` and `mark_safe`, a proven flow is marked
  reachable, carries a taint chain and may block; an unproven one is reported
  and does not block.
  - **Only an HTML response.** A response whose content type is provably not
    a document the browser renders is not a sink.
    - The type can be declared with `content_type=`, `mimetype=` or
      `media_type=`, by position (Django's `HttpResponse(body, "text/plain")`,
      Flask's and Starlette's `Response(body, 200, None, "application/json")`),
      or as a `Content-Type` entry in a literal headers dict or list of pairs,
      including Flask's `make_response(body, status, headers)` and
      `make_response((body, status, headers))`.
    - It can also be assigned after construction, when the response is bound
      to a name: `resp["Content-Type"] = ...` (Django),
      `resp.headers["Content-Type"] = ...` (Flask, Starlette), or
      `resp.mimetype`, `resp.content_type` or `resp.media_type`.
      - Such an assignment decides by itself, whatever the constructor
        declared, and the last one wins.
      - Only the statements after the binding in the same block count. The
        scan stops where the name is bound again, or at a statement that
        returns or yields, since the response may already have left.
      - An assignment inside a branch, loop, `with` or `try` may not run, so
        it makes the type unknown, which counts as HTML.
    - A type containing `html` or `xml` (`text/html; charset=utf-8`,
      `application/xhtml+xml`, `image/svg+xml`) is HTML. So is a type held in
      a variable, and an empty type. `None` is a type not given.
    - With no type declared, Django and Flask send `text/html`, and a
      Starlette `Response` sends no `Content-Type`, so the browser sniffs the
      body. All three are sinks. `HTMLResponse` is always one.
    - A 204 or 304 response is not a sink, because the browser renders no
      body for it (Werkzeug drops it). Neither is a redirect (301, 302, 303,
      307 or 308) with a `Location` entry in a literal headers dict or list
      of pairs, because the browser follows it instead of rendering the body.
      The redirect status must be an int or an imported status constant
      (`HTTPStatus.FOUND`, `http.HTTPStatus.SEE_OTHER`, or `HTTP_302_FOUND`
      from `starlette.status`, `fastapi.status` or `rest_framework.status`);
      a local name such as `FOUND = 200` is not one. A redirect status
      without a `Location` header, or a `Location` header without a redirect
      status, is still a sink.
  - **Only a framework's constructor.** An imported constructor must come
    from its framework: `HttpResponse` from Django, `make_response` from
    Flask, `HTMLResponse` from Starlette or FastAPI, and `Response` from
    Flask, Werkzeug, Starlette or FastAPI.
    - An imported alias resolves to what it imports, so
      `from flask import make_response as mk` makes `mk(...)` a sink.
    - A project's own function or class is not a sink, even when it shares
      the name:
      - one the file defines (`def make_response(message): ...`);
      - one it imports from the project (`from .utils import make_response`);
      - a method on `self` or `cls`.
    - A `Response` must be imported, so Django REST framework's `Response`,
      which renders JSON, is not a sink either.
    - A constructor called by a bare name the file neither imports nor
      defines still counts, and so does Flask's `app.make_response(...)`.
  - **Not reported:**
    - an escaped, allowlisted or membership-guarded value, as for `Markup`;
    - Django's `render(...)` and `render_to_string(...)` and Flask's
      `render_template(...)`, imported from their frameworks, which render
      autoescaped templates, and Flask's `jsonify(...)`, which sends JSON.
      - `.render(...)` on a Django template object is not reported either.
        That covers `loader.get_template(...)`, `select_template(...)`,
        `django.template.Template(...)`, and `engines[...]` with its
        `from_string`/`get_template` (Django's Jinja2 backend autoescapes),
        directly or through a variable.
      - Flask's `render_template` of a template whose constant name does not
        end in `.html`, `.htm`, `.xml`, `.xhtml` or `.svg` (`"mail.txt"`) is
        not autoescaped, so it is reported.
      - A function of the same name that the file defines is not a renderer.
      - `.render(...)` on a raw Jinja2 or Mako template is not a renderer
        either: neither autoescapes by default. Raw Jinja2 means
        `jinja2.Template`, or an `Environment`'s `from_string`/`get_template`.
        So `HttpResponse(Template(src).render(name=name))` is reported when
        `name` is request input. A template whose own source is request
        input is reported as template injection (`python.ast/PY_SSTI`,
        below), not as XSS;
    - Flask's `make_response(...)` of a dict or list, which Flask sends as
      JSON: a literal, a comprehension, a `.split()`, `.rsplit()` or
      `.splitlines()` list, request data read whole (`request.get_json()`,
      `request.json`, `request.args`, `request.form`,
      `request.args.to_dict()`, `request.form.getlist(...)`), or a name every
      assignment of which is one of these. A name assigned text in any branch,
      before or after its other assignments, stays text;
    - Flask's `make_response(...)` of a response object, which Flask sends as
      it is (`make_response(Response(...))`);
    - a body that is, as a whole, the result of a helper function, of a
      `self`/`cls` method, or of a method on a value that is not a string
      method, such as `build_page(name)`, `storage.download(path)`,
      `settings.get_sp_metadata()`, or `email_data.html_content` with
      `email_data = generate_reset_password_email(email=email)`. The engine
      cannot see what a function returns, and a function that returns the
      whole page is usually a renderer that escapes.
      - A method on the request's own data is not a helper: its receiver,
        followed through attribute and subscript reads, method calls and the
        names it is bound to, starts at `request`, or at a route handler's
        request parameter. So `HttpResponse(request.FILES["f"].read())`,
        `up = request.FILES.get("f")` then `HttpResponse(up.read())`, and
        `make_response(request.files["f"].read())` are reported.
      - Inside an interpolated part, a call carries its arguments' text, so
        `f"<div>{build(name)}</div>"` is reported. An interpolated part is an
        f-string value, a `+` or `%` operand, or a `.format` or `.join`
        argument.
      - A class constructor carries its arguments' text anywhere, so
        `form = NameForm(request.POST)` then `form.cleaned_data["name"]` is
        reported.
      - String methods (`.format`, `.join`, `.strip`, `.replace`, `.encode`,
        `.split`, `.rsplit`, `.splitlines`, `.partition`, `.rpartition` and
        the rest of `str`'s that return text), a mapping's `.get`, a raw
        template's `.render`, `str()`, `json.dumps`, `json.loads`,
        `textwrap.dedent`, `urllib.parse.unquote` and `unquote_plus`,
        `html.unescape` and `map` pass text through. So
        `HttpResponse(name.split(",")[0])` is reported.
      - These hold no text:
        - `int()`, `float()`, `bool()`, `len()`, `round()` and `abs()`;
        - `uuid.UUID`, `decimal.Decimal` and `fractions.Fraction`;
        - `fromisoformat`/`strptime` on `date`, `datetime` and `time`;
        - a comparison (`q == "x"`) or a `not`;
        - a `str` test that returns a bool, on any value: `.isdigit()`,
          `.isalpha()`, `.isalnum()` and the other `.is...()` tests,
          `.startswith()` and `.endswith()`;
        - `.count()`, `.find()`, `.rfind()`, `.index()` and `.rindex()`, but
          only on a value known to be a `str`: a str literal, an f-string,
          `str()`, the result of a `str` method that returns a `str`, a query
          or form value read off the request (`request.args`, `.form`,
          `.values`, `.GET` or `.POST`, by `.get(...)` or subscript; not files,
          JSON or the raw body), a Flask or Django URL variable, a FastAPI
          parameter annotated `str`, or a name every assignment of which is one
          of these. On any other value they carry text: an XML element's or a
          BeautifulSoup tree's `.find()` returns markup, so
          `f"<p>{root.find('name').text}</p>"` is reported;
        - a request value Werkzeug converts with `type=`:
          `request.args.get("page", 1, type=int)`, and `float`, `bool` or a
          value parser such as `uuid.UUID`. The converted value, or the
          default when conversion fails, is what the body holds, so a text
          default still counts.
  - **`json.dumps` is not an escape.** `HttpResponse(json.dumps(data))` with
    no content type is `text/html`, and `json.dumps` leaves `<` as it is, so
    request data in it is reported. With `content_type="application/json"` it
    is not.
  - **One finding per flow.** `make_response(Markup(x))` is reported once, by
    the `Markup` finding it already had, and `make_response(Response(x))` once,
    by the `Response` finding.
  - **Identity.** Existing `python.ast/PY_XSS_HTML_SINK` findings keep their
    fingerprints. The new findings are new. Their sink is the constructor and
    its body, as in `HttpResponse(f'<h1>{name}</h1>')`.
  - **Not covered:**
    - a helper function whose result is the whole body and that builds the
      HTML unescaped, as in `HttpResponse(build_page(name))`;
    - Django's other response classes, such as `HttpResponseBadRequest(...)`;
    - a content type set after construction other than by assigning to the
      bound name (`resp.headers.update(...)`, `resp.headers.set(...)`). Such a
      call is ignored, so the constructor's own type decides;
    - a media type passed to `HTMLResponse`, which is ignored.
  - **Framework parity:** the Django, Flask and FastAPI `direct` and
    `indirect` XSS cases are now detected and block, and their `cross_file`
    cases are detected and warn. No development-corpus safe case is flagged. The Python
    frameworks detect 93 of 108 vulnerable cases, up from 84, and block on
    64, up from 58.
- **A string a Flask view returns is now an XSS sink.** Flask sends a `str` a
  view returns as `text/html`, so `return f"<p>{request.args['q']}</p>"`
  writes request input into a page that nothing escapes, and it was not
  reported. The engine now judges a Flask or Quart view's return value as the
  response Flask builds from it, `make_response(value)`, under the existing
  `python.ast/PY_XSS_HTML_SINK` rule and with the same rules as
  `make_response(...)`: escaping, allowlists, autoescaped templates,
  `jsonify`, `json.dumps`, helper results and values that hold no text. A
  FastAPI route whose response class is HTML is judged the same way (below).
  - **Only a proven flow.** A returned string is reported only when request
    input is proven to reach it. The finding is marked reachable, carries a
    taint chain and may block. Every view returns something, so a string built
    from a value the engine cannot trace to the request (a database read, an
    exception's text, a constant) is not reported, not even as a warning.
  - **Only a Flask route's own returns.** The function must be the handler of
    a route whose framework is Flask, decided as for route parameters (the
    file's imports, which count Quart and Sanic as Flask, then the pattern,
    `.route(...)` and the project's dominant framework). These are not sinks:
    - a return in a def, lambda or class nested in the view, or in a helper
      that no route points at;
    - a return in a view that yields, which streams what it yields;
    - a Django view's (Django needs an `HttpResponse`), and a route whose
      framework is unknown;
    - a FastAPI or Django Ninja return under the default response class,
      which sends it as JSON, or under `PlainTextResponse`, `JSONResponse` or
      another class that is not HTML.
  - **FastAPI routes that render HTML.** A FastAPI route whose response class
    is `HTMLResponse`, or Starlette's `Response`, which sends no Content-Type
    for the browser to sniff, sends a returned `str` as the page. Its returns
    are sinks, judged as `HTMLResponse(value)`. Only a proven flow is
    reported, as for Flask.
    - The class is the route decorator's `response_class=`, else the
      `default_response_class=` of the `FastAPI(...)` or `APIRouter(...)` the
      decorator is called on, when this file binds it once at module level.
      A decorator's class overrides the default.
    - A returned response object (`JSONResponse(...)`) is sent as it is, and a
      dict, list or tuple cannot be rendered as HTML, so none of them is a
      sink.
  - **Not reported:**
    - a dict or list, which Flask sends as JSON: a literal, a comprehension,
      a `.split()` list, request data read whole (`request.get_json()`,
      `request.json`, `request.args`, `request.args.to_dict()`,
      `request.form.getlist(...)`), or a name every assignment of which is
      one of these;
    - a response object (`Response(...)`, `make_response(...)`,
      `redirect(...)`, `send_file(...)`, `app.send_static_file(...)`), a
      template (`render_template("page.html", ...)`) or `jsonify(...)`;
    - an escaped value, such as `escape(q)` or `f"<p>{escape(q)}</p>"`;
    - a value that holds no text, such as `request.args.get("page", 1,
      type=int)` or `f"<p>{q.isdigit()}</p>"`.
  - **Tuples.** A returned `(body, status)`, `(body, headers)` or
    `(body, status, headers)` is checked on its body. It is not a sink when a
    literal headers dict or list of pairs declares a `Content-Type` that is not
    HTML (`{"Content-Type": "application/json"}`), when the status is 204 or
    304, or when it is a redirect with a literal `Location` header
    (`return "Moved", 302, {"Location": "/x"}`).
  - **One finding per flow.** `return make_response(f"...")`,
    `return Response(f"...")` and `return Markup(...)` are reported once, by
    the constructor's own finding.
  - **Identity.** Existing findings keep their fingerprints. The new findings
    are new. Their sink is `return` and the body, as in
    `return f'<p>{q}</p>'`, so adding a status or headers to the returned
    tuple does not re-identify one.
  - **Not covered:**
    - a helper that builds the HTML and returns it to the view, as in
      `return render_page(q)`;
    - a headers dict held in a variable (`return body, 200, headers`), which
      counts as HTML;
    - a content type set elsewhere, such as in an `@app.after_request` hook
      or by a custom Flask `response_class`;
    - a FastAPI response class set on `app.include_router(...)`, on a router
      or app from another file, or through a subclass of `HTMLResponse`;
    - a view registered with `app.add_url_rule(...)`, such as a class-based
      `MethodView`, which is not read as a route.
  - **Framework parity:** no corpus case returns a string from a view, so the
    parity results do not change.
- **Server-side template injection is now detected in Jinja2, Django and Mako
  templates.** A template compiled from request input runs the attacker's
  template code on the server: in Jinja2,
  `{{ cycler.__init__.__globals__.os.popen("id").read() }}` runs a shell
  command. Only Flask's `render_template_string` was reported. The engine now
  reports a template built from a string under a new rule,
  `python.ast/PY_SSTI` (finding id `SEC-PY_SSTI`, CWE-1336, category
  `injection`). Its SARIF results carry a new `ruleId`,
  `fendix.injection.python-ast-py-ssti`.
  - **Sinks.** Each callee is resolved through the file's imports, aliases
    included:
    - `jinja2.Template(src)`, and Jinja2's `NativeTemplate(src)`;
    - `from_string(src)` on a Jinja2 `Environment(...)`, called on the
      constructor directly or on a name the function or module binds to it
      (`env = Environment(...)`). Its subclasses count too:
      `SandboxedEnvironment`, `ImmutableSandboxedEnvironment` and
      `NativeEnvironment`. A sandbox limits what a template can reach, but
      the attacker's template still runs;
    - `django.template.Template(src)`, and `from_string(src)` on a Django
      `engines[...]` backend;
    - `mako.template.Template(src)` and `Template(text=src)`.

    The source may also be passed by keyword (`source=`, `template_string=`,
    `text=`, `template_code=`).
  - **Severity and title.** A flow proven from request input is CRITICAL and
    titled "Template built from request input (server-side template
    injection)". It is marked reachable, carries a taint chain and may block.
    A source the engine cannot trace to the request is reported at HIGH with
    MEDIUM confidence, titled "Template built from a non-constant value
    (possible server-side template injection)", and does not block: a
    helper's parameter that no caller in the file passes request input to, a
    database value, or a configuration value such as a Django setting. The
    title is presentation, so a finding keeps its identity when its flow is
    later proven.
  - **Not reported:**
    - a template loaded by name: `get_template(...)`, Flask's
      `render_template(...)`, a Mako `TemplateLookup`, or
      `Template(filename=...)`;
    - a class that is not one of these, even one named `Template`: a class
      the file defines, one imported from the project
      (`from .templating import Template`), or `string.Template`;
    - a constant source: a literal, a name bound to one, or a concatenation,
      `format`, f-string or conditional of constants;
    - a template picked among constant templates: `TEMPLATES[key]` or
      `TEMPLATES.get(key, DEFAULT)` on a literal dict whose values are
      constants and that the file never changes in place (no
      `TEMPLATES[k] = ...`, `.update(...)` or `.setdefault(...)`), or a name
      that a preceding `if name not in ALLOWED:` guard with an early exit
      keeps inside a literal collection;
    - a template read from the file system: `.read()`, `.read_text()` or
      `.read_bytes()`, decoded or not, on a file opened with `open(...)`,
      `io.open(...)` or `codecs.open(...)` (`with open(path) as fh` too), on
      a pathlib path (`Path(...)`, `/`, `.parent`, `.joinpath(...)`), or on
      an `importlib.resources.files(...)` traversable.
      - The path given to `open(...)` or `Path(...)` is the path-traversal
        rule's concern: a path the request chooses there is still reported,
        and proven, as `python.ast/PY_PATH_TRAVERSAL`.
      - `python.ast/PY_PATH_TRAVERSAL` does not model a pathlib join, so a
        path derived with `/`, `.joinpath(...)`, `.with_name(...)` and the
        like, or an `importlib.resources.files(...)` package, is trusted only
        when no segment it adds is proven request input. With one,
        `(Path("tpl") / request.args["t"]).read_text()` and
        `files("app").joinpath(request.args["t"]).read_text()` are reported,
        and proven, as `PY_SSTI`. A segment that is only a helper's parameter,
        such as the full-stack-fastapi-template email renderer's
        `template_name`, which its callers fill with constants, keeps the
        read trusted;
    - a package resource read by a constant name:
      `pkgutil.get_data("app", "t.html")` or
      `importlib.resources.read_text("app", "t.html")`. A resource name that
      is not constant is reported, since no other rule covers it.

    Any other read can return the request's text and is reported: an
    uploaded file (`request.files["t"].read()`), `urlopen(url).read()`, a
    `requests` response's `.raw.read()`, a zip archive's `.read(...)`, and
    `io.StringIO(...)` or `io.BytesIO(...)` over a value.

    Escaping is not a sanitiser here: `html.escape` leaves `{{ }}` intact.
  - **`render_template_string` keeps its rule.** Flask's
    `render_template_string(src)` is still reported as
    `python.ast/PY_XSS_HTML_SINK`, as before, and never as `PY_SSTI`.
  - **One finding per flow, for the new HTML-response sinks only.** A
    template built from request input and rendered into an HTML response
    (`HTMLResponse(Template(src).render())`, Django `HttpResponse`, Flask
    `make_response` and `Response`), or returned from a Flask view or an
    HTML FastAPI route, is reported once, as `PY_SSTI`. These are the HTML
    response sinks added above in this release. Their XSS finding now
    follows only what `.render(...)` is passed: it is reported when a render
    argument can carry text, as in
    `HTMLResponse(Template(src).render(name=name))`, and proven only when
    that argument is request input. A construction with no template source
    argument, such as `Template(*args)` or Mako's `Template(filename=...)`,
    is neither a sink of this rule nor a template object to these XSS rules,
    which read it as before.
  - **Released XSS sinks are unchanged.** `Markup(...)`, `mark_safe(...)`
    and `render_template_string(...)` keep their
    `python.ast/PY_XSS_HTML_SINK` finding, its proof and its taint chain
    exactly as before. When their argument renders a template built from
    request input, as in `Markup(Template(src).render())`, `PY_SSTI` is
    reported beside that finding.
  - **Helper parameters after `*`.** The one-hop helper check now follows a
    keyword-only parameter (`def render(*, template_name)`) to the callers
    in the file that pass it by keyword, for every rule that proves through
    that check. Before, such a parameter was never proven. A finding inside
    such a helper whose caller passes request input is now proven: it is
    marked reachable, carries a taint chain, takes its rule's proven title
    and severity where it has one, and may now block.
    - **Identity.** A finding this change proves can change identity once. A
      baseline entry or a `.fendix-ignore` `fingerprint:` rule for it stops
      matching, and it is reported as new once.
      - The command-injection rules (`python.ast/PY_OS_SYSTEM`,
        `python.ast/PY_OS_POPEN`, `python.ast/PY_SUBPROCESS_SHELL`) and
        `python.ast/PY_SQL_INJECTION` name their sink only when the flow is
        proven, so such a finding is identified by its sink instead of its
        evidence line. The same holds for any other rule whose sink or
        identity depends on the proof.
      - A proven finding bound to a route is identified by the route's file.
        A Django route is declared in the urlconf, so a Django route-bound
        finding this change proves is identified by the urlconf's file
        instead of the view's.
  - **Imports.** `import a.b` now resolves `a.b.c` to `a.b.c`, as Python
    binds it, wherever the engine reads an import path: this rule, and the
    HTML-response sink's constructors, renderers, value types and redirect
    statuses. It used to read `a.b.b.c`. So
    `django.template.loader.get_template(...).render(...)` after
    `import django.template.loader` is now recognised as Django's
    autoescaped render, and is no longer reported as XSS.
  - **Identity.** Existing findings keep their fingerprints: existing
    `python.ast/PY_XSS_HTML_SINK` findings keep theirs, and `PY_SSTI` may
    appear alongside them. The new findings are new. Their sink names the
    constructor and the source, as in `jinja2.Template(template_src)` or
    `jinja2.Environment.from_string(src)`, whatever the import style.
  - **Catalog.** The security catalog lists `python.ast/PY_SSTI`. (This entry
    used to give a running total of 105 checks. That total was never the
    release's; see "The security catalog count" under Security.)
  - **Not covered:**
    - Flask's `app.jinja_env.from_string(...)`, Starlette's and FastAPI's
      `Jinja2Templates(...).env.from_string(...)`, and Django's
      `Engine(...).from_string(...)`;
    - an environment bound to `self` in another method, or built in another
      file.
  - **Framework parity:** the Django and FastAPI `direct` and `indirect` SSTI
    cases are now detected and block. Flask's are still found by
    `render_template_string` and block, as before. No development-corpus safe case is flagged.
    The Python frameworks detect 97 of 108 vulnerable cases, up from 93, and
    block on 68, up from 64: Django on 24, FastAPI on 21 and Flask on 23.

- **More open redirects are detected: Starlette and FastAPI
  `RedirectResponse`, Django `HttpResponsePermanentRedirect`, and `Location`
  headers.** Only `redirect(...)` and `HttpResponseRedirect(...)` were
  reported. The existing rule, `python.ast/PY_OPEN_REDIRECT`, now covers
  these sinks too:
  - **Redirect constructors.** `RedirectResponse(url)` from Starlette or
    FastAPI and `HttpResponsePermanentRedirect(url)` from Django, beside
    `redirect(url)` and `HttpResponseRedirect(url)`. Each is resolved
    through the file's imports, aliases included
    (`from fastapi.responses import RedirectResponse as Go`), and called by
    name or through its module (`responses.RedirectResponse(url)`). The
    target may also be passed by keyword: `url=`, `location=`, `to=` or
    `redirect_to=`.
  - **`Location` headers.** A `Location` header, matched in any case, on a
    framework response that redirects:
    - in the constructor's headers, as a literal dict, a literal list of
      `(name, value)` pairs, or a name bound to either:
      `Response(status=302, headers={"Location": nxt})`, or Flask's
      `make_response("", 302, {"Location": nxt})`;
    - assigned after construction to a name bound to such a response:
      `resp.headers["Location"] = nxt`, or Django's
      `resp["Location"] = nxt`;
    - in a `(body, status, headers)` tuple returned from a Flask view:
      `return "", 302, {"Location": nxt}`.

    The response is Django's `HttpResponse`, Flask's `make_response` or
    `Response`, Starlette's or FastAPI's `Response` or `HTMLResponse`,
    resolved as for the HTML-response XSS sink, or, for an assignment, a
    redirect constructor (`resp = HttpResponseRedirect("/")`).
    Its status must be a redirect (301, 302, 303, 307 or 308) or a value the
    engine cannot read. A status assigned after construction
    (`resp.status_code = 302`) decides. A response with no status is sent
    with 200, and a `201 Created` names a new resource, so a `Location` on
    either is not reported. A plain dict, such as `headers["Location"] = url`,
    is not a response.
  - **The same checks as `redirect(...)`.** A constant target, `url_for(...)`
    or `reverse(...)`, a lookup in a literal allowlist, a dominating
    membership guard and a dominating `urlparse(url).netloc` allowlist guard
    keep each of these sinks quiet. A target that joins a constant prefix and
    request input, such as `"/" + nxt`, is reported, as it is for
    `redirect(...)`.
  - **Severity and title.** As for `redirect(...)`: HIGH with MEDIUM
    confidence, titled "Open redirect — user-controlled redirect target"
    when the flow from the request is proven, and "Potential open redirect —
    dynamic redirect target" when it is not.
  - **Identity.** Existing `PY_OPEN_REDIRECT` findings keep their
    fingerprints, sinks and evidence. The new constructors name their sink
    `redirect(<target>)`, as `HttpResponseRedirect` does. A `Location`
    header's sink is `Location: <value>` in every form.
  - **A project's own `redirect` is no longer a sink.** A function or class
    named `redirect`, `HttpResponseRedirect`, `HttpResponsePermanentRedirect`
    or `RedirectResponse` that the file defines, or imports from a module
    that is not a web framework (`from app.utils import redirect`,
    `helpers.redirect(url)`), is no longer reported. The engine cannot see
    what such a helper does. A `redirect` imported from Flask, Werkzeug,
    Quart, Django, Bottle, Sanic, TurboGears (`tg`), Pylons, web.py (`web`),
    Morepath or Emmett still counts. So does a bare `redirect` the file
    neither imports nor defines, and a method on another value, such as
    Tornado's `self.redirect(url)`. For example, the four call sites of
    django-allauth's own `redirect(to)` helper in `allauth/account/views.py`
    are no longer reported; the `shortcuts.redirect(to)` inside the helper
    still is.
  - **Not covered:** a `Location` header set through `headers.update(...)`,
    `.setdefault(...)` or another method, or on FastAPI's injected
    `response: Response` parameter; a status given by the route decorator
    (`status_code=302`); a `(body, status, headers)` tuple a helper returns
    for the view to pass on; and other response classes, such as
    `JSONResponse`.
  - **Framework parity:** FastAPI's `direct`, `indirect`, `cross_file` and
    `alt_api` open-redirect cases and Flask's `alt_api` case are now
    detected. All but FastAPI's `cross_file` case block. No development-corpus safe case is
    flagged. The Python frameworks detect 102 of 108 vulnerable cases, up
    from 97, and block on 72, up from 68: Django, FastAPI and Flask each block
    on 24.

- **Starlette and FastAPI `FileResponse(path)` is now a path-traversal
  sink.** `FileResponse` opens and sends the file at `path`, so a path the
  request chooses reads any file the server can. The existing rule,
  `python.ast/PY_PATH_TRAVERSAL`, now reports it beside `open(...)`,
  `Path(...)`, `send_file(...)` and `send_from_directory(...)`.
  - **Resolution.** `FileResponse` must resolve through the file's imports
    to `starlette` or `fastapi` (`from fastapi.responses import
    FileResponse`, an alias, or `responses.FileResponse(path)`). The path may
    also be passed as `path=`. A class the file defines, one imported from
    elsewhere, and a bare `FileResponse` the file never imports are not
    sinks.
  - **Django's `FileResponse` is not a sink itself.** It takes an open file,
    not a path: given a string, it streams the string, not the file. In
    `FileResponse(open(path, "rb"))` the `open(...)` call is the sink and is
    reported once, as before. A Starlette `FileResponse(open(...))` is
    likewise reported only on the `open(...)`.
  - **The same checks as `open(path)`.** A constant path, a path built only
    from constants or trusted sources, `os.path.basename(...)`, and a
    dominating containment guard (`realpath` with `commonpath`, `startswith`
    with a trailing separator, `is_relative_to`, or `relative_to` in a `try`)
    keep it quiet; a sink inside the guard's rejecting branch is still
    reported.
  - **Severity and title.** As for `open(path)`: HIGH, titled "Path
    traversal — user-controlled input reaches filesystem path", when the flow
    from the request is proven; MEDIUM, titled "Potential unsafe dynamic
    filesystem path", when it is not.
  - **Identity.** Existing findings keep their fingerprints. The new
    finding's sink is `FileResponse(<path>)`. An `os.path.join(...)` written
    inside the call keeps its own finding, as it does inside `open(...)`.
  - **Framework parity:** no case outcome changes. FastAPI's `alt_api`
    path-traversal case, `FileResponse(os.path.join(REPORTS_DIR, filename))`,
    was already detected and blocking through the inner `os.path.join`; it
    is now also reported on the `FileResponse` call.

- **A new Semgrep rule, `python-random-token-assignment`, reports the
  `random` module's output assigned to a token-named variable.** Code like
  `token = "".join(random.choices(ALPHABET, k=40))` inside
  `def create(request):` was not reported, because only the enclosing
  function's name was checked. The new rule checks the assignment target
  instead.
  - **What it matches.** The calls are `random.random`, `choice`, `choices`,
    `randint`, `randrange`, `sample`, `shuffle`, `getrandbits` and
    `randbytes`. The target can be a name, an attribute (`self.csrf_token`)
    or a subscript (`user["token"]`), in a function or at module level. One
    of `token`, `password`, `secret`, `nonce`, `salt`, `session`, `otp`,
    `reset`, `csrf`, `api_key` or `access_key` must start a segment of the
    target's name: `reset_code` and `SESSION_SECRET` match, `footprint`
    does not.
  - **One finding per call.** In a function whose name matches
    `python-random-for-token-generation`, the call is that rule's finding and
    the new rule stays silent.
  - **Rating.** The rule is in category `secrets`, CWE-338, HIGH with MEDIUM
    confidence, the same as `python-random-for-token-generation`. Without
    corroboration its findings warn.
  - **Identity.** Its findings are new, with a new SARIF `ruleId`,
    `python-random-token-assignment`. With this rule the Python pack has 23
    rules. For the catalog's size at this release see "The security catalog
    count" under Security.

- **A Python sink in a helper is now proven when a view in another module
  passes it request input.** The one-hop helper check followed a helper's
  parameter only to the calls in the helper's own file. A view that imports
  its helper, as in `from app.services.user_queries import find_users` and
  then `find_users(username)`, left the helper's SQL injection, command
  injection, SSRF, path traversal, open redirect or XSS finding reported but
  unproven, so it only warned. The check now also follows the parameter to
  the calls that name the helper through an import, anywhere in the scanned
  tree.
  - **A proven finding.** It is marked reachable and carries a taint chain.
    The chain's first link is in the caller's file: the call, or the request
    expression when it is passed inline. The helper's own links follow, up
    to the sink. Like any proven finding, it takes the rule's proven title
    and severity where it has one, the engine escalates it one level as
    reachable, and it may now block.
  - **The caller is judged as a same-file caller is.**
    - The request value is traced through the caller's own assignments. For
      each name, the last assignment before the call decides.
    - A route handler's parameters are sources under the same rules as
      everywhere else, so a FastAPI `int` or `Depends(...)` parameter is not
      one.
    - The caller-side sanitisers of the same-file hop apply in the caller's
      file, each only for the helper sink class it protects (see "Python
      sanitisers count only for the sink they protect" under Security): a
      constant membership guard or allowlist lookup for any class; escaping
      for an HTML sink; a constant `urlparse(...).netloc` allowlist or a URL
      with a fixed scheme and host for a URL sink; path containment for a
      path sink; `shlex.quote` for a shell sink; `url_for(...)` or
      `reverse(...)` for HTML, URL and path sinks. Such a sanitiser leaves the
      helper's finding unproven. As first written any of them did, whatever
      the helper's sink.
    - A template built from request input (`Template(request.GET["t"])`)
      passed to a helper that renders it into an HTML response does not prove
      the XSS finding, exactly as in one file: that page is reported as
      `python.ast/PY_SSTI` where the template is built.
    - A caller in test or fixture code (`tests/`, `test_*.py`, `conftest.py`
      and the like) does not count.
  - **Which calls count.** `f(x)`, `m.f(x)` and `a.b.f(x)`, where an import
    binds `f`, `m` or `a`: `from a.b import f` (with or without `as`),
    `import a.b as m`, `import a.b`, or a relative import, resolved against
    the caller's package.
    - Names resolve as Python reads them: an import inside a function binds
      the name for that function only, and the innermost scope that binds
      the name decides. A name that scope binds otherwise (a parameter, an
      assignment, a def) is not the imported function.
    - Only a module-level function is matched. A method, a nested function
      and a class attribute (`m.Store.find(x)`) are not.
    - Arguments are matched as the same-file hop matches them: the positional
      argument at the parameter's index as written, else the keyword of its
      name. A keyword-only parameter is matched by its keyword alone.
  - **Module names.** A module's name is its path under the scan root:
    `app/services/q.py` is `app.services.q`. When the scan root sits above
    the package (`src/app/services/q.py`), an import of `app.services.q`
    still names it, but only when exactly one scanned module ends with
    `app.services.q`. A suffix shorter than two components is never tried.
  - **One hop.** The caller's own parameters are not traced into its
    callers. So `view -> a.helper -> b.sink` proves `a.helper`'s findings,
    not `b.sink`'s. A caller in the helper's own file that proves the flow
    still comes first.
  - **Not followed:**
    - a star import;
    - a helper re-exported by a package's `__init__.py` and imported from
      the package;
    - a scan rooted inside the package, as when scanning `app/` for code that
      imports `app.services.q`;
    - a call inside a lambda, comprehension or class body, unless the
      request value is passed inline;
    - a value read from a datastore, which is a source for the LLM prompt
      sink alone.
  - **Identity.** A finding this change proves can change identity once. A
    baseline entry or a `.fendix-ignore` `fingerprint:` rule for it stops
    matching, and it is reported as new once.
    - The command-injection rules (`python.ast/PY_OS_SYSTEM`,
      `python.ast/PY_OS_POPEN`, `python.ast/PY_SUBPROCESS_SHELL`) and
      `python.ast/PY_SQL_INJECTION` name their sink only when the flow is
      proven, so such a finding is identified by its sink instead of its
      evidence line.
    - SSRF, open-redirect, path-traversal and XSS findings in a helper that
      is not itself a route handler keep their identity: no route binds, so
      the finding stays in the helper's file and function.
    - A helper that is itself a Django view (a urlconf names it too) gets
      that view's route once newly proven, like any proven finding in a
      view. Its identity then takes the urlconf's file instead of the
      helper's, once, whatever the rule. A Flask or FastAPI route is
      declared in the helper's own file, so nothing moves.
    - Rules that pin their identity keep doing so:
      `python.ast/PY_JWT_WEAK` and `python.ast/PY_WEAK_CRYPTO_PASSWORD` give
      their evidence line as their sink.
    - A newly proven helper such as `open(os.path.join(BASE, name))` also
      reports the inner `os.path.join(...)`, which is reported only when the
      flow is proven.
  - **Cost.** Before analysing, the Python analyzer reads every file once
    more and parses the files that name `request` or `req` or hold a route
    handler, recording each call into the project in a few bytes. It keeps
    no parsed file beyond two caches of 256 KiB of source each: parses for
    the analysis to reuse, and the callers a proof needs, re-parsed when
    evicted. A helper's query stops at the first caller that proves it.
    Measured on the Python AST pass, with the same findings (on the
    generated application the helper's is now proven too):
    - a 217k-line library tree (Django, django-allauth, Django REST
      framework): 3.0 s and 35 MB peak memory before, 3.6 s and 45 MB now;
    - a generated application of 300 Flask view modules (217k lines, each
      module passing request input to one helper): 13.7 s and 98 MB before,
      16.7 s and 99 MB now.
  - **Framework parity:** in Django, Flask and FastAPI, the `cross_file`
    cases for SQL injection, command injection, SSRF, path traversal, open
    redirect and XSS now block. They warned before. No development-corpus safe case is flagged
    or blocks. The Python frameworks block on 102 of 108 vulnerable cases,
    up from 84.

- **A Semgrep taint tier, behind a per-language gate.** A match of a Semgrep taint rule (`mode: taint`) that sets
  `metadata.fendix_reachability: taint` becomes a finding with
  `source_tier: "semgrep_taint"` and `reachable: true`, but only when every
  language in the rule's `languages` is enabled in
  `semgrep.ReachabilityLanguages`. The gate ships closed: no language is
  enabled. JavaScript, TypeScript, Java and Go packs met the corpus gate but
  not the real-world one, so their findings are reported as warnings (see
  "JavaScript, TypeScript, Java and Go taint findings are reported as
  warnings, not blocking" under Changed).
  - **The match is the proof.** Semgrep reports a taint-mode match only when
    a declared source reached the sink within one function. No dataflow trace
    is needed. The engine now runs Semgrep with `--dataflow-traces`, and when
    Semgrep sends a trace, it becomes the finding's `taint_chain`: source,
    intermediate variables, sink. Semgrep 1.141.0 sends one only to a
    logged-in account. A logged-out run, which is the default, gets a chain
    that holds only the finding's own location. It is reachable all the same.
  - **When a language is enabled.** Only when its taint pack reaches
    precision of at least 0.90 on the framework-parity development set,
    within the noise budget, and precision of at least 0.80 on at least 10
    triaged findings of a blind real-world evaluation. (This entry used to
    say the release gate checks holdout precision. It does not: the release
    workflow's holdout job compares holdout recall with development recall
    only, does not gate the release, and passes without measuring when its
    deploy key is absent.) ADR-011 records the decision and the evidence
    for each language. No language is enabled yet.
  - **What a taint finding counts for.** Its reachability adds +10 to the
    confidence score, counts as an independent corroborating signal, and
    escalates the severity one level. A correlated one gets both the
    correlation and the reachable escalation. It stays a Semgrep finding: the
    -5 `tier_semgrep` delta, no deterministic-detection bonus, never a Proven
    Path, `analyzer_implementation: "semgrep"` in managed-CI evidence facts,
    and an imported Semgrep SARIF does not corroborate it. A proven finding
    scores 50, in the MEDIUM band, so at or above `--fail-on` it blocks on its
    reachable path and never on its own.
  - **Two analyzers on one line.** The tier ranks with textscan's
    (`native_go`). When both report the same category and location, the
    proven finding has already been escalated one level, so at equal declared
    severity it is the one kept, with its chain.
  - **Identity.** Such a rule's finding takes its `sink` from the match's own
    line and has no `symbol`, so it has one fingerprint whether Semgrep is
    logged in or out, whether a trace arrives, and whether its language is
    enabled. Existing rules do not set the key, and their findings keep their
    identity.
  - **Schema.** `source_tier` gains the value `semgrep_taint` in
    `docs/schema.json` and `docs/reporting-contract.json`. The change is
    additive: `schema_version` stays 2.
  - **Parity and cost.** With the gate closed, the framework parity gate
    showed no case change. Asking for traces added about 3% to Semgrep's run
    time on the parity corpus, within run-to-run noise.

- **Every bundled Semgrep rule now carries the same metadata, and rule packs
  get `semgrep --test` tests.** This is the contract the JavaScript/TypeScript,
  Java and Go packs are written to. On its own it changed no detection.
  - **The contract.** `TestEveryRuleCarriesFendixMetadata` requires
    `category` (one of `injection`, `xss`, `crypto`, `auth`, `secrets`),
    `cwe` (`CWE-<number>`), `confidence`, `fendix_severity`, `fendix_title`
    and `fendix_remediation` on every rule, with `languages` drawn from
    `python`, `javascript`, `typescript`, `java` and `go`. A taint rule is
    named `<lang>-<class>-taint`, declares `confidence: MEDIUM` and sets
    `fendix_reachability: taint`. A shape rule named `<lang>-<class>-sink`
    excludes a fully literal argument and a module constant
    (`const`, `static final`, and in Go `const $X = "..."` and the
    one-binding block `const ( $X = "..." )`; Semgrep 1.141.0 cannot parse
    the wider `const ( ... $X = "..." ... )`), so the same sink with a
    constant does not become a false positive.
  - **Twelve existing rules gain `fendix_title` and
    `fendix_remediation`:** `python-jwt-decode-no-verification`,
    `python-md5-used-for-password`, `python-sha1-used-for-password`,
    `python-legacy-cipher-import`, `python-sql-injection-string-format`,
    `python-command-injection-shell-true`, `python-eval-injection`,
    `django-orm-raw-sql`, `flask-render-template-string-injection`,
    `python-subprocess-shell-true-with-variable`,
    `python-pickle-loads-untrusted` and `python-yaml-load-unsafe`. The text
    is what the security catalog already derived from each rule's message,
    so `docs/security-catalog-contract.json` does not change. A finding's
    title and fix text come from the message, which does not change, so no
    finding changes either.
  - **Rule tests.** `go/internal/scanner/semgrep/ruletests/<stem>.<ext>`
    tests `rules/<stem>.yaml`, with `// ruleid: <id>` and `// ok: <id>`
    annotations, and the CI job `container-smoke` runs
    `semgrep --test --config go/internal/scanner/semgrep/rules go/internal/scanner/semgrep/ruletests`
    with the release image's Semgrep. Semgrep skips a test file that has no
    rule file of its stem and still reports success, so
    `TestRuleTestsPairWithRulePacks` fails on such a file. It also requires
    a `ruleid:` and an `ok:` line for every rule of a pack in a language
    other than Python. The JavaScript/TypeScript, Java and Go packs bring
    their own test files.
  - **Parity run time.** `make parity` records the wall time of every scan
    in `.parity/results.json` and prints the run's total and its slowest
    scan, to watch against the Semgrep deadline below.

- **Semgrep taint rules for JavaScript and TypeScript: Express, NestJS and
  Next.js.** 17 new bundled rules in `javascript-injection.yaml`,
  `javascript-web.yaml` and `javascript-crypto.yaml`, written in-house, run
  on `.js` and `.ts` files when Semgrep is installed.
  [`docs/semgrep-rules.md`](docs/semgrep-rules.md#the-javascript-and-typescript-pack)
  lists every source, sink and sanitiser.
  - **Ten taint rules** (`js-<class>-taint`) report request input reaching a
    sink within one function: SQL injection, command injection, template
    injection, XSS, SSRF, path traversal, open redirect, a password hashed
    with MD5 or SHA-1, and a JWT decoded without verification; and
    `Math.random()` output that becomes a token. Request input is Express's
    `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies` and
    `req.get(...)`; a NestJS parameter bound by `@Query()`, `@Param()`,
    `@Body()`, `@Headers()` or `@Req()`; and a Next.js route handler's
    `searchParams`, `json()`, `formData()`, `headers` and context `params`.
  - **An SQL builder's tagged template is never SQL injection.** A tag
    named `sql` sends its interpolations as bound parameters:
    `` sql`... ${id}` `` (postgres.js, drizzle), slonik's `sql`,
    `sql.type(...)`, `sql.unsafe`, `sql.typeAlias(...)` and `sql.fragment`,
    `Prisma.sql`, `` prisma.$queryRaw`...` `` and sql-template-strings'
    `SQL`. Neither the taint rule nor the shape rule reports them. A
    project's own tag (`buildSql`, `rawSql`, `sqlConcat`) may concatenate, so
    it is reported, as are `String.raw`, drizzle's `sql.raw(...)` and a tag
    imported under another name. A pg config object, inline or bound to a
    name first, is the parameterized form too; its `text` is still checked,
    and reported when request input reaches it.
  - **A sanitiser has to hold.** An SSRF host allowlist counts only as
    `if (!ALLOWED.has(<host>)) return` or `throw`, with the host read off
    the URL object, off `new URL(url)` or destructured from it; the URL and
    the string it parsed are clean afterwards. The check may be an operand
    of `||` but not of `&&`, and the `return` or `throw` must be a direct
    statement of the guard's body. A denylist, or a check that does not
    leave, cleans nothing. An open-redirect guard needs both halves, starts
    with `/` and not with `//`; path-traversal guards follow the same
    rules, and a prefix check counts only on a path from `path.resolve`.
    SQL accepts an identifier allowlist with the same rules (or a reset to a
    literal, or a literal-picking ternary) and values made only of
    constants: placeholders mapped from a list or built with
    `Array(n).fill('?')`, the length of a real array (not of request data),
    a literal-map lookup with a literal fallback, and a same-file helper
    that is exactly that lookup. The allowlist is a constant name or an
    array literal of string literals. These checks stay linear: the rule
    finishes a 2,000-line route file in seconds. A URL whose literal start
    fixes the scheme and host, or a same-site path, is clean wherever it is
    built, inline or in a variable first. Path traversal accepts
    `sendFile`/`download` with `root` and the `path.relative` containment
    check. XSS accepts only named HTML escapers (not `unescape`,
    `he.decode` or `_.escapeRegExp`) and the output of an engine rendering a
    fixed template that writes no value raw (ejs `<%-`, `{{{`, `| safe`,
    pug `!=`) or of React's `renderToString`. A `Math.random()` token
    is one whose name ends in the token word (`resetToken`, `sessionId`),
    not jitter such as `resetDelayMs`.
  - **Seven shape rules** (`js-<class>-sink`) report the same sinks behind a
    helper's parameter, which Semgrep CE's intraprocedural taint does not
    follow: SQL text and shell commands built from a non-constant value,
    and a template, HTML markup, redirect target or decoded JWT that is the
    helper's parameter; and a password-named value hashed with MD5 or
    SHA-1. A module constant or a literal is never reported. SSRF and path
    traversal have no shape rule: helpers that fetch a URL or read a file
    by a parameter are too common in clean code.
  - **Test code is skipped.** No rule reports in test, mock or fixture
    paths (`__tests__/`, `__mocks__/`, `__fixtures__/`, `mocks/`, `mock/`,
    `fixtures/`, `test/`, `tests/`, `spec/`, `e2e/`, `cypress/`, and
    `*.test.*`, `*.spec.*`, `*.e2e-spec.*`, `*.cy.*` files), matched relative
    to the scan root.
  - **Taint findings are warnings, not blocking.** The taint rules' findings
    are reported as warnings: JavaScript and TypeScript precision was 0.077
    (1 of 13 findings) on the blind real-world evaluation, so the gate is not
    opened for them; see "JavaScript, TypeScript, Java and Go taint findings
    are reported as warnings, not blocking" under Changed. Shape findings
    warn too.
  - **Framework parity (JS/TS):** recall 19.4% to 88.9% (96 of 108
    vulnerable cases), with no new false positive: the false-positive rate
    on safe cases stays 4.5%, the three `sqli-safe_lookalike` cases the
    Python engine's `SEC-JS_SQL_TEMPLATE` already flagged. Block recall stays
    at 19.4%: the taint findings warn (see the entry under Changed). Still
    missed: SSRF and path traversal through a helper in the
    same or another file (12 cases).
  - **Real-world noise:** no new finding on the clean
    `node-express-realworld` (2.4 kLOC). On the vulnerable-by-design apps,
    5 new findings on `juice-shop` (0.05 per kLOC) and 2 on `nodegoat` (0.65
    per kLOC); 17 of their 19 matches are true positives. The two others
    are path-traversal matches in `juice-shop` that a key lookup in another
    function guards. A scan of `juice-shop` (104 kLOC) takes 26 s instead
    of 5 s, the pack's Semgrep pass.
  - **Catalog.** `docs/security-catalog-contract.json` gains the 17
    `js-*` checks under the `semgrep` analyzer.

- **Java and Spring code now has Semgrep taint rules.** Three new rule packs
  written in-house, `java-injection.yaml`, `java-web.yaml` and
  `java-crypto.yaml`, add ten taint rules and five shape rules. A taint
  rule's match is reported as a warning, not blocking, because Java is not
  enabled in the taint gate (precision 0.111 on the real-world evaluation; see
  "JavaScript, TypeScript, Java and Go taint findings are reported as
  warnings, not blocking" under Changed); a shape rule's finding warns too.
  - **What they find.**
    - SQL injection: JdbcTemplate, NamedParameterJdbcTemplate, JDBC
      `Statement` and `Connection`, JPA `EntityManager` and Hibernate
      `Session` queries built from request input (`java-sqli-taint`).
    - Command injection: `Runtime.exec`, and a `ProcessBuilder` running
      `sh -c` or a program the request chose (`java-cmdi-taint`).
    - Template injection: FreeMarker, Velocity and Thymeleaf templates
      compiled from request input (`java-ssti-taint`).
    - Reflected XSS: the return value of a `@ResponseBody` handler that
      produces `text/html`, and the servlet response writer
      (`java-xss-taint`).
    - SSRF: RestTemplate, WebClient and RestClient, `java.net.http`,
      `URL.openConnection` and `openStream`, Apache HttpClient and Jsoup
      (`java-ssrf-taint`).
    - Path traversal: `Files`, file streams, readers and writers, and
      `MultipartFile.transferTo` (`java-path_traversal-taint`).
    - Open redirect: `sendRedirect`, a `"redirect:"` view, `RedirectView`
      and the `Location` header (`java-open_redirect-taint`).
    - A password hashed with MD5 or SHA-1, claims read from a JWT decoded
      without verifying it (auth0 `JWT.decode`, jjwt `parseClaimsJwt`,
      `parseUnsecuredClaims` and an `unsecured()` parser), and a token, code
      or key drawn from `java.util.Random`, `Math.random`,
      `ThreadLocalRandom` or `RandomStringUtils.random*` (a variable or
      method whose name ends in a token word, such as `resetToken` or
      `generateOtp`; `tokenRefreshJitterMs` and `spotPrice` do not).
  - **Sources.** A handler parameter annotated `@RequestParam`,
    `@PathVariable`, `@RequestBody`, `@RequestHeader`, `@CookieValue`,
    `@ModelAttribute`, `@RequestPart` or `@MatrixVariable`, or a plain
    `String` parameter of a request-mapping method, unless it is a number, a
    boolean, a date, a UUID or a framework object; and
    `HttpServletRequest.getParameter`, `getHeader`, `getQueryString`,
    `getInputStream` and `getReader`. Semgrep follows taint within one
    method, so a method of the same class that a handler passes a request
    value to is followed too, one call deep, and the finding is at the sink
    inside it. The called method is matched by name and number of arguments
    (one to three) among the class's own methods, not a nested class's, and
    the argument at that position must be the request value itself, a getter
    of it, or a concatenation or `String.format` of such values. A value the
    handler sanitised in the call, such as `FilenameUtils.getName(file)`, or
    reassigned before it, is not followed.
  - **Not reported.**
    - `?` placeholders, named parameters and JPA Criteria queries.
    - HTML encoding (`HtmlUtils.htmlEscape`, `Encode.forHtml`,
      `StringEscapeUtils.escapeHtml4`), a response declared JSON, and the
      output of a Thymeleaf template named by a constant.
    - A URL whose host is fixed before input is appended: a literal
      `https://host/...`, a relative `/...` path, a base-URL field or
      constant (an `@Value` property) followed by `/`, or a
      `UriComponentsBuilder` started from one.
    - `FilenameUtils.getName`, and `SecureRandom`. An argument array whose
      program is fixed. The claims of a token that went through `verify()`,
      and a token's time claims (`exp`, `iat`, `nbf`).
    - In SQL, a value that cannot hold request text: a count or length
      (`size()`, `length`), `Collections.nCopies` of a literal or a stream
      mapped to a literal (IN-list placeholders), a `get` or a
      `getOrDefault` with a literal default on a final `Map.of` or
      `Map.ofEntries` of literals, and a call of a method of the same class
      whose every `return` is a literal (or a choice between two literals),
      or whose whole body is one `return` of a constant lookup: a final
      `Map.of`/`Map.ofEntries` of string literals read with `getOrDefault`
      (literal default), `get`, or `containsKey(k) ? get(k) : "lit"`, or
      `SET.contains(k) ? k : "lit"` on a final `Set.of` or `List.of` of
      string literals. Such a helper used to leave the call tainted, which
      blocked a build on `ORDER BY " + col(sort)`. A helper on a `HashMap`
      or non-final map, with a fallback that is the parameter, with another
      statement, or with a mixed return still reports, as does the
      `if (ALLOWED.contains(k)) return k; return "id";` form (a known
      false positive).
      `"... ORDER BY " + sort` and `String.join(",", ids)` stay reported.
    - Test, fixture and mock code: every Java rule skips `src/test`,
      `src/integrationTest`, `src/testFixtures` and `src/it`, files named
      `*Test.java`, `*Tests.java` and `*IT.java`, and `mock`, `mocks`, `fake`
      and `fakes` directories. The patterns are matched below the scan root,
      so a checkout that lies under such a directory is still scanned.
    - A value behind a guard. A guard counts only when the branch taken on a
      failing check ends with a direct `return` or `throw` (or, for a
      redirect or a SQL identifier, a direct assignment of a literal to the
      value itself, followed by nothing but literal assignments, in an `if`
      with no `else`), not one nested in an `if`, `try`, loop or lambda, and
      the check is not under an `&&`; or when the use sits in the
      then-branch of a passing check with no `else`. A check that only logs
      or exits only sometimes, a denylist, and a use inside the failing
      branch stay reported. The checks are:
      - a host allowlist or a literal host comparison on the URL's host:
        `getHost()` of a `URI` or `URL` parsed from it, or a variable
        holding that host; or one exact URL (`equals`, or `matches` with
        every dot escaped). A check on the scheme, path or port alone is
        not a host check, though it may sit beside one in an `||`;
      - containment: a normalized or real `Path` that `startsWith` the base,
        or a String that is itself a canonical or normalized path
        (`getCanonicalPath()`, `normalize().toString()`), inline or in a
        variable, that `startsWith` the base plus a separator. A String
        `startsWith` without a separator is not containment, and neither is
        a canonical base joined with the input;
      - for a redirect, both halves, each with its polarity: a failing
        check holds `!t.startsWith("/")` and `t.startsWith("//")` as `||`
        operands, and a passing one `t.startsWith("/")` and
        `!t.startsWith("//")` as `&&` operands. A replacing check tests
        `startsWith("//")` on the target only;
      - for a SQL identifier: membership in an allowlist (`contains`,
        `containsKey`); a condition whose every operand is a negated
        equality of the value with a literal
        (`!"asc".equalsIgnoreCase(dir) && !"desc".equalsIgnoreCase(dir)`);
        the ternary `ALLOWED.contains(sort) ? sort : "id"`; and a `switch`
        on the value whose cases only `break` and whose `default` assigns it
        a literal or exits.
  - **Shape rules** (`java-sqli-sink`, `java-xss-sink`, `java-ssrf-sink`,
    `java-path_traversal-sink`, `java-open_redirect-sink`) report a sink in
    another class: a non-private method whose own `String` parameter is
    concatenated into SQL or HTML, is the URL of a request or a redirect, or
    is a file name joined to a directory. They exclude module constants and
    literal arguments, apply their taint rule's guards (for SQL, only when
    the parameter is the one value in the SQL text), prove no flow, and
    never count as reachable.
  - **Rating.** SQL, command and template injection, SSRF and unverified JWT
    claims are HIGH; XSS, path traversal, open redirect, weak password
    hashing and weak random tokens are MEDIUM; the shape rules are MEDIUM.
    All have MEDIUM confidence. SSRF, path traversal, open redirect and
    template injection are category `injection`, weak hashing and random
    tokens `crypto` and JWT `auth`, as textscan files them, so a textscan
    finding on the same line collapses with the Semgrep one.
  - **Identity.** The findings are new, with new rule ids.
  - **Catalog.** `docs/security-catalog-contract.json` gains the 15 `java-*`
    checks under the `semgrep` analyzer.
  - **Parity.** On the Spring corpus, recall goes from 12 to 35 of 36
    vulnerable cases (the one left is a hardcoded secret). False positives
    stay at 2 of 22 safe cases, both textscan's.
  - **Real code.** On `spring-petclinic`, nothing new. On WebGoat, 25 new
    locations, all true positives (SQL injection lessons, open redirects,
    path traversal and zip slip, predictable tokens and secrets). The scan
    takes about one second longer.
- **Go: Semgrep taint rules for net/http and Gin.** Three new packs,
  `go-injection.yaml`, `go-web.yaml` and `go-crypto.yaml`, add 19 rules: a
  taint rule (`go-<class>-taint`) and a shape rule (`go-<class>-sink`) for SQL
  injection, command injection, template injection, XSS, SSRF, path
  traversal, open redirect, weak password hashing and JWTs decoded with
  `ParseUnverified`, and a pattern rule, `go-weak-random-token`, for tokens
  drawn from `math/rand`. A taint rule's match is reported as a warning, not
  blocking, because Go is not enabled in the taint gate (precision 0.091 on
  the real-world evaluation; see "JavaScript, TypeScript, Java and Go taint
  findings are reported as warnings, not blocking" under Changed); a shape
  rule's finding and `go-weak-random-token` warn too.
  - **Sources.** net/http's query, form and path values, request headers,
    cookies and body (decoded JSON included), gorilla/mux and chi path
    variables, and Gin's request accessors and bind targets.
  - **One call into the same file.** Semgrep OSS follows taint within one
    function. A call that passes request input to a function of the same
    file whose string parameter reaches the sink is reported at the call.
  - **Lookups are not request input, helpers are followed.** A
    package-qualified or method call's result (a row, a cache entry, a stored
    file name looked up by request input) is clean, except the calls that
    hand their input back (`fmt.Sprintf`, the `strings`, `filepath`, `path`
    and `url` functions, regexp replacement, decoders) and a call of a method
    of the same file. A call of a function (or method) of the same file is
    clean only when its body is in the file and every return is constant: a
    string literal, a lookup in a map of string literals with a literal
    fallback, or a `switch` or `if` over literals. Every other call keeps the
    taint of its arguments, as Semgrep does by default: a function of another
    file of the package, a helper that builds its result (through a variable,
    a `strings.Builder`, a struct or a second return value), and a helper
    that validates its parameter and returns it. `len`, `cap`, a map lookup
    keyed by request input, and a `fmt.Sprintf` whose verbs are all numeric
    (`"$%d"` placeholders) are clean.
  - **Guards.** Placeholders and prepared statements for SQL, and an
    identifier (an `ORDER BY` column, a sort direction) checked against an
    allowlist, compared with each allowed literal, or settled by a `switch`
    default; a host allowlist (map, `slices.Contains`, a set's `Has`) or a
    fixed-host comparison that exits, on the parsed URL or the string it came
    from, for SSRF; a local-path check (starts with `/`, not with `//`) that
    exits or replaces the target for redirects; `filepath.Base`,
    `filepath.Rel` or a separator-terminated prefix check that exits for
    paths, a `..` check only for a name then joined onto a base, and an
    upload's `Filename`; escaping or `html/template` for XSS; a literal
    scheme-and-host or local-path prefix for SSRF and redirects, and a value
    placed after a literal `?` or `#`. The comma-ok membership test
    (`if _, ok := allowed[u.Host]; !ok { return }`, for a set or a bool map,
    in the `if` or as two statements) is an allowlist for SSRF hosts and SQL
    identifiers, and so is a conjunction of negated host equalities
    (`u.Host != "a.example.com" && u.Host != "b.example.com"`). A guard
    counts only when its `if`
    block ends in a `return` (or, where stated, replaces the value with a
    literal) and its check is the whole condition or one alternative of an
    `||`. A check joined to another by `&&` or wrapped in `!(...)` guards
    nothing, and a passing check covers only its own block, not the `else`.
    A denylist, a `//` check alone, a prefix check without a separator, or
    an `if` that only logs guards nothing either.
  - **Shape rules** report an exported function whose string parameter is
    formatted into a SQL value, a shell command line, an HTML response, an
    outbound URL, a joined file path or a redirect target, for callers in
    other files.
  - **GORM.** A `Where`, `Or`, `Not`, `Order`, `Group`, `Having` or `Joins`
    condition built with `fmt.Sprintf` or `+`, taken straight from a request
    accessor (`Where(c.Query("filter"))`), or held in a variable assigned
    one of those is a sink; `Where("name = ?", v)` and a map or struct
    condition are not.
  - **Go test code is skipped:** `*_test.go`, `mock_*.go` and `*_mock.go`,
    and `testdata`, `testhelpers`, `testutil`, `testutils`, `testing`,
    `test`, `tests`, `unittest`, `mock`, `mocks` and `fakes` directories.
  - **Weak password hashing is reported twice.** `go-weak-password-hash-*`
    uses the `crypto` category and textscan's `GO_WEAK_HASH_PASSWORD` uses
    `secrets`, so the two findings on one `md5.Sum(password)` line do not
    collapse (see `docs/semgrep-rules.md`).
  - **Parity.** net/http and Gin recall rises from 36% to 100% each, with no
    new false positive (the four left are textscan's, on the SQL and command
    lookalikes).
  - **Catalog.** `docs/security-catalog-contract.json` gains the 19 `go-*`
    checks under the `semgrep` analyzer.

### Changed

- **A probe the target did not answer is inconclusive, not an evaluation, and
  the report says so beside the scan-wide verdict.** Before, `active-probes`
  was `ok` with no detail whenever every probe got any HTTP response (a 429, a
  503 or a gateway timeout counted as evaluated), `ok` with "N of M probe
  requests received no HTTP response" for some, and `failed/network_error` only
  when none did, so a target could steer the verdict by how it failed. Now
  every probe is attributed from evidence about what happened on the wire (the
  connection, the request write, TLS, the scan's own contexts, a recorded
  response from the same host), never from the Go error type alone, to one of
  three origins. `scanner`: a panic, the scan's own deadline or cancellation,
  local resource exhaustion, a proxy or request-construction failure, a probe
  the request budget or egress guard never let leave. `target`: a reset, close
  or stall after the connection was established, a TLS alert from the peer,
  429/502/503/504 after the retries, a malformed or broken response, and a
  connect timeout or refusal when another request to the same host got an
  answer within 30 s. `unknown`: everything else (DNS failure, a connect
  timeout or refusal when the host never answered anything, network
  unreachable, a TLS handshake that failed with no alert, a probe recorded with
  no response and no evidence). `active-probes` is `failed/execution_error`
  when any probe is `scanner` or `unknown` (fail-closed: neither is an
  evaluation, and neither is blamed on the target) and `ok` otherwise while at
  least one probe was evaluated (round 5: when none was, it is `failed` /
  `no_endpoints`); its detail always starts with
  `probe evaluation: A attempted, E evaluated, I inconclusive (target), U
  unknown-origin, F scanner-failed` (on a failed entry after `lost evaluation:
  N probe(s) not evaluated (U unknown-origin, F scanner-failed)`), followed by
  the non-zero reasons of each origin in a fixed order. The complete account is
  the new `metadata.coverage.active_probes` (`attempted`, `evaluated`,
  `inconclusive`, `unknown_origin`, `scanner_failed`, `reasons` as
  `{origin: {reason: count}}`, `not_evaluated_checks` capped at 200 with
  `truncated`), additive in `docs/schema.json` and
  `docs/reporting-contract.json`, no `schema_version` change. Findings are
  always kept. A scan-wide `configured_complete` is never proof that every
  probe was evaluated; read `active_probes` beside it. One measured
  consequence, and a correction. **Corrected in round 5:** this entry first
  shipped a pass in which the target reset every probe as `ok`, `22 attempted, 0
  evaluated, 22 inconclusive (target)`, `configured_complete` true, and a
  consumer had to read `evaluated` to refuse it; that was a hole (C4B-06). A pass in
  which no probe was evaluated is now `failed` / `no_endpoints` and a coverage gap
  (see "Probes the target answered 401, 403, 404 or 410 are gated" below). And an
  error while the connection is still being made (before it is
  established) that is not a timeout, a refusal, a DNS or a TLS failure is
  `unknown` / `unclassified`, which fails the entry: against a local Python
  test server that answered 503 to every path but the index and listened with
  the default backlog of 5, three of twelve scans recorded one such probe among
  23 to 25 (`xss` on `GET /item` in two, `openredirect` on it in the third) and read
  `failed`,
  the others `ok` with none. Nothing the engine records settles whose fault
  such an error is (a target at its connection limit and a scanner fault look
  the same from here), which is why the origin is `unknown` and not the
  target's; whether a real network produces it is unmeasured.
- **Probes the target answered 401, 403, 404 or 410 are gated, not evaluated,
  and a pass that evaluated nothing is a gap (round 5, D5-6, C4B-01 and C4B-06).**
  Before, a 401, 403, 404 or 410 counted as an evaluated probe, so a target that
  answered 403 to every probe read every probe evaluated, `coverage: complete`,
  `required: satisfied` and exit 0 under `--require-analyzers active-probes`; a
  target that reset every probe read `0 evaluated` and exit 0 the same way (both
  measured by the round-5 probe owner on the previous tree, not re-run here). Such an answer says the
  request was refused or the path is not served to this client, which says
  nothing about whether the parameter is safe.
  - **Gated.** A probe with no finding answered 401, 403, 404 or 410 is target-side,
    reason `gated`, **not evaluated**, evidence of nothing. It is counted inside
    `inconclusive` and in a new `metadata.coverage.active_probes.gated` (`{total,
    by_status}`, always present, `by_status` holding non-zero keys only), so the
    counts line `probe evaluation: A attempted, E evaluated, I inconclusive
    (target), U unknown-origin, F scanner-failed` is byte-identical and `A = E + I +
    U + F` still holds. The detail gains `; gated probes (target answered
    401/403/404/410 so not evaluated): 403 4, 404 2` (the pairs are status and
    count) and the `inconclusive probes` segment then lists only the probes the
    target did not answer; `reasons.target.gated` equals `gated.total`, and
    `not_evaluated_checks` entries carry `origin: target`, `reason: gated` and
    evidence such as `the target answered HTTP 403 (forbidden), so the probe was
    gated and nothing was evaluated`. A gated probe is not a gap and is never
    refunded by the hosted backend.
  - **Nothing evaluated is a gap.** `attempted > 0`, `evaluated == 0` and no
    scanner-side or unknown-origin probe is `failed` / `no_endpoints` (a
    target-owned reason, no new one), the detail starting `no probe was evaluated:
    the target gave none of the <N> probes an evaluable answer; ` and then the
    counts segment. This is exactly the hosted backend's rule
    (`target_never_answered`), so `coverage.configured_complete` is false and
    `--fail-on-coverage-gap` and `--require-analyzers active-probes` exit 2.
    Measured on this tree, with `--enable-active --require-analyzers
    active-probes`, against a local server that served one linked page and answered
    every other path 403: `2606 attempted, 0 evaluated, 2606 inconclusive (target)`,
    `active probes: 2606 attempted, 0 evaluated, 0 not answered by the target, 2606
    gated (403 2606), 0 unknown-origin, 0 scanner-failed`, `failed` / `no_endpoints`,
    `coverage: incomplete (active-probes)`, `required: not delivered
    (active-probes)`, exit 2. A server that reset every other path: `14 attempted,
    0 evaluated, 14 not answered by the target, 0 gated`, the same coverage and
    required lines, exit 2.
    One evaluated probe is enough for `ok`. The stderr summary gains `active
    probes: A attempted, E evaluated, N not answered by the target, G gated (403 4,
    404 2), U unknown-origin, F scanner-failed`, never starting with `coverage: `
    or `required: ` (the prefixes the Action reads).
  - **A pass cut short names its limit (C4B-18, C4B-31).** A pass ended by
    `--max-duration` is `failed` / `timeout` with the lead `scan limit
    --max-duration=<value> elapsed before the probe pass completed; `, and one ended
    by `--max-requests` is `failed` / `execution_error` with `scan limit
    --max-requests=<value> exhausted: <N> requests refused before the probe pass
    completed; `, and `coverage.active_probes.cut_short` (`{cause, limit,
    configured, refused}`, present only then) records the flag and its value. The
    engine knows the flag and the value, not who set it; the hosted backend decides
    (a customer-set limit is labelled one and earns no refund, Fendix's default
    budget is Fendix's). Probes the limit kept from starting are in no count, so a
    consumer must key on the state and `cut_short`, not on a counts line that can
    read `E of E evaluated`. A `--max-requests` cancellation is labelled by the
    budget (`not_sent` if the request was never written, `scan_cancelled` if cut in
    flight), never as the target's doing.
  - **A redirect into a blocked address is target-side (C4B-10).** A target that
    redirects a probe to an address the SSRF egress guard refuses is `target` /
    `other_transport` (evidence `the target redirected the probe to an address the
    SSRF egress guard refuses`), no longer `scanner` / `not_sent`. A refusal of the
    probe's *own* destination stays scanner-side `not_sent`, and a target whose DNS
    flips to a private address after discovery can cause it (open owner decision).
  - **The detail prefixes are exact (C4B-35).** `unknown-origin probes (not
    evaluated): ` and `scanner-failed probes (not evaluated): `, byte for byte
    (pinned by `TestProbeDetail_ReasonSegmentPrefixesAreExact`); the hosted backend
    and frontend read these and still read the short forms without `(not
    evaluated)`.
  - **Open decisions.** The GraphQL origin sweep (every active scan POSTs to seven
    well-known paths, which a normal target answers 404) is gated under this rule, so
    most active scans list `gated 404 7` and a scan whose only other probes are not
    evaluated reads 0 evaluated; exempting the sweep would let seven 404s stand in
    for evaluation on a target that gates everything else, so it is not exempted.
    Method-tamper and GraphQL probes read a 401/403 as the secure answer, which is
    now gated and not evaluated (over-conservative, never a false clean).
- **Retries are bounded and deterministic.** A 429, 502, 503 or 504, a reset
  after the connection was established, or a timeout on an accepted connection
  is retried up to twice after 1 s then 2 s (a `Retry-After` is honoured, capped
  at 5 s). A retry is never started when the context is cancelled or its
  deadline (the per-check deadline or `--max-duration`) is not further away than
  the pause, when the per-endpoint probe cap (`--max-probes-per-endpoint`,
  which retries now share) or the `--max-requests` budget has no room, when the
  scan-wide allowance of 200 retries is spent, or when the request body cannot
  be replayed; the probe then keeps its last classification. No new flag.
- **`fendix verify` never resolves an active-probe finding.** A gated or
  removed endpoint (401/403/404/410) was `resolved` ("attack surface no longer
  reachable") and a consented re-probe without the recorded marker was
  `resolved` ("presumed resolved"). Both are now `unknown`, with a reason that
  names what was observed (`active-probe endpoint now returns HTTP 404; a
  reachability change is not proof of remediation (no validated probe-specific
  verification contract exists)`); 429/5xx, a timeout, a reset and a request
  that failed are `unknown` too. `still-present` remains only when the recorded
  payload marker reproduces, and the marker is read from the finding's evidence
  best-effort (a reflected `<script>...</script>`), so for most active-probe
  findings the answer is `unknown`. The
  same holds for a correlated finding whose blackbox half is an active-probe
  finding. The active-probe categories the checks actually stamp (`redirect`,
  `host_header`, `method_tamper`) are recognised alongside the hyphenated ones.
  No probe-specific verification contract has been independently validated, so
  none returns `resolved`.

- **JavaScript, TypeScript, Java and Go taint findings are reported as
  warnings, not blocking.** `semgrep.ReachabilityLanguages` is empty (ADR-011,
  ruling R-pf81), so a match of one of these packs' taint rules
  (`js-<class>-taint`, `java-<class>-taint`, `go-<class>-taint`) is a
  `semgrep_shim` finding: `reachable: false`, not escalated, and it never
  fails a build. A shape rule's finding (`-sink`) and `go-weak-random-token`
  warn as before. The packs still run and still report; only the blocking is
  withheld.
  - **Evidence.** The packs met ADR-011's corpus gate (precision of at least
    0.90 on the framework-parity development set, and no new finding on a
    clean application), but a blind evaluation on 70 fresh public production
    repositories did not. Every taint-tier finding was triaged by reading the
    handler. The rule fixed in advance required precision of at least 0.80 on
    at least 10 findings.
    - JavaScript and TypeScript: 1 true positive in 13 findings, precision
      0.077.
    - Java: 1 true positive in 10 findings, precision 0.111 (the one unclear
      finding is left out; counted as true it is 0.20).
    - Go: 1 true positive in 11 findings, precision 0.091.
    - The three true positives are low impact: one authenticated path
      traversal and two unvalidated open redirects.
    - Most false positives share a few causes: `Math.random()` taken for a
      token wherever its value flows, a redirect URL read from configuration
      with only a selector from the request, and a validator or sanitiser the
      rule cannot see through.
    - The aggregate evidence is
      `benchmarks/frameworks/REALWORLD.md`.
  - **Framework parity (block recall, of the vulnerable cases).** The corpus
    results are unchanged: recall is as before, and every case is still
    detected. Only blocking falls back.
    - JavaScript and TypeScript: block recall 19.4% (21 of 108 vulnerable
      cases, the secrets and template-literal SQL), recall 88.9% (96 of 108).
    - Java: block recall 8.3% (3 of 36, the secrets), recall 97.2% (35 of 36).
    - Go: block recall 11.1% (8 of 72, the secrets), recall 100% (72 of 72).
    - No development-corpus safe case newly blocks.
  - **Not enabled again until a pack clears the real-world gate.** A
    language is added to the map only with precision of at least 0.80 on at
    least 10 triaged real-world findings, and the corpus gate. The mechanism
    and its tests stay.

- **`python-random-for-token-generation` reports more token generators.**
  - **More calls.** `random.choices`, `random.randrange` and
    `random.randbytes` are reported beside `random.random`, `choice`,
    `randint`, `sample`, `shuffle` and `getrandbits`.
    `"".join(random.choices(ALPHABET, k=40))`, the most common token idiom,
    was missed.
  - **More function names.** The security-sensitive word may now start any
    segment of the function's name: `issue_api_key`, `_generate_api_key` and
    `generate_token` are reported. Semgrep anchors a `metavariable-regex` at
    the start of the name, so until now only a name that began with the word
    was reported (`token_for`). The rule's own documented example,
    `generate_token`, never fired. A word inside a segment still does not
    count: `footprint` (otp) and `preset_palette` (reset) are not reported.
  - **Identity.** Every finding the rule reported before keeps its rule id,
    message, title, severity and fingerprint. The change only adds findings.
    A call inside a nested function now gets one result per enclosing
    function whose name matches, each naming its function. Semgrep already
    did this when both names began with the word. The results share one
    fingerprint.
  - **Framework parity.** The `direct` and `indirect` weak-random-token
    cases of Django, Flask and FastAPI are detected. They were missed in all
    three: `create_api_key` and `_generate_api_key` call `random.choices`.
    They warn, and the development-corpus safe cases stay clean. The Python frameworks detect
    all 108 vulnerable cases, up from 102. They still block on 72.

- **Python weak password hashing and unverified JWT decoding are now
  proven when the value comes from the request, and may block.**
  `python.ast/PY_WEAK_CRYPTO_PASSWORD` reports MD5 or SHA-1 of a
  password-named value. `python.ast/PY_JWT_WEAK` reports `jwt.decode` with
  signature verification off. Neither rule tried to prove a flow, so even
  `hashlib.md5(request.form["password"].encode())` only warned. Both now
  trace a value back to request input: the hashed data, and the decoded token
  (the first argument, or `jwt=`).
  - **Sources and hops.** These are the same as for the other proven Python
    rules:
    - a `request.*` read;
    - a route handler's request-carrying parameter, such as a FastAPI
      `Form()` or `Header()` parameter;
    - a same-file helper that the value is passed to, keyword-only
      parameters included.

    A sanitiser in the caller that the helper hop honours, such as a
    membership guard, leaves the helper's finding unproven.
  - **A proven finding.** It is marked reachable and carries a taint chain.
    A reachable taint path is an independent signal, so the confidence gate
    lets the finding block at a `--fail-on HIGH` threshold. Neither rule has
    a proven title or severity, so the title does not change. The severity
    stays HIGH: the engine raises a reachable finding one level, and MEDIUM
    confidence caps it at HIGH again.
  - **An unproven finding** is reported as before and still warns. The
    Semgrep rules `python-md5-used-for-password`,
    `python-sha1-used-for-password` and `python-jwt-decode-no-verification`
    do not change.
  - **Identity.** Fingerprints do not change, whether a finding is proven or
    not.
    - Both rules now give the evidence line as their sink, on both paths.
      The JSON report's new `sink` field equals the `evidence` field.
    - `python.ast/PY_JWT_WEAK` is a code finding. Its fingerprint hashes the
      sink, and hashed the evidence line while the rule named no sink, so
      the operation it identifies is unchanged.
    - `python.ast/PY_WEAK_CRYPTO_PASSWORD` is a `secrets` finding, identified
      by its rule and file alone. A bound route, a sink or a chain never
      moves it, so it binds a Django route like the other rules do.
    - A proven `python.ast/PY_JWT_WEAK` finding in a Django view does not
      bind the urlconf's route. A bound route's file would replace the view's
      file in the fingerprint. A Flask or FastAPI route is declared in the
      handler's own file, so it is bound.
  - **Framework parity.** In Django, Flask and FastAPI, the `direct` and
    `indirect` weak-password-hash and JWT-no-verify cases now block. They
    warned before. No development-corpus safe case is flagged. The Python frameworks block on
    84 of 108 vulnerable cases, up from 72.

- **A Flask route without authentication now gets one missing-auth finding
  instead of two.** The Semgrep rules `flask-missing-login-required` and
  `flask-route-no-auth-decorator` both reported every unprotected Flask route.
  `flask-missing-login-required` is removed (ADR-012), and
  `flask-route-no-auth-decorator` reports the route as before, under the same
  identity.
  - **Severity.** The finding that remains is MEDIUM severity with LOW
    confidence. The removed rule's finding was HIGH with MEDIUM confidence, so
    reports show one HIGH finding fewer per unprotected route, and at MEDIUM
    the route's finding is below a `--fail-on HIGH` threshold. Without
    corroboration, the confidence gate held both findings at WARN.
  - **Protected routes.** A route protected by `@requires_auth`,
    `@jwt_required(...)` or `@auth.login_required` below `@app.route(...)` is
    no longer reported. The removed rule knew only `@login_required`.
  - **Baselines.** Baselines and `.fendix-ignore` entries that pinned
    `flask-missing-login-required` stop matching, and its GitHub Code Scanning
    alerts close on the next upload. The route stays reported by
    `flask-route-no-auth-decorator`.
  - The security catalog lists one check fewer.

- **Semgrep no longer scans build output or vendored code, in any
  language.** Every Semgrep run now skips `node_modules/`, `dist/`, `build/`,
  `.next/`, `target/` and `vendor/` at any depth, and every `*.min.js` file.
  A finding there is in code the project does not write, or in a copy of
  code it does.
  - **Python too.** `dist/` and `build/` are also where Python packaging
    writes its output, so they are skipped for Python as well. This is
    deliberate. A Python package that is itself named `build`, `dist`,
    `target` or `vendor` is skipped with them.
  - **What changes.** Semgrep already skipped `node_modules/`, `build/`,
    `dist/`, `vendor/` and `*.min.js` by default, but only in a project with
    no `.semgrepignore` of its own. A project that has one had them scanned,
    and `.next/` and `target/` were scanned in every project.
  - **What does not.** The patterns match paths below the scanned
    directory: a repository checked out under `/srv/build/` is scanned, and
    so is a file named `build.py`. A `--diff` scan that changes only files
    under these directories gets no Semgrep findings from them. Other
    analyzers are unaffected.
  - The framework parity gate shows no case change. The corpus has no such
    directory.
  - **Superseded twice.** First, a directory or file was no longer left out of
    Semgrep's scope by its name: `node_modules/`, `dist/`, `build/`, `.next/`,
    `target/`, `vendor/`, `*.min.js` and the Python environment names were
    scanned unless the directory or the file itself carried evidence that it was
    installed, built or minified code. **Then round 5 removed that evidence rule
    too (decision D5-2): every supported file at or below the size cap is
    scanned, whatever it looks like, and nothing is excluded for a name, a
    marker file, a banner or a header.** A project's own code in a directory
    called `vendor/` or `build/` is scanned. See "Source scope: everything under
    the cap is analysed (round 5)" under Security.

- **Semgrep's deadline is 300 seconds, up from 120, a rule may run for 30
  seconds on one file, up from 5, and a rule that times out is reported.**
  - **Per-rule timeout.** Semgrep gives up on a rule after `--timeout`
    seconds on one file and drops that rule's matches there. The default, 5
    seconds, can cut a taint rule off on a large file. Fendix now passes
    `--timeout 30`. The bound stays: without one, a single pathological file
    could use up the whole deadline, and a run past the deadline fails with
    no Semgrep findings at all. Semgrep's `--timeout-threshold` (3) still
    applies: after three rules time out on one file, it skips the remaining
    rules on that file, and that file's skipped rules are lost evaluation too.
  - **Timeouts are no longer silent, and a run that lost evaluation is
    `failed`.** Semgrep lists each timed-out rule and file in its output's
    `errors`, which Fendix used to ignore. Each one is now logged with the
    rule and the file. As first written this entry kept such a run `ok`, with
    a `detail` naming the timed-out rules and files, so coverage read
    complete although those rules' matches were missing. That is reversed:
    a run in which any selected rule was not evaluated on an in-scope file is
    recorded `semgrep` `failed`, reason `timeout` or `execution_error`, with
    a detail that counts what was lost (see "A Semgrep run that lost rule
    evaluation is recorded failed" under Security). The findings the run did
    produce are kept. A run that is killed or does not load a rule is still
    `failed`.
  - **A malformed `errors` entry is skipped.** Each entry is decoded on its
    own, and an `errors` field that is not a list is ignored, so the results
    beside them are always kept.
  - **Deadline.** The 300-second deadline bounds the whole run, which
    executes every bundled pack at once. As first written it was one process
    with one deadline for the whole tree. The 300 seconds are now one budget
    for the whole Semgrep stage, spent across per-language invocations and
    retries, and Semgrep also gets `--jobs` and `--max-memory` sized for the
    container (see "Semgrep runs inside a bounded budget" under Security).
  - On the parity corpus `make parity` took 552 seconds, against 567
    before this change, and no scan took longer than 1.3 seconds.

### Fixed

- **A Jinja2 template rendered by an autoescaping environment is no longer
  reported as reflected XSS.** `Environment(autoescape=True)`,
  `Environment(autoescape=select_autoescape(...))` and Flask's
  `app.jinja_env` (or `current_app.jinja_env`) escape what `.render(...)` is
  passed, but `env.get_template("a.html").render(name=request.args["n"])` was
  still reported `PY_XSS_HTML_SINK` HIGH with a proven path. `select_autoescape`
  counts for a template whose extension it covers (`html`, `htm`, `xml` unless
  the call lists others), and for `from_string` unless `default_for_string=False`.
  `Environment()` with no `autoescape`, `autoescape=False`, an argument the
  analyzer cannot read, and a file that later sets `<env>.autoescape` to
  anything but `True` are still reported.

- **A rebound import no longer proves a cross-file SQL or command injection.**
  `from svc import find`, then `find = print` (or a later `def find`), then
  `find(request.args["n"])` was reported against `svc.find` with a proven
  path, though the call is not of `svc.find`. A name one scope binds both by
  import and by assignment, `def`, `class`, loop or `with` no longer names the
  imported function, so the helper's finding stays, unproven.

- **A host Semgrep older than 1.111.0 no longer fails the whole run on an
  unknown option.** The scanner always passed `--project-root`, which Semgrep
  1.110.0 and older reject ("No such option"), so a host `semgrep` on PATH at
  the 1.45.0 that v3.7.0 documents support for recorded `failed` and lost
  every Semgrep finding. Fendix now reads `semgrep --version` once per binary
  and leaves out an option the version predates: `--project-root` (1.111.0),
  `--dataflow-traces` (0.107.0), `--timeout` (0.17.0), `--exclude` (0.12.0),
  logging a warning and naming the dropped options in the Semgrep
  `scanner_status` detail (`semgrep 1.45.0: dropped --project-root (needs
  1.111.0)`). As first written the status stayed `ok` for every dropped
  option. Without `--project-root` the packs' path filters are matched
  against the enclosing git root, so files can be excluded with no error;
  dropping it is now recorded `failed` (`execution_error`), with the note
  `files may be skipped: the packs' path filters need --project-root`.
  Dropping `--dataflow-traces`, `--timeout` or `--exclude` loses no
  detection and stays `ok` with the note. An unreadable version is run with
  every option.
  - **The version probe no longer stalls an offline scan.** As first
    written `semgrep --version` ran with Semgrep's version check on, so
    offline it waited for semgrep.dev until a 30-second cap, inside the
    run's own deadline, and a failed read was not remembered, so every scan
    paid it again. The probe now runs with `SEMGREP_ENABLE_VERSION_CHECK=0`
    and `SEMGREP_SEND_METRICS=off`, is bounded at 10 seconds, runs before
    the run's deadline starts, and a failed probe is remembered per binary
    for the process (one cut short by a cancelled scan is not). An unknown
    version still gets every option. Documented
  in `docs/checks/semgrep.md`; the docs also name `--project-root` in the
  command, and `ADR-011` gives the 300 s run timeout.

- **The published development-corpus figures match the committed baseline.**
  `README.md`, `BENCHMARKS.md`, `docs/accuracy.md` and
  `benchmarks/frameworks/RESULTS.md` quoted Java at recall 0.972 and block
  recall 0.083, and RESULTS.md's headline, family, coverage-by-class and
  harder-variant tables, its secrets, Java, Go and JS/TS safe-code figures
  and its Python rows were older measurements. They are recomputed from
  `benchmarks/frameworks/baseline.json`: Java 36/36 detected and 4 blocking
  (recall 1.000, block recall 0.111), and no false positive in any of the nine
  frameworks. Each place that quotes the blind holdout (commit `e03655a`) or
  the real-world precision (commit `6901cf7`, Semgrep 1.141.0) now names the
  commit and Semgrep version it was measured at. The holdout and real-world
  figures were not re-measured: they describe those older commits and
  Semgrep 1.141.0, not this release, and are pending re-measurement at the
  release commit (see "Published accuracy figures are pending
  re-measurement" under Security).

- **The Go taint rules keep their `ok` cases clean on Semgrep 1.182.1, the
  version Fendix ships.** The Go pack was written on Semgrep 1.141.0. Semgrep
  1.182.1 keeps the taint of a variable assigned from a call that an exact
  sanitizer clears (`$x := f(...)`, `x = f(...)`, `var x = f(...)`), which 1.141.0
  cleared, so `go-sqli-taint` and `go-path-traversal-taint` reported a column
  or a row looked up through a constant helper or a same-file method. Each Go
  call sanitizer now also matches the assignment, in every Go taint rule. The
  sink-in-receiver case (`exec.Command(...).Run()`) is kept: the sanitizers are
  not made non-exact. The rule tests (51) pass on 1.182.1 and on 1.141.0.
- **The Python engine's JavaScript SQL check no longer fires on tagged
  templates or constant-only templates, and steps aside when Semgrep ran.**
  `SEC-JS_SQL_TEMPLATE` flagged every template literal with a SQL keyword and
  a `${...}`, including `sql`...${id}``, `prisma.$queryRaw`...${id}`` and
  `Prisma.sql`...``, which bind the values as parameters, and a template that
  interpolates only a module-level `const ROLE = 'member'`. Neither is
  reported now; `pool.query(`... '${name}'`)` still is.
  - **The engine's `SEC-JS_*` pattern checks (`SEC-JS_EVAL`,
    `SEC-JS_INNER_HTML`, `SEC-JS_DOCUMENT_WRITE`, `SEC-JS_SQL_TEMPLATE`) are
    now the fallback for a scan without Semgrep** (`--fast`, or no binary).
    When the run-level `semgrep` scanner status is `ok` AND Semgrep's
    JavaScript/TypeScript taint findings can block (both languages are in
    `semgrep.ReachabilityLanguages`), they are dropped and the Semgrep pack
    answers, so one sink is reported once. Until then (the shipped state:
    those findings are warnings) they stay, because `SEC-JS_SQL_TEMPLATE` is
    the only JavaScript SQL finding that blocks; dropping it blocked nothing
    in nine express, NestJS and Next.js `sqli` corpus cases.
  - **A Semgrep run that could not load a rule is now recorded `failed`**
    (reason `execution_error`, detail naming the rule errors). Semgrep exits 7
    with a parseable document and no results for a rule it rejects, which was
    read as a clean run. It keeps the fallback checks on, and
    `--fail-on-scanner-error` sees it.
- **The regex scanner now detects `child_process` exec in every import form.**
  `JS_CHILD_PROCESS_SHELL` only matched the literal `child_process.exec(`, so
  `const { exec } = require("child_process"); exec(cmd)`,
  `import { execSync } from "node:child_process"` and
  `promisify(require("child_process").exec)` were missed. The rule now matches
  `exec(`, `execSync(` and `require("child_process").exec` in a file that
  imports `child_process`, and still ignores a RegExp `.exec(` call. A bare
  `exec(` in a file that never imports `child_process` is not reported.
- **The regex scanner now detects SQL concatenation through JdbcTemplate and
  JPA.** `JAVA_SQL_INJECTION` also fires on `jdbcTemplate.queryForList("SELECT
  ... '" + name + "'")` and `entityManager.createNativeQuery("SELECT ... " +
  x)`, for the receivers `jdbcTemplate`, `namedParameterJdbcTemplate`,
  `template`, `stmt`, `statement`, `em`, `entityManager` and `session` with
  `query*`, `update`, `execute`, `batchUpdate`, `createQuery`,
  `createNativeQuery` and `createSQLQuery`. The receiver is required, so a
  bare `executor.execute(makeTask("update " + x))` stays clean, and a
  parameterized `queryForList("... WHERE name = ?", name)` does not fire. A
  query concatenated only from `static final String` constants of the file is
  not reported (the same file-constant check as `GO_SQL_INJECTION`).
- **The regex scanner no longer flags SQL and exec calls built only from
  file constants.** `GO_SQL_INJECTION`, `GO_EXEC_COMMAND_INJECTION` and
  `JAVA_EXEC_COMMAND_INJECTION` skip a call when every argument of it
  (a literal, a `+` join, a `fmt.Sprintf` over such arguments, or a
  `new String[]{...}` of them) is built only from string constants declared in
  the same file: Go `const X = "..."` (alone or in
  a `const ( ... )` block) or Java `static final String X = "...";`. A `var`, a
  non-final field, a call, a field access or any mix with a variable, in any
  argument of the call, still fires (`exec.Command("sh", "-c", user,
  "x="+TABLE)`). This removes the false positives on
  `db.Query(fmt.Sprintf("... FROM %s", usersTable))` and
  `sh -c "df -h " + dataVolume`.
- **The regex scanner now matches calls whose arguments contain a nested
  call.** `GO_SQL_INJECTION`, `GO_EXEC_COMMAND_INJECTION`,
  `JAVA_EXEC_COMMAND_INJECTION`, `JAVA_SQL_INJECTION`, `JAVA_SSRF`,
  `JAVA_XSS_REFLECTED` and `JAVA_PATH_TRAVERSAL` stopped at the first inner
  `)`, so `exec.CommandContext(r.Context(), "sh", "-c", "ping "+host)` and
  `db.QueryRowContext(r.Context(), fmt.Sprintf(...))` were missed. They now
  cross one level of parentheses. Matching stays linear-time (RE2).
- **A Semgrep taint rule and its sink twin on one line are reported once.**
  With the taint gate closed, `js-cmdi-taint` and `js-cmdi-sink` (and the
  other `<base>-taint` / `<base>-sink` pairs of the JavaScript, Java and Go
  packs) both report as `semgrep_shim` findings, so one `exec("ping " + host)`
  showed twice. The pair now collapses into the taint finding, with the sink
  rule's references folded in. Severity is never raised, the taint finding's
  fingerprint is unchanged, and two different rule bases on one line stay two
  findings.
- **A proven taint chain survives when two analyzers report the same line.**
  When textscan and a taint analyzer both flagged one sink, the collapse kept
  the textscan finding on a tie and dropped the other member's taint chain,
  `reachable` and `proven_path`, so a proven injection read as an unproven
  pattern match. The kept finding now takes the chain of the member with the
  longest one, with its `reachable` and `proven_path` flags. Its severity and
  wording stay its own, and nothing is synthesized when no member proved a
  flow.

- **Semgrep now scans a target inside a git work tree as its own project.**
  Semgrep matches a rule's `paths.exclude` patterns, and its default ignore
  list, relative to its project root, which inside a git work tree is the git
  root and not the scanned directory. Scanning `<repo>/fixtures/repo`,
  `<repo>/mock/repo` or `<repo>/spec/repo` therefore had the JavaScript, Java
  and Go packs' test-code exclusions (`fixtures/`, `mock/`, `spec/`, `tests/`)
  applied to every file of the target, so nothing was scanned: no error, and
  an empty `paths.scanned`. Fendix now passes `--project-root <scan target>`,
  so the exclusions are relative to the directory it was asked to scan.

- **`flask-route-no-auth-decorator` now reports an auth decorator placed
  above `@app.route(...)`.** Such a decorator does not protect the route:
  `route()` registers the function below it, so a decorator above it wraps a
  copy the URL never calls. Semgrep matches a function's decorators in any
  order, so the rule treated `@login_required` above the route like
  `@login_required` below it, and neither Flask rule reported it.
  `@requires_auth`, `@jwt_required(...)` and `@auth.login_required` above the
  route were reported only by the removed `flask-missing-login-required`.
  - **Now reported:** a route with one of the rule's four decorators above
    `@app.route(...)` and no auth decorator below it. The four are
    `@login_required`, `@requires_auth` and `@auth.login_required`, bare or
    with empty parentheses, and `@jwt_required` with or without arguments.
    Other decorators may sit between the two, and the route call may span
    several lines. The finding is on the `@app.route(...)` line, once per
    route.
  - **What counts as an auth decorator below the route** when one of the four
    sits above it: a decorator line between `@app.route(...)` and the `def`
    that names `login_required`, `requires_auth` or `jwt_required`, with or
    without a module prefix and with any arguments. So `@login_required`
    above with `@requires_auth("admin")` or `@flask_login.login_required`
    below is not reported. A commented-out decorator does not count.
  - **Unchanged:** a route with none of the four decorators is reported as
    before, including one whose only auth decorator is
    `@requires_auth("admin")` or `@flask_login.login_required` below the
    route, because the rule's list of decorators is unchanged. The rule's
    existing findings keep their identity.
- **`fastapi-route-missing-auth-dependency` now recognises a dependency
  declared through an `Annotated` alias.** The rule already treated
  `user = Depends(...)`, `user: User = Depends(...)` and
  `user: Annotated[User, Depends(...)]` (and the same with `Security(...)`) as
  a route's authentication, but it reported a route whose parameter used an
  alias, the idiom of FastAPI's own docs and project template:
  `CurrentUser = Annotated[User, Depends(get_current_user)]`, then
  `current_user: CurrentUser`. On `full-stack-fastapi-template` it reported 16
  routes. 15 of them take `CurrentUser` or `SessionDep` imported from
  `app.api.deps`: 11 are authenticated, and 4 public routes have only the
  database session. It now reports only the `health-check` route, which has
  no dependency at all.
  What counts as a dependency is unchanged: any `Depends(...)` or
  `Security(...)` counts, as before, so a database-session alias such as
  `SessionDep = Annotated[Session, Depends(get_db)]` counts too.
  - **Now recognised:**
    - an alias assigned at module level in the same file, before the route;
    - an alias imported from a module named `deps` or `dependencies`
      (`from app.api.deps import CurrentUser`,
      `from ..dependencies import CurrentUser`), under the name the import
      binds in the file (`from app.api.deps import CurrentUser as CU`, then
      `c: CU`). The rule cannot see that alias's definition, so a
      dependency-free route whose parameter is any name imported from such a
      module is not reported (a false negative);
    - `Depends(...)` or `Security(...)` in any position of `Annotated[...]`,
      inline or in an alias (`Annotated[User, "doc", Depends(...)]`).
  - **Still reported:**
    - a route that does not use the alias, even in the same file;
    - a parameter typed with a model or `Request` imported from anywhere
      else, with an inline `Annotated[str, Query()]`, or with an
      `Annotated[..., Query(...)]` alias;
    - the original name of a renamed deps import:
      `from app.dependencies import Settings as SettingsDep` does not make
      `s: Settings` a dependency;
    - a name imported from a module whose name only contains `deps`
      (`app.mydeps`, `app.api.depsutil`, `app.deps.models`);
    - an alias assigned inside a function;
    - `Alias | None`;
    - an alias imported from a module with another name, or used as
      `deps.CurrentUser`;
    - a dependency set only on `APIRouter(dependencies=[...])`.
  - **Not tracked:** rebinding after the alias or the deps import. An alias
    reassigned to another type, a local class of the same name, or the same
    name imported again from another module still counts as a dependency.
  - The rule's existing findings keep their identity.
- **The Python engine's JavaScript/TypeScript pattern findings now carry a
  `rule_id`.** `JS_EVAL`, `JS_INNER_HTML`, `JS_DOCUMENT_WRITE` and
  `JS_SQL_TEMPLATE` reached the report with `rule_id` empty, unlike the Python
  engine's Python-source findings. The `rule_id` is each finding's own id
  (`SEC-JS_EVAL`, `SEC-JS_INNER_HTML`, `SEC-JS_DOCUMENT_WRITE`,
  `SEC-JS_SQL_TEMPLATE`), which is exactly the rule that fingerprint identity
  already derived from the id. Fingerprints, `.fendix-ignore` matching,
  baseline matching and grouping do not change.

  **GitHub alerts for these four checks will be re-partitioned once.** SARIF
  rule ids key on the `rule_id` where there is one and fall back to the title
  slug where there is not, so their SARIF `ruleId` changes from the title slug
  to the rule slug:

  | Check | Before | After |
  |---|---|---|
  | `JS_SQL_TEMPLATE` | `fendix.injection.sql-query-built-via-template-literal-injection-risk` | `fendix.injection.sec-js-sql-template` |
  | `JS_INNER_HTML` | `fendix.injection.unsafe-assignment-to-innerhtml-xss-risk` | `fendix.injection.sec-js-inner-html` |
  | `JS_DOCUMENT_WRITE` | `fendix.injection.unsafe-use-of-document-write-xss-risk` | `fendix.injection.sec-js-document-write` |
  | `JS_EVAL` | `fendix.injection.unsafe-use-of-eval-in-javascript` | `fendix.injection.sec-js-eval` |

  Existing Code Scanning alerts under the old rule ids close and reopen under
  the new ones on the first upload after upgrading, and an alert you had
  dismissed reappears and must be dismissed again. This is a one-time cost.
  The JSON report's `rule_id` field, and the `rule_id` of a managed-CI evidence
  submission (which fell back to the category, `injection`), now carry the id
  too.
- **A `urlparse(...).netloc` allowlist now counts as an SSRF and
  open-redirect guard in Python.** `python.ast/PY_SSRF` and
  `python.ast/PY_OPEN_REDIRECT` no longer report a request or redirect that
  follows an early exit on the URL's parsed authority, such as
  `if urlparse(url).netloc not in ALLOWED_HOSTS: return ...`. The parse may be
  `urlparse` or `urlsplit`, inline or through a local (`p = urlparse(url)`),
  and the check may be joined to others with `or`
  (`if p.scheme != "https" or p.netloc not in ALLOWED_HOSTS:`). The guard
  counts only when it is a top-level `if` of the function that ends before
  the sink, its body returns, raises or aborts, and it checks a literal set,
  list, tuple or dict. It covers the guarded URL passed as it is, or followed
  by more text (`requests.get(url + "/v1")`). These are still reported:
  - a `.hostname` allowlist, because a backslash in the authority makes
    urllib3/requests and browsers connect to a different host than the one
    `urlparse` reports (`https://169.254.169.254\@api.example.com/` has
    hostname `api.example.com`, but requests connects to `169.254.169.254`);
  - an allowlist that contains `""`, because `/\evil.com` and `https:evil.com`
    have an empty netloc and browsers send both to `evil.com`;
  - a URL built around the guarded one, as in `"https://" + url` or
    `"https://%s" % url`: `evil.com://api.example.com/x` passes the guard,
    and `https://` in front of it sends the request to `evil.com`;
  - a check joined with `and`, which can skip the host test;
  - an allowlist read from the environment or built by a call;
  - a guard that only logs, a sink inside the branch that rejects the host,
    and a guard that comes after the sink;
  - the same value passed to an XSS or path sink, because the guard bounds
    the host only.
- **A resolved path checked against its base directory now counts as a
  path-traversal guard in Python.** `python.ast/PY_PATH_TRAVERSAL` no longer
  reports a file opened or sent after the code resolves the path and leaves
  when it is outside a fixed base directory. Two forms count:
  - `full = os.path.realpath(...)`, then
    `if os.path.commonpath([base, full]) != base:` or
    `if not full.startswith(base + os.sep):` (`base + "/"` and
    `os.path.join(base, "")` work too);
  - `full = <pathlib path>.resolve()`, then
    `if not full.is_relative_to(base):`, or `full.relative_to(base)` in a
    `try` with an `except ValueError` (or `Exception`, `BaseException`, or a
    bare `except`).

  The base must be a string constant, `os.path.realpath` of one, or
  `Path(...)` or `Path(...).resolve()` of one, inline or through a name. It
  must not be the filesystem root. A module-level name must be assigned once
  in the module and declared `global` by no function. Inside a method the
  name is the module's, never a class attribute of the same name, so the
  module's value is the one checked. The resolved path must be assigned once, in
  a top-level statement of the function. The check must be a top-level
  statement between that assignment and the sink, and it must return, raise or
  abort; in the `try` form, every `except` clause must. These are still
  reported:
  - `full.startswith(base)` without a separator, which also lets through
    `/srv/reports_evil/x`, and `full.startswith(base + "\\")`, because on POSIX
    a backslash is an ordinary filename character;
  - a path that is only joined, or normalised with `os.path.abspath` or
    `os.path.normpath`. A joined path keeps its `..`, and `commonpath`,
    `startswith` and `is_relative_to` compare text, so
    `/srv/reports/../../etc/passwd` passes all three. `abspath` and `normpath`
    remove `..` but follow no symlink, so a link under the base that points
    outside it passes;
  - a resolved path that is never checked;
  - a base read from the request, the environment, a function parameter or
    any other call, and a base of `/`;
  - a module-level base that is assigned again anywhere in the module, or
    that a function declares `global`;
  - a path assigned more than once in the function, or on a branch, and the
    same for a name it is copied to (`p = full`);
  - a lambda or nested function with a parameter of the same name
    (`lambda full: open(full)`), which opens its own argument, not the checked
    path;
  - `startswith` with a start offset and `relative_to(base, walk_up=True)`;
  - a check that only logs, a `try` with an `except` clause that falls
    through, a sink inside the branch that rejects the path, and a check that
    comes after the sink.

  **The join line is no longer reported when the check covers it.** An
  `os.path.join(...)` written directly inside `os.path.realpath(...)` was
  reported on its own line, above any check, so a correctly checked handler
  was still reported there. That join is now skipped only when all of these
  hold:
  - the `realpath(...)` or `Path(...).resolve()` around it is assigned once,
    to a name, in a top-level statement;
  - an accepted check on that name follows;
  - every other use of the name comes after the check.

  Otherwise the join is reported on its own line as before. That includes:
  - a join under `os.path.abspath(...)`;
  - a resolved path passed straight to a call, as in
    `os.remove(os.path.realpath(os.path.join(...)))`;
  - a resolved path that reaches a file operation the engine does not model
    as a sink (`os.remove`, `shutil.copy`, Starlette's `FileResponse`) before
    or without a check;
  - a resolved path returned to the caller;
  - a resolved path used in the branch that rejects it.

  In a checked handler, a baseline entry for that `os.path.join(...)` finding
  no longer matches anything, and no new finding replaces it.
- **The Semgrep rule `python-sql-injection-string-format` no longer reports
  an f-string query that interpolates only string constants.**
  `cursor.execute(f"SELECT id FROM {USERS_TABLE}")`, with
  `USERS_TABLE = "users"` at module level, builds no injectable query. The
  rule now skips an interpolation that Semgrep's constant propagation
  resolves to a string literal: a module-level name assigned once, to a
  literal, and a local that holds a literal on every path to the call
  (`table = "users"`, or `"users"` and then `"admins"` on a branch). Each
  interpolation is checked on its own. These are still reported:
  - an f-string with any interpolation that is not such a constant, as in
    `f"SELECT {COLS} FROM users WHERE n = '{name}'"`;
  - a name rebound from input before the call in the same function,
    including a function-local rebinding of a module constant and
    `where = ""` followed by `if name: where = f"... {name} ..."`;
  - a module constant assigned more than once in the module, or assigned in
    any function that declares it `global`;
  - a name that a nested function declares `nonlocal`, as in
    `def add(cond): nonlocal where; where += cond`. Constant propagation
    works one function at a time and does not see that rebinding;
  - every f-string query inside a lambda, constant or not, for the same
    reason: the lambda can run after the name it reads is rebound;
  - a parameter that shadows a module constant, even with a literal default;
  - a class attribute (`self.TABLE`), a name that is only imported, an
    annotated assignment (`TABLE: Final = "users"`), a subscript
    (`TABLES[key]`), an inline expression (`{PREFIX + "users"}`) and a
    non-string constant (`LIMIT = 10`);
  - queries built with `%`, `+` or `.format(...)`, which are unchanged.

  One shape is no longer reported although the value comes from elsewhere: a
  module literal replaced by an import of the same name, at module level
  (`TABLE = "users"`, then `from settings import TABLE`) or inside the
  function (`from userinput import TABLE`). Constant propagation keeps the
  literal's value there.

  Where the rule reported such a query, a baseline entry for that finding no
  longer matches anything, and no new finding replaces it.
- **A Python sink in a helper function is now proven reachable when the caller
  assigns the request value before passing it.** The engine follows a helper's
  parameter back to the calls of that helper in the same file. It proved the
  flow only when the request expression was the argument itself, as in
  `_ping(request.GET.get("host"))`. The common form,
  `host = request.GET.get("host")` and then `_ping(host)`, was reported but not
  proven. The argument is now traced through the caller's own assignments.
  Such findings are marked reachable and carry a taint chain: the caller's
  request expression first, then the caller's assignments, then the call, then
  the sink. Like any proven finding, they take the rule's proven title and
  severity where it has one (`python.ast/PY_PATH_TRAVERSAL` rises from MEDIUM
  to HIGH), the engine escalates them one level as reachable, and they may now
  block.
  - **Identity.** SSRF, open-redirect, path-traversal and XSS findings keep
    their identity. The command-injection rules (`python.ast/PY_OS_SYSTEM`,
    `python.ast/PY_OS_POPEN`, `python.ast/PY_SUBPROCESS_SHELL`) and
    `python.ast/PY_SQL_INJECTION` name their sink only when the flow is
    proven, so a finding of theirs that this change proves is identified by
    its sink instead of its evidence line. A baseline entry or a
    `.fendix-ignore` `fingerprint:` rule for it stops matching, and it is
    reported as new once.
  - **One more finding for a path built with `os.path.join`.** A newly proven
    helper such as `open(os.path.join(BASE, name))` also reports the inner
    `os.path.join(...)`, which is reported only when the flow is proven. The
    same code written in the handler already reports both.
  - **Which assignment counts:** for each name, the last one that comes before
    the call in source order. So `host = request.GET["h"]; host = "localhost";
    _ping(host)` is not proven, and a constant assigned after the call does not
    hide the request value assigned before it. A loop or branch is not
    modelled: only source order decides.
  - **Followed in the caller:** plain, tuple, annotated and augmented (`+=`)
    assignments, `for` targets and `with ... as` targets, made in the calling
    function itself, or at module level for a call made there. An assignment
    in a nested function, lambda or class does not count for the function
    around it.
  - **Caller-side sanitisers still count, for the sink they protect.** A
    caller that passes the value through a guard or sanitiser that the
    helper's own sink would honour inline does not prove the helper's
    finding. Each counts only for its sink class (corrected; as first written
    this entry said "whichever sink the helper holds", and the engine did
    that: see "Python sanitisers count only for the sink they protect" under
    Security):
    - an `if value not in ALLOWED: return` membership guard over constants:
      any sink;
    - a `urlparse(value).netloc` allowlist guard over constant hosts: a URL
      sink that takes the whole value;
    - a resolved path checked against its base directory, or `basename`: a
      path sink;
    - escaping, including an f-string whose every value is escaped: an HTML
      sink;
    - `shlex.quote`: a shell sink;
    - an allowlist lookup (`HOSTS.get(value)`) over constants: any sink;
    - `url_for(...)` or `reverse(...)`: HTML, URL and path sinks;
    - a URL with a fixed scheme and host (`"https://api.example.com/" + value`):
      a URL sink.

    The guard must come before the call, as it must come before a sink. This
    applies to a request expression passed inline too, which proved before:
    `_render(escape(request.args["n"]))` no longer proves.
  - **Not followed:** a call inside a lambda, comprehension or class body,
    which still proves only with the request expression passed inline; a
    method call (`self._ping(host)`); and the caller's own parameters, which
    are not traced into its callers (one hop only). A helper whose callers
    all pass constants is not proven. A caller in another module is now
    followed as well (see "A Python sink in a helper is now proven when a
    view in another module passes it request input").
  - **A bare-name call no longer proves a method's parameter.** `handle(h, p)`
    calls the function `handle`, never a method of that name, but it was
    matched against a method's parameters too, `self` included. With `p` from
    the request, a `Pinger.handle(self, host)` sink was proven reachable.
  - **Framework parity:** the Django and Flask `indirect` cases for SQL
    injection, command injection, SSRF, path traversal and open redirect, and
    Flask's `ssti` `indirect` case, now block. No development-corpus safe case blocks.
- **A Python file is no longer skipped when a variable is rebound from
  itself.** `url += "/x"` on a parameter binds `url` to `url + "/x"`,
  `desc = "<p>" + desc + "</p>"` binds `desc` to an expression that reads
  `desc`, and `html = html` binds `html` to itself. The sanitiser and escape
  checks that the SSRF, open-redirect, path-traversal and XSS sinks run
  followed such a binding back into itself until it hit Python's recursion
  limit. The engine then skipped the rest of the file, with every finding after
  that point. Such a value is now not sanitised or escaped, so its sink is
  reported and the file is analysed to the end. Findings this restores are
  new.
- **A value repeated by a number is no longer treated as escaped.**
  `"&nbsp;" * depth` is inert, because it can only hold the constant's own
  characters. But any expression multiplied by a constant counted as escaped
  too, so `mark_safe(name * 2)` and `Markup(f"<b>{name * 2}</b>")` were not
  reported. Now only a constant string repeated is inert. These findings are
  new.

### Fixed

- **`fendix verify` keeps findings from the JavaScript/TypeScript, Java and Go
  Semgrep rules.** A finding of a `-taint` or `-sink` rule in those packs (tier
  `semgrep_shim` today, `semgrep_taint` once a language gate opens) is reported
  `unknown` with the rule id and a "re-run `fendix scan`" instruction, rather
  than as an unsupported shape, and is never reported `resolved`. A finding in
  an `.mjs`, `.cjs`, `.mts` or `.cts` file is recognised as a file finding.
- **`fendix verify` no longer calls a finding resolved when its scanner cannot
  read the file.** A `secrets` finding in an `.mjs`, `.cjs`, `.mts` or `.cts`
  file (textscan reads them, the secrets scanner does not) was reported
  `resolved` because the re-test could never re-emit it. It is now `unknown`,
  with the extension named. A Semgrep-tier finding is kept before any other
  scanner re-tests it.
- **`fendix verify` no longer resolves a secret the scanner skips by path or
  size.** A `secrets` finding in a file over 1 MiB was reported `resolved`, and
  one under `node_modules/`, `vendor/`, `dist/` or `build/` was judged by a
  re-scan rooted at its own directory instead of the scan root. Both are now
  `unknown`, with the skip named. (The secrets scanner now reads files up to
  128 MiB and prunes a directory only on evidence, not by name; what `verify`
  answers is under "`fendix verify` says `resolved` only after it searched for
  the credential itself" in Security.)
- **These three entries did not close the false `resolved`.** Every other
  `secrets`-category finding was still re-tested by the secrets scanner and
  matched by exact title, so a textscan or Python-engine finding the secrets
  scanner never produces (`GO_HARDCODED_AWS_KEY`, `JS_HARDCODED_AWS_KEY`,
  `GO_WEAK_HASH_PASSWORD`, `python.ast/PY_WEAK_CRYPTO_PASSWORD`) was
  reported `resolved`, exit 0, on unchanged code. That is fixed: see "`fendix
  verify` re-tests a secret only with the scanner that produced it" under
  Security.

- **The Action says enforcement was off in every outcome.** With
  `require-analyzers: none`, the gate warned "Fendix coverage not enforced"
  only on a pass. A BLOCK (exit 1), a scan error (exit 2) or a setup failure
  printed its error without saying that required-analyzer enforcement was
  off. The job was already red, but its output did not show that coverage was
  never enforced. Now every outcome adds the warning when the requirement is
  `none`. Found by the v3.7.0 Action end-to-end run.
- **A required analyzer disabled by another flag no longer reads as complete
  coverage in the gate.** Under `extra-args: --fast`, the engine prints
  `coverage: complete` next to `required: not delivered (semgrep)`, and
  the gate's job summary showed "Coverage: complete" for the failed run. The
  engine line stays as it is, because it is `coverage.configured_complete`,
  which by contract (`docs/schema.md`) never counts a disabled analyzer as a
  gap and is not changed by `--require-analyzers`, and a test pins it. The
  gate now words it "complete for the analyzers configured to run, but
  required not delivered (semgrep)", in its message and its job summary.

### Security

These entries come from a security review of the changes above. Each one
either fixes a defect those changes introduced or exposed, or corrects a claim
made above. They take precedence over the entries above where the two differ.

- **A Semgrep run that lost rule evaluation is recorded `failed`.** A
  per-rule timeout, a rule skipped by `--timeout-threshold`, a taint fixpoint
  timeout, a per-file timeout, out of memory or stack overflow, an internal
  matching error, too many matches, rules Semgrep reports as skipped, and a
  dropped `--project-root` all mean that some selected rule was not evaluated
  on some in-scope file. That rule's findings are missing there, but the run
  was recorded `semgrep` `ok`, so coverage read complete and a scan with
  nothing else to report passed. Semgrep also reports a taint fixpoint
  timeout only in its `--time` profile, which Fendix did not request, so
  JavaScript/TypeScript and Go taint findings in a large file could vanish
  with no trace at all.
  - **Now:** Semgrep always runs with `--time`, and the engine reads the
    profile's `fixpoint_timeouts`. A run that lost evaluation is `failed`,
    with reason `timeout` when every loss is a timeout (rule, threshold,
    fixpoint or interfile timeout) and `execution_error` otherwise. Its
    detail starts `lost evaluation:` and counts what was lost (`<N> rule
    timeouts on <F> files`, `every other rule skipped on <F> files after 3
    rule timeouts`, `<N> taint fixpoint timeouts on <F> files`, `<N> per-file
    errors (<type> <n>, ...)`, `<N> rules skipped by semgrep`), then names the
    first files and rules. Findings the run did produce are kept. A Semgrep
    whose profile has no fixpoint list is `failed` (`execution_error`),
    because a fixpoint timeout would be silent.
  - **Parse problems, as first written, and reversed.** As first written a
    file that only partly parsed (a syntax, lexical or partial-parsing
    problem) kept the run `ok` with the problem count in its detail. A file Semgrep
    cannot parse at all (`Syntax error`, `Lexical error`, `Other syntax
    error`, `AST builder error`) is now lost evaluation, and a partial parse
    stays `ok` only when the lines Semgrep skipped are reported and few; see
    "A file that does not parse, and a file Semgrep did not read, are lost
    evaluation" below.
  - **Effect.** More scans now record `semgrep` `failed`: the blind
    real-world evaluation saw rule timeouts in 11 of 70 repositories. Such a
    scan's coverage is incomplete, `--fail-on-scanner-error` exits 2 on it,
    and a consumer that treats `failed` as a coverage gap (the hosted backend
    does) treats it as one. Fixpoint timeouts depend on load, so the same
    file can lose its taint matches on one run and not the next; the run
    that lost them now says so. A host Semgrep older than 1.111.0 (no
    `--project-root`) is now always `failed`; upgrading Semgrep is the fix.
    As first written, files Semgrep skips for size (`--max-target-bytes`)
    were not reported as lost; they now are (see the entry named above).
  - The scanner-status vocabulary is unchanged: no new state or reason.
- **The Java Semgrep packs cost less on a large class (partial).** The
  guards and the one-hop helper patterns shared by the Java taint and shape
  rules in `java-injection.yaml` and `java-web.yaml` were restructured
  without changing rule ids, messages or metadata. Findings were identical on
  every measured target, the rule tests pass, and the Spring parity gate shows
  no case change. On a generated 3,000-line controller the Java packs took
  41 to 46% less Semgrep match time. They are still superlinear: a 7,400-line
  Spring class still loses all its Semgrep findings to three rule timeouts,
  which is now recorded `semgrep` `failed` (`timeout`), as above.
- **The JavaScript and TypeScript packs match fewer bare patterns (R-008, part
  1).** Semgrep matches a bare metavariable pattern against every expression of
  a file, and the sanitizer items of four JavaScript rules each did it once. 16
  such items were merged into 4, one per rule (`js-ssrf-taint` 5 to 1,
  `js-open-redirect-taint` 6 to 1, `js-path-traversal-taint` 3 to 1,
  `js-sqli-taint` 2 to 1), as nested `patterns` alternatives, in
  `javascript-web.yaml` and `javascript-injection.yaml`. Rule ids, messages and
  metadata are unchanged (`docs/security-catalog-contract.json` is byte for byte
  the same, 158 checks), and the rule tests pass (`semgrep --test` on Semgrep
  1.182.1: 51 of 51). New fixtures,
  `ruletests/javascript-web.merged-sanitizers.ts` and
  `ruletests/javascript-injection.merged-sanitizers.ts`, hold one handler per
  merged alternative, so dropping an alternative makes its handler a reported
  line; guard shapes the rules still report with this instantiation are left
  out of them on purpose, so they freeze no behaviour nobody chose, and two
  `startsWith` families of `js-path-traversal-taint` are not exercised by any
  fixture (the rule tests and the framework corpus did not either). Match time
  falls on large JavaScript files; the figures are in the work notes of that
  round and are not quoted here. **Not fixed, because it would weaken
  detection:** the one-hop helper patterns of the seven Java taint rules (a
  very large Java class can still cost close to the 30-second per-rule bound
  for `java-open_redirect-taint`, and the retry above is what keeps its
  verdict stable), and the Go pack, whose sanitizer items carry dozens of negated
  conjuncts and were not shown equivalent when merged.
- **A file that does not parse, and a file Semgrep did not read, are lost
  evaluation.** Semgrep's own JSON names the files it evaluated
  (`paths.scanned`) and nothing about the ones it did not. A file over
  `--max-target-bytes`, one it could not read, one it could not parse and one a
  `.semgrepignore` named all vanished with the run exit 0 and `semgrep` `ok`,
  and every finding in them missing.
  - **Now:** the engine lists the in-scope files Semgrep was meant to evaluate
    (every regular file under `--code`, or every changed file of a `--diff`
    scan, with an extension of the packs' languages in any letter case: `.py`,
    `.pyi`, `.js`, `.jsx`, `.cjs`, `.mjs`, `.ts`, `.tsx`, `.java`, `.go`, and
    the four Semgrep does not select, `.cts`, `.mts`, `.es6`, `.vue`) and
    compares the list with `paths.scanned`. A file over 1048576 bytes, one
    that cannot be opened, a directory that cannot be listed and one absent
    from `paths.scanned` are lost evaluation: `semgrep` is `failed`,
    `execution_error`, the findings of the rest of the run are kept, and the
    detail names the files: `lost evaluation: 3 in-scope files not read: 1
    over 1048576 bytes (big/huge.js), 1 unreadable (a.py), 1 not evaluated by
    semgrep (c.js)`. A document with no `paths.scanned` list loses every file
    it was meant to evaluate.
  - **A file Semgrep cannot parse is a gap.** An error of type `Syntax error`,
    `Lexical error`, `Other syntax error` or `AST builder error` (and the
    constructor spellings `ParseError`, `LexicalError`, `OtherParseError`,
    `AstBuilderError`) means Semgrep ran no rule on that file. It is listed as
    `<k> not parsed by semgrep (<path>)` in the same segment, whatever
    Semgrep's exit code says. As first written such a file left the run `ok`.
  - **A partial parse stays `ok` only when the engine can show that what was
    skipped holds no analysable code (round 5, C4B-27).** Semgrep reports
    `PartialParsing` with the line spans it skipped. The run stays `ok` only when
    every span is reported, lies inside the file, and **every line it touches is
    blank or a whole-line comment** (`#` for Python; `//`, or a one-line `/* ... */`,
    for JavaScript, TypeScript, Java and Go), judged by the engine from the file,
    one line at a time; the detail then says which lines: `partial parse, 2 files
    with skipped lines: a.py 4, b.js 10-12` (`1 file` for one). A partial parse
    with no span, with a span outside the file, or that skipped **any line of
    code, however few lines or small the share**, is lost evaluation like a
    whole-file failure: `not parsed by semgrep (<path>)`. The round-4 allowance of
    `min(max(3, 5%), lines - 1)` skipped lines let a skipped long line that held
    the handler stay `ok`. Measured on this tree: an 80-line `src/partial.js` with one
    skipped line `const bad = @@@;` reads `failed` / `execution_error`, `1 not
    parsed by semgrep (src/partial.js)`. **Cost:** three of seven realistic
    repositories the round-5 owner scanned (a frontend, a backend and WebGoat) went
    from `semgrep` `ok` to `failed` on a single skipped line of code each; a narrower
    proof (the skipped column range, or a re-run of the file with the failing token
    removed) is an open owner decision.
  - **`.semgrepignore` and Semgrep's default ignore list no longer decide
    what is scanned.** Without it, the scanned repository chose which of its
    own files Semgrep skipped, and when the tree had no `.semgrepignore` at
    its root Semgrep applied its built-in list, which drops `tests/` and
    `test/` at any depth and `*.min.js`. Semgrep is now run with
    `--x-ignore-semgrepignore-files`, so a Python `tests/` directory is
    scanned (the Python rules carry no path filter) and a `.semgrepignore`
    hides nothing. A host Semgrep older than 1.96.0 has no such option: the run
    is `failed`, `execution_error`, with the note `Semgrep's default ignore
    list and the tree's .semgrepignore files apply`. A source file of a pack
    language whose extension Semgrep does not select (`.cts`, `.mts`, `.es6`,
    `.vue`, or a selected extension in another case, such as `APP.JS` or
    `Server.Py`) is in scope and is not declared out of scope by its name: it
    is handed to Semgrep by name in an extensions pass (one invocation per
    language group, with that group's rules and `--scan-unknown-extensions`)
    and evaluated like any other file. Semgrep cannot parse a `.vue`
    single-file component as JavaScript, so a `.vue` file always ends as lost
    evaluation, `not evaluated by semgrep`: a repository with Vue components
    reads `semgrep` `failed` (`execution_error`), because their script was not
    analysed. A file the extensions pass does not report is lost evaluation
    too, and a pass that does not finish in the stage budget names `extensions
    <group> <n> files` among what was not evaluated.
  - **The same rule for the other analyzers.** The secrets scanner, textscan
    and the Python engine's injection check record an in-scope file they did
    not read (over their size cap, unreadable, or not text) as lost evaluation
    too, each `failed`, `execution_error`, with the files named; see "The
    secrets scanner reads every text file and every line" and "The Python
    engine" below for what each reads.
  - **Effect.** More scans now record `semgrep`, `secrets`, `textscan` or
    `python-engine/injection` `failed`: a repository with a file over 1 MiB, a
    file Semgrep cannot parse, or a source file it cannot read. Such a scan's
    coverage is incomplete, `--fail-on-scanner-error` exits 2 on it, the
    GitHub Action with `require-analyzers: semgrep` fails it, and a consumer
    that treats `failed` as a gap (the hosted backend does) reads it as one.
    More findings appear too: files that were hidden by name or by a
    `.semgrepignore` are scanned.
- **Source scope: everything under the cap is analysed (round 5, decision
  D5-2, contract C6).** This supersedes "Out of scope is decided by evidence,
  never by a name (D6')", which round 4 shipped and which let a repository choose
  what was never analysed.
  - **Why.** Round 4 left a file or directory unread on a banner, a header, a
    marker file or how the code looked: a first-party module with one large inline
    JSON literal read as `minified` (C4B-02), a Koa handler under a forged
    `/*! jQuery v3.6.0 */` banner or a `@generated` header read as a vendored or
    generated library, a directory with a forged `pyvenv.cfg`, `conda-meta`,
    `.yarn-integrity`, a `*.dist-info` or a nested `.git` was pruned (review items
    1, 2, 7, 8), and the classification looked at the head of the file only
    (C4B-03). None of it is evidence about the rest of the file, and each of those
    scans read `ok` with the handler's finding missing.
  - **The rule, one for the Go engine (`go/internal/scope`, Semgrep target
    planning, textscan, secrets) and the Python engine.** Every supported in-scope
    file at or below the 1 MiB cap is analysed, whatever it looks like: minified,
    vendored, generated, compiled, source-map, test and fixture code included, and
    code under `node_modules`, a virtualenv, `site-packages`, `vendor`, `target`,
    `build`, `dist` or `.next`. No exclusion is based on a banner or header, a file
    or directory name, a marker file, a large literal, line statistics or the
    appearance of the code. `scope.ClassifyFile` now returns only a lockfile
    verdict and `scope.ClassifyDir` only `git metadata`; the reasons `minified`,
    `vendored library`, `generator header`, `compiled output`, `source map`,
    `test/fixture path`, `installed npm packages`, `python virtualenv`, `installed
    python packages`, `go vendor tree`, `composer vendor tree`, `cargo`, `maven`,
    `gradle` and `next.js build output`, `npm cache` and `setuptools build output`
    are never written, and every `--exclude` they produced is gone.
  - **What is still left out.** (1) **A symbolic link**, never followed and listed
    as `symbolic link` (a directory link ends in `/`): `declared out of scope, not
    scanned: symbolic link 1 (src/linkdir/)` (measured). (2) **A recognised
    lockfile**, the only content-based exclusion the policy allows: its exact
    base name is on a closed list (`package-lock.json`, `npm-shrinkwrap.json`,
    `yarn.lock` classic and Berry, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`,
    `Cargo.lock`, `go.sum`, `composer.lock`, `Gemfile.lock`) **and** its whole
    content parses as that format (`go/internal/scope/lockfile.go`, read to the end,
    up to 32 MiB: a valid head followed by source or an unknown key makes the file
    ordinary). Ten names round 4 accepted (`bun.lockb`, `deno.lock`, `pdm.lock`,
    `uv.lock`, `mix.lock`, `pubspec.lock`, `Podfile.lock`, `packages.lock.json`,
    `gradle.lockfile`, `flake.lock`) are scanned. **No analyzer applies the
    lockfile exclusion in this tree** (a lockfile has no pack-language extension, so
    Semgrep never targets one, and the secrets scanner and textscan read it like any
    file: measured, a `Cargo.lock` and a `yarn.lock` holding a credential each
    produce a finding); the function is tested and the reason is never written.
    Whether secrets and textscan should apply it is an open owner decision, and a
    secret written as a package name inside an otherwise well-formed lockfile would
    be skipped if they did. (3) **`<root>/.git`**, skipped quietly (not listed,
    `--exclude /.git` for Semgrep) and only when its layout is real: a regular
    `HEAD` file plus `objects/` and `refs/` directories, probed with `Lstat` only. A
    `.git` or `objects` directory anywhere else, a `HEAD` alone, a link for
    `objects` or a `.git` that is a file or link is ordinary content (measured:
    a fixture whose `.git` held only an `app.py` reported it, a fixture with a real
    layout did not). An uploaded archive can still carry a real-layout root `.git`
    whose contents are then not analysed (accepted).
  - **Over the cap or unreadable is lost evaluation, never a skip.** A file over
    1048576 bytes (secrets: 128 MiB) is `failed` / `execution_error` for every
    analyzer that should have read it, `over 1048576 bytes (<names>)` in the
    `lost evaluation:` segment, whatever it looks like (a lockfile, minified or
    generated bundle over the cap included). The Python engine's reason is
    `skipped: over the 1 MB size cap (<n> bytes)`.
  - **Probing never blocks and never leaves the root.** The readability probe of
    every Semgrep target, the read of a partially parsed file and of a finding's
    evidence line, a lockfile read and the Python engine's reads use
    `O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` plus an `fstat` that must say regular file
    (`scope.OpenRegular`, Python `read_regular`), and marker probes are `Lstat` only.
    A named pipe at a source path used to stall a scan forever (the Python engine's
    `read_bytes()`); it is now `unreadable: not a regular file`, and the scan
    completes.
  - **No file name can become a Semgrep option (review item 4).** Semgrep's
    command line ends `... --x-ignore-semgrepignore-files [--exclude /.git]
    [--include=<changed file> ...] -- <absolute target> ...`: `--include` takes its
    value in one argument, every target is absolute and follows `--`, so a file
    called `-x.py` or `--config=x.mts` is a path. Semgrep 1.182.1 rejects both
    `-x.py` and `--include -x.py` as unknown options.
  - **No installed-dependency tree is excluded (owner amendment A1).** The owner
    allowed excluding installed third-party code only on independently verified
    provenance. A first scheme excluded a Go module directory whose files hashed to
    the `go.sum` `h1:` line and listed it as `verified go module (lockfile hash)`; it
    was removed before release: a repository writes `go.sum`, a
    `package-lock.json`, a dist-info `RECORD` and `vendor/modules.txt` itself, so a
    forged `third_party/example.com/lib@v1.0.0/` directory holding a credential and a
    SQL injection plus its own hash made the scan read complete with the findings
    gone (measured by the round-5 engine owner: 0 findings, exit 0; after the removal
    4 findings, exit 1). An offline scan has no authority outside the repository to
    check a pin against, so nothing is excluded and that text is never written. An
    online scheme (a checksum-database lookup, or re-fetching the tarball or wheel by
    its lockfile integrity hash and comparing file by file) needs network access on
    the hosted worker and a new coverage reason: an open owner decision.
  - **Cost, measured and not mitigated by exclusion.** With no exclusion the engine
    analyses minified bundles and installed dependency trees, which costs time. The
    round-5 owners measured it on realistic repositories on a shared VM, one run each
    (their figures, with raw outputs, are in
    `review-reports/fendix-remediation/work/budget5.md` and `verify5.md`; they were not
    re-run for these notes, and a 2x difference is real while a few seconds are noise).
    Semgrep at `--cpus=2`, round-4b checkpoint (exclusions) against this tree: WebGoat
    21 to 33 s became 63 to 70 s, `semgrep` `ok` became `failed` /
    `execution_error`; `gogs` 50 to 55 s became 305 s, `failed` / `timeout`, with 1
    JavaScript file named lost after heavy-file isolation (230 files, a first-party
    `gogs.js` among them, before it); the backend repository 22 s became 36 s, `ok`
    became `failed` / `execution_error`; juice-shop 34 s became 50 s; a synthetic tree
    of 6,196 first-party and installed JavaScript and TypeScript files (92 MB) took 313 s
    and ended `failed` / `timeout`; the whole frontend checkout with `node_modules` and
    `.next` (3.4 GB) took 533 s at a peak of 2.7 GiB with 31,955 JavaScript files named
    lost. The secrets scan of that checkout went from 0.9 s to 178.9 s and textscan from
    0.34 s to 21.7 s. Two scans at once in 2 CPUs and no memory limit peaked at 1,076
    MiB, and no run was killed for memory. **A hosted scan of a repository that commits or
    installs a large JavaScript tree can therefore read `semgrep` `failed`
    (`timeout`), the loss named.** The owner decides whether to raise the budget,
    optimise the five slow JavaScript taint rules (they carry two TypeScript-only source
    clauses that also run on every `.js` file; run only on TypeScript files, the
    estimated effect is that gogs' lost file evaluates in under 10 s, a change to public
    rule packaging), add a literal prefilter to textscan, or accept the cost.
  - **Python engine.** The Python-engine scope code is rewritten to the same rule
    (its minified, vendored, generator-header, compiled-output, `dist-info`, npm
    package and virtualenv code and tests are deleted), and it gains the losses
    listed under "The Python engine" below.
  - **`.vue` and the other extensions** are unchanged: evaluated in the extensions
    pass, with `.vue` always lost evaluation.
- **A scanner status detail is segments, loss first, and never cut mid-list
  (C1, C2).** The detail of a `scanner_status` entry the engine composes is
  segments joined by `; `: the segments that say evaluation was lost first
  (`lost evaluation: ...`), then notes, then the declared exclusions, which
  start `declared out of scope, not scanned:`. A consumer reads loss patterns
  outside that segment only, so a file named like a loss message cannot change
  a verdict. Every file name the engine puts in a detail is sanitised: `;`,
  `…`, control characters, line and paragraph separators and bidirectional
  controls become `?`, and a name is cut to 80 bytes. In a segment a consumer
  does read, the characters a loss pattern is built from (space, `,`, `:`,
  `(`, `)`, quotes) are replaced too. A listing names as many entries as the
  240-byte budget allows and ends `and N more (see report metadata)`; when
  even the counts do not fit, whole trailing segments are dropped and `N` is
  the number of segments dropped (not of files). The same composition writes
  the `active-probes` detail. The complete lists are written to `metadata.coverage.limitations`,
  one or more entries per kind, each at most 240 bytes and starting with the
  analyzer's name (`semgrep: lost evaluation, not parsed by semgrep:
  src/big.js`, `secrets: declared out of scope, not scanned: symbolic
  link: linked/x.py`, `semgrep: partial parse, skipped lines: a.py 4`),
  and capped at 400 entries (the last then says `and N more entries not listed
  (limit 400)`). So `coverage.limitations` now also carries these lists, not
  only a note for each `unsupported` entry; `configured_complete` and `gaps`
  are computed from `state` and `reason` as before. Two limits. A `failed`
  entry composed from an error value (a fatal Semgrep run, a stage timeout,
  rule errors) can still end in `…` at 240 bytes, which is harmless because it
  is `failed` already. And the Python engine builds its own detail within the
  same budget (it never cuts a segment, keeps the marker and the kind down to
  its worst case of 207 bytes) and carries the complete lists in an additive
  `scope` field of its protocol status line (`{"lost": [[path, reason]],
  "declared": [[path, reason]], "truncated": bool}`); the Go side copies them
  into `metadata.coverage.limitations` as `python-engine/<check>: lost
  evaluation, not fully analysed: <path> (<reason>), ...` and
  `python-engine/<check>: declared out of scope, not scanned: <path>
  (<reason>), ...` (measured), and adds `python-engine/<check>: the lists above
  stop at the check's own cap; more were not listed` when the check cut them.
- **`nosemgrep` suppressions are reported, not silent.** Semgrep drops a result
  whose line carries a `// nosemgrep` comment and says nothing, so anyone who
  can commit a comment could remove a finding from a scan unseen. Semgrep now
  runs with `--disable-nosem` and the engine applies the comment itself. A
  result is suppressed when `nosem` or `nosemgrep` is a whole token (a blank
  before it, any case; `nosemantic`, `nosem-x` and `nosem_x` are not it) inside
  a real comment of the file's language (`#` for Python; `//` and `/* */` for
  JavaScript, TypeScript, Java and Go), found with string literals skipped, on
  the first line of the match after the match starts or on a line before it
  that is only a comment starting with the token. The token may be followed by
  `:` or `=` and a comma-separated list of rule ids; a listed id suppresses
  the rule it equals or ends, at a dot, with, and a bare `nosemgrep`
  suppresses every rule. Semgrep itself matches ` nosem` anywhere on the line,
  inside a string literal and as a word prefix included, so a line such as
  `"SELECT nosemantic ..." + x` could hide a finding unseen; the engine's
  reading is a subset of Semgrep's, so where Semgrep would suppress a result
  and the engine cannot be sure, the result is kept as a finding. Each suppressed result is removed from the findings and
  listed in the Semgrep detail, `nosemgrep suppressed 2 results (js-sqli-taint
  routes.js:12, ...)`, and in full in `metadata.coverage.limitations`
  (`semgrep: nosemgrep suppressed: python-yaml-load-unsafe app.py:10`). It
  affects Semgrep results only: the comment is not read for the other
  analyzers (measured: the Python engine's `PY_YAML_UNSAFE_LOAD` still blocked
  a line whose Semgrep result a `nosemgrep` suppressed).
- **Semgrep runs inside a bounded budget (R-008, part 2).** Semgrep used to run
  with defaults sized from the host: `--jobs` from the core count the kernel
  reports (nine threads on two CPUs inside a container), no `--max-memory`
  (the kernel's out-of-memory killer ended Semgrep whole, with no JSON and so
  no finding), and one 300-second deadline for the whole tree. It now runs
  with `--jobs` and `--max-memory` derived from the container's cgroup limits
  (`--jobs` is 0.85 of the CPU allowance, rounded, at least 1; `--max-memory`
  is 90% of (the memory budget less 384 MiB), at least 256 MiB; with no cgroup
  limit the budget is half the host's memory), logged at INFO, for example
  `semgrep: stage budget budget="jobs=2 max-memory=1004MiB wall=5m0s (cgroup
  v2, cpu quota 2.00, memory limit 1500 MiB)"`. The 300-second wall budget is
  for the whole stage, shrunk to leave 90 seconds of the run's own remaining
  time when the run has a deadline. A tree with files in at least two language groups
  (python, javascript and typescript, java, go) and at least 4 MiB of in-scope
  source is run as one invocation per group, cheapest first, with static
  deadlines, so a group that reaches its deadline loses only its own findings.
  A small or single-language tree is one invocation, as before. Source files
  Semgrep does not select by extension (`APP.JS`, `.mts`, `.vue`) are run in a
  further pass, one invocation per language group, inside the same budget.
  - **A file that lost evaluation to time is re-run alone.** Files that hit a
    rule timeout, the three-timeout threshold, a taint fixpoint timeout or an
    interfile timeout in the first pass are re-run one at a time with
    `--jobs 1` and a per-rule timeout of twice the first pass plus one second
    per 32 KiB of the file (capped at 8 times), at most 12 files, in a
    deterministic order, inside what is left of the stage budget. A retry
    resolves a file only when its document reports the file as scanned, has a
    `fixpoint_timeouts` list and carries no time-class or other
    lost-evaluation entry for the file; a re-run that lost it to memory or to
    a parse failure resolves nothing, and its findings are kept either way.
    Every retry is recorded in `metadata.coverage.limitations`: `semgrep:
    retried alone after losing evaluation to time in the first pass: a.js
    (resolved, evaluated in full when run alone), b.js (still lost: timed out
    again)`. This answers a verdict that depended on host speed: a pair that
    took 23 seconds alone and 31 on a busy host used to read `ok` on one run
    and `failed` on the next.
  - **A stage that reaches its budget says so.** The detail is one segment,
    never cut: `semgrep: timed out after 1m0s; not evaluated: java 3 files`,
    `failed`, reason `timeout`, with the finished groups' findings kept.
  - **A timed-out Semgrep is killed whole.** Killing it used to stop only its
    Python wrapper and leave `semgrep-core` running, which kept using CPU and
    memory for the next analyzer and the next scan. The whole process tree is
    now killed, and it stays in the engine's own process group, so a caller
    that ends a timed-out engine by process group still ends it.
  - **Settings.** `FENDIX_SEMGREP_JOBS` (1 to 256), `FENDIX_SEMGREP_MAX_MEMORY_MIB`
    (0 for none, else at least 256), `FENDIX_SEMGREP_BUDGET_SECONDS` (30 to
    3600) and `FENDIX_SEMGREP_SPLIT_BYTES` (-1 never splits) override the
    derived values; an unusable value is ignored with a warning, never turned
    into an unbounded run. `models.ScanConfig` has `SemgrepJobs`,
    `SemgrepMaxMemoryMiB` and `SemgrepWallBudget`; there is no command-line
    flag for them. A service that builds each engine child's environment by
    default-deny never passes the variables on.
  - **What this does not solve.** A pair that costs more than the retry bound
    (about 60 to 90 seconds alone on two CPUs) still reads `failed`, `timeout`;
    one near that bound can still differ between runs, because Semgrep's time
    bounds are wall-clock and its taint fixpoint budget is internal. More than
    12 files to retry, or a stage budget that is spent, leaves the rest `failed`
    and named. A group killed at its deadline loses all its findings, because
    Semgrep prints its JSON once, and Semgrep's per-rule timeout is not
    preemptive inside one pattern evaluation, so a single file that it
    evaluates extremely slowly can hold its whole invocation to the stage
    deadline. Measured in round 4 with the 461 KB emscripten output
    `openjpeg_nowasm_fallback.js` from a pdf.js build, given thirty ordinary
    functions above it: a stage budget of 120 s ran 121 s and recorded `semgrep`
    `failed`, `timeout`, `semgrep: timed out after 2m0s`, with no Semgrep finding.
    (Round 4 declared such a file out of scope as `minified`; round 5 scans every
    file under the cap, so this shape now reaches Semgrep, see "Source scope:
    everything under the cap is analysed".) No rule edit makes such a file
    finish. Round 5 isolates the heaviest files of a large group in invocations of their
    own (`FENDIX_SEMGREP_CHUNK_BYTES`, `FENDIX_SEMGREP_HEAVY_FILE_BYTES`; see
    `docs/checks/semgrep.md`, "Isolating heavy files"), so such a file loses only
    itself. The production CPU quota was not observed, and
    production runs the scan worker at concurrency 2 with no container memory limit
    on a 2-CPU, 3.8 GB host with no swap (read-only check, 2026-11-12; backend
    `DEPLOY_RUNBOOK.md` 8.5), so the budget assumes at most 2 CPUs per scan and
    no memory cap. The completion rate and wall times of the round-4
    benchmark are in the work notes of that round, were measured on a work
    tree, and are pending re-measurement at the release commit; none is quoted
    here.
- **`fendix verify` re-tests a secret only with the scanner that produced
  it.** It sent every `secrets`-category finding to the secrets scanner and
  matched by exact title. Findings of textscan (`GO_HARDCODED_AWS_KEY`,
  `JS_HARDCODED_AWS_KEY`, `GO_WEAK_HASH_PASSWORD`) and of the Python engine
  (`python.ast/PY_WEAK_CRYPTO_PASSWORD`) carry titles the secrets scanner
  never emits, so on unchanged code they were reported `resolved`, exit 0.
  - **Now:** the secrets scanner re-tests a finding only when its `rule_id`
    is `secrets/<pattern>` for a pattern the scanner has, it carries no
    `source_tier`, and it is a white-box finding. Every other finding is
    `unknown` (exit 2), with a reason that names the producing rule and tier.
    That includes textscan and Python-engine findings, imported SARIF, and a
    baseline row with no `rule_id`.
  - **The re-test began by reading exactly the finding's file**, through the
    same containment as a scan: `still-present` when the rule still fires in
    that file, `resolved` when the whole file was read and it no longer fires
    there, `unknown` when the file could not be read completely. That was not
    enough for `resolved`, because a credential moved to another file, or
    rewritten so that no rule matches it, left the file clean. `resolved` now
    also needs a search of the whole tree for the credential itself; see
    "`fendix verify` says `resolved` only after it searched for the
    credential itself" below.
  - **Exit codes are unchanged** (`resolved` 0, `still-present` 1, `unknown`
    and `not-found-in-baseline` 2), and so are the JSON fields. Only the
    `reason` text is new. Textscan and Python-engine `secrets` findings can
    no longer be verified as fixed by `fendix verify`; a real re-test of
    those analyzers is not implemented.
- **The secrets scanner reads every text file and every line.** It read only
  files whose extension was on a list, so a credential in a `Dockerfile`, an
  extension-less `credentials` file or a `.properties` file was never looked
  at; it skipped every JavaScript or TypeScript line over 500 characters, so a
  hand-written or minified-looking line holding a key was never read, with
  `secrets` `ok`; it read at most 1 MiB; and it skipped directories called
  `node_modules`, `vendor`, `dist`, `build`, `.venv`, `venv`, `.tox` and
  `__pycache__` by name.
  - **Now:** it reads every regular file that is text: a file is left unread
    only by a known binary extension (images, fonts, archives and packages,
    compiled code, media, documents and databases, and key stores such as
    `.jks`, `.p12`, `.pfx`) or because a NUL byte in its first 8000 bytes
    proves it binary, and an extension on the source list (`.py`, `.js`,
    `.json`, `.yaml`, `.env`, ...) is never ruled binary by a NUL byte. Those
    two kinds are not listed. Files stream in 64 KiB windows, so memory is
    bounded whatever the file or line length and no line is skipped. A window
    is `[1 KiB of context][owned region][4 KiB lookahead]`: a match belongs to
    the window in which it starts, the lookahead lets a match that crosses the
    boundary be seen whole, and the context keeps a credential glued to a token
    before it (`key=AKIA...`, `x` + key) from being missed at a boundary. As
    first written the next window blanked the token it started inside, so a
    credential glued to a token across the boundary of a line over 64 KiB was
    found by no window; the windowed result is now tested equal to the
    whole-line result at every offset. A UTF-16 file is decoded, with a byte
    order mark or without one (a file whose NUL bytes fall almost only on one
    byte parity is read as UTF-16 of that endianness). The size cap is
    128 MiB; a file over it is lost evaluation, not a skip.
  - **What it does not read, stated exactly.** Files of a known binary
    extension; a file that a NUL byte proves binary and that is not UTF-16
    or UTF-32 text (unless its extension is a source extension; nothing is
    recorded for it); a file over 128 MiB (lost
    evaluation, named); a symbolic link, whose target outside the root is
    listed as `symbolic link` and is never read; and a real `<root>/.git`
    (round 5: nothing is pruned for its name or markers any more, see "Source
    scope: everything under the cap is analysed"). It does not read the inside of
    an archive, and a credential encoded or split over variables is not matched by
    any pattern. UTF-32 text is decoded in round 5 (it used to be skipped as binary
    with nothing recorded); an unknown-kind file with a NUL byte that is not
    UTF-16 or UTF-32 text is still skipped and not listed.
  - **Effect.** More files are read, so more findings appear (a Dockerfile
    `ENV`, a `.properties` value, a long minified-looking line), and a scan of
    a repository with a file over 128 MiB reads `failed`.
- **`fendix verify` says `resolved` only after it searched for the credential
  itself.** A secrets finding was re-tested by running the secrets scanner on
  the finding's file, so moving the credential to a `Dockerfile`, a
  `.properties` file or an extension-less file, or rewriting it
  (`os.environ.get("DB_PASSWORD", "<literal>")`, `"abc" + "def"`, a backslash
  escape), left the file clean and read `resolved`, exit 0.
  - **Now:** the baseline evidence of a secrets finding carries a marker,
    `[REDACTED len=22 sha256:0a8636d8...]`: the credential's byte length and
    the first 4 bytes of its SHA-256. Before it answers `resolved`, verify
    searches the tree under `--code` for a value with that length and digest.
    A candidate starts at any byte that can start a value (the scanner reports
    a credential glued to the letters before it, so the search does too). The
    search reads every file, text or binary (a binary file as raw bytes, and
    with its NUL bytes removed for UTF-16 inside it), the directories a scan
    prunes (`node_modules/`, virtual environments, build output), and the
    contents of gzip, bzip2, zip (jar, war, whl, apk, docx, ...) and tar files,
    recognised by their first bytes and not their name, to a depth of 4 and
    within a size bound. It finds the value as written; with adjacent string
    literals, array elements (`["ab", "cd"]`), `.concat(` and line
    continuations joined; with `\" \' \\ \/ \xHH \uXXXX \u{X} \UXXXXXXXX
    \NNN` escapes and `%XX` undone; and as a base64 (standard or URL alphabet)
    or hex run decoded. A git object store is not searched, and is counted.
    (Round 5 extends the forms and tightens what makes the answer `unknown`;
    see "`fendix verify` says `resolved` only when the whole scope was read and
    decoded" below, which supersedes this list.)
  - **A second guard.** Before any `resolved`, verify also runs the secrets
    scanner over the whole tree: a sighting with the baseline's marker
    anywhere is `still-present`, so verify is at least as permissive as the
    scanner. As first written the search missed a value glued to a letter, a
    value in an array join, a base64 or binary copy, a gzip or jar, a copy in
    `node_modules/` or a virtualenv, and UTF-16 without a byte order mark, each
    of which read `resolved`.
  - **The answers.** `still-present` when the rule still fires in the file or
    the value is found anywhere under `--code`, with the places in the reason:
    `the same credential ([REDACTED len=22 sha256:0a8636d8...]) is still
    committed: found at Dockerfile:2 (as written). It is no longer reported by
    secrets/HARDCODED_PASSWORD in settings.py, but moving or reshaping a secret
    does not remove it from the repository.` (`found at enc.txt:1
    (base64-decoded)`, `found at x.zip!a.txt:1 (as written)`). `resolved` only
    when the whole file was re-read, the rule fires there no more and the value
    was found nowhere, and the reason says what was searched and what was not:
    `... searched 3 text files (251.5 KB) and 1 binary files as raw bytes under
    --code, including directories a scan prunes, for the value as written, with
    adjacent string literals and line continuations joined, backslash escapes
    and %XX undone, and base64 and hex runs decoded; not covered: a value built
    at run time or split over variables, reversed or encrypted, a compressed
    stream inside a binary format, an archive in a format that cannot be
    decoded, and version-control history`. `unknown` (exit 2) when any of that
    could not be established: a file that no longer exists (`missing or
    inaccessible source is not proof of remediation`), a file or directory under
    `--code` that could not be read or was over the read cap, an archive in a
    format it cannot decode (xz, zstd, 7z, rar, lz4, an encrypted or corrupt
    gzip or zip), a decompressed size over its bound, a credential longer than
    3 KiB, or a baseline without the marker (a non-primary occurrence of a
    group, a signature-only rule, an older baseline), which needs a rule that
    matches the credential's own token shape and fires nowhere under `--code`,
    else `unknown`.
  - **What `resolved` does not cover** (as first written; round 5 narrows this
    list, see below). A value built at run time or split over variables,
    reversed, shifted or encrypted, a list of character codes, a compressed
    stream inside another format (a PNG, a PDF, a font), and a value that
    exists only in version-control history. A binary file was searched as raw
    bytes only and did not by itself make the answer `unknown`. `resolved` says
    what was searched, not that no copy exists.
  - **Still unknown, never resolved:** every file-anchored finding that is not
    from the secrets scanner (Semgrep, textscan, the Python engine, imported
    SARIF). (Round 5: the re-tests of a URL-anchored finding and of a dependency finding
    are `unknown` too.) Exit codes are unchanged: `resolved` 0,
    `still-present` 1, `unknown` and `not-found-in-baseline` 2, and no other
    status exits 0. A search reads far more than a re-read, and a group of
    many moved occurrences runs one search for each distinct marker set.
- **`fendix verify` says `resolved` only when the whole scope was read and
  decoded, and an HTTP status never resolves anything (round 5, decision D5-3,
  contract C8).** Round 4's search left several ways to a false `resolved`
  with the credential still committed: in the round-5 owner's end-to-end matrix of
  synthetic cases, every one of the new encodings, an opaque binary, a nested git
  object store, an unknown `\N{}` name, a correlated 401/403/404/410 and the URL
  fallback answered `resolved`, exit 0, on the previous binary; each is now
  `still-present`, or `unknown` with the reason (the matrix is in the owner's work
  notes and was not re-run for these docs). This supersedes the lists in the two
  entries above.
  - **A correlated finding never resolves on an HTTP status (C4B-11).**
    `verifyCorrelated` returned `resolved` on 401/403/404/410 for every category
    but the active-probe ones, and the correlator merges `secrets` into
    `data_exposure` and `auth` into `auth_bypass`, so a still-committed AWS key was
    `resolved` when its endpoint answered 404. All 12 combinations of those four
    statuses and `data_exposure`, `auth_bypass` and `secrets` are now `unknown`,
    exit 2 (200 stays `still-present`). The same rule covers the URL re-test's
    status-only resolutions: the generic fallback ("presumed gated or removed"),
    "Missing authentication on endpoint" with a non-2xx answer and "No rate limiting
    observed" are `unknown`. A header that is now set, or a version string that is
    gone, still resolves: that is an observation about the response, not its
    status. **Closed in the round-5 continuation (DE5-02):** a URL-anchored passive
    finding whose header is now set, a version string that is gone and a dependency
    the manifest no longer lists are `unknown`, never `resolved`: `verifyURL` and
    `verifyDep` report an absent observation as `unknown` with the note that it is
    what one re-test observed, not proof of remediation, and a backstop in `verifyOne`
    turns any `resolved` on a finding that is not the secrets scanner's into
    `unknown`. A 404 on a CORS or version finding no longer resolves, and a CORS
    re-test sends the scanner's attacker `Origin`, so a wildcard returned only to a
    request that carries one is `still-present`. The e2e test that pinned "a missing
    CSP resolves when the header is set" now resolves a real secrets finding, and the
    old scenario expects exit 2.
  - **Bounded, safe decoders for the common encodings (C4B-20).** The search also
    finds the value as `\N{NAME}` escapes (ASCII names), HTML and XML character
    references (decimal, hex, named; two passes), lists of character codes
    (`String.fromCharCode(65,75)`, `chr(65)+chr(75)`, `[65,75]`, `char[]{...}`),
    hex with or without separators (`:` `-` space `,` `;` `_` `.`, `0x` or `\x`
    prefixes), base64 inside base64 (two nested layers), hex inside base64 and the
    reverse, zlib or gzip inside base64, URL encoding twice, UTF-32 text (a byte
    order mark or none, both endiannesses), zlib, gzip and bzip2 streams found by
    header inside any file that is not text (a raw compressed file, an image's or a
    PDF's flate data, a git object; 16 MiB per stream, 4096 candidates per segment,
    inside the existing 1 GiB per top-level file), and the value written backwards.
    Nothing it decodes is executed. A value **built at run time** (case-changed,
    concatenated from variables, shifted, computed) is out of scope, and the
    `resolved` reason says so.
  - **Anything unread or undecoded is `unknown`, and the reason lists it.** New
    lost-evaluation entries (recorded under the existing `not text (NUL bytes)`
    kind, so the existing detail, the unknown verdict and the backend patterns apply;
    no new enum): an **opaque binary** (no recognised container and no decodable
    stream, at least 1 KiB, at least 7.2 bits per byte of entropy over its first 8000
    bytes, and not a recognised media container by content: PNG with an `IHDR`, JPEG,
    GIF, WEBP/WAV, WOFF/WOFF2, TrueType/OpenType, MP3/Ogg/FLAC, MP4 `ftyp`, ICO; a
    file only named `.png` is not one), a compressed stream cut before its end or
    past the bound, a file with more than 4096 stream-header candidates, and a
    `\N{...}` name outside the ASCII table. A credential inside a recognised media
    payload, or in a file under 1 KiB that is encrypted, is not found and not
    flagged; treating any unread binary as `unknown` would make every repository
    with an image `unknown`, so that stricter reading is an open owner decision.
  - **Only `<root>/.git/objects` is history (review item 5).** Any `objects`
    directory beside a `HEAD` file and a `refs` directory used to be skipped as git
    history, so a forged or vendored layout hid its content (a password in
    `fixtures/r/objects/ab/cd` beside a `HEAD` and `refs/` read `resolved`). Now only
    `<root>/.git/objects`, and only when `<root>/.git` has a real layout, is left
    unsearched and counted; any other object-store-shaped directory is searched like
    any directory and recorded as lost evaluation (`<dir>/ (a git object store that
    is not the scan root's own)`), so the answer is `unknown` or `still-present`.
  - **The resolved reason says what is not covered and never says fixed.** Every
    `resolved` reason ends `Not detected is not the same as fixed: verify cannot see
    the repository's history or a value built at run time, so rotate or revoke the
    credential rather than rely on this result.`, and its search scope names what is
    covered (`backslash escapes (\xHH, \uXXXX, \N{NAME}), HTML character references
    and %XX undone, character-code lists, base64 and hex (with or without
    separators) decoded, up to two layers deep, compressed streams inside files
    decompressed, and the value written backwards`) and what is not (`a value built
    at run time (case-changed, concatenated from variables, shifted or otherwise
    computed), encrypted, held in an image or another recognised media payload, or
    only in version-control history`). `was found nowhere` is unchanged.
  - **Redaction survives a stream window boundary (review item 6).** The spans a
    window redacted came from that window's own matches, so a credential that began
    in an earlier window (a PEM header followed by its body, a token longer than the
    lookahead) was plain text in the window that saw only its tail, and a finding of
    that window printed the tail in `evidence` (measured on the previous tree: a
    one-line `-----BEGIN RSA PRIVATE KEY-----` followed by a body holding an
    AWS-shaped token printed body bytes around the marker). Spans are now carried
    from one window to the next (`secrets/carry.go`): a span that ends at its
    window's end is open and is extended, to the end of the line for a rest-of-line
    credential, over the next run of bytes that are neither white space nor a quote
    for any other. Property tests move the credential across every offset (step 1)
    over two window starts and two geometries and require that no body byte reaches
    any finding's evidence. Over-redacting is the safe error. A non-rest credential
    longer than the 4 KiB lookahead does not match in any window; that is a
    detection limit, not a redaction gap.
  - **The textscan extension set (C4B-26).** The text scanner matched `.js` and the
    other extensions in lower case only and stopped at `.cjs`: `eval(userCode)` in
    `a.mts`, `a.cts`, `a.es6`, `a.vue`, `APP.JS`, `X.TS`, `Main.GO`, `K8S.YAML` or
    `DOCKERFILE` produced no finding from any analyzer. Extension and name tests are
    now case-insensitive and the JavaScript set is `.js .jsx .ts .tsx .mjs .cjs .mts
    .cts .es6 .vue`, the set the Semgrep planner uses.
  - **Round-4 tests reversed.** Tests that pinned a pruned directory, a declared
    generated file or an over-cap lockfile skip were changed to the D5-2 opposite,
    each with its justification in the test; none was loosened to accept a worse
    behaviour.
  - **Help text still stale.** `fendix verify --help` in `go/cmd/fendix` still lists
    "File-anchored SAST findings" as supported shapes and "Active injection probe
    findings" under not-yet-supported; it is outside the documentation files and is
    open (C4B-21).
- **The secrets scanner no longer follows symlinks.** Its full walk read a
  symlinked file's target and checked the size limit on the link, so a
  repository link such as `.env -> /proc/1/environ` put the target's text
  into finding evidence, and a link to `/dev/zero` exhausted memory. The
  `--diff` path read a symlinked leaf the same way. The scanner now reads
  regular files only, through one `os.Root` opened on the scan root, and
  checks the size limit on the bytes it reads. A link inside the repository
  is reported once, at its target's path; a link out of the repository
  produces no finding and is listed as declared out of scope (`symbolic
  link`), so it is not silent. The hosted backend's clones also stop materialising
  symlinks, as a separate backend change.
- **Connection-string passwords are redacted to the end of their
  property.** The `DB_CONNECTION_STRING` redaction stopped at the first `;`,
  `&`, quote, space or `@`, so the rest of a SQL Server `{braced;}` value, a
  quoted or spaced password, a password holding `@`, or a second `password=`
  in the same URL stayed in evidence and SARIF as plaintext. Redaction now
  covers the whole value: URL userinfo to the authority's last `@`, a braced
  value to its closing `}` (`}}` is an escaped brace), and any other value to
  the next `;` or `&` that starts another `key=` property, to its literal's
  closing quote, or to the end of the line. Every `password=` property is
  redacted. Detection, rule id, identifier and fingerprint are unchanged;
  only the length and hash in the redaction marker differ. As first written
  the scanner did not read `.properties` files; it now reads every text file.
- **A Python URL host allowlist guard counts only for the value it
  checked.** The `urlparse(url).netloc` allowlist guard was matched by the
  variable's name, so rebinding the URL after the guard, a parse of an
  earlier value of the name, or an allowlist holding request data hid SSRF
  and open-redirect findings. A guard now counts only when the parse is the
  sole binding of its name, placed before the guard, nothing rebinds the
  guarded name after the parse anywhere in the function, and the allowlist
  holds only non-empty string constants (a named allowlist is bound once in
  the module and never mutated). The membership guard (`if x not in
  ALLOWED: abort()`) follows the same rules: constant members, no rebind
  after the guard. A module
  that binds an allowlist name twice loses the guard's suppression, which can
  add a finding, never hide one.
- **Python sanitisers count only for the sink they protect.** A sanitiser was
  honoured for every sink class, both inline (`html.escape` or `quote` around
  a URL) and in the caller of a one-hop helper (`basename`, `html.escape` or
  a netloc guard before a helper that runs a shell command). So
  `requests.get(html.escape(url))`, `redirect(quote(target))` and a
  `basename`-reduced value reaching `os.system` through a helper were not
  proven, and did not block. Each taint chain now carries its sink's class,
  and only that class's sanitisers apply; the classes are listed under "A
  Python sink in a helper function is now proven reachable when the caller
  assigns the request value before passing it" and "A Python sink in a helper is now proven when
  a view in another module passes it request input" above.
  A netloc guard or a fixed authority does not protect a URL the value is
  only part of (`"https://" + host`). Because escaping no longer protects a
  redirect, a redirect to a literal same-origin path or a fixed
  `https://host/` prefix (`"/search?q=" + quote(q)`) is treated as safe; `/`
  alone and `/\` do not count. Findings this restores are new.
- **Safe Python download idioms no longer block.** Flask's
  `send_from_directory(<constant dir>, <request filename>)` was a proven path
  traversal, though Werkzeug's `safe_join` contains the filename, and
  `os.path.join(BASE, basename(name))` (or `secure_filename`) was too. With
  route parameters as sources this blocked the documented Flask idiom.
  `send_from_directory` is now judged on its directory: a constant or trusted
  directory is not a sink, and a request-controlled one is proven. A join
  (`os.path.join`, `Path(...) / x`, `.joinpath`) is contained when every part
  is a constant, a trusted base, or reduced to one path component on every
  path to it. A partly contained join is traced through its uncontained
  parts only.
  - **Identity.** A `send_from_directory` finding's sink now names the
    directory argument, not the filename, so a finding for a
    request-controlled directory has a new fingerprint once.
  - **Still blocking (false positives, not fixed):** a path guarded by
    `any(p.startswith(root + os.sep) ...)`.
  - **Test replaced.** `python/tests/test_ast_analyzer.py`'s
    `test_send_from_directory_uses_second_arg` asserted this false positive
    (a constant directory with a request filename had to be a proven path
    traversal). It is replaced by
    `test_send_from_directory_constant_dir_request_name_not_proven` and
    `test_send_from_directory_request_dir_is_proven`.
- **A Python guard counts only for the value it tested.** A guard on a
  name is a statement about the value the name held when the guard ran:
  `if ".." in name or os.path.isabs(name): abort(400)`, then `name =
  unquote(name)` or `name = "/" + name`, then `open(name)` read as guarded, so
  a decode or a concatenation after a traversal guard hid a path traversal.
  The guards were checked by name and by per-guard rebind rules. One rule now
  governs the traversal guard, the membership allowlist guard, the URL-host
  allowlist guard and the resolved-path containment guard: a guard protects a
  use only if every definition of the name that can supply the use also
  reached the guard (`python/analyzers/reaching_defs.py`, a forward dataflow
  over the function). Where control flow is uncertain (an exception leaving a
  `try` or `with`, a loop that may run again, a short-circuit operand that may
  not run) the pass adds definitions, which can only invalidate a guard. A name
  the function declares `global` or `nonlocal`, or a free name, is volatile,
  and no guard on it is proven. A call that rebinds a name through `exec`,
  `globals()` or `locals()`, and a nested function or lambda that reads the
  name, are not modelled. This can add findings, never hide one.
  - **A guard must provably end control flow.** The rejecting branch counts
    only when it ends in `return` or `raise`, in an `if`/`else` whose both
    branches end, or in a call that never returns: `sys.exit`, `os._exit`,
    `os.abort`, and `abort` of flask, werkzeug, quart or bottle resolved
    through the file's imports (aliases and `from m import *` included); the
    `exit` and `quit` builtins when nothing in the file rebinds, defines or
    imports them; or a function the file defines once, undecorated, not async,
    not a generator, with no `return`, whose body ends on every path (three
    levels deep). A call counted by its name alone (`log.abort()`, `log.exit()`,
    a local `abort` that only prints) used to count, and hid a path traversal.
    A free `abort` with no import is not proven, so a guard written that way
    now reports, which is the safe side. A sink written inside the guard's own
    rejecting body is never covered by it; one in the `else` or after is.
  - **A guard follows the value, not the name.** A tuple assignment takes its
    right-hand names at the binding in effect before the statement (`name,
    other = other, name` used to leave a sink after the swap hidden), and
    rebinding a name first freezes every earlier binding that reads it (`name
    = request.args['f']; base = name; name = 'x'; open(base)` reported nothing
    before; this is a general false negative the swap case exposed, present in
    the previous release), bounded to 400 bindings per scope and 400 nodes per
    value. A name that has no binding and is not a route parameter (a plain
    helper parameter) is still resolved lazily, as before. A swap that moves a
    guarded value (`name, other = other, name; open(other)`) reports, a false
    positive.
- **The Python engine reports what it did not analyse (D6', D1', DE-03).**
  - **A file the interpreter cannot parse is lost evaluation.** The engine
    parses `.py` files with the running interpreter and dropped a file on
    `SyntaxError`. A `match` statement under Python 3.9 is valid Python the
    interpreter is too old for: on a macOS `python3` a Flask route with a
    `match` and `subprocess.call(cmd, shell=True)` read `python-engine/injection`
    `ok`, no finding, exit 0, while 3.11 blocked it. The check is now `failed`,
    `execution_error`, and the detail says which it is: `lost evaluation: 1
    in-scope file not fully analysed: app.py (parse: python 3.9.6 too old for
    line 8 (invalid syntax))`, `(parse: python 3.9.6 may be too old, error at
    line N (<msg>))` when the interpreter is older than 3.14 and the error line
    does not look like newer syntax, `(parse: syntax error at line 3 (invalid
    syntax))` for a file that does not parse on any Python 3, or `(parse: not
    valid source text (null byte))`. The findings of every other file are kept.
  - **Interpreter floor.** Below Python 3.9 the engine reports every requested
    check `failed`, `execution_error`, with `python 3.8.10 is below the 3.9
    floor the engine runs on: nothing was analysed (install Python 3.9+ or use
    the engine image)`, and exits 2. Between 3.9 and 3.14 it logs that a file
    in newer syntax is reported as lost evaluation, not as clean. The hosted
    image runs Python 3.14.5.
  - **The same lost-evaluation rule** covers a source file over 1 MB, whatever
    it looks like (`skipped: over the 1 MB size cap (<n> bytes)`; round 5: a
    generator header or a minified shape no longer declares an over-cap file out
    of scope), a file or directory that cannot be read or is not a regular file
    (`unreadable: not a regular file`), a parse that exhausts
    the recursion limit or memory, and a project call index that could not be
    built. The check finishes the whole tree first, so every finding of every
    other file is kept.
  - **Scope: everything under the cap (round 5, D5-2).** The engine analyses
    every `.py` and JavaScript-family file at or below 1 MB whatever it looks like
    or is called, by the same rule as the Go engine (`python/analyzers/
    scope_evidence.py`, about 150 lines, rewritten; the round-4 minified,
    vendored-library, generator-header, compiled-output, `dist-info`, npm-package
    and virtualenv evidence and its tests are deleted). It leaves out only a
    symbolic link to a directory (`declared out of scope, not scanned: 1 path:
    src/linkdir/ (symbolic link)`, measured; it used to read `symlink, not
    followed`) and `<root>/.git` when it has a real layout (a regular `HEAD`, real
    `objects/` and `refs/`, three `lstat` calls, quiet). A `.git` elsewhere, a
    `.git` with a missing `refs/` or a link for `objects` or `HEAD` is ordinary
    content. Reads use `read_regular` (`O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` and
    `fstat`), so a named pipe is `unreadable: not a regular file` instead of
    stalling the scan forever. A 1 MB JavaScript file of 20,000 SQL-template lines
    was quadratic (`_js_module_string_constants` re-read the file per line); its
    constants are now read once. The Python engine has no lockfile logic: no
    lockfile has a `.py` or JavaScript suffix.
  - **A branch or `try` that binds a name two ways is lost evaluation (round 5,
    C4B-23).** The visitor resolved a name from its last binding in source order, so
    `if c: name = request.args['g']` / `else: name = 'safe'` followed by
    `open(name)`, a `try:` whose later binding made the name safe, `os.system(cmd)`
    after an if/else, and a route parameter overwritten on one branch reported
    nothing and noted nothing. After a call whose own checks read a name and reported
    nothing, the engine asks whether two or more definitions reach the use and
    whether one carries request input while the binding the checks used does not;
    it then re-runs the sink rules with that definition substituted, and only when
    the call *would* be reported is the file's evaluation lost (a `print(name)` or a
    helper no rule reports is never a gap). `python-engine/injection` is `failed` /
    `execution_error`, findings kept, the file named: `lost evaluation: 1 in-scope
    file not fully analysed: app.py (ambiguous binding: name (line 11))` (measured
    by the round-5 owner). At most 20 are listed, then `ambiguous bindings: <N> more
    not listed`; past 200 names in one function the analysis is not run and
    `ambiguous bindings not analysed: over 200 names (function at line <N>)` is
    recorded, never read as clean. A real one-branch vulnerability is reported as a
    gap, not as a finding (open owner decision: report a counterfactually proven
    path as a finding). The note is per file. The cause is the repository's code:
    the hosted backend reads `lost evaluation: N in-scope files not fully analysed`
    as repository-caused and gives no automatic refund.
  - **A generator expression runs where it is consumed (round 5, C4B-22).** Only
    its first iterable is evaluated at the definition, so a guard before `g =
    (open(name).read() for _ in [1])` no longer covers a read that happens at
    `next(g)` after `name` was rebound to request input. List, set and dict
    comprehensions are unchanged.
  - **A star import must agree with every other (round 5, review item 3).** A
    never-returning call (`abort(400)`) from a star import ended control flow
    whenever any star import supplied the name, in walk order, ignoring relative
    imports' dots; `from flask import *` plus `from helpers import *` (a returning
    `abort`) hid a path traversal. The proof now needs every `from X import *` in the
    module to be a known never-returning supplier of the name.
  - **Test-path confidence demotion is kept and extended (RC-10 (a), Release Closure
    Sprint).** `_is_test_path` (a finding under `tests/`, `fixtures/` or `test_*.py` is
    forced to LOW confidence and tagged `in_test`) is a name-based influence on
    blocking: a repository can put a vulnerable handler under a directory called
    `tests/` and a confidence-gated scan warns instead of blocking. It is not an
    exclusion, and it conflicts in spirit with C6; the owner kept it and extended the
    conventions it knows, in Go and Python together (see "More test-code conventions
    are recognised" in the Release Closure Sprint above).
  - **Letter case and extensions.** `.py`, `.js`, `.jsx`, `.ts` and `.tsx` are
    matched without regard to case (`Server.Py`, `APP.JS` were skipped without
    a trace), and `.mjs`, `.cjs`, `.mts` and `.cts` are scanned.
  - **Decoding.** A UTF-8 byte order mark and a PEP 263 coding declaration are
    honoured, so a BOM file is parsed instead of dropped.
- **"No safe case blocks" is a statement about the development corpus.**
  Every such statement above, and the precision of 1.000 quoted for the
  development corpus, describes the framework-parity development corpus the
  rules were tuned on; those statements now say so. On independently written
  safe handlers the review found blocking false positives on an `int()` cast,
  a literal-dict allowlist, `basename`, `shlex.quote` and `parseInt` (4 of 11
  Python handlers, 1 of 10 JavaScript). The entries above change how
  `basename` and `shlex.quote` are honoured in Python; that independent set
  was not re-run against them, so whether those false positives are gone is
  unverified. Holdout precision has never been measured.
- **The Python baseline recall is 0.769.** The base engine (v3.7.0) and
  v3.6.3 detect 83 of 108 Python vulnerable cases of the development corpus,
  recall 0.769 (`benchmarks/frameworks/results/v3.6.3-corpus-v2.json`). A
  "before" figure of 0.756 quoted for this work is the Python blind-holdout
  recall, not the baseline. The intermediate counts in the entries above
  were recorded when each change was made and were not re-measured.
- **The security catalog count.** `docs/security-catalog-contract.json` is
  generated from the engine's rule registries (`go run ./cmd/catalog-contract
  -out ../docs/security-catalog-contract.json` from `go/`; a test in
  `go/internal/catalog` fails when it is stale). One check is one catalog
  `id`. Counted that way the catalog has 158 checks, against 85 in v3.7.0:
  74 added and `flask-missing-login-required` removed. The running totals
  given above (105 and 106), and 157 in `benchmarks/frameworks/RESULTS.md`,
  were never the release's. Each figure below was measured on this tree and
  is reproduced by the command after it, run from the repository root with
  `C=docs/security-catalog-contract.json`.
  - **Unique checks: 158**, all ids distinct; v3.7.0 had 85.

    ```sh
    jq '.checks | length' "$C"
    jq '[.checks[].id] | unique | length' "$C"
    git show v3.7.0:docs/security-catalog-contract.json | jq '.checks | length'
    ```

  - **By analyzer:** `semgrep` 74, `textscan` 30, `python-engine/injection`
    21 (17 `python.ast/*` and four `SEC-JS_*`), `secrets` 18, `dast` 15.

    ```sh
    jq -r '.checks | group_by(.analyzer)[] | "\(.[0].analyzer) \(length)"' "$C"
    ```

  - **Added:** 52 Semgrep rules (51 JavaScript/TypeScript, Java and Go, and
    `python-random-token-assignment`), the 21 `python-engine/injection`
    checks and `JAVA_WEAK_HASH_PASSWORD`. Removed:
    `flask-missing-login-required`.

    ```sh
    git show v3.7.0:docs/security-catalog-contract.json > /tmp/old.json
    jq -n --slurpfile a /tmp/old.json --slurpfile b "$C" \
      '{added: ([$b[0].checks[].id] - [$a[0].checks[].id] | length),
        removed: ([$a[0].checks[].id] - [$b[0].checks[].id])}'
    ```

  - **Rules.** A Semgrep check is one YAML rule: 74 rules in
    `go/internal/scanner/semgrep/rules/`, one catalog check each (23 Python,
    17 JavaScript/TypeScript, 15 Java, 19 Go). 29 are taint-mode, and all 29
    declare `fendix_reachability: taint`. For the other analyzers one
    registry entry (a textscan rule, a secrets pattern, a DAST check, a
    Python-engine check) is one check, so there rules and checks are the
    same count.

    ```sh
    cat go/internal/scanner/semgrep/rules/*.yaml | grep -c '^  - id:'
    jq -r '.checks[] | select(.analyzer == "semgrep") | .applicability | join(",")' "$C" | sort | uniq -c
    cat go/internal/scanner/semgrep/rules/*.yaml | grep -c '^    mode: taint'
    cat go/internal/scanner/semgrep/rules/*.yaml | grep -c 'fendix_reachability: taint'
    ```

  - **Variants are not counted as checks.** Pattern alternatives inside a
    rule (`pattern-either` branches, the one-hop helper forms of a Java
    taint rule) belong to that rule and add nothing to the count; no figure
    is given for them. 21 Semgrep rules are `-sink` variants: each reports
    the sink shape of the vulnerability its `-taint` partner (the same id
    stem) reports with a proven in-function flow. They have their own ids
    and findings, so they are counted; the 50 `-taint` and `-sink` rules
    share 29 stems, and counting each pair once would leave 53 Semgrep
    detections instead of 74.

    ```sh
    jq '[.checks[].id | select(endswith("-sink"))] | length' "$C"
    jq '[.checks[].id | select(test("-(taint|sink)$"))] | length' "$C"
    jq '[.checks[].id | select(test("-(taint|sink)$")) | sub("-(taint|sink)$"; "")] | unique | length' "$C"
    ```

  - **Framework-specific detections: 5.** Only five checks match one
    framework's API and name it in their id, all Python Semgrep rules:
    `django-view-missing-login-required`, `django-orm-raw-sql`,
    `fastapi-route-missing-auth-dependency`, `flask-route-no-auth-decorator`
    and `flask-render-template-string-injection`. Every other check applies
    to a language. The JavaScript/TypeScript, Java and Go taint rules carry
    framework-specific sources (Express, NestJS and Next.js; Spring;
    net/http and Gin) inside language-wide rules. The contract has no
    framework field, so per-framework detection is not a catalog count; it
    is measured per framework by the parity corpus, nine framework
    directories under `benchmarks/frameworks/`.

    ```sh
    jq -r '.checks[].id | select(test("^(django|flask|fastapi|express|nestjs|nextjs|spring|gin)-"))' "$C"
    jq -c '[.checks[] | keys[]] | unique' "$C"
    ls -d benchmarks/frameworks/*/ | grep -vc results
    ```

  - **Enabled: 158; disabled: none.** Every check has `availability`
    `stable`: the generator sets that value for every entry
    (`go/internal/catalog/security.go`, `python_engine.go`), so the contract
    cannot mark a check disabled or preview. There is no per-check off
    switch, and Semgrep is given the whole embedded rules directory, so all
    74 rules run whenever Semgrep runs (it is `skipped`,
    `dependency_missing`, when it is not installed). What differs is when a
    check runs: 149 are `passive`; of the 15 DAST checks, 7 are `active` and
    run only with `--enable-active`, 1 (`auth`) needs credentials and 1
    (`idor`, `multiuser`) needs two users. Each check runs only against its
    `applicability` (`url` for DAST, a language or `code` for the rest). The
    YAML under `python/rules/` is read by no code and is not in the catalog.
    The reachable taint tier is off for every language
    (`semgrep.ReachabilityLanguages` is empty): the 29 taint rules run, and
    their findings are `semgrep_shim`.

    ```sh
    jq -r '.checks | group_by(.availability)[] | "\(.[0].availability) \(length)"' "$C"
    jq -r '.checks | group_by(.execution_mode)[] | "\(.[0].execution_mode) \(length)"' "$C"
    (cd go && go test -count=1 -run 'TestNoLanguageClearsTheRealWorldGate' ./internal/scanner/semgrep/)
    ```

  - **Warn-only and blocking are not properties of a check.** The contract
    has no such field (the `keys` command above). Whether a finding blocks
    is decided per finding, from its confidence band and `--fail-on`. A
    Semgrep finding scores 40 (MEDIUM: base 35, static evidence +10, Semgrep
    tier −5), and under default confidence gating a MEDIUM finding blocks
    only with an independent corroborating signal, so none of the 74
    Semgrep checks blocks on its own; with `--enforce-confidence=false`
    (severity only) a finding at or above the threshold blocks whatever its
    analyzer. Measured on this tree, a scan of `benchmarks/frameworks` with
    Semgrep 1.182.1 (`fendix scan --code benchmarks/frameworks --format json
    --offline --fail-on high --output r.json`, `semgrep` recorded `ok`) gave
    118 findings: 91 `semgrep_shim` findings from 44 of the 74 Semgrep rules,
    all WARN; 9 textscan (`native_go`), all WARN; 16 Python-engine
    (`tree_sitter_sidecar`), 11 BLOCK; and 2 with no tier
    (`secrets/DB_CONNECTION_STRING`, `SEC-JS_SQL_TEMPLATE`), both BLOCK.
    Which of the 84 checks outside Semgrep can block is decided per finding
    and is not counted.

    ```sh
    (cd go && go test -count=1 -run 'TestNoBlockWithoutCorroboration|TestSemgrepTaint' ./internal/decision/)
    (cd go && go test -count=1 -run 'TestSemgrepTierPenalty' ./internal/confidence/)
    jq -r '.findings[] | "\(.source_tier // "none") \(.status)"' r.json | sort | uniq -c
    jq '[.findings[] | select(.source_tier == "semgrep_shim") | .rule_id] | unique | length' r.json
    ```

  - The contract's `engine_version` reads `v3.7.0` (`StableEngineVersion`
    in `go/internal/catalog`) until it is bumped for this release.
- **Published accuracy figures are pending re-measurement.** The blind
  holdout recall (measured at commit `e03655a`) and the real-world blocking
  precision (commit `6901cf7`), both on Semgrep 1.141.0, describe neither
  this release's Semgrep (1.182.1) nor the detection changes above,
  including this section's. They are kept as measured, labelled with their
  commit, and are to be re-measured at the release commit before they are
  quoted for it. The release workflow's holdout job compares recall only,
  does not gate the release, and passes without measuring when its deploy key
  is absent, so a release run is not evidence that they were re-measured.
  Four open-redirect cases the development corpus labels safe (net/http,
  Gin, Next.js and Spring) can be bypassed with a tab or newline in the
  target, so the development figures for open redirect in those frameworks
  are scored against those labels. After this section's changes the parity
  gate was re-run for Django, Flask, FastAPI and Spring (no case change);
  Express, NestJS, Next.js, net/http and Gin were not re-run.


## [3.7.0] - 2026-10-25

The GitHub Action now fails closed when an analyzer it requires cannot run,
Semgrep first. Until v3.6.5 a runner whose Semgrep could not scan passed the
gate: on a self-hosted runner with glibc older than 2.34, pip built Semgrep
1.182.1 from source without `semgrep-core`, the scan recorded `semgrep`
failed and coverage incomplete, and the job still went green. An unavailable
required analyzer can no longer produce a green release gate.

The engine gets the same fix: a fatal Semgrep run is now recorded `failed`,
never `ok`, so a Semgrep that dies on the scanned tree fails a required
Semgrep there too. Report schema, SARIF structure, fingerprints, finding
identity, decision policy, CLI flags and defaults, and the meaning of each
exit code are otherwise the same as v3.6.5. The Python lock is v3.6.5's
(Semgrep 1.182.1, MCP 1.29.0).

**Why a minor release:** it adds a public Action input, `require-analyzers`,
and makes failing closed the default, so the Action now exits 2 on a runner
whose Semgrep cannot run, and a fatal Semgrep run exits 2 under
`--require-analyzers`, `--fail-on-coverage-gap` or `--fail-on-scanner-error`.
The Action stays on `v1`: inputs are only added, and `require-analyzers: none`
opts out explicitly.

### Security

- **The Action requires Semgrep for every code scan, and checks it runs.** A
  new `require-analyzers` input defaults to `auto`, which requires `semgrep`
  whenever `code` is set. A required analyzer fails closed twice:
  - **Before the scan.** A new step, *Preflight required analyzers*, runs the
    Semgrep the scan will run, from the prepared environment, on a bundled
    rule and file, offline (`--metrics=off --disable-version-check`), with a
    90 s bound, and requires their one match. A missing executable, a Semgrep
    without `semgrep-core`, a damaged install that reports nothing, a startup
    crash, a binary for another architecture and a hang each fail setup with
    exit 2 and their own message, under an error titled *Fendix required
    analyzer semgrep is unavailable*.
  - **During the scan.** The required list is passed to the engine as
    `--require-analyzers`, so an analyzer that passed the preflight and then
    is not delivered (recorded anything but `ok` or `not_applicable`) exits 2.
    `extra-args` cannot cancel it: a repeated `--require-analyzers` only adds
    names, and a flag that disables a required analyzer, such as `--fast`,
    exits 2.
- **No source builds.** The Action installs the engine's Python dependencies
  from wheels only (`--only-binary=:all:`), for the release lock and for a
  caller-managed `engine_path`, as the official image already did. A package
  with no wheel for the runner stops preparation with exit 2. The error names
  the package, the runner's C library and version, its architecture and the
  supported floor (glibc 2.34 or later, or musl 1.2 or later, on x86_64 or
  aarch64 for Semgrep), with the remedies.
- **No upload of a partial result.** SARIF goes to code scanning only when the
  scan finished (exit 0 or 1). A report a failed scan left, for example one
  without the required Semgrep, is no longer uploaded: code scanning would
  have closed every alert missing from it.
- **No misleading success.** The gate prints its clean-scan line only when the
  scan ran, its required analyzers were delivered and coverage was complete.
  A pass with coverage incomplete is a warning that names the gaps; a pass with
  `require-analyzers: none` is a warning that coverage is not enforced. Every
  local-mode run now writes a job summary with the result, the exit code, the
  required analyzers and the coverage.

- **A fatal Semgrep run is `failed`, not `ok`** (engine, every
  integration). Until v3.6.5 the engine accepted any parseable Semgrep JSON
  envelope whatever the exit code, and read stdout that was not JSON as zero
  findings. A Semgrep whose engine was killed mid-run, for example by the
  kernel for memory, prints a valid envelope with an error and no results
  and exits 2. That was recorded `semgrep ok` with no findings, and passed
  `--require-analyzers semgrep` with exit 0. The preflight cannot catch it,
  because it happens only on the scanned tree. Now, following Semgrep
  1.182.1's own contract (its `error.py`, `output.py` and `core_output.py`,
  and recorded runs of the real binary):
  - **`failed/execution_error`:** a non-zero exit other than 1, a death by
    signal, or any error of level `error`. That covers an invalid or missing
    config (exit 7), a rule that does not parse (exit 2), and an engine killed
    or crashed, out of memory included (exit 2). An error-level entry counts
    even on exit 0, because Semgrep sets its exit code from its last error
    only: a rule parse error followed by per-file warnings exits 0. The detail
    names the first error, bounded to one line.
  - **`failed/malformed_output`:** exit 0 with no JSON results envelope.
  - **Still `ok`:** per-file problems of level `warn` (a file that does not
    fully parse, a per-file or per-rule timeout, a per-file memory limit) are
    normal on real trees and leave the run `ok`. They are no longer
    invisible: `detail` counts them by type, for example `1 non-fatal
    per-file problem(s) reported by semgrep (PartialParsing 1)`, never with
    the message, which can quote the source. Only an error's `level` is read,
    never its `code`, because a per-file timeout has `code` 2 at level `warn`.
  - **Findings kept.** Findings Semgrep still printed in a failed run stay in
    the report.

### Changed

- **`require-analyzers` input** (default `auto`). `auto` requires `semgrep`
  when `code` is set and nothing for a URL-only scan, where the engine records
  Semgrep `not_applicable`. An explicit comma-separated list requires exactly
  those engine analyzer names; an unknown name fails setup. `none` is the
  explicit opt-out: nothing is required, a Semgrep with no wheel for the runner
  is left out with a warning (the scan records it `unavailable`), and the gate
  warns that coverage is not enforced. Managed mode accepts only `auto`,
  because the binding's backend policy decides what is required there; Semgrep
  must still pass its preflight before evidence is submitted.
- **Engine preparation exits 2** on failure (was 1), the engine's setup-failure
  code. The job outcome is unchanged: the gate already failed closed with 2.
- **The official images check that Semgrep scans.** `Dockerfile` and
  `Dockerfile.app` run the Action's preflight against the installed Semgrep
  after the lock install, so an image whose Semgrep cannot scan fails to
  build. The release smoke still requires `semgrep` `ok` in a real scan.

### Upgrading

- **Self-hosted Linux runners with glibc older than 2.34 now fail code scans
  at setup.** This affects Ubuntu 20.04 and Debian 11 (glibc 2.31), RHEL,
  Rocky Linux and AlmaLinux 8 (2.28) and Amazon Linux 2 (2.26), with v3.6.5 or
  later installed (`version: v3.6.5`, or `latest`). Until v3.6.5 the Action
  passed there with Semgrep failed; now it exits 2 before the scan, naming
  Semgrep, the runner's glibc and architecture. GitHub-hosted runners, the
  official image and hosts with glibc 2.34 or later (Ubuntu 22.04, Debian 12,
  RHEL 9, Amazon Linux 2023) are not affected. Choose one:
  - run Fendix in the official image as a container job, pinned by digest
    (`docker.io/fendixapp/fendix@sha256:...`;
    [INTEGRATION_GUIDE §3.4](docs/INTEGRATION_GUIDE.md#34-the-docker-image-invoked-directly)
    has the job and the current digest);
  - move the runner to glibc 2.34 or later;
  - `version: v3.6.4`, whose Semgrep 1.141.0 has a wheel for glibc 2.17. It
    passes the preflight, but gives up v3.6.5's fixes (see its Upgrading
    notes);
  - `require-analyzers: none`, to scan without Semgrep. The job can pass, and
    its gate warns that coverage is not enforced.
- **`extra-args: --fast` now fails a code scan** with exit 2, because it
  disables the required Semgrep. Set `require-analyzers: none`, or a list
  without `semgrep`, to keep using it.
- **`extra-args: --require-analyzers semgrep`**, recommended in v3.6.5's notes,
  is no longer needed for code scans; keeping it is harmless.
- **A scan that exits 2 no longer uploads SARIF.** Code-scanning alerts stay as
  the last finished scan left them.
- **The native CLI keeps its defaults.** Semgrep stays optional: without it
  the scan records `semgrep` unavailable and coverage incomplete, and the exit
  code is decided by the analyzers that ran. `--require-analyzers semgrep`
  makes it required. What changes is that a Semgrep that ran and failed
  fatally is now recorded `failed`. A scan with `--fail-on-scanner-error`,
  `--fail-on-coverage-gap` or `--require-analyzers semgrep` therefore exits 2
  on such a run, where v3.6.5 passed it. Without those flags the exit code is
  unchanged, and the report shows the gap.
- **`semgrep` `ok` can now carry a `detail`** counting per-file problems.
  Consumers that read `detail` only for non-ok entries are unaffected.
- **`@v1` still points to the v3.6.2 release commit.** It moves to the v3.7.0
  release commit after that release's external-user end-to-end run; until
  then, the fail-closed Action is available by pinning the v3.7.0 release
  commit.

## [3.6.5] - 2026-10-25

A security patch on v3.6.4. It fixes the two HIGH vulnerability sets left in
the official image:
- golang.org/x/mod in the `fendix` binary;
- MCP in the image's Python environment and the Action's hash-locked install.

Fixing MCP moves Semgrep from 1.141.0 to 1.182.1. The image now installs its
Python packages from the same hash-locked file the Action installs, and its
build applies the Debian security updates. One engine change goes with the
upgrade: Fendix now runs Semgrep without Semgrep's version check (see Fixed).

Report schema, SARIF structure, fingerprints, finding identity, decision
policy, exit codes and the Action's inputs and outputs are unchanged.

> **Addendum, 2026-10-25.** As first published, this entry did not mention a
> new platform requirement: Semgrep 1.182.1 runs only on Linux with glibc
> 2.34 or later. That affects the Action and other installs of this
> release's Python dependencies on older self-hosted runners. See the new
> item under Upgrading. The v3.6.5 tag message keeps the original wording.

### Security

- **golang.org/x/mod 0.40.0** (was 0.35.0). It is linked into the `fendix`
  binary through golang.org/x/vuln, so every release artifact carries it:
  standalone binaries, `.deb`/`.rpm`, Homebrew and the official image. It
  fixes:
  - GO-2026-6180 (CVE-2026-56864): `sumdb` accepted unrelated,
    unauthenticated hashes in `Lookup`, so a coordinating GOPROXY and GOSUMDB
    could serve module content that is not in the transparency log.
  - GO-2026-6179 (CVE-2026-56865): a `sumdb/tlog` tile verification bypass
    let a malicious GOPROXY forge tiles and get module content past the
    GOSUMDB check.

  Minimal version selection also moves golang.org/x/tools 0.44.0 to 0.49.0,
  x/sync 0.20.0 to 0.22.0, x/sys 0.43.0 to 0.47.0 and x/telemetry, because
  x/mod 0.40.0 requires them. x/vuln stays at 1.3.0.
- **MCP 1.29.0** (was 1.16.0), through Semgrep 1.182.1. Semgrep pins MCP
  exactly, and 1.173.0 is the first Semgrep release on 1.29.0. It fixes:
  - CVE-2025-66416 (GHSA-9h52-p55h-vw2f, fixed in 1.23.0): DNS rebinding
    protection was not enabled by default.
  - CVE-2026-52869 (GHSA-jpw9-pfvf-9f58, fixed in 1.27.2): the HTTP
    transports served session requests without verifying the authenticated
    principal.
  - CVE-2026-59950 (GHSA-vj7q-gjh5-988w, fixed in 1.28.1): the WebSocket
    server transport did not support Host/Origin validation.

  Fendix runs `semgrep scan` and never starts Semgrep's MCP server. The
  package still shipped in the image and in the Action's environment, and it
  is upgraded in both.
- **Debian security updates in the image.** The image build now runs
  `apt-get upgrade`, so the image carries the Debian 13 security updates
  published after its base image digest (see Changed).
- **Image scan.** A linux/amd64 candidate built from this tree on 2026-10-25,
  against the published v3.6.4 image, scanned with Trivy 0.75.0 (`--severity
  HIGH,CRITICAL --scanners vuln`, one database, updated 2026-10-25T01:20Z):
  - CRITICAL: 0 in both.
  - HIGH: 102 in v3.6.4, 44 in the candidate. No row was added.
  - The 58 rows that go are the two x/mod rows, the three MCP rows and 53
    Debian rows in util-linux and its libraries (CVE-2026-53612 to
    CVE-2026-53615), OpenSSL (CVE-2026-14456, CVE-2026-45447,
    CVE-2026-84782), PCRE2, SQLite, gzip and libcap2.
  - The 44 that remain are Debian packages with no fixed version published:
    util-linux (CVE-2026-76642, CVE-2026-78408 to CVE-2026-78410), ncurses
    (CVE-2025-69720), systemd's libsystemd0 and libudev1 (CVE-2026-16742),
    libacl1 (CVE-2026-54369) and perl-base (CVE-2026-9538, fix deferred).
  - A release build applies the updates published on its own build day, so
    its Debian rows can differ from this candidate's.

### Fixed

- **Semgrep no longer contacts semgrep.dev on every scan.** Fendix now runs
  Semgrep with `--disable-version-check`. Before, every run first asked
  semgrep.dev whether a newer Semgrep existed. That held for every scan that
  ran Semgrep, `--offline` included, although the README says Semgrep runs
  locally and that Fendix does not phone home.
  - With no route out, the check waited before the scan started: about 25 s
    with Semgrep 1.141.0 and 96 s with 1.182.1.
  - With 1.182.1 that wait was enough to push an offline scan of a mid-size
    repository past Semgrep's 120 s limit. A candidate without this fix
    recorded `semgrep` failed/timeout and incomplete coverage on a
    repository of about 760 Python files, where v3.6.4 recorded `semgrep` ok.
  - With the flag, an offline Semgrep run over an empty directory takes
    about 1 s with either Semgrep, and the accuracy benchmark's four offline
    runs took 39 s instead of v3.6.4's 2 min 6 s.

### Changed

- **Semgrep 1.182.1** (was 1.141.0) in the official image and in the
  Action's hash-locked install. `python/requirements.txt` now requires
  `semgrep>=1.182.1`.
  - **The rule pack.** All 23 bundled rules load under 1.182.1 with no error,
    skipped rule or warning, as under 1.141.0. `semgrep --validate` reports 0
    configuration errors with both versions.
  - **Detection, titles and fingerprints: no change measured.** On the
    accuracy corpus, Semgrep 1.182.1 reports the same 11 matches as 1.141.0,
    with the same rule, location, message and metadata. The accuracy
    benchmark (`scripts/accuracy`, run as for the v3.6.3 measurement: linux/amd64,
    `--network none`, three runs with `--python-engine` and one without)
    gives 38 TP, 0 FP, 0 FN and 18 TN, F1 1.000. All four raw outputs are
    byte-identical to v3.6.3's and v3.6.4's.
  - **Finding by finding.** Compared with v3.6.4, nothing differs in rule id,
    title, severity, status, confidence, fix text, fingerprint, `fingerprint_v1`
    or occurrence fingerprints. The scans compared are the benchmark scan, the
    Semgrep-only corpus scan, the deterministic and online coverage smokes
    (govulncheck, pip and npm findings included) and an offline scan of a
    real Django repository. The four Semgrep finding groups and nine
    occurrences of the published v3.6.3 Semgrep-only measurement are
    reproduced exactly.
- **The image installs the hash-locked Python dependencies.** `Dockerfile`
  and `Dockerfile.app` install `python/requirements.lock` with
  `--require-hashes --only-binary=:all:`, then run `pip check`. Until v3.6.4
  they installed `requirements.txt` without the lock, so the image got
  whatever versions the package index served on its build day, and these
  could differ from the Action's. The image and the Action now install the
  same Python package versions. The interpreters still differ: the image
  runs CPython 3.14, and the Action's venv runs 3.11.
  - The lock moves only where Semgrep 1.182.1 requires it: click 8.4.2,
    glom 25.12.0, jsonschema 4.25.1 (was 4.26.0), ruamel-yaml-clib 0.2.15
    and tomli 2.4.1. It adds pyjwt 2.15.1 with cryptography 50.0.2, cffi and
    pycparser, `opentelemetry-instrumentation-threading` and
    `semantic-version`. Pydantic stays at 2.13.5, and certifi at 2026.10.23.
  - `openapi-spec-validator` is removed from `requirements.txt`, together
    with the six packages only it needed. Its 0.9.0 requires
    `jsonschema>=4.26.0`, Semgrep 1.182.1 requires `jsonschema~=4.25.1`, and
    nothing in Fendix imports it.
  - ruamel-yaml-clib 0.2.15 ships CPython 3.14 wheels, so the image build no
    longer compiles it and no longer installs `build-essential`. In v3.6.4
    that toolchain's purge left `binutils`, `cpp`, `dpkg-dev`,
    `libcrypt-dev` and `perl` in the image. They are gone.
- **The image build applies Debian security updates.** The base image is
  pinned by digest, so its packages are as old as that digest. Until v3.6.4
  only the transient `build-essential` install upgraded some of them, as a
  side effect (`libc6`, `perl-base`, `liblzma5`). An explicit `apt-get
  upgrade` now applies every published update. The Python interpreter and
  pip are the base image's, unchanged.

### Upgrading

- **Nothing to migrate.** No configuration, baseline or `.fendix-ignore`
  change is needed, and finding identity is unchanged.
- **Your own Semgrep.** A standalone binary runs the `semgrep` on the
  host's `PATH` and now passes it `--disable-version-check`. Semgrep 1.45.0,
  1.141.0 and 1.182.1 all accept the flag (checked).
- **Installing `python/requirements.txt` yourself** now resolves Semgrep
  1.182.1 or later, and no longer installs `openapi-spec-validator`.
- **The GitHub Action is unchanged,** and `@v1` still points to the v3.6.2
  release commit. To install this release, set `version: v3.6.5`, or leave
  `version` unset to install the latest release. Either way, the Action
  installs this release's lock, so its Python environment moves to Semgrep
  1.182.1 and MCP 1.29.0 too.
- **Self-hosted Linux runners need glibc 2.34 or later for Semgrep.** No
  Semgrep release with the MCP fix supports an older glibc. Semgrep 1.173.0
  to 1.182.1 publish Linux wheels only for glibc 2.34 or later
  (`manylinux_2_34`) and musl 1.2 or later (`musllinux_1_2`). Semgrep 1.141.0
  published `manylinux2014` wheels, which need only glibc 2.17. On an older
  glibc, pip builds Semgrep 1.182.1 from its source distribution, and that
  build has no `semgrep-core`.
  - **Affected:** the Action on a self-hosted Linux runner with glibc older
    than 2.34, and any other install of this release's
    `python/requirements.lock` or `requirements.txt` on such a host,
    including a caller-managed `engine_path`. Examples are Ubuntu 20.04 and
    Debian 11 (glibc 2.31), RHEL, Rocky Linux and AlmaLinux 8 (2.28), and
    Amazon Linux 2 (2.26).
  - **Not affected:** GitHub-hosted runners, the official image (Debian 13,
    glibc 2.41), hosts with glibc 2.34 or later (Ubuntu 22.04, Debian 12,
    RHEL 9, Amazon Linux 2023), and scans that do not run Semgrep.
  - **What happens:** the install succeeds and the scan runs. The scan
    records `semgrep` as `failed` (`execution_error`: "Failed to find
    semgrep-core in PATH or in the semgrep package.") and coverage as
    incomplete. It does not fail because of this: the exit code, and so the
    Action's gate, is decided by the analyzers that ran. This was reproduced
    on Debian 11 with the Action's install command. With v3.6.4's lock,
    Semgrep 1.141.0 installs from its wheel and runs.
  - **What to do:** run the official container image, or move the runner to
    a distribution with glibc 2.34 or later. Setting `version: v3.6.4` also
    works, but it gives up this release's fixes: v3.6.4 keeps MCP 1.16.0 with
    its three HIGH advisories (Fendix never starts Semgrep's MCP server),
    golang.org/x/mod 0.35.0 in the binary, and the semgrep.dev version check
    on every Semgrep run. To make the job fail when Semgrep does not run, add
    `extra-args: --require-analyzers semgrep`. The scan then exits 2 when
    Semgrep is not delivered.

## [3.6.4] - 2026-10-24

A security rebuild of v3.6.3. The scanner source is unchanged; what changes
is the toolchain and one bundled certificate store:
- release binaries, packages and the official image are built with Go 1.27.3
  (was 1.27.1), and the image ships Go 1.27.3 for govulncheck;
- the image's Python environment and the Action's hash-locked engine install
  carry certifi 2026.10.23.

Report schema, SARIF structure, fingerprints, finding identity, decision
policy, exit codes and the Action's inputs and outputs are unchanged.

### Security

- **Go 1.27.3.** The `fendix` binary in every release artifact (standalone
  binaries, `.deb`/`.rpm`, Homebrew and the official image) and the Go
  toolchain the image ships move from Go 1.27.1 to Go 1.27.3, which fixes:
  - GO-2026-6809 (CVE-2026-111943): `crypto/x509` now rejects the eMudhra
    (emSign) intermediate CA certificates whose private keys were
    compromised. Every TLS connection the engine makes is verified through
    it, including connections to scan targets, to the vulnerability
    databases, and, in the image, to the Go module proxy and the Go
    vulnerability database govulncheck reads.
  - GO-2026-6611 (CVE-2026-78669), fixed in Go 1.27.2: excessive CPU
    consumption from repeated initial window changes in `net/http`.
  - GO-2026-6609 (CVE-2026-78667): no limit on the size of parsed `Range`
    headers in `net/http`.
  - GO-2026-6607 (CVE-2026-97031): malformed ECH outer extension references
    in `crypto/tls`.
- **certifi 2026.10.23 (GHSA-6q48-6c7w-9gw2).** certifi before 2026.10.19
  bundles the `emSign ECC Root CA - G3` root, under which eight eMudhra
  intermediate CAs have compromised private keys. requests and httpx verify
  TLS against this bundle. The official image's Python environment and
  `python/requirements.lock`, which the composite Action installs with
  `--require-hashes`, now carry 2026.10.23. `python/requirements.txt` gains a
  `certifi>=2026.10.19` floor, because the Dockerfiles install it without the
  lock.

### Changed

- **govulncheck in the official image evaluates the standard library at Go
  1.27.3.** govulncheck reports standard-library advisories against the
  toolchain that loads the module, which in the image is the bundled one. A
  Go module scanned with the v3.6.3 image that reaches
  `x509.Certificate.Verify` was reported as affected by GO-2026-6809; with
  v3.6.4 it is not. Scans of Go repositories in the image can therefore
  report fewer standard-library findings than v3.6.3 did. A standalone binary
  uses the `go` command on the host's `PATH`, so its results do not change.

### Upgrading

- **Nothing to migrate.** No configuration, baseline or `.fendix-ignore`
  change is needed, and finding identity is unchanged.
- **A `GODEBUG=http2client=0` workaround can go.** If you set it to contain
  CVE-2026-78669 on v3.6.3 or earlier, v3.6.4 no longer needs it: the binary
  carries the fix.
- **The GitHub Action is unchanged,** and `@v1` still points to the v3.6.2
  release commit. To install this release, set `version: v3.6.4`, or leave
  `version` unset to install the latest release.

## [3.6.3] - 2026-10-17

A security-correctness patch:
- one Flask finding gave remediation advice that, if followed, left a route
  unauthenticated;
- four bundled Semgrep rules could never match;
- the public security catalog printed raw Semgrep metavariables.

Report schema, SARIF structure, fingerprints, finding identity, exit codes and
the Action's inputs and outputs are unchanged.

> **Correction, 2026-10-17.** This entry first said the repaired JWT rule
> blocks under `--fail-on HIGH`, and that scans can now block where v3.6.2
> passed. Under the default confidence-gated `--fail-on`, neither is true: an
> uncorroborated Semgrep finding remains WARN, as
> [docs/semgrep-rules.md](docs/semgrep-rules.md) describes, so the
> release-gate outcome is unchanged from v3.6.2. The two passages below are
> corrected. The v3.6.3 tag message keeps the original wording.

### Fixed

- **`flask-route-no-auth-decorator` gave inverted advice.** Its finding said
  an auth decorator belongs "directly above the @app.route(...) line". Flask's
  `route()` must be the outermost decorator, so following that advice
  registered the unwrapped view and left the route unauthenticated. The
  finding's fix text, SARIF help and catalog remediation now say the decorator
  goes directly below `@app.route(...)` and that one placed above it does not
  protect the route. Only the text after "directly" changed, so every finding
  keeps its title, fingerprint, grouping and baseline match.
- **Four bundled Semgrep rules never matched.**
  - `python-eval-injection`, `python-jwt-decode-no-verification`,
    `python-sql-injection-string-format` and
    `python-command-injection-shell-true` listed their alternative patterns
    as sibling `pattern:` entries. Semgrep requires all of those to match at
    once, so none of the four ever fired.
  - Each now uses `pattern-either`:
    - `eval()` / `exec()` with a non-literal argument;
    - `jwt.decode()` with `verify_signature: False` or `"none"` among the
      algorithms;
    - an `execute()` query built with `%`, `+`, an f-string or `.format()`;
    - `os.system()` / `os.popen()` with a non-literal command.
  - `subprocess(..., shell=True)` stays with
    `python-subprocess-shell-true-with-variable`, so it is reported once.
  - The Python analyzer already detects most of these shapes. Where it and
    these rules flag one location in the same category, the location is
    still reported once.
  - These rules add the first detection of
    `jwt.decode(..., algorithms=["none"])`, which no analyzer caught.
  - Where the Python analyzer does not run, they are the only detection for
    every shape above, for example in a standalone binary without its
    Python engine.
  - **Known overlap.** When both analyzers run,
    `jwt.decode(..., options={"verify_signature": False})` can produce two
    findings for the same call:
    - a Python-analyzer finding (`python.ast/PY_JWT_WEAK`, category
      `auth_bypass`, HIGH);
    - a Semgrep finding (`python-jwt-decode-no-verification`, category
      `auth`, CRITICAL).

    Both describe the same real insecure call. Each keeps its own evidence and
    analyzer provenance, and the second finding does not mean the code ran
    twice. Under the default confidence-gated `--fail-on`, both are WARN. The
    Semgrep finding is CRITICAL severity, but without qualifying
    corroboration a Semgrep-only finding stays in the MEDIUM confidence band
    and does not block. This shape's release-gate outcome is unchanged from
    v3.6.2. v3.6.3 does not change how findings from different analyzers are
    correlated or which verdict takes precedence. Merging the two without
    lowering the verdict is tracked in
    [#127](https://github.com/Fendix-app/Fendix/issues/127).
- **The public security catalog printed raw Semgrep metavariables.** Eleven
  checks published titles and remediation such as "found in '$VAR'" or
  "Flask route '$FUNC'". Rules whose message interpolates a metavariable now
  carry static `fendix_title` and `fendix_remediation` metadata, which the
  catalog publishes in their place. Runtime findings still name the matched
  symbol.
- **A Semgrep rule clause was silently ignored.** A `pattern-not` sat
  outside `patterns:` in `python-hardcoded-secret-assignment`, so Semgrep
  skipped it with a warning. It was redundant and is removed; detection is
  unchanged.

### Changed

- **The Fendix Action is the recommended GitHub integration.** The README,
  the integration guide and `docs/ci-cd-integration.md` recommend
  `uses: Fendix-app/Fendix@v1` with an explicit `version`, show the full
  release commit as the immutable choice for high-assurance pipelines, and
  keep the digest-pinned reference workflow as an alternative. `v1` points to
  the v3.6.2 release commit, which passed the external-user end-to-end
  matrix. The public-claims check now flags a branch reference such as
  `Fendix-app/Fendix@main` instead of `@v1`.
- **The Action is listed on GitHub Marketplace** as
  [Fendix Security Scan](https://github.com/marketplace/actions/fendix-security-scan), published from the v3.6.2
  release in the Security and Continuous integration categories. The README,
  the integration guide and `docs/ci-cd-integration.md` link the listing, and
  the public-claims check no longer treats "public Marketplace Action" as an
  obsolete claim.

### Upgrading

- **New findings.** Scans can now report findings that v3.6.2 did not.
  These are findings v3.6.2 should have reported:
  - `eval()` / `exec()` with a non-literal argument;
  - SQL built by string formatting;
  - `os.system()` / `os.popen()` with a non-literal command;
  - JWT decoding with signature verification disabled or the `"none"`
    algorithm.

  The default `--code` scan, the official image and the Action run the Python
  analyzer, which already reported most of these. There, two findings are new:
  `algorithms=["none"]`, and the Semgrep `verify_signature: False` finding
  described above. Without the Python analyzer, every one of these shapes is
  new.

  These findings carry their rule severity: CRITICAL, or HIGH for `eval()` /
  `exec()`. Under the default confidence-gated `--fail-on`, an uncorroborated
  Semgrep finding remains WARN, so the release-gate outcome is unchanged from
  v3.6.2. With `--enforce-confidence=false`, the legacy severity-only gate,
  they block at or above the threshold and are marked `policy_override`.
- **Finding identity is unchanged.** No title, fingerprint, grouping key,
  baseline entry or `.fendix-ignore` match changes. The
  `flask-route-no-auth-decorator` Fix text and SARIF help change for new scans;
  stored scans and existing Jira tickets keep the old text.
- **The GitHub Action is unchanged,** and `@v1` still points to the v3.6.2
  release commit. To install this release, set `version: v3.6.3`, or leave
  `version` unset to install the latest release.

## [3.6.2] - 2026-10-16

Fixes a coverage-integrity defect in diff-aware scans. With a relative
`--code` such as `.`, Semgrep and the native text scanner scanned none of the
changed files while reporting a clean, complete run, so the composite Action's
default pull-request check and the pre-commit hook could pass a change that a
full scan blocks. Diff scoping now gives the same result for every spelling of
the scan root, and a diff scope that cannot be represented safely widens to a
full scan instead of narrowing to nothing. Report schema, SARIF, fingerprints,
exit codes and the Action's inputs and outputs are unchanged.

### Fixed

- **Diff-aware scans with a relative `--code` scope the native scanners
  correctly.** In diff mode (`--diff`, `--staged`) with a relative code path
  such as `.` or `./`, Semgrep received absolute `--include` paths that
  matched no file and the text scanner refused every changed file, while the
  coverage table reported both as `ok`. A relative and an absolute `--code`
  now scope the same files and report the same findings at the same paths.
  The secrets scanner and the Python engine were not affected.
- **The composite Action's default pull-request setup no longer misses text
  scanner and Semgrep findings.** With `code: .` and `diff: auto`, a pull
  request adding a privileged Kubernetes container passed with zero
  findings; the same change now blocks, as it does with an absolute `code`
  or `diff: 'false'`.
- **The pre-commit hook no longer misses staged text-scanner findings.** The
  hook `fendix hook install` writes runs
  `fendix scan --code . --staged --fast`; it let a staged privileged
  Kubernetes manifest be committed, and now rejects the commit.

### Changed

- **A diff scope that cannot be represented safely widens to a full scan.**
  When a changed file cannot be placed under the scan root, the scan logs
  `diff-aware scan: file scope could not be represented safely — falling back
  to full scan` and scans `--code` in full, as it already did when `git diff`
  fails. It never narrows to scanner input that matches nothing.
- **Temporary behaviour for a subdirectory `--code`.** Git reports changed
  paths from the repository root, which the diff mapper cannot yet place under
  a subdirectory, so a diff-mode scan with `--code` set to a subdirectory now
  falls back to a full scan of `--code` (previously it scanned no changed
  file). Diff scoping for a subdirectory is planned for v3.7.0.

### Upgrading

- Pull requests scanned by the composite Action with its default `code: .`,
  and commits checked by the pre-commit hook, can now report findings and
  block where v3.6.1 passed. These are findings v3.6.1 should have reported.
- With `--code` set to a subdirectory, a diff-mode scan now reports existing
  findings across the whole `--code` tree and runs the dependency scanners,
  as a full scan does. Use a baseline to report only new findings.
- The v3.6.1 workarounds (an absolute `code` path or `diff: 'false'` in the
  Action, an absolute `--code` on the command line) remain valid and can be
  removed.

## [3.6.1] - 2026-10-15

Makes the composite GitHub Action safe to run. Its Fendix binary now runs only
after the release's cosign signature verifies, its Python engine is prepared
from verified source with a hash-locked dependency set, and its failures are
legible and fail closed. Also fixes invalid SARIF for scans with no findings.
`fendix scan` keeps its report schema, finding policy and exit codes; the diff
behaviour is unchanged and now documented accurately. Read "Upgrading" before
moving a workflow to this release.

### Security

- **The Action verifies the binary's signature before it first runs** (#113).
  It used to install Fendix before cosign existed, so the installer fell back
  to checksum-only verification and the binary ran before any signature
  check. Now:
  - cosign is installed first, for every caller, including those that set
    `engine_path`;
  - the installer bundled with the Action revision (no longer
    `get.fendix.dev`) installs one exact release from `Fendix-app/Fendix`
    with `FENDIX_REQUIRE_SIGNATURE=1`, checking the checksum and then the
    signature before installing;
  - every inherited `FENDIX_*` variable is removed from the installer's
    environment, so none can redirect the source, signer, directory or
    version, or weaken verification;
  - the binary goes into a unique private directory under `RUNNER_TEMP` and
    must report exactly the requested release before that directory is added
    to `PATH`.

  There is no checksum-only fallback.
- **The Action's SARIF upload is pinned by commit** (#109): `upload-sarif`
  v4.38.3 instead of the floating, deprecated `@v3`. The SHA-pin policy now
  covers `action.yml` as well as the workflows, and rejects `@main` and short
  SHAs, not just `@vN`.
- **The Action prepares its Python engine from verified source** (#98). The
  source is fetched at the commit named by the release's cosign-signed build
  record, and the installed binary's hash must appear in that record. A
  missing record or signature, a mismatched binary or an unsafe archive stops
  the Action.

### Fixed

- **SARIF for a scan with no findings is valid** (#106). The exporter wrote
  `"rules": null`, which SARIF 2.1.0 forbids and GitHub's `upload-sarif`
  rejects, so a clean scan failed at the upload. It now writes `"rules": []`.
  This affects `fendix scan --format sarif` and `fendix report --format
  sarif`. The goldens are validated against the OASIS SARIF 2.1.0 schema.
- **The Action works with its defaults** (#98). Every tag through v3.6.0 ran
  `fendix engine sync` with no Python tree when `engine_path` was empty, and
  failed before scanning.
- **Action failures are legible and fail closed** (#110).
  - A setup failure ends with "A setup step failed before the scan" and exit
    2, not bash's `numeric argument required`.
  - SARIF is uploaded only when the scan wrote a report.
  - Exit code `1` is a policy `BLOCK` at the configured `fail-on`, `2` a scan
    error, and any other value fails closed with `2`.
- **Clear Action setup errors** (#112), for:
  - a release that predates signed build records (they are published from
    v3.5.0);
  - a missing or incomplete record;
  - a signature that does not verify;
  - a failed download, pip install or engine sync.

  Only transient download failures are retried: at most three attempts,
  keeping the original reason.
- **Semgrep keeps running** (#97). Semgrep's MCP 1.16.x imports
  `eval_type_backport`, which Pydantic 2.14 removed; `python/requirements.txt`
  now bounds `pydantic<2.14`.
- **`fendix init --ci gitlab` keeps SARIF as an ordinary artifact** (#97). It
  no longer declares SARIF under `artifacts:reports:sast`, which expects
  GitLab's own SAST schema.
- **The `--diff` help states what diff mode scopes.**
  - The native secrets, text and Semgrep scanners read the changed files,
    whole files.
  - Dependency checks run when a manifest changed.
  - The Python engine, DAST and plugins scan the full target.
  - A failed `git diff` falls back to a full scan.

  Behaviour is unchanged.

### Changed

- **Action Python dependencies are reproducible** (#112).
  - A release's own tree installs only from its hash-locked
    `python/requirements.lock`, with `--require-hashes`. The lock is derived
    from `requirements.txt` by `scripts/release/regenerate-python-lock.sh`.
    It pins the proven line: `semgrep` 1.141.0, `mcp` 1.16.0, `pydantic`
    2.13.5.
  - Releases up to v3.6.0 have no lock and keep `requirements.txt` with the
    `pydantic<2.14` bound. A later release without a lock is refused.
  - A caller-managed `engine_path` still installs its own `requirements.txt`
    with that bound, and a lock inside it is not used.
- **`setup-python` no longer changes the caller's job environment** (#112).
  It runs with `update-environment: false`, so `pythonLocation` and
  `Python*_ROOT_DIR` are no longer set, and the tool-cache interpreter is not
  added to `PATH`. The Action's venv `bin/` and `FENDIX_ENGINE` are still
  published for later steps.
- **The Action's binary install** (#113).
  - It lives in a private temporary directory, no longer `/usr/local/bin`,
    and no `sudo` is needed.
  - A caller's `~/.curlrc` is ignored; proxies work through `HTTPS_PROXY` and
    `NO_PROXY`.
  - `version` must be an exact release tag or `latest`, which is resolved
    once. A request for `v3.6.1` never accepts `v3.6.10`.
  - The log records the verified binary's path and SHA-256.
- **The scan step** (#110). A file already at the `output` path is removed
  before the scan, so it cannot pass for the scan's report. The logged scan
  command quotes its arguments.
- **Action descriptions only.** The descriptions of `diff`, `upload-sarif`,
  `version` and `engine_path` now state their actual behaviour. No input or
  output was added, removed or renamed.
- **The reference workflow** (`examples/github-actions/fendix-scan.yml`,
  #104, #105). It pins `upload-sarif` v4.38.3 and grants `actions: read`. Its
  gate decides from the scan's exit code even when a reporting step failed,
  and fails closed. Private repositories skip the SARIF upload unless the
  variable `FENDIX_UPLOAD_SARIF` is `true`. A temporary step normalizes v3.6.0's
  `"rules": null`. It passed external end-to-end tests on `ubuntu-24.04` and
  `ubuntu-26.04` (#108).
- **Documentation** (#107 and this release). The docs recommend the reference
  workflow at a fixed, tested commit and warn against the `v1` tag. They also
  document:
  - diff behaviour;
  - the permissions for public and private repositories;
  - the GitHub Code Security requirement for private SARIF upload;
  - the Sigstore connectivity the Action requires;
  - the signed-release boundary;
  - the Python lock behaviour.

  New claim detectors flag workflow lines that use `Fendix-app/Fendix@v1`, and
  the retired diff, lock and Marketplace claims.

### Upgrading

- **Pin the Action to the v3.6.1 release commit**, with `version: v3.6.1`.
  Workflows on `@v3.6.0` or older tags keep the old behaviour. **Do not use
  `@v1`:** it still points to a June 2026 revision with known defects.
- **The runner needs outbound HTTPS to Sigstore** (its TUF root and Rekor), as
  well as to GitHub and PyPI. Without Sigstore access the Action's install
  fails, and there is no opt-out.
- **SARIF upload in a private or internal repository** needs `actions: read`
  and GitHub Code Security. Without Code Security, set `upload-sarif: 'false'`.
- **Releases without a cosign signature can no longer be installed by the
  Action.** Automatic Python preparation needs v3.5.0 or later.
- **Later steps that read `pythonLocation` or `Python*_ROOT_DIR` from the
  Action**, or that expect `fendix` in `/usr/local/bin`, need their own
  `setup-python` step or should use `fendix` from `PATH`.

### Known limitations

- **Diff mode is unchanged** and scopes whole files of the native scanners
  only; use a baseline to report only new findings. With `--code` set to a
  subdirectory of the repository, diff mode can miss changed files. Fixes are
  planned for v3.7.0.
- **The Semgrep and Pydantic line is held** at the versions above. Upgrading
  to Semgrep ≥1.180 with Pydantic 2.14 is planned for v3.7.0, as one paired
  change (#111).
- **Pull requests from forks** get a read-only token, so the Action cannot
  upload SARIF there.

## [3.6.0] - 2026-10-06

Fixes a gate bypass: baselines and `.fendix-ignore` rules suppressed whole
grouped findings, so a new production credential that the report grouped with
a baselined or ignored test fixture passed CI with exit 0. Whether it did
depended on how the directory names sorted. Identity, suppression and
baselines now act on each occurrence, and so do SARIF, `fendix jira` and
`fendix verify`. This changes the baseline file format, the scope of some
ignore rules and the shape of SARIF output; read "Changed" and "Upgrading"
before upgrading.

### Security

- **Baselines and ignore rules no longer suppress occurrences they do not
  match.** A finding groups every occurrence of one check (same severity,
  category and title) for presentation, and its `fingerprint` was its
  lexically first occurrence's. Baseline matching and `.fendix-ignore` rules
  ran on that group. Three consequences:
  - A test fixture saved in a baseline hid a new production credential in a
    directory that sorted after `tests/`, with `new_findings=0` and exit 0.
  - An `endpoint: "**/tests/**"` rule suppressed the production occurrence
    with the fixture.
  - A new occurrence that sorted first changed the group's fingerprint and
    re-reported every baselined occurrence as new.

  The engine now:
  1. stamps each occurrence's fingerprint before any grouping;
  2. applies `.fendix-ignore` and `--baseline` to each occurrence;
  3. groups only the survivors.

  As a result, the primary endpoint, evidence, secret metadata,
  `affected_endpoints` and decision of every finding come from occurrences
  that survived suppression.

- **SARIF identity is per occurrence.**
  - SARIF used to emit one result per grouped finding, located at the primary
    occurrence and keyed (`partialFingerprints`) on its fingerprint. A GitHub
    Code Scanning dismissal of a test-fixture alert therefore kept covering a
    production occurrence that later joined the same finding, and the
    production location was never shown.
  - Each occurrence of a grouped finding is now its own result, with its own
    location and `partialFingerprints`.
  - The evidence snippet, taint chain and route appear only on the occurrence
    they belong to.
  - Rules and the decision are shared, and `properties.finding_id` /
    `occurrence_count` name the group.
  - A grouped finding from a report without `occurrences` renders grouped as
    before but without `partialFingerprints`.
- **`fendix jira` tracks occurrences, not positional IDs.**
  - Idempotency was the label `fendix-id:SEC-NNN`. That positional ID is
    reassigned every scan, so an unrelated finding numbered like an old one
    was reported "Unchanged" and never ticketed. A new occurrence joining a
    ticketed finding was also covered by the existing ticket.
  - Issues now carry one `fendix-fp:<fingerprint>` label per occurrence. An
    occurrence not on any issue gets an issue of its own.
- **`fendix verify` re-tests every occurrence.**
  - A grouped finding was re-tested only at its primary location and reported
    `resolved` for the whole group.
  - Each occurrence is now re-tested. The finding is `resolved` only when every
    occurrence is, `still-present` when any is. The verdicts appear in
    `occurrences` on the result.

### Added

- `occurrences` on every finding: `[{endpoint, fingerprint}]`, one entry per
  security occurrence the finding presents. The finding's own `fingerprint`
  is always among them. This is additive, so `schema_version` stays 2.
- Baseline format v2. `--save-baseline` writes `{"baseline_version": 2,
  "fingerprint_algorithm": "fendix/v2", "findings": [...]}`, with every
  occurrence recorded. `fendix verify --baseline` reads it.

### Changed

- **Baselines.** An occurrence counts as known only when the baseline proves
  that exact occurrence was present.
  - Baselines written by v3.5.1 or earlier, and reports without
    `occurrences`, still load. Each of their entries proves its own
    fingerprint and, at each exact recorded location, a finding of the same
    category and title or rule.
  - As a one-time effect, an occurrence that was absorbed into a baselined
    group and has since moved line is reported as new. Re-save the baseline
    once.
  - A `baseline_version` above 2, or a different `fingerprint_algorithm`,
    exits 2.
- **`.fendix-ignore` scope.**
  - A `fingerprint:` rule suppresses only the occurrence it names. A rule
    copied from a grouped finding's top-level `fingerprint` used to suppress
    the whole group; to suppress other occurrences, add rules with their
    `occurrences[].fingerprint`.
  - An `endpoint:` rule, alone or with `category:`, is matched against each
    occurrence's own path. It suppresses the occurrences under that path and
    leaves the finding's other occurrences reported and gated.
  - `id:` is unchanged: it is positional and suppresses the whole presented
    group.
  - A rule that sets `fingerprint` or `id` together with `endpoint` or
    `category` now logs a warning, because only `fingerprint` or `id` is used.
- **Endpoint globs.**
  - `**` as a path segment matches zero or more directories, so
    `**/tests/**` now matches a top-level `tests/` directory.
  - `*` no longer crosses `/`.
  - A wildcard pattern with no `/` (`*.py`, `*fixtures*`) matches a path
    segment at any depth, plus everything below it, as in `.gitignore`.
  - Patterns whose only wildcard is one trailing `*` (`dir/*`, `prefix*`)
    keep their prefix meaning.
  - `\` separators in patterns match `/`.
  - These changes mostly narrow a match. Two widen it: `**/` now matches a
    top-level directory, and a slash-less pattern now matches everything
    below a directory whose name matches it. Review slash-less rules after
    upgrading.
- **Secret identifier.** The identifier is now the binding of the string
  literal that holds the credential. `create(email="…", password="…")` used
  to be named after `email`, which made the secret's identity depend on an
  unrelated preceding argument and merged distinct credentials. Findings on
  such lines get a new fingerprint once; a v3.5.1 baseline still matches them
  by recorded location.

### Upgrading

- **GitHub Code Scanning, one time.** The first SARIF upload from v3.6.0
  changes alerts for grouped findings:
  - the primary occurrence keeps its alert, because its fingerprint is
    unchanged;
  - every other occurrence of a grouped finding opens a new alert of its own;
  - a dismissal made on the old grouped alert stays with the primary
    occurrence only, so the other occurrences need their own triage;
  - a secret whose identifier changed (see "Secret identifier") opens a new
    alert once.
- **`fendix jira`** files new issues once for findings that were tracked only
  by their old `fendix-id:` label.
- **Baselines.** Re-save once with `--save-baseline` to switch to exact
  occurrence matching.
- **Legacy grouped findings.** Reports written by v3.5.1 or earlier carry no
  `occurrences`, and their grouped finding's one `fingerprint` names only its
  primary occurrence. v3.6.0 still reads them, and never extends that
  fingerprint to the other occurrences:
  - as a `--baseline`, an entry proves its own fingerprint and its exact
    recorded locations, as described under "Baselines";
  - `fendix report --input … --format sarif` renders a grouped legacy finding
    as one result, as before, but without `partialFingerprints`. Code Scanning
    then falls back to its own fingerprinting, so the result may not match an
    alert uploaded earlier, and a dismissal of that alert may not carry over.
    Re-scan with v3.6.0 for per-occurrence identities;
  - `fendix verify` re-tests each distinct affected endpoint of a grouped
    legacy finding;
  - `fendix jira` tracks a legacy finding by its own fingerprint, as one
    occurrence.
- **Consumers of the report.** A finding's top-level `fingerprint` and `id`
  are still present but name its primary occurrence and its position.
  Anything that suppresses, dismisses, tracks or proves a finding should key
  on `occurrences[].fingerprint`.

See [docs/suppression-semantics.md](docs/suppression-semantics.md).

## [3.5.1] - 2026-10-05

An identity and install-integrity release. `fendix init` now writes CI that
installs Fendix: each generated file pins the release that wrote it, fetches
the official installer at that release's commit, and requires a verified
cosign signature. New binaries carry the organization module path
`github.com/Fendix-app/Fendix/go`, and `brew upgrade` reaches installs that
older Homebrew recorded as `64`. No scanner, fingerprint, report-schema,
decision-policy or exit-code changes.

### Fixed

- `fendix init` writes CI that installs Fendix. The generated GitHub
  workflow ran `go install …@latest`, which has never resolved; the GitLab
  and CircleCI files downloaded a v0.13.0 tarball that current releases do
  not publish, against a placeholder checksum. All three now pin
  `FENDIX_VERSION` to the release of the `fendix` binary that generated
  them and install it with the official installer, fetched at
  `FENDIX_INSTALLER_COMMIT`, the commit that release was built from, so the
  script cannot be swapped by moving a tag. All three install cosign and
  require a verified release signature: the CircleCI job, whose `cimg/base`
  image has no cosign, downloads cosign v3.1.3 and checks it against pinned
  SHA-256 values before running it. All three accept an optional
  `FENDIX_SHA256` pin. A build that is not a
  release, or that does not know its commit, writes placeholders the
  install step rejects. The Docker image passes its commit in as
  `REVISION`, since its build context has no `.git`.
- `brew upgrade fendix` offers new releases to existing installs. Older
  Homebrew read the release URLs (`…-amd64`, `…-arm64`) as version `64` and
  recorded installs under it; current Homebrew reads the tag in the URL but
  ranks an installed `64` above every 3.x release, so those installs were
  never offered an upgrade. The formula now sets `version_scheme 1`, which
  ranks every release above them; the version itself still comes from the
  URL, since `brew audit --strict` rejects an explicit one as redundant. One
  generator, `scripts/release/render-homebrew-formula.sh`, now produces both
  the published formula and `Formula/fendix.rb`; CI checks they match and
  drives real Homebrew through a stuck `64` install recovering, `brew
  outdated` and `brew upgrade` from 3.5.0 to 3.5.1, a fresh install, `brew
  style` and `brew audit --strict`. The published caveats now match the
  reviewed copy: the formula does not install the Python analyzer tree.
- `install.sh` no longer falls back to the checksum alone when asked not
  to: `FENDIX_REQUIRE_SIGNATURE=1` refuses the install if cosign is missing
  or the release carries no signature, and `FENDIX_SHA256` refuses any
  binary whose hash differs from the pin. Both are opt-in; the default
  `curl … | sh` behaviour is unchanged.

### Changed

- The Go module path is `github.com/Fendix-app/Fendix/go`, matching the
  repository and the `go/` directory holding `go.mod`. New binaries report
  it in `go version -m`, stack traces and SBOMs. Nothing could import the
  previous path remotely, so no importer is affected. Remote `go install`
  is not a supported installation method.
- Verification of releases through v3.4.1, whose certificates keep the
  pre-transfer signer, lives in one place:
  `docs/historical-release-verification.md`. `install.sh` keeps that
  signer as a single labelled constant used only for those releases.
- The public-claims gate now scans Go source, init templates and Python
  source, catches every spelling of the retired personal namespace, and
  no longer depends on `rg`, which the CI runner lacks; two of its checks
  had silently never run.

## [3.5.0] - 2026-10-05

A managed-CI producer release, shipped as a preview. The engine can write
managed-CI evidence (contract `managed-ci/v2`), and the GitHub Action can
submit it to the Fendix backend and gate on the backend's Decision Record.
Nothing changes unless a workflow selects `mode: managed`. One local fix
changes exit behaviour: an invalid `--fail-on` now stops the run with exit
2 instead of silently scanning with no threshold (see "Changed"). **No
fingerprint changes**, no report schema change (`metadata.schema_version`
stays `2`), and no change to the finding decision policy.

### Added

- **Managed-CI evidence export (preview, ADR-010).** `fendix scan
  --managed-context <file> --managed-evidence <file>` writes the exact
  request body a runner submits: 17 normalized evidence facts per finding,
  taken from the same evidence the confidence scorer and decision layer
  read, plus analyzer coverage in registry order. Unmappable engine state
  or contradictory facts fail the export rather than producing a guessed
  fact. Analyzer families are reported by what the capability did: a
  failed member fails the family, a family that ran at all is `completed`.
  Findings and analyzers are always arrays, so a clean scan is a valid
  document.
- **`fendix managed context` and `fendix managed submit` (preview).**
  `context` builds the scan context from the workflow environment, using
  the pull request's head commit rather than the ephemeral merge commit.
  `submit` is the transport: the `FENDIX_CI_TOKEN` credential stays in one
  process and one header, never in argv, a log line or an error. It
  retries resets, timeouts, 429 and 5xx with jittered backoff inside a
  10-minute budget, treats 400/401/403/404/409/413/415 as terminal, polls
  only the configured origin, and never computes a local fallback
  decision. Exit 0 or 1 is the backend's decision; exit 2 means no
  decision was obtained.
- **Action `mode: managed` (preview).** The GitHub Action can run the
  managed producer, submit the evidence and gate on the backend's
  decision, which the job summary heads as authoritative. `mode: local`
  remains the default and is unchanged.
- **A signed build record per release** (`build-record.json` with cosign
  `.sig`/`.crt`). It names every published executable by the SHA-256 of
  the uncompressed binary (what the engine self-hashes at scan time), the
  managed-CI contract revision and bundle digest, the finding-policy
  version and the release workflow identity. A backend accepts managed
  evidence only from an executable a record it trusts names.
- **Generated reference contracts.** `docs/cli-contract.json`,
  `docs/config-contract.json`, `docs/reporting-contract.json` and
  `docs/security-catalog-contract.json` are generated from the executable
  registries and checked by drift tests, so the documented command, flag,
  report and rule surfaces cannot fall behind the code.

### Changed

- **`--fail-on` fails closed.** It now accepts a severity in any case
  (`high`, `High`, `HIGH`; surrounding spaces ignored) and refuses anything
  else, `INFO` included, with exit 2 before scanning. v3.4.1 matched only
  upper-case names and ran an unrecognised value as *no threshold*: `--fail-on
  high` warned on a HIGH finding and exited 0, so the requested gate was off.
  This applies to `scan`, `import` and `hook install`. A pipeline that passed
  an invalid value used to pass and now fails with exit 2; the four valid
  thresholds are `CRITICAL`, `HIGH`, `MEDIUM` and `LOW`. Classification and
  the decision policy are unchanged.
- **`fendix verify` no longer infers remediation from missing input.** A
  source file or dependency manifest that is absent or unreadable, or a
  header finding re-checked against a non-2xx response (a login or error
  page), now returns `unknown` (exit 2) instead of `resolved`. Missing
  source is not proof the finding was fixed.
- **Official distribution.** Images publish to `docker.io/fendixapp/fendix`
  (tags without a `v`: `3.5.0`, `3.5`, `3`, `latest`) and
  `ghcr.io/fendix-app/fendix`; the Homebrew tap and installer mirror is
  `Fendix-app/homebrew-fendix`; the GitHub App ships as its own image.
  The legacy GHCR package is not updated after v3.4.1. Binary signing
  certificates now carry the `Fendix-app/Fendix` workflow identity;
  certificates through v3.4.1 keep the identity they were issued with.
- **SARIF `tool.driver.informationUri`** is now
  `https://github.com/Fendix-app/Fendix`.
- **Release binaries are built and tested with Go 1.27.1**, the toolchain
  the images ship, instead of Go 1.25.
- **In managed mode the local summary is labelled diagnostic**: "Local
  diagnostic summary (NOT the managed decision)", because the managed scan
  runs with no `--fail-on` and its local report never shows BLOCK.

### Fixed

- **govulncheck reports why a Go module could not be loaded.** When the
  `go` command itself cannot run (no toolchain, a refused toolchain switch,
  module mode off), the analyzer records `failed` with the go command's
  diagnosis instead of a misleading "no go.mod file". It can never become a
  `not_applicable` skip.
- **Managed evidence over a contract ceiling** (more than 10,000 findings,
  an 8 MiB body or 200 analyzers) stops with one line naming the ceiling,
  the actual and the maximum, and exit 2. Nothing is truncated, split or
  sent.

### Known issues

Recorded in `audits/engine-contract-reconciliation-2026-10-03.md`, not
fixed in this release:

- `--offline` does not reach the Python deps check that `--code` enables, so
  it can still call networked tools. For a hermetic scan add `--checks
  auth,injection` or `--python-engine=false`, plus `--no-plugins`.
- When the Python engine runs, a remote `--spec` URL is fetched again
  without the Go private-address guard.
- `--fast` does not disable the Python phase that `--code` enables; add
  `--python-engine=false` for a native-only pre-commit scan.
- The Action's default `mode: local` path runs `engine sync` with no engine
  tree, and standalone binaries embed none: supply a version-matched tree
  or use the official container.
- The JSON `sources` counters omit imported findings, so they do not add up
  to `total` on import or mixed scans.

## [3.4.1] - 2026-09-07

A toolchain currency release. No scanner, fingerprint or exit-code changes.

### Changed

- **The images build with Go 1.27** (`golang:1.27-alpine`, previously
  1.25) and ship that toolchain, so `govulncheck` can load any module whose
  `go.mod` requires Go 1.27 or older. Under `GOTOOLCHAIN=local` a module
  that asks for a newer Go than the image carries still records
  `govulncheck` as `failed/execution_error`; that ceiling moved from 1.25 to
  1.27. The Go module floor (`go 1.25.0` in `go.mod`) is unchanged.

## [3.4.0] - 2026-09-06

A coverage-integrity release. A scan can no longer look complete when it was
not: every analyzer records whether it ran and, if not, a closed reason; the
report states its own coverage; a URL scan with zero endpoints writes its
report before exiting 2; two opt-in flags turn a gap into a failing build;
and the images ship a Go toolchain so govulncheck runs inside them. **No
fingerprint changes** and no change to default exit codes. Three behaviour
changes are listed under "Changed" because they alter existing reports:
`pip` with no manifest, npm without a lockfile, and the wider reach of
`--fail-on-scanner-error`.

### Added

- **Both images ship a Go toolchain**, so `govulncheck` runs inside them
  (`Dockerfile` and `Dockerfile.app`, the GitHub App). Every earlier image
  recorded `govulncheck` as `failed/execution_error` on any Go repository it
  scanned, because `golang.org/x/vuln` loads the module through the `go`
  command and none was present — a gap the coverage contract now makes
  visible instead of fail-open. Module resolution uses Go's default proxy
  and checksum database, so the dependency graph of a scanned repository
  leaves the scan host; set `GOPRIVATE` (and `GOPROXY`/`GONOSUMDB`) on the
  container for private modules, and an unresolvable dependency records
  `execution_error`. `GOTOOLCHAIN=local`: a module that requires a newer Go
  than the image carries records `execution_error` rather than downloading
  a toolchain during the scan; `GOFLAGS=-mod=readonly` and `GOENV=off` keep
  a scan from writing to the target or reading a user env file;
  `CGO_ENABLED=0`, since the runtime has no C compiler; caches live under
  `/tmp`. The release smoke fixture now carries a real, pinned, vulnerable
  dependency (`golang.org/x/text v0.3.0`) so the network smoke exercises
  module resolution end to end. Image size grows by roughly 300 MB (637 MB →
  946 MB on linux/arm64).
- **Coverage contract v1.** Every analyzer that can silently degrade is now
  recorded once per scan in `metadata.scanner_status`, in a fixed registry
  order, with a closed machine-readable `reason` on every non-ok entry:
  `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`,
  `govulncheck`, `pip`, `npm`, `python-engine` (plus `python-engine/auth`,
  `/injection`, `/deps` when the Python engine reports them) and `plugins`.
  `metadata.coverage` states whether everything the run was configured to
  execute actually ran (`configured_complete`), names the `gaps`, lists
  `limitations` (unsupported targets), and echoes `required_analyzers` /
  `required_gaps`. `metadata.policy_version` names the decision policy.
- **`--fail-on-coverage-gap`** exits 2 when `configured_complete` is false.
  **`--require-analyzers a,b`** exits 2 when a named analyzer was not
  delivered — `disabled` and `unsupported` do not satisfy an explicit
  requirement. Both off by default; default exit behaviour is unchanged.
- **One in-process retry** for a `network_error` or `timeout` on
  `govulncheck`, `pip` or `npm`; the entry carries `attempts: 2`. Nothing
  else is retried. There is no whole-engine re-run.
- **Python engine protocol v2** — one `{"status": {...}}` line per check.
- **SARIF** itemises every non-ok analyzer as a `toolExecutionNotification`
  (error / warning / note by class) and carries the coverage block and, on
  Fendix Cloud re-renders, the release verdict in `runs[].properties`.
  `executionSuccessful` is unchanged in default mode, strict under the new
  flags, and false on any hosted export whose coverage is incomplete.
- **HTML and PDF** gain a coverage table under the verdict.

### Changed

- **`Dockerfile.app` (the GitHub App image) builds on CPython 3.14 again.**
  It compiles semgrep's `ruamel.yaml.clib` with a transient build toolchain
  and purges it in the same layer, exactly as `Dockerfile` has since the
  cp314 base; without that the image had failed at `pip install` since the
  semgrep pin. The release network smoke now also requires an `ok`
  `govulncheck` to have reported the fixture's pinned vulnerability.
- **A URL scan that discovers zero endpoints now writes the report before
  exiting 2**, with `dast` recorded `failed/no_endpoints`. Previously it
  exited with no report and Fendix Cloud stored it as a clean scan.
- **`pip` with no manifest is `skipped/not_applicable`**, not `ok`. **An npm
  `package.json` without a lockfile is `skipped/unsupported_target`.**
- **A failed OSV lookup is no longer a silent `ok`.** `pip` and `npm` record
  `failed/network_error` when package lookups fail after every fallback,
  keeping the findings that did resolve.
- **A missing Python interpreter or engine tree is `python-engine`
  `skipped/dependency_missing`** instead of a stderr line; a Python engine
  crash, unparseable stream, missing done line or `done.total` mismatch is
  recorded as `failed` with the matching reason, and the findings received
  are kept.
- **`--fast`, `--no-native-deps`, `--offline`, `--no-plugins` and
  `--python-engine=false` record `disabled` entries** instead of leaving
  the analyzer absent from the list. Blackbox scans gain `not_applicable`
  entries where the list used to be empty.
- **SARIF `fendix report --input` of a pre-contract report** now emits a
  `warning` notification for a skipped entry that has no reason (class
  `unknown`), where it emitted nothing.
- **`--fail-on-scanner-error` now trips on any recorded analyzer, not just
  six.** It reads the whole `metadata.scanner_status` registry — `dast`,
  `spec`, `active-probes` and `plugins` and the python-engine (and its
  checks) can now cause the exit-2 failure alongside the original
  `govulncheck`/`pip`/`npm`/`secrets`/`semgrep`/`textscan`. Skipped entries
  still never count.
- **`checks_run` can now omit `"deps"` on a `--code` scan with no Python
  manifest, no `go.mod` and no `package.json`.** `pip` with no manifest
  moved to `skipped/not_applicable` (above), and the coarse `"deps"` label
  is derived from `ok` entries, so a repo with none of the three
  manifests now reports `checks_run` without `"deps"` where it previously
  included it. The derivation rule is unchanged; the derived value is not.
- **`fendix verify` can now answer `unknown` (exit 2) on a dependency
  finding where it previously answered `resolved`.** `pip.Scan`/`npm.Scan`
  return a typed lookup error on a partial OSV lookup failure instead of a
  silent `ok`, and `verifyDep` treats any re-scan error as `unknown` —
  fail-closed rather than presuming the finding is gone.

## [3.3.0] - 2026-09-02

An identity-and-honesty release. One new key is published, one report field
stops overstating what happened, and the latency harness becomes reproducible.
**No fingerprint changes**: `Fingerprint` itself is untouched, so saved
`--baseline` files and `.fendix-ignore` `fingerprint:` rules keep matching, and
no finding changes status or severity.

### Added

- **`fingerprint_v1` — the retired identity, published as a migration bridge.**
  Every finding now carries the old `sha1(Category|Endpoint|Title)` key
  alongside the canonical v2 one, as `fingerprint_v1` (omitted when empty).

  It is **not an identity and nothing may key on it**: v1 moved whenever a line
  was inserted above a finding, which is the defect v2 exists to fix. Its only
  job is to let a consumer that first tracked a finding under v1 recognise it
  after the re-key, instead of reading the transition as "the old finding
  vanished and a new one appeared" — which is how the hosted backend ended up
  with two Issues, and two SEC ids, for one vulnerability.

  Both keys are stamped together in one place (`models.StampIdentity`, called
  centrally in the orchestrator), so a future caller cannot set the canonical
  key and silently omit the bridge. Computed here rather than downstream
  because this side owns both algorithms and cannot drift from either.

- **A reproducible latency harness** (`scripts/bench/latency.py`) that records
  the environment it measured in — load average, worktree cleanliness, machine
  — and marks a result `publishable` only when that environment justifies it.
  No published figure changes in this release; the harness exists so the next
  one can be defended.

### Fixed

- **`checks_run` no longer lists checks that did not run.** The list was
  hand-appended whenever a code path was *configured*, so a scan could report
  `semgrep` under `checks_run` while `scanner_status` simultaneously recorded
  it as skipped because the binary was missing — the same document asserting a
  check both ran and did not.

  The labels are now derived from the recorded per-scanner status, and only an
  `ok` pass earns one. A consumer cannot audit a release decision made from
  evidence that was never gathered.

  `scanner_status` itself is unchanged, so **coverage evaluation and release
  decisions are unaffected**; what changes is that `checks_run` now agrees with
  it. Expect fewer labels on scans where a scanner was skipped — that is the
  correction, not a regression. The three dependency passes stay summarised
  under the single coarse `deps` label for backward compatibility.

## [3.2.0] - 2026-08-30

A reporting-integrity release. Every decision Fendix already made is now
explainable from the exported report alone, in both formats. No scoring rule,
threshold or gate changed: **no fingerprint changes, and no finding changes
status or severity** — verified by scanning one target with 3.1.0 and 3.2.0
and diffing every finding under both policies.

### Added

- **`confidence_breakdown` — the score, in machine-readable form.** Every
  scored finding now carries one entry per scoring rule that fired:
  `{delta, code, text}`, index-aligned with `confidence_reasons`, with the
  deltas summing exactly to `confidence_score`.

  `confidence_reasons` has always explained the score in prose, which meant the
  only way to act on it was to parse English. `code` is a stable snake_case
  identity from a single namespace, so a policy can now match on
  `deterministic_detection` or `component_not_imported` directly. The wording
  in `text` stays free to change; the codes do not.

  The namespace covers the decision layer's enforcement lines too, so the
  reasons a finding was *held back* — `held_uncorroborated`,
  `held_confidence_low`, `not_applicable_component_absent`,
  `deescalated_test_fixture_corroborated` — are matchable on the same footing
  as the reasons it scored.

- **SARIF publishes `confidence_reasons` and `confidence_breakdown`.** SARIF
  carried the final score and the decision block but not the breakdown behind
  them, so a SARIF-only consumer could see *that* a finding scored 75 and never
  *which* rules produced it. Both forms now travel, and the two report formats
  describe the same score identically.

### Fixed

- **`policy_override` no longer marks findings that do not block.** The flag
  answers one question — which BLOCKs exist only because
  `--enforce-confidence=false` switched the evidence requirement off — and it
  was being set before the applicability gate and the test-fixture
  de-escalation had run. Either can move a finding off BLOCK, and neither
  re-evaluated the flag, so a relaxed run exported WARN and INFO findings
  claiming to be relaxed-policy blocks.

  Anyone filtering `policy_override` to audit which blocks were operator-forced
  was getting back findings that block nothing. The flag is now settled after
  every arm has run; it is only ever withdrawn, never set, so a genuine relaxed
  BLOCK is unaffected. Status, severity, score and fingerprint are untouched.

  The SARIF exporter also refuses to emit `policy_override` on a non-BLOCK
  result, which covers reports archived before this fix and re-rendered later.

### Changed

- **Native JSON and SARIF are contract-tested against each other.** Status,
  confidence score and band, intrinsic severity, decision policy, override
  state, decision reason, both corroboration classes and the breakdown codes
  are asserted equal across the two formats for every decision shape —
  deterministic dependency BLOCK, reachable taint BLOCK, sink-only WARN,
  fixture credential, provider credential in test code, absent dependency
  component, unresolved import, and relaxed policy. The formats may differ
  structurally; they can no longer differ semantically.

## [3.1.0] - 2026-08-29

A grading release. Six checks were asserting an impact their evidence never
reached, so severities and statuses move — but no finding is deleted, no
detection is lost, and **no fingerprint changes**.

### Changed

- **`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials:
  true` is no longer CRITICAL, and no longer blocks.** It is MEDIUM/WARN,
  titled and worded as an invalid configuration whose exploitation was not
  demonstrated.

  The pair is not merely unproven, it is inert. The Fetch standard forbids the
  wildcard when a request's credentials mode is `include`, so every compliant
  browser rejects the response and no authenticated cross-origin read occurs.
  Reading the two headers establishes a server misconfigured to *intend*
  permissive credentialed sharing; it does not demonstrate that the sharing
  works.

  **This changes exit codes.** A pipeline that failed on this finding alone
  will now pass. Origin REFLECTION with credentials — the shape that genuinely
  is account-takeover grade — stays CRITICAL, and the wildcard finding is
  re-ranked below every reflection signal so a configuration observation can
  never mask a demonstrated one.

  Reflection severity is now sensitivity-aware too: when a source of truth
  declares an operation public, the readable body is not authenticated data, so
  the finding lands HIGH rather than CRITICAL. Only that positive declaration
  de-escalates — an endpoint with no declaration keeps full severity.

- **"No rate limiting observed" is graded by what abusing the operation is
  worth.** The observation is identical everywhere; the consequence is not. On
  a 700-endpoint target the old flat MEDIUM produced one enormous WARN
  asserting equal urgency for an unlimited login and an unlimited list read.

  Severity now follows an abuse-sensitivity grade built from parameter
  semantics (an operation accepting `password` or `otp_code` is an
  authentication endpoint whatever its route is called), whole-segment route
  semantics matched exactly (so `/api/authors` is not authentication), and
  authentication context. Authentication and identity gateways and expensive
  unauthenticated operations stay MEDIUM; ordinary operations become INFO.

  Grouping needs no new machinery — the existing dedup key is
  `Severity|Category|Title`, so this splits one undifferentiated group into an
  abuse-sensitive WARN group and an ordinary INFO group, each keeping its own
  `affected_endpoints`. The bounded-burst claim and both scope disclaimers are
  unchanged; a fourth sentence names the signal behind the grade.

- **Browser-document headers are graded against the response type.**
  Content-Security-Policy, X-Frame-Options, Permissions-Policy,
  Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy instruct a
  browser that is rendering a document. A JSON payload has no DOM to inject
  into, no frame to be nested in and no browsing context to isolate, so on a
  response parsed as data these are reported at INFO with an appended sentence
  explaining that the header would not have applied.

  Strict-Transport-Security, X-Content-Type-Options and
  Cross-Origin-Resource-Policy are deliberately unaffected — `nosniff` matters
  *more* for JSON, not less. Classification is three-state: an absent or
  unrecognised `Content-Type` changes nothing at all.

- **A dynamic filesystem path is separated from a proven traversal.**
  `open(path)` with a non-constant argument established that a value is
  dynamic, never that it is externally controlled, but reported "Potential path
  traversal" at HIGH. Without a proven chain it is now "Potential unsafe
  dynamic filesystem path" at MEDIUM (non-blocking); with one it takes the
  traversal wording at HIGH and ships the chain as SARIF `codeFlows`.

  Traversal-specific containment is now recognised: basename-family and
  `secure_filename` calls, pathlib's `.name` on a pathlib construction, and a
  dominating early-exit guard rejecting `..`. A bare `Path(x).resolve()` is
  deliberately *not* credited — resolving is not containing.

- **A fixture credential in test code reaches INFO.** Being in test code and
  having a fixture-shaped value are two independent deterministic signals — the
  path and the bytes — and their agreement is enough to stop reporting the
  finding at the same level as a real unconfirmed one.

  Bounded by provider anchoring: a value carrying a provider's own token
  signature (`AKIA`, `gh[opusr]_`, `sk_live_`, `xox`, `AIza`, `sk-ant-`,
  `npm_`, PEM headers) keeps the WARN floor no matter how the variable is
  named. `TEST_STRIPE_KEY = "sk_live_…"` is a live key with a misleading label,
  and a label is evidence about its author's intent, not about the credential.

### Fixed

- **A dependency finding could claim safety from an import that was never going
  to be there.** The applicability pass de-escalated whenever an advisory's
  component was not *statically* imported. A project reaching that component
  only through a computed import — `import_module(name)`, `require(pkg)` —
  names it nowhere in the source, so the grep found nothing and the finding was
  annotated "affected component not imported; effective risk reduced".

  The walk now also records, per language and over the same bytes, whether the
  tree calls dynamic-import machinery with a non-literal target. When it does,
  the de-escalation is withheld and the finding stays at applicability
  `unknown`, saying why. "We looked and could not tell" is a different claim
  from "we looked and the component is unused", and only the second justifies
  reducing anyone's risk assessment. Literal dynamic imports are unaffected —
  the grep already reads through them.

  **This direction is stricter**: some dependency findings that were previously
  de-escalated now keep full weight.

### Upgrade notes

- **Fingerprints do not change.** Verified by diffing
  `partialFingerprints["fendix/v2"]` across the release on a fixture that
  changed both title and severity: identical, with no identity lost or created.
  Saved `--baseline` files and `.fendix-ignore` `fingerprint:` rules keep
  working. Rules keyed on a finding's *title* will need updating for the
  path-traversal and CORS wildcard findings.
- **Exit codes can move in both directions.** A build gated only on a CORS
  wildcard+credentials finding will now pass; a build against a project using
  computed imports may newly fail on a dependency finding that was previously
  de-escalated.
- `metadata.schema_version` stays `1` — no field was added or removed from the
  report contract, only the values that populate it.

## [3.0.2] - 2026-08-28

### Fixed

- **Semgrep findings had unstable and colliding identities.** Neither is
  visible on a machine without semgrep installed, so the whole family went
  untested until a scan through the released image exercised it.

  The rule id carried the temporary directory the rule files are written to —
  `tmp.fendix-semgrep-rules-1072928901.flask-route-no-auth-decorator` — with a
  fresh number every run. Harmless while the id was decoration; once 3.0.0 made
  it an identity input it meant **every semgrep finding got a new identity on
  every scan**, churning without the file changing at all.

  Separately, nothing distinguished two matches of one rule in one file, so
  **five unprotected Flask routes collapsed into one finding** and suppressing
  any one of them silently suppressed the other four.

- **Semgrep findings showed "requires login" as their evidence.** Semgrep OSS
  without a logged-in account replaces `extra.lines` with that literal string,
  and it was passed through verbatim — so the field a user reads to judge a
  finding said nothing about the code. The matched line is now read from disk,
  at the path and line number semgrep does supply.

  Credential-shaped literals are masked before that line reaches identity: a
  rule matching a hardcoded secret matches the line the secret is on, and a
  fingerprint outlives any report. Route paths and config keys are left intact,
  because for a route-shaped rule the path is the identity — masking every
  literal traded a credential leak for a collision.

  Measured on the same before/after fixture, scanned through the released image
  with semgrep present: 40 findings, **40 identities** (was 32), 100% matched
  across the cosmetic edit, 0 vanished, 0 new.

## [3.0.1] - 2026-08-28

### Fixed

- **A re-rendered archived report no longer mislabels its fingerprints.** The
  SARIF `partialFingerprints` key was bound to the algorithm this build
  computes, but `fendix report --input` re-renders a report whose findings —
  and whose fingerprints — come out of the file. A pre-3.0.0 report was
  therefore published with v1 values under the `fendix/v2` key, so a v2
  consumer would match them against real v2 identities: the wrong namespace,
  silently. The key now names the algorithm the report announces
  (`metadata.fingerprint_algorithm`), and an absent announcement means
  `fendix/v1` — every engine build before 3.0.0 omitted the field, so every
  archived report is a v1 report. A live scan stamps the algorithm it used, so
  its own SARIF is unaffected.

## [3.0.0] - 2026-08-28

### Changed

- **BREAKING (baselines): findings now have a stable identity that survives
  irrelevant code changes.** The fingerprint was `sha1(Category|Endpoint|Title)`,
  and `Endpoint` for a whitebox finding is `path:line`. Inserting one unrelated
  line above a vulnerability therefore gave it a new identity — which silently
  broke baseline tracking, new-vs-existing detection, `.fendix-ignore`
  `fingerprint:` rules and PR annotations, because every one of those asks
  "have I seen this before?" and the answer flipped to no whenever the file was
  edited above the finding.

  Identity is now semantic and versioned as `fendix/v2`: which rule fired,
  about which artifact, concerning which operation — built per finding family
  and tolerant of partial evidence. Location (endpoint, line, taint-chain line
  numbers) is reporting; it may change freely. Title, evidence prose, severity,
  confidence, decision and applicability are excluded: every one of them is
  expected to change over a finding's life without making it a different
  vulnerability.

  Measured on a fixture repository scanned before and after a purely cosmetic
  edit — licence header, unrelated imports and helper, comments above each
  finding, internal reformatting, a reordered `requirements.txt`, moving every
  line of both source files:

  | scheme | findings | identities | matched | vanished | new |
  |---|---|---|---|---|---|
  | v1 | 30 | 30 | 22 (73.3%) | 8 | 8 |
  | v2 | 30 | 30 | 30 (100%) | 0 | 0 |

  **What you must do.** Regenerate every saved `--baseline` file with
  `--save-baseline`, and rewrite every `.fendix-ignore` rule that pins a
  `fingerprint:` against the new value. Rules that match by path, category or
  rule id are unaffected.

  Baseline matching recomputes the key from each finding's fields rather than
  reading the stored fingerprint, which is what let pre-fingerprint baselines
  keep working in the past — but it does not rescue this upgrade. A baseline
  written by a pre-v2 build has no `rule_id`, `dependency`, `secret`, `sink` or
  `symbol`, so recomputing v2 over it yields components the current scan does
  not produce. Measured on a 30-finding fixture: a genuine pre-upgrade baseline
  matched **0 of 30**; a regenerated one matched 30 of 30. Until you
  regenerate, the first v2 scan reports every finding as new. Across a 138-finding corpus from three
  real repositories the remap was 90.6% one-to-one with zero splits; the
  remaining cases merge one advisory affecting several installed copies of the
  same package in one lockfile into a single record.

  `metadata.schema_version` moves `1` -> `2` and
  `metadata.fingerprint_algorithm` names the scheme, so a consumer comparing
  archived reports can tell whether their identities are comparable. SARIF
  publishes identities under the `fendix/v2` partialFingerprints key; a
  consumer keyed on `fendix/v1` will not match them by mistake.

- **A finding's wording now follows the evidence it holds.** A chainless
  path-traversal match reported "user input flows to filesystem path" while
  holding no evidence of any flow, and "Open redirect — user-controlled
  redirect target" asserted user control that was never established. In the
  other direction a fully proven SSRF still reported "Potential SSRF",
  understating the finding a reader most needs to act on. Three families now
  use one vocabulary — `Potential X — dynamic …` when only the sink was
  observed, `X — user-controlled …` when the source→sink path was proven.
  Presentation only: identity does not move when a finding is retitled.

- **SARIF rule ids key on the rule, not the title.** They were
  `fendix.<category>.<title-slug>`, so with evidence-aware titles one check's
  results would have scattered across two rules the moment a taint chain was
  proven. Rules now key on the rule id where there is one and fall back to the
  old title slug where there is not.

  **GitHub alerts will be re-partitioned once.** Every blackbox check gained a
  rule id in this release (see below), so its SARIF rule id changes from the
  title slug to the rule slug. Existing alerts under the old rule ids close and
  reopen under the new ones on the first v2 upload. This is a one-time cost,
  taken now rather than split across two releases.

- **`run.automationDetails.id` is derived from the scan mode.** It was the
  constant `fendix/scan`, and GitHub partitions alerts by that category and
  reads an upload with no findings as "everything in this category is fixed" —
  so a code-only scan and a live DAST scan of one repository were clearing each
  other's alerts. It is now `fendix/scan/<mode>` for whitebox, blackbox, hybrid
  and import. A run with no declared mode keeps the original constant, so
  existing alert sets are not re-partitioned. **Repositories that upload more
  than one scan mode will see their alerts re-partitioned once.**

- **Rate limiting is probed with the operation's own method, or reported as
  untested.** The check sent a hardcoded GET and labelled the finding with the
  operation's method, so Fendix reported "No rate limiting observed" against
  `POST /login` having never sent a POST. GET, HEAD and OPTIONS are probed as
  themselves. POST, PUT and PATCH are probed as themselves only under
  `--active`. DELETE is never burst-probed at any level — twenty deletions is
  data loss, not scanning. Anything not probed emits an INFO "not tested"
  record rather than silence, which would read as "tested, nothing found".

  **This changes finding counts.** A passive scan of an API whose operations
  are mostly writes will report far fewer rate-limit findings and a
  corresponding number of INFO not-tested records.

### Added

- **SARIF separates intrinsic severity, confidence, effective risk and
  decision.** A synthetic `FAKE_API_KEY` scored 25, banded LOW and held at WARN
  was published under a rule ranked High with nothing to say Fendix disagreed.
  `security-severity` stays intrinsic and now declares `severity_model:
  "intrinsic"`; it is a rule-level property shared by results whose confidence
  differs, so it cannot honestly carry a per-instance assessment. Effective
  risk goes on `result.rank`, SARIF's own per-result priority field. Each
  concept is also published by name on the result. Because GitHub renders
  `security-severity` rather than `rank`, a materially downgraded assessment is
  also named in the result message — only when the two genuinely disagree.

- **`rule_id`, `dependency`, `secret`, `sink` and `symbol` are published on
  findings.** All additive and `omitempty`. They are what the v2 identity is
  computed from, and a fingerprint whose inputs the report withholds is the
  black box the decision-integrity work removed for decisions. Probe payloads,
  responses and detection timestamps remain internal.

### Fixed

- **Eleven header checks at one endpoint no longer share one identity.** A
  blackbox identity is category + rule + endpoint, and no blackbox scanner
  emitted a rule — so every check in a category collapsed onto its endpoint.
  Measured against a bare test server, eleven header checks on `GET /api/data`
  produced ONE record: suppressing "missing CSP" silently suppressed "missing
  HSTS", "X-Frame-Options" and every sibling with it. A collision hides
  findings, where a split merely duplicates them. Every blackbox check now
  carries its own rule id.

  `auth` is deliberately one rule across both its titles: "Unauthenticated
  endpoint observed" and "Authentication requirement bypassed" are the same
  observation about the same endpoint, differing only in whether a source of
  truth established that authentication was expected — evidence enrichment, not
  a different vulnerability.

- **Four CVEs across three packages no longer share one identity.** The Python
  dependency analyzer sent neither `rule_id` nor a dependency block, so all its
  findings reduced to `deps` + the manifest name. A `fingerprint:` ignore rule
  written against any one of them would silently have suppressed the others.

- **Proving a flow no longer re-files the finding.** A chainless finding fell
  back to its evidence text for the vulnerable operation while the same finding
  with a chain used the chain's sink, and a symbol read off the bound route
  appeared only once a chain existed — so an analyzer improvement turned into a
  new vulnerability. The analyzer now states the sink and the enclosing symbol
  whether or not it proved the flow.

- **A committed credential is named after its binding, not its own contents.**
  `DATABASE_URL = "postgres://appuser:pw@host/db"` was identified as `appuser`,
  so rotating the credential — the correct response to the finding — filed it
  as a different vulnerability.

- **A rate-limit sweep no longer emits hundreds of SARIF locations.** One
  deduplicated result carried roughly 883 `logicalLocations` on a large API.
  The list is capped at 10; the full set, the true count and an explicit
  truncation marker move to result properties, so nothing is lost and a
  truncated result cannot be mistaken for a complete one.

### Security

- **Fingerprints never derive from credential material.** A secret's identity
  is the non-sensitive identifier it is bound to, never the credential and
  never a digest of it. The redaction marker already published in evidence is
  an unsalted, 4-byte truncated SHA-256 that `redact.go` itself calls
  dictionary-recoverable; a fingerprint is persisted into ignore files,
  baselines and GitHub Code Scanning, which is the wrong lifetime for a
  reversible function of a secret. Any redaction marker reaching a normalizer
  is collapsed to a constant first, so no credential-derived byte can enter an
  identity by another route.

  Trade-off, stated rather than hidden: material with no binding identifier — a
  bare `-----BEGIN … KEY-----` block — has an empty identifier, so two such
  blocks in one file share one record. Merging two key blocks is a reporting
  imprecision; persisting a credential oracle would be a security defect.


## [2.1.1] - 2026-08-28

### Fixed

- **A running scan now shows real progress while it scans endpoints.** The
  worker pool logged only once, on completion, so anything watching the
  engine's output saw nothing between "scanning endpoints" and "worker pool
  complete" — the longest stretch of a black-box scan, and longer still with
  active probing. A dashboard progress bar driven by those messages sat at one
  checkpoint for most of the scan and looked frozen. The pool now reports
  completions as it sweeps, throttled to roughly twenty lines per scan so the
  output stays readable regardless of how many endpoints are in flight.

  Detection, findings and exit codes are unchanged.

## [2.1.0] - 2026-08-26

### Added

- **Cross-tool corroboration is now visible.** Findings carry two additive
  fields — `cross_tool_corroborated` and `corroborating_tools` — published
  when an INDEPENDENT tool reported the same normalized weakness at the same
  normalized location. Both are `omitempty`, so a report without corroboration
  is byte-identical to one produced before they existed and `schema_version`
  stays `1`. Fendix's own SARIF output carries `corroborating_tools` as a
  result property, so the provenance survives re-export into GitHub code
  scanning.

  The fields are stamped from the evidence the decision layer scores, not
  projected through the finding adapter: the stamped value is the proof-union
  over a dedup group, so an uncorroborated duplicate occurrence cannot erase a
  validly established confirmation.

- **Report metadata reconciles imports.** `metadata.imports` consolidates to
  one block per normalized tool (folded across runs *and* across attached
  files) and each block gains `corroborated: N` — how many of that tool's
  findings collapsed into a native representative. Without it, uploading 50
  findings and seeing 47 rows looks like data loss rather than agreement.

- **SARIF import.** `fendix import <file.sarif>` ingests SARIF 2.1.0 reports
  from other scanners (CodeQL, semgrep, trivy, …) and runs them through the
  full fendix flow — normalization, fingerprinting, deterministic confidence
  scoring, dedup, `.fendix-ignore`/`--baseline`, confidence-gated `--fail-on`,
  and every report format. `fendix scan --import <file.sarif>` (repeatable)
  merges foreign findings into a native scan. Report `metadata` gains an
  additive `imports` accounting block; `schema_version` stays 1.

  Imported findings are input evidence, never fendix verification: `source` is
  `"imported"`, the analyzer tier stays unknown (most-conservative correlator
  treatment), and SARIF codeFlows are ignored — an import can never claim a
  reachable/proven path. Finding identity (the fendix fingerprint) is separate
  from cross-tool correlation identity: an imported finding strengthens a
  fendix decision only through **strong corroboration** — an independent tool
  (normalized tool identity, never SARIF filename or run multiplicity)
  reporting the same normalized CWE at the same normalized location (≤5 lines
  apart, or overlapping declared regions). Title similarity, category
  equality, fingerprint collisions, same-file proximity, and the imported
  tool's self-declared confidence never count. A strongly corroborated
  native+imported pair collapses to the native representative with the
  imported provenance folded in. Established corroboration survives later
  deduplication by proof union (an uncorroborated duplicate occurrence cannot
  erase it; unstamped occurrences cannot manufacture it), and exact-CWE
  matching is a deliberate v1 trust boundary — CWE parent/child taxonomy is
  intentionally not resolved.

## [2.0.1] - 2026-08-24

### Fixed

- **The published Docker image now reports its real version.** `Dockerfile`
  hardcoded `-X main.Version=docker` with no way to override it, so every image
  ever pushed to GHCR answered `fendix version docker` — including the 2.0.0
  image. The build now takes a `VERSION` build-arg and `release.yml` passes the
  git tag, matching how the platform binaries have always been stamped.

  This was invisible for as long as the value was only printed by
  `fendix version`. It stopped being invisible in 2.0.0: the backend now
  persists the engine version on each scan and forwards it as SARIF
  `driver.version`, so a deployed scan recorded its engine as `"docker"` —
  which is the same class of uninformative placeholder that release replaced
  `"backend"` to remove. A report has to be able to say which engine produced
  it.

  The `ARG` default stays the literal `docker` rather than a version number: a
  plain `docker build .` has no tag to claim, and a local build asserting it is
  a release would be worse than one that says it is an unversioned image.

## [2.0.0] - 2026-08-24

A precision and trust release. Every change below exists because the reports
this engine produced made claims it could not support: a file called `"None"`,
a file called `"https"`, six findings for three vulnerabilities, an upgrade
recommendation naming a git commit SHA, a confidence band that was arithmetically
stuck at MEDIUM, and a build failed by a finding whose own evidence text said it
was unconfirmed.

### BREAKING

Read this before upgrading a CI pipeline.

- **`--fail-on` now consults confidence, not severity alone.** A finding at or
  above the threshold BLOCKs only when the deterministic confidence band
  supports the claim: HIGH blocks; MEDIUM blocks only with at least one
  corroborating signal; LOW warns. A finding the correlator marked unconfirmed
  by live scan does not block without corroboration, regardless of band.

  **Builds that used to fail may now pass.** That is the point — an
  uncorroborated finding failing a build is the incoherence this release
  removes — but it is a behaviour change on the default path, so it gets a
  major version.

  `--enforce-confidence=false` restores the previous severity-only mapping
  byte-for-byte. That is not a promise: `TestExitCodeMatchesLegacyCheckFailOn`
  locks all 54 severity/threshold combinations against the frozen legacy
  implementation, which is retained solely to be that oracle.

  Real credentials in production code still block. A deterministic pattern
  match in non-test source scores into HIGH on its own, so a hardcoded AWS or
  Stripe key still exits 1 on a code-only scan. Fixture-shaped values do not.

- **An uncorroborated BLOCK in test code is demoted to WARN.** Previously
  `--deescalate-tests` only moved WARN→INFO, so it could never reach the
  project's own largest false-positive class (test fixtures are 31 of 35 FPs in
  the corpus), whose findings are HIGH/CRITICAL and therefore always took the
  BLOCK path. A corroborated finding in test code — a provider-validated live
  credential — still blocks.

- **Dependency finding identity changed.** Alias-linked OSV records are merged
  into one finding per vulnerability and named after the canonical id
  (`CVE-*` > `GHSA-*` > `PYSEC-*` > other), so `SEC-DEPS-PYSEC_2026_3552`
  becomes `SEC-DEPS-CVE_2026_69247`. Because `models.Fingerprint` and the dedup
  key both hash the title, **saved `--baseline` files and `fingerprint:` rules
  in `.fendix-ignore` that pin a dependency finding stop matching** and must be
  regenerated. `fendix verify` was taught to match on `References` as well as
  the id, so re-verifying a pre-2.0 report does not report a still-installed
  vulnerability as resolved.

- **The CSRF cookie finding was retitled.** A `csrftoken` / `XSRF-TOKEN` /
  `_csrf` cookie without `HttpOnly` is no longer reported as a session cookie
  issue — it is an INFO finding describing the double-submit pattern. Same
  fingerprint caveat as above for those findings.

- **Base images that are not digest-pinned are now flagged** at INFO
  (`python:3.14-slim`, `ubuntu:24.04`, `node:20-alpine`). This adds roughly one
  finding per Dockerfile. It does not gate a build at that severity.

### Added

- **`metadata.schema_version` — the JSON report now says which contract it is.**
  `fendix scan --format json` and `fendix report --format json` stamp
  `"schema_version": 1` into the metadata block of every report they write.
  Until now a consumer had to infer the shape from which optional keys
  happened to be present, which cannot distinguish "this build does not emit
  `decisions`" from "this scan produced none" — and gave a downstream
  integration nothing to warn on when it is handed a report from a newer
  engine than it was written against.

  Additive and backward compatible, in both directions:

  - **Older reports keep parsing.** `reporters.ParseJSONReport` rejects a
    document only when `metadata.version` AND `metadata.mode` are both empty.
    `schema_version` is deliberately NOT part of that check: an archived
    report omits the key, decodes to `0`, and is still accepted. `0` means
    "pre-versioned", never "invalid".
  - **Newer reports keep parsing too.** An unrecognised value is not a parse
    error — the reader stays permissive and leaves "I don't know this
    contract" to the consumer that has to act on it.
  - `docs/schema.json` lists the key under `properties` (it must —
    `additionalProperties` is `false`) but deliberately NOT under `required`,
    the same treatment `decisions` gets, so pre-v1.2.2 archived reports still
    validate.

  The writer stamps the value rather than propagating it, so
  `fendix report --input old.json --format json` labels its output with the
  build that actually wrote the bytes. Version `1` describes today's shape;
  it is bumped only for a change a consumer must react to — a purely
  additive key does not bump it, because a reader that ignores an unknown
  key still reads a v1 report correctly.

- **SARIF results now carry a stable identity, a GitHub ranking score, and an
  analysis category.** Three separate gaps that each cost something concrete on
  the `fendix report --format sarif` → GitHub code-scanning path the GitHub App
  already uses:

  - `result.partialFingerprints["fendix/v1"]` (SARIF §3.27.16), sourced from
    `Finding.Fingerprint` — the same `sha1(Category|Endpoint|Title)` token that
    `.fendix-ignore` fingerprint rules pin to. Without it a consumer identifies
    an alert by file and line, so a re-ordered scan closes and reopens every
    alert. Per DECISIONS.md D4 the key is emitted ONLY when a real
    engine-scheme fingerprint is present: one producer, one meaning. A finding
    without one gets no key rather than an invented value, and a pre-fingerprint
    report stays byte-identical.

  - `rule.properties["security-severity"]` — the CVSS-style score GitHub ranks
    alerts by, as a string: CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 3.0,
    INFO 1.0, one per GitHub bucket. Without it GitHub files every Fendix alert
    as "medium" no matter what level it carries. Working rule 8: it is a pure
    function of SEVERITY and never of confidence.

  - `run.automationDetails.id` = `"fendix/scan"` (SARIF §3.14.3 → §3.17), on the
    RUN object. GitHub reads the id as the analysis "category"; two tools
    uploading SARIF for the same commit without distinct ids overwrite each
    other's alerts. Emitted on zero-findings runs too, otherwise a clean upload
    cannot clear the previous run's alerts for the category. Treat the value as
    a one-way door — changing it re-partitions existing alerts.

- **`IAC_DOCKER_FLOATING_TAG` — a Dockerfile base image that is not pinned to
  a digest.** A tag is a mutable pointer: `python:3.14-slim`, `ubuntu:24.04`,
  `node:20-alpine` and `alpine:3.19` all look specific and all silently change
  contents when the publisher pushes a rebuild, which is how an unreviewed
  upstream layer reaches production without a single line of the Dockerfile
  changing. Only `@sha256:…` is content-addressable. `COPY --from=<image:tag>`
  is covered too.

  Exempt, each a genuine non-finding rather than a suppression: a build-stage
  alias, an existing digest pin, `FROM scratch` (no registry entry, so nothing
  to pin), a build-arg reference such as `${BASE_IMAGE}` (not knowable from the
  file), and a numeric stage index (`COPY --from=0`).

  > **Severity is INFO, deliberately.** The rule is broad by construction — it
  > fires on nearly every real-world Dockerfile — so a gating severity would
  > newly fail builds that were passing, on a hygiene issue whose remedy (a
  > digest plus a bot to bump it) is a project decision rather than a defect
  > fix. Expect a finding-count increase on any repo with Dockerfiles; expect
  > no change to exit codes at the default `--fail-on`.

### Fixed

- **A SARIF result's message was the raw evidence — for a SAST finding, a line
  of source code.** `result.message.text` is what GitHub renders as the PR
  annotation, and it read `with open(path, 'w', ...) as f:` — the code, with no
  statement of what was wrong with it. An evidence-less finding produced an
  EMPTY message, which GitHub rejects outright.

  The message is now a description: the rule name plus the location it fired
  at — `Hardcoded secret at src/config.py:14`, `Missing CSP at GET /api/users
  (+2 more)`. It is composed from the same branch that built `result.locations`,
  so the two can never disagree about where the finding is, and it falls back to
  the rule key when a finding has no title, so it is never empty.

  The code line moves to `region.snippet.text` (SARIF §3.30.13), where it
  belongs — reusing `Finding.Evidence` rather than re-reading the source file,
  because Evidence is already the redacted/truncated string and re-reading would
  put raw credentials into a blob the GitHub App uploads. Working rule 3: the
  evidence is DE-ESCALATED, not deleted — it is also kept verbatim in
  `result.properties.evidence` for every finding, including the blackbox ones
  that have no snippet to hold it.

- **A URL in a finding's `line` field became a SARIF file called `https`.**
  `parseLine` split the value on EVERY `:` and read the last segment as the
  line number, so `https://api.example.com/openapi.json` produced
  `artifactLocation.uri: "https"`. With a port it was worse:
  `https://host:8080/api/x` split into three parts, `8080` parsed as a line
  number, and the emitter published `uri: "host"` with `startLine: 8080` — a
  line that was never observed, in a file that does not exist. This is a live
  path, not a hypothetical: `python/analyzers/spec_parser.py` stamps the spec
  path into `line` at eight sites and that path may be an `https://` URL, and
  the GitHub App re-renders the same findings as SARIF and uploads them.

  Only a TRAILING `:<digits>` run is a line suffix now; anything else comes
  back whole with line 0. That matches what the Python side already asserts
  about the field (`test_line_field_format` does `rsplit(":", 1)` and requires
  `parts[1].isdigit()`).

  A second guard covers what the parser cannot: when the parsed path still
  contains `://`, or is a bare scheme token left over from one, the renderer
  takes the endpoint branch and emits a `logicalLocations` entry instead of a
  physical location. That branch was already correct — the bug was feeding it
  a non-empty `line` so it never ran. The guard is deliberately narrow (a
  literal `://`, or an exact scheme token) rather than the existing
  `uriSchemeRE`, which also matches the `C:` of a Windows drive path.

  Working rule 3 holds on the fallback: a URL-shaped `line` on a finding with
  no endpoint is de-escalated to a logical location, not dropped.

  Three smaller behaviour changes fall out of the same rule and are called out
  rather than buried: a `line` ending in a bare colon (`src/app.py:`) keeps
  the colon in the uri where it used to lose it; a `line` that normalizes to
  nothing (`../..`) now takes the endpoint branch instead of emitting
  `"uri": ""`; and `file:line:col` (`src/app.py:42:10`) still yields path
  `src/app.py:42`, exactly as before — that shape has no producer in the tree
  and is out of this fix's scope.

- **Multi-stage Dockerfiles were flagged for "unpinned base image" on lines
  that reference a build stage, not an image.** `IAC_DOCKER_LATEST_TAG` fired
  on `FROM base AS production` and `FROM base AS development` — references to a
  stage declared earlier in the same file, which cannot be pinned because they
  are not image references at all. Worse, it did NOT fire on the line that
  declares the real base image (`FROM python:3.14-slim AS base`), because a
  floating MINOR tag is deliberately outside that rule's scope. Since
  `Deduplicate` collapses the group and keeps the lexicographically smallest
  endpoint, the user-visible symptom was one finding pointing at the wrong line.

  A whole-file pre-pass now collects `FROM <image> AS <alias>` stage names,
  lower-cased (Dockerfile stage names are case-insensitive), and the rule is
  suppressed on the specific LINES whose source is one of them. `COPY --from=`
  is covered the same way. This is a new per-LINE suppression channel, kept
  distinct from the existing whole-FILE one on purpose: routing it through
  `suppressRule` would have disabled the rule for every multi-stage Dockerfile,
  including one whose first stage really is `FROM golang:latest`.

  The pre-pass parses FROM more permissively than the detection pattern does —
  case-insensitive `AS`, tolerant of `--platform=` flags and trailing comments —
  because an alias it fails to register is a false positive that survives the
  fix.

- **Fixture-shaped credentials scored the same as real ones.**
  `FAKE_API_KEY = "08bf2e526…"`, `ghp_` followed by 36 `A`s and AWS's own
  documented `AKIAIOSFODNN7EXAMPLE` were reported at exactly the confidence of
  a live production credential, because nothing downstream of the regex looked
  at the value or the name it was bound to.

  The secrets scanner now classifies each captured value against four
  deterministic rules — a `FAKE_`/`TEST_`/`DUMMY_`/`MOCK_`/`EXAMPLE_`/
  `PLACEHOLDER_`/`SAMPLE_` assignment key (snake, kebab or camelCase), a
  placeholder word inside the value, a long identical run or a single dominant
  byte, and a value too short to be a credential — and records the verdict on
  the evidence. The confidence scorer turns it into a named `-20` delta, and a
  classified value no longer earns the deterministic-detection bonus, so a
  fixture-shaped secret lands in the LOW band where a real one lands HIGH.

  Per Rule 3 this is de-escalation, never suppression: the finding is still
  emitted, at the same id, severity, endpoint and evidence. It is deliberately
  NOT folded into the existing placeholder suppression — that path DROPS
  matches, and "EXAMPLE" appears inside real leaked keys too.

  The classifier is pure and rule-based (Rule 8): no model, no randomness, and
  every point it costs is a reason line that reconciles with the score. The
  boundary cases are pinned — `latest_token`, `testament`, `testing_key` and
  `TESTING_KEY` do NOT classify as fixtures, and neither do Stripe's
  documentation key, a 48-char OpenAI key or a database password.

  > **`confidence_score` and `confidence_band` change for affected findings.**
  > Both are serialized into JSON and SARIF. Severity, `Status` and the
  > `confidence` enum are untouched — the decision layer keys status off
  > severity rank alone.

- **Secrets findings leaked the first 20 characters of every credential into
  their own evidence.** `truncateSecret` kept a 20-char raw prefix of the
  matched value, and `truncateEvidence` then framed it in a 120-char window
  over the SOURCE LINE. `Finding.Evidence` is not an internal field: the JSON,
  SARIF, HTML and PDF reporters print it, `internal/ghapp` posts it into GitHub
  PR comments, and the Jira integration pastes it into a ticket body. Half of a
  40-char token, distributed to every one of those, is a leak.

  Credential material is now redacted at CAPTURE time — before an
  `evidence.Evidence` is constructed — and replaced with
  `[REDACTED len=N sha256:xxxxxxxx...]`. The marker is deterministic and
  unsalted so identical values render identically (evidence bytes stay
  reproducible and the dedup tiebreak stays stable), and it carries enough to
  correlate two occurrences of the same credential without carrying the
  credential. It is a fingerprint, not a security boundary: a low-entropy value
  is still recoverable from an 8-hex-char digest by dictionary.

  Redaction covers the union of EVERY pattern's value spans on the line, not
  just the emitting pattern's own match. Two credentials on one line previously
  each shipped the other in the clear inside its neighbour's window, and a
  one-line PEM (the shape of a Google service-account JSON file) shipped the
  whole key body, because `PRIVATE_KEY` matches only the armour header.
  Retained signal is deliberate and tested: the PEM header, the connection
  string's scheme/user/host, the `"type": "service_account"` signature and the
  assignment's variable name all survive.

  > **Evidence text changes for every secrets finding.** The strings are
  > different, so a snapshot or golden file that pinned secrets evidence needs
  > regenerating. `models.Fingerprint` hashes `(Category, Endpoint, Title)` and
  > `dedupKey` hashes `(Severity, Category, Title)` — neither reads Evidence —
  > so fingerprints, `.fendix-ignore` rules and `--baseline` entries are
  > unaffected.

- **`csrftoken` was reported as a session cookie missing HttpOnly.** `"csrf"`
  and `"xsrf"` sat in the cookie scanner's session/auth name list and the
  HttpOnly finding's title was hardcoded to `Session cookie missing HttpOnly
  flag`, so Django's `csrftoken`, Angular/Laravel's `XSRF-TOKEN` and
  Express/Rails' `_csrf` were all reported as session-credential defects at
  MEDIUM. A CSRF double-submit token has to be readable by `document.cookie` —
  that is how the client echoes it back in a header — so "missing HttpOnly" is
  the expected configuration for one, not a defect.

  Cookies are now classified into ignore / CSRF / session, and the CSRF list is
  consulted BEFORE the session list because `csrftoken` also contains `token`.
  A CSRF token without HttpOnly gets its own INFO finding that says what was
  actually observed and asks the reader to confirm the name is not misleading
  them. Per Rule 3 the observation is de-escalated, never suppressed: the
  finding count is a 1-for-1 swap, and CWE-1004 is retained so a consumer
  filtering on it still sees the observation.

  The `Secure` and `SameSite` checks are unchanged and still apply to CSRF
  cookies — a token has to be readable by script, but it does not have to
  travel in the clear, and `SameSite=None` on one is genuinely CSRF-permissive.

  > **Fingerprint churn.** `models.Fingerprint` hashes
  > `(Category, Endpoint, Title)` and `dedupKey` hashes
  > `(Severity, Category, Title)`, so the new title mints a new fingerprint and
  > a new dedup group. Any committed `.fendix-ignore` `fingerprint:` rule or
  > `--baseline` entry that suppressed `Session cookie missing HttpOnly flag`
  > on a csrf/xsrf-named cookie STOPS MATCHING, and a `--diff` scan reports the
  > INFO finding as new. A host that sets both a session cookie and a CSRF
  > cookie now produces two HttpOnly-class dedup groups where it produced one.

- **A dependency advisory scoped to a sub-component the project never imports
  scored exactly like one on a code path it uses every request.** A Django
  advisory that only touches `django.contrib.gis` is real — the vulnerable code
  is installed — but a project that never imports GeoDjango cannot reach it, and
  reporting both at identical confidence is what makes a dependency report
  tiring to read rather than actionable.

  A new `internal/scanner/deps/applicability` pass consults a small curated
  catalog and, when an advisory maps to an importable component, greps the
  scanned tree for it. If nothing imports it, the finding gains one sentence of
  evidence saying so and a named `-10` confidence delta, which moves a typical
  dependency finding from the HIGH band to MEDIUM.

  Per Rule 3 this is de-escalation and nothing else: the finding keeps its id,
  its severity, its endpoint, its upgrade advice and its original evidence text
  verbatim. No path is suppressed and no finding is dropped.

  Everything about it is deterministic (Rule 8). The catalog is Go literals; the
  package tier only fires when the advisory's OWN summary names the component,
  so it cannot mis-scope an advisory that says nothing about one; the id tier
  ships empty because an entry there is an assertion about a specific published
  advisory. The grep is one `WalkDir` for all advisories at once with a
  per-language compiled alternation — a scan whose advisories are not in the
  catalog touches the filesystem zero times — and it fails OPEN, at full
  confidence, if the tree exceeds the file budget or the walk cannot complete.

  The matchers deliberately over-match rather than under-match, because a false
  "imported" costs nothing while a false "not imported" quietly reduces the
  confidence of a real risk. A Python component counts as imported when its
  dotted path appears anywhere in a `.py` file — including as a string in
  `INSTALLED_APPS`, which is how a Django app is actually enabled. A fully
  dynamic import (`importlib.import_module(name)`, `require(variable)`) is a
  known blind spot, and is the reason the penalty is a modest `-10` rather than
  something that could move a band on its own.

- **Every dependency vulnerability was reported once per OSV RECORD, not once
  per vulnerability.** OSV's `/v1/query` returns the GHSA record and each PYSEC
  record for the same underlying bug as separate `vulns[]` entries, and the
  scanner emitted one finding per entry. Verified against live OSV.dev:
  `cryptography==48.0.1` returns **six** records that are **three** real
  vulnerabilities, so the report asked the user to fix the same CVE three times
  — the kind of inflated count that makes a whole report untrustworthy.

  The pip and npm scanners now partition each `(package, version)` result set
  into alias-connected components — union-find over `{id} ∪ aliases` — and emit
  one finding per component. The finding is named after the **canonical** id of
  its alias set: `CVE-*` first, then `GHSA-*`, then `PYSEC-*`, then everything
  else, lexicographically smallest within a tier. The picker ranges over
  ALIASES as well as top-level ids, because OSV routinely carries the CVE only
  as an alias — in the cryptography data no record's own `id` is a CVE at all.
  `BIT-*` is a real OSV alias prefix and ranks in the "other" tier.

  Nothing is dropped (Rule 3): every merged id is preserved in `references`,
  canonical first. Alias data is not verified upstream, so two alias-linked
  records whose affected version ranges are provably disjoint are NOT merged —
  they stay separate and the refusal is logged to stderr.

  `govulncheck` is deliberately untouched: vuln.go.dev emits one `GO-*` record
  per vulnerability with aliases pointing outward, so the duplicate-record
  problem does not arise there. `python/analyzers/deps.py`'s pip-audit path
  gets the identical canonicalisation, because `Deduplicate` collapses the
  Go/Python overlap on `Severity|Category|Title` and a one-sided rename would
  double-report every dependency vulnerability under `--python-engine`.

  > **Fingerprint churn.** `models.Fingerprint` hashes
  > `(Category, Endpoint, Title)` and the title now carries the canonical id,
  > so every saved `--baseline` entry and every `.fendix-ignore`
  > `fingerprint:` rule pinned to a dependency finding STOPS MATCHING, and a
  > `--diff` scan reports the renamed finding as new. `fendix verify` is
  > already handled — it matches on the whole preserved id set, so a finding
  > recorded under the old id still resolves to its renamed twin instead of
  > being reported as fixed.

- **The batch path — the default one — emitted findings with no description
  and no fix version.** `/v1/querybatch` answers with bare vuln ids: no
  summary, no aliases, no affected ranges. So on the route most scans actually
  take, every dependency finding fell back to printing the raw OSV id as its
  description and said *"no fix listed in OSV"* even when OSV listed one.

  Any package the batch reports as vulnerable is now re-fetched through the
  per-package `/v1/query` before findings are built. The cost is one extra
  request per VULNERABLE package — one for cryptography's six records, not six
  — and clean packages cost nothing beyond their share of the batch. If that
  hydration fails, the degraded record is still reported (Rule 3) with a
  stderr warning, and is deliberately not cached.

  > **Cache entries are now shape-versioned.** The OSV cache previously stored
  > a bare array whose alias and range content depended on which code path
  > filled it, so a single pre-upgrade batch run could serve alias-less records
  > to every path for 24 hours. Entries written by an older fendix are now
  > treated as a miss and re-fetched once.

- **A dependency finding could tell you to "upgrade to" a git commit SHA, or
  to jump a major version.** Two separate defects in one line of output.

  `osvRange` did not decode OSV's `type` field, so a GIT range — whose `fixed`
  event carries a commit SHA rather than a release — was indistinguishable from
  an ECOSYSTEM one. Whichever the advisory listed first won. This is not
  hypothetical: `pillow==9.0.0`'s advisory set carries ECOSYSTEM, SEMVER **and**
  GIT ranges today. GIT ranges are now ignored for the upgrade message in the
  pip, npm and govulncheck scanners; an absent `type` is still treated as
  ECOSYSTEM, because the offline-snapshot and pip-audit adapters synthesise
  ranges without one.

  Separately, the version chosen was simply the first `fixed` event in the JSON,
  with no reference to what the user actually has installed. An advisory that
  patches several release branches lists one `fixed` per branch —
  `django`'s PYSEC-2026-3717 lists `5.2.17` and `6.0.8` — so a user pinned at
  `5.2.16` could be told to move to `6.0.8`. The rule is now two-level: WITHIN
  one advisory, the lowest `fixed` version strictly greater than the installed
  pin (the minimal in-branch upgrade); ACROSS the alias-merged members of one
  finding, the maximum of those per-advisory candidates, so the printed version
  really does fix every vulnerability the finding reports.

  Ranking reuses `internal/offline`'s existing comparator (now exported as
  `CompareVersions`) rather than growing a second one. When it cannot rank a
  fix above the pin — it collapses PyPI pre-releases onto their release core —
  the scanner falls back to the lowest listed fix rather than claiming "no fix
  listed in OSV". A version is never invented: an advisory with no usable
  `fixed` event still prints the honest no-fix sentinel.

  > **Advisory freshness is bounded by a 24h cache.** OSV responses are cached
  > per `(package, version)` under `~/.fendix/cache/osv-{pypi,npm}/` for 24
  > hours, so an advisory published in the last day is not seen until that
  > entry expires, and one withdrawn in the last day keeps being reported.
  > There is no cache-bust flag — delete the directory to force a refresh.

### Changed

- **A deduplicated SARIF rule now takes the MAXIMUM severity of the findings
  under it, not the first one seen.** A rule is keyed on (category, title) while
  the engine's `dedupKey` is severity|category|title, so `Deduplicate`
  deliberately keeps a same-check pair at two severities as two findings — and
  `enforceConsistency` (LOW confidence caps severity at MEDIUM, MEDIUM at HIGH)
  actively creates that split. First-wins was not deterministic in any useful
  sense: the orchestrator sorts by Endpoint → Category → Title and never by
  severity, so the rule's level was whichever finding had the lexicographically
  smallest endpoint, and `fendix report --input` accepts an arbitrarily ordered
  array anyway.

  This changes `defaultConfiguration.level` for a rule that spans severities.
  It is also required for correctness: `security-severity` has no per-result
  equivalent, so one value serves every alert under the rule, and a rule reading
  level "note" beside security-severity "9.5" is a defect. Per-result `level` is
  unaffected — each result still carries its own, from the decision verdict.

  Out of scope, and still first-wins: the rule's Name, Help, HelpURI, and
  `properties.category`/`tags`/`confidence`. `properties.confidence` in
  particular remains order-dependent on a deduplicated rule — an independent
  reason `security-severity` must not be derived from it.

- **`--fail-on` now requires the confidence band to support the claim.**
  `decision.Decide` computed a full confidence `Result`, attached it to every
  decision, published it as `confidence_score` / `confidence_band` /
  `confidence_reasons` — and then set `BLOCK` purely from severity rank, never
  reading it. The engine could therefore print `[Unconfirmed by live scan]` in a
  finding's evidence and fail the build on that same finding, in one report.

  Under the new default (`--enforce-confidence`, on), a finding at or above the
  `--fail-on` threshold BLOCKs only when the deterministic band supports it:

  | severity vs `--fail-on` | confidence band | corroborating signal | status | with `--enforce-confidence=false` |
  | --- | --- | --- | --- | --- |
  | at or above | HIGH | any | **BLOCK** | BLOCK |
  | at or above | MEDIUM | ≥ 1 | **BLOCK** | BLOCK |
  | at or above | MEDIUM | none | **WARN** | BLOCK |
  | at or above | LOW | any | **WARN** | BLOCK |
  | at or above | any | marked unconfirmed-by-live-scan, and uncorroborated | **WARN** | BLOCK |
  | at or above | any | in test code, uncorroborated, `--deescalate-tests` on | **WARN** | WARN |
  | below | — | — | WARN (≥ MEDIUM severity) | unchanged |
  | below | — | — | INFO (< MEDIUM severity) | unchanged |

  The corroborating signals, in the fixed order they are reported in: **cross-
  engine agreement** (`source: correlated`), **live runtime observation**
  (`source: blackbox` or `correlated` — the finding came from a probe against a
  running target), **direct observation of a live response** (the header /
  cookie / CORS deterministic read), **deterministic detection in production
  code** (a high-confidence pattern match outside test and fixture code),
  **confirmed route**, **reachable taint path**, **proven path**, and
  **payload-validated probe**. A BLOCK's reason names the ones that justified
  it; a WARN's reason names what was missing, and a 0-point line is added to
  `confidence_reasons` so the published breakdown still reconciles with
  `confidence_score`.

  > **This changes the process exit code, not only the reported status.**
  > `orchestrator.Run` returns `decision.ExitCode(decisions)`, so a CI job
  > gating on `--fail-on` can now exit 0 where it exited 1. The largest class
  > affected is chainless static findings: a whitebox finding scores
  > `35 base + 10 static = 45` (MEDIUM) and, unless it is a high-confidence
  > pattern match in production code or carries a proven taint path, nothing
  > corroborates it — so shape-match SAST no longer gates on its own. That
  > explicitly includes the **semgrep-shim tier**, which is excluded from the
  > deterministic-detection bonus and lands at 40: a semgrep HIGH with no taint
  > chain now WARNs. Pure DAST findings are unaffected (`source: blackbox` is
  > itself a corroborating signal), and a real hardcoded credential in
  > production code still bands HIGH and still exits 1.
  >
  > Two independent escape hatches, because there are two independent rules:
  > `--enforce-confidence=false` (or `scan.enforce_confidence: false` in
  > `.fendix.yaml`) restores the legacy severity-only gate byte-for-byte, and
  > `--deescalate-tests=false` restores blocking on uncorroborated test-code
  > findings. Neither implies the other.

- **`--deescalate-tests` now also demotes an uncorroborated BLOCK to WARN.**
  The rule only ever demoted `WARN → INFO`, so a team that set `--fail-on` —
  exactly the audience the demotion exists for — got none of it. Test fixtures
  are 31 of the 35 catalogued false positives in `tasks/FP_CORPUS.md`, and they
  were structurally exempt from their own mitigation.

  A finding in test/fixture code that meets `--fail-on` with **no** corroborating
  signal beyond the pattern match is now held at WARN, with the reason stating
  both the rule and the missing corroboration. A **corroborated** one — a proven
  taint path, a provider-validated live credential — still BLOCKs, which is what
  keeps this de-escalation rather than path suppression (Rule 3). Nothing is
  dropped, no evidence text is touched and no score moves.

  A finding that crossed the `--fail-on` threshold is never reported below WARN:
  the two demotion rules cannot cascade into INFO and bury it alongside a
  below-threshold LOW.

- **`[Unconfirmed by live scan]` gained a machine-readable counterpart.** The
  correlator writes that suffix into a finding's evidence text when a live scan
  ran and did not confirm a URL-shaped whitebox finding. It is now produced
  alongside an internal `UnconfirmedByLiveScan` marker that the decision layer
  reads, so enforcement gates on structure rather than on prose. The suffix text
  is byte-identical and the public `Finding` shape is unchanged — no new JSON
  field — so consumers parsing the suffix keep working. Under the default policy
  a finding carrying the marker cannot reach BLOCK without a corroborating
  signal.

- **Confidence bands were arithmetically stuck at MEDIUM for uncorrelated
  scans.** A DAST-only finding topped out at `35 base + 10 runtime = 45` — the
  `+10` payload-validated bonus cannot fire, because `Evidence.Response` has no
  producer anywhere in the module — while the HIGH band starts at 70. Worse,
  correlation could never close the gap either: `engine.categoryMap` covers only
  secrets/injection/auth, so a headers/cookie/CORS finding is never
  `SourceCorrelated`. `decisions.confirmed` was therefore a synonym for
  "correlated", and a scan with no code path could not produce a single
  confirmed finding.

  Two new deltas fix that, both deterministic named rules with reason lines like
  every other (Rule 8):

  - **direct observation, +30** — the claim is a deterministic read of a live
    response: a header present or absent, a cookie attribute present or absent,
    a literal CORS header value. Set by `scanner/headers.go`,
    `scanner/cors.go` and `scanner/cookie_flags.go` on exactly the checks that
    already assert `ConfidenceHigh` from a literal read. `Weak
    Content-Security-Policy`, the SameSite finding and the two CORS
    method-policy findings are excluded: each grades a policy or cannot
    disambiguate its own parse, and each already carries `ConfidenceMedium`.
  - **deterministic detection, +30** — the static mirror: a high-confidence
    pattern match in production code, where the finding IS the read. Withheld
    from test/fixture code, from placeholder-shaped credential values, and from
    the semgrep-shim tier, each of which is a documented false-positive class
    (31 of the 35 instances in `tasks/FP_CORPUS.md` are test fixtures).

  The de-escalation still dominates: a direct observation on an auth-gated 4xx
  or a CDN-served static asset lands at 60 — MEDIUM, not HIGH — and a
  fixture-shaped credential lands at 25.

  **Visible effects.** `confidence_score` and `confidence_band` move on almost
  every scan. `decisions.confirmed` (JSON), the HTML "Confirmed" stat tile and
  the stderr `Decision summary … (N high-confidence)` line all count
  `ConfidenceBand == HIGH`, so all three jump. The GitHub App's PR comment ranks
  its top five by `(status, severity, confidence_score)`, so that list reorders
  against SAST findings of equal severity. No finding is added, removed,
  re-titled, re-categorised or re-severitied.

  On its own this entry changed no exit code. The band it moves is now an input
  to enforcement — see the confidence-gated `--fail-on` entry above — so the two
  must be read together.

## [1.2.1] - 2026-08-18

**Headline:** two precision corrections found by running the engine over 216K LOC
of real OSS, plus a release gate that was measuring CI runner load instead of
the scanner. No new flags, no output-schema change.

> **Gating note.** The first fix lowers severity on *unproven* findings. If you
> gate on `--fail-on CRITICAL`, a build that previously failed on a chainless
> SQLi shape-match will now pass — the finding is still reported, at HIGH. This
> is a correction of over-severity, not a loss of coverage: recall is unchanged
> and both accuracy corpora still score F1 = 1.000.

### Fixed

- **Unproven dataflow no longer claims a proven finding's confidence.** The AST
  analyzer emits findings for dangerous *shapes* (`cursor.execute(x)`,
  `os.system(x)`) as well as for proven source→sink paths, but both carried the
  same HIGH/CRITICAL. Measured over 216K LOC of real OSS (flask, requests,
  httpx, fastapi, django-cms at pinned SHAs), **every one of the 19 findings the
  taint analyzer produced was chainless**, and most outside test code were false
  positives on developer-controlled input — `config.from_pyfile`, `setup.py`
  reading its own version file, a PYTHONSTARTUP hook, docs examples, CI scripts.
  A reachability-dependent sink with no proven path now drops HIGH→MEDIUM
  confidence, which feeds the existing severity cap so an *unproven* SQLi lands
  at HIGH while a *proven* one keeps CRITICAL. Evidence is preserved (Rule 3);
  only the strength of the claim changes. Sinks that are dangerous regardless of
  input (`pickle.loads`, `yaml.load`, `eval`, weak crypto, JWT) never attempt a
  chain and are untouched.
- **The benchmark regression gate judged scan duration on the accuracy band.**
  `duration_ms` sat under the same ±10% threshold as precision/recall, so a busy
  CI runner failed release tags for a cost the code never incurred: one
  unchanged commit measured 25.6s locally, 33.0s and 35.5s on two runners (a 39%
  spread, the slowest logging an HTTP `context deadline exceeded`). Duration
  still gates — Rule 6 treats performance regressions as bugs — but against its
  own `DurationRegressionThreshold` (100%), above observed jitter and still
  catching anything that doubles the scan's cost.

## [1.2.0] - 2026-08-17

**Headline:** the wiring release. v1.1 shipped several real-world-precision
features whose logic was written and unit-tested but never reached the
production pipeline — so `BENCHMARKS.md` described behaviour the binary did not
have. This release connects them, removes two pieces of dead code that were
actively dangerous to leave in place, and closes four silent-failure paths an
adversarial audit surfaced. It also collapses cross-analyzer duplicates — one
vulnerability was being reported up to three times — and corrects a synthetic
accuracy score that was partly an artifact of those duplicates in both
directions.

**No output-schema change**: `models.Finding`'s serialized shape is
byte-identical. Both CI accuracy gates score F1 = 1.000 (the SAST corpus number
is now earned rather than accidental — see below), and DVWA and Juice Shop both
hold 100% recall at +0.0% against the committed baseline. Every fix is
mutation-tested: the defect was reintroduced and the test confirmed to fail.

Behaviour changes worth reading before upgrading:

- Findings in test/fixture code now report `status: INFO` instead of `WARN` by
  default (`--deescalate-tests=false` restores the old behaviour). Exit codes
  are unaffected — a finding at or above `--fail-on` still `BLOCK`s.
- The rate-limit check now probes generated-content routes
  (`/api/reports/export.pdf`, `/api/invoices/2024.zip`) it previously skipped.
- The cookie-flags check now reports on 4xx responses it previously discarded.

### Fixed — v1.1 wiring pass (documented behaviour that never reached production)

Three v1.1 features were implemented and unit-tested but unreachable through the
real pipeline, so `BENCHMARKS.md` described behaviour the binary did not have.
**No output-schema change** — `models.Finding`'s serialized shape is untouched.

- **`test-fixture` de-escalation (B3) is now wired.** `decision.DecideWithOptions`
  and `Options.DeescalateTests` existed, but `stampDecisions` called the
  option-less `decision.DecideAll` and no config field could enable the rule.
  Added `ScanConfig.DeescalateTests`, the `--deescalate-tests` flag (**default
  on**) and the `scan.deescalate_tests` policy key, and routed the orchestrator
  through `decision.DecideAllWithOptions`. Findings in test/fixture code now
  report `INFO` instead of `WARN`; evidence is preserved (Rule 3) and anything at
  or above `--fail-on` still `BLOCK`s.
- **`static-asset` confidence context (B4) is now produced.** The confidence
  scorer penalised `ResponseContext == "static-asset"`, but the only producer
  returned `"4xx"` or `""`, so the branch was dead. The header and CORS checks now
  tag static-asset findings via a shared `scanner.responseContextFor`; the
  rate-limit check keeps its hard skip, which is correct — rate limiting a
  CDN-served file is not an app-layer control, so there is no observation to
  preserve.
- **`models.IsTestPath` no longer classifies live HTTP routes as test code.**
  The marker regex matches a `tests?` / `testing` / `fixtures` path segment
  anywhere, so a deployed route named `GET /tests`, `GET /api/test` or
  `GET /api/testing/run` was treated as test code and its DAST findings
  de-escalated to `INFO`. Only source-file endpoints are eligible now; a route
  is attack surface regardless of its name.
- **Static-asset classification no longer matches generated-content routes.**
  `pdf`, `zip`, `gz`, `tar` and `wasm` were dropped from `staticFilePathRe`.
  Those extensions overwhelmingly appear on generated endpoints
  (`/api/v1/reports/export.pdf`, `/api/invoices/2024.zip`), where the previous
  behaviour both skipped the rate-limit check — suppressing exactly the CWE-770
  evidence it exists to find — and would have de-escalated their header
  findings. **Behaviour change:** such routes are now probed and reported like
  any other API route.
- **Docker availability is now behind the `democmd` DI seam.** `Run` called
  `exec.LookPath("docker")` before dispatching through the injectable runtime, so
  the suite passed on CI (Docker present) and failed on developer machines
  without it. `Available()` moved onto the `dockerCmd` interface.

### Fixed — dead paths and silent failures found by an adversarial audit

- **Auth profiles failed silently on the documented-but-wrong shape.**
  `docs/fendix-yaml.md` showed a flat `type:` / `value:`; the parser only reads
  a nested `auth:` block. The flat file unmarshalled to a zero value,
  `LoadProfileFrom` returned `(nil, nil)`, and the scan ran **completely
  unauthenticated with no diagnostic**. The parser now detects that exact
  mistake and returns the correction, `ProfileLoader` logs load failures
  instead of discarding them, and the doc is fixed.
- **Cookie-flags discarded auth-gated evidence.** The check returned nil for
  any status `>= 400`, so a login endpoint answering 401 while issuing a
  session cookie without `HttpOnly` produced no finding at all. Now only
  404/410/5xx are skipped; 4xx findings are preserved and de-escalated through
  the shared B4 context.
- **`Deduplicate` was arrival-order dependent.** It seeded a group's endpoint
  set from the first member only, so two members tying on every ordering key
  but carrying different `affected_endpoints` produced different published
  output — including `confidence_score` and `status` — depending on which
  arrived first. Every member's `AffectedEndpoints` is now folded in (F-L6).
- **Python engine died on a missing optional dependency.** `spec_parser`'s
  top-level `import yaml` sat outside the per-check guard, so an environment
  without PyYAML aborted the engine with exit 1 and **zero** findings —
  including from the AST taint analyzer, which needs no third-party package.
  Analyzer imports moved inside their guarded callables; one missing dep now
  skips one analyzer with a stderr notice.
- **`--checks` had no flag.** The orchestrator read `ScanConfig.Checks` and its
  own comment told users to "pass `--checks secrets,semgrep`", but nothing ever
  set the field. The flag now exists and is documented.

### Removed

- `budget.Transport()` — an unreferenced constructor returning a budget-counted
  transport with **no netguard SSRF policy**. Left in place it was a footgun:
  any future check reaching for the obvious-looking helper would have silently
  opted out of egress filtering.
- `ScanRequest.Language` — never set by production, so the key was never
  emitted; the AST analyzer routes by file extension anyway.

### Added

- `models.IsTestPath` — one deterministic test/fixture-path classifier shared by
  the decision layer, mirroring the Python analyzer's `_is_test_path` markers
  (locked by a parity table test).
- `evidence.Evidence.InTest` + `ScoringProvenance.InTest` — internal-only, merged
  across a dedup group with the existing "agree or drop" rule, so a group earns
  the test-fixture de-escalation only when **every** occurrence is test code.
- `benchmark.FPClass.Mechanism()` — every false-positive taxonomy class must now
  name the shipped code that enforces it, guarded by
  `TestEveryFPClassNamesItsMechanism`. This is the drift guard that makes the
  `test-fixture` / `static-asset-context` failure mode unrepeatable.

### Fixed — cross-analyzer duplicates, and an accuracy number that was partly an artifact

Running the engine over 216K LOC of real OSS (flask, requests, httpx, fastapi,
django-cms at pinned SHAs) surfaced a cluster of related defects.

- **One vulnerability was reported up to three times.** Several static engines
  cover the same constructs, and `Deduplicate` groups on
  `(Title, Category, Severity)` — so two engines describing one sink in
  different words never merged. On fastapi 0.110.0 a single `SECRET_KEY = "..."`
  produced three findings at two different severities. New
  `engine.CollapseDuplicateLocations` keeps the finding from the most-trusted
  analyzer tier per `(Category, Endpoint)`. It is **cross-tier only**: two
  findings from the *same* engine at one location are two distinct rules (a
  Dockerfile legitimately earns both "no USER directive" and "pins to :latest"),
  and severity is never raised to the group maximum, so the lowest-trust engine
  cannot escalate through the back door.
- **The synthetic-corpus F1 was inflated by duplicate emissions.** The accuracy
  scorer matched *findings* to cases within a ±6-line window, so a spare
  duplicate claimed the next unclaimed case and shifted every later emission one
  case along. This cut both ways: it manufactured a false positive on cmdi line
  36 (holding overall F1 at 0.987, under the 0.990 CI floor) **and** it credited
  `secrets` with 13/13 while the multi-line JWT on line 24 was never detected at
  all — a duplicate eleven lines away was filling its slot. The scorer now
  deduplicates emissions by line, because the corpus asserts which *lines* are
  vulnerable, not how many findings land on them.
- **Multi-line JWTs were not detected.** A token split by implicit string
  concatenation is invisible to a line-based three-segment pattern. Added a
  header-anchored pattern (`eyJhbGciOi` is the base64 of `{"alg":"`), which
  closes the real false negative the scorer fix exposed.
- **`double-sanitize` (B5) only covered half the shapes.** `_expr_is_fully_escaped`
  handled f-strings and `+` concat but not `%`-format, whose right operand is an
  `ast.Tuple` with no handler. `mark_safe("%s%s" % (indent, escape(title)))` —
  the django-cms shape — was reported as reflected XSS despite the explicit
  `escape()`. Added `Tuple`, `Name`-binding and constant-repetition arms.
- **The DAST benchmark could not run on a busy machine.** `benchmark run`
  hardcoded ports 3000/8080 and failed with a raw `exit status 125`, leaving a
  stale container behind. Port 3000 is the single most commonly occupied port on
  a developer machine. Added a preflight that names the port and the override
  (`FENDIX_BENCH_JUICESHOP_PORT` / `FENDIX_BENCH_DVWA_PORT`), plus cleanup on
  failure.

Verified after the change: synthetic accuracy corpus **F1 1.000** (38 TP / 0 FP /
0 FN, semgrep installed — the CI configuration); Python taint corpus F1 1.000;
DVWA and Juice Shop both 100% recall, F1 1.000, +0.0% vs the committed baseline.

## [1.1.0] - 2026-07-08

**Headline:** Fendix v1.1 — real-world precision. v1.0 proved the engine on
hand-authored corpora (P/R/F1 = 1.000); v1.1 proves it on real code. We built a
real-repo benchmark instrument, measured our own false-positive rate honestly,
and closed the dominant noise classes — while the synthetic accuracy gate held
at 1.000 throughout. The scan-report JSON schema is unchanged (this release adds
no output fields). Every accuracy claim below is backed by a reproducible
measurement (Rule 5); no AI is in any scoring path (Rule 8).

### Added
- **Real-world precision benchmark** (`fendix benchmark run --target realworld`).
  Scores a real source tree against a committed labels file and reports
  precision, per-FP-class counts, false-negatives, and findings-per-KLOC — not
  just a synthetic pass-rate. Three corpus tiers: **seed** (private repos,
  loud-SKIP when absent — never silently green), **public** (pinned-SHA OSS,
  CI-gated), **regression** (per-class negatives in the taint corpus). Ships an
  offline scorer so a repo can be scanned once and re-scored without re-running,
  and a triage report listing unlabeled findings for incremental labeling.
- **`fendix verify` now covers correlated and active-probe findings** (previously
  returned `unknown`). Correlated findings resolve two-sided (blackbox endpoint
  gated OR whitebox sink gone → resolved); active-probe findings re-verify via a
  consent-gated re-probe (`--enable-active`), reporting still-present without
  consent rather than guessing.

### Fixed — false positives (the noise-reduction pass)
Measured on a real Django app: the SAST taint surface dropped from ~90 findings
to 5, eliminating 8 of 11 labeled FP classes while retaining the one confirmed
true positive.

- **SQL constant-folding** — literal/constant SQL built with `%`-format, `.join`,
  or a ternary is no longer flagged as injection (`const-fold-miss`).
- **Membership-guard dominance** — a `if x not in (...)` guard only suppresses a
  finding when it dominates the sink; fixed over-suppression (false negatives)
  and spurious suppression alike (`guard-dominance`).
- **Test-fixture de-escalation** — findings under `tests/`, `conftest.py`,
  `*_test.go`, `spec/` de-escalate to INFO (evidence preserved, config-overridable)
  instead of alerting as production issues (`test-fixture`).
- **DAST response-context** — header/CORS findings on 4xx responses and
  rate-limit findings on static assets are confidence-penalized rather than
  reported at full weight (`http-4xx-context`, `static-asset-context`).
- **Double-sanitize** — `Markup(html.escape(x))` (and the f-string/concat forms)
  no longer flagged as XSS (`double-sanitize`).
- **Weak-crypto over-fire** — `md5()`/`sha1()` on metadata-named identifiers no
  longer misread as password hashing (`heuristic-overfire`).
- **Fabricated path-traversal** — from-imported `webbrowser.open()` and other
  non-filesystem `.open()` calls no longer synthesize a traversal chain
  (`fabricated-chain`).
- **npm version-range floor** — caret/tilde ranges report as INFO instead of
  asserting a vuln at the range floor without lockfile resolution
  (`version-range-floor`).

### Fixed — performance (Rule 6)
- **Secret-in-log analyzer O(fan-out) collapse.** `ASTAnalyzer._expr_references_secret`
  re-walked the AST subtree per resolved binding; combined with augmented-assignment
  tree synthesis (`acc += acc` doubles the tree per rebind), shared subtrees were
  re-walked combinatorially. Threading a shared `id(node)` seen-set makes every
  node visited at most once — exponential → linear. A full `--python-engine` scan
  of a ~1,200-file real repo went from **~50 minutes to 9 seconds** (>37,000× on
  the worst single file). This is what made real-world measurement feasible.

### Changed
- **Benchmark CI** gates on the synthetic taint corpus (F1 must stay 1.000; any
  HANDLED regression fails the build) and discovers the real-world regression
  tier; seed entries loud-SKIP in CI, public entries gate.
- `docs/accuracy.md` and `BENCHMARKS.md` gain a real-world track (§5) with the
  measured numbers, per-FP-class deltas, and honest lower-bound / label-coverage
  caveats retained.

## [1.0.0] - 2026-07-01

**Headline:** Fendix v1.0 — the production milestone (validated via v1.0.0-rc1:
signed pipeline green, cosign signature verified). Bundles the v0.20→v0.29 engine-quality arc — a decision/confidence layer
surfaced across every output, an honesty pass that made every accuracy number
reproducible + CI-gated, faster developer experience, and Java SAST coverage.
Each phase was adversarially reviewed before merge. The scan-report JSON schema
stayed backward-compatible throughout (additive only).

### Added
- **Decision reports (v0.24).** Every finding carries a BLOCK/WARN/INFO decision
  + a deterministic 0–100 confidence score with explainable reasons, surfaced in
  JSON (`decisions` block), SARIF (level + properties), HTML, the CLI stderr
  summary, and the PR comment. PR blocking is driven by the (contract-locked)
  exit code. Confidence is rule-based — no AI decides a score (Rule 8).
- **Evidence architecture (v0.22) + confidence engine (v0.23).** Internal
  provenance/lineage threaded through correlation; deterministic confidence
  scoring whose reasons reconstruct the score exactly.
- **Benchmark framework + `BENCHMARKS.md` (v0.20/v0.26).** Reproducible
  recall/precision with per-number reproduce commands, version stamps, caveats,
  and CI gating; DVWA + Juice Shop DAST baseline; a `fendix benchmark` command.
- **CLI-success-rate instrumentation (v0.25).** Opt-in metrics record one event
  per invocation (command name + coarse error class only — no args/PII);
  `fendix metrics show` reports the rate.
- **Java SAST — 11 line-local regex rules (v0.27–v0.29):** command injection,
  SQLi-by-concat, weak crypto, insecure deserialization, XXE, insecure cookie,
  weak randomness, LDAP injection, SSRF, reflected XSS, path traversal — all at
  the `native_go` (regex) honesty tier.
- **Developer experience (v0.25):** teaching error messages, a quickstart +
  grouped `--help`, detection-aware `fendix init`, triage-first PR comment
  (leads with the merge verdict), O(changed-files) incremental scans.

### Changed
- **Accuracy claims reconciled to reproduced numbers (v0.26, Rule 5).** Stale
  v0.11.0 marketing figures that no longer reproduced were corrected; synthetic
  F1 is **1.000** again only after the v0.27 SSRF taint fix made it reproduce,
  and it is now CI-gated (`--min-f1 0.99`). Heavy-eval `min_count:0` advisory
  rows are excluded from recall (no fabricated "N/N" — reproduced 2026-06-30).

### Fixed
- **SSRF multi-hop taint (v0.27):** taint now flows through a `"scheme://" +
  tainted` concatenation into the request sink.
- Java-SQL `Executor.execute` false positive; weak-random comment/string/
  identifier false positives; XSS non-response-receiver false positive (v0.28–v0.29).

### Security
- **GitHub Action shell-injection fixes** — all `${{ inputs.* }}` routed through
  `env:` (v0.24).
- **Diff fast-path symlink containment** — incremental scans can't read outside
  the repo via a symlinked parent (v0.25).
- **OWASP Benchmark two-layer SKIP** — `Scan()` + `Run()` both refuse to emit a
  number (Java needs deep taint analysis Fendix doesn't yet have); machine-pinned
  (v0.27). No Java/OWASP accuracy number is published.

## [0.19.0] - 2026-06-22

**Headline:** scan from an uploaded OpenAPI/Swagger spec file, plus a
false-positive precision pass on the FastAPI auth check and the password
exposure guard.

### Added
- **Local-file OpenAPI/Swagger spec upload.** Start a scan from an uploaded
  spec file (JSON or YAML) instead of only a hosted schema URL. The local-file
  spec read is capped by the same `maxSpecBytes` ceiling as the URL path so a
  malicious or runaway spec can't exhaust memory.

### Fixed
- **FastAPI "missing auth dependency" check scoped to real FastAPI routes.**
  The rule matched any `@object.method(...)` decorator with no framework check,
  flagging Django/DRF (`@action`, `@extend_schema_field`), Celery
  (`@shared_task`) and Pydantic (`@field_validator`) as unauthenticated FastAPI
  routes. It now gates on a FastAPI import + real HTTP verbs and recognises
  `Depends`/`Security`/`Annotated[...]` auth. On a real Django monorepo this cut
  256 findings to 10 (the 10 being genuine unauthenticated routes in embedded
  FastAPI services).
- **Password-field exposure guard hardened against i18n false positives.**
  i18n/label dictionaries (where `"password"` is the translated UI label) are
  no longer flagged, while genuine plaintext-credential leaks — verbose user
  records, combined payloads, non-Latin credentials — are still caught. The
  guard keys off the matched value's shape rather than a body-wide heuristic.
- **Whitebox taint false positives suppressed.** Closed a batch of taint
  false positives surfaced by real-world scans, each backed by a regression
  case.

## [0.15.0] - 2026-05-24

**Headline:** real-world accuracy pass. Closes five gaps surfaced by a
fendix-vs-bandit-vs-semgrep-vs-pip-audit benchmark on Vulnerable-Flask-App,
django.nV, dvpwa, a CVE-pinned `requirements.txt`, and `psf/requests` v2.32.4
(clean-code FP baseline).

The headline outcome: `fendix scan --code <path>` now exercises the AST
analyzer by default — that work was sitting unreachable behind a flag in
v0.14.1. On the vulnerable-Flask corpus this lifts findings from 103 to
119 without touching the CLI invocation. On `psf/requests` the FP count
on path-traversal sinks drops from 2 to 0.

Commits in this release:

- `914c6f7` — three accuracy fixes (CLI wiring, pip-audit failure mode, os.path FP)
- `91c38c2` — config-style hardcoded-secret pattern + `fendix engine` subcommand
- `8cb258c` — preceding analyzer gap fixes from the E2E audit (alias-resolved pickle, os.path.join sinks, 3 missing PyPI CVEs)

### Added

- **`fendix engine` subcommand** (`info` / `sync`). `engine info` shows
  which Python engine path resolves and from where (`FENDIX_ENGINE` env /
  embedded payload / local `python/`), plus the version stamp on disk.
  `engine sync` force-reextracts the embedded engine to `~/.fendix/engine/`
  — clears, repopulates, and re-stamps — so users can recover from
  hand-edited or partially-deleted state without reinstalling. See
  [go/cmd/fendix/engine.go](go/cmd/fendix/engine.go).
- **`HARDCODED_SECRET_CONFIG` secret pattern** in the native-Go secrets
  scanner. Catches config-style assignments the bare `HARDCODED_PASSWORD`
  regex missed: `app.config['SECRET_KEY_HMAC'] = 'secret'` (subscript +
  compound suffix), `app.secret_key = 'X'` (attribute style), bare
  `SESSION_SECRET = "..."` with values as short as 4 chars (below the
  20-char floor of the API-key regex). Narrow keyword family
  (`secret_key | jwt_secret | hmac_key | app_secret | encryption_key |
  signing_key | csrf_secret | session_secret | cookie_secret |
  api_secret`) keeps the false-positive rate at zero on `psf/requests`.
  Orchestrator-side `Deduplicate` collapses multiple per-file hits into
  one finding with `AffectedEndpoints` listing every line.
- **3 missing PyPI CVEs** in the curated fallback list — PyYAML
  CVE-2020-14343 (safe ≥ 5.4), requests CVE-2023-32681 (safe ≥ 2.31.0),
  lxml CVE-2021-28957 (safe ≥ 4.6.3). Closes a gap where the offline /
  pip-audit-unavailable path missed CVEs that OSV.dev had.
- **`os.path.join` / `os.path.abspath` / `os.path.expanduser` /
  `os.path.expandvars` as path-traversal sinks** in the Python AST
  analyzer. Catches the standalone `os.path.join(base, user_input)`
  pattern that previously slipped through (the join was tracked through
  the taint chain only when fed into `open()` / `send_file()`).
- **Import-alias resolution for pickle and yaml** in the AST analyzer.
  `import pickle as p; p.loads(blob)` and `import yaml as y; y.load(s)`
  are now detected via a `_module_aliases` map populated by
  `visit_Import`. Closes an evasion class flagged by the E2E audit
  fixtures at `/tmp/fendix-e2e/fixtures/vulnerable/evasion_pickle_alias.py`.

### Changed

- **`fendix scan --code <path>` auto-enables the Python engine.** The
  `--python-engine` flag stays in place — unchanged for users who set it
  explicitly — but when `--code` is passed AND the flag was not given on
  the command line, the engine now defaults to ON. Without this nudge,
  v0.14.1's `fendix scan --code <path>` ran only the native-Go checks
  (`secrets / semgrep / deps`) and silently skipped the AST analyzer
  (`SEC-PY_SQL_INJECTION`, `SEC-PY_YAML_UNSAFE_LOAD`, `SEC-PY_PICKLE_LOAD`,
  `SEC-PY_SSTI_*`, `SEC-PY_OPEN_REDIRECT`, `SEC-PY_PATH_TRAVERSAL`,
  `SEC-PY_AUTH_HEADER_TRUST`) — the engine code shipped, but no user
  exercised it. `NewOrchestrator` already falls back gracefully when no
  engine is discoverable, so binaries built without an embedded payload
  retain the v0.14.1 behavior. See [go/cmd/fendix/main.go](go/cmd/fendix/main.go).
- **`os.path.expanduser / abspath / expandvars / join` only emit when
  taint-proven.** Library code passes opaque parameters to these all the
  time; v0.14.1's emit-on-any-non-constant posture produced 2 FPs on
  `psf/requests`. For the `os.path.*` family, only emit when
  `_collect_taint_chain` proves a flow back to a request source. The
  conservative posture is preserved for `open()` / `Path()` /
  `send_file()` / `send_from_directory()` — passing user input to those
  is suspicious shape even without a proven chain. See
  [python/analyzers/ast_analyzer.py](python/analyzers/ast_analyzer.py).

### Fixed

- **pip-audit `exit=1 + empty stdout` no longer swallowed as success.**
  pip-audit exits 1 BOTH on "vulns found" (success path) AND on internal
  errors (e.g. can't install a package to read its metadata under a
  newer Python). In the failure case stdout is empty; v0.14.1 parsed
  `{}`, found zero entries, returned success, and the curated fallback
  never fired — a silent zero-finding dep scan. Real-world repro:
  pillow 8.0 on Python 3.14. Now treated as failure and falls through
  to the curated list. See [python/analyzers/deps.py](python/analyzers/deps.py).

### Tests

- 41 new Python tests (path-traversal sink edge cases, alias resolution
  positive + negative, pip-audit exit-1-empty-stdout fallback,
  3 new dep CVEs).
- 2 new Go tests (`TestScan_HardcodedSecretConfig` + FP-guard variant).
- 202 tests passing total (161 Python + 41 Go in the relevant packages).

### Verified outcomes

| Metric | v0.14.1 | v0.15.0 |
|---|---|---|
| `fendix scan --code vflask` total findings | 103 (Go-only) | **119** (+16 AST) |
| Hardcoded-secret coverage on vflask lines | 1/4 | **4/4** (3 via `AffectedEndpoints`) |
| Path-traversal FPs on `psf/requests` | 2 | **0** |
| Real SAST TPs across vuln corpus | ~14 | **~24** |
| Test count (Python + Go scanner pkgs) | 159 | **202** |

## [0.14.1] - 2026-05-16

**Headline:** enterprise-readiness audit pass — closes every actionable
finding from the 2026-05-16 multi-round audit. Pure hardening; no new
features, no API surface, no CLI flag, no schema field. Backend +
frontend sync against this tag is a no-op on the data contract; the
deltas are entirely in supply-chain provenance + plugin-trust posture
+ engine concurrency.

Single PR: [#6](https://github.com/Abdel-RahmanSaied/Fendix/pull/6).
The 4 audit commits plus 1 follow-up workflow-lint fix are all on
this tag.

### Added

- **Supply-chain hardening** (commit `a3f4d9b`).
  - `enforce-signing` job in `release.yml` refuses to ship a `v*` tag
    unless `vars.COSIGN_ENABLED` is `true` (or explicit
    `allow-unsigned` for debugging). Closes a marketing-vs-artifact
    gap where `SECURITY.md` advertised signed releases but cosign was
    off by default.
  - CycloneDX + SPDX SBOMs per binary via `syft`, both cosign-signed.
    Docker image gets an in-toto CycloneDX attestation in Rekor.
  - SLSA v1.0 build provenance attestations per binary
    (`.intoto.jsonl`) and per Docker image. L2 claim with self-
    verifiable L3 properties.
  - Every third-party GitHub Action pinned to a 40-char commit SHA.
    `actionlint` job + inline SHA-pin guard in `ci.yml` fail CI on
    drift. `actionlint` and `syft` installed via `go install` so no
    new third-party actions to pin.
  - `.github/dependabot.yml` (new): weekly Monday bumps for
    github-actions / gomod / pip / docker ecosystems; action bumps
    grouped by family (actions / docker / sigstore).
  - `Dockerfile` and `Dockerfile.app` base images pinned to digest
    (`golang:1.22-alpine@sha256:1699c10...`,
    `python:3.11-slim@sha256:9a7765b3...`).
  - `-trimpath` + explicit `CGO_ENABLED=0` in release.yml and both
    Dockerfiles.
  - `SECURITY.md` discloses the transitive `golang.org/x/telemetry/
    counter` import (via `golang.org/x/vuln`). Local-only counters;
    uploads nothing unless host user runs `go telemetry on`.

- **Plugin trust tier-1** (commit `363c091`).
  - `fendix plugins install <url>` scheme allowlist: accepts
    `https://`, `http://`, `git://`, `ssh://`, scp-style git URLs.
    Rejects `file://`, `ext::`, and the rest of git's transport zoo
    that can execute arbitrary commands (CVE-2017-1000117 family).
  - `redactPluginEnv()` strips credential-shaped env vars
    (`AWS_*`, `GITHUB_TOKEN`, `OPENAI_*`, `*_SECRET`, etc.) from
    `os.Environ()` before invoking a plugin subprocess.
  - `~/.fendix/plugins/` created with mode `0700` (was `0755`).
  - `TestPluginSandbox_DocumentsUnmitigatedRisks` is living
    documentation of tier-1 scope-outs (filesystem reads, network
    egress, detached children) that will be promoted to real
    assertions when tier-2 ships.

### Changed

- **Engine concurrency + perf** (commit `c103601`).
  - `WorkerPool` channel buffer reduced from N×M to `workers*4`.
    Producer now selects on `ctx.Done()` so mid-flight cancel
    propagates (previously masked by oversized buffer never
    blocking). `time.Sleep` replaced with `time.After` + ctx
    select so the inter-request delay also honours cancellation.
  - `Correlate` hoisted the path-segment noise filter to package
    scope and pre-caches per-blackbox + per-whitebox segment
    splits. `BenchmarkMemory_Correlate1000` delta: time **−15%**
    (6.25ms → 5.32ms), bytes **−41%** (2.12 MB → 1.25 MB),
    allocs **−22.6%** (13 324 → 10 316).
  - Crawler BFS short-circuits the moment
    `len(endpoints) >= --max-endpoints` so `--crawl-depth ≥ 2`
    scans of large sites stop fetching pages they'd discard
    anyway.
  - `auth.go::mustJSON` panic replaced with `slog.Error` + empty-
    JSON fallback. Zero `panic(` calls remain in production code.
  - `pip.SetOSVAPIBaseForTest(url)` exported as a test-only seam
    so orchestrator-level continue-on-error tests can drive OSV
    at a 503 server.

### Tests

- **9 new test files; 27 new tests across engine + plugin + scanner**:
  workerpool cancel-during-produce + bounded-buffer, dedup
  order-invariance + idempotency (100 random permutations),
  correlator order-invariance + no-blackbox-suffix + idempotency
  property tests, correlator scaling bench at n ∈ {500, 1 000,
  2 500, 5 000}, crawler BFS cap test, OSV total-outage continue-
  on-error test, plugin env-redaction unit + integration, plugin
  install-URL rejection contract.

### Documentation

- **`FENDIX_AUDIT_REPORT.md`** §3.2, §6, §11, §13, §15 refreshed
  in place with inline "Refreshed 2026-05-16" markers. Every
  numbered finding from the 2026-05-14 audit cut now carries a
  STATUS line; new §15.6 (findings raised during refresh) and
  §15.7 (explicit open follow-ups) added.
- **Sprint Status sections** for Sprints 04, 05, 06, 07, 08, 09
  backfilled (they shipped but DoD #7 was violated at ship time).
  Honest about what was and wasn't recorded at the moment.
- **`SECURITY.md`** verify-blob / verify-attestation commands for
  cosign + SBOM + SLSA provenance.

### Fixed

- **`release.yml` mirror job** (commit `5aafa8a`): `$ASSETS` unquoted
  glob converted to a bash array with `nullglob` (shellcheck
  SC2086). Adds an explicit "no assets matched" guard.
- **`heavy-eval.yml` quality-gate step**: `ls -td | head -1`
  replaced with a `find -printf` pipeline (shellcheck SC2012). Now
  emits an explicit "no run directory" error rather than passing
  an empty path to `gate.py`.

## [0.14.0] - 2026-05-16

**Headline:** the plan-finish "v0.12 → v0.14" mega-release. Folds
13 sprint commits (Sprints 04, 05, 06, 09, 10, 11, 13, 14, 15, 16,
17, 18, plus a code-review follow-up) into a single minor cut.

Single PR: [#6](https://github.com/Abdel-RahmanSaied/Fendix/pull/6).
The author originally drafted this CHANGELOG with `### v0.12.0`,
`### v0.13.x`, `### v0.14.0` sub-headings inside `[Unreleased]`,
intending separate tags. The plan-finish session shipped fast
enough that splitting into 3 release events would have been
ceremony without value; tagged together. The pre-existing
sub-headings are preserved below so cherry-pick / revert maps
cleanly.

### Sprints 07 + 08 — closed by reference to sibling repo

**Sprint 07 (`fendix serve` REST API)** and **Sprint 08 (OIDC login)**
are marked ✅ in PLAN.md as **already-covered by the sibling repo
`fendix-services/fendix-backend`** — a Django 5.2 + DRF API server
that:

- Wraps the fendix CLI as a multi-tenant SaaS (Celery 5.4 +
  Postgres 16 + Redis).
- Exposes the REST scan-job lifecycle the brief specified
  (`backend/scanning/views.py`, OpenAPI contract at
  `backend/openapi.json`).
- Implements JWT auth via simplejwt (RS256), with key generation
  at `make keys`.
- Adds billing, subscriptions, accounts, scheduling, notifications
  — well past Sprint 07's "in-memory MVP" scope.

The plan-finish session started a Go-native `internal/servecmd`
package, then discarded it on the user's instruction to "stop
implementing REST API, check fendix-backend." The right framing is:
Sprint 07/08's audit-gap ("no REST API, no auth on a serve mode")
is closed by the production backend, not by adding a parallel Go
implementation. The Fendix CLI in this repo remains a CLI; the
serve-mode story lives in the Django backend.

D1 (persistence) and the in-memory caveat from the brief are
moot for the same reason — Postgres handles persistence in the
backend.

### v0.12.0 — Sprints 04 / 05 / 06 (unified textscan engine)

#### Added

- **`internal/scanner/textscan` package (Sprints 04 + 05 + 06).**
  A unified regex-based SAST engine that drives Go, JS/TS,
  Dockerfile, and Kubernetes YAML rules in one shared codebase.
  Plan-finish session combined three originally-separate sprints
  to deliver shared scaffolding once instead of three times.

  Rulesets (16 rules total):
  - **Go (4):** SQL injection via concat, exec.Command shell
    invocation, weak hash (MD5/SHA1) for password storage,
    hardcoded AWS access-key ID.
  - **JS/TS (6):** eval() with non-literal arg, innerHTML
    assignment from non-literal, child_process.exec, document.write,
    require() with non-literal path, hardcoded AWS key.
  - **IaC (6):** Dockerfile FROM (privilege drop), ADD vs COPY,
    :latest pinning; Kubernetes privileged: true, hostNetwork: true,
    allowPrivilegeEscalation: true, runAsUser: 0.

  Filename-extension routing (.go → Go rules, .js/.ts → JS rules,
  Dockerfile / *.dockerfile → Docker rules, .yaml → k8s rules).
  Skips noisy build dirs (node_modules, vendor, .git, build, dist).
  1 MiB per-file cap. Pure stdlib — no new deps, no CGo.

  Wired into orchestrator.go between the semgrep and Python
  passes; runs whenever `--code` is set. 11 tests in
  textscan_test.go cover positive / negative pairs per rule
  category plus the dir-skip and endpoint-format invariants.

  Closes audit §15.2 / §15.3 (SAST coverage gaps).

  **Cuts vs original briefs (carried to follow-up sprints):**
  - **Sprint 04.5:** Go XXE + INSECURE_RAND — need AST context
    to avoid stdlib FP floods.
  - **Sprint 05.5:** JS prototype-pollution + insecure-RNG
    (proximity-based) — regex+window has too many FPs.
  - **Sprint 06.5:** Terraform HCL — D2 gate at default (no TF).

### v0.13.0 — Sprint 09 (Offline mode + `fendix db`)

#### Added

- **`internal/offline/` package + `fendix db` subcommand (Sprint 09).**
  Air-gapped CVE-database snapshot format (JSON, schema v1) with
  three management subcommands:
  - `fendix db update --source <osv-export.json>` — ingest an OSV
    advisory export into a snapshot.
  - `fendix db list [--path]` — print snapshot metadata.
  - `fendix db verify [--path]` — print SHA-256 for integrity check.

  Plus additive `--offline` and `--offline-db <path>` flags on
  `fendix scan` (honest stub today; per-scanner integration is the
  follow-up Sprint 09.5 — see internal/offline/offline.go package
  doc for the API the scanners will call).

  Closes audit §17 / D3-Option-A precondition. Today's shippable
  surface is the format + tooling; the runtime path that swaps each
  ecosystem's HTTP CVE call for a snapshot lookup is a per-scanner
  bolt-on that benefits from being staged.

### v0.13.0 — Sprint 11 (PDF executive report)

#### Added

- **`--format pdf` (Sprint 11).** New PDF executive report
  output via `fendix scan --format pdf` and `fendix report --format
  pdf`. Adds direct dep `github.com/go-pdf/fpdf` (MIT, pure Go, no
  CGo — pre-allowed in PLAN.md). Structure: cover page →
  executive summary with severity counts table and top-3 findings
  → paginated findings table with severity-coloured cells →
  remediation plan (CRITICAL + HIGH only) → metadata appendix.

  New flag `--classification <text>` (default `INTERNAL`) renders
  a red banner at the top-right of every page. Empty disables.

  English-only for v0.13.0. Arabic PDF is **deferred to Sprint
  11.5** — fpdf's built-in fonts don't render Arabic glyphs;
  shipping a 10MB Noto Arabic font inflates the binary too much
  for the MVP. Closes audit §6 ("no PDF today").

### v0.13.1 — Sprint 14 (Jira integration)

#### Added

- **`fendix jira` subcommand and `internal/integrations/jira`
  package (Sprint 14).** Idempotent Jira sync: each finding above
  FENDIX_JIRA_MIN_SEVERITY (default HIGH) gets one Jira issue with
  a `fendix-id:<finding.ID>` label as the idempotency key.

  ```bash
  fendix scan ... --format json --output findings.json
  export FENDIX_JIRA_URL=https://your-org.atlassian.net
  export FENDIX_JIRA_PROJECT_KEY=SEC
  export FENDIX_JIRA_EMAIL=you@example.com
  export FENDIX_JIRA_API_TOKEN=<token>
  fendix jira --findings findings.json
  ```

  Severity → priority mapping: CRITICAL→Highest, HIGH→High,
  MEDIUM→Medium, LOW/INFO→Low. Description format is Jira's
  plaintext+markup (universal across Cloud and Server tiers);
  ADF auto-rendering happens server-side on Cloud.

  Auto-resolution (transition issues to Done when findings stop
  appearing in scans) is **deferred to Sprint 14.5** because it
  needs a "this is the latest scan" signal that requires Sprint
  07.5 persistence to be honest. Today the subcommand is
  create-or-skip only; re-runs are idempotent.

  Closes audit §13 ("no ticketing today"). The package is
  designed to slot into `fendix serve` (Sprint 07) and the ghapp
  post-scan hook with no code change — `(*Client).SyncFindings`
  is the integration surface.

### v0.14.0 — Sprint 16 (Enterprise benchmark harness)

#### Added

- **`scripts/benchmark-enterprise/` (Sprint 16).** Apples-to-apples
  comparison of three Python-aware SAST tools (fendix vs. semgrep
  vs. bandit) on a shared ~100-LOC fixture with 5 labeled true
  positives and 5 labeled false-positive probes. Measures
  wall-clock, peak RSS (via GNU `time -v`), TP count, and FP count.
  Tools that aren't on PATH are honestly reported as "skipped" — no
  silent zeros.

  Each tool's output is scored against the fixture manifest
  (`manifest.json`) by `score.py`, which tolerates the three different
  output shapes (fendix's `"findings"[].endpoint`, semgrep's
  `"results"[].start.line`, bandit's `"results"[].line_number`).
  Findings on lines outside the labeled set are ignored — they're
  typically style or import-hygiene rules outside the benchmark scope.

  CI: a new `benchmark-enterprise.yml` workflow runs on release tags
  and `workflow_dispatch`, installs semgrep + bandit + GNU time, then
  posts the results table as a GitHub Actions job summary.

  **Honesty constraint (in the runner's stdout AND every doc):**
  measures Python SAST on a single fixture. Does NOT compare DAST
  (only fendix), JS coverage (semgrep), or general SAST against a
  customer's full repo.

### v0.13.0 — Sprint 10 (Arabic HTML report, i18n)

#### Added

- **Arabic HTML report (Sprint 10).** `fendix scan` and `fendix
  report` now accept `--lang ar` to render the HTML output
  right-to-left with Arabic strings. JSON, SARIF, and (future) PDF
  outputs stay English (machine-consumed; localisation would break
  downstream tooling).

  New package `go/internal/reporters/i18n/` holds the language
  catalog (`Strings` struct, `English()`, `Arabic()`, `Get(lang)`,
  `IsSupported(lang)`, `IsRTL(lang)`). Adding a language is one new
  constructor + a switch case. The new `RenderHTMLOpts(w, findings,
  meta, HTMLOptions{Lang: lang})` is the i18n-aware entry point;
  `RenderHTML` is preserved as an English-defaulting thin wrapper so
  every existing caller keeps working byte-for-byte.

  Arabic strings ship as a machine-generated baseline marked with
  `TRANSLATION_REVIEW_NEEDED` comments inline. A native-speaker
  security professional is expected to clear those before Fendix
  v0.13.0-stable is promoted — see RISKS.md ("Arabic translation
  review"). Numerals stay Western Arabic (0-9), not Eastern
  (٠-٩), for tooling compatibility.

  Unknown `--lang` values fall back to English with a stderr warning.
  RTL is detected from the language code (ar, he, fa, ur) so adding
  the next RTL language is a single switch entry.

  Closes audit §13 ("no i18n today").

### v0.13.1 — Sprint 15 (Slack / Teams webhook alerts)

#### Added

- **`fendix notify` subcommand and `internal/integrations/notify`
  package (Sprint 15).** Post Slack Block Kit + Teams Adaptive Card
  alerts for findings above a severity floor:

  ```bash
  fendix scan ... --format json --output findings.json
  export FENDIX_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
  fendix notify --findings findings.json
  ```

  Configuration (12-factor, matching `cmd/fendix-app`):
  - `FENDIX_SLACK_WEBHOOK_URL` / `FENDIX_TEAMS_WEBHOOK_URL` — either
    or both. No-op when neither is set.
  - `FENDIX_NOTIFY_MIN_SEVERITY` — `CRITICAL` (default) / `HIGH` /
    `MEDIUM` / `LOW` / `INFO`.
  - `FENDIX_NOTIFY_DEDUP_WINDOW` — Go duration (default `1h`); same
    finding ID won't re-alert inside the window. In-memory only;
    process restart re-alerts. Persistence is Sprint 15.5 (waits on
    Sprint 07.5 SQLite).

  Per-sink errors are logged but do not block the other sink. Webhook
  URLs are redacted to `[REDACTED]` in error messages so secrets
  don't leak into operator logs. The Teams payload is pinned to
  Adaptive Card schema 1.3 for the widest client compatibility.

  Closes audit §13 ("no real-time alerts today"). The package is
  designed to slot into `fendix serve` (Sprint 07) and the ghapp
  post-scan hook with no code change — `(*Notifier).NotifyAll(ctx,
  findings)` is the integration surface.

### v0.14.0 — Sprint 17 (GitLab + CircleCI templates)

#### Added

- **`fendix init --ci <github|gitlab|circleci>` (Sprint 17).** The
  init command now emits CI templates for three systems, not just
  GitHub Actions. Without `--ci`, fendix auto-detects from `.github/`,
  `.gitlab-ci.yml`, or `.circleci/` in the project root and falls
  back to `github` when none are present. Per CI:
  - **github** (default): `.github/workflows/fendix.yml` (unchanged)
  - **gitlab**: `.gitlab-ci.fendix.yml` (a GitLab `include:` file
    that emits a `gl-sast-report.json` SAST report) plus a
    `NEXT-STEPS-fendix.md` that explains the `include:` wiring.
  - **circleci**: `.circleci/fendix-config.yml` (an inline snippet
    the user merges into their main `config.yml`) plus a
    `NEXT-STEPS-fendix.md` explaining the merge recipe.

  Every emitted `.yml` is parsed by `gopkg.in/yaml.v3` at test time
  (`TestAllTemplatesParseAsYAML`) so a typo can't ship in a release.
  Closes audit §8 ("GitHub Actions only today").

### v0.13.1 — Sprint 13 (GitHub App handler doc cleanup)

#### Fixed

- **Stale package doc in `go/internal/ghapp/webhook.go` (Sprint 13).**
  The package comment still described `handler.go`'s scan-and-comment
  workflow as "stubbed pending a follow-up commit." It hasn't been a
  stub for several commits: `Handler.HandlePullRequest` (clone → scan
  → comment → SARIF), `Handler.HandleCheckRun` (Re-run check button),
  and `Handler.HandlePush` (no-op baseline placeholder) are all
  implemented with `cmd/fendix-app/main.go` fully wired. Updated the
  package doc to describe what's actually there. No behaviour change.

### v0.14.0 — Polish phase, Sprint 18

#### Added

- **Semgrep rule pack expanded from 9 to 24 rules (Sprint 18).** New
  rules target patterns the native regex engine cannot catch
  (multi-line, framework-specific, proximity-based crypto misuse):

  - **auth:** Django function-based view missing auth decorator
    (`@login_required` / `@permission_required` / `@user_passes_test`
    / `@staff_member_required`); Flask route with no auth-style
    decorator above `@app.route(...)` (`@login_required` /
    `@requires_auth` / `@jwt_required` / `@auth.login_required`).
  - **injection:** Django ORM raw SQL (`Model.objects.raw(<var>)`,
    `<qs>.extra(where=<var>)`); Flask `render_template_string(<var>)`
    SSTI; `subprocess(<var>, shell=True)` (high-precision variant of
    the existing rule, only fires on non-literal commands); `pickle.loads(<var>)`;
    `yaml.load(...)` without `SafeLoader`.
  - **secrets:** inline GCP service-account JSON (matched by
    `"type":"service_account"`); AWS access-key ID literal
    (`AKIA[A-Z0-9]{16}` shape); Slack incoming-webhook URL literal;
    PEM-encoded private-key block literal.
  - **crypto** (new file `rules/crypto.yaml`): `hashlib.md5` /
    `hashlib.sha1` called on a password-shaped variable;
    legacy/broken symmetric cipher imports (DES, 3DES, RC4, ARC2,
    Blowfish from `Crypto.Cipher`); `random` module used inside a
    function whose name suggests token/password/nonce generation.

  Every rule carries `metadata.category`, `metadata.fendix_severity`,
  `metadata.confidence`, `metadata.cwe`, and a comment explaining its
  FP/FN class. A new YAML-only catalog test
  (`scanner_rulepack_test.go`) enforces these invariants — including
  the LOW-confidence/MEDIUM-severity-cap rule documented in
  `docs/semgrep-rules.md` — so subsequent rule additions can't drift
  the metadata schema silently. A separate
  `TestRulepack_ValidatesViaSemgrepCLI` runs `semgrep --validate`
  against the bundled pack when semgrep is on PATH (skipped
  otherwise), catching pattern-syntax errors the YAML catalog can't
  see. Closes audit §15.1 ("embedded semgrep rule pack is very
  small").

#### Fixed

- **Documentation drift in `docs/semgrep-rules.md` and README** (also
  Sprint 18, surfaced by the rule-pack work). Both documents still
  referenced `python/rules/` and
  `python/analyzers/semgrep_runner.py` from before TASK-116 migrated
  the Semgrep runner to native Go (`go/internal/scanner/semgrep/`).
  Updated all paths, the worked-example source links, and the
  "Adding a rule" workflow to match the post-migration reality. The
  legacy quick reference `semgrep --config python/rules/ --validate`
  is now `semgrep --config go/internal/scanner/semgrep/rules/
  --validate`.

- **Pre-existing YAML quoting in `auth.yaml`'s
  `python-jwt-decode-no-verification` rule.** The patterns embedded
  `{"verify_signature": False, ...}` unquoted, which strict YAML
  parsers (`gopkg.in/yaml.v3`, `ruamel-yaml --rt`) reject with
  "mapping values are not allowed in this context." Semgrep itself
  tolerated the loose form, so the bug had no scan-time effect, but
  Sprint 18's new YAML-only catalog test surfaced it. Patterns are
  now single-quoted; the rule's behaviour is unchanged.

### v0.11.1 — Phase 1 trust fixes (Sprints 01–03)

#### Fixed

- **pip-audit naming gap (Sprint 01).** The Python dep-CVE scanner has
  always been a direct OSV.dev `/v1/query` REST client, but its package
  doc and surrounding comments described it as "pip-audit parity," which
  was the kind of claim/implementation drift an external evaluator
  reasonably loses trust over. The package doc, log messages, and inline
  comments now state the implementation honestly: native code talks to
  OSV.dev; behavioural parity with pip-audit (same advisory sources,
  same finding shape) is preserved but the *tool* shown to users is no
  longer misnamed. Closes audit §15.5.

#### Added

- **`--use-pip-audit` flag on `fendix scan` (Sprint 01).** Opt in to
  shell out to the actual pip-audit binary instead of the native
  OSV.dev client. The flag honours the same recursive walk
  (`pip.DefaultRecurseDepth=3`) so multi-service repos still see every
  manifest. Falls back to OSV.dev with a stderr warning if pip-audit is
  not on PATH — never fails-closed silently. Targets pip-audit ≥ 2.7.0
  JSON schema; older versions produce a clear "upgrade pip-audit"
  error. Eight new tests exercise the subprocess + fallback paths
  (`TestScanViaSubprocess_*`, `TestParsePipAuditJSON_*`).

#### Performance

- **OSV.dev `/v1/querybatch` for pip dep-CVE scans (Sprint 02).** The
  pip dep-CVE path no longer queries OSV.dev one package at a time. It
  collects every (package, manifest) pair across discovered manifests,
  serves cache hits inline, then chunks cache misses into batches of up
  to 100 packages and runs up to 4 batch requests in flight. On a 150
  pinned-deps fixture with simulated 50ms-per-`/v1/query` and
  100ms-per-`/v1/querybatch` RTT, the batch path is **62× faster**
  (~7.8s → ~0.13s) — comfortably above Sprint 02's 4× gate. The serial
  per-package fallback is preserved and kicks in automatically on any
  batch-level failure (non-2xx, length mismatch, transport error) so a
  /v1/querybatch outage cannot hide CVEs.

  Known trade-off: OSV.dev's `/v1/querybatch` response shape includes
  vuln IDs but NOT aliases, so batch-path findings carry only an
  OSV-id reference; CVE-* aliases that the per-package `/v1/query`
  path includes are deferred to Sprint 02.6 (alias hydration via
  `GET /v1/vulns/{id}`). The serial fallback path preserves alias
  coverage for any chunk that hits it. Closes audit §15.4 ("OSV.dev
  rate limiting / outage" → first thing to break under enterprise
  load).

  Promotes `golang.org/x/sync` from indirect to direct dependency
  (already transitively present via `golang.org/x/vuln`; `go.sum`
  unchanged). No new CGo. No new external deps.

- **OSV.dev `/v1/querybatch` for npm dep-CVE scans (Sprint 02.5).**
  Mirrors Sprint 02's pip work into the npm scanner: `npm.Scan` now
  collects all (package, version) pairs from `package-lock.json`,
  serves cache hits inline, and chunks cache misses into batches of up
  to 100 packages with up to 4 batch requests in flight. On a 150
  resolved-deps fixture with the same simulated RTT as Sprint 02
  (50ms /v1/query, 100ms /v1/querybatch), the batch path is **~62×
  faster** (~7.87s → ~0.13s), comfortably above the 4× gate. Serial
  per-package fallback kicks in automatically on any batch-level
  failure so a /v1/querybatch outage cannot hide npm CVEs.

  Same alias trade-off as the pip path: batch findings carry the
  OSV-id; CVE-* alias hydration is folded into Sprint 02.6.

  Public surface of `npm.Scan` is unchanged — same signature, same
  sentinel errors (`ErrNoLockfile`,
  `ErrLockfileMissingButPackageJsonPresent`), same Finding shape. The
  orchestrator and `fendix verify` integration paths see no behaviour
  change beyond the speedup.

#### Changed

- **`fendix verify` exit codes are now CI-script-friendly (Sprint 03).**
  Previously verify always exited 0; CI scripts that wanted to fail the
  build on still-present findings had to parse JSON output. New mapping:
  - **0** — finding is resolved
  - **1** — finding is still present (CI should fail the build)
  - **2** — verify could not produce a confident result (unknown shape,
    not in baseline, or correlated/active-probe finding that needs a
    full re-scan to verify)

  This is a behaviour change for any CI pipeline that previously relied
  on `fendix verify ... && rest-of-pipeline` (which always succeeded);
  those pipelines now correctly fail the build when the finding is
  still present, which is what they wanted. The new internal package
  `internal/cli` carries the `*ExitError` type; `main.go` honours it
  via `errors.As` before the generic exit-2 path.

- **`fendix verify` correlated findings now return an honest "unknown"
  with a workaround.** Pre-Sprint-03, a correlated finding with a URL
  endpoint was routed through the URL-shape verifier, which would
  re-test ONE side of the correlation and report "still-present" or
  "resolved" based on a single side's verdict — incorrect in principle
  because re-testing one side cannot confirm a correlation still
  holds. The `Run` dispatcher now gates `Source==correlated` BEFORE
  the shape switch and returns Status=unknown with an explanation
  pointing at the workaround (re-run the full scan and diff). Closes
  audit §7.

- **`fendix verify --help` now lists supported and unsupported finding
  shapes explicitly**, plus the new exit-code table. Correlated and
  active-probe findings are documented as MVP-deferred.

### Engine UX gaps surfaced by the TwiScope-backend e2e scan (2026-05-14)

Three real product gaps the TwiScope scan exposed; each fixed in
lockstep with a unit test. See `docs/accuracy.md` Track 4 §9.

- **Gap 1 — pip-audit now walks subdirectories.** Previously, the
  pip scanner only checked `<code-path>/requirements.txt` and
  silently skipped multi-service monorepos. On TwiScope-backend
  this hid 8 dep-CVEs (7× `cryptography==41.0.7` + 1×
  `python-dotenv==1.0.1`) because the manifests lived at
  `Twiscope_Main_App/requirements.txt` etc., not the repo root.
  New `pip.ScanRecursive(ctx, root, depth)` walks up to depth=3
  (`pip.DefaultRecurseDepth`) and stamps the relative manifest
  path on each finding's endpoint so users can tell which service
  owns each CVE. Skips vendored/cache dirs (`.venv`, `venv`,
  `node_modules`, `.git`, `site-packages`, `__pycache__`, `.tox`,
  `.mypy_cache`, `.pytest_cache`, `build`, `dist`) at any depth.
  Orchestrator switched from `pip.Scan` to `pip.ScanRecursive`;
  5 new Go tests (`TestFindRequirementsManifests_*`,
  `TestScanRecursive_*`).

- **Gap 3 — auth-probe suppresses JWT-bypass FPs on fully-public
  endpoints.** Previously, a public endpoint like Prometheus
  `/metrics` (returns 200 to no-auth + 200 to garbage Bearer
  values) generated 4 CRITICAL findings: `Missing authentication
  on endpoint` PLUS `JWT not validated`, `Expired JWT accepted`,
  `JWT algorithm confusion (alg:none accepted)` — but the latter
  three were all downstream byproducts of the same root cause.
  TwiScope-backend's `/metrics` scan produced exactly this 4-CRIT
  cluster where only 1 finding was actionable.

  New posture in `internal/scanner/auth.go::CheckAuth`: when
  `Missing authentication on endpoint` fires AND a follow-up
  probe with a deliberately-garbage Authorization header
  (`Bearer fendix-auth-probe-not-a-real-token`) also returns 2xx,
  the endpoint is fully unauthenticated — suppress the JWT-bypass
  probes for THAT endpoint. The conservative two-probe gate means
  endpoints that DO require a header but fail to validate it
  (the legitimate JWT-bypass shape) still emit all relevant
  findings unchanged.

  Two new unit tests:
  `TestCheckAuth_PublicEndpointEmitsOnlyMissingAuth` (asserts the
  4→1 collapse on a public endpoint) and
  `TestCheckAuth_JWTBypassEndpointEmitsAllJWTFindings` (asserts
  the JWT findings still fire on a header-checks-only server).
  Two pre-existing tests updated:
  `TestCheckAuth_{Malformed,Expired,AlgNone}_Vulnerable` now use
  `newJWTOnlyServer()` instead of `newAuthTestServer("", true)`,
  exercising the real JWT-bypass surface where the FP-dedup
  doesn't kick in.

  Verified end-to-end against TwiScope-backend `/metrics`:
  authenticated DAST went from 10 findings (4 auth_bypass, 4 MED,
  2 INFO) to **7 findings (1 auth_bypass, 4 MED, 2 INFO)** — the
  one real CRITICAL preserved, the 3 derivative FPs gone.

- **Gap 2 — `fendix verify <id>` shipped (was a Phase-4 stub).**
  Previously the subcommand was documented in `fendix --help`
  but printed `verify: not yet implemented (Phase 4)`. Now reads
  a baseline `findings.json` (saved from a prior scan), locates
  the requested finding, and re-tests just that one against the
  current state. Three finding shapes covered in the MVP:
  - URL-anchored (DAST): re-issues the request with same auth and
    re-applies the per-title check (missing headers, permissive
    CORS, version disclosure, missing-authentication, software-
    version-in-body). Status reasoning is per-check, not generic.
  - File-anchored secrets (`category=secrets`): re-runs the native
    secrets scanner against the file's directory and looks for the
    same title at the same path.
  - Dep-CVE (`category=deps`): re-runs `pip.Scan` / `npm.Scan`
    against the manifest's directory and matches by ID tail.
  CLI: `fendix verify <id> --baseline findings.json --url <base>
  [--code <root>] [--auth "Bearer ..."] [--json]`. Returns
  `still-present` / `resolved` / `unknown` / `not-found-in-baseline`.
  Verified end-to-end against TwiScope-backend: `SEC-002`
  (missing CSP) → `still-present`, `SEC-009` (missing auth on
  `/metrics`) → `still-present` with the correct evidence string.
  New `internal/verifycmd/` package (~470 LOC) + 12 unit tests.

### Engine quality lift driven by Track 4 heavy-eval (2026-05-14)

**Headline:** the v0.11.0 "Track 4" evaluation surfaced 7 real engine
gaps that the synthetic Track 1 corpus couldn't see (because Track 1
was built around the canonical shapes the engine was originally
designed for). All 7 are fixed in lockstep; Track 4a F1 moved from
**0.921 → 0.987** (95% bootstrap CI **[0.953, 1.000]**), Track 4b
expectation-recall from **0.938 → 1.000**, Track 4c from "5/5 with
silent-deps-skip caveat" to **8/8 with operator-visible advisory**.

#### Eval rigor (Phase 1)

- SHA-pinned every CVE-anchored repo in `scripts/heavy-eval/corpus.py`
  (10 repos captured 2026-05-14; reruns are now bit-identical, not
  HEAD-drift-dependent).
- Per-CWE roll-up added to the category-count scorer
  (`scripts/heavy-eval/score.py`): every label expectation carries a
  `cwe:` tag; the scorer aggregates hit/miss per CWE for honest
  cross-category breakdown.
- Bootstrap 95% CI on Track 4a F1 — 1000 iterations, fixed seed, see
  `_bootstrap_f1_ci` in `score.py`.
- External bandit-`examples/` cross-validator added as `bandit-examples`
  target (91 files, SHA-pinned at `8309bc39`). NIST SARD has no
  Python suite; bandit's maintainer-curated corpus is the closest
  authoritative ground truth for Python SAST.
- New `.github/workflows/heavy-eval.yml` runs the SAST sweep on
  every PR; new `scripts/heavy-eval/gate.py` gates CI on
  F1 ≥ 0.95, bandit-recall ≥ 0.95, aggregate-real-repo-recall ≥ 0.95.

#### Engine fixes (Phase 2)

- **SSRF: `urllib.request.urlopen` / `urlretrieve` / `six.moves.urllib.*`
  added as sinks.** Pre-fix the AST analyser only matched
  `requests.<method>()`. New helper `_ssrf_sink_name` resolves the
  attribute chain; constant-arg suppression parity preserved.
  4 new unit tests in `test_ast_analyzer.py::TestSSRF`.
- **Whitelist-via-dict-lookup recognised as a sanitiser.**
  `<const_dict>.get(name)` / `<const_dict>[name]` now suppresses
  reachable findings when the dict resolves to a literal collection
  in scope.
- **Whitelist-via-set-membership guard recognised as a sanitiser.**
  `if name not in <const_collection>: return/raise/abort` followed by
  use of `name` is treated as constrained. The pass walks the
  enclosing FunctionDef for guards; heuristic but precise.
- **BinOp-aware sanitiser propagation.** `requests.get(allowed.get(t) + "/p")`
  recursively checks every BinOp operand. Closed the last SSRF FP on
  the corpus.
- **AWS secret-key regex accepts short prefix.** Pre-fix required
  `aws...secret...key` together; production code often writes
  `aws_secret = "<40-char>"`. Relaxed prefix to
  `aws[_\-\s]*secret(?:[_\-\s]*(?:access[_\-\s]*)?key)?` while
  keeping the 40-char base64 value shape (FP guard). 4 new test
  sub-cases.
- **Django ORM raw-SQL sinks added (bandit B610/B611 parity).**
  `<qs>.raw(<non-literal>)`, `<qs>.extra(where=[non-literal], …)`,
  `RawSQL(<non-literal>, …)` now flag under `SEC-PY_SQL_INJECTION`.
  Closed the PyGoat-SQLi miss that Track 3 had silently accepted.
  7 new unit tests in `test_ast_analyzer.py::TestDjangoORMSQLInjection`.
- **`os.popen2 / popen3 / popen4` added as cmdi sinks.** Deprecated
  but real in legacy Python-2 code paths; surfaced by bandit's
  `examples/os-popen.py`. 1 new parametric test covering all 3 variants.
- **npm-audit emits INFO advisory when `package-lock.json` missing.**
  Pre-fix the scanner silently skipped; many vulnerable-app OSS
  repos ship only `package.json`. New sentinel
  `ErrLockfileMissingButPackageJsonPresent` + orchestrator emits
  `SEC-NPM_LOCKFILE_MISSING` pointing the user at `npm install`.
  1 new test in `internal/scanner/deps/npm/scanner_test.go`.

#### Test counts

- Python: 168 → **180 passed** (12 net new tests).
- Go: existing suite green; 2 new tests
  (`TestScan_AWSSecretShortPrefix`, `TestScan_PackageJsonNoLock_ReturnsAdvisoryError`).

## [0.11.0] - 2026-05-13

**Headline:** FP discipline round 2 + a seventh reachable sink class.
Phase 17d (P7 Engine-first v0.11) ships five tasks that close the
engine-first roadmap: re-triaged the existing FP corpus through the
post-Phase-17a lens (TASK-132); added a native-Go exposed-config-file
detector that inverts the noisy `missing-CSP-on-/.env` story into one
CRITICAL "exposed config file" finding (TASK-133); added path-
traversal as the seventh reachable taint-chain sink class (TASK-134);
shipped `fendix ignore list / validate / prune` so suppression
bookkeeping is no longer write-once / pile-up-forever (TASK-135);
refreshed the cold-start benchmark numbers and showed the new
detection paths cost no more than the noise floor on default-mode
scans (TASK-136).

Plus one pre-existing-bug fix surfaced during TASK-134's end-to-end
validation: the Python spawner's `engineDir` could resolve to a
doubled relative path (`python/python/engine.py`) when the local
fallback was used. Latent since TASK-118 made the relative-path
branch the default-non-embedded path; fixed by `filepath.Abs` before
spawn.

This release folds 5 tasks (TASK-132/133/134/135/136) plus the
spawner fix into a single minor release. Phase 17d is 5/5 complete.
The engine-first roadmap (`docs/quarter_plan.md` Phase 17a→17d) is
now done; next-planned work is Cloud Q1 (Stripe + AI explanation
from `docs/example_plan.md`).

### Added

- **TASK-133 — exposed-config-file detection** (`internal/scanner/configleak.go`,
  ~280 LOC). New `CheckConfigLeak` worker-pool scanner: 27 basename-
  exact patterns covering env files, web-server config (.htaccess,
  .htpasswd, web.config), package-manager creds (.npmrc, .pypirc,
  .netrc), Docker, IDE/OS leftovers; 5 prefix patterns for directory-
  style leaks (.git/, .aws/, .ssh/, .idea/, .vscode/). Fires CRITICAL
  with CWE-538 on any 2xx response to a known config-file path.
  Body sample (capped 512 bytes) gets `[REDACTED]` masking of common
  secret-shape tokens before landing in evidence — no engine leak
  of leaked credentials. 9 race-clean unit tests.

- **TASK-134 — path-traversal reachable taint chains** (`python/analyzers/ast_analyzer.py`).
  New `SEC-PY_PATH_TRAVERSAL` finding (CWE-22, HIGH severity, MEDIUM
  confidence, category=injection). Four filesystem-path sinks:
  `open(x)`, `Path(x)` / `pathlib.Path(x)`, `send_file(x)`,
  `send_from_directory(safe_dir, x)` (user-controlled arg at index
  1 — handled in `_path_traversal_arg_index`). When user input flows
  to the path argument, `_collect_taint_chain` records the chain and
  sets `reachable: true`; correlator escalation (TASK-114) and step
  5.4 escalation (TASK-125) both apply. Brings the engine's reachable
  sink categories to **7** across SQLi / SSRF / open-redirect / XSS
  / cmd-injection / now path-traversal. 9 new Python tests.

- **TASK-135 — `fendix ignore` subcommand tree** (`internal/ignorecmd/`,
  ~300 LOC). Three subcommands close the "I have 30 ignore rules
  accumulated over a year and no way to see what's still useful" gap:
  `fendix ignore list` renders a tabular view of all rules with
  EXPIRED / expiring-soon (within 30 days) / active / no-expiry /
  INVALID-DATE status; `fendix ignore validate` reports schema and
  date errors with non-zero exit for CI gating; `fendix ignore
  prune [--dry-run]` removes expired rules and rewrites the file
  (preserves rules with invalid dates — `validate` surfaces those).
  All three default to `.fendix-ignore` in cwd; `--file <path>`
  targets a different file. 14 race-clean unit tests.

### Documented

- **TASK-132 — FP corpus re-triage.** `tasks/FP_CORPUS.md` extended
  with a "2026-05-13 (Phase 17d, synthetic input)" addendum
  recording which corpus patterns are now addressed (P1/P2/P3/P4
  all closed by Phase 17a's TASK-105/123/124) and which deferred
  follow-ups landed in TASK-133 vs got deferred to a future round
  with real post-launch data (D1 SPA-fallback dedup deferred; D2
  dotfile-config-leak shipped).

- **TASK-136 — cold-start benchmark refresh.** `docs/benchmarks.md`
  "Cold-start latency" section rewritten with the v0.11 row added
  and a v0.9 → v0.11 delta column. Default v0.11 = 6.1 ms p50
  (+0.5 ms vs v0.9, within noise — configleak doesn't run with
  zero endpoints discovered); `--python-engine` v0.11 = 40.7 ms p50
  (+16.3 ms vs v0.9 — real cost of TASK-134's path-traversal sink
  in the AST analyzer). Phase 17b's <500 ms exit gate still
  cleared by 82× on default / 12× on opt-in. Default v0.11 is
  still 16 % faster than v0.8.0 (pre-Phase-17b).

### Fixed

- **Spawner double-relative-path bug** (`internal/engine/spawner.go`).
  Latent since TASK-118: when `engineDir` was the relative local
  fallback `python`, `cmd.Dir = engineDir` + relative `enginePath`
  composed to `python/python/engine.py` in the child's working dir,
  causing exit 2 on every `--python-engine` invocation that didn't
  set `FENDIX_ENGINE` explicitly. Surfaced during TASK-134's
  end-to-end validation. Fixed by resolving via `filepath.Abs`
  before composing the script path or setting `cmd.Dir`.

## [0.10.0] - 2026-05-13

**Headline:** the plugin ecosystem is genuinely usable now. Phase 17c
(P7 Engine-first v0.10) ships four tasks that turn the plugin system
from "exists" into "a third party can ship a plugin against an
installed binary in 60 seconds." The wire contract from TASK-113
(v0.7) is unchanged; what changed is the surface around it —
external-author docs, two new reference plugins in Node + Ruby
proving the contract is language-agnostic, a `fendix plugins`
CLI subcommand tree, and a CI smoke test that catches wire-contract
regressions automatically.

This release folds 4 tasks (TASK-128/129/130/131) into a single
minor release. Phase 17c is 4/4 complete.

### Added

- **TASK-128 — `docs/plugins.md` rewritten for external authors.**
  Restructured around the outside-contributor audience: 60-second
  copy-paste quickstart (TODO-finder, ~30 LOC) before any conceptual
  content; new "How plugins fit into a scan" pipeline diagram
  showing where plugins (step 4.5) sit in the orchestrator;
  Python / Node / Bash skeleton entrypoints; "Testing your plugin
  locally" section with smoke-test recipes inside and outside the
  engine; "Common errors" 8-row diagnosis table; "Distributing your
  plugin" covering both `git clone` and the new `fendix plugins
  install`; tightened security model with explicit auth-token
  handling guidance; authoring checklist expanded 8 → 13 items.
  ~580 LOC total.

- **TASK-129 — two new reference plugins in non-Go languages.**
  `examples/plugins/license-header-check/` (Node, stdlib-only,
  ~150 LOC): walks the source tree, flags files lacking an
  `SPDX-License-Identifier` header in the first 30 lines.
  Configurable via `FENDIX_LICENSE_HEADER_REGEX`.
  `examples/plugins/dockerfile-best-practices/` (Ruby, stdlib-only,
  ~210 LOC): walks for `Dockerfile` / `Dockerfile.*`, emits up to 5
  distinct findings per file (`:latest` tag, `curl | sh`,
  `ADD <url>`, root-by-default, missing HEALTHCHECK) with CWE refs.
  Both plugins ship with a README. Reference-plugin shelf in
  `docs/plugins.md` updated 3 → 5 plugins; language spread is now
  Python ×2, Bash ×1, Node ×1, Ruby ×1.

- **TASK-130 — `fendix plugins list` + `fendix plugins install`
  CLI.** New `internal/pluginscmd/` package (~280 LOC) and
  `fendix plugins` cobra subcommand tree. `fendix plugins list`
  enumerates discovered plugins (NAME / VERSION / MODE / DIR) using
  the same discovery roots a real scan uses, so what's printed is
  exactly what would run. `fendix plugins install <git-url>` is a
  thin wrapper over `git clone --depth=1`: derives the on-disk
  name from the URL, refuses to overwrite preexisting directories,
  validates the cloned tree's `plugin.yaml` after clone, and
  removes the directory on validation failure so you never end up
  with a half-installed plugin that WARNs every scan. URL-to-name
  derivation handles `.git` suffix, scp-style `git@host:org/repo`,
  query strings, and trailing slashes. **Folded in the symlink-
  discovery fix from TASK-127's audit**: plugin discovery now
  `os.Stat`s each entry before `IsDir()`-checking, so symlinked
  plugin dirs (`ln -s ../my-plugin .fendix/plugins/`) work too.

- **TASK-131 — plugin smoke test in CI.** New
  `internal/e2e/refplugins_test.go` (build-tag `e2e`, ~330 LOC)
  under the existing `make e2e` umbrella. One subtest per
  reference plugin (5 total) that copies the plugin into a temp
  scan root, runs `fendix scan` against a deterministic fixture,
  and asserts the expected findings flow through with the
  engine-attached `fendix-plugin:<name>` provenance tag. Each
  subtest skips cleanly when its required runtime (node, ruby,
  python3, bash + jq) isn't installed on the CI runner — so the
  test still passes on minimal images while exercising every
  plugin on full ones. Catches wire-contract regressions: anything
  that breaks `orchestrator.runPlugins`, NDJSON terminator
  parsing, finding validation, or provenance attachment will fail
  this test on every PR.

## [0.9.1] - 2026-05-13

**Patch.** v0.9.0 introduced a regression: every `fendix scan` invocation
emitted `WARN python engine not available — whitebox scanning disabled`
even when `--python-engine` was not set. With TASK-118 dropping the
embedded Python distribution, `EnsureEngine()` now always fails for
users without a local `python/` source tree, but `NewOrchestrator` was
calling it eagerly regardless of the flag — so the WARN spammed every
scan and contradicted v0.9's "no Python required by default" promise at
the log level. Fixed by gating the `EnsureEngine` resolution on
`cfg.PythonEngine`. Caught while validating that every command example
on the `/docs/getting-started` page actually works against the v0.9
binary; all 14 examples now run cleanly with no spurious WARN.

### Fixed

- **Spurious `python engine not available` WARN on every scan.**
  `internal/engine/orchestrator.go::NewOrchestrator` now skips the
  `EnsureEngine` call entirely when `--python-engine` is off (the
  default). Previously it ran on every orchestrator construction and
  logged a misleading WARN for users who had no intention of using the
  Python whitebox engine.

## [0.9.0] - 2026-05-13

**Headline:** cold-start under 6 ms, no Python required. Phase 17b
(P7 Engine-first v0.9) ships four tasks that move the engine off
embedded Python entirely: secrets detection ported to native Go
(TASK-115), Semgrep shelled-out instead of embedded (TASK-116), the
embedded Python distribution removed from the binary with a published
cold-start benchmark (TASK-118), and a plugin wire-contract
compatibility audit confirming the v0.7-era plugin ecosystem still
works (TASK-127). Default cold start = 5.6 ms p50 (was 7.3 ms on v0.8
— 23 % faster); `--python-engine` opt-in for users who still want the
Python `auth` / `injection` / `deps` checks. Phase 17b exit gate
(<500 ms p50) cleared by ~89×. fendix no longer carries a Python
interpreter requirement at all in the default scan path.

This release folds 4 tasks (TASK-115/116/118/127) into a single
minor release. Phase 17b is 4/4 complete.

### Removed

- **TASK-118 — embedded Python distribution dropped from binary.** The
  `Makefile`'s `embed-engine` target no longer copies `python/` into
  `go/internal/embedded/engine/`; the binary's `//go:embed` directive
  now bundles only a placeholder. The redundant Python wrappers
  `python/analyzers/secrets.py` and `python/analyzers/semgrep_runner.py`
  (and their test files) were deleted — the native Go scanners from
  TASK-115 + TASK-116 cover the same surface. Python whitebox spawning
  (auth / injection / deps checks) is now opt-in via a new
  `--python-engine` CLI flag, requires a local `python/` source tree
  (or explicit `FENDIX_ENGINE` env var), and is silently skipped when
  no Python engine is resolvable. **Cold-start benchmark** captured in
  `docs/benchmarks.md`: default v0.9 = **5.6 ms p50** (was 7.3 ms on
  v0.8 — 23 % faster) on a tiny fixture; opt-in `--python-engine` =
  **24.4 ms p50** (4.4× the default — that gap is the actual cost of
  Python interpreter startup + engine extraction we removed).
  **Phase 17b exit gate (<500 ms p50) cleared by ~89×.** New
  reproduction script at `scripts/bench/coldstart.py`. Binary size:
  -99 KB (-0.5 %); the real win is the dependency posture — fendix no
  longer carries a Python interpreter requirement at all in the
  default path.

### Added

- **TASK-127 — plugin wire-contract compatibility audit.** All three
  reference plugins (`custom-secret-pattern`, `custom-blackbox-check`,
  `custom-semgrep-pack`) re-verified end-to-end against the
  TASK-118 binary: discovery works, NDJSON in/out works, findings
  flow through the correlation + dedup pipeline unchanged. Plugins do
  not depend on `embedded.HasEngine()`, the extracted
  `~/.fendix/engine/` tree, or `--python-engine` being set. Pre-
  existing discovery limitation surfaced and documented:
  `os.ReadDir().IsDir()` returns false for symlinked plugin
  directories, so plugins must be installed as real directories
  (`cp -R` / `git clone`, not `ln -s`). Documented in `docs/plugins.md`.
  **Phase 17b: 4/4 complete; v0.9.0 ready to tag.**

- **TASK-116 — Semgrep shelled-out, not embedded.** New
  `internal/scanner/semgrep/` package wraps the host's installed
  `semgrep` binary instead of running it through the embedded Python
  engine. The fendix rule pack (`auth.yaml`, `injection.yaml`,
  `secrets.yaml`, identical bytes to `python/rules/`) is bundled into
  the Go binary via `//go:embed` and extracted to a per-process temp
  dir on first scan. `semgrep --config <tmpdir> --json --no-git-ignore
  --quiet <codePath>` runs as a subprocess with a 120 s default
  deadline (layered onto the caller's `ctx`); cancellation kills the
  child. Result mapping mirrors the Python wrapper byte-for-byte:
  `SEC-<RULE_ID>` IDs (uppercased, `-`/`.` → `_`), `metadata.fendix_severity`
  preferred over Semgrep's ERROR/WARNING/INFO mapping, `metadata.confidence`
  / `metadata.category` / `metadata.cwe` propagated, evidence truncated
  at 200 chars, title at 120. Graceful absence: `exec.LookPath("semgrep")`
  failure returns `ErrSemgrepUnavailable` and the orchestrator logs an
  install hint and continues. Non-fatal exit codes (1 for matches, 2/5/7
  for rule-parse errors that still emit valid JSON) are absorbed in
  parity with the Python wrapper. Wired into orchestrator step 3.7
  (after secrets, before Python spawn). `semgrep` removed from default
  Python checks list. End-to-end verified locally: with semgrep absent
  the orchestrator emits the install hint and continues; with semgrep
  present (1.162.0 in a temp venv) Go and Python wrappers agree on the
  same fixture (zero findings — pre-existing rules issue affects both
  wrappers identically). 28 race-clean unit tests cover mapping,
  graceful absence, ctx cancellation, fake-semgrep happy path, and rule
  embedding extraction. **Phase 17b: 2/4 complete.**

- **TASK-115 — native Go secrets scanner.** New `internal/scanner/secrets/`
  package ports `python/analyzers/secrets.py` to Go in-process: all 15
  patterns (7 generic + 8 provider-specific) plus the `.env`-only
  `ENV_SECRET` regex, walker with skip-dirs / size cap / minified-JS
  detection, and evidence truncation. Same `SEC-<PATTERN_ID>` finding
  IDs as the Python implementation so any overlap dedupes cleanly. Go
  RE2 lookarounds are handled by a per-pattern `boundaryOK` post-match
  validator (Python's `(?<![A-Za-z0-9])` etc. don't compile in RE2).
  Wired into the orchestrator as step 3.6 (between native deps scanners
  and Python spawn). `secrets` is removed from the Python default check
  list — users can still opt in via `--checks secrets`. Real-world
  parity verified against the Python fixture suite: 30 unique
  (title, endpoint) tuples emitted by both engines, set-diff empty in
  both directions. **Phase 17b: 1/4 complete.**

## [0.8.0] - 2026-05-12

**Headline:** detection depth + FP discipline. Phase 17a (P7 Engine-first
v0.8) ships eight tasks across two workstreams: (1) detection breadth —
native dep-CVE scanners in Go, two new reachability patterns (XSS sinks,
command-injection sinks), and a severity-scoring refresh with a
`reachable_code` multiplier; (2) FP reduction — a real FP corpus (35
instances, 4 root-cause patterns), two deterministic gates (4xx-response
skip, static-file path regex), and one-click suppression snippets in PR
comments. ADR-008 formalises the read-only AI boundary that governs all
future AI work: explanation + fix-as-text permitted in the cloud backend;
auto-PR and OSS-engine LLM calls permanently forbidden.

This release folds 10 commits since v0.7.0 across Phase 17a (TASK-119
through TASK-126). Phase 17a is 8/8 complete.

### Added

- **Native dep-CVE scanners: govulncheck / pip-audit / npm-audit in Go
  (TASK-119).** Three new packages under `internal/scanner/deps/`:
  `govulncheck` (uses `golang.org/x/vuln/scan` in-process with call-graph
  reachability — only reports vulnerabilities in code paths actually
  called), `pip` (queries OSV.dev `/v1/query` per pinned `==` dependency,
  24-hour cache at `~/.fendix/cache/osv-pypi/`), `npm` (parses
  `package-lock.json` v2/v3 transitive tree, queries OSV.dev npm ecosystem,
  24-hour cache at `~/.fendix/cache/osv-npm/`). All three behind
  `--no-native-deps` escape hatch. Phase 17b can drop the Python `deps.py`
  path without losing coverage.

- **XSS-sink reachability pattern (TASK-120).** Python AST analyzer gains
  three new sinks: `Markup(x)` / `flask.Markup(x)` / `markupsafe.Markup(x)`,
  `mark_safe(x)` / `django.utils.safestring.mark_safe(x)`, and
  `render_template_string(x)`. New finding `SEC-PY_XSS_HTML_SINK` (CWE-79,
  HIGH/MEDIUM). Taint chains emitted when input traces to a request source.
  9 new unit tests.

- **Command-injection-sink reachability pattern (TASK-121).** Existing
  `PY_OS_SYSTEM` and `PY_SUBPROCESS_SHELL` sinks now emit taint chains.
  New `PY_OS_POPEN` finding (CWE-78, HIGH/HIGH). Six reachable sink
  categories now ship: SQLi + SSRF + open-redirect (TASK-114), XSS
  (TASK-120), os.system / subprocess(shell=True) / os.popen (TASK-121).
  8 new unit tests.

- **FP corpus and root-cause catalog (TASK-122).** `scripts/fp-corpus/run.sh`
  runner; 35 false positives catalogued in `tasks/FP_CORPUS.md` across
  four patterns: P1 test-fixtures-as-prod (31 instances), P2 header/CORS
  check on 4xx (3), P3 rate-limit on static asset (1), P4 metrics endpoint
  (true positive). Satisfies Phase 17a exit gate of ≥15 real FPs.

- **FP-reduction gates (TASK-123).** Two deterministic skip rules: (1)
  `CheckHeaders` and `CheckCORS` early-return on response status ≥ 400; (2)
  `CheckRateLimit` early-returns for static-asset paths (`.css`, `.js`,
  `.woff2`, `robots.txt`, `sitemap.xml`, etc.). Both gates also eliminate
  probe cost for the skipped paths. 6 new tests.

- **One-click suppression snippet in PR comments (TASK-124).** Every
  finding in the GitHub App PR comment now ships with a fenced `.fendix-ignore`
  YAML snippet keyed on a stable `(title, category, endpoint)` hash.
  Stable across runs (SEC-NNN IDs reassign; the hash does not). 5 new
  tests in `internal/ghapp/comment_test.go`.

- **Severity scoring refresh — `reachable_code` multiplier (TASK-125).**
  New `ReachableMult = 1.5` in `scoring.go`. New
  `CalculateSeverityReachable` function; existing `CalculateSeverity` is a
  backwards-compatible wrapper. New orchestrator step 5.4
  `escalateNonCorrelatedReachable` bumps severity one level when
  `Reachable=true` and source is not `correlated`. Confidence cap (step 5.6)
  still applies. EPSS/KEV multipliers deferred to the cloud quarter. 8 new
  tests.

- **ADR-008: read-only AI permitted, auto-remediation permanently forbidden
  (TASK-126).** New `docs/adr/ADR-008-readonly-ai.md`. The boundary: AI
  finding explanation + fix suggestion as text delivered by the cloud backend
  is permitted and planned for Cloud Q1. Auto-PR generation, auto-merge, and
  any LLM calls from the OSS engine binary are permanently forbidden.
  BACKLOG-017 annotated with the partial supersession.

### Changed

- BACKLOG-017 in `tasks/PHASES.md`: the "AI-driven triage / LLM fix
  suggestions" entry now notes that read-only AI in the cloud backend is
  permitted per ADR-008; auto-PR / auto-merge / OSS-engine LLM calls remain
  forbidden.

## [0.7.0] - 2026-05-01

**Headline:** the wedge is now defensible. Phase 14 (P4 External
Wedge) closed end-to-end with the GitHub App business logic;
Phase 15 (P5 Open & Extensible) shipped open-source ratification
+ plugin system + reachability/dataflow correlation. The
correlator now distinguishes "DAST + SAST agreed" from "DAST +
SAST agreed AND we can prove the path" — the latter gets a
double severity escalation, which is what makes the wedge
defensible against vendor noise.

This release folds 8 commits since v0.6.1 (`5855dc4..1d739cf`):
TASK-106 numbers, TASK-107 GitHub App scaffold, TASK-107b GitHub
App business logic, TASK-108 `fendix demo`, TASK-109 `.fendix.yaml`
policy, TASK-112 ADR-007, TASK-113 plugin system, TASK-114
reachability. Also includes two MEMORY-only commits documenting
the frontend syncs along the way.

### Added

- **Phase 15 — Open & Extensible (v1.2). Three task ship: open-source
  posture, plugin system, reachability correlation.**

- **Open-source posture: ADR-007 ratifies MIT, single-repo, no
  open-core split (TASK-112).** Codifies what was previously a
  tactical choice (MIT in `LICENSE` since v0.1.0) as a deliberate
  strategic decision. README hero gains a fourth bullet "Open source
  under MIT — read the source, audit the wedge, fork it, ship
  plugins." CONTRIBUTING.md gains a "Licensing of contributions"
  section: by submitting a PR, contributors agree to MIT for their
  work; no CLA, no copyright assignment. Out-of-tree plugins choose
  their own license. ADR-007 documents the full rationale (rejected
  Apache 2.0, AGPL 3.0, dual-license, open-core).

- **Plugin system: out-of-tree extension via NDJSON IPC (TASK-113).**
  New `internal/plugin` package: `Discover` walks `<repo>/.fendix/
  plugins/` (repo-local, takes precedence) + `~/.fendix/plugins/`
  (user-global), parses each child's `plugin.yaml` with strict
  `KnownFields(true)`, validates name/entrypoint/mode/timeout, and
  returns plugins deduplicated by name. `(*Plugin).Run` invokes the
  entrypoint with a JSON `ScanRequest` on stdin and reads NDJSON
  Findings on stdout — same wire contract as the embedded Python
  engine (ADR-002). Per-plugin timeout (default 30s, max 5m) bounds
  wall-clock; partial findings before a kill or non-zero exit are
  preserved; plugins inherit `FENDIX_PLUGIN_NAME` + `FENDIX_PLUGIN_DIR`
  env vars; every emitted finding gets `fendix-plugin:<name>`
  appended to References for provenance. Plugin findings flow through
  the same Correlate / Dedup / Sort / ID-assignment pipeline as
  embedded engine findings. New `--no-plugins` CLI flag disables
  discovery for sandboxed CI or debugging. Three reference plugins
  under `examples/plugins/`: `custom-secret-pattern` (Python, custom
  regex over source), `custom-blackbox-check` (Python, custom
  HTTP-response assertion), `custom-semgrep-pack` (shell, wraps a
  custom Semgrep rule pack). Author guide: `docs/plugins.md` covers
  discovery, IPC schema, reference plugins, security model, and an
  authoring checklist. 12 unit tests in `internal/plugin/plugin_test.go`
  (race-clean) covering discovery, manifest parsing, validation,
  shadow precedence, happy-path Run, mode-tagged source attribution,
  error terminator, non-zero-exit-retains-partial-findings, prompt
  timeout, malformed-line tolerance, DefaultRoots ordering.

- **Reachability/dataflow correlation: `correlated:reachable` for
  proven exploit paths (TASK-114).** The Python AST analyzer records
  taint chains for SQLi, SSRF, and open-redirect findings: when
  `_collect_taint_chain` proves intra-function dataflow from a
  request source (`request.args/POST/form/data/json/headers` plus
  the Flask handler-arg form `req`) to the dangerous sink, the
  emitted finding carries `taint_chain: [{file, line, expr}, …]`
  plus `reachable: true`. The chain walks recursively through
  scope assignments, so `q = request.args.get('q'); sql = '...' + q;
  cursor.execute(sql)` resolves three links without false positives
  on literal-only chains. Models gain `TaintLink` struct +
  `TaintChain []TaintLink` and `Reachable bool` on Finding (both
  `omitempty`). Correlator's `mergeFindings` propagates chain +
  Reachable from whitebox to merged correlated finding AND applies
  a *second* severity escalation when reachable — so a MEDIUM
  blackbox finding plus a MEDIUM whitebox finding plus reachability
  jumps to CRITICAL (vs HIGH without reachability). HTML reporter
  renders the chain as an ordered list
  ("Reachable dataflow (N steps)"). 5 new Python AST tests + 3 new
  Go correlator tests + 1 new e2e regression
  (`TestReachable_HybridScanProducesReachableCorrelated`) asserting
  a real hybrid scan emits ≥1 finding with `taint_chain` referencing
  `request.args` alongside ≥1 correlated finding.

- **GitHub App: clone + scan + PR comment + SARIF upload (TASK-107b).**
  Wires the business-logic layer on top of the v0.6.1 scaffold. On
  every `pull_request.{opened,synchronize,reopened}` event, the
  webhook handler now: (1) fetches an installation token via
  `TokenSource` (cached + single-flighted as before); (2) clones the
  PR head SHA into a per-scan tempdir using `git init` + shallow
  `fetch --depth=1 origin <sha>` + `checkout FETCH_HEAD` — only the
  exact commit, no history; auth via `x-access-token:<token>@…`
  userinfo on the HTTPS clone URL; (3) runs `fendix scan --code
  <tmp> --format json --output findings.json`; (4) re-renders SARIF
  via `fendix report --format sarif` so the PR comment + Code
  Scanning tab describe identical findings; (5) renders a Markdown
  PR comment matching the github-script template from
  `examples/github-actions/fendix-scan.yml` (TASK-098) byte-for-byte
  modulo whitespace, so users see the same output regardless of
  installation path; (6) POSTs the comment via the Issues API
  (`/repos/{o}/{r}/issues/{n}/comments`); (7) gzip+base64-encodes
  the SARIF and uploads via the Code Scanning Sarifs API
  (`/repos/{o}/{r}/code-scanning/sarifs`) against
  `refs/pull/<n>/head`. SARIF upload is best-effort: a misconfigured
  repo (Code Scanning disabled, missing `security_events: write`)
  logs a warning but the PR comment still posts. **Check-run re-run
  support:** `check_run.action == "rerequested"` re-runs the scan
  against the recorded head SHA; other check_run actions (created,
  completed) silently ack. **Tempdir always cleaned up via
  `defer os.RemoveAll`.** **Tokens redacted** from any error
  surfaced for git-step failures so credentials don't leak into
  webhook 5xx responses or operator logs. **Per-scan timeout:**
  15-minute wall-clock cap on the entire flow (clone + scan +
  comment + SARIF). **New `internal/ghapp` files:** `scanner.go`
  (FendixScanner shells out to `git` + `fendix` on PATH;
  configurable binaries for tests), `comment.go` (RenderPRComment
  parser + PostPRComment HTTP client), `sarif.go` (UploadSARIF
  with gzip+base64 encoding). **New tests:** scanner (8 tests
  with PATH-injected fake git/fendix scripts; covers auth-URL
  redaction, git-failure error mapping, fendix-scan/report failure
  paths, input validation), comment (6 tests covering zero-finding
  / 1-finding / >5-finding rendering, malformed JSON, full
  PostPRComment via httptest including header + path + body
  assertions, 403 error path), sarif (4 tests covering gzip+base64
  round-trip, request shape via httptest, 422 error path, empty-
  payload guard), handler (8 tests covering full PR flow with
  fake scanner + httptest token endpoint, filtered actions,
  no-installation skip, SARIF-failure-non-fatal, check_run
  rerequested, check_run other-action no-op, NewHandler defaults).
  **Distribution:** new `Dockerfile.app` at the repo root (multi-
  stage; bundles `fendix` + `fendix-app` + Python engine + `git`
  in a single ~250 MiB Debian-slim image). The image is the
  deployment surface; `fendix-app` is a stateless HTTP server with
  no shared state, so any container platform (Fly.io, Cloud Run,
  Render, Railway, ECS, `docker run` under systemd, k8s) runs it
  unchanged — we don't ship platform-specific manifests, since
  every cluster/PaaS already has its own conventions for image
  registries, secrets, ingress, and resource defaults.
  **`docs/github-app.md` updated** to flip the "stubbed" section
  to "wired today (TASK-107b)" and replace the placeholder
  deployment-recipes section with a single "Running fendix-app"
  block: the `docker build` + `docker run` commands plus a list
  of supported platforms in prose.

- **`.fendix.yaml` repo-committed policy file (TASK-109).** New
  `internal/policy` package + new `--config <path>` flag on
  `fendix scan`. Teams can now commit a `.fendix.yaml` at repo
  root encoding their scan posture (severity threshold, scan
  budgets, auth profile reference, crawler defaults, format) and
  invoke `fendix scan` with one CLI flag (`--url X` or `--code X`)
  instead of the prior six-flag-and-growing wall of text.
  **Precedence** matches `git config`: cobra defaults < `.fendix.yaml`
  values < explicit CLI flags. CLI always wins when explicitly
  passed; `.fendix.yaml` is a default, not a lock. Auto-pickup:
  no `--config`, no policy applied; `--config <path>`, policy
  required (missing file is a hard error, not silent fallback);
  `.fendix.yaml` exists in cwd, picked up silently. **Strict
  parsing:** `yaml.KnownFields(true)` rejects typos like
  `fial_on:` with a clear error rather than silently dropping the
  field. Schema is versioned (`version: 1` required); future fendix
  builds will reject files declaring a higher version with a
  clear upgrade message. **Tests:** 14 unit tests covering schema
  parsing (full schema, missing version, future version, invalid
  fail_on, unknown field, malformed YAML) + ApplyTo precedence
  (nil policy no-op, full apply with no CLI overrides, CLI
  overrides specific fields, nil-setter skips field, nil CLISet
  semantics). 3 e2e tests covering --config-points-at-missing-file,
  unknown-field-rejection, and fail_on-from-policy-fires-the-gate.
  **Reference:** `docs/fendix-yaml.md` documents the full schema,
  precedence model, what's intentionally NOT in the schema (per-
  invocation flags like --baseline, --debug-bundle, credential
  values), worked examples, and a migration table from CLI-only
  to policy-driven scans.

- **`fendix init` now writes `.fendix.yaml` (TASK-109).** The init
  command's contract grew from 2 files to 3: it now generates a
  starter `.fendix.yaml` alongside `.github/workflows/fendix.yml`
  and `.fendix-ignore`. The policy template is heavily commented
  with each section's purpose so future contributors don't need
  to consult the docs to understand a knob. Refuse-to-clobber and
  `--force` semantics extend to the new file (pre-flight check
  still atomic — either everything writes or nothing does).

- **`fendix demo` command (TASK-108).** New `fendix demo` cobra
  subcommand spins up `bkimminich/juice-shop:v17.1.1` in Docker,
  runs a stock fendix scan against `http://localhost:3000`, renders
  an HTML report, and (with `--open`) opens it in the user's
  default browser. Removes the cold-start "what does a real scan
  look like?" question for first-time evaluators. Container is
  always cleaned up on exit (success or failure) via a deferred
  `docker rm -f` running on a fresh context so a parent-cancel
  doesn't strand the container. Flags: `--open`, `--port`,
  `--output`, `--image` (image is overrideable but defaults to the
  same pinned digest the benchmark suite uses, for reproducibility).
  New `internal/democmd` package shells out to the host's `docker`
  CLI rather than pulling in a Docker SDK dep — same pattern as
  `scripts/benchmark/run-juice-shop.sh`. **Tests:** 10 unit tests
  covering happy-path, docker-run-fails, juice-shop-never-healthy
  (verifies cleanup still runs via the defer), context cancel
  during health poll, becoming-healthy-after-503-retries, fendix
  binary missing, and Options resolution defaults/overrides. 1 e2e
  smoke test (`TestDemo_HelpListsFlags`) catches cobra-wiring
  regressions without requiring Docker on every CI runner.

- **GitHub App scaffold (TASK-107).** New `cmd/fendix-app` binary
  (separate from `fendix` CLI; long-running webhook server) plus
  `internal/ghapp` package and `app/manifest.yml` for one-click App
  registration via GitHub's manifest flow. Webhook layer:
  HMAC-SHA256 signature verification (legacy `sha1=` rejected),
  event router (`pull_request`, `push`, `check_run`, `ping`), 4 MiB
  body size cap, 401 on missing/mismatched signatures, 200-OK silent
  drop on unknown event types so a new event won't disable the
  endpoint via repeated 4xx. Auth layer: pure-stdlib RS256
  App-JWT signing (no `golang-jwt` dep added — the project's
  zero-runtime-deps posture is preserved), `/app/installations/{id}/access_tokens`
  exchange, single-flight installation-token cache via
  `TokenSource` (concurrent webhook bursts for the same installation
  produce one network refresh, not N). 28 unit tests with `-race`
  including PKCS1 + PKCS8 private-key formats, JWT structural
  correctness verified by parsing the App's own JWT with the public
  half of the test key, and per-installation cache isolation.
  **Setup guide:** `docs/github-app.md` walks through manifest
  registration, env-var configuration, and the security model.
  **What's stubbed (TASK-107b follow-up):** the actual clone +
  hybrid-scan + PR-comment + SARIF-upload workflow on `pull_request`
  events. The scaffold acknowledges events, fetches installation
  tokens, and logs — operators can deploy *now* and confirm
  credentials wire correctly before the business logic lands.
  Marketplace listing is an operator step (App must be public, GH
  review process, listing copy/screenshots) — distinct from
  TASK-107's code deliverable.

## [0.6.1] - 2026-05-01

**Phase 14 — P4 External Wedge — partial.** Folds the four Phase 14
features that landed on `main` between v0.6.0 and 2026-05-01 into a
tagged release, and ships a critical install-pipe fix that was
blocking the TASK-106 benchmark CI (and any first-time user passing
`FENDIX_DIR=$HOME/.local/bin`).

The Phase 14 work in this release is partial by design: TASK-105
(`fendix init`), TASK-110 (README repositioning), and TASK-111
(telemetry statement) shipped as standalone features; TASK-106
(vulnerable-app benchmark) ships its scaffold here, with the
juice-shop numbers landing in a follow-up commit once the benchmark
CI run captures them. TASK-107 (GH App), TASK-108 (`fendix demo`),
and TASK-109 (`.fendix.yaml`) remain ahead.

### Fixed

- **`scripts/install.sh` now creates the install directory before
  `mv`.** Previously, running `curl -fsSL https://get.fendix.dev/install.sh
  | FENDIX_DIR=$HOME/.local/bin sh` on a system where `$HOME/.local/bin`
  did not pre-exist failed with `mv: cannot move 'fendix' to
  '/home/runner/.local/bin/fendix': No such file or directory`. The
  GitHub Actions benchmark workflow (TASK-106) hit this on every run
  because fresh runners don't have `~/.local/bin` populated. Fixed by
  adding `mkdir -p "$INSTALL_DIR"` before the `mv`, attempting it
  without `sudo` first and falling back to `sudo mkdir -p` only when a
  parent up the chain isn't writable. Locally verified end-to-end on a
  non-existent `FENDIX_DIR=/tmp/.../bin` target.

### Added

- **`fendix init` zero-config workflow generator (TASK-105).** New
  `fendix init` subcommand detects the project's stack (Go, Python,
  Node.js, Ruby, Rust, Java/Kotlin, PHP — coarse, by canonical
  marker file) and a colocated OpenAPI/Swagger spec at any of 14
  conventional paths (`openapi.{yaml,yml,json}` at root, `api/`,
  `docs/`, `spec/`, plus `swagger.*` equivalents). Echoes what was
  detected so the user can sanity-check, then writes two files into
  the working directory: `.github/workflows/fendix.yml` (drop-in
  PR-gated DAST + SAST scan with SARIF upload — same content as
  `examples/github-actions/fendix-scan.yml` shipped in TASK-098,
  embedded into the binary via `go:embed`) and `.fendix-ignore`
  (commented starter for finding-level suppressions). Ends with a
  next-steps block telling the user the exact `git add` + `git commit`
  commands. Refuses to overwrite existing files by default — pre-flight
  checks all targets *before* writing any of them, so a partial-init
  state is impossible. New flags: `--force` (overwrite anyway) and
  `--print` (dry-run; render to stdout without touching disk). New
  `internal/initcmd` package: `detect.go` (stack + spec detection,
  no I/O beyond `os.Stat`), `init.go` (Run loop + embedded templates),
  `templates/{workflow.yml, fendix-ignore.txt}` (embedded via
  `go:embed`). 12 unit tests + 3 e2e tests covering: empty dir
  defaults to Generic, polyglot repo lists all stacks with first-found
  primary, Python dedupes pyproject.toml + requirements.txt, OpenAPI
  spec discovery at root and nested paths, refuse-to-clobber
  preserves the user's existing file byte-for-byte, --force overwrites,
  --print writes nothing to disk, detection echoes to stdout, e2e
  binary respects all flags via cobra wiring. Closes the
  manual-CI-setup-yaml gap that filtered ~80% of first-time users.

- **Vulnerable-app benchmark scaffold (TASK-106, partial).** New
  `scripts/benchmark/run-juice-shop.sh` spins up
  `bkimminich/juice-shop:v17.1.1` in Docker, runs `fendix scan` against
  it, and captures findings + scan duration into a structured
  `bench-results/juice-shop/<UTC-timestamp>/` directory (gitignored).
  Outputs: `findings.json` (raw fendix output), `summary.json` (parsed
  metrics — duration, severity counts, source counts, endpoints
  scanned, fendix version), and a human-readable terminal summary.
  Container is force-cleaned on script exit (success or failure) via
  bash `trap`. New `make benchmark` Makefile target wraps the script.
  New `.github/workflows/benchmark.yml` (workflow_dispatch only —
  manual runs against published release tags, not on every push)
  installs Fendix via `https://get.fendix.dev/install.sh`, runs the
  juice-shop scan, uploads `findings.json`/`summary.json`/`scan.stderr`
  as a build artifact, and posts the summary JSON to the workflow
  step-summary. **vAPI + crapi fixtures intentionally deferred** to a
  follow-up commit (one fixture is enough to start producing numbers;
  the infra is a copy-paste pattern). New `docs/benchmarks.md`
  documents the recipe, the targets table, the methodology (what
  counts as `correlated` vs `blackbox` vs `whitebox`), and the
  caveats (single-run variance, stock-config-only, no ZAP/Semgrep
  comparison yet). The "Latest results" table is currently
  `_pending_` — actual numbers land in a follow-up commit after CI
  runs the workflow against `v0.6.0`. The CI workflow doubles as a
  smoke test of the published install pipe (cosign-signed binary
  pulled via `get.fendix.dev/install.sh`).

### Changed

- **README repositioned around the wedge (TASK-110).** Hero rewritten
  from "Find vulnerabilities before attackers do." (generic, every
  scanner says this) to "DAST + SAST in one PR check. Fails only when
  both engines confirm." Three-bullet trust block under the hero
  matches the landing page at `https://get.fendix.dev/` (confirmed
  findings, single binary, signed and silent). Architecture
  description ("hybrid API and code security scanner that combines
  black-box HTTP probing with white-box static analysis") moved out of
  the lede; lede now leads with the *outcome* (small triage queue,
  every alert means something), architecture appears later in the
  Architecture section where readers expect it.

### Added

- **"What Fendix sends to the network" section at top of README
  (TASK-111).** Five-row table covering default scan, active probing,
  white-box mode, no-flags-passed, and telemetry — explicit "there is
  no telemetry code; verify with tcpdump or read go/internal/, there's
  nothing to find." First-question-an-AppSec-buyer-asks made
  unmissable. Future contract: any non-target outbound traffic added
  in a future release will be opt-in, named in this section, and
  called out in the CHANGELOG.

- **"Verifying signed releases" section in README.** Full cosign
  keyless verify recipe (Sigstore Fulcio + GitHub Actions OIDC
  identity-regexp anchor) for binaries, `.deb`, `.rpm`, and Docker
  images. Notes the cutoff: releases earlier than v0.6.0-rc2 don't
  have sidecars (cosign was opt-in via `COSIGN_ENABLED` until then).
  Cross-links to SECURITY.md for supported-versions and the broader
  artifact-trust policy.

## [0.6.0] - 2026-04-30

**Phase 13 — P3 External Release readiness — ✅ complete.**

Identical content to `v0.6.0-rc2`, promoted to stable after the rc2
release pipeline ran fully green across all 7 jobs and the cosign
signing path was verified end-to-end via real `cosign verify-blob`
against a signed binary (Sigstore Fulcio anchor + GitHub Actions OIDC
identity → `Verified OK`). See [v0.6.0-rc2](#060-rc2---2026-04-30) for the full
feature list. New since v0.5.0:

- TASK-099 — Reproducible release pipeline (linux/arm64, cosign keyless
  signing on every artifact, signed multi-arch Docker, Homebrew formula
  auto-update)
- TASK-100 — Distribution artifacts (`.deb` + `.rpm` via nfpm) plus the
  `https://get.fendix.dev/install.sh` short-URL installer (DNS + GitHub
  Pages + Let's Encrypt + auto-mirror-sync of install.sh + landing page
  on every `v*` tag)
- TASK-101 — Documentation pass (juice-shop walkthrough, Semgrep guide,
  triage workflow, schema reference)
- TASK-102 — `--debug-bundle <path>` redacted diagnostic tarball
- TASK-103 — `SECURITY.md` + active-scanner threat model; signed
  commits/releases now active
- TASK-104 — Performance benchmark suite published in README
- Landing-page positioning at `get.fendix.dev` rewritten around the
  wedge ("DAST + SAST in one PR check, fails only when both engines
  confirm")

This is the first stable signed release. Every binary, `.deb`, `.rpm`,
and Docker manifest ships with `.crt` + `.sig` cosign sidecars
verifiable against the build's GitHub Actions OIDC identity — no
static public key, no rotation surface.

## [0.6.0-rc2] - 2026-04-30

Phase 13 — P3 External Release readiness, second release candidate.
Validates the cosign keyless signing pipeline end-to-end (rc1 was tagged
before `COSIGN_ENABLED=true` flipped on the engine repo on
2026-04-30T14:07Z, so rc1's release pipeline ran with signing dormant).
rc2 is the first tag where every binary, `.deb`, `.rpm`, and Docker
image gets `.crt` + `.sig` cosign sidecars via Sigstore Fulcio.

Also includes the `get.fendix.dev` short-URL installer rollout
(complete — DNS + Pages + Let's Encrypt + auto-mirror-sync of
install.sh / index.html / .nojekyll on every `v*` tag) and the
landing-page positioning rewrite around the wedge ("DAST + SAST in
one PR check, fails only when both engines confirm").

### Added

- **`get.fendix.dev` short-URL installer is live** (TASK-100, complete).
  `curl -fsSL https://get.fendix.dev/install.sh | sh` now installs the
  latest signed Fendix binary on macOS and Linux. Pipeline: operator-owned
  `fendix.dev` zone + DNS CNAME `get.fendix.dev → abdel-rahmansaied.github.io`
  → GitHub Pages on the [`homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix)
  mirror → Let's Encrypt cert (auto-provisioned by Pages, mandatory because
  `.dev` is HTTPS-only) → static files served from the mirror root.

  **Engine-side artifacts** (auto-synced into the mirror on every `v*`
  tag by `release.yml`): new `scripts/release/mirror-pages-bootstrap/`
  holds the four files Pages needs — `CNAME` (binds the custom domain),
  `.nojekyll` (skips Jekyll), `index.html` (browser landing page; static,
  no JS, dark-mode CSS, points at the install one-liner), plus a `README.md`
  with the full operator playbook (DNS records, Pages settings, smoke-test
  commands). The `mirror` job in `.github/workflows/release.yml` now
  copies these four files plus `scripts/install.sh` into the mirror
  alongside the existing Formula update — closing a long-standing drift
  hazard where `install.sh` claimed to be "mirrored on every release"
  but in reality was hand-committed once and silently diverged on every
  later edit. The engine repo is now the single source of truth for
  everything served at `get.fendix.dev`.

  **Cutover**: README quick-start + curl-install section, README CI
  example, and `docs/install.md` install one-liner all flipped from the
  `raw.githubusercontent.com/.../homebrew-fendix/main/install.sh` URL to
  `https://get.fendix.dev/install.sh`. The mirror URL is documented as a
  fallback for users behind networks that block the custom domain. The
  `docs/install.md` "rollout status" section was rewritten as a "how
  it's wired" reference (with a table mapping each served file to its
  engine-repo source) plus a `dig`/`curl -I`/end-to-end verification
  recipe.

  **`install.sh` header** now points at the canonical
  `https://get.fendix.dev/install.sh` URL; PATH-not-set warning suggests
  the `FENDIX_DIR=$HOME/.local/bin` re-run flow with the canonical URL.

  **End-to-end smoke test (2026-04-30)**: `dig +short get.fendix.dev`
  resolves to the GitHub Pages CNAME chain; `curl -I https://get.fendix.dev/install.sh`
  returns HTTP/2 200 with `content-type: application/x-sh`; full
  `curl … | sh` install pulled `fendix v0.6.0-rc1` for `darwin/arm64`,
  verified the sha256, installed to `/usr/local/bin/fendix`, and
  `fendix version` reported the expected version. Pipeline validated
  end-to-end before this entry shipped.

- **Landing-page positioning around the wedge.** `https://get.fendix.dev/`
  rewritten to lead with the differentiation, not the architecture.
  Tagline flipped from "Hybrid API and code security scanner. DAST +
  SAST in one PR check." → "DAST + SAST in one PR check. Fails only
  when both engines confirm." Three-bullet "what it does" block under
  the hero: confirmed findings (false-positive-flood reduction is the
  value prop), single binary (active probes off by default), signed +
  no telemetry (TASK-103/TASK-111 trust statement folded in). New
  "First scan" example block right after install. New "In your CI"
  section with an 8-line GitHub Actions snippet showing a PR-gated
  DAST+SAST scan with SARIF upload. New "Verify the binary (cosign)"
  section with the keyless verify recipe (Sigstore Fulcio,
  `--certificate-identity-regexp` + `--certificate-oidc-issuer`).
  OpenGraph + Twitter Card meta tags so social shares get a real
  preview card; canonical link tag. HTML title flipped to carry the
  wedge ("Fendix — DAST + SAST in one PR check") so search-result
  snippets do too. All static, no JS, dark-mode CSS via
  `prefers-color-scheme`.

- **Cosign keyless signing now active on the release pipeline.**
  `COSIGN_ENABLED=true` repo variable flipped on the engine repo
  (2026-04-30T14:07Z). rc1 was tagged before the flip and shipped
  without sidecar files; rc2 is the first tag where every binary,
  `.deb`, `.rpm`, and Docker image gets a `.crt` + `.sig` cosign
  sidecar. Verification anchors to the GitHub Actions OIDC identity
  that built the release — no static public key to distribute, no
  key rotation, no key-loss recovery. Verify recipe is documented at
  the landing page section above and in `SECURITY.md`. Hard-fail
  semantics: cosign step failure fails the release job, so a broken
  signing path can't silently ship unsigned artifacts.

## [0.6.0-rc1] - 2026-04-30

Phase 13 — P3 External Release readiness, release-candidate. Validates the
new release pipeline (linux/arm64 binaries, multi-arch Docker, .deb/.rpm
packages, opt-in cosign keyless signing) end-to-end before tagging the
clean v0.6.0. Functional surface unchanged from `[Unreleased]` above —
all 6 Phase 13 work items (TASK-099..104) included. Operator items pending
for the v1.0 cut: `COSIGN_ENABLED=true` repo variable (signed artifacts +
commits) and `get.fendix.dev` DNS rollout (short-URL installer).

### Added

- **`--debug-bundle <path>` diagnostic tarball** (TASK-102). New flag on
  `fendix scan` writes a redacted `.tar.gz` at scan end intended for
  attaching to bug reports. Bundle contains six entries:
  `README.md` (top-level explainer), `config.json` (scan config with
  `auth.value` masked as `[REDACTED]` while preserving `auth.type` and
  `auth.header` for diagnosis), `environment.json` (fendix version, Go
  version, GOOS/GOARCH, resolved Python version, capture timestamp),
  `metadata.json` (the same `ScanMetadata` the JSON reporter receives),
  `findings.json` (post-sanitization findings), and `debug.log`
  (DEBUG-and-above slog stream captured via a tee handler installed for
  the duration of the scan, with auth values literal-replaced before
  serialization). When `--enable-active` is on, also includes
  `probes.jsonl` (one `ProbeRecord` per line, sorted by timestamp →
  endpoint → parameter for reproducibility across runs). New
  `internal/diagnostic` package (`bundle.go` + `redact.go`); new
  `internal/scanner/probe_audit_global.go` adds a process-level
  `ProbeAuditLog` with `ResetGlobalAuditLog` + `GlobalAuditRecords` so
  the orchestrator can read post-scan audit records (pre-fix the
  per-endpoint audit log was created freshly on each `CheckInjection`
  call and discarded after returning). Wired into the orchestrator at
  scan start (logagg + audit reset, slog tee install) and end (capture
  python version, probes, findings, metadata; write tarball before the
  fail-on check so non-zero exits still produce a bundle). 8 unit tests
  under `internal/diagnostic/` cover redaction, tarball shape,
  `--enable-active` probe inclusion, environment metadata, and
  unwritable-path error handling. New e2e regression
  `TestDebugBundle_WrittenAndRedacted` runs the binary against an
  httptest server with a real `--auth` value and asserts the bundle
  exists, contains all expected entries, and never leaks the auth
  credential anywhere — including the buffered slog stream. Closes the
  `--debug` exit criterion for Phase 13.
- **Linux `.deb` and `.rpm` packages** (TASK-100). Each release now ships
  Debian and RPM packages alongside the bare binaries: `fendix-vX.Y.Z-linux-amd64.deb`,
  `fendix-vX.Y.Z-linux-arm64.deb`, `fendix-vX.Y.Z-linux-amd64.rpm`,
  `fendix-vX.Y.Z-linux-arm64.rpm`, each with a matching `.sha256` sidecar
  (and `.sig` + `.crt` once `COSIGN_ENABLED=true` rolls out). Built with
  [nfpm](https://github.com/goreleaser/nfpm) from a single repo-root
  [`nfpm.yaml`](nfpm.yaml) covering both packagers. Dependencies declared
  on `python3` (required) and `semgrep` (recommended). Files install to
  `/usr/bin/fendix` plus docs under `/usr/share/doc/fendix/`. Install via
  `sudo dpkg -i fendix-*.deb && sudo apt-get install -f` on Debian/Ubuntu
  or `sudo dnf install ./fendix-*.rpm` on RHEL/Fedora — see new
  [`docs/install.md`](docs/install.md) for the canonical reference.
- **`docs/install.md` install reference** (TASK-100). Single-page guide
  covering every install path (Homebrew, install.sh, .deb, .rpm, Docker,
  manual binary, source), cosign verification one-liners for each asset
  type, the `get.fendix.dev` rollout status (operator-action: domain
  registration + GitHub Pages CNAME), and a troubleshooting section for
  the common install failures. Linked from the README's Documentation
  index. README install section gained `.deb` / `.rpm` quick-start
  blocks alongside the existing Homebrew and Docker entries.
- **Documentation pass for external evaluators** (TASK-101). Four new
  reference docs under `docs/`: [`walkthrough-juice-shop.md`](docs/walkthrough-juice-shop.md)
  takes a first-time user from `docker run` to opened HTML report in
  under 5 minutes against OWASP Juice Shop;
  [`semgrep-rules.md`](docs/semgrep-rules.md) is the rule-author guide
  covering Fendix's metadata expectations (`fendix_severity`, `category`,
  `confidence`), the Semgrep-result-to-Finding mapping, and worked
  examples for each bundled rule;
  [`triage-workflow.md`](docs/triage-workflow.md) is the operator guide
  for going from a fresh report to closed work items, covering the
  triage funnel, baseline diffs, suppression model + anti-patterns, and
  `jq` recipes for the JSON output. Plus a top-level "Documentation"
  index in [README.md](README.md) linking the walkthrough, CI integration
  page, triage workflow, JSON schema reference, Semgrep guide, per-check
  reference, ADRs, and security policy. Closes the docs-pass exit
  criterion for Phase 13.
- **Performance benchmark suite + published numbers** (TASK-104). Three new
  benchmarks in `go/internal/engine/scan_benchmark_test.go` measure
  end-to-end scan cost as a function of endpoint count: `BenchmarkScan_Throughput`
  (wall time + B/op + allocs/op), `BenchmarkScan_Goroutines` (peak goroutine
  count via a 2 ms ticker probe + atomic CAS), `BenchmarkScan_Memory` (allocation
  profile at scale). Each runs at sizes 10/100/500/1000 endpoints × 3 checks
  per endpoint × 32 workers against a local `httptest` server with a
  pool-friendly transport (`MaxIdleConnsPerHost: 64`) and silenced slog. New
  `make bench` Makefile target with `BENCHTIME ?= 5x` override. Reference
  numbers published in [README.md "Performance"](README.md#performance):
  Apple M1, Go 1.21 — 1000 endpoints in 31.7 ms / 24.7 MB / 166 peak goroutines.
- **`SECURITY.md` + active-scanner threat model** (TASK-103). New
  top-level [`SECURITY.md`](SECURITY.md) documents the vulnerability
  reporting channels (private GitHub Security Advisory + email),
  supported-versions policy, scope/out-of-scope for security reports,
  artifact-verification instructions (`cosign verify-blob` for binaries,
  `cosign verify` for the Docker image), disclosure timeline (72h ack,
  7d triage, 14d publication target), and an explicit policy for
  active-scanner misuse reports. New companion [`docs/threat-model.md`](docs/threat-model.md)
  is the reference for the active scanner's safety envelope: 7 threats
  (T1 destructive payload, T2 DoS, T3 auth/credential leakage, T4 safe-payload
  side effects, T5 cross-target contamination, T6 supply-chain compromise,
  T7 report XSS) each documented with scenario, Fendix-side mitigations,
  and operator-side residual risk; the explicit 5-property safety envelope
  any active probe must maintain (no write verbs without opt-in, no
  state-mutating payloads, no out-of-band callbacks, no cross-host
  crawl, all probes auditable); and an operator-responsibilities section
  delineating what Fendix owns vs. what the human running it owns.
- **Linux arm64 release binary** (TASK-099, partial). The release matrix now
  builds `fendix-vX.Y.Z-linux-arm64` alongside the existing
  `linux-amd64`/`darwin-amd64`/`darwin-arm64` artifacts. The Homebrew tap
  formula's `on_linux` block now branches on `Hardware::CPU.arm?` to download
  the arm64 build automatically; `scripts/install.sh` has matched arm64
  detection since v0.4.x. arm64 server users (Graviton, Ampere, Raspberry Pi
  4/5, ARM Linux laptops) can now `brew install fendix` or use
  `curl -fsSL …/install.sh | sh` and get a native binary.
- **Multi-arch Docker images** (TASK-099, partial). The Docker image at
  `ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z` is now a multi-arch manifest
  list covering both `linux/amd64` and `linux/arm64`. `docker pull` picks the
  right arch automatically per host. QEMU is wired into the release workflow
  so cross-arch builds run on the standard `ubuntu-latest` runner.
- **Cosign keyless signing — opt-in via repo variable** (TASK-099, partial).
  Both release binaries and the Docker image can be signed with cosign in
  keyless mode (Sigstore Fulcio + GitHub Actions OIDC — no static keys, no
  secrets to manage). Disabled by default; enable by setting the repo
  variable `COSIGN_ENABLED=true` (Settings → Secrets and variables →
  Actions → Variables tab). When enabled, every binary ships with `.sig` +
  `.crt` sidecar files; verify with:

  ```sh
  cosign verify-blob \
    --certificate fendix-vX.Y.Z-linux-amd64.crt \
    --signature   fendix-vX.Y.Z-linux-amd64.sig \
    --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    fendix-vX.Y.Z-linux-amd64
  ```

  Docker image verification:

  ```sh
  cosign verify ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z \
    --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  ```

## [0.5.0] - 2026-04-30

Phase 12 — Quality & Ops. Polish that turns a working scanner into one
that fits production workflows: documented public JSON schema with
validation tests, schema-aware path-parameter substitution (templated
endpoints now actually get scanned), aggregated WARN log volume,
global scan budgets (`--max-requests`, `--max-duration`,
`--respect-robots`), apikey-query auth profile + e2e coverage of every
auth type, race-clean concurrency proof at 1000 endpoints + worker-pool
cancellation fuzzer, and a drop-in GitHub Actions workflow with SARIF
upload and PR summary comments.

### Added

- **Reference GitHub Actions workflow** (TASK-098). New
  `examples/github-actions/fendix-scan.yml` is a complete,
  drop-in CI workflow: scans on every PR and push to main,
  uploads SARIF to GitHub Code Scanning (inline annotations
  on the PR), persists the previous run's baseline via
  `actions/cache` (so PRs see only the diff), posts a PR
  summary comment via `actions/github-script@v7` with
  severity/source counts and the top 5 findings, and gates
  merges on `--fail-on HIGH` while still uploading SARIF and
  posting the comment when the gate fails. The comment
  payload reads the public JSON schema (`summary`, `sources`,
  `total`, `findings[].endpoint|line`) — same shape that
  `docs/schema.md` documents — so it stays correct as long as
  the schema is stable. `docs/ci-cd-integration.md` updated
  to point at the canonical example as its quick-start.

- **Concurrency review tests** (TASK-097). Two new tests in
  `internal/engine/` cover the worker pool's concurrency surface:
  - `TestWorkerPool_LargeConcurrentScan_RaceClean` — drives the pool with
    1000 endpoints × 3 checks × 32 workers against a single httptest
    server, asserts all 3000 invocations completed, server hit count
    matches, and no goroutines leaked. Runs under `-race` in CI as part
    of `go test ./...`, so any data race in the pool, scanner clients,
    or shared findings collection is caught on every PR.
  - `FuzzWorkerPool_CancelTiming` — native Go fuzzer that drives the
    pool with randomized (worker count, endpoint count, cancel-delay,
    busy-time) tuples and asserts no deadlock, no panic, and no
    goroutine leak under any cancel timing. Seed corpus exercises
    cancel-before-start, cancel-mid-flight, cancel-after-completion,
    zero-endpoints, zero-workers (clamped), and the tight cancel race.
    The seed corpus is exercised on every PR via `go test -race`.
    New `make fuzz FUZZTIME=30s` target runs deeper ad-hoc fuzzing
    (15s of `-race -fuzz` reaches 4400+ executions and 30+
    new-interesting inputs locally with no failures).

- **`--auth-type apikey-query`** (TASK-096). API-key authentication can
  now be delivered via URL query string instead of a request header — the
  common pattern for legacy or sensor-style APIs that prefer query
  placement (sometimes to avoid logging Authorization-class headers).
  CLI: `--auth-type apikey-query --auth-header api_key --auth my-key`
  produces `?api_key=my-key` on every outbound request and never sets a
  header. The param name comes from `--auth-header` (overloaded — same
  flag doubles as query-param name in this mode); defaults to `api_key`
  when unset. New constants `AuthTypeAPIKeyQuery` and
  `DefaultAPIKeyQueryParam` in `internal/models/auth.go`. New branch in
  `AuthContext.ApplyToRequest` mutates `req.URL.RawQuery` via
  `url.Values.Set` (idempotent on double-apply, preserves existing query
  params). Mirror branch in `injection.addAuth` for active-probe
  requests. Verified end-to-end: server-side wire-format assertion
  confirms the credential reaches the URL query and never a header.

- **End-to-end auth-profile coverage** (TASK-096). New
  `internal/e2e/auth_profiles_test.go` exercises every supported
  auth-type via the actual fendix CLI: bearer, apikey-header,
  apikey-query, basic, cookie. Each subtest spins up an httptest server
  that records every incoming request, asserts the expected wire
  format reaches it, and confirms the JSON report was written. This
  closes a Phase 12 visibility gap — the auth scanner had unit
  coverage since Phase 2 but no e2e proving the CLI flag-parsing,
  ScanConfig population, and per-scanner `ApplyToRequest` calls all
  worked as one integrated path.

- **Scan budget controls** (TASK-095). Three new flags shape how much
  work a scan does:
  - `--max-requests N` — soft-cap on total HTTP requests sent during the
    scan phase (discovery is exempt by design — a small cap shouldn't
    starve discovery before any check runs). Implemented as an
    `http.RoundTripper` wrapper in the new `internal/budget` package
    that increments an atomic counter on every outbound request and
    refuses further requests once the cap is hit. Cap-hit also fires a
    one-shot `context.CancelFunc` so the worker pool stops scheduling
    new jobs. Soft-stop semantics: in-flight requests finish, no new
    ones start; per-worker overshoot is bounded by `--workers`.
  - `--max-duration 5m` — wall-clock deadline. Wraps the run context
    with `context.WithTimeout`; deadline expiry triggers the same
    soft-stop path as the request cap. Accepts standard Go duration
    strings (e.g. `90s`, `2m30s`).
  - `--respect-robots` — when set, robots.txt `Disallow` paths are
    treated as a hard restriction across every discovery source (spec,
    sitemap, HTML crawl, brute-force). Brute-force pre-filters the
    wordlist so disallowed URLs never receive even a discovery probe.
    Default behaviour unchanged: Disallow paths are queued as endpoint
    hints, since they're often the highest-value targets for a
    security tool.
  Orchestrator emits a single `INFO budget summary` line at scan end
  with `requests_sent`, `requests_rejected`, `max_requests`, and
  `max_duration` whenever any cap is set. Unit tests cover the
  RoundTripper math under concurrent load (50-goroutine race test);
  e2e regressions verify the CLI integration: a 50-path scan with
  `--max-requests 20` is server-side capped, and `--respect-robots`
  with a `Disallow: /admin` rule prevents `/admin` from being touched.

- **Aggregated per-check WARN log volume** (TASK-094). New
  `internal/logagg` package caps WARN-level emissions at 3 per check key
  per scan (configurable via `SetCap`); subsequent events are downgraded
  to DEBUG and tallied. The orchestrator emits a single
  `INFO warning summary` line at scan end with per-key
  `warned=N suppressed=M` attrs (alphabetically sorted, deterministic).
  Eliminates terminal-flooding on partially-unreachable targets where
  every check fires the same transient error per endpoint. Real-world
  measure: a 10-endpoint scan against an unreachable target dropped from
  30 WARN lines (1 per check per endpoint) to 9 WARN lines + 1 summary
  (a 3× reduction). Goroutine-safe — worker pool calls into the
  aggregator from N goroutines concurrently. Integrated into the 18
  per-request WARN sites across auth, CORS, exposure, headers, injection
  (sqli/error/boolean/cmdi/crlf, baseline measurement, request build),
  and the Python engine spawner's malformed-JSON handler. Setup-time
  errors that fire at most once per scan (spec parsing failure, ignore
  file parsing, baseline save, python availability) keep their direct
  `slog.Warn` / `slog.Error` calls — capping wouldn't help and would
  hide important one-shot signals.

- **Path-parameter substitution for templated endpoints** (TASK-093).
  Discovered endpoints like `/users/{id}` previously produced HTTP
  requests to `/users/%7Bid%7D` because `http.NewRequest` URL-encodes
  the literal `{` and `}` characters. Every server returned 404 to that
  request, so every black-box check (headers, CORS, exposure, auth,
  rate-limit, injection) silently observed nothing on every templated
  endpoint of every OpenAPI spec. The crawler now substitutes a concrete
  sample value into the `FullURL` field at discovery time. The Path
  field is preserved as the template form so reports still show
  `GET /users/{id}` (not `GET /users/1`). Resolution order:
  `schema.example` → `schema.enum[0]` → type-driven default
  (integer/number → `1`, boolean → `true`, string + format=uuid → all-zero UUID,
  format=date → `2024-01-01`, format=date-time → `2024-01-01T00:00:00Z`,
  format=email → `user@example.com`) → parameter-name heuristic
  (`*Id`/`*_id`/`id` → `1`, `*uuid*`/`*guid*` → all-zero UUID,
  `count`/`page`/`limit`/`offset`/`index` → `1`, else `sample`) → `1`.
  Substitution applies to all five discovery sources (spec, JS, robots.txt,
  sitemap, HTML crawl); only the spec source has access to schema info,
  the rest fall through to the name heuristic. Verified against a real
  petstore3 spec scan: 4 templated paths (`/pet/{petId}`,
  `/pet/{petId}/uploadImage`, `/store/order/{orderId}`,
  `/user/{username}`) now produce non-zero black-box findings and zero
  `%7B` leakage in the report.

## [0.4.2] - 2026-04-29

Quality + UX patch. Two real-world bugs fixed (silent `fendix report` on
SARIF input; silent `os.Exit(2)` on any subcommand error) and the first
Phase 12 task lands (TASK-092 — output schema cleanup). No breaking
changes; safe upgrade for all v0.4.x users.

### Added

- **Documented JSON output schema** (TASK-092). New `docs/schema.md` +
  `docs/schema.json` (JSON Schema draft-07) act as the public, versioned
  contract for `fendix scan --format json` output. Stable for the v0.x
  line; additive changes only within minor releases. Schema-validation
  test walks every emitted report and enforces required fields, types,
  enums, the `SEC-NNN` id pattern, and the LOW-confidence severity cap.
- **Severity↔confidence consistency enforcement** (TASK-092). LOW
  confidence now caps severity at MEDIUM, MEDIUM caps at HIGH (derived
  from the scoring formula's implicit max). New
  `models.MaxSeverityForConfidence` + `EnforceSeverityConsistency`,
  wired as orchestrator step 5.6 between Deduplicate and Sort.
  Inconsistent findings get severity downgraded with an aggregated WARN
  summary; per-finding violations logged at DEBUG.

### Changed

- **`RenderJSON` always emits `findings: []`** (never `null`) so
  consumers can iterate without a null-check (TASK-092). Now part of
  the documented schema contract.
- **`[Unconfirmed by live scan]` evidence suffix tightened** (TASK-092).
  Only added when the whitebox finding normalises to a URL/path
  endpoint. File:line findings (e.g. a hardcoded secret in
  `src/config.py:14`) can't be confirmed by a live HTTP scan, so the
  suffix was misleading there. New `isURLEndpoint` helper gates both
  call sites in the correlator.

### Fixed

- **`fendix report --input` now rejects non-Fendix-JSONReport input.**
  Real-world bug: feeding a SARIF file to
  `fendix report --input results.sarif --format html` silently
  deserialized the SARIF document into a zero-value `JSONReport` and
  rendered an empty HTML page (0 findings, zero-time timestamp, blank
  version) — no error, no warning. New
  `reporters.ParseJSONReport(data)` helper detects SARIF (via `$schema`
  containing "sarif" OR top-level `runs` + `version` keys), random JSON
  (missing `metadata.version` and `metadata.mode`), and malformed JSON,
  and returns actionable error messages for each. SARIF-specific
  message hints at `fendix scan --format json` to produce a valid
  re-rendering input.
- **Subcommand errors now print to stderr** instead of vanishing into a
  silent `os.Exit(2)`. The root command had `SilenceErrors: true` to
  avoid double-printing structured logs from `fendix scan`, but
  `main()` never printed the error itself. Result: every
  command-level failure (bad `--format`, missing `--input`, parse
  errors, network errors) produced a bare exit 2 with no message.
  Now prints `Error: <msg>` to stderr before exiting.

## [0.4.1] - 2026-04-29

Build-infrastructure-only release. **No behavior changes vs v0.4.0** — all
detection logic, CLI flags, and report output are identical. v0.4.0 users
should upgrade to v0.4.1 only if they want to install via Homebrew or curl;
the v0.4.0 binary itself remains correct.

### Fixed

- **Distribution: anonymous install paths now actually work.** v0.4.0's
  release artifacts lived on a private repo, so every install path the
  README claimed (`brew tap`, curl-pipe, `github.com/.../releases/...`)
  returned 404 for any non-authenticated user. v0.4.1 routes all
  user-facing distribution through a public mirror at
  [`Abdel-RahmanSaied/homebrew-fendix`](https://github.com/Abdel-RahmanSaied/homebrew-fendix):
  `brew tap Abdel-RahmanSaied/fendix && brew install fendix` and
  `curl -fsSL https://raw.githubusercontent.com/Abdel-RahmanSaied/homebrew-fendix/main/install.sh | sh`
  both work end-to-end without auth.
- **CI on `main` is green for the first time since 2026-03-20.** Three
  long-standing pre-existing failures fixed: Python Test job was only
  installing `pytest` (now installs `requirements.txt` + `hypothesis`);
  TASK-085's `.env` test fixture was gitignored and never committed (now
  tracked via a fixtures-scoped negation rule); TASK-086's longer field
  name had left 4 files with stale gofmt alignment.

### Added

- **Docker image publishing** — `release.yml` now builds and pushes
  `ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z` and `:latest` on every `v*`
  tag (linux/amd64). Image visibility must be flipped to public via
  GHCR package settings on first push.
- **Public install mirror automation** — `release.yml` now has a `mirror`
  job that auto-creates a matching release on the public mirror with
  binaries+sha256s, and auto-regenerates `Formula/fendix.rb` in the
  mirror's main branch with fresh SHA256 sums on every `v*` tag.
  Idempotent (re-runs upload with `--clobber`).

### Changed

- **SARIF `tool.driver.informationUri`** now points at the public install
  mirror (`https://github.com/Abdel-RahmanSaied/homebrew-fendix`) so
  consumers reading SARIF reports don't 404 on a private repo URL.

## [0.4.0] - 2026-04-29

This release ships **Phase 11 — P1 Coverage Parity**: secrets, static analysis,
active scanning, deduplication, crawler discovery, real CVE lookups, and
correlator finalization. The goal was to close the gap with industry-baseline
detection (gitleaks / semgrep / ZAP) on the obvious checks. Folds the planned
v0.3.0 batch (TASK-085 + TASK-086) into v0.4.0 since v0.3.0 was never tagged.

### Added
- **Provider-specific secret patterns** — secrets analyzer now covers GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), Stripe live secret keys (`sk_live_`), Slack tokens (`xoxa-`/`xoxb-`/`xoxp-`/`xoxr-`/`xoxs-`), Google API keys (`AIza...`), Anthropic API keys (`sk-ant-`), OpenAI API keys (legacy `sk-`/`sk-proj-`/`sk-svcacct-`), npm registry tokens (`npm_`), and GCP service-account JSON files (matched on the canonical `"type": "service_account"` signature). Total pattern count: 7 → 15. (TASK-085)
- **`.env` file scanning** — `.env`, `.env.local`, `.env.production` etc. are now properly walked and scanned with a dedicated unquoted-`KEY=value` pattern. Previously the file walker missed dotfiles whose `Path.suffix` is empty, and the generic `HARDCODED_PASSWORD` regex only matched quoted values, so `.env` files passed through silently. (TASK-085)
- **Active scanner: body-param probing on POST/PUT/PATCH** — `requestBody.content."application/json".schema.properties` (OpenAPI 3) and `parameters[in:body].schema.properties` (Swagger 2) now flow into a new `Endpoint.BodyParams` field. Body-location probes serialize a JSON body where the target field carries the payload and sibling fields get a `"fendix"` placeholder, so server-side validation doesn't reject the request before reaching the vulnerable code. (TASK-086)
- **Active scanner: header-param probing** — `in: header` parameters now flow into `Endpoint.Headers` (with standard auth headers `Authorization`/`Cookie`/`X-Api-Key` filtered out) and get probed with header-location requests. Custom headers like `X-Trace-Id` and `X-Tenant-Id` are exactly the surface where header-value injection bugs hide. (TASK-086)
- **Error-based SQL injection detection** — sends a single `'"`-class payload and matches the response body against compiled regex patterns for MySQL, Postgres, MSSQL, Oracle, and SQLite error signatures. Confirmed matches surface as HIGH-severity HIGH-confidence findings. (TASK-086)
- **Boolean-based SQL injection detection** — sends a true/false payload pair (`' OR '1'='1` vs `' AND '1'='2`) and flags status-code flips or response-body length deltas > 5% as MEDIUM-confidence findings. (TASK-086)
- **SQLite + Oracle time-based SQLi payloads** — total time-based DB types: 3 → 5. SQLite uses `randomblob(99999999)` gated on a CASE expression; Oracle uses `DBMS_PIPE.RECEIVE_MESSAGE`. (TASK-086)
- **`--max-probes-per-endpoint` flag** (default 20) — the per-endpoint probe budget is now configurable. Replaces the previously hardcoded `MaxProbesPerEndpoint` constant; `0` falls back to the default. (TASK-086)
- **Static analyzer: pickle deserialization (`PY_PICKLE_LOAD`)** — `pickle.load()` / `pickle.loads()` flagged as CRITICAL HIGH-confidence (CWE-502). Also catches `cPickle` and `_pickle` aliases. (TASK-087)
- **Static analyzer: unsafe yaml.load (`PY_YAML_UNSAFE_LOAD`)** — `yaml.load()` without `Loader=SafeLoader`, `yaml.unsafe_load()`, and `yaml.load_all()` flagged as HIGH HIGH-confidence (CWE-502). `yaml.safe_load()` and explicit `Loader=yaml.SafeLoader` correctly skipped. (TASK-087)
- **Static analyzer: weak crypto for passwords (`PY_WEAK_CRYPTO_PASSWORD`)** — `hashlib.md5()` / `hashlib.sha1()` / `hashlib.new('md5'/'sha1', ...)` flagged HIGH MEDIUM-confidence (CWE-916) when the input subtree contains a password-like identifier (`password`, `passwd`, `passphrase`, `secret`, or whole-token `pw` / `pwd`). Substring-match for long tokens; whole-token snake_case-aware match for short abbreviations to avoid false positives like `pw` matching `power`. (TASK-087)
- **Static analyzer: open redirect (`PY_OPEN_REDIRECT`)** — `redirect()` / `HttpResponseRedirect()` called with `request.args/GET/POST/...` data flagged HIGH MEDIUM-confidence (CWE-601). (TASK-087)
- **Static analyzer: SSRF (`PY_SSRF`)** — `requests.get/post/put/delete/head/patch/options/request()` with a non-literal first arg flagged HIGH MEDIUM-confidence (CWE-918). Variables resolved through scope tracking — a constant URL assigned to a variable doesn't trigger. (TASK-087)
- **Static analyzer: auth-header trust (`PY_AUTH_HEADER_TRUST`)** — `if request.headers.get('X-Admin') == 'true':` and `if req.headers['X-Role']:` patterns flagged HIGH MEDIUM-confidence (CWE-290) under `auth_bypass` category. Recognizes both the global `request` and Flask-style `req` handler-arg name. (TASK-087)
- **Static analyzer: multi-step SQL injection** — `cursor.execute(name)` where `name` was assigned a BinOp/JoinedStr/Call earlier in the same function is now flagged via intra-function scope tracking. Closes the "Bobby Tables" string-concat gap from the 2026-04-28 evaluation. (TASK-087)
- **Findings deduplication via `AffectedEndpoints []string`** — N findings sharing the same (Title, Category, Severity) collapse into one finding whose `affected_endpoints` array lists every endpoint where the issue was detected. The grouped finding promotes to the highest confidence in the group, the strongest source signal (`correlated > blackbox > whitebox`), and the union of all references. Singleton findings keep `affected_endpoints` omitted so the JSON shape stays clean. Real-world re-test on `petstore3.swagger.io`: 160 findings → 10 (16× reduction; 9 deduped findings collapsed 159 occurrences across 21 endpoints). HTML reporter shows a "+N more" badge in the finding header and an "Affected endpoints (N)" list in the body; SARIF reporter emits one `Location` per affected endpoint per result (matches SARIF 2.1.0 §3.27.12 "this issue applies to all of them" semantics). (TASK-088)
- **Crawler: robots.txt discovery** — fetches `/robots.txt`, parses `Disallow:` and `Allow:` directives as endpoint hints, and follows `Sitemap:` directives to enqueue child sitemaps. Disallow paths are some of the highest-value targets — they're often the URLs operators don't want indexed, like admin or staging interfaces. (TASK-089)
- **Crawler: sitemap.xml discovery** — fetches `/sitemap.xml` (and any `Sitemap:` URLs from robots.txt), parses `<url><loc>` entries from `<urlset>` documents and `<sitemap><loc>` entries from `<sitemapindex>` documents (one level of recursion). Cross-host links filtered out. (TASK-089)
- **Crawler: HTML link parsing with recursive depth** — extracts `<a href>` and `<form action>` targets from HTML responses and follows them via BFS up to `--crawl-depth` levels deep. Same-host only (cross-host links dropped); a visited set prevents loops. New `--crawl-depth` flag (default `1` = home-page links only; `0` disables; `2+` follows links from those pages too). Non-HTTP schemes (`mailto:`, `tel:`, `javascript:`, `data:`, `ftp:`, `file:`, `sms:`) are filtered out so the scanner doesn't try to GET phantom endpoints. (TASK-089)
- **Crawler: `--wordlist` flag** — pass a path to override the built-in `CommonPaths` brute-force list. Plain text format, one path per line, `#` comments and blank lines ignored, leading `/` auto-added. (TASK-089)
- **Crawler: `--max-endpoints` budget** (default `500`) — caps total endpoint count after dedupe so a chatty sitemap or a deep HTML crawl can't produce a runaway scan. `0` removes the cap. (TASK-089)
- **Larger built-in `CommonPaths`** — wordlist expanded from ~50 to ~117 entries with admin/dashboard surfaces (`/admin/login`, `/console`, `/dashboard`), source-control leakage (`/.git/config`, `/.svn/entries`, `/.env`), DevOps tooling (`/grafana`, `/prometheus`, `/jenkins`, `/phpmyadmin`), debug endpoints (`/debug/vars`, `/debug/pprof`), and modern API conventions (`/api/v1/auth/login`, `/api/me`). (TASK-089)
- **Real CVE coverage via primary tools (pip-audit / npm audit / govulncheck)** — the deps analyzer now invokes pip-audit for `requirements.txt`, npm audit for `package.json` (when a lockfile is present), and govulncheck for `go.mod` as primary detection paths. The hardcoded 14-package known-vuln list is now a true offline fallback that fires only when the primary tool is missing or fails. **Real-world impact**: scan of `/tmp/fendix-test/badcode/requirements.txt` produced **6 deps findings** with the offline fallback alone, **97 deps findings (16× coverage)** with pip-audit installed. govulncheck against a Go fixture using `golang.org/x/net@v0.10.0` produces 4 HIGH findings (XSS, infinite parsing loop, non-linear and quadratic parsing) — only the actually-called vulns; vendored-but-uncalled noise is dropped. (TASK-090)
- **Go module support in deps analyzer** — `go.mod` files in `--code` are now scanned by govulncheck when installed. New `_check_go_modules` + `_run_govulncheck` methods; new module-level `_parse_govulncheck_json` parses govulncheck's pretty-printed multi-line JSON via `json.JSONDecoder.raw_decode` (the NDJSON assumption was wrong — caught during in-session live testing). Govulncheck `finding` messages with at least one `function` in their trace become "called" findings; vendored-but-uncalled vulns are skipped to avoid supply-chain noise. (TASK-090)
- **Correlator: path-suffix matching** — when one normalized path is a `/`-bounded suffix of the other, the correlator merges blackbox + whitebox findings even with base-path skew. Closes the petstore-style case where the spec describes `/pet/findByStatus` and the live server hosts it under `/api/v3/pet/findByStatus` — pre-fix, no exact path match meant no correlation; now they merge. (TASK-091)
- **Correlator: HTTP method-prefix stripping in endpoint normalization** — whitebox spec_parser emits endpoints as `"GET /pet/findByStatus"`. Pre-fix, the leading method dropped the value into the file-path branch and produced `"get /pet/findbystatus"`, blocking exact match against URL-derived blackbox endpoints. Method tokens (GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS/CONNECT/TRACE) are now stripped via regex before path parsing. (TASK-091)
- **Correlator: debug instrumentation** — every match attempt (and every miss) is logged at DEBUG level with the normalized endpoints, related categories, and match kind. Successful matches log at INFO with `match_kind=exact|suffix|fuzzy` so users can trace which predicate fired in real-world hybrid scans. (TASK-091)

### Fixed

- **Correlator: blackbox findings consumed at most once** — the previous index lookup didn't filter against the `bbCorrelated` set, so two different whitebox findings could both merge with the same blackbox, producing duplicate correlated findings. The new `findCorrelationMatch` honours a `taken` set across all three match passes. (TASK-091)
- Pattern boundaries on provider-specific tokens (`(?<![A-Za-z0-9])` anchors) prevent the OpenAI `sk-` regex from matching Anthropic's `sk-ant-` keys or matching inside concatenated base64 strings. (TASK-085)
- HTML crawler dropping `mailto:`, `tel:`, `javascript:`, `data:` scheme links surfaced as a real-world bug on `httpbin.org` where the home-page contact link was being followed and produced "unsupported protocol scheme" warnings on every check. (TASK-089)
- **pip-audit JSON key mismatch** — the integration was reading `data.get("vulnerabilities")`, but modern pip-audit (≥2.x) emits findings under `data["dependencies"]`. The result: pip-audit "ran" silently and emitted zero findings, with no fallback to the local list. Fixed by accepting both keys, treating any non-success exit code as a tool error that triggers fallback, and parsing the `aliases` field in references. (TASK-090)
- **e2e suite flakiness on macOS** — the brute-force phase opened 117 sequential connections per URL-based test, didn't drain the response body before close (preventing keep-alive reuse), and accumulated TIME_WAIT sockets that exhausted ephemeral ports under parallel-test load. Fixed by (a) draining response bodies in `fromBruteForce` before close, (b) raising `MaxIdleConnsPerHost` to 32 on the crawler's HTTP transport for connection reuse, and (c) routing every URL-based e2e test through a 1-path `tinyWordlist` so they don't pay 117 probes for tests that don't exercise brute-force. Suite now passes 7/7 sequential runs. (TASK-090)

## [0.2.0] - 2026-04-29

This release closes six P0 user-facing bugs surfaced by the 2026-04-28 real-world test pass.
After this release, every documented CLI flag does what its `--help` text claims.

### Fixed
- **`--save-baseline` was dead code at the CLI** — flag was declared but never read into `ScanConfig`, so no file was written. Now wired through `main.go` to the orchestrator's existing baseline path. (TASK-079)
- **`--code`-only scans refused to run** — orchestrator early-exited on "no endpoints discovered" before reaching the white-box branch. The guard now fires only when both endpoints AND `--code` are absent. (TASK-080)
- **Active scanner ignored spec-defined query parameters** — every probe targeted a hardcoded `id` param, missing real vulnerabilities on `host`/`url`/`username`/etc. The crawler now extracts `in: query` and `in: path` parameters from OpenAPI 2.0 and 3.x specs (path-level + operation-level layered correctly). (TASK-081)
- **`--spec` did not accept HTTP/HTTPS URLs** — `--spec http://host/openapi.json` silently fell back to brute-force. Specs are now fetched over HTTP with format auto-detection (URL suffix → `Content-Type` → first-byte sniff), 50 MB size cap, and 4xx/5xx surfaced as errors. (TASK-082)
- **`make test` failed from a clean checkout** — `cd python/ && pytest` broke `test_self_audit.py` (paths are repo-root relative). Makefile now runs pytest from repo root; the test was also hardened with cwd-agnostic `Path(__file__).resolve().parents[2]`. (TASK-084)

### Changed
- **SARIF: 1 rule per check type, not 1 rule per finding** — previously, 160 findings produced 160 unique rule IDs (`SEC-001..SEC-160`), so GitHub Code Scanning scattered the same vuln across N "rules". Rule IDs are now stable `fendix.<category>.<title-slug>`. Per-finding `SEC-NNN` IDs remain in JSON output as instance IDs but no longer appear in SARIF. **This is a breaking change for any consumer that pinned to v0.1 SARIF rule IDs in baselines or suppressions.** (TASK-083)

### Added
- **End-to-end test infrastructure** — `go/internal/e2e/` gated behind `//go:build e2e` and run via `make e2e`. Each fixed Phase 10 flag now has an e2e regression test that runs the built binary and asserts the externally-observable effect (`TestSaveBaseline_WritesFile`, `TestCodeOnlyScan_ProducesFindings`, `TestActiveProbe_UsesSpecParam`, `TestSpecURL_FetchedAndParsed`). This closes the bug class where unit tests pass but the CLI flag is unreachable.

## [0.1.0] - 2026-04-11

### Added
- **Hybrid scanning engine** — Go black-box scanner + Python white-box analyzer communicating via newline-delimited JSON IPC
- **Black-box checks:** security headers, CORS misconfiguration, authentication bypass (JWT malformed/expired/alg:none), sensitive data exposure, rate limiting detection, IDOR two-account check
- **Active injection probes** (opt-in via `--enable-active`): time-based SQL injection (MySQL, PostgreSQL, MSSQL), command injection (echo canary), CRLF header injection
- **White-box checks:** secrets detection (7 pattern types), Semgrep rules (auth, injection, secrets), OpenAPI spec parser (2.0 + 3.x), AST analyzer (Python + JavaScript), dependency CVE checker (PyPI + npm)
- **Correlator** — cross-references black-box and white-box findings; correlated findings get elevated confidence
- **Three output formats:** JSON (default), self-contained HTML, SARIF 2.1.0
- **CI/CD integration:** `--fail-on` exit codes, `--baseline` / `--save-baseline` diff mode, SARIF upload for GitHub Code Scanning
- **`.fendix-ignore`** suppression file — suppress by ID, endpoint, category with optional expiry dates
- **Auth profiles** — `~/.fendix/profiles/<name>.yaml` for reusable auth configurations
- **Credential masking** — auth values always displayed as `[REDACTED]` in all output
- **Distribution:** embedded Python engine via `go:embed`, multi-stage Dockerfile, curl-pipe installer, Homebrew formula
- **`fendix report`** command — re-render saved JSON findings to HTML/SARIF without re-scanning
- **Active probe safety:** legal disclaimer, per-endpoint rate limit (20 probes max), full audit log
- **Severity scoring model** — multiplicative formula: ImpactBase x ConfidenceMult x SourceMult
- **Worker pool** — concurrent HTTP scanning with configurable `--workers`, `--timeout`, `--delay`
