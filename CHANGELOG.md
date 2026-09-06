# Changelog

All notable changes to Fendix are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
