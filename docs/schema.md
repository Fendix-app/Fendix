# Fendix JSON Report Schema

This document defines the public schema for `fendix scan --format json` output.
A machine-readable JSON Schema (draft-07) lives alongside this file at
[`schema.json`](./schema.json) and is used by Fendix's own test suite to
validate every report produced.

The report contract carries its **own** version — `metadata.schema_version`,
today `1` — which is independent of the engine's release version. Additive
changes (new optional fields) are allowed in any engine release and do not bump
it; it is bumped only for a change a consumer must react to, such as a removal
or a type change.

**Engine v2.0.0 was a major bump for CLI behaviour, not for this contract.** It
gated `--fail-on` on the confidence band (see below) and added
`metadata.schema_version`; it removed and retyped nothing. Reports written by
`1.x` and `0.x` builds still validate against this schema, and a consumer
written against `1.x` still parses a `2.x` report. What did change is the
**content** of several fields — see
[What v2.0 changed in the values](#what-v20-changed-in-the-values).

Reports produced by `0.x` builds validate against this schema too — every
change across the `0.x` line was additive — but `0.x` is end of life (see
[`SECURITY.md`](../SECURITY.md)) and the version-gated notes below (`v0.24`,
etc.) record when a field first appeared, not a support commitment.

---

## Top-level shape

```json
{
  "metadata":  { ... ScanMetadata ... },
  "summary":   { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "sources":   { "blackbox": 0, "whitebox": 0, "correlated": 0 },
  "total":     0,
  "decisions": { "total": 0, "confirmed": 0, "blocking": 0, "warning": 0, "informational": 0 },
  "findings":  [ { ... Finding ... }, ... ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `metadata` | object | yes | Scan-level metadata (target, timing, mode). |
| `summary` | object | yes | Severity counts. Sums to `total`. |
| `sources` | object | yes | Source counts (blackbox / whitebox / correlated). Sums to `total`. |
| `total` | integer | yes | Total findings in `findings`. |
| `decisions` | object | effectively yes | **v0.24+** decision summary (`StatusCounts`): `total`, `confirmed` (HIGH-confidence), `blocking` (status BLOCK), `warning` (WARN), `informational` (INFO). The reporter serialises it **unconditionally** (`JSONReport.Decisions` has no `omitempty`), so every report a current build produces carries it. It stays out of `schema.json`'s root `required` set purely so pre-v0.24 archived reports still validate — a consumer reading current output can rely on it being present. |
| `findings` | array of `Finding` | yes | Each finding produced by the scan, sorted deterministically. May be empty. |

---

## ScanMetadata

```json
{
  "schema_version":    1,
  "target":            "https://api.example.com",
  "started_at":        "2026-04-29T10:00:00Z",
  "duration":          "12.5s",
  "version":              "2.0.1",
  "mode":                 "hybrid",
  "endpoints_scanned":    21,
  "endpoints_discovered": 34,
  "endpoints_truncated":  true,
  "active_probes":        false,
  "checks_run":           ["headers", "cors", "exposure", "ratelimit", "secrets", "semgrep", "deps"],
  "scanner_status": [
    {"name": "secrets",  "state": "ok"},
    {"name": "semgrep",  "state": "skipped", "reason": "dependency_missing", "detail": "semgrep binary not installed"},
    {"name": "npm",      "state": "failed",  "reason": "execution_error",    "detail": "npm audit: exit status 1"}
  ]
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `schema_version` | integer | effectively yes | Version of this report contract. `RenderJSON` stamps it on **every** report it writes (overwriting whatever the caller set), so any report a current build produces carries it. It stays out of `schema.json`'s `required` set so pre-2.0 archived reports still validate: those omit the key, and an absent key means "pre-versioned", **not** invalid. A consumer that does not recognise the value should warn, not fail — `ParseJSONReport` accepts any value, including 0 and unknown future ones. Bumped only for a change consumers must react to; purely additive keys do not bump it. |
| `target` | string | yes | The `--url` value, or empty string for `--code`-only scans. |
| `started_at` | string (RFC 3339 timestamp) | yes | When the scan started. |
| `duration` | string (Go-formatted duration, e.g. `"12.5s"`) | yes | Wall-clock duration of the scan. |
| `version` | string | yes | Fendix version, e.g. `"2.0.1"` or `"dev"`. **Docker images published before v2.0.1 report the literal `"docker"` here** — the image build hardcoded it — so a report from one of those cannot say which engine produced it. Images from v2.0.1 onward carry the git tag. |
| `mode` | string enum | yes | One of `blackbox`, `whitebox`, `hybrid`. |
| `endpoints_scanned` | integer | yes | Number of endpoints actually scanned — i.e. *after* the `--max-endpoints` cap was applied. May be 0 for `--code`-only. |
| `endpoints_discovered` | integer | no | Number of endpoints found **before** `--max-endpoints` truncated the list. Omitted when zero. Without it, `endpoints_scanned: 500` cannot be distinguished from "found exactly 500" vs "found 801, capped to 500". When no cap fires, this equals `endpoints_scanned`. |
| `endpoints_truncated` | boolean | no | `true` when the `--max-endpoints` cap actually dropped endpoints. Omitted when false. Pair with `endpoints_discovered` to detect a silent coverage gap from a CI gate. |
| `active_probes` | boolean | yes | Whether `--enable-active` was set. |
| `checks_run` | array of string | no | Names of checks executed. Omitted when empty. |
| `scanner_status` | array of `ScannerStatus` | no | Per-analyzer outcome, one entry per registry analyzer, in registry order: `dast`, `spec`, `active-probes`, `secrets`, `textscan`, `semgrep`, `govulncheck`, `pip`, `npm`, `python-engine`, `python-engine/auth`, `python-engine/injection`, `python-engine/deps`, `plugins`. The three `python-engine/*` children appear only when the Python engine reports them. Empty for `import` mode. See below. |
| `coverage` | `Coverage` | no (present on every report from v3.4.0) | The engine's configured-completeness statement. See below. |
| `policy_version` | string | no (present from v3.4.0) | Version of the finding-decision policy (`docs/DECISION_POLICY.md`) this build applied. `"1.0.0"` for the RC-3 semantics shipped in v3.2.0. |
| `release_decision`, `coverage_state`, `decision_policy_version`, `decision_rationale` | string / string / string / object | no | Present only on reports re-rendered by Fendix Cloud, which embeds its release verdict in the input it hands to `fendix report`. A live `fendix scan` never writes them. |

### ScannerStatus

```json
{"name": "semgrep", "state": "skipped", "reason": "dependency_missing", "detail": "semgrep binary not installed"}
{"name": "pip", "state": "ok", "attempts": 2}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Registry identity (list above). |
| `state` | string enum | yes | `ok`, `skipped`, `failed`. |
| `reason` | string enum | when `state` ≠ `ok` | Skip reasons: `not_applicable`, `diff_unchanged`, `disabled_by_flag`, `disabled_offline`, `dependency_missing`, `unsupported_target`. Fail reasons: `network_error`, `timeout`, `execution_error`, `malformed_output`, `truncated_output`, `input_error`, `no_endpoints`. Closed set. |
| `detail` | string | no | Short human-readable excerpt. Never used for classification. |
| `attempts` | integer ≥ 2 | no | Present when the analyzer was retried in process (one retry, `network_error`/`timeout` on the dependency scanners only). `state`/`reason` describe the final attempt. |

Lifecycle classes, derived from `(state, reason)`: `ok`; `not_applicable` (`not_applicable`, `diff_unchanged`); `disabled` (`disabled_by_flag`, `disabled_offline`); `unavailable` (`dependency_missing`); `unsupported` (`unsupported_target`); `failed` (any fail reason). Only `unavailable` and `failed` are engine gaps: the analyzer was configured to run and did not deliver. `disabled` and `unsupported` are visible, intentional or structural, and never a gap on their own.

### Coverage

```json
{"contract_version": 1, "strict": false, "configured_complete": false, "gaps": ["semgrep"], "limitations": ["npm: package.json without package-lock.json"], "required_analyzers": [], "required_gaps": [], "retried": ["pip"]}
```

| Field | Type | Description |
|---|---|---|
| `contract_version` | integer | Version of the registry-and-reason contract (`1`). Independent of `schema_version`. |
| `strict` | boolean | The run used `--fail-on-coverage-gap` or `--require-analyzers`. |
| `configured_complete` | boolean | `true` iff no entry is `unavailable` or `failed`. Not changed by `--require-analyzers`. |
| `gaps` | array of string | Names of `unavailable` or `failed` entries. |
| `limitations` | array of string | `"<name>: <detail>"` for every `unsupported` entry. |
| `required_analyzers` | array of string | The `--require-analyzers` list; empty when none. |
| `required_gaps` | array of string | Required names not `ok` or `not_applicable`. An explicit requirement is stricter than `configured_complete`: `disabled` and `unsupported` do not satisfy it. |
| `retried` | array of string | Entries with `attempts > 1`. |

A consumer that wants "was this scan complete?" should read `coverage.configured_complete` and, on a strict run, `coverage.required_gaps`; `gaps` and `limitations` carry the detail. Checking only for a `failed` entry is no longer sufficient: a missing dependency is `skipped/dependency_missing`, and it is a gap.

---

## Finding

```json
{
  "id":                  "SEC-001",
  "title":               "Hardcoded API key detected",
  "severity":            "CRITICAL",
  "source":              "whitebox",
  "category":            "secrets",
  "endpoint":            "src/config.py:14",
  "affected_endpoints":  ["src/config.py:14", "src/admin.py:22"],
  "evidence":            "API_KEY = 'sk-live-abc... [REDACTED]'",
  "fix":                 "Move to environment variable. Rotate the exposed key immediately.",
  "references":          ["CWE-798"],
  "confidence":          "HIGH",
  "line":                "src/config.py:14",
  "taint_chain":         [
    {"file": "app/views.py", "line": 12, "expr": "q = request.args.get('q')"},
    {"file": "app/views.py", "line": 14, "expr": "sql = 'SELECT * FROM users WHERE name=' + q"},
    {"file": "app/views.py", "line": 15, "expr": "cursor.execute(sql)"}
  ],
  "reachable":           true
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string (`SEC-NNN`) | yes | Sequential ID assigned by the orchestrator. Stable for a single scan only. |
| `title` | string | yes | Human-readable finding title. |
| `severity` | string enum | yes | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `source` | string enum | yes | One of `blackbox`, `whitebox`, `correlated`. |
| `category` | string | yes | Taxonomy category (`auth_bypass`, `injection`, `secrets`, `idor`, `data_exposure`, `cors`, `headers`, `info_disclosure`, `auth`, ...). |
| `endpoint` | string | yes | URL path or `file:line`. Primary endpoint for this finding. |
| `affected_endpoints` | array of string | no | Populated only when dedup collapsed `N≥2` occurrences into one finding. Includes the primary `endpoint`. |
| `evidence` | string | yes | Snippet showing what was detected. Auth credentials passed via `--auth` are masked as `[REDACTED]`. Since v2.0 credential material **found by the secrets scanner** is redacted at capture time and rendered as `[REDACTED len=N sha256:xxxxxxxx...]` — deterministic and unsalted, so the same value renders identically in every report, but never carrying the value itself. May end with the suffix `[Unconfirmed by live scan]` when correlation against a live scan ran but produced no match. |
| `fix` | string | yes | Remediation guidance. |
| `references` | array of string | yes | CWE / OWASP / RFC identifiers. May be empty array. |
| `confidence` | string enum | yes | One of `HIGH`, `MEDIUM`, `LOW`. |
| `line` | string \| null | yes | File and line for whitebox findings, e.g. `"src/config.py:14"`. Always serialised; `null` when not applicable. |
| `taint_chain` | array of `TaintLink` | no | Whitebox dataflow proof: ordered chain from source (e.g. `request.args.get`) through intermediate assignments to the sink. Each link is `{file, line, expr}`. Emitted by the Python AST analyzer for SQLi / SSRF / open-redirect / XSS / command-injection findings when intra-function dataflow resolves end-to-end. Inherited onto the merged `source: "correlated"` finding. Omitted when no chain was proven. |
| `reachable` | boolean | no | Whitebox-proven that user input reaches the sink. Currently implies `taint_chain` is non-empty. Used by the correlator to apply a *second* severity escalation on top of the standard correlated-bonus (so MEDIUM × MEDIUM × reachable → CRITICAL). Omitted (treat as `false`) when not proven. |
| `fingerprint` | string | no | Semantic stable identity, hex, 20 bytes. **v3.0.0 changed how it is computed** — see the algorithm section below. Survives across scans for suppressions/baselines; survives line movement, reformatting, retitling, and any change of severity/confidence/decision. |
| `source_tier` | string enum | no | Analyzer tier that produced a whitebox finding: `native_go`, `tree_sitter_sidecar`, `semgrep_shim`. |
| `rule_id` | string | no | **v3.0.0** The precise check that fired — a semgrep rule id, a DAST check name, a CVE for an advisory. Finer-grained than `category`, and the primary input to `fingerprint`. |
| `dependency` | object | no | **v3.0.0** Package identity behind a `deps` finding: `{ecosystem, package, version, manifest}`. Absent on every other family. `version` is reported but is **not** an identity input. |
| `secret` | object | no | **v3.0.0** Safe identity of a committed credential: `{identifier, file}`. `identifier` is the non-sensitive name the credential is bound to. Never contains credential material or a digest of it. |
| `sink` | string | no | **v3.0.0** The normalized vulnerable operation for a code finding, e.g. `requests.get(url)`. Emitted whether or not a taint chain was proven. |
| `symbol` | string | no | **v3.0.0** Enclosing function or method for a code finding. Distinct from `route.handler`, which exists only when a route was bound. |
| `route` | object | no | HTTP route binding `{method, pattern, handler, file, line}` (Proven Path v1). |
| `route_confirmed` | boolean | no | A live blackbox scan hit the finding's `route.pattern`. |
| `proven_path` | boolean | no | `route_confirmed` AND `reachable` — DAST hit + SAST taint path + exact route. |
| `status` | string enum | no | **v0.24** decision verdict: `BLOCK`, `WARN`, `INFO`. Since v2.0.0 `BLOCK` additionally requires the confidence band to support the claim — see the decision-summary section below. |
| `confidence_score` | integer (0–100) | no | **v0.24** deterministic confidence score (see Confidence Engine). |
| `confidence_band` | string enum | no | **v0.24** score-derived band `HIGH`/`MEDIUM`/`LOW`. Distinct from `confidence` (the scanner/correlator enum, unchanged for back-compat). |
| `confidence_reasons` | array of string | no | **v0.24** plain-text, per-rule breakdown of the score (no black boxes). |

### Decision summary & confidence (v0.24)

`decisions` reduces the finding list to "what needs action": `blocking`
(status `BLOCK` — the build-failing set), `warning`, `informational`, and
`confirmed` (HIGH-confidence, the v0.23 score axis — kept distinct from
`sources.correlated`). Per-finding `status` + `confidence_*` mirror this. The
score is deterministic and rule-based (no AI); see `internal/confidence`. All
v0.24 fields are additive/optional — existing consumers are unaffected
(minor-release additive policy above).

**`BLOCK` is not "severity ≥ `--fail-on`" as of v2.0.0.** Meeting the threshold
is necessary but no longer sufficient: under the default `--enforce-confidence`
a finding also needs its band to support the claim — HIGH always blocks, MEDIUM
blocks only with at least one corroborating signal, LOW never blocks — and a
finding the correlator marked unconfirmed-by-live-scan never blocks
uncorroborated. `--enforce-confidence=false` restores the severity-only mapping.
`confidence_reasons` carries a `+0` line naming the reason whenever a
threshold-crossing finding was held at WARN, so the demotion is always
attributable from the report alone. See CHANGELOG `[2.0.0]` for the full
rule table.

**SARIF level note:** as of v0.24 the SARIF result `level` follows the
decision verdict (`BLOCK`→`error`, `WARN`→`warning`, `INFO`→`note`), not raw
severity. Because nothing is `BLOCK` without a threshold, a bare
`fendix scan --format sarif` (no `--fail-on`) emits every result at
`warning`/`note` and zero `error`. SARIF consumers that key off `error` level
should pass `--fail-on` (the GitHub Action defaults to `fail-on: HIGH`).
Build-blocking is driven by the exit code, not the SARIF level.

### Severity ↔ confidence consistency

The orchestrator enforces a consistency rule before reports are written: a
finding with `confidence: "LOW"` cannot have `severity` higher than `MEDIUM`.
This matches the implicit cap from the scoring formula (`base × 0.5` is
≤ 5.0 for every category, which lands at MEDIUM or below). Findings that
violate the rule have their severity downgraded; the original score is
preserved in the scoring formula's intent.

### `[Unconfirmed by live scan]` suffix semantics

The suffix is appended to a whitebox finding's `evidence` only when:

1. Both engines actually ran (the orchestrator only invokes correlation when
   blackbox **and** whitebox findings exist), AND
2. The whitebox finding's `endpoint` normalises to a URL path (e.g. `/users`
   or `GET /users`) — i.e. live scanning could in principle have caught it.

Source-only findings (e.g. a hardcoded secret at `src/config.py:14`) never
receive the suffix because a live scan cannot observe source files.

As of v2.0.0 the suffix has an internal machine-readable counterpart
(`evidence.Evidence.UnconfirmedByLiveScan`) produced at the same moment by the
same code, which the decision layer reads: a finding carrying it cannot reach
status `BLOCK` under the default policy unless a corroborating signal is also
present. **No new JSON field is added** — the public `Finding` shape is
unchanged and the suffix text is byte-identical — so consumers that parse the
prose suffix keep working exactly as before. The marker exists so that
enforcement gates on structure instead of on a published string.

---

## Severity values

| Value | Numeric rank | Meaning |
|---|---|---|
| `CRITICAL` | 4 | Immediate exploit risk; e.g. unauth admin endpoint, exposed live API key. |
| `HIGH` | 3 | High-impact bug requiring privileged access or specific conditions. |
| `MEDIUM` | 2 | Defence-in-depth violation (missing security header, weak CORS). |
| `LOW` | 1 | Informational with mild impact. |
| `INFO` | 0 | Diagnostic only; no exploit path. |

## Confidence values

| Value | Meaning |
|---|---|
| `HIGH` | Detected by direct evidence (regex hit, error response, `correlated` finding). |
| `MEDIUM` | Pattern match with potential false positives (boolean-based SQLi, semgrep MEDIUM). |
| `LOW` | Heuristic or statistical signal. |

## Source values

| Value | Meaning |
|---|---|
| `blackbox` | Produced by the Go HTTP scanner against a live target. |
| `whitebox` | Produced by a static analyser against source / spec. Since TASK-115/116 this covers the native-Go secrets scanner and the Go Semgrep shell-out as well as the (opt-in `--python-engine`) Python AST and spec analysers — `source` does not distinguish which; use `source_tier` for that. |
| `correlated` | Produced by the correlator when both engines agree on the same endpoint + related category. Severity is escalated by one level; confidence is `HIGH`. |

---

## What v2.0 changed in the values

No field was added, removed or retyped for findings, so `schema_version` stayed
at `1`. But v2.0 moved a lot of *content*, and a consumer that stored yesterday's
report will see the difference:

| Field | What moved | What it breaks |
|---|---|---|
| `status`, `confidence_score`, `confidence_band` | Two new deterministic confidence deltas (direct observation of a live response `+30`, deterministic pattern match in production source `+30`) and two new penalties (placeholder-shaped credential `-20`, advisory component never imported `-10`) move the score on almost every scan; `status` is then gated on the resulting band. | Nothing structurally — but a dashboard that charts these will show a step change, and `decisions.confirmed` / `decisions.blocking` step with them. |
| `title`, `id`, `fingerprint` on **dependency** findings | Alias-linked OSV records merge into one finding per vulnerability, named after the canonical id (`CVE-*` > `GHSA-*` > `PYSEC-*` > other). `SEC-DEPS-PYSEC_2026_3552` becomes `SEC-DEPS-CVE_2026_69247`. | **Saved `--baseline` files and `.fendix-ignore` `fingerprint:` rules pinned to a dependency finding stop matching** and must be regenerated; a `--diff` scan reports the renamed finding as new. Every merged id is preserved in `references`, and `fendix verify` matches on `references` as well as the id, so re-verifying a pre-2.0 report does not call a still-installed vulnerability resolved. |
| `title`, `severity`, `fingerprint` on the **CSRF-cookie** finding | A `csrftoken` / `XSRF-TOKEN` / `_csrf` cookie without `HttpOnly` is no longer "Session cookie missing HttpOnly flag" at MEDIUM; it is its own INFO finding describing the double-submit pattern. CWE-1004 is retained. | Same fingerprint caveat as above. A host setting both a session cookie and a CSRF cookie now produces two HttpOnly-class dedup groups where it produced one. |
| `evidence` on **secrets** findings | Credential material is redacted at capture time as `[REDACTED len=N sha256:xxxxxxxx...]`, over the union of every pattern's spans on the line — not just the emitting pattern's. | A golden file or snapshot that pinned secrets evidence needs regenerating. Fingerprints were unaffected at the time: the v1 `fingerprint` hashed `(category, endpoint, title)` and the dedup key hashes `(severity, category, title)`; neither read `evidence`. Under the v3.0.0 algorithm a redaction marker reaching a normalizer is collapsed to a constant before hashing, so this remains true. |
| Finding **count** on repos with Dockerfiles | A base image pinned to a tag rather than a digest (`python:3.14-slim`, `node:20-alpine`) is now an INFO finding. Build-stage aliases, existing digest pins, `FROM scratch`, build-arg references and numeric stage indexes are exempt. | Roughly one extra INFO finding per Dockerfile. It does not gate a build at that severity. |

---

## What v3.0 changed in the values

`schema_version` moves `1` → `2`. The report SHAPE is only additively extended
(`rule_id`, `dependency`, `secret`, `sink`, `symbol`, all optional), but the
MEANING of `fingerprint` changed, and that is a change a consumer must react to.

`metadata.fingerprint_algorithm` names the scheme that produced a report's
fingerprints (`fendix/v2` today), so two archived reports can be compared for
whether their identities are comparable at all.

| Field | What moved | What it breaks |
|---|---|---|
| `fingerprint` on **every** finding | Identity is computed from semantics rather than from `sha1(category\|endpoint\|title)`. v1 and v2 share no hash. | **Every saved `--baseline` file must be regenerated and every `.fendix-ignore` `fingerprint:` rule rewritten.** Measured on a 30-finding fixture: a genuine pre-upgrade baseline matched **0 of 30**; a regenerated one matched 30 of 30. Rules matching by path, category or rule id are unaffected. Baseline matching recomputes the key from each finding's fields, but a pre-v3 baseline carries none of the fields v2 identity reads, so recomputation does not rescue the upgrade. |
| `fingerprint` on **dependency** findings | The installed version is no longer an identity input. | One advisory affecting several installed copies of one package in one lockfile is now ONE identity rather than several. A `fingerprint:` suppression covers all copies of that advisory for that package. In exchange, a package bumped from one vulnerable version to another keeps its record instead of reporting "1 fixed, 1 new". |
| `title` on **path-traversal**, **open-redirect** and **SSRF** findings | Wording now follows the evidence the finding holds: `Potential X — dynamic …` when only the sink was observed, `X — user-controlled …` when the source→sink path was proven. | Nothing structurally — titles are not identity inputs as of v3.0.0. A snapshot pinning the old strings needs regenerating. |
| SARIF `partialFingerprints` key | `fendix/v1` → `fendix/v2`, bound to the algorithm constant so the key can never name one scheme while carrying another. | A consumer keyed on `fendix/v1` stops matching — deliberately, so v1 and v2 identities are never confused. |
| SARIF rule ids | Derived from `rule_id` where one exists, instead of from the title slug. Every blackbox check gained a `rule_id` in this release. | **GitHub alerts re-partition once.** Existing alerts under the old title-slug rule ids close and reopen under the new rule-slug ids on the first v3 upload. |
| SARIF `run.automationDetails.id` | `fendix/scan` → `fendix/scan/<mode>`. | A repository that uploads more than one scan mode had those modes clearing each other's alerts; they now hold separate alert sets, which re-partitions once. A run with no declared mode keeps the original constant. |
| Finding **count** on rate-limit checks | A non-safe operation is probed with its own verb under `--active`, or reported as an INFO "not tested" record. It is never probed with a substituted GET. | A passive scan of a write-heavy API reports far fewer rate-limit findings and a corresponding number of INFO not-tested records. |

### The fingerprint algorithm (`fendix/v2`)

Identity is an ordered list of labelled `key=value` components joined on `\0`
and hashed with SHA-256, truncated to 20 bytes so it is the same width as the
v1 SHA-1 it replaces. Every component is optional and labelled, so an absent
component cannot impersonate a present one.

| Family | Components |
|---|---|
| all | `alg`, `cat`, `rule` |
| whitebox code | `file`, `sym`, `op` — normalized path, enclosing symbol, normalized sink |
| dependencies | `eco`, `pkg`, `manifest` (advisory rides in `rule`; version excluded) |
| secrets | `file`, `ident` (the non-sensitive binding name; never the credential) |
| blackbox / config | `ep` — normalized method + path |

Excluded on purpose: title, evidence prose, fix and reference text
(presentation); severity, confidence, score, band, status, decision reason,
policy and applicability (evolving judgements *about* a finding); line and
column numbers, absolute paths, worktree and temp prefixes, timestamps and run
ids (the machine and the moment); and credential material, raw or digested.

---

## Stability guarantees

These are guarantees about `metadata.schema_version` (today `2`), not about the
engine's release version — engine v2.0.0 was a major release that left this
contract at `1`, and engine v3.0.0 moved it to `2`.

- New optional fields may be added at any time without bumping
  `schema_version`; `1.1.0` added none, `2.0.0` added `metadata.schema_version`
  itself.
- Existing field types and enum values do **not** change without a
  `schema_version` bump.
- A field marked optional may become required only under a `schema_version` bump.
- Removing a field is reserved for a `schema_version` bump.
- A **value** moving inside an unchanged field is not a contract change and does
  not bump `schema_version` — v2.0.0 moved a great many, see below. The one
  exception is a value whose meaning changes such that a consumer's stored copy
  silently stops matching: v3.0.0 bumped to `2` for exactly that reason, because
  a stale baseline matching *nothing* is the failure this field exists to warn
  about.
- "Optional" in `schema.json` means *this schema will validate a report that
  omits it*, not *current builds may omit it*. Fields whose Go struct tag
  carries no `omitempty` — `decisions` today — are always emitted by a current
  build; the optional marking exists so archived reports from older releases
  still validate.

If you build tooling that consumes Fendix JSON, validate against
[`schema.json`](./schema.json) and pin the schema version through your CI.
