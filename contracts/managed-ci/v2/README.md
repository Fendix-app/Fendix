# Managed CI contract v2

## Why v2 exists

`managed-ci/v1` could not support an authoritative decision. Its findings
carried severity, evidence hashes and free-form `signals`, but no defined
facts from which a backend could calculate confidence or corroboration. A
backend reading v1 had two options: trust a client conclusion, or classify on
severity alone. The first violates the authority boundary. The second diverges
from the engine: a HIGH, medium-confidence, uncorroborated finding is WARN
locally and would have been BLOCK in the backend. Neither is acceptable.

v2 adds a closed, typed evidence-fact vocabulary and a shared finding-policy
specification. It is a new major, not a v1 amendment. The v1 compatibility
rule says required, enum, meaning or authority changes need a new major, and
v2 adds required fields (`analyzer_id`, `evidence_facts`) and changes what
decides a finding. v1 was never released, but it had consumers (generated
backend and frontend copies with conformance tests), so it is not amended in
place.

**v1 is superseded.** A document declaring `api_version: managed-ci/v1` or
`schema_version: evidence-manifest/v1` is rejected with `unsupported_version`.
v1 does not carry the facts classification needs, and it is never interpreted
as v2. The v1 bundle stays in the canonical repository for history only; it is
no longer exported. The ingestion path moves to `/api/ci/v2`.

## Authority boundary

The runner may attest normalized **facts**. It may not select an authoritative
verdict, confidence conclusion, tier, risk score, coverage conclusion, exit code
or publication outcome. `producer_diagnostics` is explicitly untrusted and the
backend must exclude it from policy inputs. A managed Decision Record exists
only after backend evaluation reaches `completed`.

The backend computes confidence score, band, corroboration and each finding's
status from `evidence_facts`, using the finding-policy specification. It
then derives the decision from those statuses, analyzer health and coverage,
using the release policy.

The GitHub App, if restored, is an adapter to these contracts. It cannot become
a separate decision authority.

## Schemas

| Schema                              | Purpose                                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `managed-scan-context`              | Tenant, Asset, immutable repository, exact commit and workflow execution identity.         |
| `evidence-manifest`                 | Normalized findings with evidence facts, provenance, analyzer health, coverage and hashes. |
| `evidence-facts`                    | The closed vocabulary of normalized facts that classification reads.                       |
| `analyzer-execution-result`         | One analyzer's identity and execution outcome.                                             |
| `coverage-state`                    | Observable coverage inputs; it deliberately carries no client coverage conclusion.         |
| `evidence-submission-request`       | Versioned submission envelope and idempotency identity.                                    |
| `evidence-submission-response`      | Stable accepted identifiers and polling location.                                          |
| `scan-status-response`              | Polling state and terminal decision/error projection.                                      |
| `authoritative-decision-response`   | Backend-owned decision and release-gate result (`authoritative-decision/v1`, unchanged).   |
| `decision-record-reference`         | Immutable record ID, revision, digest and canonical URL.                                   |
| `sanitized-github-summary`          | Bounded structured input for a GitHub step summary.                                        |
| `sanitized-sarif-publication-input` | Bounded result locations/messages derived from accepted evidence.                          |
| `error-response`                    | Stable code, safe message, retryability and field codes.                                   |

Unknown properties are rejected. Unsupported version constants return
`unsupported_version`; they are not interpreted as the closest known version.
Duplicate JSON object keys are invalid everywhere and consumers must reject
them, even where a JSON library would silently keep the last value.

## Evidence facts

Every finding carries `analyzer_id` and an `evidence_facts` object. The facts
are lower-level observations. None is a conclusion, and a fact named
`confidence`, `tier`, `decision`, `blocking` or `status` is structurally
impossible.

| Fact                       | Type                                                 | Meaning                                                                       |
| -------------------------- | ---------------------------------------------------- | ----------------------------------------------------------------------------- |
| `observation_source`       | `whitebox` · `blackbox` · `correlated` · `imported`  | static, live, both independently, or an imported external report              |
| `rule_precision`           | `high` · `medium` · `low`                            | the emitting rule's declared precision (literal match vs graded heuristic)    |
| `analyzer_implementation`  | `native` · `tree_sitter` · `semgrep` · `unspecified` | implementation class of the producing analyzer                                |
| `reachable_taint_path`     | boolean                                              | a source-to-sink taint path was proven                                        |
| `route_confirmed`          | boolean                                              | a live request confirmed the vulnerable route                                 |
| `proven_path`              | boolean                                              | route confirmed AND taint path proven                                         |
| `payload_validated`        | boolean                                              | an active probe elicited the predicted response (payload/response never sent) |
| `direct_observation`       | boolean                                              | a deterministic read of one live response                                     |
| `cross_tool_corroborated`  | boolean                                              | an independent tool reported the same weakness at the same location           |
| `corroborating_tools`      | up to 20 unique identifiers                          | which independent tools; non-empty exactly when `cross_tool_corroborated`     |
| `response_context`         | `none` · `client_error_4xx` · `static_asset`         | context of the live response the finding fired on                             |
| `in_test_code`             | boolean                                              | every occurrence lies in test or fixture code                                 |
| `fixture_shaped_value`     | boolean                                              | the matched credential value matches the deterministic placeholder heuristics |
| `provider_anchored_secret` | boolean                                              | the matched credential carries a known provider signature                     |
| `dependency_applicability` | `unknown` · `applicable` · `evidence_against`        | whether the advisory's vulnerable component is used                           |
| `auth_expectation`         | `unknown` · `public` · `required`                    | what an authoritative source declared about authentication                    |
| `unconfirmed_by_live_scan` | boolean                                              | correlation ran against a live scan and did not confirm the finding           |

- **Required facts** are defined per finding-policy version
  (`policy/finding-policy-<version>.json` `required_facts`), not by the schema.
  For `1.0.0` every fact is required.
- **Missing facts:** the finding is _unclassifiable_
  (`classification_facts_missing`), and a result that would otherwise be PASS
  or WARN becomes INCOMPLETE.
- **Conflicting facts:** any violated `consistency_rules` entry makes the
  finding unclassifiable (`conflicting_evidence_facts`), with the same
  consequence. The rules are the invariants the engine guarantees: the
  corroborating-tools list matches its flag; `proven_path` requires a confirmed
  route, a taint path and a non-semgrep analyzer; direct observation and
  payload validation require a live source; and severity stays within the cap
  implied by `rule_precision`.
- **Duplicate facts:** impossible in a valid document, because duplicate JSON
  keys are rejected.
- **Unknown facts:** a name outside the vocabulary rejects the submission as
  `invalid_evidence`. A producer must not emit a fact the declared
  `finding_policy_version` does not define.
- **Provenance:** `analyzer_id` must name a manifest analyzer, and every
  analyzer's `finding_count` equals the number of findings naming it.
  `observed_analyzers` is a subset of the reported analyzers. Each finding's
  facts are the producing analyzer's attestation about the evidence items
  identified by its `evidence_hashes`.
- **Sanitization:** facts are booleans, closed enums and tool identifiers only.
  No free text, no payloads, no responses and no values from the scanned code.
  `payload_validated` exists precisely so the probe exchange is never sent.
- **Limits:** 17 facts per finding; `corroborating_tools` holds at most 20
  identifiers of at most 128 characters. The 8 MiB body limit still applies,
  so a manifest near 10,000 findings must keep locations and signals lean
  (roughly 800 bytes per finding).
- **`signals`** remain bounded, non-authoritative display context. They are
  never a classification input.

## Finding policy and parity

`policy/finding-policy-1.0.0.json` is a declarative encoding of the engine's
finding-decision policy `1.0.0` (`go/internal/decision`, `go/internal/confidence`).
It holds score deltas and bands, the independent and self-evident signal
classes, the ordered confidence gate, the applicability and test-fixture
adjustments, and the severity cap. Everything is expressed in the small
predicate grammar it defines. The managed-CI default options (`enforce_confidence`,
`deescalate_tests`, `block_on_inapplicable=false`) are fixed. The relaxed
severity-only mode does not exist in managed CI.

Parity chain:

1. `go/internal/decision/managed_ci_policy_vectors_test.go` generates
   `policy/finding-policy-1.0.0.vectors.json` from the engine's
   `DecideWithOptions`: named cases, each with an asserted intent, plus a
   seeded sample of consistent fact combinations. It fails if the committed
   vectors ever differ from what the engine decides, or if `PolicyVersion` and
   the specification disagree.
2. `reference_policy.py` interprets the specification. `validate_bundle.py`
   proves it reproduces every vector exactly.
3. The backend interprets the same specification and must reproduce every
   vector.

A finding-policy change bumps the engine's `PolicyVersion` and adds a new
specification and vector file. An evidence document names its policy in
`engine.finding_policy_version`; a version the backend does not support is
rejected with `unsupported_version`.

## Release decision

`policy/managed-release-2.0.0.json` turns finding statuses, analyzer health
and coverage into the authoritative decision. The ranking is BLOCK >
INCOMPLETE (coverage gap or unclassifiable finding) > WARN > PASS. INFO is
never emitted. `fail_gate` is true for BLOCK and INCOMPLETE. Required analyzers
come from the binding's backend-owned policy (minimum `sast`, `sca`), never
from the runner's `coverage.required_analyzers`.

**Required-analyzer invariant.** A required analyzer is satisfied only when its
`analyzers` entry has status `completed` and its id appears in
`coverage.observed_analyzers`. Absence, and every other status, produces an
incomplete coverage result. That includes `not_applicable` and any status a
later contract adds.

| Required analyzer                            | Reason codes                                               |
| -------------------------------------------- | ---------------------------------------------------------- |
| `completed` and observed                     | none                                                       |
| `failed`                                     | `required_analyzer_failed`                                 |
| `skipped` with `diff_unchanged`              | `differential_scope_rejected`, `required_coverage_missing` |
| `skipped` for any other reason               | `required_coverage_missing`                                |
| `not_applicable`                             | `required_coverage_missing`                                |
| `completed` but absent from observed         | `required_coverage_missing`                                |
| absent from `analyzers`, or any other status | `required_coverage_missing`                                |

For the pilot, an SCA analyzer that finds no supported manifest completes
successfully with zero findings. `not_applicable` cannot satisfy a required
analyzer. An optional analyzer reported `not_applicable` (or `completed` or
`skipped`) is not a gap; an optional analyzer that `failed` still reports
`optional_analyzer_failed`. A confirmed BLOCK outranks every coverage gap and
unclassifiable finding. The decision stays BLOCK and those reason codes stay
visible.

`fixtures/decision-cases.json` pairs every valid submission fixture with its
decision fixture and per-finding outcomes. The validator re-derives each pair
with the reference interpreter, so no decision fixture is asserted by hand.

## Evidence boundary and limits

Allowed input is limited to repository/commit identity, engine and analyzer
provenance, configuration/artifact hashes, normalized finding identity,
severity facts, normalized evidence facts, bounded relative locations, bounded
signals, dependency facts, evidence hashes, analyzer execution health and
coverage facts.

The following are forbidden:

- source archives or arbitrary source files;
- source content or excerpts;
- secrets, credentials, environment-variable maps and authentication headers;
- GitHub or Fendix tokens;
- raw/unbounded scanner logs;
- request/response or other unredacted HTTP bodies, including probe payloads;
- absolute or user-identifying local filesystem paths;
- a client-selected verdict, risk score, confidence conclusion, tier, blocking
  status, coverage conclusion or managed exit code.

The JSON request limit is 8 MiB after decompression and before persistence.
Canonical evidence is also limited to 8 MiB. Limits include 10,000 findings,
200 analyzers, 20 locations and 20 evidence hashes per finding, and bounded
strings defined in the schemas. Compression ratio is limited to 10:1 when a
future transport adds compression. v2 accepts no archives and performs no
server-side extraction. Larger approved artifacts require a future private,
pre-authorized object upload flow with content type, byte limit, digest,
retention and one-submission binding; that flow is outside v2.

## Identifier separation

- `scan_execution_id` identifies one workflow execution attempt.
- `evidence_submission_id` identifies one accepted submission/receipt.
- `decision_record_id` identifies the immutable backend decision record.
- a future `publication_output_id` identifies one provider publication command
  or result and is never any of the three IDs above.

The GitHub pilot idempotency key is:

```text
github:<repository_id>:<run_id>:<run_attempt>:<head_sha>
```

The database must enforce uniqueness on `(binding_id, idempotency_key)`.
Insertion and receipt selection occur in one transaction. A retry with the same
key and exact artifact hash returns the original receipt and does not create a
second execution, finding set, evaluation, Decision Record or publication. The
same key with a different artifact hash returns audited
`409 idempotency_conflict`. Concurrent requests are governed by the same unique
constraint and transaction, not a check-then-insert sequence.

## State machine

Unchanged from v1 (`state-machine.json`).

| From                                   | To           | Owner                | External behavior                          | Audit event               |
| -------------------------------------- | ------------ | -------------------- | ------------------------------------------ | ------------------------- |
| none                                   | `accepted`   | ingestion API        | `202`, stable IDs and status URL           | `ci.submission.accepted`  |
| `accepted`                             | `validating` | validation worker    | poll remains retryable                     | `ci.validation.started`   |
| `validating`                           | `evaluating` | validation worker    | evidence and binding validated             | `ci.validation.succeeded` |
| `validating`                           | `failed`     | validation worker    | terminal safe error; never PASS            | `ci.validation.failed`    |
| `evaluating`                           | `completed`  | decision worker      | terminal authoritative decision and record | `ci.decision.completed`   |
| `evaluating`                           | `failed`     | decision worker      | terminal safe error; never local fallback  | `ci.evaluation.failed`    |
| `accepted`, `validating`, `evaluating` | `cancelled`  | API/lease reconciler | terminal; late worker result ignored       | `ci.scan.cancelled`       |
| `accepted`, `validating`, `evaluating` | `superseded` | ordering reconciler  | terminal; names newer execution            | `ci.scan.superseded`      |

`completed`, `failed`, `cancelled` and `superseded` are terminal. `accepted`,
`validating` and `evaluating` are retryable processing states. A worker may
retry its current operation without publishing another transition. Terminal
errors expose `retryable=false`; the client starts a new execution/attempt when
the error contract says a new attempt is allowed.

Only the decision worker may create a Decision Record, in the same transaction
that changes `evaluating` to `completed`. Failed, cancelled and superseded
executions have no authoritative record. A policy-evaluation error fails the
execution; it never falls back to severity-only classification or to any client
output.

A newer PR head supersedes every older nonterminal execution for the same
binding and PR. If an older execution completes after the newer head is known,
its compare-and-swap transition loses and it remains superseded. A repeated
GitHub run uses its new `run_attempt`, receives a distinct `scan_execution_id`
and idempotency key, and supersedes the earlier nonterminal attempt. Historical
completed records remain immutable and are never made current for a different
head.

## Polling contract

The Action polls the returned status URL with exponential backoff, full jitter,
a 250 ms minimum, 60 s maximum and 10 minute total decision timeout. It retries
connection resets, timeouts, 429 and 5xx responses while honoring `Retry-After`.
Validation 4xx, binding mismatch, unsupported version and idempotency conflict
are terminal. Resubmission after an ambiguous acceptance uses the identical
idempotency key and bytes. Cancellation is best effort from the Action and is
also enforced by a backend lease/expiry reconciler. Loss or timeout of the
authoritative result never falls back to local success.

## Pilot authentication contract

Unchanged from v1. The pilot credential is a random 256-bit bearer token
prefixed `fxci_`; its prefix plus a nonsecret lookup identifier may be
displayed. Plaintext is shown once at creation and is never stored. The backend
stores SHA-256 of the complete high-entropy token for lookup and compares
candidate/full digests with a constant-time primitive. A server-side pepper may
be added without changing the wire contract.

Every credential row is bound to one environment, tenant/organization, Asset,
provider `github`, immutable repository ID and immutable repository owner ID.
Its allowed scopes are exactly `ci:evidence:write`, `ci:status:read` and, when
enabled, `ci:publication:read`. It is not accepted by user, generic scan,
runner-management or other Asset endpoints.

Organization owners/admins create and revoke credentials. Creation and rotation
return plaintext once. Rotation creates a new credential and permits at most a
24-hour configurable overlap before the old credential is revoked. Each row has
`created_at`, `expires_at`, `revoked_at`, `last_used_at`, `last_used_ip`, safe
prefix and creator/revoker audit references. Maximum lifetime is 90 days for the
pilot. Verification rechecks active binding, environment, scopes, expiry and
revocation on every request.

Audit events are `ci.token.created`, `ci.token.rotated`, `ci.token.revoked`,
`ci.token.authenticated`, and `ci.token.rejected`, without raw tokens or
digests. Limits are per credential, binding and tenant: 30 submission attempts
per hour, 5 concurrent nonterminal executions, 120 status reads per minute and
the evidence byte/finding limits above. Exact production values remain
configuration, but weakening them requires review.

The Action receives the token only through a secret input, invokes GitHub
`::add-mask::` before any diagnostic, keeps it in an environment variable for
the HTTP client, and never passes it in argv. It redacts request headers and
safe exception messages. Logs, process listings, evidence, SARIF, summaries and
artifacts must not contain it.

The authentication interface reserves `credential_kind` with `asset_token/v1`
for the pilot and `github_oidc/v1` for a future exchange. OIDC must produce the
same internal principal and binding; it cannot change ingestion or decision
contracts.

## Compatibility matrix

| Component         | Pilot version                               | Supported range                         | Older/newer behavior                                                      |
| ----------------- | ------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------- |
| Action interface  | future managed major `v2`                   | exactly its reviewed major              | v1 remains local-only; unknown managed input fails before scan            |
| Engine            | minimum `v3.4.1` plus accepted build digest | backend allowlist                       | older/unknown build is `unsupported_version`, never PASS                  |
| Evidence schema   | `managed-ci/v2` (`evidence-manifest/v2`)    | exactly v2                              | v1 and any unknown major are rejected with `unsupported_version`          |
| Finding policy    | `1.0.0` (`engine.finding_policy_version`)   | the backend's supported set             | unsupported version is `unsupported_version`, never severity-only         |
| Ingestion API     | `/api/ci/v2`                                | v2                                      | unsupported media/API version is 415/400 with standard error              |
| Decision schema   | `authoritative-decision/v1`                 | exactly v1 initially                    | Action refuses unknown version and fails closed                           |
| Frontend consumer | generated types/fixtures for v2             | current and previous API during rollout | unknown decision schema renders unsupported/error, never inferred verdict |

The Action `version` input contract for managed mode is an exact SemVer release,
never `latest`. The installer receives it via `FENDIX_VERSION`, verifies the
release checksum and required signing identity, and verifies `fendix version`
matches before scanning.

Additive optional fields may be introduced inside v2 only when old consumers
ignore them without semantic change. Required, enum, meaning or authority
changes require v3. New evidence facts arrive only with a new finding-policy
version, and a backend must support that version before any producer emits
its facts. A supported version receives at least 180 days' deprecation notice
once released, and one prior Action major remains downloadable. Rollback keeps
the backend reading the prior supported schema and the frontend reading the
prior decision schema until the migration window closes. Feature negotiation,
if needed, is a server capability list fetched before scan; absence means v2
only.

## `extra-args` replacement

Managed mode will use typed Action inputs. It will not interpolate or word-split
raw input.

| Classification      | Examples                                                                                                                                                       | Managed behavior                                                             |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Safe supported      | exact engine version, SAST/SCA enablement, output/SARIF toggle, polling timeout within server bounds                                                           | typed and allowlisted                                                        |
| Deprecated          | `extra-args` itself and duplicate report/output flags                                                                                                          | warning in local v1; rejected in managed v2                                  |
| Prohibited          | auth headers/tokens, `--auth`, arbitrary URL/DAST target, repo-local plugins, alternate backend/tenant/Asset/repository, disabling coverage/required analyzers | validation error before execution                                            |
| Advanced local-only | baselines, differential scope, custom plugins, custom engine path, experimental analyzer flags, `--enforce-confidence=false`                                   | retains standalone CLI support; cannot affect managed authoritative evidence |

Differential results may be rendered for presentation, but the submitted
managed evidence always describes the exact full PR head. Secret-bearing values
never appear in an echoed command. Compatibility guidance will direct existing
users to explicit local CLI steps when they need advanced local-only behavior.
