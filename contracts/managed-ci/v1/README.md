# Managed CI contract v1

> **Superseded by [`managed-ci/v2`](../v2/README.md) before release.** v1 carries
> no normalized evidence facts, so an authoritative confidence calculation
> cannot be made from it. A v1 document is rejected with `unsupported_version`.
> This bundle is retained for history and is no longer exported.

## Authority boundary

The runner may attest normalized facts. It may not select an authoritative
verdict, confidence conclusion, risk score, coverage conclusion, exit code or
publication outcome. `producer_diagnostics` is explicitly untrusted and the
backend must exclude it from policy inputs. A managed Decision Record exists
only after backend evaluation reaches `completed`.

The GitHub App, if restored, is an adapter to these contracts. It cannot become
a separate decision authority.

## Schemas

| Schema                              | Purpose                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------ |
| `managed-scan-context`              | Tenant, Asset, immutable repository, exact commit and workflow execution identity.   |
| `evidence-manifest`                 | Minimal normalized evidence, provenance, analyzer health, coverage facts and hashes. |
| `analyzer-execution-result`         | One analyzer's identity and execution outcome.                                       |
| `coverage-state`                    | Observable coverage inputs; it deliberately carries no client coverage conclusion.   |
| `evidence-submission-request`       | Versioned submission envelope and idempotency identity.                              |
| `evidence-submission-response`      | Stable accepted identifiers and polling location.                                    |
| `scan-status-response`              | Polling state and terminal decision/error projection.                                |
| `authoritative-decision-response`   | Backend-owned decision and release-gate result.                                      |
| `decision-record-reference`         | Immutable record ID, revision, digest and canonical URL.                             |
| `sanitized-github-summary`          | Bounded structured input for a GitHub step summary.                                  |
| `sanitized-sarif-publication-input` | Bounded result locations/messages derived from accepted evidence.                    |
| `error-response`                    | Stable code, safe message, retryability and field codes.                             |

Unknown properties are rejected. Unsupported version constants return
`unsupported_version`; they are not interpreted as the closest known version.

## Evidence boundary and limits

Allowed input is limited to repository/commit identity, engine and analyzer
provenance, configuration/artifact hashes, normalized finding identity,
severity facts, bounded relative locations, bounded signals, dependency facts,
evidence hashes, analyzer execution health and coverage facts.

The following are forbidden:

- source archives or arbitrary source files;
- source content or excerpts in v1;
- secrets, credentials, environment-variable maps and authentication headers;
- GitHub or Fendix tokens;
- raw/unbounded scanner logs;
- request/response or other unredacted HTTP bodies;
- absolute or user-identifying local filesystem paths;
- a client-selected verdict, risk score, confidence conclusion, coverage
  conclusion or managed exit code.

The JSON request limit is 8 MiB after decompression and before persistence.
Canonical evidence is also limited to 8 MiB. Limits include 10,000 findings,
200 analyzers, 20 locations and 20 evidence hashes per finding, and bounded
strings defined in the schemas. Compression ratio is limited to 10:1 when a
future transport adds compression. V1 accepts no archives and performs no
server-side extraction. Larger approved artifacts require a future private,
pre-authorized object upload flow with content type, byte limit, digest,
retention and one-submission binding; that flow is outside v1.

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
executions have no authoritative record.

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

The pilot credential is a random 256-bit bearer token prefixed `fxci_`; its
prefix plus a nonsecret lookup identifier may be displayed. Plaintext is shown
once at creation and is never stored. The backend stores SHA-256 of the complete
high-entropy token for lookup and compares candidate/full digests with a
constant-time primitive. A server-side pepper may be added without changing the
wire contract.

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
| Evidence schema   | `managed-ci/v1`                             | exactly v1 initially                    | unknown major is rejected with `unsupported_version`                      |
| Ingestion API     | `/api/ci/v1`                                | v1                                      | unsupported media/API version is 415/400 with standard error              |
| Decision schema   | `authoritative-decision/v1`                 | exactly v1 initially                    | Action refuses unknown version and fails closed                           |
| Frontend consumer | generated types/fixtures for v1             | current and previous API during rollout | unknown decision schema renders unsupported/error, never inferred verdict |

The Action `version` input contract for managed mode is an exact SemVer release,
never `latest`. The installer receives it via `FENDIX_VERSION`, verifies the
release checksum and required signing identity, and verifies `fendix version`
matches before scanning. Phase 0 does not change or release the Action.

Additive optional fields may be introduced inside v1 only when old consumers
ignore them without semantic change. Required, enum, meaning or authority
changes require v2. A supported version receives at least 180 days' deprecation
notice and one prior Action major remains downloadable. Rollback keeps backend
reading the prior supported schema and frontend reading the prior decision
schema until the migration window closes. Feature negotiation, if needed, is a
server capability list fetched before scan; absence means v1 only.

## `extra-args` replacement

Managed mode will use typed Action inputs. It will not interpolate or word-split
raw input.

| Classification      | Examples                                                                                                                                                       | Managed behavior                                                             |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Safe supported      | exact engine version, SAST/SCA enablement, output/SARIF toggle, polling timeout within server bounds                                                           | typed and allowlisted                                                        |
| Deprecated          | `extra-args` itself and duplicate report/output flags                                                                                                          | warning in local v1; rejected in managed v2                                  |
| Prohibited          | auth headers/tokens, `--auth`, arbitrary URL/DAST target, repo-local plugins, alternate backend/tenant/Asset/repository, disabling coverage/required analyzers | validation error before execution                                            |
| Advanced local-only | baselines, differential scope, custom plugins, custom engine path, experimental analyzer flags                                                                 | retains standalone CLI support; cannot affect managed authoritative evidence |

Differential results may be rendered for presentation, but the submitted
managed evidence always describes the exact full PR head. Secret-bearing values
never appear in an echoed command. Compatibility guidance will direct existing
users to explicit local CLI steps when they need advanced local-only behavior.
