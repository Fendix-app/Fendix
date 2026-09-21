# ADR-010: CI-first, backend-authoritative security decisions

## Status

**Accepted for Phase 0 — contracts and conformance only.**

Phase 0 is authorized to establish version-controlled architecture, schemas,
fixtures, conformance tests, and the Phase 1 plan. It does not authorize the
managed runtime, deployment, release, DNS, credential, migration, or public
claims changes. The current runtime remains NOT READY for a managed CI launch.

Date: 2026-09-21

This is an evidence-based architecture record. It does not authorize an
application change, deployment, release, DNS change, credential change, merge,
push, or announcement.

## Executive recommendation

Use customer-controlled CI as the primary managed integration for the first
Fendix product release. Defer the hosted GitHub App scan executor. Preserve the
useful event, evidence, decision, idempotency, and publication boundaries from
ADR-009 so a future GitHub App becomes another adapter to the same backend
contract.

The GitHub App may return only as an adapter to the same managed scan,
evidence, evaluation, Decision Record, and publication contracts. It cannot
calculate, persist, or publish a separate authoritative decision.

Standalone or local engine decisions remain local diagnostic outcomes. They
must never be stored, labeled, or presented as managed Fendix Security Decision
Records; only the backend's authoritative terminal evaluation can create one.

The desired managed flow does **not** exist today. The Marketplace Action runs
the engine locally, derives a local exit code, and optionally uploads SARIF. It
does not authenticate to Fendix SaaS, bind the run to an Asset or immutable
repository identity, submit evidence, receive a backend decision, create an
immutable Security Decision Record, write a GitHub step summary, or link to a
dashboard record.

The backend has reusable pieces, including multi-tenant scans, runner report
ingestion, normalized findings, coverage accounting, Celery, API keys, Assets,
and a backend release-decision projection. Its documented direct-CI path is not
a production-grade managed CI contract: it needs two long-lived secrets plus
two identifiers, is gated as an Enterprise self-hosted runner, lacks immutable
repository/commit binding, has no submission idempotency key or immutable
Decision Record, returns no authoritative decision or deep link, and accepts
client-produced finding decisions and analyzer telemetry as evidence.

The smallest safe pilot is therefore a new CI submission surface, not a wrapper
around the current runner endpoints:

1. scan an exact checked-out pull-request head on the customer's runner;
2. create a bounded, versioned and sanitized evidence envelope;
3. authenticate with one Asset/repository-scoped credential for the pilot;
4. authorize the immutable repository-to-Asset binding in the backend;
5. persist the accepted bytes and digest, normalize evidence, correlate it, and
   calculate policy in the backend;
6. write an immutable Security Decision Record;
7. let the Action poll a bounded status endpoint;
8. map the backend decision to the job conclusion and link the exact record;
9. optionally render sanitized SARIF from the accepted evidence/record.

The backend must ignore any client-supplied final verdict. It must also rebuild
finding-level policy inputs from allowed evidence fields instead of accepting
the engine's aggregate decision counts as authority.

## Evidence base and workspace state

All evidence below is from executable code, tests, schemas, fixtures, and
configuration at these revisions. Marketing copy is recorded only when it
conflicts with executable behavior.

| Component                                              | Repository root                                                                          | Branch and SHA                                                              | Worktree state                            |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ----------------------------------------- |
| Engine, Action, examples, installer and standalone App | `/Users/asaied/WorkDir/Fendix/fendix-services/Fendix`                                    | `main` at `514cf4074da6549453976afdc7370125567427c0`                        | untracked ADR-009 only before this record |
| Engine secondary worktree                              | `/Users/asaied/WorkDir/Fendix/fendix-services/Fendix/.worktrees/decision-integrity-core` | `fix/decision-integrity-core` at `f37673b2d0591dd3fa95e9cd263e5e0b22a154b1` | clean                                     |
| Django backend                                         | `/Users/asaied/WorkDir/Fendix/fendix-services/fendix-backend`                            | `main` at `525a76aea3b334719a297a66961443cc27c53dd9`                        | clean                                     |
| Next.js frontend                                       | `/Users/asaied/WorkDir/Fendix/fendix-services/fendix_frontend`                           | `main` at `4b679e3aedbda93ab47de6119377429d8c1c2a49`                        | clean                                     |
| Homebrew and install mirror                            | `/Users/asaied/WorkDir/Fendix/fendix-services/homebrew-fendix`                           | `main` at `9ae5cdbcdda31cd0268dcf93ee11de9c1e64a653`                        | clean                                     |

The engine repository's remote is `https://github.com/Fendix-app/Fendix.git`.
The backend and frontend remotes still use the personal
`Abdel-RahmanSaied/*` namespace. Homebrew uses
`https://github.com/Fendix-app/homebrew-fendix.git`.

## Current implemented CI sequence

### Marketplace composite Action

`action.yml` implements this exact path:

1. The caller normally checks out source. The Action does not verify the
   checkout SHA, repository identity, dirty state, event type, or whether the
   checkout matches the pull-request head.
2. `Install Fendix` pipes `https://get.fendix.dev/install.sh` to `sh`.
   `action.yml` passes a non-latest version as an argv option, while
   `scripts/install.sh` reads `FENDIX_VERSION` from the environment and does not
   parse that option. The Action's `version` pin is therefore ineffective for
   non-`latest` values.
3. `fendix engine sync` resolves the Python engine and fails if it cannot.
4. The scan step builds a Bash array from `code`, `url`, `spec`, `fail-on`,
   `format`, `output`, and `diff`. Ordinary inputs are passed through the
   environment and array elements. `extra-args` is intentionally word-split.
5. On pull requests, the default `diff=auto` fetches the base and adds
   `--diff=origin/$GITHUB_BASE_REF`; it does not perform the pilot's required
   exact full-head scan.
6. The command is echoed and then executed as `fendix scan`. This prints all
   raw `extra-args`; credentials supplied there can leak to logs. No explicit
   `::add-mask::` is used.
7. The Action records the local engine exit code but temporarily exits zero so
   SARIF can upload.
8. `github/codeql-action/upload-sarif@v3` uploads the caller-selected SARIF.
   The Action reference is a mutable tag.
9. The final step maps engine exit 0/1/other directly to workflow success,
   policy failure, or scan error.

The Action has no SaaS URL, credential, organization, Asset, immutable GitHub
repository ID, commit metadata, workflow/run identity, evidence submission,
polling, Decision Record ID, step summary, or dashboard-link input/output.

### Stage-by-stage trace

| Stage                    | Exact evidence                                            | Inputs and outputs                                                      | Trust boundary                                          | Failure/retry                                                                            | Test evidence                                                       |
| ------------------------ | --------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Install                  | `action.yml`, step `Install Fendix`; `scripts/install.sh` | Action `version`; binary on `PATH`                                      | Fendix distribution and runner                          | curl/install is one attempt; script verifies SHA-256 and optionally Cosign if present    | installer has its own release checks; no Action contract test found |
| Python engine resolution | `action.yml`, `Sync Fendix Python engine`                 | optional `engine_path`; resolved engine                                 | checked-out workflow and runner filesystem              | fails job immediately; no retry                                                          | engine sync tests exist; Action wiring is not tested                |
| Scope selection          | `action.yml`, `Run Fendix scan`                           | code/url/spec/diff and GitHub env                                       | PR head can control Action inputs and repository config | base fetch errors are ignored and a possibly invalid diff is still passed                | no Action-specific test found                                       |
| Config load              | engine configuration loader and `.fendix.yaml` support    | CLI flags plus repository configuration and ignore file                 | scanned repository may be attacker-controlled           | parse errors fail; valid malicious exclusions can suppress evidence                      | engine config tests exist; no trusted-CI-policy test                |
| Analyzer execution       | engine orchestrator and scanner packages                  | checked-out files; optional network target                              | customer runner executes Fendix and external analyzers  | per-analyzer states are recorded; some failures are nonfatal unless strict flags are set | broad engine unit/E2E coverage                                      |
| Evidence/correlation     | engine evidence, confidence and correlator packages       | analyzer findings                                                       | local process                                           | deterministic local processing                                                           | engine fixtures and cross-language vectors                          |
| Local policy             | engine decision package, policy version `1.0.0`           | local normalized findings/config                                        | local process and repository-selected inputs            | BLOCK only when engine policy supports it                                                | engine decision tests                                               |
| Coverage enforcement     | engine orchestrator flags                                 | `--fail-on-scanner-error`, `--fail-on-coverage-gap`, required analyzers | caller-controlled workflow                              | current Action does not pass these flags; missing/failed analyzers can still exit 0      | engine tests prove strict behavior only when enabled                |
| Report                   | engine JSON/SARIF reporters                               | local evidence                                                          | runner filesystem                                       | report errors return engine error                                                        | reporter tests                                                      |
| GitHub output            | `upload-sarif@v3`                                         | local SARIF                                                             | GitHub API and workflow token                           | Action controls its own retry; upload failure affects step                               | no repository-level Action integration test                         |
| Gate                     | `action.yml`, `Enforce fail-on threshold`                 | local engine exit code                                                  | local process                                           | no retry; no backend consultation                                                        | no Action test                                                      |

### Reference workflow

`examples/github-actions/fendix-scan.yml` is a second, different implementation:

- it pins third-party Actions to full SHAs;
- it installs `github.com/Abdel-RahmanSaied/Fendix/cmd/fendix@v0.15.0`, an old
  personal-namespace version rather than the current official release;
- it caches a baseline, runs local JSON, re-renders SARIF, uploads it, posts a
  new pull-request comment, and enforces the local exit;
- it asks for `pull-requests: write` on untrusted pull-request workflows;
- the comment interpolates finding title/location into Markdown without a
  bounded escaping contract;
- it has no backend call, Decision Record, immutable repository binding, or
  authoritative dashboard link.

The example's cache restore key establishes neither immutable baseline identity
nor provenance. It is unsuitable for the exact full-head pilot.

### Existing direct-CI publishing path

`fendix-backend/docs/runner-protocol.md`, section “Publishing scan results from
CI,” documents a separate two-call path:

1. `POST /api/scans` with a human/user `FENDIX_API_KEY`, organization UUID and
   runner UUID creates a queued scan.
2. `POST /api/runners/jobs/{scan_id}/result` with a separate
   `FENDIX_RUNNER_TOKEN` submits engine JSON directly, without claiming work.

This path is real and tested at the endpoint level, but the official Action
does not use it. It requires the Enterprise `self_hosted_runners` feature and
four coordinated values (`API key`, `runner token`, `runner ID`, `org ID`). It
uses the generic scan/runner trust model, not a CI repository binding.

## Current decision authority

### Local engine authority

The engine computes finding decisions and a local process exit. A BLOCK finding
produces exit 1. Hard execution errors produce exit 2. Coverage/analyzer gaps
produce exit 2 only when strict flags such as `--fail-on-coverage-gap`,
`--fail-on-scanner-error`, or required analyzers are active. The current Action
sets only `--fail-on`; it can therefore report workflow success with incomplete
analysis.

`go/internal/reporters/json.go` can carry backend projection fields such as
`release_decision`, `coverage_state`, and `decision_policy_version`, but a live
local scan does not populate a backend decision. Those fields support reports
that were enriched elsewhere.

### Backend authority today

`backend/scanning/models.py::Scan.recompute_release_decision` calls the backend
policy in `backend/scanning/decision_policy.py` and stores
`release_decision`, `coverage_state`, `decision_policy_version`, and rationale.
The current backend policy version is `2.0.0`; the engine finding-policy version
is `1.0.0`. These versions describe different layers and are not synchronized.

`backend/runners/ingest.py::ingest_runner_report` normalizes and persists a
runner report, then recomputes the aggregate backend release decision. It does
not accept the report's `metadata.release_decision` as the stored backend
verdict. It does, however, rely on client-produced findings, their normalized
decision fields/counts, and client-produced scanner status/coverage. The
backend does not re-run finding-level evaluation from raw source evidence.

The result endpoint returns only `{scan_id, status}`. The current CI caller has
no direct authoritative decision response and no Decision Record URL.

### Divergence finding

The same nominal repository can produce different CI and dashboard results:

- the Action exits from local engine policy and local configuration;
- the backend may later apply release policy `2.0.0` to a separately submitted
  report;
- local strict coverage flags are absent;
- backend coverage requirements depend on mode and persisted telemetry;
- the local and backend policy versions are independent;
- repository baselines/ignore files may suppress local evidence before the
  backend ever sees it.

`BLOCK`, `WARN`, and `INFO` are finding-level engine concepts, while backend
`pass`, `warn`, `block`, and `incomplete` are scan-level outcomes. They are not
one shared enum. `INCOMPLETE` is a backend scan decision, not a fourth finding
status. Current copy sometimes presents them as one gate, which is inaccurate.

## Backend capability inventory

### Reusable endpoints

| URL/method                                | Auth/permission                                                                                                     | Tenant resolution                                     | Schema/result                                             | Idempotency and transaction                                                                            | Background behavior/tests                                              |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `POST /api/scans`                         | API key/JWT/session; `IsAuthenticated`, `HasScope`, `OrgPolicyObjectPermission`; `scan:write`; scan-create throttle | personal user or membership in requested organization | `LaunchScanSerializer`; returns mutable `Scan` projection | atomic quota and create; no external CI idempotency key                                                | Celery dispatch with recovery/refund; scan/quota/dispatch tests        |
| `GET /api/scans/{id}`                     | authenticated; `scan:read`; object tenant checks                                                                    | scan owner or organization membership                 | `ScanResultSerializer` with scan/findings                 | read only                                                                                              | frontend polling tests; scan view tests                                |
| `POST /api/scans/import`                  | authenticated; `scan:write`; SARIF feature/quota checks                                                             | selected workspace                                    | multipart SARIF 2.1.0, max 10 MiB                         | creates a scan; no CI run key                                                                          | Celery import; parser/import tests                                     |
| `POST /api/runners`                       | authenticated org admin; `runners:write`; Enterprise feature                                                        | explicit organization with role check                 | name/org; returns runner and one-time token               | one runner row/token                                                                                   | runner management tests                                                |
| `POST /api/runners/heartbeat`             | custom `X-Runner-Token`; DRF auth/throttling disabled                                                               | token resolves one organization runner                | version/runtime; returns pending count                    | touch update                                                                                           | runner protocol tests                                                  |
| `POST /api/runners/claim`                 | custom runner token                                                                                                 | token-bound runner                                    | oldest job/config/min version                             | conditional update makes claim atomic                                                                  | polling; claim/race tests                                              |
| `POST /api/runners/jobs/{scan_id}/result` | custom runner token; no DRF throttle                                                                                | scan must be assigned to token-bound runner           | free-form engine JSON or error; returns id/status         | terminal precheck gives 409 on replay, but no request key/body digest and no locked ingest transaction | synchronous ingestion; validation/replay/foreign-runner/coverage tests |
| backend GitHub webhook                    | raw HMAC and installation lookup                                                                                    | installation maps to one organization                 | GitHub event                                              | application-level `(org, repo text, head SHA)` dedupe, no database uniqueness                          | Celery clone/scan/check path; integration tests                        |

### Reusable data and services

- `Scan`, `ScanFinding`, `Asset`, organization membership, quotas, API keys,
  Celery, audit events, coverage telemetry, report generation and release-policy
  calculation are reusable.
- `Scan` already stores GitHub repository text, pull-request number and commit
  SHA, but the public scan serializer does not expose all of that provenance.
- Assets can represent repositories, but there is no immutable provider
  repository-ID binding with rename/transfer rules.
- API keys support scopes, organization binding, expiry, IP restrictions,
  revocation and last-use tracking. They are user credentials and are not
  repository/Asset scoped.
- Runner tokens are random, shown once, hash-stored and revocable. They scope to
  an organization runner, not an Asset/repository/workflow.
- Existing scan processing and runner ingestion are synchronous around database
  normalization, with Celery available for a new asynchronous submission
  processor.
- Existing filesystem report storage is not a suitable immutable evidence
  archive across deployment replacements. There is no production object-store
  integration for this contract.
- Plan retention is mutable scan retention. Deleting a scan cascades evidence.
  That is not an immutable Decision Record retention policy.
- The current terminal-result check is vulnerable to a concurrent submit race:
  two requests can observe queued/running before either commits. A unique receipt
  plus row lock/conditional transition is required.
- Proxy configuration commonly caps request bodies at 12 MiB, and SARIF import
  explicitly caps 10 MiB. Runner ingestion caps findings and per-field sizes but
  has no dedicated compressed/uncompressed CI-envelope limit.

### Missing backend capabilities

1. CI integration/binding model keyed by provider plus immutable repository ID.
2. One-purpose Asset-scoped ingestion credential and rotation overlap.
3. GitHub OIDC exchange and replay store.
4. Versioned CI submission schema with exact-byte digest.
5. Atomic idempotency receipt and conflict semantics.
6. Server-authorized scan manifest/policy input.
7. Evidence sanitization validation and provenance allowlist.
8. Backend finding-level evaluation that ignores client verdict/count fields.
9. Immutable evidence artifact and Security Decision Record models.
10. CI lifecycle, cancellation, expiry and supersession states.
11. Status/decision endpoint with deep link and stable terminal response.
12. Per-credential rate, concurrency, byte and finding limits.
13. Durable audit events for accepted/rejected evidence and decisions.

## Frontend capability inventory

The current scan detail route can display ordinary CI-published runner results
as a normal scan if the caller manually uses the two-call runner protocol.
`app/lib/api.ts` retrieves scans and the scan detail page renders status,
findings, release decision, coverage state, analyzer gaps and policy versions.
`ScanProgress` polls running scans. `ReleaseDecisionBanner` has tests for pass,
warn, block and incomplete combinations. English and Arabic infrastructure and
messages exist for current scan states.

The frontend cannot present the proposed managed CI record completely:

- no immutable Decision Record route/model exists;
- the existing “Security Decision Record” public page is illustrative, and
  release-approval export is an exception record, not this record;
- scan responses omit important stored GitHub provenance;
- there is no provider repository ID, workflow, run, attempt, ref, trigger SHA,
  scanned SHA, evidence digest, artifact receipt or engine provenance;
- there are no accepted/uploaded/processing/decided/expired/cancelled/
  superseded CI states;
- no distinction exists between a dashboard-created scan, runner job, managed
  backend GitHub scan, and CI-originated submission;
- no GitHub run/commit backlink or canonical CI deep link exists;
- settings expose the current GitHub App and two-secret Runner setup, not a
  selected-repository CI binding;
- empty/error/cancelled/superseded translations and RTL layouts for the new
  lifecycle have not been implemented or tested.

The browser must remain a renderer. It must never infer a decision from finding
counts, local engine fields, or partial evidence.

## Authentication and immutable binding

### Current findings

The official Action accepts no backend credential. The documented direct-CI
flow accepts a broad user API key plus an organization runner token. Neither is
bound to an immutable GitHub repository ID, Asset, workflow, event, ref or SHA.
The user supplies a target-like string such as `myrepo@$SHA`; it is not verified
against GitHub identity. A compromised token can submit evidence for any scan
assigned to that runner, and a broad API key can create scans within its allowed
workspace.

Repository names are mutable. Any binding based only on `owner/name` becomes
ambiguous after rename or transfer. The binding must use GitHub's numeric
`repository_id` and `repository_owner_id`, retain names only for display, update
display names on trusted observations, and quarantine a transfer until an
authorized administrator rebinds the Asset.

### Pilot credential recommendation

Create one new credential type for the pilot:

- scoped to exactly one organization, Asset, provider and immutable repository
  ID;
- permissions limited to `ci:evidence:write`, `ci:status:read` and optional
  `ci:artifact:read` for the submission it creates;
- random high entropy, shown once, hash-stored, expiring, revocable, rate-limited,
  and supporting a short rotation overlap;
- never accepted by human/dashboard or generic scan endpoints;
- one credential in `FENDIX_CI_TOKEN`; no runner token, runner ID, organization
  ID, or broad user API key in the workflow;
- never included in argv, JSON, report, SARIF, artifact, summary or logs; the
  Action registers the exact secret for GitHub masking before any diagnostics.

Fork pull requests do not receive repository secrets. In the pilot, a fork PR
may run a local scan but must be reported as “not submitted to Fendix” and must
not be treated as a backend decision. Do not use `pull_request_target` to execute
or scan untrusted fork code with secrets.

### Long-term GitHub OIDC recommendation

GitHub.com's issuer is `https://token.actions.githubusercontent.com`. GitHub's
documented token includes `jti`, timestamps, repository and owner IDs, run ID and
attempt, event, ref, trigger SHA, workflow identity, runner environment and,
for reusable workflows, `job_workflow_ref`/`job_workflow_sha`. See the
[OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) and
[reusable workflow guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows).

The backend exchange must:

1. fetch and cache GitHub's discovery/JWKS data with bounded refresh by `kid`;
2. require the expected issuer, exact Fendix audience, approved algorithm,
   valid signature, `nbf`, `iat`, `exp`, nonempty `jti`, repository IDs, run ID,
   run attempt and workflow claims;
3. compare repository/owner IDs to the enabled Fendix binding;
4. allow only configured events, workflow refs and reusable workflow SHA;
5. reject `pull_request_target` for source scanning;
6. store the token hash/`jti` and a unique run-attempt exchange receipt to stop
   replay, without storing or logging the raw JWT;
7. return a minutes-lived token bound to one submission nonce, repository,
   Asset, run, attempt and maximum byte count;
8. recheck binding status and token lifetime on evidence upload.

OIDC proves that GitHub issued identity to a workflow job. It does not prove that
the engine ran honestly, that the checked-out code matches an arbitrary field,
or that the evidence is true. A repository administrator controls workflow
code. Pinning a Fendix-owned reusable workflow by SHA and requiring
`job_workflow_ref`/`job_workflow_sha` materially narrows that trust, but the
backend must still describe the evidence as an authenticated customer-runner
attestation.

For pull-request events, GitHub's workflow trigger SHA may represent a merge
commit while `github.event.pull_request.head.sha` is the exact head. The envelope
must carry both `trigger_sha` and `scanned_sha`, and the Action must check out and
verify `scanned_sha` before scanning. OIDC directly authenticates the run context,
not the truth of the Action-supplied head SHA. A future GitHub read adapter can
independently confirm private-repository PR-head relationships. Until then the
record must retain this trust limitation.

OIDC is the long-term default for GitHub.com. The scoped token is the pilot
default because it requires less backend identity infrastructure and also works
on GitHub Enterprise Server and non-GitHub CI. GHES support, fork submission,
custom subject templates and organization-wide reusable-workflow enforcement are
deferred.

## Threat model

| Threat                         | Current mitigation                                         | Gap                                                                           | Required implementation/test                                                                                              |
| ------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Forged evidence                | runner/API tokens identify a caller                        | no repository/run provenance; caller controls content                         | Asset-scoped auth/OIDC binding, signed receipt, schema and semantic validation; wrong-binding tests                       |
| Client-selected verdict        | backend ignores `metadata.release_decision`                | client finding decisions/counts still influence aggregate                     | rebuild policy inputs; inject fake PASS/BLOCK/counts and prove no effect                                                  |
| Replay                         | result returns 409 once terminal                           | no idempotency key/digest; race and ambiguous response                        | unique `(binding,key)` plus body digest, atomic receipt; parallel/retry tests                                             |
| Wrong tenant/Asset/repo/SHA    | org-bound runner                                           | caller chooses target and lacks immutable IDs                                 | server resolves binding; mismatch/rename/transfer/cross-tenant tests                                                      |
| Duplicate/out-of-order runs    | limited runner terminal check                              | no PR-head sequence/supersession                                              | explicit run/attempt/observed-at fields and monotonic supersession rules                                                  |
| Stale/superseded head          | none in Action                                             | old run can appear current                                                    | never mutate old record; latest-current-head projection; out-of-order tests                                               |
| Fork PR                        | secrets withheld by GitHub                                 | examples request write permissions and lack explicit state                    | local-only pilot state; no `pull_request_target`; fork fixtures                                                           |
| Malicious repository           | plugin default is restricted; several symlink checks exist | `.fendix.yaml`/ignore can weaken evidence; external tools share host          | backend-issued manifest, disallow repo policy from authoritative scope, sandbox/self-host guidance; poisoned-config tests |
| Command/argument injection     | normal inputs use env and Bash array                       | raw word-split `extra-args`; command echo leaks values                        | remove raw authoritative args, typed inputs only, no secrets in argv; hostile-string tests                                |
| Path/archive/symlink escape    | engine scanners contain targeted protections               | no single Action workspace boundary contract                                  | realpath containment, no archive upload, symlink fixtures for every collector                                             |
| Secret leakage                 | engine secret evidence is redacted at capture              | arbitrary evidence, source snippets, HTTP bodies, Action echo, SARIF/comments | sanitizer before upload and again server-side; canary corpus across logs/body/SARIF/summary                               |
| Excessive payload/DoS          | 20k runner finding cap; proxy limits                       | no credential throttle or decompression contract                              | envelope/body/finding/string limits, streaming hash, decompression ratio, token and tenant quotas                         |
| Compromised token              | revocation exists                                          | current credentials are broad and long-lived                                  | narrow token/expiry/rotation; leak/revoke/overlap tests; OIDC later                                                       |
| OIDC misuse                    | not implemented                                            | issuer/audience/claim/replay pitfalls                                         | strict exchange described above; forged/expired/wrong-aud/replay tests                                                    |
| Cross-tenant read              | scan object permissions                                    | no CI record surface                                                          | deny-by-default queryset and opaque IDs; exhaustive tenant matrix                                                         |
| In-transit tampering           | TLS                                                        | no exact-body receipt                                                         | canonical bytes, SHA-256, persisted receipt, compare before processing                                                    |
| Policy mismatch                | versions are stored                                        | local/backend versions differ and local gate wins                             | backend chooses policy; record both versions; unsupported/missing version tests                                           |
| Unsupported/compromised engine | min version and official runner digest concepts exist      | direct CI skips heartbeat/claim, so runtime is classified custom              | accepted version/build allowlist and signed release provenance; downgrade/unknown-build tests                             |
| Cancellation/timeout           | GitHub can cancel a job                                    | backend has no CI cancellation/abandonment model                              | best-effort cancel plus server expiry; crash/cancel/late-result tests                                                     |
| Publication injection          | local Markdown/SARIF uses client strings                   | unbounded/unescaped GitHub output                                             | backend-derived bounded summary and sanitized SARIF; Markdown/SARIF injection tests                                       |

## CI-first versus hosted GitHub App

| Dimension             | CI-first managed integration                                             | ADR-009 hosted GitHub App executor                                               |
| --------------------- | ------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Onboarding            | workflow plus one scoped secret; OIDC later removes secret               | App installation and repository selection, then hosted execution setup           |
| Time to first scan    | short; uses existing runner/tooling                                      | longer; installation, webhook, clone and worker path                             |
| Source custody        | source remains on customer-controlled runner                             | Fendix clones private source into hosted infrastructure                          |
| Isolation burden      | primarily customer's existing runner boundary                            | Fendix must provide strong multi-tenant clone/analyzer isolation                 |
| Backend authority     | missing today; straightforward new contract                              | also missing in standalone App; ADR-009 designs it                               |
| Decision consistency  | one backend result can drive CI and dashboard                            | one backend result can drive Check/dashboard after publication adapter           |
| Checks/comments       | native job conclusion/summary; SARIF optional                            | richer first-class Check Runs/comments                                           |
| Dashboard/audit       | requires new record and API                                              | requires the same core record and API                                            |
| Self-hosted runners   | natural fit                                                              | would need customer-hosted execution adapter                                     |
| Private repositories  | source never leaves runner                                               | installation token and hosted clone required                                     |
| Fork PRs              | safe local run; authenticated submission needs OIDC or explicit deferral | App can access base installation, but safe fork checkout/execution remains hard  |
| Operations            | API, object storage and policy workers                                   | plus webhook service, GitHub tokens, clone fleet, sandbox and publication outbox |
| Fendix compute cost   | policy/correlation/storage only                                          | scanner CPU, disk, network and isolation capacity                                |
| Customer compute cost | customer pays CI minutes/runner capacity                                 | mostly Fendix pays scan compute                                                  |
| Scale                 | upload/policy workload; naturally distributed scanning                   | Fendix scan worker fleet is bottleneck                                           |
| Portability           | contract maps to GitLab, Bitbucket, Jenkins                              | GitHub-specific event and publication surface                                    |
| Enterprise fit        | strong for source-custody/self-hosting requirements                      | stronger zero-workflow UX, but harder data-processing review                     |
| Support               | workflow/runner/analyzer variability                                     | GitHub App and hosted scanner/infrastructure variability                         |

CI-first is the better first product path. The App remains valuable later for
zero-workflow onboarding, durable Check Runs/comments, repository events and
managed scanning for customers who permit source transfer.

## Reusable contracts from ADR-009

Keep these ADR-009 decisions unchanged:

- GitHub/provider identity is separate from Fendix tenant/Asset identity;
- event, authorized work, evidence, decision and publication are separate
  durable objects;
- immutable numeric repository IDs and exact commit identity;
- exact-byte evidence digests and provenance;
- delivery/run/submission idempotency;
- the engine supplies facts while the backend owns cloud policy;
- accepted engine/schema versions and fail-closed coverage;
- immutable Decision Records and append-only revisions;
- durable publication commands for adapters that mutate provider state;
- explicit cancellation, expiry and supersession;
- frontend rendering only;
- tenant-scoped retention and auditable deletion.

ADR-010 supersedes ADR-009's immediate delivery choice. ADR-009 remains a useful
design for a future managed GitHub event/execution/publication adapter and should
be marked “deferred by ADR-010” when both records are accepted. Its backend core
must not fork into an App-only protocol.

## Target CI architecture

### Chosen first-pilot sequence

1. An administrator binds a Fendix repository Asset to provider `github`,
   immutable repository ID and owner ID, allowed event `pull_request`, allowed
   workflow, and active backend policy.
2. The dashboard creates one repository-scoped pilot token. The customer stores
   it as `FENDIX_CI_TOKEN`.
3. A `pull_request` workflow checks out
   `github.event.pull_request.head.sha` explicitly and verifies
   `git rev-parse HEAD` equals it. `pull_request_target` is rejected.
4. The Action downloads a pinned, signed Fendix release and verifies checksum,
   Cosign identity and engine build identifier. It never uses `latest`.
5. The Action obtains a server-authorized scan manifest. For the pilot the
   manifest requires full-head SAST and SCA, strict coverage, required analyzers,
   no DAST, no repository-local plugins, and no repository-controlled evidence
   exclusions. The manifest is bound to the Asset and policy revision.
6. The engine writes canonical JSON to a private temporary directory. The Action
   captures analyzer health, exact tool/version provenance and checked-out SHA.
7. A sanitizer removes source bodies, credentials, authorization data, full HTTP
   bodies, environment values and unapproved evidence. It writes one canonical
   evidence document and computes SHA-256 over the exact bytes.
8. `POST /api/ci/v1/submissions` authenticates the scoped token, resolves its
   binding server-side, validates context/schema/size/version/digest, creates one
   immutable receipt and returns `202`.
9. A Celery task validates semantics, persists the accepted artifact, normalizes
   findings, correlates them against authorized tenant history, independently
   evaluates finding and release policy, and writes an immutable Decision Record.
10. The Action polls `GET /api/ci/v1/submissions/{id}` with exponential backoff,
    jitter and a ten-minute decision timeout.
11. The terminal response contains the backend decision and canonical dashboard
    URL. The Action writes a bounded `GITHUB_STEP_SUMMARY`, optionally uploads
    backend-derived sanitized SARIF, and exits only from the backend outcome.

Polling is the correct pilot transport. Processing can remain asynchronous while
the Action needs no inbound endpoint, callback secret, durable callback delivery,
or GitHub App. A fully synchronous request risks proxy and workflow timeouts.

### Evidence envelope v1

Illustrative wire shape; the implementation must publish JSON Schema and
cross-repository fixtures before enabling the endpoint:

```json
{
  "schema": "fendix.ci-evidence/1",
  "submission_key": "github:123456:987654:1:0123456789abcdef...",
  "provider": {
    "name": "github",
    "repository_id": "123456",
    "repository_owner_id": "42",
    "repository": "acme/api",
    "event": "pull_request",
    "pull_request": 17,
    "run_id": "987654",
    "run_attempt": 1,
    "workflow_ref": "acme/api/.github/workflows/fendix.yml@refs/heads/main",
    "trigger_sha": "<40-hex>",
    "scanned_sha": "<40-hex>",
    "head_ref": "feature/x",
    "base_ref": "main",
    "runner_environment": "github-hosted"
  },
  "engine": {
    "version": "v3.4.1",
    "build_digest": "sha256:<hex>",
    "report_schema": 2,
    "finding_policy_version": "1.0.0"
  },
  "manifest": {
    "id": "<uuid>",
    "revision": 1,
    "sha256": "<hex>",
    "scan_type": "full-head",
    "required_analyzers": ["sast", "sca"]
  },
  "execution": {
    "started_at": "2026-09-21T12:00:00Z",
    "completed_at": "2026-09-21T12:03:00Z",
    "source_root_digest": "sha256:<optional-tree-manifest-digest>"
  },
  "analyzers": [],
  "findings": [],
  "sanitization": {
    "profile": "ci-default/1",
    "source_excerpts_included": false,
    "redactions": 0
  }
}
```

The envelope must not contain `release_decision`, workflow conclusion or trusted
decision counts. If retained for diagnostics, engine finding decisions must live
under a clearly untrusted `producer_projection` ignored by backend policy.

Each analyzer entry requires analyzer/check ID from an allowlist, version,
status, reason, attempts, duration and coverage counters. Each finding requires
stable fingerprint inputs, rule ID, severity facts, confidence signals,
corroboration identifiers, sanitized locations, dependency/package facts where
applicable, and evidence hashes. Fields must have provenance labels and semantic
validators. Numbers must decode without binary-float loss.

### Sanitization and limits

Default pilot rules:

- never upload repository archives, source files, diffs, environment variables,
  credentials, request authorization headers, cookies, full HTTP bodies, build
  logs, debug bundles, local config files or baselines;
- paths are repository-relative, normalized UTF-8, no absolute path, drive,
  NUL, `..`, symlink target or home directory;
- source excerpts are omitted by default; an eventual opt-in excerpt is at most
  1 KiB per finding and is redacted before and after serialization;
- secret findings contain only rule/type, location, length and one-way digest;
- package evidence contains ecosystem, normalized name/version/advisory IDs,
  not lockfile contents;
- maximum HTTP body 8 MiB, maximum expanded canonical evidence 8 MiB, maximum
  10,000 findings, maximum 200 analyzers, maximum 4 KiB ordinary string, maximum
  16 KiB bounded rationale list, and maximum decompression ratio 10:1;
- no server-side archive extraction in v1;
- server repeats sanitization/deny-pattern validation and rejects rather than
  silently truncating authoritative content.

### Ingestion contract

`POST /api/ci/v1/submissions`

Headers:

- `Authorization: Bearer <Asset-scoped token>` for pilot;
- `Idempotency-Key: <submission_key>`;
- `Digest: sha-256=<base64 exact-body digest>`;
- `Content-Type: application/vnd.fendix.ci-evidence+json;version=1`.

Server behavior:

- resolve organization, Asset, provider and repository binding only from the
  credential/session;
- compare envelope repository and execution context with that binding;
- stream-limit and hash the exact body before JSON decode;
- insert a unique receipt on `(binding_id, idempotency_key)` atomically;
- same key plus same digest returns the original status/record; same key plus a
  different digest returns `409 idempotency_conflict`;
- unsupported schema/engine/manifest returns a stable 4xx code and no scan;
- accepted input returns `202` and never a speculative verdict.

Example acceptance response:

```json
{
  "submission_id": "<uuid>",
  "state": "accepted",
  "evidence_sha256": "<hex>",
  "status_url": "https://api.fendix.dev/api/ci/v1/submissions/<uuid>",
  "expires_at": "2026-09-21T12:15:00Z"
}
```

`GET /api/ci/v1/submissions/{id}` returns only a record allowed by the same
binding/session. Terminal example:

```json
{
  "submission_id": "<uuid>",
  "state": "decided",
  "decision": "block",
  "coverage_state": "complete",
  "decision_record_id": "<uuid>",
  "decision_revision": 1,
  "backend_policy_version": "2.0.0",
  "evidence_sha256": "<hex>",
  "dashboard_url": "https://app.fendix.dev/en/decisions/<uuid>",
  "sarif_url": null
}
```

### Lifecycle, retry and supersession

States are `accepted`, `processing`, `decided`, `failed`, `cancelled`,
`superseded`, and `expired`. Transitions are compare-and-swap and auditable.
Celery delivery is at least once; each processor stage is idempotent by receipt
and artifact digest.

The Action retries transport errors and 429/5xx with capped exponential backoff
and jitter. It retries submission with the same key/body. A network timeout after
acceptance is recovered by resubmitting the same key or polling the deterministic
receipt. Validation 4xx and idempotency conflicts are not retried.

Cancellation is best effort from the Action and definitive from a server lease
timeout. A cancelled GitHub job may not execute cleanup, so the backend expires
abandoned work. A newer run for the same binding and pull request may supersede
an older nonterminal run; it never deletes or mutates the older evidence/record.
A late terminal result remains historical and cannot replace the current-head
projection. Re-runs use a new `run_attempt` and submission key.

### Policy and exit mapping

The server binding chooses the backend policy and records its exact version.
Workflow `fail-on` is either an allowed request constrained by the server policy
or, preferably, an Asset policy setting fetched in the manifest. The client
cannot weaken required analyzers, coverage rules or organization minimums.

The Action maps terminal backend results only:

| Backend result                                         | Action exit                                |
| ------------------------------------------------------ | ------------------------------------------ |
| `pass`                                                 | 0                                          |
| `warn`                                                 | 0, with warning summary                    |
| `block`                                                | 1                                          |
| `incomplete`                                           | 2 and fail closed                          |
| processing timeout/failed/expired/cancelled/superseded | 2, except an actually cancelled GitHub job |

There is no local fallback verdict if the backend is unavailable. The workflow
can have an explicitly configured nonblocking integration mode, but the summary
must say “no authoritative Fendix decision,” never PASS.

### Decision Record

The immutable record includes organization/Asset/binding IDs, provider IDs,
display repository name, PR/run/attempt/workflow, trigger/scanned SHA, evidence
receipt and digest, engine build/schema/finding-policy versions, manifest and
sanitizer versions, analyzer health, correlation snapshot/reference, backend
policy ID/version, coverage state, decision, bounded rationale, timestamps and
supersession relation. A correction creates a new append-only revision linked to
the prior revision; it does not edit history.

The dashboard deep link is server generated. Locale may be added by the client,
but the canonical record ID and authorization do not vary by locale.

### Compatibility and deprecation

- keep local CLI exit behavior as an offline/community mode;
- keep the current runner polling protocol for private targets;
- mark direct CI through generic scan+runner endpoints legacy once the CI API is
  stable, then publish a migration window before disabling it;
- Action v1 remains local-only; release a new major Action version for backend
  authority so existing users do not silently change gates;
- accept evidence schema v1 for a documented window; additive optional fields
  do not change semantics, while semantic changes require a new schema;
- use one backend submission/decision contract for GitHub Actions, GitLab CI,
  Bitbucket Pipelines, Jenkins, future App and future runner adapters.

## Smallest pilot

### Included

- GitHub.com selected repositories;
- pull-request workflows using `pull_request`;
- GitHub-hosted and customer self-hosted runners;
- exact full-head SAST and SCA;
- strict analyzer/coverage requirements;
- one repository/Asset-scoped secret;
- sanitized evidence submission;
- backend normalization, correlation and authoritative policy;
- immutable evidence receipt and Decision Record;
- polling, GitHub step summary and canonical dashboard link;
- optional sanitized SARIF derived from accepted evidence;
- safe job failure from backend `block`/`incomplete`;
- English and Arabic dashboard display for all pilot states.

### Deferred

- GitHub App installation, webhooks, hosted clone/scan and Check/comment adapter;
- GitHub OIDC exchange and fork evidence submission;
- GitHub Enterprise Server;
- push/default-branch, scheduled and deployment events;
- DAST and customer credentials/target authorization;
- differential/baseline gating;
- repository-local plugins and customer-provided analyzer executables;
- source excerpts by default;
- callbacks/webhooks from Fendix to CI;
- GitLab, Bitbucket and Jenkins adapters;
- managed runners and execution billing;
- automated repository transfer acceptance;
- public announcement and removal of compatibility paths.

## Phased implementation plan and gates

### Phase 0 — contracts and threat fixtures

Publish JSON Schema, sanitization contract, state machine, error codes, accepted
engine/build list, policy input contract and cross-repository fixtures. Add
malicious-config, secret-canary, oversized-input and float/Unicode/path boundary
fixtures. Gate: independent contract consumers pass byte-for-byte.

### Phase 1 — backend core

Add binding, scoped credential, receipt, artifact and immutable Decision Record
models; migrations and rollback/recovery drill; ingestion/status APIs; atomic
idempotency; object storage; Celery processor; backend finding-level policy;
audit/rate/concurrency/retention controls. Gate: migration, tenancy, replay,
failure recovery and policy-vector suites pass.

### Phase 2 — Action and engine producer

Fix version pinning; require signed immutable engine release; verify exact head;
consume server manifest; full strict scan; sanitize; submit/poll; summary/SARIF;
map only backend decisions. Remove raw authoritative `extra-args`. Gate: a local
fake backend plus real GitHub Actions matrix validates hosted/self-hosted,
retry/cancel/fork/no-secret behavior.

### Phase 3 — dashboard

Add repository binding/setup, credential rotation/revocation, submission and
Decision Record routes, provenance, analyzer/coverage views, GitHub links and all
lifecycle states in English/Arabic. Gate: generated OpenAPI client, component,
route, accessibility, RTL and tenant-isolation E2E tests.

### Phase 4 — selected-repository pilot

Canary with non-customer test repositories, then selected customer repositories
behind a feature flag. Observe upload bytes, latency, queue depth, policy drift,
timeouts and false incomplete states. Gate: rollback drill, support runbook,
retention/deletion drill and no secret-canary leakage.

### Phase 5 — OIDC and adapters

Add GitHub OIDC exchange and pinned reusable workflow, then treat the future
GitHub App as event/publication/execution adapters over the same core. Gate:
issuer/JWKS outage, replay, fork, repository rename/transfer and workflow-identity
tests.

## Exact required tests

### Contract and producer

1. Every accepted and rejected envelope fixture passes identically in Go/Python.
2. Decimal/numeric boundaries preserve exact JSON precision.
3. Unknown fields, duplicate keys, invalid Unicode, noncanonical paths, absolute
   paths, traversal and symlink escapes are rejected.
4. Unsupported schema, engine version/build, policy and analyzer ID fail closed.
5. Action version input installs the requested version and verifies signature.
6. Exact head mismatch, dirty checkout and `pull_request_target` are rejected.
7. Full-head mode never silently becomes diff mode.
8. Required analyzer missing/failed/skipped produces incomplete, never pass.
9. Poisoned `.fendix.yaml`, `.fendix-ignore`, plugin and baseline cannot weaken
   the authorized manifest.
10. Shell metacharacters/newlines in every input do not execute or corrupt args.
11. Secret canaries do not appear in command lines, logs, JSON, SARIF, artifacts
    or summaries.

### API, authentication and tenancy

12. Token scopes exactly one binding; other organization/Asset/repository and
    object-ID enumeration return indistinguishable denial.
13. Expiry, revocation, rotation overlap, rate and concurrency limits work.
14. Same idempotency key+digest returns the original receipt; different digest
    is 409; concurrent identical requests create one artifact/findings set.
15. A dropped acceptance response recovers without duplicate processing.
16. Body, expanded body, finding, analyzer, string and ratio limits reject early.
17. Stored exact bytes hash to the receipt after process/restart/recovery.
18. Client `pass`, `block`, decision counts and coverage projections cannot alter
    the backend result.
19. Repository rename updates display only; owner transfer quarantines; stale
    tokens cannot submit after transfer/revocation.
20. OIDC suite: valid issuer/audience/signature/time/claims, wrong issuer/aud,
    expired/future token, unknown key, replayed `jti`, wrong repository/owner,
    workflow/event/ref mismatch and JWKS rotation/outage.

### Lifecycle and decision

21. Celery redelivery executes every stage once logically.
22. Cancellation before/after upload and worker crash expire safely.
23. Newer PR head supersedes old nonterminal work; late old result never becomes
    current; rerun attempt remains distinct.
24. Backend and Action use one terminal record for pass/warn/block/incomplete.
25. Correlation/policy vectors are shared with engine facts but backend policy
    owns the aggregate result.
26. Record revisions are append-only and old evidence remains verifiable.
27. Artifact deletion/retention is authorized, audited and does not leave a
    record falsely claiming available proof.

### Frontend and GitHub

28. Decision pages cover loading, empty, accepted, processing, decided, failed,
    expired, cancelled, superseded and incomplete states.
29. EN/AR copy, RTL layout, keyboard/focus, screen-reader names and narrow mobile
    widths pass.
30. GitHub run/commit links are escaped and derived from bound provider data.
31. Summary Markdown and SARIF resist title/path/URL injection and obey bounds.
32. Optional SARIF describes the accepted evidence digest and cannot change the
    authoritative decision.
33. Fork PR has no secret and cannot be mislabeled as backend PASS.
34. End-to-end GitHub-hosted and self-hosted runs produce the same stored record,
    summary link and workflow conclusion.

## Cost and operational estimate

Assumptions for an illustrative pilot: 10,000 submissions/month, average 1 MiB
sanitized artifact, 90-day retention, 30 GiB steady-state evidence, and existing
backend/Redis/Celery/Postgres capacity with some headroom.

- Customer cost: scan CPU, disk and network remain on GitHub-hosted minutes or
  the customer's self-hosted runner. Fendix does not pay repository clone or
  analyzer compute.
- New Fendix resource: one private S3-compatible evidence bucket with encryption,
  lifecycle, blocked public access and a narrowly scoped worker role. Amazon S3
  bills storage, requests, retrieval/transfer and optional management features;
  see [official S3 pricing](https://aws.amazon.com/s3/pricing/). At common
  S3 Standard public rates, 30 GiB and 10,000 writes are roughly below USD 1/month
  before region, taxes, logs, KMS and transfer. This is a planning estimate, not
  a quote.
- Database growth: receipts, normalized findings and Decision Records dominate;
  budget several GiB for a 10k/month pilot depending on finding density. Keep
  large exact evidence out of Postgres.
- Compute: policy/correlation is materially smaller than scanning. If existing
  workers have headroom, incremental instance cost can be near zero; otherwise
  plan approximately USD 15–60/month for a small dedicated worker tier plus
  monitoring. Load tests must replace this estimate.
- Network: evidence ingress to AWS is normally not the dominant cost; dashboard
  downloads and cross-region storage are excluded.
- Operational load: credential support, analyzer variability, incomplete scans,
  object retention, queue lag and runner-specific failures are the main risks.

No cost estimate should be treated as a production forecast until evidence size,
findings per scan, submission rate, retention, region and worker timings are
measured in the selected-repository pilot.

## Open owner decisions

1. Confirm the pilot's exact organization plan/entitlement and whether the new
   integration is available before Enterprise.
2. Choose S3 region, retention period, encryption mode and deletion/legal-hold
   policy.
3. Decide whether server policy alone controls `fail-on` or permits a workflow
   request bounded by an organization minimum.
4. Approve default omission of source excerpts and the package/evidence field
   allowlist.
5. Choose accepted engine builds and the release signing identity.
6. Decide whether fork PRs are local-only during the pilot or held until OIDC.
7. Define Decision Record retention after an Asset/customer is deleted.
8. Decide whether repository administrators may create bindings or only Fendix
   organization owners/admins.
9. Choose canonical dashboard host/locale behavior for deep links.
10. Decide when to deprecate the direct generic scan+runner CI recipe.

These choices do not block contract implementation where the schema represents
them explicitly. They block pilot enablement.

## Readiness decision

**READY to implement the phased CI-first architecture and its contracts.** The
existing integration is **NOT READY** to be marketed or enabled as a managed,
backend-authoritative CI product. Pilot enablement remains gated on Phases 0–3,
all 34 test groups, migration/recovery/retention drills, a selected-repository
canary, and explicit owner decisions above.

## Files inspected

### Engine, Action, App and distribution

- `action.yml`
- `scripts/install.sh`
- `examples/github-actions/fendix-scan.yml`
- `docs/ci-cd-integration.md`
- `docs/INTEGRATION_GUIDE.md`
- `docs/example_plan.md`
- `docs/github-app.md`
- `docs/threat-model.md`
- `docs/adr/ADR-009-backend-authoritative-github-app-integration.md`
- `go/cmd/fendix/main.go`
- `go/cmd/fendix-app/main.go`
- `go/internal/models/config.go`
- `go/internal/models/finding.go`
- `go/internal/engine/orchestrator.go`
- `go/internal/decision/*`
- `go/internal/policy/*`
- `go/internal/reporters/json.go`
- `go/internal/reporters/parse.go`
- `go/internal/ghapp/auth.go`
- `go/internal/ghapp/webhook.go`
- `go/internal/ghapp/handler.go`
- `go/internal/ghapp/scanner.go`
- `go/internal/ghapp/worker.go`
- relevant engine, reporter, policy and GitHub App tests/fixtures

### Backend

- `AGENTS.md`
- `backend/openapi.json`
- `backend/config/urls.py`
- `backend/config/settings/base.py`
- `backend/accounts/models.py`
- `backend/accounts/authentication.py`
- `backend/accounts/permissions.py`
- `backend/scanning/models.py` (`Asset`, `Scan`, and `ScanFinding`)
- `backend/organizations/models.py`
- `backend/runners/models.py`
- `backend/runners/urls.py`
- `backend/runners/views.py`
- `backend/runners/ingest.py`
- `backend/scanning/models.py`
- `backend/scanning/serializers.py`
- `backend/scanning/views.py`
- `backend/scanning/services.py`
- `backend/scanning/tasks.py`
- `backend/scanning/decision_policy.py`
- `backend/scanning/urls.py`
- `backend/integrations/models.py`
- `backend/integrations/github_views.py`
- `backend/integrations/tasks.py`
- `backend/integrations/github_checks.py`
- `docs/runner-protocol.md`
- relevant scan, runner, decision, coverage, auth and GitHub integration tests

### Frontend

- `app/lib/api.ts`
- `app/types/api.ts`
- `app/lib/verdict.ts`
- `app/[locale]/scans/[id]/page.tsx`
- `app/components/ScanProgress.tsx`
- `app/components/ReleaseDecisionBanner.tsx`
- `app/components/IntegrationsPanel.tsx`
- `app/components/RunnersPanel.tsx`
- `app/[locale]/integrations/page.tsx`
- `app/[locale]/security-decision-record/page.tsx`
- locale message catalogs and relevant dashboard, API, scan progress and release
  decision tests

## Validation and remaining uncertainty

Repository SHAs, branches, worktrees, endpoints and code paths were inspected
locally. The following read-only or test commands were run:

```text
git rev-parse --show-toplevel
git branch --show-current
git rev-parse HEAD
git remote get-url origin
git status --short --branch
git worktree list --porcelain

cd Fendix/go
go test ./internal/decision ./internal/policy ./internal/reporters ./internal/ghapp
# PASS: all four packages

cd fendix-backend
docker compose run --rm --no-deps \
  -e DJANGO_SETTINGS_MODULE=config.settings.development \
  -e FAST_TESTS=1 -e DB_HOST=localhost \
  django python -m pytest \
  runners/tests/test_runners.py \
  runners/tests/test_ingest_validation.py \
  scanning/tests/test_decision_policy.py \
  scanning/tests/test_coverage_contract_ingest.py \
  integrations/tests/test_github_pr_scan.py -q
# PASS: 131 tests

cd fendix_frontend
npm test -- --run \
  tests/components/ReleaseDecisionBanner.test.tsx \
  tests/components/ScanProgress.test.tsx \
  tests/lib/dashboard-integrity.test.ts
# PASS: 3 files, 18 tests

cd Fendix
npx --yes prettier --check \
  docs/adr/ADR-010-ci-first-backend-authoritative-integration.md
# PASS: Prettier and trailing-whitespace checks
```

Two initial backend invocations did not establish test results. The first was
interrupted while production settings waited for an unavailable database. The
second was rejected before collection by the development database guard because
the repository `.env` names a managed database. No remote connection was opened.
The final command explicitly selected in-memory SQLite and a local host, then
passed all 131 selected tests. The existing remote-looking `.env` values were not
printed or changed.

No runtime implementation was added by this review.

Uncertainties that require runtime evidence during implementation:

- real sanitized evidence size and policy-worker latency;
- analyzer behavior across customer self-hosted runner images;
- private-repository SARIF availability under each customer's GitHub plan;
- exact fork submission experience after OIDC;
- selected AWS region and measured cost;
- the private-repository PR-head relationship until a GitHub read adapter or an
  accepted customer-attestation rule is implemented.
