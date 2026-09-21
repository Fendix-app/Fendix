# Managed CI Phase 1 implementation plan

Status: planned, not implemented. Depends on ADR-010 Phase 0 contracts.

1. Add backend models and reversible migrations for repository binding,
   Asset-scoped CI credential, scan execution, evidence receipt/artifact,
   Decision Record/revision and publication output. Add database uniqueness for
   immutable provider repository binding and `(binding, idempotency_key)`.
2. Implement credential creation/rotation/revocation under organization admin
   permissions. Store no plaintext; enforce environment, tenant, Asset,
   repository and scopes on every request.
3. Add `POST /api/ci/v1/submissions`, streaming 8 MiB limit, exact-body digest,
   schema/semantic validation, atomic receipt selection and stable `202`.
4. Store accepted exact evidence in a private encrypted object store with a
   digest, immutable key, narrow worker IAM and retention lifecycle. Persist the
   receipt transaction before dispatch.
5. Add idempotent Celery validation/evaluation tasks with compare-and-swap state
   transitions, leases, cancellation, expiry, supersession and recovery.
6. Implement backend normalization, correlation, confidence and policy from
   allowed evidence facts. Exclude every `producer_diagnostics` value and client
   projection from authority.
7. Persist the immutable Decision Record in the terminal evaluation transaction.
   Add append-only revision mechanics and audited retention/deletion behavior.
8. Add tenant-scoped status/cancel/decision APIs, stable errors, polling hints,
   per-token/tenant throttles, concurrency limits and audit events.
9. Extend the engine with a v1 sanitized evidence exporter and exact full-head
   provenance. Add secret canaries and path/archive/symlink boundary tests.
10. Add Action managed mode in a new major: exact pinned engine verification,
    token masking, typed inputs, full-head validation, submission/recovery,
    bounded polling, cancellation, summary/SARIF and backend-only gate mapping.
11. Add the frontend binding/token administration and immutable Decision Record
    route with provenance, analyzer/coverage, lifecycle and GitHub links in
    English/Arabic. Regenerate OpenAPI types.
12. Run migration forward/backward, duplicate/concurrency, worker redelivery,
    object-store recovery, tenant isolation, rate/size, secret leakage,
    GitHub-hosted/self-hosted E2E, RTL/accessibility and rollback drills behind a
    disabled feature flag.

Rollback keeps existing local Action and runner protocols unchanged, disables
the managed feature flag, stops new ingestion, drains or safely fails accepted
executions, and retains immutable receipts/records. No Phase 1 migration may
delete or reinterpret existing Scan data.
