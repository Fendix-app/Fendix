# Public reference audit — 2026-09-21

This audit covers every tracked or non-ignored worktree file after the
repository-transfer remediation. The case-insensitive search included every
personal namespace and multi-engine phrase required by the remediation brief.
Semantic variants that state or imply that blocking always needs two engines
are enforced by `scripts/check-public-claims.py`.

The snapshot contains 627 matching lines. Every line is classified below;
there are no unclassified matches and no remaining current namespace or
obsolete-blocking-claim violations on a public/distributable surface.

| Classification | Matching lines | Disposition |
|---|---:|---|
| Current violation | 0 | The live Action/App copy, generic verification docs, release runbook, service-doc clone URL, and SARIF information URI were corrected in this branch. |
| Historical signer identity | 5 | `README.md`, `SECURITY.md`, `docs/install.md`, and `scripts/install.sh`; required to verify immutable binaries/packages through v3.4.1 and explicitly scoped as historical. |
| Stable Go module path | 471 | `go/**`, plus import/install examples in `CONTRIBUTING.md`, `README.md`, `go_explanation.md`, `resume-engine-work.md`, and `examples/github-actions/fendix-scan.yml`. The module path is compatibility-sensitive and is not repository ownership metadata. |
| Explicit migration instruction | 5 | `docs/container-registry-migration.md` and the DNS compatibility explanation in `docs/install.md`. |
| Historical changelog/audit record | 109 | `CHANGELOG.md`, `ENTERPRISE_REVIEW_2026-06-07.findings.json`, `FENDIX_AUDIT_REPORT.md`, `FENDIX_VC_DUE_DILIGENCE_2026-06-07.md`, `TASK_MANIFEST.md`, `plan.md`, `docs/superpowers/**`, and `tasks/**`. These dated records are not current guidance. |
| Negative-match regression fixture | 19 | `scripts/check-public-claims.py`, `scripts/check-public-claims.sh`, and `scripts/public-claims-allowlist.json`. These literals prove that the guard rejects the retired forms. |
| Required compatibility reference | 1 | `deploy/k8s/fendix-app.yaml`; retained because no verified brand-owned application image exists. Its removal gate is documented in `docs/github-app-image-status.md`. |
| Current accurate correlation description | 17 | `README.md`, `docs/adr/ADR-003-severity-scoring.md`, `docs/benchmarks.md`, `docs/schema.md`, `nfpm.yaml`, `service-docs/README.md`, and correlation/decision implementation or tests under `go/internal/`. These explain that independent agreement raises confidence; they do not say it is universally required for blocking. |

The public regression guard separately scans root Markdown and package metadata,
`docs/`, `service-docs/`, `action.yml`, `app/manifest.yml`, `deploy/`, Docker
files, GitHub metadata/workflows, examples, the Homebrew formula, installer,
and generated mirror-page sources. Its allowlist is exact and count-bound, so
an added occurrence or a stale exception fails CI.
