# Managed CI contracts

This directory is the canonical public contract package for ADR-010. The
official `Fendix-app/Fendix` repository owns the schemas, fixtures, semantic
boundary checks, policy specifications and version policy. Backend and frontend
repositories consume generated, hash-locked copies made by `export_bundle.py`;
they do not edit their copies.

- `v2/` is the supported contract (`managed-ci/v2`). See `v2/README.md` for why
  it exists, the evidence-fact vocabulary and the finding/release policies.
- `v1/` is superseded and retained for history only. It is not exported.
- `reference_policy.py` interprets the v2 policy specifications. The validator
  uses it to prove that every policy vector and every decision fixture is
  derived from evidence facts and policy.

Both bundles use JSON Schema Draft 2020-12. Validate with:

```sh
python -m pip install 'jsonschema>=4.25.1,<5'
python contracts/managed-ci/validate_bundle.py contracts/managed-ci/v2
python contracts/managed-ci/validate_bundle.py contracts/managed-ci/v1
```

The engine side of the parity chain runs with the Go suite:

```sh
cd go && go test ./internal/decision -run TestManagedCI
```

To update a consumer after the canonical change is merged:

```sh
python contracts/managed-ci/export_bundle.py \
  --source-revision "$(git rev-parse HEAD)" \
  --destination ../fendix-backend/backend/contracts/managed-ci/v2
python contracts/managed-ci/export_bundle.py \
  --source-revision "$(git rev-parse HEAD)" \
  --destination ../fendix_frontend/contracts/managed-ci/v2
```

Every exported copy has `CONTRACT_SOURCE.json`, containing the contract name,
the canonical source commit and SHA-256 of every copied file. Consumer
conformance tests verify these hashes and the fixture outcomes. A schema or
policy change starts here, receives a new canonical commit, and is then
regenerated into each consumer. Manual schema forks are prohibited.

The package defines shapes, invariants and policy specifications. It does not
implement an API, authentication, persistence, or GitHub publication.
