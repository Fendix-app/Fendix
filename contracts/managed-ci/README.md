# Managed CI contracts

This directory is the canonical public contract package for ADR-010. The
official `Fendix-app/Fendix` repository owns the schemas, fixtures, semantic
boundary checks and version policy. Backend and frontend repositories consume
generated, hash-locked copies made by `export_bundle.py`; they do not edit their
copies.

`v1/` uses JSON Schema Draft 2020-12. Run:

```sh
python -m pip install 'jsonschema>=4.25.1,<5'
python contracts/managed-ci/validate_bundle.py
```

To update a consumer after the canonical change is committed:

```sh
python contracts/managed-ci/export_bundle.py \
  --source-revision "$(git rev-parse HEAD)" \
  --destination ../fendix-backend/backend/contracts/managed-ci/v1
```

Every exported copy has `CONTRACT_SOURCE.json`, containing the canonical source
commit and SHA-256 of every copied file. Consumer conformance tests verify these
hashes and the fixture outcomes. A schema change starts here, receives a new
canonical commit, and is then regenerated into each consumer. Manual schema
forks are prohibited.

The package defines shapes and invariants only. It does not implement an API,
authentication, policy evaluation, persistence, or GitHub publication.
