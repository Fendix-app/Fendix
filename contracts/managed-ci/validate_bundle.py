#!/usr/bin/env python3
"""Validate the canonical managed-CI v1 schemas and fixtures.

This is a contract harness, not a production ingestion implementation.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), parse_float=str)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def semantic_errors(value: object, rules: dict, path: tuple[str, ...] = ()) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            current = path + (key,)
            if key.lower() in rules["prohibited_keys"]:
                errors.append(f"prohibited key: {'.'.join(current)}")
            if key == "path" and isinstance(child, str):
                if rules["forbid_absolute_paths"] and (
                    child.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", child)
                ):
                    errors.append(f"absolute local path: {'.'.join(current)}")
                if child.startswith(tuple(rules["forbid_user_path_prefixes"])):
                    errors.append(f"user-identifying local path: {'.'.join(current)}")
            errors.extend(semantic_errors(child, rules, current))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(semantic_errors(child, rules, path + (str(index),)))
    elif isinstance(value, str):
        for pattern in rules["secret_patterns"]:
            if re.search(pattern, value):
                errors.append(f"secret-like content: {'.'.join(path)}")
                break
    return errors


def schema_registry(schema_dir: Path) -> tuple[Registry, dict[str, dict]]:
    registry = Registry()
    schemas: dict[str, dict] = {}
    for path in sorted(schema_dir.glob("*.schema.json")):
        document = load_json(path)
        Draft202012Validator.check_schema(document)
        schema_id = document["$id"]
        schemas[schema_id] = document
        registry = registry.with_resource(schema_id, Resource.from_contents(document))
    return registry, schemas


def validate_protocol_cases(path: Path) -> list[str]:
    document = load_json(path)
    errors: list[str] = []
    cases = {item["id"]: item for item in document.get("cases", [])}
    required = {
        "duplicate-identical-submission",
        "conflicting-duplicate-submission",
        "wrong-repository-id",
        "wrong-asset",
        "wrong-tenant",
        "wrong-environment",
        "wrong-commit-sha",
        "stale-superseded-commit",
        "repeated-run-attempt",
        "oversized-payload",
        "backend-overrides-local-diagnostic",
    }
    if missing := sorted(required - cases.keys()):
        errors.append(f"missing protocol cases: {', '.join(missing)}")
    duplicate = cases.get("duplicate-identical-submission", {})
    if not (
        duplicate.get("first_key") == duplicate.get("second_key")
        and duplicate.get("first_artifact_hash") == duplicate.get("second_artifact_hash")
        and duplicate.get("expected") == "return_original_receipt"
    ):
        errors.append("identical duplicate case does not describe receipt reuse")
    conflict = cases.get("conflicting-duplicate-submission", {})
    if not (
        conflict.get("first_key") == conflict.get("second_key")
        and conflict.get("first_artifact_hash") != conflict.get("second_artifact_hash")
        and conflict.get("expected") == "idempotency_conflict"
    ):
        errors.append("conflicting duplicate case does not describe a 409 conflict")
    oversized = cases.get("oversized-payload", {})
    if not oversized.get("body_bytes", 0) > oversized.get("maximum_body_bytes", 0):
        errors.append("oversized fixture is not over its declared limit")
    authority = cases.get("backend-overrides-local-diagnostic", {})
    if authority.get("local_diagnostic") == authority.get("backend_decision"):
        errors.append("authority fixture does not conflict")
    return errors


def validate_state_machine(path: Path) -> list[str]:
    document = load_json(path)
    errors: list[str] = []
    states = document.get("states", {})
    expected = {"accepted", "validating", "evaluating", "completed", "failed", "cancelled", "superseded"}
    if set(states) != expected:
        errors.append("state machine does not define the exact v1 state set")
    record_transitions = [item for item in document.get("transitions", []) if item.get("creates_decision_record")]
    if record_transitions != [
        {
            "audit_event": "ci.decision.completed",
            "creates_decision_record": True,
            "from": "evaluating",
            "owner": "decision_worker",
            "to": "completed",
        }
    ]:
        errors.append("only evaluating -> completed may create a Decision Record")
    for transition in document.get("transitions", []):
        if transition.get("from") is not None and transition["from"] not in states:
            errors.append(f"unknown transition source: {transition['from']}")
        if transition.get("to") not in states:
            errors.append(f"unknown transition destination: {transition.get('to')}")
        if not transition.get("audit_event") or not transition.get("owner"):
            errors.append("transition missing owner or audit event")
    return errors


def validate_bundle(root: Path) -> list[str]:
    registry, schemas = schema_registry(root / "schemas")
    index = load_json(root / "fixtures" / "index.json")
    rules = load_json(root / "semantic-rules.json")
    errors: list[str] = []
    for fixture in index["fixtures"]:
        fixture_path = root / "fixtures" / fixture["path"]
        value = load_json(fixture_path)
        schema_id = fixture["schema"]
        validator = Draft202012Validator(schemas[schema_id], registry=registry)
        schema_errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
        semantic = semantic_errors(value, rules)
        if len(canonical_bytes(value)) > rules["maximum_canonical_body_bytes"]:
            semantic.append("payload_too_large")
        if fixture["expected"] == "valid" and (schema_errors or semantic):
            errors.append(f"{fixture['path']}: expected valid: {schema_errors or semantic}")
        if fixture["expected"] == "rejected" and not (schema_errors or semantic):
            errors.append(f"{fixture['path']}: expected rejection")
        expected_semantic = fixture.get("semantic_error")
        if expected_semantic == "secret_like_content" and not any("secret-like" in item for item in semantic):
            errors.append(f"{fixture['path']}: expected secret-like semantic rejection")
    errors.extend(validate_protocol_cases(root / "fixtures" / "protocol" / "conformance-cases.json"))
    errors.extend(validate_state_machine(root / "state-machine.json"))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).parent / "v1")
    args = parser.parse_args()
    errors = validate_bundle(args.root.resolve())
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"managed CI contract bundle valid: {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
