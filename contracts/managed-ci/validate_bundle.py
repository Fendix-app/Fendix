#!/usr/bin/env python3
"""Validate the canonical managed-CI schemas, fixtures and policy specifications.

This is a contract harness, not a production ingestion implementation. v2
additionally proves that every finding-policy vector and every decision fixture
is derived from evidence facts and policy by the reference interpreter
(`reference_policy.py`), and that the vectors are what the engine decides
(`go/internal/decision/managed_ci_policy_vectors_test.go` generates them).
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

try:  # imported as a module by the pytest wrapper, or run as a script
    from reference_policy import Unclassifiable, classify_finding, decide_submission
except ImportError:  # pragma: no cover - resolved via the file's own directory
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from reference_policy import Unclassifiable, classify_finding, decide_submission

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
    if document.get("schema_version") == "managed-ci-conformance-cases/v2":
        required.add("superseded-contract-version")
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


def version_errors(document: object, contract: str) -> list[str]:
    """Unknown version constants are unsupported_version, never 'nearest known'."""
    if not isinstance(document, dict):
        return []
    errors = []
    if "api_version" in document and document["api_version"] != contract:
        errors.append("unsupported_version: api_version")
    manifest = document.get("manifest")
    expected_manifest = "evidence-manifest/v2" if contract == "managed-ci/v2" else "evidence-manifest/v1"
    if isinstance(manifest, dict) and manifest.get("schema_version") not in (None, expected_manifest):
        errors.append("unsupported_version: manifest.schema_version")
    return errors


def provenance_errors(document: object, rules: dict, supported_policies: set[str]) -> list[str]:
    """v2 cross-field rules the schema cannot express."""
    manifest = document.get("manifest") if isinstance(document, dict) else None
    if not isinstance(manifest, dict):
        return []
    errors = []
    engine = manifest.get("engine")
    if isinstance(engine, dict) and engine.get("finding_policy_version") not in supported_policies:
        errors.append("unsupported_finding_policy")
    analyzers = [a for a in manifest.get("analyzers", []) if isinstance(a, dict)]
    findings = [f for f in manifest.get("findings", []) if isinstance(f, dict)]
    reported = {a.get("analyzer_id") for a in analyzers}
    provenance = rules.get("provenance", {})
    if provenance.get("finding_analyzer_must_be_reported") and any(
        f.get("analyzer_id") not in reported for f in findings
    ):
        errors.append("finding_analyzer_unreported")
    if provenance.get("analyzer_finding_count_must_match"):
        for analyzer in analyzers:
            attributed = sum(1 for f in findings if f.get("analyzer_id") == analyzer.get("analyzer_id"))
            if analyzer.get("finding_count") != attributed:
                errors.append("analyzer_finding_count_mismatch")
                break
    coverage = manifest.get("coverage")
    if provenance.get("observed_analyzers_must_be_reported") and isinstance(coverage, dict):
        if not set(coverage.get("observed_analyzers", [])) <= reported:
            errors.append("observed_analyzer_unreported")
    return errors


def validate_finding_policies(root: Path, contract_set: dict, schemas: dict) -> list[str]:
    errors: list[str] = []
    facts_schema = schemas["https://schemas.fendix.dev/managed-ci/v2/evidence-facts.schema.json"]
    for entry in contract_set.get("finding_policies", []):
        spec = load_json(root / entry["specification"])
        if spec["finding_policy_version"] != entry["version"]:
            errors.append(f"{entry['specification']}: version does not match contract-set")
        if set(spec["facts"]) != set(facts_schema["properties"]):
            errors.append(f"{entry['specification']}: fact vocabulary differs from evidence-facts schema")
        if not set(spec["required_facts"]) <= set(spec["facts"]):
            errors.append(f"{entry['specification']}: required facts outside the vocabulary")
        forbidden = {"confidence", "tier", "decision", "blocking", "verdict", "status", "risk_score"}
        if forbidden & set(spec["facts"]):
            errors.append(f"{entry['specification']}: a conclusion is declared as a fact")
        vectors = load_json(root / entry["vectors"])
        if vectors["finding_policy_version"] != entry["version"]:
            errors.append(f"{entry['vectors']}: version does not match its specification")
        options = spec["options"][vectors["options"]]
        for vector in vectors["vectors"]:
            finding = {"severity": vector["severity"], "category": vector["category"], "evidence_facts": vector["facts"]}
            try:
                derived = classify_finding(finding, vector["fail_on"], spec, options)
            except Unclassifiable as exc:
                errors.append(f"{entry['vectors']}: {vector['id']} is unclassifiable ({exc.code})")
                continue
            if derived != vector["expected"]:
                errors.append(f"{entry['vectors']}: {vector['id']} is not reproduced by the specification")
    return errors


def validate_decision_cases(root: Path, contract_set: dict) -> list[str]:
    errors: list[str] = []
    cases = load_json(root / contract_set["decision_cases"])
    release = load_json(root / contract_set["release_policy"])
    finding_specs = {
        entry["version"]: load_json(root / entry["specification"]) for entry in contract_set["finding_policies"]
    }
    for case in cases["cases"]:
        submission = load_json(root / "fixtures" / case["submission"])
        decision = load_json(root / "fixtures" / case["decision"])
        spec = finding_specs[submission["manifest"]["engine"]["finding_policy_version"]]
        derived = decide_submission(submission, spec, release, case["binding_policy"])
        for key in ("decision", "fail_gate", "coverage_state", "backend_policy_version", "reason_codes"):
            if derived[key] != decision[key]:
                errors.append(f"{case['id']}: decision fixture {key} is not derived from evidence and policy")
        findings = [{k: v for k, v in f.items() if k != "detail"} for f in derived["findings"]]
        if findings != case["expected_findings"]:
            errors.append(f"{case['id']}: expected_findings are not derived from evidence and policy")
        if (
            decision["scan_execution_id"] != submission["manifest"]["context"]["scan_execution_id"]
            or decision["evidence_submission_id"] != submission["evidence_submission_id"]
        ):
            errors.append(f"{case['id']}: decision fixture names a different submission")
    return errors


def validate_bundle(root: Path) -> list[str]:
    registry, schemas = schema_registry(root / "schemas")
    contract_set = load_json(root / "contract-set.json")
    contract = contract_set["contract"]
    index = load_json(root / "fixtures" / "index.json")
    rules = load_json(root / "semantic-rules.json")
    supported = {entry["version"] for entry in contract_set.get("finding_policies", [])}
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
        if contract == "managed-ci/v2":
            semantic.extend(version_errors(value, contract))
            semantic.extend(provenance_errors(value, rules, supported))
        if fixture["expected"] == "valid" and (schema_errors or semantic):
            errors.append(f"{fixture['path']}: expected valid: {schema_errors or semantic}")
        if fixture["expected"] == "rejected" and not (schema_errors or semantic):
            errors.append(f"{fixture['path']}: expected rejection")
        expected_semantic = fixture.get("semantic_error")
        if expected_semantic == "secret_like_content" and not any("secret-like" in item for item in semantic):
            errors.append(f"{fixture['path']}: expected secret-like semantic rejection")
        if expected_semantic == "unsupported_version" and not any(i.startswith("unsupported_version") for i in semantic):
            errors.append(f"{fixture['path']}: expected unsupported_version")
        if expected_semantic in ("unsupported_finding_policy", "analyzer_finding_count_mismatch", "finding_analyzer_unreported"):
            if expected_semantic not in semantic:
                errors.append(f"{fixture['path']}: expected {expected_semantic}")
            if schema_errors:
                errors.append(f"{fixture['path']}: must be schema-valid so only {expected_semantic} rejects it")
    errors.extend(validate_protocol_cases(root / "fixtures" / "protocol" / "conformance-cases.json"))
    errors.extend(validate_state_machine(root / "state-machine.json"))
    if contract == "managed-ci/v2":
        errors.extend(validate_finding_policies(root, contract_set, schemas))
        errors.extend(validate_decision_cases(root, contract_set))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).parent / "v2")
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
