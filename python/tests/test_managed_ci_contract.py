import json
import shutil
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = REPOSITORY_ROOT / "contracts" / "managed-ci"
VALIDATOR_PATH = CONTRACTS / "validate_bundle.py"


def _validator_module():
    spec = spec_from_file_location("managed_ci_validate_bundle", VALIDATOR_PATH)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_v2(tmp_path: Path) -> Path:
    root = tmp_path / "v2"
    shutil.copytree(CONTRACTS / "v2", root)
    return root


def _rewrite(path: Path, mutate) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_managed_ci_v1_contract_and_fixtures_are_conformant():
    module = _validator_module()
    errors = module.validate_bundle(CONTRACTS / "v1")
    assert errors == []


def test_managed_ci_v2_contract_policy_and_fixtures_are_conformant():
    module = _validator_module()
    assert module.validate_bundle(CONTRACTS / "v2") == []


def test_a_hand_edited_decision_fixture_is_not_derived(tmp_path):
    root = _copy_v2(tmp_path)
    _rewrite(root / "fixtures" / "valid" / "backend-overrides-local-diagnostic.decision.json",
             lambda d: d.update(decision="PASS", fail_gate=False, reason_codes=["policy_passed"]))
    errors = _validator_module().validate_bundle(root)
    assert any("backend-overrides-local-diagnostic: decision fixture decision" in e for e in errors)


def test_a_hand_edited_policy_vector_is_not_reproduced(tmp_path):
    root = _copy_v2(tmp_path)
    vectors = root / "policy" / "finding-policy-1.0.0.vectors.json"

    def flip(document):
        vector = next(v for v in document["vectors"] if v["id"] == "high-medium-precision-uncorroborated")
        vector["expected"]["status"] = "BLOCK"

    _rewrite(vectors, flip)
    errors = _validator_module().validate_bundle(root)
    assert any("high-medium-precision-uncorroborated is not reproduced" in e for e in errors)


def test_a_conclusion_cannot_be_declared_as_an_evidence_fact(tmp_path):
    root = _copy_v2(tmp_path)
    _rewrite(root / "policy" / "finding-policy-1.0.0.json",
             lambda d: d["facts"].update(confidence={"type": "enum", "values": ["high"]}))
    errors = _validator_module().validate_bundle(root)
    assert any("a conclusion is declared as a fact" in e for e in errors)
    assert any("fact vocabulary differs from evidence-facts schema" in e for e in errors)


def _reference():
    sys.path.insert(0, str(CONTRACTS))
    import reference_policy

    return reference_policy


def test_missing_mandatory_facts_make_a_finding_unclassifiable():
    reference = _reference()
    Unclassifiable, classify_finding = reference.Unclassifiable, reference.classify_finding

    spec = json.loads((CONTRACTS / "v2" / "policy" / "finding-policy-1.0.0.json").read_text())
    finding = {"severity": "HIGH", "category": "injection", "evidence_facts": {"observation_source": "whitebox"}}
    try:
        classify_finding(finding, "HIGH", spec, spec["options"]["managed_ci_default"])
    except Unclassifiable as exc:
        assert exc.code == "classification_facts_missing"
    else:  # pragma: no cover
        raise AssertionError("a finding without mandatory facts was classified")


# Owner-approved intent, pinned independently of derivation: the validator
# proves each decision fixture is DERIVED by the reference interpreter; this
# table proves the derivation still says what was approved, so a regression in
# the interpreter cannot silently re-derive every fixture into a new meaning.
APPROVED_DECISIONS = {
    "clean-pass": ("PASS", "complete", ["policy_passed"]),
    "non-blocking-warn": ("WARN", "complete", ["non_blocking_findings"]),
    "high-uncorroborated-warn": ("WARN", "complete", ["non_blocking_findings"]),
    "high-deterministic-block": ("BLOCK", "complete", ["blocking_findings"]),
    "cross-tool-corroborated-block": ("BLOCK", "complete", ["blocking_findings"]),
    "backend-overrides-local-diagnostic": ("BLOCK", "complete", ["blocking_findings"]),
    "forged-local-block-clean": ("PASS", "complete", ["policy_passed"]),
    "forged-confidence-cannot-promote": ("WARN", "complete", ["non_blocking_findings"]),
    "missing-classification-facts": ("INCOMPLETE", "complete", ["classification_facts_missing"]),
    "conflicting-evidence-facts": ("INCOMPLETE", "complete", ["conflicting_evidence_facts"]),
    "required-analyzer-failure": ("INCOMPLETE", "incomplete", ["required_analyzer_failed"]),
    "required-coverage-gap": ("INCOMPLETE", "incomplete", ["required_coverage_missing"]),
    "required-sast-not-applicable": ("INCOMPLETE", "incomplete", ["required_coverage_missing"]),
    "required-sca-not-applicable": ("INCOMPLETE", "incomplete", ["required_coverage_missing"]),
    "optional-analyzer-not-applicable": ("PASS", "complete", ["policy_passed"]),
    "required-completed-not-observed": ("INCOMPLETE", "incomplete", ["required_coverage_missing"]),
    "required-analyzer-skipped": ("INCOMPLETE", "incomplete", ["required_coverage_missing"]),
    "required-analyzer-diff-unchanged": (
        "INCOMPLETE",
        "incomplete",
        ["differential_scope_rejected", "required_coverage_missing"],
    ),
    "block-with-required-coverage-gap": ("BLOCK", "incomplete", ["blocking_findings", "required_coverage_missing"]),
    "block-with-unclassifiable-finding": ("BLOCK", "complete", ["blocking_findings", "classification_facts_missing"]),
}


def test_every_decision_fixture_encodes_the_approved_intent():
    cases = json.loads((CONTRACTS / "v2" / "fixtures" / "decision-cases.json").read_text())["cases"]
    assert {case["id"] for case in cases} == set(APPROVED_DECISIONS)
    for case in cases:
        decision = json.loads((CONTRACTS / "v2" / "fixtures" / case["decision"]).read_text())
        want_decision, want_coverage, want_codes = APPROVED_DECISIONS[case["id"]]
        assert decision["decision"] == want_decision, case["id"]
        assert decision["coverage_state"] == want_coverage, case["id"]
        assert decision["reason_codes"] == want_codes, case["id"]
        assert decision["fail_gate"] is (want_decision in ("BLOCK", "INCOMPLETE")), case["id"]


def _manifest(analyzers, observed, gaps=()):
    return {"analyzers": analyzers, "coverage": {"observed_analyzers": list(observed), "gaps": list(gaps)}}


def _analyzer(analyzer_id, status="completed", reason_code="completed"):
    return {"analyzer_id": analyzer_id, "status": status, "reason_code": reason_code}


REQUIRED_CASES = [
    # (sca status, sca reason_code, sca observed?, expected coverage reason codes)
    ("completed", "completed", True, []),
    ("completed", "completed", False, ["required_coverage_missing"]),
    ("failed", "execution_error", False, ["required_analyzer_failed"]),
    ("failed", "totally_new_reason", False, ["required_analyzer_failed"]),
    ("skipped", "dependency_missing", False, ["required_coverage_missing"]),
    ("skipped", "disabled_by_flag", False, ["required_coverage_missing"]),
    ("skipped", "unsupported_target", False, ["required_coverage_missing"]),
    ("skipped", "not_applicable", False, ["required_coverage_missing"]),
    ("skipped", "diff_unchanged", False, ["differential_scope_rejected", "required_coverage_missing"]),
    ("not_applicable", "not_applicable", False, ["required_coverage_missing"]),
    ("not_applicable", "no_supported_manifest", True, ["required_coverage_missing"]),
    ("deferred", "future_status", True, ["required_coverage_missing"]),
]


def test_required_analyzer_invariant_holds_for_every_status():
    reference = _reference()
    for status, reason, observed, expected in REQUIRED_CASES:
        manifest = _manifest(
            [_analyzer("sast"), _analyzer("sca", status, reason)],
            ["sast", "sca"] if observed else ["sast"],
        )
        got = reference.coverage_codes(manifest, ["sast", "sca"])
        assert got == expected, (status, reason, observed)


def test_an_absent_required_analyzer_is_a_gap():
    reference = _reference()
    assert reference.coverage_codes(_manifest([_analyzer("sast")], ["sast"]), ["sast", "sca"]) == [
        "required_coverage_missing"
    ]


def test_optional_analyzers_only_gap_when_they_fail():
    reference = _reference()
    for status, reason, expected in [
        ("not_applicable", "not_applicable", []),
        ("skipped", "dependency_missing", []),
        ("completed", "completed", []),
        ("failed", "timeout", ["optional_analyzer_failed"]),
    ]:
        manifest = _manifest([_analyzer("sast"), _analyzer("sca"), _analyzer("secrets", status, reason)], ["sast", "sca"])
        assert reference.coverage_codes(manifest, ["sast", "sca"]) == expected, status


def test_a_confirmed_block_outranks_a_required_coverage_gap_and_keeps_its_reason():
    reference = _reference()
    root = CONTRACTS / "v2"
    submission = json.loads((root / "fixtures" / "valid" / "block-with-required-coverage-gap.submission.json").read_text())
    derived = reference.decide_submission(
        submission,
        json.loads((root / "policy" / "finding-policy-1.0.0.json").read_text()),
        json.loads((root / "policy" / "managed-release-2.0.0.json").read_text()),
        {"fail_on_severity": "HIGH", "required_analyzers": ["sast", "sca"]},
    )
    assert derived["decision"] == "BLOCK"
    assert derived["coverage_state"] == "incomplete"
    assert derived["reason_codes"] == ["blocking_findings", "required_coverage_missing"]
