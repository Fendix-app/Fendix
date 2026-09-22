import json
import shutil
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


def test_missing_mandatory_facts_make_a_finding_unclassifiable():
    import sys

    sys.path.insert(0, str(CONTRACTS))
    from reference_policy import Unclassifiable, classify_finding

    spec = json.loads((CONTRACTS / "v2" / "policy" / "finding-policy-1.0.0.json").read_text())
    finding = {"severity": "HIGH", "category": "injection", "evidence_facts": {"observation_source": "whitebox"}}
    try:
        classify_finding(finding, "HIGH", spec, spec["options"]["managed_ci_default"])
    except Unclassifiable as exc:
        assert exc.code == "classification_facts_missing"
    else:  # pragma: no cover
        raise AssertionError("a finding without mandatory facts was classified")
