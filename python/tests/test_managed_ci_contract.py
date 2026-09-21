from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = REPOSITORY_ROOT / "contracts" / "managed-ci" / "validate_bundle.py"


def _validator_module():
    spec = spec_from_file_location("managed_ci_validate_bundle", VALIDATOR_PATH)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_managed_ci_v1_contract_and_fixtures_are_conformant():
    module = _validator_module()
    errors = module.validate_bundle(REPOSITORY_ROOT / "contracts" / "managed-ci" / "v1")
    assert errors == []
