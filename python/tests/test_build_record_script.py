"""The build record is the only thing standing between managed CI and an
engine nobody vetted, so the script that writes it is held to the same bar as
the contract it describes.

Four properties matter, and each has a failure mode that would be silent:

* the bytes are canonical — a record signed on one machine and re-derived on
  another must be identical, or the signature verifies against nothing;
* the digest is the digest of the EXECUTABLE. The engine hashes its own
  running binary at scan time, so a record that pinned an archive or a
  package would accept no submission at all;
* the contract digest is comparable with what a backend vendors, which means
  excluding the lock file only exported copies carry;
* the record satisfies engine-build-record/v1, because a backend refuses
  anything that does not.
"""

import hashlib
import json
import subprocess
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY / "scripts" / "build-record.py"
SCHEMA = REPOSITORY / "contracts" / "engine-build-record" / "v1" / "build-record.schema.json"
BUNDLE = REPOSITORY / "contracts" / "managed-ci" / "v2"


def load_script():
    spec = spec_from_file_location("build_record", SCRIPT)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_record = load_script()


def an_executable(tmp_path, name="fendix-v3.5.0-linux-amd64", body=b"\x7fELF not really"):
    path = tmp_path / name
    path.write_bytes(body)
    return path


def generate(tmp_path, artifacts, out="build-record.json"):
    """Run the script the way the release workflow does, and read it back."""
    destination = tmp_path / out
    argv = [
        sys.executable,
        str(SCRIPT),
        "--version",
        "v3.5.0",
        "--commit",
        "a" * 40,
        "--tag",
        "v3.5.0",
        "--run-id",
        "123456789",
        "--workflow-ref",
        "Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.5.0",
        "--out",
        str(destination),
    ]
    for artifact in artifacts:
        argv += ["--artifact", artifact]
    completed = subprocess.run(argv, capture_output=True, text=True, cwd=REPOSITORY)
    return completed, destination


def test_the_record_it_writes_satisfies_the_v1_schema(tmp_path):
    from jsonschema import Draft202012Validator

    completed, destination = generate(tmp_path, [f"linux/amd64={an_executable(tmp_path)}"])
    assert completed.returncode == 0, completed.stderr
    record = json.loads(destination.read_bytes())
    errors = list(Draft202012Validator(json.loads(SCHEMA.read_text())).iter_errors(record))
    assert errors == [], [error.message for error in errors]


def test_the_digest_is_of_the_executable_itself(tmp_path):
    """Not of a wrapper, and not of anything the workflow staged around it."""
    body = b"\x7fELFdeterministic"
    executable = an_executable(tmp_path, body=body)
    _, destination = generate(tmp_path, [f"linux/amd64={executable}"])
    artifact = json.loads(destination.read_bytes())["artifacts"][0]
    assert artifact["executable_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest()


@pytest.mark.parametrize(
    "name",
    [
        "fendix-v3.5.0-linux-amd64.tar.gz",
        "fendix-v3.5.0-linux-amd64.deb",
        "fendix-v3.5.0-linux-amd64.rpm",
        "fendix-v3.5.0-linux-amd64.sha256",
        "fendix-v3.5.0-linux-amd64.sig",
    ],
)
def test_a_package_or_a_checksum_file_is_refused_in_place_of_the_binary(tmp_path, name):
    """The workflow builds all of these next to the binary, so a typo in the
    glob would otherwise pin something no engine can ever match."""
    completed, _ = generate(tmp_path, [f"linux/amd64={an_executable(tmp_path, name=name)}"])
    assert completed.returncode != 0
    assert "not an executable" in completed.stderr


def test_the_same_inputs_produce_byte_identical_records(tmp_path):
    """What gets signed must be reproducible, or the signature proves nothing.

    `created_at` is second-resolution, so two runs in the same second are
    expected to agree; the assertion strips it to stay honest about that
    rather than depending on the clock.
    """
    executable = an_executable(tmp_path)
    _, first = generate(tmp_path, [f"linux/amd64={executable}"], out="first.json")
    _, second = generate(tmp_path, [f"linux/amd64={executable}"], out="second.json")
    left, right = json.loads(first.read_bytes()), json.loads(second.read_bytes())
    left.pop("created_at"), right.pop("created_at")
    assert json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    assert first.read_bytes() == json.dumps(
        json.loads(first.read_bytes()), separators=(",", ":"), sort_keys=True
    ).encode()


def test_platforms_are_ordered_and_one_entry_deep(tmp_path):
    executables = {
        "linux/amd64": an_executable(tmp_path, name="l-amd64", body=b"one"),
        "darwin/arm64": an_executable(tmp_path, name="d-arm64", body=b"two"),
        "linux/arm64": an_executable(tmp_path, name="l-arm64", body=b"three"),
    }
    _, destination = generate(tmp_path, [f"{k}={v}" for k, v in executables.items()])
    artifacts = json.loads(destination.read_bytes())["artifacts"]
    assert [(a["os"], a["architecture"]) for a in artifacts] == [
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
    ]


def test_the_same_binary_offered_as_two_platforms_is_refused(tmp_path):
    """Identical digests mean the matrix published one build twice, and a
    record that claimed otherwise would vouch for a platform never built."""
    executable = an_executable(tmp_path)
    completed, _ = generate(tmp_path, [f"linux/amd64={executable}", f"linux/arm64={executable}"])
    assert completed.returncode != 0
    assert "same digest" in completed.stderr


def test_the_contract_digest_ignores_the_lock_a_consumer_would_add():
    """A backend derives this digest from its exported copy, which carries a
    CONTRACT_SOURCE.json the canonical tree does not. Including it would put
    the two sides permanently out of agreement."""
    hashed = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file() and path.name != "CONTRACT_SOURCE.json"
    }
    manifest = "\n".join(
        f"{name} {hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest()}" for name in sorted(hashed)
    )
    assert build_record.bundle_digest() == "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()
    assert "CONTRACT_SOURCE.json" not in manifest


def test_the_contract_revision_is_the_commit_the_bundle_last_changed_in():
    revision = build_record.contract_revision()
    assert len(revision) == 40 and set(revision) <= set("0123456789abcdef")
    reachable = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=REPOSITORY,
        capture_output=True,
    )
    assert reachable.returncode == 0, "the record would name a revision this checkout does not contain"


def test_the_policy_version_is_read_from_the_engine_not_hardcoded():
    """If these drift the record lies about what the binary implements."""
    source = build_record.POLICY_VERSION_SOURCE.read_text(encoding="utf-8")
    assert f'"{build_record.policy_version()}"' in source
