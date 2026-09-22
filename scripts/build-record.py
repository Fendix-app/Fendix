#!/usr/bin/env python3
"""Build the signed-build record for one engine release.

The record states which sources produced this release, which EXECUTABLES it
published, and which managed-CI contract and finding policy those executables
implement. The release workflow signs it with the keyless GitHub Actions
identity; a Fendix backend verifies it once, administratively, and then
accepts managed evidence only from an executable it names.

Two details decide whether the record is usable at all:

* the digest of each artifact is the digest of the EXECUTABLE, uncompressed
  and unwrapped. The engine hashes its own running binary when it produces
  evidence, so an archive checksum could never match;
* `contract.bundle_sha256` is a digest of the bundle's CONTENTS, excluding the
  lock file that only exported copies carry. A backend compares it with its
  own vendored bundle, so what is checked is "does this build implement the
  same contract bytes I serve" rather than "were we cut from the same commit".
  `contract.revision` travels alongside as provenance.

Usage (see .github/workflows/release.yml):

    build-record.py --version v3.5.0 --commit "$GITHUB_SHA" --tag "$GITHUB_REF_NAME" \\
        --run-id "$GITHUB_RUN_ID" --workflow-ref "$GITHUB_WORKFLOW_REF" \\
        --artifact linux/amd64=dist/fendix-v3.5.0-linux-amd64 \\
        --artifact linux/arm64=dist/fendix-v3.5.0-linux-arm64 \\
        --out dist/build-record.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "engine-build-record/v1"
CONTRACT_NAME = "managed-ci/v2"
ISSUER = "https://token.actions.githubusercontent.com"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BUNDLE = REPOSITORY_ROOT / "contracts" / "managed-ci" / "v2"
POLICY_VERSION_SOURCE = REPOSITORY_ROOT / "go" / "internal" / "decision" / "policy_version.go"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def bundle_digest() -> str:
    """A deterministic digest of the whole contract bundle.

    Hashing a manifest of `path sha256` lines rather than a tarball keeps the
    value independent of archive metadata, so two checkouts of the same
    revision always produce the same digest.
    """
    lines = []
    for path in sorted(BUNDLE.rglob("*")):
        # CONTRACT_SOURCE.json exists only in an EXPORTED copy, so excluding
        # it makes the canonical tree and every consumer's copy hash the same.
        # That is the point: a backend can compare this digest with its own
        # vendored bundle and learn whether the build implements the same
        # contract bytes it serves.
        if path.is_file() and path.name != "CONTRACT_SOURCE.json":
            lines.append(f"{path.relative_to(BUNDLE).as_posix()} {sha256_file(path)[7:]}")
    manifest = "\n".join(lines).encode()
    return "sha256:" + hashlib.sha256(manifest).hexdigest()


def contract_revision() -> str:
    """The commit the vendored bundle was last changed in.

    That is the revision a consumer exported from, and the one a backend
    compares against — not the commit being released, which usually touches
    nothing in `contracts/`.
    """
    # --first-parent credits the MERGE that brought the change to the default
    # branch, which is the revision consumers export from.
    result = subprocess.run(
        ["git", "log", "-1", "--first-parent", "--format=%H", "--", str(BUNDLE.relative_to(REPOSITORY_ROOT))],
        cwd=REPOSITORY_ROOT, capture_output=True, text=True, check=True,
    )
    revision = result.stdout.strip()
    if len(revision) != 40:
        raise SystemExit("could not determine the contract revision from git history")
    return revision


def policy_version() -> str:
    """The finding policy this engine implements, read from the engine itself."""
    for line in POLICY_VERSION_SOURCE.read_text(encoding="utf-8").splitlines():
        if "PolicyVersion" in line and "=" in line and '"' in line:
            return line.split('"')[1]
    raise SystemExit("could not read PolicyVersion from the engine source")


def parse_artifact(value: str) -> dict:
    """`os/arch=path` → one artifact entry, digesting the executable itself."""
    platform, separator, raw_path = value.partition("=")
    operating_system, _, architecture = platform.partition("/")
    if not (separator and operating_system and architecture):
        raise SystemExit(f"--artifact must be os/arch=path, got {value!r}")
    path = Path(raw_path)
    if not path.is_file():
        raise SystemExit(f"artifact {raw_path} does not exist")
    if path.suffix in {".gz", ".zip", ".tar", ".deb", ".rpm", ".sig", ".crt", ".sha256"}:
        # The record pins the executable. An archive or a package is a
        # different artifact with a different digest, and pinning one would
        # mean no submission could ever match.
        raise SystemExit(f"{raw_path} is a package or archive, not an executable")
    return {
        "os": operating_system,
        "architecture": architecture,
        "executable_sha256": sha256_file(path),
        "download_name": path.name,
    }


def build(args) -> dict:
    workflow_ref = args.workflow_ref
    identity = workflow_ref.split("@", 1)[0] + "@" + args.ref if "@" not in workflow_ref else workflow_ref
    record = {
        "schema_version": SCHEMA_VERSION,
        "engine_version": args.version,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"repository": args.repository, "commit": args.commit, "tag": args.tag},
        "workflow": {
            "identity": identity,
            "issuer": ISSUER,
            "ref": args.ref,
            "run_id": args.run_id,
        },
        "contract": {
            "name": CONTRACT_NAME,
            "revision": contract_revision(),
            "bundle_sha256": bundle_digest(),
            "finding_policy_version": policy_version(),
        },
        "artifacts": sorted(
            (parse_artifact(value) for value in args.artifact),
            key=lambda entry: (entry["os"], entry["architecture"]),
        ),
    }
    digests = [artifact["executable_sha256"] for artifact in record["artifacts"]]
    if len(set(digests)) != len(digests):
        raise SystemExit("two artifacts have the same digest; a platform was passed twice")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Released engine version, e.g. v3.5.0")
    parser.add_argument("--repository", default="Fendix-app/Fendix")
    parser.add_argument("--commit", required=True, help="Exact commit being released")
    parser.add_argument("--tag", required=True, help="Release tag")
    parser.add_argument("--ref", default="", help="Git ref of the workflow run (defaults to refs/tags/<tag>)")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workflow-ref", required=True, help="$GITHUB_WORKFLOW_REF")
    parser.add_argument("--artifact", action="append", required=True, metavar="os/arch=path")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if not args.ref:
        args.ref = f"refs/tags/{args.tag}"

    record = build(args)
    # Sorted keys and a compact separator: the bytes that get signed must be
    # reproducible from the same inputs, on any machine.
    payload = json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
    Path(args.out).write_bytes(payload)
    print(f"{args.out}: {record['engine_version']} with {len(record['artifacts'])} artifacts")
    print(f"  contract {record['contract']['revision'][:12]} policy {record['contract']['finding_policy_version']}")
    for artifact in record["artifacts"]:
        print(f"  {artifact['os']}/{artifact['architecture']} {artifact['executable_sha256']}")
    print(f"  record sha256: {hashlib.sha256(payload).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
