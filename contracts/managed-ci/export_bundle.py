#!/usr/bin/env python3
"""Export a hash-locked generated copy of the canonical contract bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).parent / "v1")
    args = parser.parse_args()
    source = args.source.resolve()
    destination = args.destination.resolve()
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    files = {
        str(path.relative_to(destination)): digest(path)
        for path in sorted(destination.rglob("*"))
        if path.is_file()
    }
    lock = {
        "contract": "managed-ci/v1",
        "generated": True,
        "source_repository": "https://github.com/Fendix-app/Fendix",
        "source_revision": args.source_revision,
        "files": files,
    }
    (destination / "CONTRACT_SOURCE.json").write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    print(f"exported {len(files)} files to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
