#!/usr/bin/env python3
"""Reject stale public namespaces and inaccurate blocking claims."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = ROOT / "scripts" / "public-claims-allowlist.json"


@dataclass(frozen=True)
class Detector:
    name: str
    expression: re.Pattern[str]


DETECTORS = (
    Detector(
        "personal_repository_url",
        re.compile(
            r"https?://(?:www\.)?github\.com/Abdel-RahmanSaied/"
            r"(?:Fendix|homebrew-fendix)(?=$|[/?#)`'\"\s:])",
            re.IGNORECASE,
        ),
    ),
    Detector(
        "personal_ghcr_path",
        re.compile(r"ghcr\.io/abdel-rahmansaied/[a-z0-9._/-]+", re.IGNORECASE),
    ),
    Detector(
        "obsolete_multi_engine_blocking_claim",
        re.compile(
            r"(?:"
            r"fail(?:s|ed|ing)?(?:\s+the\s+(?:build|check|pipeline))?\s+only\s+when\s+"
            r"(?:both|two|multiple)\s+(?:engines|scanners)[^.\n]{0,100}(?:confirm|agree)"
            r"|findings?\s+only\s+fail[^.\n]{0,100}(?:both|two|multiple)\s+"
            r"(?:engines|scanners|runtime)"
            r"|(?:both|two|multiple)\s+(?:engines|scanners)[^.\n]{0,80}"
            r"(?:must|required\s+to)\s+(?:confirm|agree)"
            r"|only\s+(?:confirmed[, ]+)?correlated(?:[, ]+reachable)?\s+findings\s+block"
            r")",
            re.IGNORECASE,
        ),
    ),
)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = [Path(raw.decode()) for raw in result.stdout.split(b"\0") if raw]
    return sorted(path for path in paths if is_public_surface(path))


def is_public_surface(path: Path) -> bool:
    value = path.as_posix()
    if len(path.parts) == 1 and path.suffix.lower() in {
        ".md",
        ".markdown",
        ".toml",
        ".yaml",
        ".yml",
    }:
        return True
    if value.startswith(
        ("docs/", "deploy/", "examples/", "Formula/", "service-docs/", ".github/")
    ):
        return True
    if value.startswith("scripts/release/mirror-pages-bootstrap/"):
        return True
    return value in {
        "action.yml",
        "app/manifest.yml",
        "scripts/install.sh",
    } or value.startswith("Dockerfile")


def load_allowlist() -> list[dict[str, object]]:
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    required = {
        "id",
        "path",
        "detector",
        "pattern",
        "expected_count",
        "reason",
        "classification",
        "removal_condition",
    }
    if not isinstance(data, list):
        raise ValueError("allowlist root must be an array")
    ids: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError(f"allowlist entry must contain exactly {sorted(required)}")
        if entry["id"] in ids:
            raise ValueError(f"duplicate allowlist id: {entry['id']}")
        ids.add(str(entry["id"]))
        if entry["classification"] not in {"historical", "compatibility"}:
            raise ValueError(f"invalid classification for {entry['id']}")
        if not isinstance(entry["expected_count"], int) or entry["expected_count"] < 1:
            raise ValueError(f"invalid expected_count for {entry['id']}")
        for field in ("path", "detector", "pattern", "reason", "removal_condition"):
            if not isinstance(entry[field], str) or not str(entry[field]).strip():
                raise ValueError(f"missing {field} for {entry['id']}")
        re.compile(str(entry["pattern"]), re.IGNORECASE)
    return data


def scan(files: list[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for relative in files:
        try:
            content = (ROOT / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for detector in DETECTORS:
            for match in detector.expression.finditer(content):
                findings.append(
                    {
                        "path": relative.as_posix(),
                        "detector": detector.name,
                        "match": match.group(0),
                        "line": content.count("\n", 0, match.start()) + 1,
                    }
                )
    return findings


def classify(
    findings: list[dict[str, object]], allowlist: list[dict[str, object]]
) -> tuple[list[dict[str, object]], dict[str, int]]:
    counts = {str(entry["id"]): 0 for entry in allowlist}
    violations: list[dict[str, object]] = []
    for finding in findings:
        matches = [
            entry
            for entry in allowlist
            if fnmatch.fnmatchcase(str(finding["path"]), str(entry["path"]))
            and finding["detector"] == entry["detector"]
            and re.fullmatch(
                str(entry["pattern"]), str(finding["match"]), re.IGNORECASE
            )
        ]
        if len(matches) != 1:
            violations.append(finding)
            continue
        counts[str(matches[0]["id"])] += 1
    return violations, counts


def self_test() -> None:
    cases = (
        ("obsolete_multi_engine_blocking_claim", "Fails only when both engines confirm.", True),
        (
            "obsolete_multi_engine_blocking_claim",
            "Findings only fail the build when both runtime and static engines agree.",
            True,
        ),
        (
            "obsolete_multi_engine_blocking_claim",
            "Two scanners must confirm before the check fails.",
            True,
        ),
        ("obsolete_multi_engine_blocking_claim", "Only correlated findings block", True),
        (
            "obsolete_multi_engine_blocking_claim",
            "Independent corroboration can raise confidence.",
            False,
        ),
        (
            "obsolete_multi_engine_blocking_claim",
            "Strong deterministic single-source evidence may block.",
            False,
        ),
        ("personal_repository_url", "https://github.com/Abdel-RahmanSaied/Fendix/releases", True),
        ("personal_repository_url", "https://github.com/Fendix-app/Fendix/releases", False),
        ("personal_ghcr_path", "ghcr.io/abdel-rahmansaied/fendix:latest", True),
        ("personal_ghcr_path", "docker.io/fendixapp/fendix:3.4.1", False),
    )
    detectors = {detector.name: detector.expression for detector in DETECTORS}
    for detector_name, sample, expected in cases:
        actual = detectors[detector_name].search(sample) is not None
        if actual != expected:
            raise AssertionError(
                f"{detector_name} regression for {sample!r}: {actual} != {expected}"
            )
    public_samples = {
        Path("README.md"),
        Path("nfpm.yaml"),
        Path("docs/install.md"),
        Path("service-docs/README.md"),
        Path("deploy/k8s/fendix-app.yaml"),
        Path(".github/ISSUE_TEMPLATE/config.yml"),
        Path("examples/github-actions/fendix-scan.yml"),
        Path("scripts/release/mirror-pages-bootstrap/index.html"),
    }
    for sample in public_samples:
        if not is_public_surface(sample):
            raise AssertionError(f"public-surface regression for {sample}")
    print(
        f"public-claims self-test passed ({len(cases)} detector cases, "
        f"{len(public_samples)} surface cases)"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--show-unclassified", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0

    files = tracked_files()
    allowlist = load_allowlist()
    findings = scan(files)
    violations, counts = classify(findings, allowlist)
    stale = [
        entry
        for entry in allowlist
        if counts[str(entry["id"])] != entry["expected_count"]
    ]
    if violations or stale:
        for finding in violations:
            print(
                f"{finding['path']}:{finding['line']}: {finding['detector']}: "
                f"{finding['match']}",
                file=sys.stderr,
            )
        for entry in stale:
            print(
                f"stale allowlist {entry['id']}: expected {entry['expected_count']}, "
                f"found {counts[str(entry['id'])]}",
                file=sys.stderr,
            )
        if args.show_unclassified:
            print(json.dumps(violations, indent=2), file=sys.stderr)
        return 1
    print(
        f"public-claims scan passed: {len(files)} surfaces, {len(findings)} "
        "narrowly allowlisted historical/compatibility references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
