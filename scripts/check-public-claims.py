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
APP_RELEASE_PATH = ROOT / "deploy" / "fendix-app-release.json"
APP_MANIFEST_PATH = ROOT / "deploy" / "k8s" / "fendix-app.yaml"


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
    # Every other spelling of the retired personal namespace: bare module
    # paths, repository slugs, tap names, Pages hosts. Matches inside a span
    # the two detectors above already report are skipped (see find_matches),
    # so each occurrence is classified exactly once.
    Detector(
        "personal_namespace",
        re.compile(r"abdel-rahmansaied(?:[/.][A-Za-z0-9_-]+)*", re.IGNORECASE),
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
    # A workflow line that runs the composite Action from a branch, which
    # changes without review. The validated `@v1` tag and a full release
    # commit are the supported references.
    Detector(
        "floating_action_branch",
        re.compile(
            r"^[ \t]*(?:-[ \t]*)?uses:[ \t]*[\"']?Fendix-app/Fendix@(?:main|master|HEAD)(?![\w.\-/])",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    # Retired claims about the Action and diff mode: diff mode scopes only the
    # native file scanners, whole files, so it does not surface only "new"
    # issues; requirements.txt declares ranges.
    Detector(
        "obsolete_action_claim",
        re.compile(
            r"actually\s+introduced"
            r"|net-new\s+(?:issues|findings)"
            r"|pins\s+exact\s+versions"
            r"|whitebox\s+scanners\s+(?:are\s+)?scoped\s+to\s+(?:the\s+)?changed\s+files",
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
    # Shipped source: Go imports and module metadata end up in every binary,
    # and go/internal/initcmd/templates/ is written into users' repositories.
    if value.startswith(("go/", "python/")):
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
        # regression-guard: a test's own search pattern for the string it
        # forbids, the one place the pattern must be spelled out.
        if entry["classification"] not in {"historical", "compatibility", "regression-guard"}:
            raise ValueError(f"invalid classification for {entry['id']}")
        if not isinstance(entry["expected_count"], int) or entry["expected_count"] < 1:
            raise ValueError(f"invalid expected_count for {entry['id']}")
        for field in ("path", "detector", "pattern", "reason", "removal_condition"):
            if not isinstance(entry[field], str) or not str(entry[field]).strip():
                raise ValueError(f"missing {field} for {entry['id']}")
        re.compile(str(entry["pattern"]), re.IGNORECASE)
    return data


def find_matches(content: str) -> list[tuple[str, re.Match[str]]]:
    matches: list[tuple[str, re.Match[str]]] = []
    claimed: list[tuple[int, int]] = []
    for detector in DETECTORS:
        for match in detector.expression.finditer(content):
            if detector.name == "personal_namespace" and any(
                start < match.end() and match.start() < end for start, end in claimed
            ):
                continue
            if detector.name in {"personal_repository_url", "personal_ghcr_path"}:
                claimed.append(match.span())
            matches.append((detector.name, match))
    return matches


# ---------------------------------------------------------------------------
# Accuracy claims must name what they were measured on.
#
# A bare "F1 = 1.000" reads as a statement about every language Fendix scans.
# Fendix's numbers differ by language and by corpus (development set versus the
# blind holdout), so a figure is only publishable in a sentence that also names
# a language, framework or corpus. See benchmarks/frameworks/ and
# docs/accuracy.md.
# ---------------------------------------------------------------------------

ACCURACY_METRIC = re.compile(
    r"\bF1\b|\bprecision\b|\brecall\b|\baccuracy\b|\baccurate\b", re.IGNORECASE
)
# A ratio (0.944, 1.000, .75) or a percentage (94%, 94.4 %) anywhere near a
# metric word. A ratio needs two decimals and must not touch another dot-digit
# group, so versions such as 3.6.2 or 1.141.0 and short numbers such as 3.6
# stay out.
ACCURACY_FIGURE = re.compile(
    r"(?<![\w.])(?:[01]?\.\d{2,}|\d{1,3}(?:\.\d+)?[ ]?%)(?![\w]|\.\d)"
)
# A bare integer or one-decimal value ("F1 = 1.0", "F1 of 1", "recall: 94")
# only counts when it follows the metric word directly, so "recall ... 10
# findings" and "precision on Track 4" stay out.
ACCURACY_FIGURE_AFTER_METRIC = re.compile(
    r"\b(?:F1|precision|recall|accuracy)\b(?:[\s*_`|]|\b(?:score|rate|of|is|was|at|reaches|hits)\b|[=:≥>~≈])*"
    r"(?<![\w.])(\d+(?:\.\d+)?)(?![\w]|\.\d)",
    re.IGNORECASE,
)
# "0.5% lower than expected" is a difference, not a measurement.
ACCURACY_RELATIVE = re.compile(
    r"^[ ]?%?\s*(?:points?\s+)?(?:lower|higher|less|more|better|worse|smaller|larger|faster|slower)\b",
    re.IGNORECASE,
)
ACCURACY_WINDOW = 80
# Scope: a language or framework, or an explicitly named corpus. Generic words
# such as "cases", "samples", "benchmark", "dataset" or "dev" name nothing.
ACCURACY_SCOPE = re.compile(
    r"\b(?:python|django|flask|fastapi|javascript|typescript|node\.?js|"
    r"golang|net/http|kotlin|php|js/ts|"
    r"java|"
    r"synthetic(?:\s+python)?\s+corpus|juliet|holdout|hold-out|"
    r"(?:development|dev)\s+(?:corpus|set)|parity\s+(?:corpus|gate|holdout)|"
    r"heavy-eval\s+corpus|twiscope|pygoat|juice\s+shop|dvwa|webgoat|bwapp)\b",
    re.IGNORECASE,
)
# Names that are ordinary words in lower case count only capitalised.
ACCURACY_SCOPE_CAPITALISED = re.compile(r"\b(?:Go|Express|NestJS|Next\.js|Spring|Gin|Rust|Ruby)\b")
# An F1 of 1 is the strongest claim Fendix makes, and the one that was
# repeated without its scope: it must carry the language and the known gaps.
ACCURACY_F1_ONE = re.compile(
    r"\bF1\b(?:[\s*_`|]|\b(?:score|of|is|was|at|reaches|hits)\b|[=:≥>~≈])*"
    r"(?<![\w.])1(?:\.0+)?(?![\w]|\.\d)"
    r"|(?<![\w.])1\.0+(?![\w]|\.\d)[\s*_`|]*F1\b",
    re.IGNORECASE,
)
# A table row's F1 label followed by a cell holding exactly 1.
ACCURACY_F1_ROW_ONE = re.compile(r"\bF1\b[^|]*\|[\s*]*1(?:\.0+)?[\s*]*(?:\||$)", re.IGNORECASE)
# A confidence interval's upper bound ("[0.953, 1.000]", "0.953–1.000") is not
# an F1 of 1.
ACCURACY_F1_INTERVAL = re.compile(r"\[[^\]]*\]|[\d.]+\s*[–-]\s*[\d.]+")
ACCURACY_F1_PYTHON = re.compile(r"\bpython\b", re.IGNORECASE)
ACCURACY_F1_GAPS = re.compile(r"\bknown[- ]gaps?\b", re.IGNORECASE)
_BLOCK_START = re.compile(r"^\s*(?:\||#{1,6}\s|[-*+]\s|\d+[.)]\s)")
_QUOTE_MARKER = re.compile(r"^\s*(?:>\s?)+")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z`*(\[\"'])")


def _accuracy_units(text: str) -> list[tuple[int, str]]:
    """Split markdown into (line, sentence) units, skipping fenced code.

    A table row, heading or list item starts its own unit; a wrapped paragraph
    is joined and split on sentence ends, so a scope in the previous sentence
    does not carry over.
    """
    units: list[tuple[int, str]] = []
    paragraph: list[str] = []
    start = 0
    in_fence = False

    def flush() -> None:
        if paragraph:
            joined = " ".join(part.strip() for part in paragraph)
            units.extend((start, part) for part in _SENTENCE_END.split(joined))
            paragraph.clear()

    for number, raw in enumerate(text.splitlines(), start=1):
        # A blockquote continues its sentence over lines, so judge its text.
        line = _QUOTE_MARKER.sub("", raw)
        if line.lstrip().startswith(("```", "~~~")):
            flush()
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not line.strip():
            flush()
            continue
        if _BLOCK_START.match(line):
            flush()
            if line.lstrip().startswith("|"):
                units.append((number, line))
                continue
            start = number
        elif not paragraph:
            start = number
        paragraph.append(line)
    flush()
    return units


def _has_accuracy_figure(sentence: str) -> bool:
    metrics = list(ACCURACY_METRIC.finditer(sentence))
    if not metrics:
        return False
    for figure in ACCURACY_FIGURE.finditer(sentence):
        if ACCURACY_RELATIVE.match(sentence[figure.end():]):
            continue
        if any(abs(m.start() - figure.start()) <= ACCURACY_WINDOW for m in metrics):
            return True
    for figure in ACCURACY_FIGURE_AFTER_METRIC.finditer(sentence):
        if not ACCURACY_RELATIVE.match(sentence[figure.end():]):
            return True
    return False


def _is_scoped(sentence: str) -> bool:
    return bool(
        ACCURACY_SCOPE.search(sentence) or ACCURACY_SCOPE_CAPITALISED.search(sentence)
    )


def _is_unscoped_f1_one(sentence: str) -> bool:
    """An F1 of 1 without both the language (Python) and the known gaps."""
    if not re.search(r"\bF1\b", sentence, re.IGNORECASE):
        return False
    sentence = ACCURACY_F1_INTERVAL.sub(" ", sentence)
    claims_one = ACCURACY_F1_ONE.search(sentence) or (
        # A table row: "| F1 (scope) | 1.000 |".
        sentence.lstrip().startswith("|") and ACCURACY_F1_ROW_ONE.search(sentence)
    )
    if not claims_one:
        return False
    return not (
        ACCURACY_F1_PYTHON.search(sentence) and ACCURACY_F1_GAPS.search(sentence)
    )


def find_unscoped_accuracy(text: str) -> list[tuple[int, str]]:
    """Return (line, sentence) for every accuracy figure with no scope.

    Two rules: any accuracy figure needs a language, framework or named corpus
    in its sentence; an F1 of 1 also needs "Python" and "known gaps" there.
    """
    found: list[tuple[int, str]] = []
    for line, sentence in _accuracy_units(text):
        if _is_unscoped_f1_one(sentence) or (
            _has_accuracy_figure(sentence) and not _is_scoped(sentence)
        ):
            found.append((line, sentence.strip()))
    return found


# Dated records and design history describe a past measurement; they are not
# current product claims.
ACCURACY_SCOPE_EXEMPT_PREFIXES = (
    "docs/superpowers/",
    "docs/plans/",
    "docs/reviews/",
)


def is_accuracy_surface(path: Path) -> bool:
    value = path.as_posix()
    if value.startswith(ACCURACY_SCOPE_EXEMPT_PREFIXES):
        return False
    if value in {"README.md", "BENCHMARKS.md"}:
        return True
    return value.startswith("docs/") and path.suffix.lower() in {".md", ".markdown"}


def scan_accuracy_scope(files: list[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for relative in files:
        if not is_accuracy_surface(relative):
            continue
        try:
            content = (ROOT / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line, sentence in find_unscoped_accuracy(content):
            findings.append(
                {
                    "path": relative.as_posix(),
                    "detector": "unscoped_accuracy_figure",
                    "match": sentence[:160],
                    "line": line,
                }
            )
    return findings


def scan(files: list[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for relative in files:
        try:
            content = (ROOT / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for detector_name, match in find_matches(content):
            findings.append(
                {
                    "path": relative.as_posix(),
                    "detector": detector_name,
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


def validate_app_deployment(manifest: str, contract: dict[str, object]) -> None:
    image = contract.get("image")
    version = contract.get("version")
    digest = contract.get("digest")
    platforms = contract.get("platforms")
    platform_digests = contract.get("platform_digests")
    if image != "docker.io/fendixapp/fendix-app":
        raise ValueError("fendix-app release contract must use the official image")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("fendix-app release contract has an invalid version")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("fendix-app release contract has an invalid manifest digest")
    if platforms != ["linux/amd64", "linux/arm64"]:
        raise ValueError("fendix-app release contract must declare exactly two supported platforms")
    if not isinstance(platform_digests, dict) or set(platform_digests) != set(platforms):
        raise ValueError("fendix-app release contract platform digests are incomplete")
    if any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        for value in platform_digests.values()
    ):
        raise ValueError("fendix-app release contract has an invalid platform digest")

    references = re.findall(r"^\s*image:\s*([^\s#]+)", manifest, re.MULTILINE)
    expected = f"{image}@{digest}"
    if references != [expected]:
        raise ValueError(
            "deploy/k8s/fendix-app.yaml must contain exactly the verified "
            f"application image {expected}; found {references}"
        )
    if f"Official application image version: {version}" not in manifest:
        raise ValueError("Kubernetes image digest must retain its human-readable version")
    if re.search(r"^\s*imagePullSecrets\s*:", manifest, re.MULTILINE):
        raise ValueError("the public fendix-app image must use anonymous pull access")


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
        ("personal_namespace", '"github.com/Abdel-RahmanSaied/Fendix/internal/models"', True),
        ("personal_namespace", "brew tap Abdel-RahmanSaied/fendix", True),
        ("personal_namespace", "get.fendix.dev CNAME abdel-rahmansaied.github.io.", True),
        ("personal_namespace", '"github.com/Fendix-app/Fendix/go/internal/models"', False),
        ("floating_action_branch", "      - uses: Fendix-app/Fendix@main\n", True),
        ("floating_action_branch", "uses: fendix-app/fendix@master # moving branch", True),
        ("floating_action_branch", "      - uses: Fendix-app/Fendix@v1\n", False),
        ("floating_action_branch", "> Never reference `uses: Fendix-app/Fendix@main`.", False),
        ("floating_action_branch", "      - uses: Fendix-app/Fendix@b9e1fad6e1d9531ac899ab44b01f413424f30a7a # v3.6.2", False),
        ("obsolete_action_claim", "only surfaces issues the PR actually introduced", True),
        ("obsolete_action_claim", "`python/requirements.txt` pins exact versions.", True),
        ("obsolete_action_claim", "Whitebox scanners are scoped to the changed files", True),
        ("obsolete_action_claim", "a CI job using the public Marketplace Action", False),
        ("obsolete_action_claim", "only flags net-new issues", True),
        ("obsolete_action_claim", "whole files, so existing issues in them are reported", False),
        ("obsolete_action_claim", "Use a baseline to report only new findings.", False),
    )
    accuracy_cases = (
        # An accuracy figure with no language or corpus scope in its sentence.
        ("Fendix reaches F1 = 1.000.", 1),
        ("Precision is 0.97 across the board.", 1),
        ("We catch 94% of vulnerabilities, a recall of 0.94.", 1),
        ("Overall accuracy: 99%.", 1),
        ("| recall | 0.944 |", 1),
        # Scoped by a language, framework or corpus in the same sentence.
        ("Python recall is 0.756 on the blind holdout.", 0),
        ("Dev recall 1.000 on the development corpus.", 0),
        ("HANDLED F1 == 1.000 on the Python synthetic corpus, excluding documented known gaps.", 0),
        ("| JS/TS | 0.889 | recall |", 0),
        ("Java (Spring) precision was 0.11 on real-world code.", 0),
        ("Go precision 0.09.", 0),
        # A scope in the previous sentence does not carry over.
        ("This is the Python layer. Recall is 0.99.", 1),
        # A paragraph wrapped over lines is one sentence.
        ("Recall on the\nholdout corpus is 0.756.", 0),
        # A blockquote wrapped over lines is one sentence.
        ("> Recall is 0.99 on the\n> Python corpus.", 0),
        ("> Recall is 0.99 on\n> the full set.", 1),
        # (a) A generic word is not a scope: name a language, framework or corpus.
        ("Overall F1 of 0.97 across all cases.", 1),
        ("The benchmark shows precision of 0.99.", 1),
        ("recall of 94 across the dataset", 1),
        ("Recall is 0.92 on these samples, in dev.", 1),
        ("Precision is 0.9 for js and ts.", 1),
        ("Recall is 0.99 on the development corpus.", 0),
        ("Recall is 0.75 on the parity holdout.", 0),
        ("Precision is 0.04 on TWISCOPE.", 0),
        ("Recall is 0.99 on the Juliet-style Python corpus.", 0),
        ("Recall is 0.9 for JS/TS.", 0),
        # (b) Integers and one-decimal values count as figures.
        ("F1 = 1.0", 1),
        ("F1 of 1 across the board.", 1),
        ("Precision is 0.9 everywhere.", 1),
        ("Recall: 94 everywhere.", 1),
        ("F1 **1** everywhere.", 1),
        ("Python recall is 0.9.", 0),
        # (c) An F1 of 1 needs Python and the known gaps in the same sentence.
        ("F1 = 1.000 on the Python synthetic corpus.", 1),
        ("F1 = 1.000 on the synthetic corpus, excluding documented known gaps.", 1),
        ("F1 = 1.000 on the Go development corpus, excluding documented known gaps.", 1),
        ("F1 = 1.000 on the Python synthetic corpus, excluding documented known gaps.", 0),
        ("1.000 F1 on the Python synthetic corpus, excluding documented known gaps.", 0),
        ("| F1 (Python synthetic corpus, excluding documented known gaps) | 1.000 |", 0),
        ("| F1 (Python synthetic corpus) | 1.000 |", 1),
        ("| F1 (Python synthetic corpus) | **1.000** |", 1),
        ("| 4a Juliet | F1 = 0.987 (P 0.974 / R 1.000) |", 0),
        ("F1 95% bootstrap CI [0.953, 1.000] on the Juliet-style Python corpus.", 0),
        ("1.000 F1 on the Python corpus (CI 0.953–1.000, bootstrapped).", 1),
        ("F1 is 0.987 on the Juliet-style Python corpus.", 0),
        ("Python recall is 1.000 on the development corpus.", 0),
        # (d) A relative difference is not an accuracy figure.
        ("recall is 0.5% lower than expected value", 0),
        # Not accuracy claims.
        ("Fendix v3.6.2 ships a precision-focused gate.", 0),
        ("Requires Python 3.11 and Semgrep 1.141.0.", 0),
        ("CVSS 9.8 findings are critical; 100% of CI runs are cached.", 0),
        ("Recall matters because a miss hides a vulnerability.", 0),
        ("Raise the confidence threshold to 0.80 to cut noise.", 0),
        ("```\nrecall = 0.94\n```", 0),
    )
    for sample, expected in accuracy_cases:
        actual = len(find_unscoped_accuracy(sample))
        if actual != expected:
            raise AssertionError(
                f"unscoped accuracy regression for {sample!r}: {actual} != {expected}"
            )
    detectors = {detector.name: detector.expression for detector in DETECTORS}
    for detector_name, sample, expected in cases:
        actual = detectors[detector_name].search(sample) is not None
        if actual != expected:
            raise AssertionError(
                f"{detector_name} regression for {sample!r}: {actual} != {expected}"
            )
    url = "https://github.com/Abdel-RahmanSaied/Fendix/releases"
    if [name for name, _ in find_matches(url)] != ["personal_repository_url"]:
        raise AssertionError("a personal URL must be reported once, by its specific detector")
    public_samples = {
        Path("README.md"),
        Path("go/go.mod"),
        Path("go/internal/initcmd/templates/workflow.yml"),
        Path("nfpm.yaml"),
        Path("docs/install.md"),
        Path("service-docs/README.md"),
        Path("deploy/k8s/fendix-app.yaml"),
        Path(".github/ISSUE_TEMPLATE/config.yml"),
        Path("examples/github-actions/fendix-scan.yml"),
        Path("scripts/release/mirror-pages-bootstrap/index.html"),
    }
    for path, expected in (
        ("README.md", True),
        ("BENCHMARKS.md", True),
        ("docs/accuracy.md", True),
        ("docs/superpowers/plans/x.md", False),
        ("CHANGELOG.md", False),
    ):
        if is_accuracy_surface(Path(path)) != expected:
            raise AssertionError(f"accuracy-surface regression for {path}")
    for sample in public_samples:
        if not is_public_surface(sample):
            raise AssertionError(f"public-surface regression for {sample}")
    digest = "sha256:" + "a" * 64
    contract = {
        "image": "docker.io/fendixapp/fendix-app",
        "version": "3.4.1",
        "digest": digest,
        "platforms": ["linux/amd64", "linux/arm64"],
        "platform_digests": {
            "linux/amd64": "sha256:" + "b" * 64,
            "linux/arm64": "sha256:" + "c" * 64,
        },
    }
    valid_manifest = (
        "# Official application image version: 3.4.1\n"
        f"          image: docker.io/fendixapp/fendix-app@{digest}\n"
    )
    validate_app_deployment(valid_manifest, contract)
    invalid_manifests = (
        valid_manifest.replace("docker.io/fendixapp", "ghcr.io/personal"),
        valid_manifest.replace(f"@{digest}", ":latest"),
        valid_manifest.replace(digest, "sha256:" + "d" * 64),
        valid_manifest + "imagePullSecrets: []\n",
    )
    for invalid_manifest in invalid_manifests:
        try:
            validate_app_deployment(invalid_manifest, contract)
        except ValueError:
            continue
        raise AssertionError(f"invalid app deployment accepted: {invalid_manifest!r}")
    print(
        f"public-claims self-test passed ({len(cases)} detector cases, "
        f"{len(accuracy_cases)} accuracy-scope cases, "
        f"{len(public_samples)} surface cases, 5 application-image cases)"
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
    contract = json.loads(APP_RELEASE_PATH.read_text(encoding="utf-8"))
    validate_app_deployment(
        APP_MANIFEST_PATH.read_text(encoding="utf-8"), contract
    )
    findings = scan(files)
    scope_violations = scan_accuracy_scope(files)
    violations, counts = classify(findings, allowlist)
    stale = [
        entry
        for entry in allowlist
        if counts[str(entry["id"])] != entry["expected_count"]
    ]
    violations = violations + scope_violations
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
