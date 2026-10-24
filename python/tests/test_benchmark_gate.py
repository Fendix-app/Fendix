"""Regression gate on the labeled accuracy benchmark.

The HANDLED metrics (excluding documented known-gaps) must stay perfect: any
in-scope false positive or false negative is a real regression and fails CI.
The HONEST recall is asserted at its current floor so a *new* missed category
is caught, while the known roadmap gaps don't fail the build.

Run the full report with:  python -m benchmark.run_benchmark
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

from benchmark.run_benchmark import evaluate, load_corpus


def _results():
    return evaluate(load_corpus())


def test_handled_precision_and_recall_perfect():
    # In-scope behavior must be exact — no FP, no FN on handled patterns.
    h = _results()["handled"]
    assert h["fp"] == 0, f"in-scope false positives: {h['fp']}"
    assert h["fn"] == 0, f"in-scope false negatives: {h['fn']}"
    assert h["f1"] == 1.0


def test_no_unexpected_misscores():
    # `misses` only ever contains non-known-gap mis-scores; must be empty.
    assert _results()["misses"] == []


def test_honest_recall_floor():
    # True recall (incl. known gaps) must not drop below the recorded floor —
    # catches a NEW category becoming undetected. Raise this when gaps close.
    hon = _results()["honest"]
    assert hon["precision"] == 1.0, f"precision regressed: {hon['precision']}"
    assert hon["recall"] >= 0.80, f"honest recall regressed: {hon['recall']}"


def test_corpus_has_both_labels_per_category():
    # A category with only-vulnerable or only-safe cases can't measure both
    # precision and recall — guard the corpus stays balanced enough.
    corpus = load_corpus()
    assert len(corpus) >= 30
    assert sum(1 for c in corpus if c["label"] == "vulnerable") >= 10
    assert sum(1 for c in corpus if c["label"] == "safe") >= 10


# ── Framework parity corpus (benchmarks/frameworks/, defined by SPEC.md) ──────

_FRAMEWORKS_ROOT = Path(__file__).resolve().parents[2] / "benchmarks" / "frameworks"
_PARITY_FRAMEWORKS = (
    "django",
    "flask",
    "fastapi",
    "express",
    "nestjs",
    "nextjs",
    "spring",
    "nethttp",
    "gin",
)
_PARITY_CASES_PER_FRAMEWORK = 58
_MARKER_LINE = re.compile(r"EVAL-(SINK|SAFE)")
_RAW_CREDENTIAL_PATTERNS = (
    re.compile(r"AKIA[A-Z2-7]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
)


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace")


def _marker_lines(path: Path) -> list[str]:
    return [m.group(1) for line in _read(path).splitlines() if (m := _MARKER_LINE.search(line))]


def test_parity_corpus_is_well_formed():
    """The parity corpus is structurally sound and carries no real credentials.

    Secret-class cases contain placeholder tokens (``__EVAL_...__``) that the
    harness substitutes at scan time, so the corpus itself must never hold a
    credential-shaped value and the placeholders must stay inside the
    ``hardcoded_secret`` cases.
    """
    problems: list[str] = []

    for fw in _PARITY_FRAMEWORKS:
        root = _FRAMEWORKS_ROOT / fw
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            problems.append(f"{fw}: missing {manifest_path}")
            continue

        cases = json.loads(manifest_path.read_text(encoding="utf-8"))["cases"]
        if len(cases) != _PARITY_CASES_PER_FRAMEWORK:
            problems.append(
                f"{fw}: manifest lists {len(cases)} cases, expected {_PARITY_CASES_PER_FRAMEWORK}"
            )

        ids = [c["id"] for c in cases]
        if len(set(ids)) != len(ids):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            problems.append(f"{fw}: duplicate case ids {dupes}")

        secret_files: set[Path] = set()
        for case in cases:
            case_file = root / case["file"]
            if case["class"] == "hardcoded_secret":
                secret_files.add(case_file)
                if "entry_file" in case:
                    secret_files.add(root / case["entry_file"])

            if not case_file.is_file():
                problems.append(f"{case['id']}: file {case['file']} does not exist")
            else:
                markers = _marker_lines(case_file)
                expected = "SINK" if case["vulnerable"] else "SAFE"
                if markers != [expected]:
                    problems.append(
                        f"{case['id']}: {case['file']} has markers {markers}, "
                        f"expected exactly one EVAL-{expected}"
                    )

            entry = case.get("entry_file")
            if entry is not None:
                entry_path = root / entry
                if not entry_path.is_file():
                    problems.append(f"{case['id']}: entry_file {entry} does not exist")
                elif _marker_lines(entry_path):
                    problems.append(f"{case['id']}: entry_file {entry} contains a marker")

        # Placeholder tokens belong to hardcoded_secret cases only. This scans
        # the nine corpus roots; SPEC.md, RESULTS.md, run_parity.py and results/
        # live beside them and legitimately name the tokens.
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            if path not in secret_files and "__EVAL_" in _read(path):
                problems.append(
                    f"{fw}: {path.relative_to(root)} contains __EVAL_ but is not a "
                    "hardcoded_secret case file"
                )

    # Raw credentials must not appear anywhere under benchmarks/frameworks/.
    corpus_files = (
        sorted(p for p in _FRAMEWORKS_ROOT.rglob("*") if p.is_file())
        if _FRAMEWORKS_ROOT.is_dir()
        else []
    )
    for path in corpus_files:
        text = _read(path)
        for pattern in _RAW_CREDENTIAL_PATTERNS:
            if pattern.search(text):
                problems.append(
                    f"{path.relative_to(_FRAMEWORKS_ROOT)}: matches raw credential "
                    f"pattern {pattern.pattern}"
                )

    assert not problems, "parity corpus problems:\n  " + "\n  ".join(problems)


# ── Framework parity gate (benchmarks/frameworks/run_parity.py) ───────────────


def _load_run_parity():
    """Import the harness by file path.

    benchmarks/frameworks is a data directory, not a package, and putting it on
    sys.path would let a corpus file named like a stdlib or test module shadow
    that module for the whole test session. Loading the one file under a private
    name avoids both.
    """
    spec = importlib.util.spec_from_file_location(
        "fendix_run_parity", _FRAMEWORKS_ROOT / "run_parity.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_parity = _load_run_parity()
compare_to_baseline = _parity.compare_to_baseline
load_baseline = _parity.load_baseline


def test_gate_rejects_tp_to_fn():
    assert compare_to_baseline(current={"a": ("FN", False)}, baseline={"a": ("TP", True)}).regressions == [
        "a: TP->FN"
    ]


def test_gate_rejects_tn_to_fp_and_new_safe_block():
    r = compare_to_baseline(current={"s": ("FP", True)}, baseline={"s": ("TN", False)})
    assert r.regressions == ["s: TN->FP", "s: safe case now blocks"]


def test_gate_rejects_lost_block():
    assert compare_to_baseline(current={"a": ("TP", False)}, baseline={"a": ("TP", True)}).regressions == [
        "a: no longer blocks"
    ]


def test_gate_reports_improvements_without_failing():
    r = compare_to_baseline(current={"a": ("TP", True)}, baseline={"a": ("FN", False)})
    assert r.regressions == [] and r.improvements == ["a: FN->TP"]


def test_gate_rejects_unknown_or_missing_cases():
    r = compare_to_baseline(current={}, baseline={"a": ("TP", True)})
    assert r.regressions == ["a: missing from run"]


def test_gate_rejects_case_not_in_baseline():
    r = compare_to_baseline(current={"new": ("TP", True)}, baseline={})
    assert r.regressions == ["new: not in baseline"]


def test_baseline_round_trips_through_the_file(tmp_path):
    state = {"b": ("FN", False), "a": ("TP", True)}
    path = tmp_path / "baseline.json"
    _parity.write_baseline(path, "fendix version dev", state)
    assert load_baseline(path) == state
    assert list(json.loads(path.read_text(encoding="utf-8"))["cases"]) == ["a", "b"]


def test_committed_baseline_matches_the_corpus():
    """baseline.json holds exactly the manifest's cases, each scored as its label implies.

    run_parity.py --frameworks gates a subset by the "<framework>-" prefix of the
    case ids, so the prefix is checked here too.
    """
    baseline = load_baseline(_FRAMEWORKS_ROOT / "baseline.json")
    cases = {}
    for fw in _PARITY_FRAMEWORKS:
        manifest = json.loads((_FRAMEWORKS_ROOT / fw / "manifest.json").read_text(encoding="utf-8"))
        for case in manifest["cases"]:
            cases[case["id"]] = (fw, case["vulnerable"])

    assert set(baseline) == set(cases)
    problems = []
    for case_id, (fw, vulnerable) in cases.items():
        outcome, _ = baseline[case_id]
        if not case_id.startswith(f"{fw}-"):
            problems.append(f"{case_id}: id does not start with '{fw}-'")
        if (outcome in ("TP", "FN")) != vulnerable:
            problems.append(f"{case_id}: outcome {outcome} contradicts vulnerable={vulnerable}")
    assert not problems, "\n  ".join(problems)
