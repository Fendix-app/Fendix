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

import pytest

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


# ── Corpus root and held-out recall (the release-time holdout run) ────────────
#
# The holdout lives in a private repository and has the same nine framework
# directories and manifest format as the development corpus, but fewer cases
# (30 per framework, not 58). run_parity.py reads it through --corpus-root and,
# with --compare-recall-to, checks its recall per language family against the
# development baseline. Nothing here needs the engine or the holdout itself.

_FAKE_ENGINE = """#!{python}
import json, os, sys

args = sys.argv[1:]
if args[:1] == ["version"]:
    print("fendix fake-engine")
    raise SystemExit(0)
root = args[args.index("--code") + 1]
findings = []
for folder, _, names in os.walk(root):
    for name in sorted(names):
        path = os.path.join(folder, name)
        for number, line in enumerate(open(path, encoding="utf-8"), start=1):
            if "EVAL-SINK" in line:
                findings.append({{
                    "rule_id": "PY_SQL_INJECTION",
                    "title": "SQL injection",
                    "status": "BLOCK",
                    "endpoint": os.path.relpath(path, root).replace(os.sep, "/") + ":" + str(number),
                }})
print(json.dumps({{"findings": findings}}))
"""


def _write_flask_corpus(root: Path, cases: list[tuple[str, str, bool]]) -> None:
    """A one-framework corpus under `root`: (case id, class, vulnerable) per case.

    The fake engine reports every EVAL-SINK file as SQL injection, so a
    vulnerable sqli case is a TP and a vulnerable case of any other class is
    an FN.
    """
    app = root / "flask" / "app"
    app.mkdir(parents=True)
    manifest = []
    for case_id, klass, vulnerable in cases:
        rel = f"app/{case_id}.py"
        marker = "EVAL-SINK" if vulnerable else "EVAL-SAFE"
        (root / "flask" / rel).write_text(f"# {marker}\nvalue = 1\n", encoding="utf-8")
        manifest.append(
            {
                "id": case_id,
                "class": klass,
                "variant": "direct" if vulnerable else "safe",
                "vulnerable": vulnerable,
                "file": rel,
            }
        )
    (root / "flask" / "manifest.json").write_text(
        json.dumps({"framework": "flask", "language": "python", "cases": manifest}), encoding="utf-8"
    )


def _fake_engine(tmp_path: Path) -> Path:
    binary = tmp_path / "fendix"
    binary.write_text(_FAKE_ENGINE.format(python=sys.executable), encoding="utf-8")
    binary.chmod(0o755)
    return binary


def _dev_baseline(tmp_path: Path, outcomes: dict[str, str]) -> Path:
    """A dev baseline over the real flask corpus: `outcomes` by case id, every other case a clean result.

    Unlisted vulnerable cases are FN and unlisted safe cases TN, so a test names only the cases it cares about.
    """
    manifest = json.loads((_FRAMEWORKS_ROOT / "flask" / "manifest.json").read_text(encoding="utf-8"))
    state = {}
    for case in manifest["cases"]:
        default = "FN" if case["vulnerable"] else "TN"
        outcome = outcomes.get(case["id"], default)
        state[case["id"]] = (outcome, outcome == "TP")
    unknown = set(outcomes) - set(state)
    assert not unknown, f"not flask dev cases: {unknown}"
    path = tmp_path / "dev-baseline.json"
    _parity.write_baseline(path, "fendix dev", state)
    return path


def test_corpus_root_flag_changes_manifest_source(tmp_path):
    """materialize() and score_framework() read the given root, not the script's directory."""
    root = tmp_path / "holdout"
    _write_flask_corpus(root, [("flask-h-one", "sqli", True), ("flask-h-two", "sqli", False)])

    held_out = tmp_path / "held-out-tree"
    _parity.materialize("flask", held_out, root=root)
    held_manifest = json.loads((held_out / "manifest.json").read_text(encoding="utf-8"))
    assert [c["id"] for c in held_manifest["cases"]] == ["flask-h-one", "flask-h-two"]
    assert (held_out / "app" / "flask-h-one.py").is_file()
    assert not (held_out / "app" / "sqli_direct.py").exists()  # a development-corpus file

    scored = _parity.score_framework("flask", {"findings": []}, held_out, root=root)
    assert [c["id"] for c in scored["cases"]] == ["flask-h-one", "flask-h-two"]
    assert [c["outcome"] for c in scored["cases"]] == ["FN", "TN"]

    # With no root, today's behaviour is unchanged: the development corpus.
    default_tree = tmp_path / "default-tree"
    _parity.materialize("flask", default_tree)
    assert (default_tree / "manifest.json").read_bytes() == (_FRAMEWORKS_ROOT / "flask" / "manifest.json").read_bytes()


def test_corpus_root_substitutes_placeholders_in_the_given_root(tmp_path):
    root = tmp_path / "holdout"
    _write_flask_corpus(root, [("flask-h-secret", "hardcoded_secret", True)])
    (root / "flask" / "app" / "flask-h-secret.py").write_text("# EVAL-SINK\nkey = '__EVAL_GITHUB_TOKEN__'\n")

    tree = tmp_path / "tree"
    _parity.materialize("flask", tree, root=root)
    text = (tree / "app" / "flask-h-secret.py").read_text(encoding="utf-8")
    assert "__EVAL_" not in text
    assert re.search(r"ghp_[A-Za-z0-9]{36}", text)


def test_timing_scales_the_corpus_it_was_given(tmp_path):
    root = tmp_path / "holdout"
    _write_flask_corpus(root, [("flask-h-a", "sqli", True), ("flask-h-b", "sqli", False)])
    timed = _parity.timing(str(_fake_engine(tmp_path)), "flask", tmp_path / "scratch", "HIGH", 1, 3, root=root)
    assert timed["1x"]["files"] == 2  # not the ~60 files of the development corpus
    assert timed["3x"]["files"] == 6


def test_main_rejects_a_corpus_root_that_lacks_a_requested_framework(tmp_path, monkeypatch, capsys):
    (tmp_path / "empty-root").mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_parity.py", "--fendix", "unused", "--out", str(tmp_path / "out"), "--frameworks", "flask",
         "--corpus-root", str(tmp_path / "empty-root")],
    )
    with pytest.raises(SystemExit) as raised:
        _parity.main()
    assert raised.value.code == 2
    assert "flask" in capsys.readouterr().err


def _counts(**families):
    """Pair-level counts with one shared (sqli, direct) pair per family: family=(detected, vulnerable)."""
    return {family: {("sqli", "direct"): tuple(pair)} for family, pair in families.items()}


def test_recall_comparison_passes_when_every_family_is_within_ten_points():
    dev = _counts(python=(80, 100), **{"js-ts": (90, 100)}, java=(70, 100), go=(60, 100))
    holdout = _counts(python=(75, 100), **{"js-ts": (81, 100)}, java=(70, 100), go=(66, 100))  # js-ts: -9 points
    result = _parity.compare_recall(dev, holdout, 0.10)
    assert result.failures == []
    assert result.lines == [
        "go dev=0.600 holdout=0.660 drop=-0.060 pairs=1",
        "java dev=0.700 holdout=0.700 drop=0.000 pairs=1",
        "js-ts dev=0.900 holdout=0.810 drop=0.090 pairs=1",
        "python dev=0.800 holdout=0.750 drop=0.050 pairs=1",
    ]


def test_recall_comparison_fails_and_names_the_family_that_drops_eleven_points():
    dev = _counts(python=(80, 100), java=(70, 100))
    holdout = _counts(python=(69, 100), java=(70, 100))  # python: -11 points
    result = _parity.compare_recall(dev, holdout, 0.10)
    assert len(result.failures) == 1
    assert result.failures[0].startswith("python:")
    assert "python dev=0.800 holdout=0.690 drop=0.110 pairs=1" in result.lines
    assert "java dev=0.700 holdout=0.700 drop=0.000 pairs=1" in result.lines


def test_recall_comparison_accepts_exactly_ten_points_without_float_noise():
    # 0.8 - 0.7 is 0.10000000000000009 in binary floating point; the limit is
    # "more than 10 points", so exactly 10 must pass.
    result = _parity.compare_recall(_counts(python=(8, 10)), _counts(python=(7, 10)), 0.10)
    assert result.failures == []


def test_recall_comparison_limit_is_configurable():
    dev, holdout = _counts(go=(80, 100)), _counts(go=(74, 100))
    assert _parity.compare_recall(dev, holdout, 0.05).failures != []
    assert _parity.compare_recall(dev, holdout, 0.06).failures == []


def test_a_direct_only_holdout_is_compared_with_dev_direct_cases_only():
    """A dev cross_file miss must not lower dev recall when the holdout has no cross_file case."""
    dev = {"python": {("sqli", "direct"): (10, 10), ("sqli", "cross_file"): (0, 10), ("cmdi", "indirect"): (0, 10)}}
    holdout = {"python": {("sqli", "direct"): (9, 10)}}
    result = _parity.compare_recall(dev, holdout, 0.10)
    # Over all 30 dev cases dev recall would be 0.333 and this would pass; matched, it is 1.0 against 0.9.
    assert result.lines == ["python dev=1.000 holdout=0.900 drop=0.100 pairs=1"]
    assert result.failures == []  # exactly ten points
    worse = _parity.compare_recall(dev, {"python": {("sqli", "direct"): (8, 10)}}, 0.10)
    assert [f.split(":")[0] for f in worse.failures] == ["python"]


def test_a_pair_present_only_in_the_holdout_is_excluded():
    dev = {"python": {("sqli", "direct"): (8, 10)}}
    holdout = {"python": {("sqli", "direct"): (8, 10), ("ssti", "alt_api"): (0, 5)}}
    result = _parity.compare_recall(dev, holdout, 0.10)
    # Counting the holdout-only pair would give 8/15 = 0.533 and fail.
    assert result.lines == ["python dev=0.800 holdout=0.800 drop=0.000 pairs=1"]
    assert result.failures == []


def test_recall_is_pooled_over_the_comparable_pairs_of_a_family():
    dev = {"go": {("sqli", "direct"): (10, 10), ("xss", "direct"): (6, 10), ("ssrf", "direct"): (0, 40)}}
    holdout = {"go": {("sqli", "direct"): (9, 10), ("xss", "direct"): (5, 10)}}
    result = _parity.compare_recall(dev, holdout, 0.10)
    assert result.lines == ["go dev=0.800 holdout=0.700 drop=0.100 pairs=2"]  # 16/20 against 14/20; ssrf is dev-only
    assert result.failures == []


@pytest.mark.parametrize(
    "dev, holdout, reason",
    [
        ({"go": {("sqli", "direct"): (0, 0)}}, {"go": {("sqli", "direct"): (9, 10)}}, "dev set"),
        ({"go": {("sqli", "direct"): (9, 10)}}, {"go": {("sqli", "direct"): (0, 0)}}, "holdout set"),
        ({"go": {("sqli", "direct"): (9, 10)}}, {}, "holdout set"),  # the family is missing from the run altogether
        ({}, {"go": {("sqli", "direct"): (9, 10)}}, "dev set"),  # ... or from the baseline
        # Both sides have vulnerable cases but no (class, variant) pair in common.
        ({"go": {("sqli", "direct"): (9, 10)}}, {"go": {("cmdi", "direct"): (9, 10)}}, "pair"),
    ],
)
def test_recall_comparison_fails_closed_when_a_family_has_no_comparable_vulnerable_cases(dev, holdout, reason):
    """A family that cannot be measured fails the comparison instead of passing silently."""
    result = _parity.compare_recall(dev, holdout, 0.10)
    assert len(result.failures) == 1
    assert result.failures[0].startswith("go:")
    assert reason in result.failures[0]
    assert result.lines == ["go dev=n/a holdout=n/a drop=n/a pairs=0"]


def test_baseline_recall_counts_cover_only_the_frameworks_that_ran():
    baseline = {
        "flask-sqli-direct": ("TP", True),
        "flask-sqli-cross_file": ("FN", False),
        "flask-sqli-safe": ("TN", False),  # a safe case never counts toward recall
        "django-sqli-direct": ("TP", True),
        "gin-sqli-direct": ("TP", True),
        "nethttp-sqli-direct": ("FN", False),
    }
    assert _parity.baseline_recall_counts(baseline, ["flask", "gin"]) == {
        "python": {("sqli", "direct"): (1, 1), ("sqli", "cross_file"): (0, 1), ("sqli", "safe"): (0, 0)},
        "go": {("sqli", "direct"): (1, 1)},
    }


def test_baseline_recall_counts_read_class_and_variant_from_the_manifest_not_the_id(tmp_path):
    root = tmp_path / "dev"
    (root / "flask").mkdir(parents=True)
    (root / "flask" / "manifest.json").write_text(
        json.dumps({"cases": [{"id": "flask-odd", "class": "path_traversal", "variant": "alt_api", "vulnerable": True, "file": "x.py"}]})
    )
    counts = _parity.baseline_recall_counts({"flask-odd": ("TP", True)}, ["flask"], root=root)
    assert counts == {"python": {("path_traversal", "alt_api"): (1, 1)}}


def test_baseline_recall_counts_reject_a_case_the_dev_manifest_does_not_list():
    with pytest.raises(ValueError, match="flask-not-a-case"):
        _parity.baseline_recall_counts({"flask-not-a-case": ("TP", True)}, ["flask"])


def test_tally_recall_lists_a_family_that_has_only_safe_cases():
    counts = _parity.tally_recall(
        [
            ("python", "sqli", "safe", "TN"),
            ("go", "sqli", "direct", "TP"),
            ("go", "sqli", "direct", "FN"),
            ("go", "sqli", "safe", "FP"),
        ]
    )
    assert counts == {
        "python": {("sqli", "safe"): (0, 0)},
        "go": {("sqli", "direct"): (1, 2), ("sqli", "safe"): (0, 0)},
    }


@pytest.mark.parametrize(
    "extra, complaint",
    [
        (["--max-recall-drop", "0.1"], "--compare-recall-to"),
        # The dev baseline was recorded with --isolate, so the comparison needs it too.
        (["--compare-recall-to", "b.json"], "--isolate"),
        (["--isolate", "--compare-recall-to", "b.json", "--gate", "b.json"], "not allowed with"),
        (["--isolate", "--compare-recall-to", "b.json", "--write-baseline", "b.json"], "not allowed with"),
        # --gate prints one line per regressed case, which --quiet exists to prevent.
        (["--isolate", "--gate", "b.json", "--quiet"], "--quiet"),
        (["--isolate", "--compare-recall-to", "b.json", "--max-recall-drop", "1.5"], "between 0 and 1"),
        # A baseline written from the holdout would replace the development one.
        (["--isolate", "--write-baseline", "b.json", "--corpus-root", "somewhere-else"], "--corpus-root"),
    ],
)
def test_main_rejects_incompatible_recall_comparison_flags(tmp_path, monkeypatch, capsys, extra, complaint):
    monkeypatch.setattr(sys, "argv", ["run_parity.py", "--fendix", "unused", "--out", str(tmp_path), *extra])
    with pytest.raises(SystemExit) as raised:
        _parity.main()
    assert raised.value.code == 2
    assert complaint in capsys.readouterr().err


def test_holdout_run_reports_recall_per_family_and_exits_one_on_a_drop(tmp_path, monkeypatch, capsys):
    """End to end with a fake engine: a small corpus under --corpus-root, scored and compared.

    The holdout has 4 vulnerable `direct` cases, 3 detected (recall 0.75). The
    dev baseline detected flask's sqli and cmdi `direct` cases, so over those
    two pairs dev recall is 1.0: a 25 point drop, and the run exits 1. Every
    other dev case is a miss, which would drag an unmatched dev recall to about
    0.05 and let this pass.
    """
    root = tmp_path / "holdout"
    _write_flask_corpus(
        root,
        [
            ("flask-h-a", "sqli", True),
            ("flask-h-b", "sqli", True),
            ("flask-h-c", "sqli", True),
            ("flask-h-d", "cmdi", True),  # the fake engine only reports SQL injection: a miss
            ("flask-h-e", "sqli", False),
        ],
    )
    argv = [
        "run_parity.py", "--fendix", str(_fake_engine(tmp_path)), "--out", str(tmp_path / "out"),
        "--frameworks", "flask", "--isolate", "--no-timing", "--corpus-root", str(root),
        "--compare-recall-to",
        str(_dev_baseline(tmp_path, {"flask-sqli-direct": "TP", "flask-cmdi-direct": "TP"})),
        "--max-recall-drop", "0.10",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert _parity.main() == 1
    out = capsys.readouterr().out
    assert "python dev=1.000 holdout=0.750 drop=0.250 pairs=2" in out
    assert "RECALL: python:" in out

    # The same holdout against a dev baseline it is within 10 points of: dev 0.5 over the same two pairs.
    argv[argv.index("--compare-recall-to") + 1] = str(_dev_baseline(tmp_path, {"flask-sqli-direct": "TP"}))
    monkeypatch.setattr(sys, "argv", argv)
    assert _parity.main() == 0
    assert "python dev=0.500 holdout=0.750 drop=-0.250 pairs=2" in capsys.readouterr().out


def test_quiet_holdout_run_prints_only_family_level_lines(tmp_path, monkeypatch, capsys):
    """--quiet keeps case ids, outcomes and per-framework numbers out of a public log."""
    root = tmp_path / "holdout"
    _write_flask_corpus(
        root,
        [("flask-secret-case-id", "sqli", True), ("flask-other-case-id", "cmdi", True), ("flask-safe-case-id", "sqli", False)],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_parity.py", "--fendix", str(_fake_engine(tmp_path)), "--out", str(tmp_path / "out"),
            "--frameworks", "flask", "--isolate", "--no-timing", "--quiet", "--corpus-root", str(root),
            "--compare-recall-to", str(_dev_baseline(tmp_path, {"flask-sqli-direct": "TP"})),
        ],
    )
    assert _parity.main() == 0  # dev 0.5, holdout 0.5
    captured = capsys.readouterr()
    assert captured.err == ""
    assert "case-id" not in captured.out
    assert not re.search(r"\b(TP|FN|FP|TN)\b", captured.out)
    lines = captured.out.splitlines()
    assert lines[0] == "python dev=0.500 holdout=0.500 drop=0.000 pairs=2"
    assert len(lines) == 2  # the one family line and the verdict


def test_quiet_holdout_run_withholds_failure_details(tmp_path, monkeypatch, capsys):
    """An unexpected error in --quiet mode names its type only: messages and tracebacks can name holdout cases."""
    root = tmp_path / "holdout"
    _write_flask_corpus(root, [("flask-secret-case-id", "sqli", True)])
    broken = tmp_path / "broken-engine"
    broken.write_text(f"#!{sys.executable}\nimport sys\nif sys.argv[1] == 'version':\n    print('v')\n"
                      "else:\n    sys.stderr.write('flask-secret-case-id exploded')\n    sys.exit(3)\n")
    broken.chmod(0o755)
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_parity.py", "--fendix", str(broken), "--out", str(tmp_path / "out"), "--frameworks", "flask",
         "--isolate", "--quiet", "--corpus-root", str(root), "--compare-recall-to", str(_dev_baseline(tmp_path, {}))],
    )
    assert _parity.main() == 2
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "secret-case-id" not in captured.out + captured.err
