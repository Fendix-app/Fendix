"""Unit tests for the real-world noise harness (benchmarks/realworld-noise/run.py).

Only the pure parts and the subprocess plumbing are covered, against fake
`fendix` scripts and local directories: no test touches the network or a real
engine. The committed targets.json is checked for shape and pinning, because a
mutable pin would make the recorded baseline unreproducible.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
import textwrap
from pathlib import Path

import pytest

_NOISE_ROOT = Path(__file__).resolve().parents[2] / "benchmarks" / "realworld-noise"


def _load_run():
    """Import the harness by file path.

    benchmarks/realworld-noise is a data directory, not a package, and its name
    is not a valid module name; loading the one file under a private name keeps
    it off sys.path (see the same pattern for run_parity in test_benchmark_gate).
    """
    spec = importlib.util.spec_from_file_location("fendix_realworld_noise", _NOISE_ROOT / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


noise = _load_run()


def _write(path: Path, text: str = "", lines: int | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if lines is not None:
        text = "x = 1\n" * lines
    path.write_text(text, encoding="utf-8")
    return path


# ── kLOC counting ────────────────────────────────────────────────────────────


def test_kloc_counts_lines_of_source_extensions_only(tmp_path):
    for i, ext in enumerate(noise.SOURCE_EXTENSIONS):
        _write(tmp_path / f"f{i}{ext}", lines=10)
    # Not source: documentation, data, markup, and a dotfile with no extension.
    _write(tmp_path / "README.md", lines=500)
    _write(tmp_path / "data.json", lines=500)
    _write(tmp_path / "index.html", lines=500)
    _write(tmp_path / "style.css", lines=500)
    _write(tmp_path / "Makefile", lines=500)

    assert noise.count_kloc(tmp_path) == pytest.approx(10 * len(noise.SOURCE_EXTENSIONS) / 1000)


def test_source_extensions_are_the_ones_the_brief_names():
    assert set(noise.SOURCE_EXTENSIONS) == {
        ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go",
    }


@pytest.mark.parametrize("skipped", ["node_modules", "vendor", "dist", "build", ".git", "target", ".next"])
def test_kloc_skips_vendored_and_build_directories_at_any_depth(tmp_path, skipped):
    _write(tmp_path / "src" / "app.py", lines=100)
    _write(tmp_path / skipped / "lib.py", lines=900)
    _write(tmp_path / "src" / "deep" / skipped / "nested" / "lib.js", lines=900)

    assert noise.count_kloc(tmp_path) == pytest.approx(0.1)


def test_kloc_skip_matches_whole_directory_names_only(tmp_path):
    # "builder" and "my_vendor" merely contain a skipped name; they are real source.
    _write(tmp_path / "builder" / "a.go", lines=50)
    _write(tmp_path / "my_vendor" / "b.go", lines=50)

    assert noise.count_kloc(tmp_path) == pytest.approx(0.1)


def test_kloc_counts_an_unterminated_last_line_and_ignores_empty_files(tmp_path):
    _write(tmp_path / "a.py", "one\ntwo\nthree")  # no trailing newline: 3 lines
    _write(tmp_path / "b.py", "one\ntwo\n")  # 2 lines
    _write(tmp_path / "empty.py", "")  # 0 lines

    assert noise.count_kloc(tmp_path) == pytest.approx(0.005)


def test_kloc_survives_non_utf8_bytes(tmp_path):
    (tmp_path / "bin.java").write_bytes(b"\xff\xfe\x00\nfoo\n\x80\n")

    assert noise.count_kloc(tmp_path) == pytest.approx(0.003)


def test_kloc_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    _write(outside / "big.py", lines=1000)
    inside = tmp_path / "inside"
    _write(inside / "real.py", lines=10)
    try:
        os.symlink(outside, inside / "link_dir")
        os.symlink(outside / "big.py", inside / "link_file.py")
    except OSError:
        pytest.skip("symlinks unavailable")

    assert noise.count_kloc(inside) == pytest.approx(0.01)


def test_kloc_of_an_empty_tree_is_zero(tmp_path):
    assert noise.count_kloc(tmp_path) == 0.0


# ── findings aggregation ─────────────────────────────────────────────────────


def test_count_by_rule_aggregates_and_orders_by_count_then_name():
    findings = [
        {"rule_id": "b-rule"},
        {"rule_id": "a-rule"},
        {"rule_id": "b-rule"},
        {"rule_id": "c-rule"},
        {"rule_id": "a-rule"},
        {"rule_id": "b-rule"},
    ]

    by_rule = noise.count_by_rule(findings)

    assert by_rule == {"b-rule": 3, "a-rule": 2, "c-rule": 1}
    assert list(by_rule) == ["b-rule", "a-rule", "c-rule"]


def test_count_by_rule_ties_break_alphabetically_and_total_is_preserved():
    findings = [{"rule_id": "z"}, {"rule_id": "m"}, {"rule_id": "a"}]

    by_rule = noise.count_by_rule(findings)

    assert list(by_rule) == ["a", "m", "z"]
    assert sum(by_rule.values()) == len(findings)


@pytest.mark.parametrize("finding", [{}, {"rule_id": ""}, {"rule_id": None}, {"title": "no rule"}])
def test_count_by_rule_buckets_findings_without_a_rule_id(finding):
    assert noise.count_by_rule([finding, {"rule_id": "r"}]) == {"r": 1, "(no rule_id)": 1}


def test_count_by_rule_of_nothing_is_empty():
    assert noise.count_by_rule([]) == {}


def test_summarize_computes_findings_per_kloc_from_the_unrounded_values():
    findings = [{"rule_id": "r"}] * 7

    row = noise.summarize(kloc=2.0, findings=findings)

    assert row == {"kloc": 2.0, "findings": 7, "per_kloc": 3.5, "by_rule": {"r": 7}}
    assert list(row) == ["kloc", "findings", "per_kloc", "by_rule"]


def test_summarize_rounds_to_three_decimals():
    row = noise.summarize(kloc=0.123456, findings=[{"rule_id": "r"}] * 5)

    assert row["kloc"] == 0.123
    assert row["per_kloc"] == round(5 / 0.123456, 3)


def test_summarize_a_target_with_no_source_has_zero_density_not_a_crash():
    row = noise.summarize(kloc=0.0, findings=[{"rule_id": "r"}])

    assert row["findings"] == 1
    assert row["per_kloc"] == 0.0


# ── scan output parsing ──────────────────────────────────────────────────────


def test_parse_findings_reads_the_findings_array():
    doc = {"metadata": {}, "findings": [{"rule_id": "a"}, {"rule_id": "b"}]}

    assert noise.parse_findings(json.dumps(doc)) == [{"rule_id": "a"}, {"rule_id": "b"}]


def test_parse_findings_treats_null_or_absent_findings_as_none_found():
    assert noise.parse_findings(json.dumps({"findings": None})) == []
    assert noise.parse_findings(json.dumps({"metadata": {}})) == []


@pytest.mark.parametrize("text", ["", "not json", "[1, 2]", '{"findings": {"a": 1}}', '{"findings": [1]}'])
def test_parse_findings_rejects_output_that_is_not_a_scan_report(text):
    with pytest.raises(noise.TargetError):
        noise.parse_findings(text)


# ── running the scanner (fake binary, no engine) ─────────────────────────────


def _fake_fendix(tmp_path: Path, *, exit_code: int, stdout: str = "", stderr: str = "") -> Path:
    script = tmp_path / "fake-fendix"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import sys
            sys.stdout.write({stdout!r})
            sys.stderr.write({stderr!r})
            sys.exit({exit_code})
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_scan_passes_the_documented_arguments(tmp_path):
    argv_file = tmp_path / "argv.json"
    script = tmp_path / "recording-fendix"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json, sys
            json.dump(sys.argv[1:], open({str(argv_file)!r}, "w"))
            print(json.dumps({{"findings": []}}))
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    code = tmp_path / "code"
    code.mkdir()

    noise.scan(str(script), code, cwd=tmp_path, timeout=60)

    assert json.loads(argv_file.read_text()) == ["scan", "--code", str(code), "--format", "json", "--offline"]


@pytest.mark.parametrize("exit_code", [0, 1])
def test_scan_accepts_exit_codes_zero_and_one_as_normal(tmp_path, exit_code):
    out = json.dumps({"findings": [{"rule_id": "r1"}, {"rule_id": "r1"}]})
    fake = _fake_fendix(tmp_path, exit_code=exit_code, stdout=out)

    assert noise.scan(str(fake), tmp_path, cwd=tmp_path, timeout=60) == [{"rule_id": "r1"}, {"rule_id": "r1"}]


@pytest.mark.parametrize("exit_code", [2, 3, 70, 127])
def test_scan_reports_any_other_exit_code_as_a_target_error(tmp_path, exit_code):
    fake = _fake_fendix(
        tmp_path, exit_code=exit_code, stdout=json.dumps({"findings": []}), stderr="boom: engine unavailable"
    )

    with pytest.raises(noise.TargetError) as err:
        noise.scan(str(fake), tmp_path, cwd=tmp_path, timeout=60)

    message = str(err.value)
    assert f"exited {exit_code}" in message
    assert "boom: engine unavailable" in message


def test_scan_reports_unparseable_output_as_a_target_error(tmp_path):
    fake = _fake_fendix(tmp_path, exit_code=0, stdout="this is not json")

    with pytest.raises(noise.TargetError):
        noise.scan(str(fake), tmp_path, cwd=tmp_path, timeout=60)


def test_scan_reports_a_missing_binary_as_a_target_error(tmp_path):
    with pytest.raises(noise.TargetError):
        noise.scan(str(tmp_path / "does-not-exist"), tmp_path, cwd=tmp_path, timeout=60)


def test_scan_reports_a_timeout_as_a_target_error(tmp_path):
    script = tmp_path / "slow-fendix"
    script.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    with pytest.raises(noise.TargetError, match="timed out"):
        noise.scan(str(script), tmp_path, cwd=tmp_path, timeout=1)


# ── fetching at a pinned commit (local git repository, no network) ──────────

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def _git(cwd: Path, *args: str) -> str:
    import subprocess

    done = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env={**os.environ, **_GIT_ENV}
    )
    return done.stdout.strip()


@pytest.fixture
def remote(tmp_path, monkeypatch):
    """A local stand-in for github.com/<owner>/<name>.git with two commits and an annotated tag."""
    origin = tmp_path / "remotes" / "owner" / "name.git"
    origin.mkdir(parents=True)
    _git(origin, "init", "-q")
    (origin / "main.go").write_text("package main\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-q", "-m", "first")
    first = _git(origin, "rev-parse", "HEAD")
    (origin / "main.go").write_text("package main\n\nfunc main() {}\n")
    _git(origin, "commit", "-q", "-am", "second")
    second = _git(origin, "rev-parse", "HEAD")
    _git(origin, "tag", "-a", "-m", "release", "v1")
    tag_object = _git(origin, "rev-parse", "v1")
    monkeypatch.setattr(noise, "REMOTE_BASE", f"file://{tmp_path / 'remotes'}/")
    return {"first": first, "second": second, "tag_object": tag_object}


def test_fetch_checks_out_exactly_the_pinned_commit(tmp_path, remote):
    dest = tmp_path / "clone"

    noise.fetch(_target(repo="owner/name", sha=remote["second"]), dest)

    assert (dest / "main.go").read_text() == "package main\n\nfunc main() {}\n"
    assert _git(dest, "rev-parse", "HEAD") == remote["second"]


def test_fetch_is_shallow(tmp_path, remote):
    dest = tmp_path / "clone"

    noise.fetch(_target(repo="owner/name", sha=remote["second"]), dest)

    assert _git(dest, "rev-list", "--count", "HEAD") == "1"


def test_fetch_of_a_commit_that_does_not_exist_is_a_target_error(tmp_path, remote):
    with pytest.raises(noise.TargetError, match="git fetch"):
        noise.fetch(_target(repo="owner/name", sha="0" * 40), tmp_path / "clone")


def test_fetch_of_a_missing_repository_is_a_target_error(tmp_path, remote):
    with pytest.raises(noise.TargetError, match="git fetch"):
        noise.fetch(_target(repo="owner/absent", sha=remote["first"]), tmp_path / "clone")


def test_fetch_refuses_a_tag_object_in_place_of_a_commit_sha(tmp_path, remote):
    # A tag can be moved; only the commit it points at is a pin.
    with pytest.raises(noise.TargetError, match="expected the pinned"):
        noise.fetch(_target(repo="owner/name", sha=remote["tag_object"]), tmp_path / "clone")


# ── targets.json ─────────────────────────────────────────────────────────────

_SHA = re.compile(r"[0-9a-f]{40}")
_REQUIRED_VULNERABLE = {"juice-shop", "nodegoat", "webgoat", "govwa", "pygoat"}


def _targets():
    return noise.load_targets(_NOISE_ROOT / "targets.json")


def test_committed_targets_are_pinned_to_full_commit_shas():
    for t in _targets():
        assert _SHA.fullmatch(t["sha"]), f"{t['name']}: {t['sha']!r} is not a 40-character lowercase SHA"


def test_committed_targets_have_unique_names_and_repos():
    targets = _targets()
    assert len({t["name"] for t in targets}) == len(targets)
    assert len({t["repo"] for t in targets}) == len(targets)


def test_committed_targets_cover_the_five_vulnerable_apps_and_a_clean_app_per_language():
    targets = _targets()
    names = {t["name"] for t in targets}
    assert _REQUIRED_VULNERABLE <= names

    clean = [t for t in targets if t["name"] not in _REQUIRED_VULNERABLE]
    families = {"js": "js-ts", "ts": "js-ts", "python": "python", "java": "java", "go": "go"}
    assert {families[t["language"]] for t in clean} == {"js-ts", "python", "java", "go"}


def test_the_vulnerable_apps_use_the_brief_repositories():
    repos = {t["name"]: t["repo"] for t in _targets()}
    assert repos["juice-shop"] == "juice-shop/juice-shop"
    assert repos["nodegoat"] == "OWASP/NodeGoat"
    assert repos["webgoat"] == "WebGoat/WebGoat"
    assert repos["govwa"] == "0c34/govwa"
    assert repos["pygoat"] == "adeyosemanputra/pygoat"


def _target(**overrides):
    base = {"name": "t", "repo": "o/r", "sha": "a" * 40, "language": "go", "code_dir": "."}
    base.update(overrides)
    return base


def _write_targets(tmp_path: Path, targets) -> Path:
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(targets))
    return path


@pytest.mark.parametrize(
    "bad",
    [
        {"sha": "main"},  # a branch is not a pin
        {"sha": "a" * 7},  # abbreviated
        {"sha": "A" * 40},  # git prints lowercase; mixed case invites mismatches
        {"sha": "g" * 40},
        {"code_dir": "../elsewhere"},
        {"code_dir": "/etc"},
        {"code_dir": "a/../../b"},
        {"repo": "just-a-name"},
        {"repo": "https://example.com/o/r"},
        {"repo": "o/r; rm -rf /"},
        {"name": ""},
        {"name": "has/slash"},
    ],
)
def test_load_targets_rejects_unpinned_or_unsafe_entries(tmp_path, bad):
    with pytest.raises(ValueError):
        noise.load_targets(_write_targets(tmp_path, [_target(**bad)]))


def test_load_targets_rejects_missing_keys_and_duplicates(tmp_path):
    incomplete = _target()
    del incomplete["language"]
    with pytest.raises(ValueError):
        noise.load_targets(_write_targets(tmp_path, [incomplete]))
    with pytest.raises(ValueError):
        noise.load_targets(_write_targets(tmp_path, [_target(), _target(repo="o/other")]))
    with pytest.raises(ValueError):
        noise.load_targets(_write_targets(tmp_path, {"not": "a list"}))


def test_load_targets_accepts_a_valid_entry(tmp_path):
    assert noise.load_targets(_write_targets(tmp_path, [_target(code_dir="backend")])) == [
        _target(code_dir="backend")
    ]


# ── main(): per-target errors do not abort the run ───────────────────────────


def _main_env(tmp_path: Path, monkeypatch, targets, fake_exit_codes):
    """Wire main() to local fixture trees and a fake scanner keyed by tree."""
    targets_path = _write_targets(tmp_path, targets)
    trees = {}
    for t in targets:
        tree = tmp_path / "trees" / t["name"]
        _write(tree / t["code_dir"] / "a.py", lines=200)
        _write(tree / t["code_dir"] / "node_modules" / "skipped.js", lines=5000)
        trees[t["name"]] = tree

    def fake_fetch(target, dest):
        import shutil

        shutil.copytree(trees[target["name"]], dest)

    monkeypatch.setattr(noise, "fetch", fake_fetch)

    def fake_scan(fendix, code_dir, *, cwd, timeout):
        name = Path(code_dir).relative_to(cwd).parts[0]  # clones live at <work dir>/<target name>
        code = fake_exit_codes[name]
        if code not in (0, 1):
            raise noise.TargetError(f"fendix exited {code}")
        return [{"rule_id": "r1"}, {"rule_id": "r1"}, {"rule_id": "r2"}]

    monkeypatch.setattr(noise, "scan", fake_scan)
    return targets_path


def test_main_writes_noise_json_in_the_documented_shape(tmp_path, monkeypatch):
    targets = [_target(name="alpha"), _target(name="beta", repo="o/beta", code_dir="src")]
    targets_path = _main_env(tmp_path, monkeypatch, targets, {"alpha": 0, "beta": 1})
    out = tmp_path / "out"

    rc = noise.main(["--fendix", "unused", "--out", str(out), "--targets", str(targets_path)])

    assert rc == 0
    result = json.loads((out / "noise.json").read_text())
    assert list(result) == ["alpha", "beta"]
    assert result["alpha"] == {"kloc": 0.2, "findings": 3, "per_kloc": 15.0, "by_rule": {"r1": 2, "r2": 1}}
    assert result["beta"]["kloc"] == 0.2  # node_modules is skipped, code_dir is honoured


def test_main_reports_a_failing_target_and_still_records_the_others(tmp_path, monkeypatch, capsys):
    targets = [_target(name="alpha"), _target(name="beta", repo="o/beta")]
    targets_path = _main_env(tmp_path, monkeypatch, targets, {"alpha": 2, "beta": 0})
    out = tmp_path / "out"

    rc = noise.main(["--fendix", "unused", "--out", str(out), "--targets", str(targets_path)])

    assert rc == 1
    assert list(json.loads((out / "noise.json").read_text())) == ["beta"]
    assert "alpha" in capsys.readouterr().err


def test_main_only_runs_the_named_targets(tmp_path, monkeypatch):
    targets = [_target(name="alpha"), _target(name="beta", repo="o/beta")]
    targets_path = _main_env(tmp_path, monkeypatch, targets, {"alpha": 0, "beta": 0})
    out = tmp_path / "out"

    rc = noise.main(["--fendix", "unused", "--out", str(out), "--targets", str(targets_path), "--only", "beta"])

    assert rc == 0
    assert list(json.loads((out / "noise.json").read_text())) == ["beta"]


def test_main_rejects_an_unknown_only_name(tmp_path, monkeypatch):
    targets_path = _main_env(tmp_path, monkeypatch, [_target(name="alpha")], {"alpha": 0})

    with pytest.raises(SystemExit):
        noise.main(["--fendix", "unused", "--out", str(tmp_path / "out"), "--targets", str(targets_path), "--only", "nope"])
