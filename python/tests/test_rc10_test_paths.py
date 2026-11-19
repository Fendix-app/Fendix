"""RC-10 (a) (Round 6 closure): one test-path convention set, in Go and in Python.

`models.IsTestPath` (go/internal/models/testpath.go) decides which findings are
test code, and its twin `_is_test_path` (python/analyzers/ast_analyzer.py)
decides the same for the Python analyzer's own findings and for which files the
call index reads as callers. Both knew only the Python conventions, so since D6'
(Semgrep evaluates test paths) JavaScript, TypeScript, Go, Java and Ruby test
code reached the decision at full severity: 44 Tier B BLOCK groups, 41 of them
in test code only, became WARN once the set is extended (decision package
RC-10 (a); `r6-decision/rc10/make_overlay.py`, `exttest`).

The two sides are kept in lockstep three ways:

* one vector file, `fixtures/test_path_vectors.json`, read by this test and by
  `TestIsTestPathSharedVectors` in Go;
* the regex source in `testpath.go` must equal `_TEST_PATH_RE.pattern`, read
  from the Go file here (a drift on either side fails this file);
* the Go table in `testpath_test.go` keeps the URL guard (a live route is never
  test code), which only the Go side applies.

The fixture text below is scanned as text and never executed.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import _TEST_PATH_RE, ASTAnalyzer, _is_test_path
from analyzers.call_index import ProjectCallIndex

REPOSITORY = Path(__file__).resolve().parents[2]
VECTORS = json.loads((Path(__file__).parent / "fixtures" / "test_path_vectors.json").read_text(encoding="utf-8"))["vectors"]


def test_the_vector_file_is_not_empty_and_has_both_polarities() -> None:
    assert len(VECTORS) >= 80
    assert {v["want"] for v in VECTORS} == {True, False}


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_is_test_path_matches_the_shared_vector(vector: dict) -> None:
    assert _is_test_path(vector["path"]) is vector["want"], vector["path"]


def test_the_go_marker_regex_is_the_python_marker_regex() -> None:
    source = (REPOSITORY / "go" / "internal" / "models" / "testpath.go").read_text(encoding="utf-8")
    block = re.search(r"var testPathRe = regexp\.MustCompile\((.*?)\n\)", source, re.S)
    assert block is not None, "testPathRe declaration not found in testpath.go"
    go_pattern = "".join(re.findall(r"`([^`]*)`", block.group(1)))
    assert go_pattern == _TEST_PATH_RE.pattern


# ---------------------------------------------------------------------------
# What changes for the Python analyzer
# ---------------------------------------------------------------------------

_QUERY = 'def find(name):\n    return "SELECT * FROM t WHERE n = \'%s\'" % name\n'
_CALLER = (
    "from flask import request\n"
    "from app.services.q import find\n"
    "def view():\n"
    "    return find(request.args['n'])\n"
)
_NEW_DIRECTORIES = ["mocks", "mock", "specs", "spec", "e2e", "cypress", "testdata", "testutils", "test-utils", "__mocks__", "__tests__", "__fixtures__"]


def _index(tmp_path: Path, files: dict[str, str]) -> ProjectCallIndex:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    routes = ASTAnalyzer(str(tmp_path))._build_route_index(tmp_path)
    return ProjectCallIndex.build(tmp_path, routes)


@pytest.mark.parametrize("directory", _NEW_DIRECTORIES)
def test_python_in_a_new_test_directory_is_never_a_caller(tmp_path: Path, directory: str) -> None:
    index = _index(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/services/__init__.py": "",
            "app/services/q.py": _QUERY,
            f"{directory}/caller.py": _CALLER,
        },
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


def test_the_same_caller_outside_a_test_directory_is_still_a_caller(tmp_path: Path) -> None:
    index = _index(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/services/__init__.py": "",
            "app/services/q.py": _QUERY,
            "app/views.py": _CALLER,
        },
    )
    assert [link.line for link in index.tainted_args("app.services.q", "find", 0, "name")] == [4]


def _pickle_finding(rel: str) -> dict:
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        path = Path(d, rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n")
        ASTAnalyzer(d, "python").run(findings.append)
    [finding] = [f for f in findings if f["rule_id"] == "python.ast/PY_PICKLE_LOAD"]
    return finding


@pytest.mark.parametrize("directory", _NEW_DIRECTORIES)
def test_a_python_finding_in_a_new_test_directory_is_marked_test_code(directory: str) -> None:
    finding = _pickle_finding(f"{directory}/loader.py")
    assert finding.get("in_test") is True
    assert finding["confidence"] == "LOW"


def test_a_python_finding_outside_a_test_directory_keeps_its_confidence() -> None:
    finding = _pickle_finding("app/loader.py")
    assert not finding.get("in_test")
    assert finding["confidence"] == "HIGH"
