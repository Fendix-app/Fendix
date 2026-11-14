"""Round 5 verification, cluster 1 (DE6-01, security5-01, redteam5-01, qa5-03).

Owner amendment A1: a hash pinned in a file the repository controls is not
independent provenance. A go.sum written by the same change that adds a
directory named like a module cache entry must not take that directory out of
the Python engine's walk. The scan is offline and cannot check go.sum against
the checksum database, so nothing is excluded.

The hash here is computed by the test itself (the dirhash Hash1 algorithm), not
by engine code, so the test holds whatever the engine does or does not contain.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.scope_evidence import SourceWalk

MOD, VER = "example.com/lib", "v1.0.0"
REL = f"third_party/{MOD}@{VER}"
EVAL_PY = "import os\n\n\ndef run(request):\n    return eval(request.args['x'])\n"


def hash1(directory: Path, prefix: str) -> str:
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        name = f"{prefix}/{path.relative_to(directory).as_posix()}"
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n")
    digest = hashlib.sha256("".join(sorted(lines)).encode()).digest()
    return "h1:" + base64.b64encode(digest).decode()


def forged_tree(tmp_path: Path) -> Path:
    target = tmp_path / REL / "web"
    target.mkdir(parents=True)
    (target / "app.py").write_text(EVAL_PY, encoding="utf-8")
    (tmp_path / "go.sum").write_text(f"{MOD} {VER} {hash1(tmp_path / REL, f'{MOD}@{VER}')}\n", encoding="utf-8")
    return tmp_path


def test_a_self_pinned_directory_stays_in_the_walk(tmp_path):
    root = forged_tree(tmp_path)
    walk = SourceWalk(root)
    dirs = [os.path.relpath(d, root) for d, _ in walk.walk(record=True)]
    assert os.path.join(REL, "web") in dirs
    assert walk.declared == []


def test_the_analyzer_reports_code_under_a_self_pinned_directory(tmp_path):
    root = forged_tree(tmp_path)
    findings: list = []
    analyzer = ASTAnalyzer(str(root))
    analyzer.run(findings.append)
    assert any("third_party" in str(f) for f in findings), "the forged directory must be analysed"
    assert analyzer.excluded == [] or not any("go module" in why for _, why in analyzer.excluded)
