"""Remediation round 3 regressions (Python taint engine).

D6: an in-scope source file the analyzer never analysed is lost evaluation.
A ``.py`` file over the 1 MB cap (``_MAX_FILE_BYTES``, also the call index's
cap), a file or directory that cannot be read, and a JavaScript file over the
cap make ``ASTAnalyzer.run`` raise ``AnalysisIncomplete`` after the walk,
naming the files (round 5, D5-2: whatever the file claims to be, minified,
vendored or generated); ``engine.py`` reports the injection check
``failed/execution_error``. What the analyzer leaves out on purpose (symlinks,
and a real ``<root>/.git``) is listed by name in the injection status detail
instead (``ASTAnalyzer.scope_note``).

redteam2-py-01: a file saved with a UTF-8 BOM (or a PEP 263 declaration) is
decoded the way CPython decodes it, so it is analysed instead of failing to
parse and being dropped.

qa2-05: the call index's failures and a route-index-only abort are recorded.

redteam2-py-02: a ``'..' in name`` guard is containment for a direct
``open(name)`` only together with a guard that rejects an absolute path.

redteam2-r006-01: ``os.open`` opens a directory, so it is not a file sink.

redteam2-r006-02: an import shadowed by a class, a parameter (default) or any
other store in an enclosing scope resolves to nothing.

redteam2-r001-01: an allowlist is not constant once a bound mutator escapes
(``f = ALLOWED.add``) or another project file reaches the collection.

redteam2-r058-01: ``html.escape(x, quote=False)`` (and ``cgi.escape``'s
default) is no HTML escape: it leaves quotes alone.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

SHELL = "SEC-PY_SUBPROCESS_SHELL"
PATH = "SEC-PY_PATH_TRAVERSAL"
SSRF = "SEC-PY_SSRF"
XSS = "SEC-PY_XSS_HTML_SINK"
SQLI = "SEC-PY_SQL_INJECTION"

_SHELL_ROUTE = (
    "import subprocess\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/run')\n"
    "def run():\n"
    "    subprocess.run('ls ' + request.args.get('x', ''), shell=True)\n"
    "    return 'ok'\n"
)
_PAD_LINE = "PAD_%07d = %d\n"


def _oversized(tail: str) -> str:
    """Valid Python over the 1 MB cap whose last lines are `tail`."""
    lines = []
    size = 0
    i = 0
    while size <= 1_048_576:
        line = _PAD_LINE % (i, i)
        lines.append(line)
        size += len(line)
        i += 1
    return "".join(lines) + tail


def _write(d: str, files: dict[str, str | bytes]) -> None:
    for rel, src in files.items():
        p = Path(d) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(src, bytes):
            p.write_bytes(src)
        else:
            p.write_text(src)


def _run(d: str) -> tuple[list[dict], AnalysisIncomplete | None, ASTAnalyzer]:
    findings: list[dict] = []
    analyzer = ASTAnalyzer(d, "python")
    try:
        analyzer.run(findings.append)
    except AnalysisIncomplete as exc:
        return findings, exc, analyzer
    return findings, None, analyzer


def _scan(files: dict[str, str | bytes]) -> tuple[list[dict], AnalysisIncomplete | None]:
    with tempfile.TemporaryDirectory() as d:
        _write(d, files)
        findings, raised, _analyzer = _run(d)
    return findings, raised


def _of(findings: list[dict], rule: str, rel: str = "app.py") -> list[dict]:
    return [f for f in findings if f["id"] == rule and f["line"].startswith(rel + ":")]


def _is_proven(f: dict) -> bool:
    return f.get("reachable") is True and bool(f.get("taint_chain"))


def _proven(findings: list[dict], rule: str, rel: str = "app.py") -> dict:
    found = [f for f in _of(findings, rule, rel) if _is_proven(f)]
    assert found, f"expected a proven {rule} in {rel}; got {_of(findings, rule, rel)}"
    return found[0]


def _not_proven(findings: list[dict], rule: str, rel: str = "app.py") -> None:
    proven = [f for f in _of(findings, rule, rel) if _is_proven(f)]
    assert not proven, proven


def _reasons(raised: AnalysisIncomplete | None) -> dict[str, list[str]]:
    assert isinstance(raised, AnalysisIncomplete), raised
    out: dict[str, list[str]] = {}
    for rel, reason in raised.files:
        out.setdefault(rel, []).append(reason)
    return out


_root_only = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads a mode-000 path"
)


def _engine(d: str) -> tuple[dict, list[dict]]:
    engine = Path(__file__).parent.parent / "engine.py"
    proc = subprocess.run(
        [sys.executable, str(engine)],
        input=json.dumps({"mode": "whitebox", "checks": ["injection"], "code_path": d}),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    objects = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
    statuses = {o["status"]["check"]: o["status"] for o in objects if isinstance(o.get("status"), dict)}
    return statuses["injection"], [o for o in objects if "id" in o]


# ---------------------------------------------------------------------------
# D6: oversized or unreadable in-scope source is a coverage gap
# ---------------------------------------------------------------------------


class TestD6OversizedSource:
    def test_oversized_py_file_is_lost_evaluation(self) -> None:
        findings, raised = _scan({"big.py": _oversized(_SHELL_ROUTE), "app.py": _SHELL_ROUTE})
        reasons = _reasons(raised)
        assert list(reasons) == ["big.py"]
        assert reasons["big.py"][0].startswith("skipped: over the 1 MB size cap")
        # The rest of the tree is analysed and its findings are kept.
        _proven(findings, SHELL)

    def test_file_at_the_cap_is_analysed(self) -> None:
        src = _SHELL_ROUTE
        src += "#" * (1_048_576 - len(src.encode()) - 1) + "\n"
        assert len(src.encode()) == 1_048_576
        findings, raised = _scan({"app.py": src})
        assert raised is None
        _proven(findings, SHELL)

    def test_oversized_caller_of_the_call_index_is_reported(self) -> None:
        # The call index skips the same file for size; the walk reports it,
        # so the helper's lost cross-file proof is not silent.
        helper = (
            "import sqlite3\n"
            "def find(name):\n"
            "    return sqlite3.connect('d').execute(f\"SELECT * FROM t WHERE n='{name}'\")\n"
        )
        caller = (
            "from flask import Flask, request\n"
            "from app.services.h import find\n"
            "app = Flask(__name__)\n"
            "@app.route('/x')\n"
            "def v():\n"
            "    return find(request.args['n'])\n"
        )
        files = {
            "app/__init__.py": "",
            "app/services/__init__.py": "",
            "app/services/h.py": helper,
            "app/views.py": _oversized(caller),
        }
        findings, raised = _scan(files)
        assert "app/views.py" in _reasons(raised)
        assert _of(findings, SQLI, "app/services/h.py")

    def test_oversized_js_file_is_lost_evaluation(self) -> None:
        js = "var a = 1;\n" * 100_000 + "eval(location.hash);\n"
        _findings, raised = _scan({"static/app.js": js, "app.py": _SHELL_ROUTE})
        assert list(_reasons(raised)) == ["static/app.js"]

    def test_oversized_minified_bundle_is_lost_evaluation(self) -> None:
        # Round 5 (D5-2): measured minification is not evidence either; an
        # over-cap file is a gap whatever it looks like.
        js = "var a=1;" * 140_000
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"static/vendor.min.js": js, "app.py": _SHELL_ROUTE})
            findings, raised, analyzer = _run(d)
        assert list(_reasons(raised)) == ["static/vendor.min.js"]
        assert analyzer.scope_note() == ""
        _proven(findings, SHELL)


class TestD6UnreadableSource:
    @_root_only
    def test_unreadable_py_file_is_lost_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"secret.py": _SHELL_ROUTE, "app.py": _SHELL_ROUTE})
            os.chmod(Path(d, "secret.py"), 0)
            try:
                findings, raised, _a = _run(d)
            finally:
                os.chmod(Path(d, "secret.py"), 0o644)
        reasons = _reasons(raised)
        assert "secret.py" in reasons
        # Both passes that read it say so: the route pass and the analysis.
        assert reasons["secret.py"] == [
            "route index: unreadable: PermissionError",
            "unreadable: PermissionError",
        ]
        _proven(findings, SHELL)

    @_root_only
    def test_unreadable_directory_is_lost_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"locked/views.py": _SHELL_ROUTE, "app.py": _SHELL_ROUTE})
            os.chmod(Path(d, "locked"), 0)
            try:
                findings, raised, _a = _run(d)
            finally:
                os.chmod(Path(d, "locked"), 0o755)
        reasons = _reasons(raised)
        assert reasons == {"locked/": ["directory unreadable: PermissionError"]}
        _proven(findings, SHELL)

    @_root_only
    def test_engine_reports_unreadable_file_as_failed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"secret.py": _SHELL_ROUTE, "app.py": _SHELL_ROUTE})
            os.chmod(Path(d, "secret.py"), 0)
            try:
                injection, findings = _engine(d)
            finally:
                os.chmod(Path(d, "secret.py"), 0o644)
        assert injection["state"] == "failed"
        assert injection["reason"] == "execution_error"
        # Round 4 (C1/C2): the detail is built by status_detail, never cut.
        assert injection["detail"].startswith("lost evaluation: 1 in-scope file not fully analysed: secret.py (")
        assert "unreadable: PermissionError" in injection["detail"]
        assert SHELL in {f["id"] for f in findings}


class TestD6EngineStatus:
    def test_engine_reports_oversized_file_as_failed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"big.py": _oversized(_SHELL_ROUTE), "app.py": _SHELL_ROUTE})
            injection, findings = _engine(d)
        assert injection["state"] == "failed"
        assert injection["reason"] == "execution_error"
        assert "big.py (skipped: over the 1 MB size cap" in injection["detail"]
        assert SHELL in {f["id"] for f in findings}

    def test_message_puts_the_count_first_and_names_the_first_files(self) -> None:
        files = [(f"m{i}.py", "skipped: over the 1 MB size cap (2 bytes)") for i in range(7)]
        files.append(("m0.py", "skipped: over the 1 MB size cap (2 bytes)"))
        text = str(AnalysisIncomplete(files))
        # Round 4 (C2): the count and kind first, as many names as the 240-byte
        # budget allows, then the pointer; the listing is never half-written.
        assert text.startswith("lost evaluation: 7 in-scope files not fully analysed: m0.py (")
        assert len(text.encode()) <= 240 and "…" not in text
        assert text.endswith("and 4 more (see report metadata)")
        assert "m2.py" in text and "m3.py" not in text
        # A reason repeated for one file is named once.
        assert text.count("m0.py") == 1


class TestD6ScopeIsListed:
    def test_named_and_marked_dirs_are_walked_and_a_real_root_git_is_skipped(self) -> None:
        # Round 5 (D5-2): neither a name nor a marker file (`pyvenv.cfg`) is
        # evidence; only a real `<root>/.git` is left out.
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                {
                    "node_modules/x/index.js": "eval(a)\n",
                    "venv/lib/m.py": _SHELL_ROUTE,
                    "pkg/build/gen.py": _SHELL_ROUTE,
                    "realenv/pyvenv.cfg": "home = /usr\n",
                    "realenv/lib/m.py": _SHELL_ROUTE,
                    ".git/HEAD": "ref: x\n",
                    ".git/objects/pack/.keep": "",
                    ".git/refs/heads/.keep": "",
                    ".git/hooks/h.py": _SHELL_ROUTE,
                    "app.py": _SHELL_ROUTE,
                },
            )
            findings, raised, analyzer = _run(d)
        assert raised is None
        assert analyzer.scope_note() == ""
        assert not _of(findings, SHELL, ".git/hooks/h.py")
        for walked in ("venv/lib/m.py", "pkg/build/gen.py", "realenv/lib/m.py"):
            assert _of(findings, SHELL, walked), walked
        _proven(findings, SHELL)

    def test_symlinked_source_file_is_listed(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.py"
        outside.write_text(_SHELL_ROUTE)
        root = tmp_path / "root"
        root.mkdir()
        (root / "app.py").write_text(_SHELL_ROUTE)
        (root / "link.py").symlink_to(outside)
        findings: list[dict] = []
        analyzer = ASTAnalyzer(str(root), "python")
        analyzer.run(findings.append)
        assert "link.py (symbolic link)" in analyzer.scope_note()
        assert not _of(findings, SHELL, "link.py")

    def test_symlinked_directory_is_listed(self, tmp_path: Path) -> None:
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / "views.py").write_text(_SHELL_ROUTE)
        root = tmp_path / "root"
        root.mkdir()
        (root / "app.py").write_text(_SHELL_ROUTE)
        (root / "lib").symlink_to(shared, target_is_directory=True)
        findings: list[dict] = []
        analyzer = ASTAnalyzer(str(root), "python")
        analyzer.run(findings.append)
        assert "lib/ (symbolic link)" in analyzer.scope_note()
        assert not _of(findings, SHELL, "lib/views.py")

    def test_clean_tree_has_no_note(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"app.py": _SHELL_ROUTE})
            _f, raised, analyzer = _run(d)
        assert raised is None and analyzer.scope_note() == ""

    def test_engine_ok_detail_lists_the_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"app.py": _SHELL_ROUTE})
            Path(d, "vendor").symlink_to("/tmp")
            injection, _findings = _engine(d)
        assert injection["state"] == "ok"
        assert "reason" not in injection
        assert injection["detail"] == "declared out of scope, not scanned: 1 path: vendor/ (symbolic link)"

    def test_engine_ok_without_exclusions_has_no_detail(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"app.py": _SHELL_ROUTE})
            injection, _findings = _engine(d)
        assert injection == {"check": "injection", "state": "ok"}

    def test_engine_mixed_tree_detail_keeps_the_js_note(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"web.js": "eval(a)\n", "app.py": _SHELL_ROUTE})
            Path(d, "node_modules").symlink_to("/tmp")
            injection, _findings = _engine(d)
        assert injection["state"] == "ok"
        assert injection["detail"].startswith("1 JavaScript/TypeScript file(s) got pattern checks only")
        assert injection["detail"].endswith(
            "; declared out of scope, not scanned: 1 path: node_modules/ (symbolic link)"
        )


# ---------------------------------------------------------------------------
# redteam2-py-01: BOM and declared encodings are decoded as CPython does
# ---------------------------------------------------------------------------


class TestSourceDecoding:
    def test_utf8_bom_file_is_analysed(self) -> None:
        findings, raised = _scan({"app.py": b"\xef\xbb\xbf" + _SHELL_ROUTE.encode()})
        assert raised is None
        _proven(findings, SHELL)

    def test_latin1_declared_file_is_analysed(self) -> None:
        src = "# -*- coding: latin-1 -*-\n# caf\xe9\n" + _SHELL_ROUTE
        findings, raised = _scan({"app.py": src.encode("latin-1")})
        assert raised is None
        _proven(findings, SHELL)

    def test_bom_caller_proves_the_cross_file_hop(self) -> None:
        helper = "import os\ndef run(cmd):\n    os.system('ls ' + cmd)\n"
        caller = (
            "from flask import Flask, request\n"
            "from app.h import run\n"
            "app = Flask(__name__)\n"
            "@app.route('/x')\n"
            "def v():\n"
            "    run(request.args['c'])\n"
            "    return 'ok'\n"
        )
        files = {
            "app/__init__.py": "",
            "app/h.py": helper,
            "app/views.py": b"\xef\xbb\xbf" + caller.encode(),
        }
        findings, raised = _scan(files)
        assert raised is None
        _proven(findings, "SEC-PY_OS_SYSTEM", "app/h.py")

    def test_stray_byte_in_a_comment_is_still_analysed(self) -> None:
        findings, raised = _scan({"app.py": _SHELL_ROUTE.encode() + b"# \xff stray\n"})
        assert raised is None
        _proven(findings, SHELL)


# ---------------------------------------------------------------------------
# qa2-05: the call index's and the route index's losses are recorded
# ---------------------------------------------------------------------------


class TestIndexLossesAreRecorded:
    def test_call_index_failure_on_one_caller_names_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from analyzers.call_index import ProjectCallIndex

        original = ProjectCallIndex._call_sites

        def boom(self, rel, source, tree):  # noqa: ANN001
            if rel == "app/views.py":
                raise RuntimeError("index bug")
            return original(self, rel, source, tree)

        monkeypatch.setattr(ProjectCallIndex, "_call_sites", boom)
        files = {
            "app/__init__.py": "",
            "app/h.py": "import os\ndef run(cmd):\n    os.system('ls ' + cmd)\n",
            "app/views.py": (
                "from flask import Flask, request\n"
                "from app.h import run\n"
                "app = Flask(__name__)\n"
                "@app.route('/x')\n"
                "def v():\n"
                "    run(request.args['c'])\n"
                "    return 'ok'\n"
            ),
        }
        _findings, raised = _scan(files)
        assert _reasons(raised) == {"app/views.py": ["call index: internal error: RuntimeError"]}

    def test_call_index_recursion_on_a_proof_names_the_caller(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from analyzers.call_index import ProjectCallIndex

        def deep(self, rel):  # noqa: ANN001
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(ProjectCallIndex, "_caller", deep)
        files = {
            "app/__init__.py": "",
            "app/h.py": "import os\ndef run(cmd):\n    os.system('ls ' + cmd)\n",
            "app/views.py": (
                "from flask import Flask, request\n"
                "from app.h import run\n"
                "app = Flask(__name__)\n"
                "@app.route('/x')\n"
                "def v():\n"
                "    run(request.args['c'])\n"
                "    return 'ok'\n"
            ),
        }
        _findings, raised = _scan(files)
        assert _reasons(raised) == {"app/views.py": ["call index: recursion limit"]}

    def test_total_call_index_failure_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from analyzers.call_index import ProjectCallIndex

        def boom(cls, root, route_table, walk=None):  # noqa: ANN001
            raise MemoryError()

        monkeypatch.setattr(ProjectCallIndex, "build", classmethod(boom))
        findings, raised = _scan({"app.py": _SHELL_ROUTE})
        assert _reasons(raised) == {"(project call index)": ["out of memory"]}
        _proven(findings, SHELL)

    def test_route_index_only_abort_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The route extractor alone hits the recursion limit; the security
        # pass over the same file does not. The file's routes are missing,
        # so it must still be reported.
        import analyzers.route_extractor as rx

        original = rx._DecoratorRouteVisitor.visit

        def deep(self, node):  # noqa: ANN001
            if self.rel == "routes.py":
                raise RecursionError("maximum recursion depth exceeded")
            return original(self, node)

        monkeypatch.setattr(rx._DecoratorRouteVisitor, "visit", deep)
        _findings, raised = _scan({"routes.py": _SHELL_ROUTE, "app.py": _SHELL_ROUTE})
        assert _reasons(raised) == {"routes.py": ["route index: recursion limit"]}

    def test_scan_module_reports_its_own_abort(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import analyzers.route_extractor as rx

        def deep(self, node):  # noqa: ANN001
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(rx._DecoratorRouteVisitor, "visit", deep)
        errors: list[str] = []
        table, summary = rx.scan_module(_SHELL_ROUTE, "r.py", errors=errors)
        assert errors == ["recursion limit"]
        assert summary is None and not table.routes

    def test_scan_module_reports_a_parser_abort(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import analyzers.route_extractor as rx

        def deep(*_a, **_k):  # noqa: ANN002, ANN003
            raise MemoryError()

        monkeypatch.setattr(rx.ast, "parse", deep)
        errors: list[str] = []
        rx.scan_module(_SHELL_ROUTE, "r.py", errors=errors)
        assert errors == ["out of memory"]

    def test_route_index_unreadable_file_is_recorded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import analyzers.ast_analyzer as aa

        original = aa._read_python_source
        calls = {"n": 0}

        def flaky(path):  # noqa: ANN001
            # The route pass reads first and fails; later reads succeed.
            if Path(path).name == "routes.py" and calls["n"] == 0:
                calls["n"] += 1
                raise PermissionError("denied")
            return original(path)

        monkeypatch.setattr(aa, "_read_python_source", flaky)
        _findings, raised = _scan({"routes.py": _SHELL_ROUTE})
        assert _reasons(raised) == {"routes.py": ["route index: unreadable: PermissionError"]}


# ---------------------------------------------------------------------------
# redteam2-py-02: a '..' guard needs an absolute-path guard too
# ---------------------------------------------------------------------------

_PATH_APP = (
    "import os\n"
    "from pathlib import Path\n"
    "from flask import Flask, request, abort\n"
    "app = Flask(__name__)\n"
    "@app.route('/f')\n"
    "def f():\n"
)


def _path_case(body: str) -> list[dict]:
    src = _PATH_APP + "".join("    " + ln + "\n" for ln in body.strip("\n").split("\n"))
    findings, raised = _scan({"app.py": src})
    assert raised is None
    return findings


class TestDotdotGuardNeedsAbsoluteGuard:
    def test_dotdot_guard_alone_does_not_contain_an_absolute_path(self) -> None:
        f = _path_case("name = request.args['f']\nif '..' in name:\n    abort(400)\nreturn open(name).read()")
        _proven(f, PATH)

    @pytest.mark.parametrize(
        "guard",
        [
            "if '..' in name or os.path.isabs(name):\n    abort(400)",
            "if '..' in name or name.startswith('/'):\n    abort(400)",
            "if '..' in name:\n    abort(400)\nif os.path.isabs(name):\n    abort(400)",
            "if name.startswith(('/', '\\\\')) or '..' in name:\n    abort(400)",
            "if '..' in name or name.startswith(os.sep):\n    abort(400)",
            "if '..' in name or Path(name).is_absolute():\n    abort(400)",
        ],
    )
    def test_dotdot_and_absolute_guards_contain(self, guard: str) -> None:
        f = _path_case("name = request.args['f']\n" + guard + "\nreturn open(name).read()")
        # Judged at the `open` sink. (`Path(name)` inside a guard is a path
        # sink of its own, which this change does not touch.)
        at_open = [x for x in f if x["id"] == PATH and "open(name)" in x["evidence"]]
        assert not [x for x in at_open if _is_proven(x)], at_open

    @pytest.mark.parametrize(
        "guard",
        [
            # Not every absolute path: "/etc" does not start "/srv".
            "if '..' in name or name.startswith('/srv'):\n    abort(400)",
            # Not the same name.
            "if '..' in name or os.path.isabs(other):\n    abort(400)",
            # Does not leave the function.
            "if '..' in name or os.path.isabs(name):\n    print('bad')",
            # An `and` rejects only when both hold.
            "if '..' in name and os.path.isabs(name):\n    abort(400)",
        ],
    )
    def test_incomplete_absolute_guards_do_not_contain(self, guard: str) -> None:
        f = _path_case(
            "name = request.args['f']\nother = 'x'\n" + guard + "\nreturn open(name).read()"
        )
        _proven(f, PATH)

    def test_shadowed_isabs_does_not_count(self) -> None:
        src = (
            _PATH_APP.replace("import os\n", "import os\nfrom os.path import isabs\n")
            + "    isabs = lambda p: False\n"
            "    name = request.args['f']\n"
            "    if '..' in name or isabs(name):\n"
            "        abort(400)\n"
            "    return open(name).read()\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, PATH)


# ---------------------------------------------------------------------------
# redteam2-r006-01: os.open is no file sink
# ---------------------------------------------------------------------------

_B = "os.path.basename(request.args['t'])"


class TestOsOpenIsNotAFileSink:
    def test_os_open_of_a_last_part_basename_join_is_proven(self) -> None:
        f = _path_case(
            f"fd = os.open(os.path.join('/srv/data', {_B}), os.O_RDONLY)\nreturn str(os.listdir(fd))"
        )
        _proven(f, PATH)

    def test_from_os_import_open_is_not_a_file_sink(self) -> None:
        src = (
            _PATH_APP.replace("import os\n", "import os\nfrom os import open as osopen\n")
            + f"    fd = osopen(os.path.join('/srv/data', {_B}), os.O_RDONLY)\n"
            "    return str(os.listdir(fd))\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, PATH)

    @pytest.mark.parametrize(
        "opener,imp",
        [
            ("open", ""),
            ("io.open", "import io\n"),
            ("codecs.open", "import codecs\n"),
            ("gzip.open", "import gzip\n"),
        ],
    )
    def test_file_opens_still_contain_a_last_part_basename(self, opener: str, imp: str) -> None:
        src = (
            imp
            + _PATH_APP
            + f"    return {opener}(os.path.join('/srv/data', {_B})).read()\n"
        )
        findings, _raised = _scan({"app.py": src})
        _not_proven(findings, PATH)

    def test_shadowed_builtin_open_is_not_a_file_sink(self) -> None:
        f = _path_case(
            f"def inner(open=os.open):\n    return open(os.path.join('/srv/data', {_B}), os.O_RDONLY)\n"
            "return str(inner())"
        )
        _proven(f, PATH)


# ---------------------------------------------------------------------------
# redteam2-r006-02: a shadowed import proves nothing
# ---------------------------------------------------------------------------


class TestShadowedImportProvesNothing:
    def test_class_shadowing_an_imported_module(self) -> None:
        src = (
            "from os import path\n"
            "class path:\n"
            "    @staticmethod\n"
            "    def basename(p):\n"
            "        return p\n"
            + _PATH_APP
            + "    return open(os.path.join('/srv/data', path.basename(request.args['f']))).read()\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, PATH)

    def test_parameter_default_shadowing_an_imported_function(self) -> None:
        src = (
            "from os.path import basename\n"
            + _PATH_APP
            + "    def inner(basename=lambda p: p):\n"
            "        return open(os.path.join('/srv/data', basename(request.args['f']))).read()\n"
            "    return inner()\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, PATH)

    def test_later_module_level_store_shadows(self) -> None:
        src = (
            "from os.path import basename\n"
            + _PATH_APP
            + "    return open(os.path.join('/srv/data', basename(request.args['f']))).read()\n"
            "basename = str\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, PATH)

    def test_parameter_shadowing_an_imported_escape(self) -> None:
        src = (
            "from html import escape\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/p')\n"
            "def p(escape=lambda s: s):\n"
            "    return '<p>' + escape(request.args.get('x', '')) + '</p>'\n"
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, XSS)

    def test_local_import_inside_a_function_resolves(self) -> None:
        # The handler is named `h`; inside it `h` is the html module.
        src = (
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/p')\n"
            "def h():\n"
            "    import html as h\n"
            "    return '<p>' + h.escape(request.args.get('x', '')) + '</p>'\n"
        )
        findings, _raised = _scan({"app.py": src})
        _not_proven(findings, XSS)

    def test_unshadowed_imports_still_contain(self) -> None:
        src = (
            "from os import path\n"
            "from os.path import basename\n"
            + _PATH_APP
            + "    a = open(os.path.join('/srv/data', basename(request.args['f']))).read()\n"
            "    return a + open(os.path.join('/srv/data', path.basename(request.args['g']))).read()\n"
        )
        findings, _raised = _scan({"app.py": src})
        _not_proven(findings, PATH)


# ---------------------------------------------------------------------------
# redteam2-r001-01: an allowlist whose mutator escapes, or that another file
# reaches, is not constant
# ---------------------------------------------------------------------------

_URL = (
    "from urllib.parse import urlparse\n"
    "import requests\n"
    "from flask import Flask, request, abort\n"
    "app = Flask(__name__)\n"
    "ALLOWED = {'api.example.com'}\n"
)
_GUARD = (
    "    u = request.args.get('url', '')\n"
    "    if urlparse(u).netloc not in ALLOWED:\n"
    "        abort(400)\n"
    "    return requests.get(u).text\n"
)
_PROXY = "@app.route('/p')\ndef proxy():\n" + _GUARD


class TestAllowlistEscapes:
    @pytest.mark.parametrize(
        "mutation",
        [
            "    f = ALLOWED.add\n    f(request.args.get('h'))\n",
            "    g = ALLOWED.update\n    g([request.args.get('h')])\n",
            "    cb = [ALLOWED.add]\n    cb[0](request.args.get('h'))\n",
            "    ALLOWED.symmetric_difference_update({request.args.get('h')})\n",
        ],
    )
    def test_bound_mutator_in_a_function(self, mutation: str) -> None:
        src = _URL + "@app.route('/add')\ndef add():\n" + mutation + "    return 'ok'\n" + _PROXY
        findings, _raised = _scan({"app.py": src})
        _proven(findings, SSRF)

    def test_bound_mutator_at_module_level(self) -> None:
        src = (
            _URL
            + "ADD = ALLOWED.add\n"
            + "@app.route('/add')\ndef add():\n    ADD(request.args.get('h'))\n    return 'ok'\n"
            + _PROXY
        )
        findings, _raised = _scan({"app.py": src})
        _proven(findings, SSRF)

    @pytest.mark.parametrize(
        "other",
        [
            "import app\nfrom flask import request\ndef add():\n    app.ALLOWED.add(request.args.get('h'))\n",
            "from app import ALLOWED\nfrom flask import request\ndef add():\n    ALLOWED.add(request.args.get('h'))\n",
            "from app import (\n    app,\n    ALLOWED,\n)\ndef add(h):\n    ALLOWED.add(h)\n",
            "import app\ndef add(h):\n    getattr(app, 'ALLOWED').add(h)\n",
        ],
    )
    def test_mutation_from_another_file(self, other: str) -> None:
        findings, _raised = _scan({"app.py": _URL + _PROXY, "views.py": other})
        _proven(findings, SSRF)

    def test_allowlist_another_file_never_reaches_is_constant(self) -> None:
        other = "ALLOWED_EXTS = ['.png']\ndef f():\n    return 1\n"
        findings, _raised = _scan({"app.py": _URL + _PROXY, "views.py": other})
        _not_proven(findings, SSRF)

    def test_reads_of_non_mutating_methods_stay_constant(self) -> None:
        src = (
            _URL
            + "SNAP = ALLOWED.copy()\n"
            + "N = ALLOWED.__len__()\n"
            + _PROXY
        )
        findings, _raised = _scan({"app.py": src})
        _not_proven(findings, SSRF)

    def test_tuple_allowlist_reached_from_another_file_is_constant(self) -> None:
        src = _URL.replace("{'api.example.com'}", "('api.example.com',)") + _PROXY
        other = "from app import ALLOWED\ndef f():\n    return ALLOWED\n"
        findings, _raised = _scan({"app.py": src, "views.py": other})
        _not_proven(findings, SSRF)


# ---------------------------------------------------------------------------
# redteam2-r058-01: an escape that leaves quotes alone is no HTML escape
# ---------------------------------------------------------------------------

_XSS_APP = (
    "import html\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/p')\n"
    "def p():\n"
    "    x = request.args.get('x', '')\n"
)


def _xss(expr: str, extra: str = "") -> list[dict]:
    findings, _raised = _scan({"app.py": extra + _XSS_APP + f"    return {expr}\n"})
    return findings


class TestQuoteFlagEscapes:
    @pytest.mark.parametrize(
        "call",
        [
            "html.escape(x, quote=False)",
            "html.escape(x, False)",
            "html.escape(x, quote=flag)",
            "html.escape(x, **opts)",
        ],
    )
    def test_escape_leaving_quotes_is_not_an_escape(self, call: str) -> None:
        f = _xss(f"'<a title=\"' + {call} + '\">l</a>'", extra="flag = False\nopts = {}\n")
        _proven(f, XSS)

    @pytest.mark.parametrize("call", ["html.escape(x)", "html.escape(x, quote=True)", "html.escape(x, True)"])
    def test_escape_with_quotes_is_an_escape(self, call: str) -> None:
        _not_proven(_xss(f"'<a title=\"' + {call} + '\">l</a>'"), XSS)

    def test_cgi_escape_default_is_not_an_escape(self) -> None:
        f = _xss("'<a title=\"' + cgi.escape(x) + '\">l</a>'", extra="import cgi\n")
        _proven(f, XSS)

    def test_cgi_escape_with_quote_true_is_an_escape(self) -> None:
        f = _xss("'<a title=\"' + cgi.escape(x, quote=True) + '\">l</a>'", extra="import cgi\n")
        _not_proven(f, XSS)
