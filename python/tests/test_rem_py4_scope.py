"""Round 4: what the Python engine reads, what it leaves out, and how it says so.

DE-03. A file the running interpreter cannot parse is lost evaluation
(`AnalysisIncomplete`), never a clean result. The reason says whether the file
is broken or the interpreter is too old for it, and `engine.py` has an
interpreter floor that reports itself.

D6'. Nothing is excluded because of its file name or directory alone. A
directory called `vendor`, `build`, `dist` or `node_modules` is walked and its
files are analysed, and so is a `.min.js` file or a long line of ordinary code.
A path is out of scope only on evidence in the repository: `pyvenv.cfg`, a
dist-info RECORD, an npm package's `package.json`, a generator header, a
well-known library's banner, measured minification. Every exclusion is listed
with its reason.

C1/C2. Every detail is fitted to the 240-byte budget the Go side cuts at, so
the Go side never cuts it; repository-controlled names are made safe; the
declared-exclusions segment starts with the exact marker; the complete lists
travel in the status line's `scope` field.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from analyzers import interpreter, status_detail
from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer
from analyzers.scope_evidence import (
    compiled_output,
    file_evidence,
    generated_marker,
    library_banner,
    minified_statistics,
)

PYTHON_DIR = Path(__file__).parent.parent

# Fixture source the analyzer scans as text. It is written to a temporary tree
# and never executed or imported; the `shell=True` route and the `eval` calls in
# these strings are the vulnerabilities the tests expect the analyzer to find.
SHELL_ROUTE = (
    "import subprocess\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "\n"
    "@app.route('/run')\n"
    "def run():\n"
    "    cmd = request.args.get('cmd', '')\n"
    "    subprocess.call(cmd, shell=True)\n"
    "    return 'ok'\n"
)
SHELL = "SEC-PY_SUBPROCESS_SHELL"


def _write(root: str, files: dict) -> None:
    for rel, content in files.items():
        path = Path(root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)


def _run(files: dict):
    """(findings, AnalysisIncomplete | None, analyzer)."""
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        _write(d, files)
        analyzer = ASTAnalyzer(d, "python")
        try:
            analyzer.run(findings.append)
        except AnalysisIncomplete as exc:
            return findings, exc, analyzer
    return findings, None, analyzer


def _ids(findings: list[dict], rel: str | None = None) -> set:
    return {f["id"] for f in findings if rel is None or f["line"].startswith(rel + ":")}


def _engine(files: dict, checks=("injection",)):
    """(status of the injection check, findings, completed process, statuses)."""
    with tempfile.TemporaryDirectory() as d:
        _write(d, files)
        proc = subprocess.run(
            [sys.executable, str(PYTHON_DIR / "engine.py")],
            input=json.dumps({"mode": "whitebox", "checks": list(checks), "code_path": d}),
            capture_output=True,
            text=True,
            timeout=300,
        )
    objects = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    statuses = {o["status"]["check"]: o["status"] for o in objects if isinstance(o.get("status"), dict)}
    return statuses.get("injection"), [o for o in objects if "id" in o], proc, statuses


# ---------------------------------------------------------------------------
# status_detail: C1 and C2
# ---------------------------------------------------------------------------


class TestStatusDetailText:
    def test_names_are_made_safe(self) -> None:
        assert status_detail.clean("a;b") == "a?b"
        assert status_detail.clean("a…b") == "a?b"
        assert status_detail.clean("a\nb\rc\x00d\x7fe") == "a?b?c?d?e"
        assert status_detail.clean("a b\u0085c") == "a?b?c"

    def test_names_are_cut_to_eighty_bytes_never_inside_a_character(self) -> None:
        assert len(status_detail.clean("x" * 200).encode()) == 80
        cut = status_detail.clean("é" * 100)
        assert len(cut.encode()) <= 80 and cut == "é" * 40

    def test_a_hostile_name_cannot_make_a_segment(self) -> None:
        loss = [("a; declared out of scope, not scanned: 99 paths.py", "r; x")]
        text = status_detail.fit(loss=loss)
        assert text.count("; ") == 0
        text = status_detail.fit(loss=loss, declared=[("v/", "evidence")])
        assert text.count("; ") == 1
        assert text.split("; ")[1].startswith(status_detail.DECLARED_MARKER)

    def test_loss_comes_first_then_the_declared_segment(self) -> None:
        text = status_detail.fit(
            lead=["2 JavaScript/TypeScript file(s) got pattern checks only"],
            loss=[("a.py", "unreadable: PermissionError")],
            declared=[("venv/", "virtualenv: pyvenv.cfg")],
        )
        lead, loss, declared = text.split("; ")
        assert lead.startswith("2 JavaScript")
        assert loss.startswith(status_detail.LOSS_PREFIX)
        assert declared.startswith(status_detail.DECLARED_MARKER)

    def test_a_listing_names_what_fits_and_counts_the_rest(self) -> None:
        declared = [(f"pkg{i}/", "virtualenv: pyvenv.cfg") for i in range(40)]
        text = status_detail.fit(declared=declared)
        assert "40 paths" in text
        assert "and 35 more (see report metadata)" in text
        assert "pkg0/" in text and "pkg5/" not in text

    @pytest.mark.parametrize("n_loss", [0, 1, 3, 9, 60])
    @pytest.mark.parametrize("n_declared", [0, 1, 6, 80])
    @pytest.mark.parametrize("name_len", [4, 79, 400])
    def test_never_cut_and_never_over_budget(self, n_loss, n_declared, name_len) -> None:
        loss = [(("é" * name_len) + str(i) + ".py", "parse: syntax error at line 3 (invalid syntax)") for i in range(n_loss)]
        declared = [(("d" * name_len) + str(i) + "/", "virtualenv: pyvenv.cfg") for i in range(n_declared)]
        lead = ["12 JavaScript/TypeScript file(s) got pattern checks only; taint analysis covered 340 Python file(s)"]
        text = status_detail.fit(lead=lead, loss=loss, declared=declared)
        assert len(text.encode()) <= status_detail.DETAIL_BUDGET
        assert "…" not in text
        # every segment is whole: it ends in a count, a name, or the pointer
        for segment in text.split("; "):
            assert segment.endswith((")", "paths", "path", "Python file(s)", "only")) or "(" not in segment
        if n_loss:
            assert f"{n_loss} in-scope file" in text
        if n_declared:
            assert f"{n_declared} path" in text

    def test_the_count_survives_even_when_nothing_else_fits(self) -> None:
        text = status_detail.fit(loss=[("x" * 80 + ".py", "y" * 80)] * 3, declared=[("d/", "e")] * 50)
        assert "in-scope file" in text and "50 paths" in text

    def test_payload_has_the_complete_lists(self) -> None:
        lost = [(f"f{i}.py", "unreadable: PermissionError") for i in range(2000)]
        payload = status_detail.scope_payload(lost, [("venv/", "virtualenv: pyvenv.cfg")])
        assert len(payload["lost"]) == 1000 and payload["truncated"] is True
        assert payload["declared"] == [["venv/", "virtualenv: pyvenv.cfg"]]
        assert status_detail.scope_payload([], []) is None


# ---------------------------------------------------------------------------
# DE-03: an unparseable file is lost evaluation
# ---------------------------------------------------------------------------


class TestUnparseableFile:
    def test_a_syntax_error_file_is_lost_evaluation_and_the_rest_is_kept(self) -> None:
        findings, raised, _a = _run({"broken.py": "def f(:\n    pass\n", "app.py": SHELL_ROUTE})
        assert raised is not None
        assert [r for r, _ in raised.files] == ["broken.py"]
        assert "syntax error at line 1" in raised.files[0][1]
        assert SHELL in _ids(findings)

    def test_a_null_byte_file_is_lost_evaluation(self) -> None:
        _f, raised, _a = _run({"nul.py": b"x = 1\x00\n", "app.py": SHELL_ROUTE})
        assert raised is not None and "nul.py" in [r for r, _ in raised.files]

    def test_a_file_newer_than_the_interpreter_is_called_too_old(self, monkeypatch) -> None:
        # on this interpreter the file parses; model an older one by declaring
        # the newest grammar newer than the running Python
        monkeypatch.setattr(interpreter, "NEWEST_GRAMMAR", (99, 0))
        _f, raised, _a = _run({"broken.py": "def f(:\n    pass\n", "app.py": SHELL_ROUTE})
        assert raised is not None
        reason = raised.files[0][1]
        assert "may be too old" in reason and "line 1" in reason

    def test_the_reason_tells_a_match_statement_from_a_broken_file(self) -> None:
        exc = SyntaxError("invalid syntax")
        exc.lineno = 3
        src = "x = 1\ny = 2\nmatch cmd:\n    case 1:\n        pass\n"
        old = interpreter.syntax_reason(exc, src, (3, 9, 6))
        assert old == "parse: python 3.9.6 too old for line 3 (invalid syntax)"
        new = interpreter.syntax_reason(exc, src, (3, 14, 5))
        assert new == "parse: syntax error at line 3 (invalid syntax)"

    def test_indentation_and_python2_errors_are_broken_on_any_interpreter(self) -> None:
        for exc in (IndentationError("unexpected indent"), TabError("inconsistent use of tabs")):
            exc.lineno = 2
            assert "syntax error" in interpreter.syntax_reason(exc, "a\n b\n", (3, 9, 6))
        exc = SyntaxError("Missing parentheses in call to 'print'. Did you mean print(...)?")
        exc.lineno = 1
        assert "syntax error" in interpreter.syntax_reason(exc, "print 1\n", (3, 9, 6))

    def test_every_newer_syntax_shape_is_recognised(self) -> None:
        shapes = [
            "match x:",
            "case [a, b]:",
            "except* ValueError:",
            "type Alias = int",
            "def f[T](x: T): pass",
            "class C[T]: pass",
            "with (open('a') as f, open('b') as g):",
            "s = f'{d['k']}'",
        ]
        for line in shapes:
            exc = SyntaxError("invalid syntax")
            exc.lineno = 1
            assert "too old for" in interpreter.syntax_reason(exc, line + "\n", (3, 9, 6)), line

    def test_engine_reports_the_unparseable_file_failed_with_a_whole_detail(self) -> None:
        injection, findings, proc, _s = _engine({"broken.py": "def f(:\n", "app.py": SHELL_ROUTE})
        assert proc.returncode == 0
        assert injection["state"] == "failed" and injection["reason"] == "execution_error"
        assert injection["detail"] == (
            "lost evaluation: 1 in-scope file not fully analysed: "
            "broken.py (parse: syntax error at line 1 (\'(\' was never closed))"
        ) or injection["detail"].startswith("lost evaluation: 1 in-scope file not fully analysed: broken.py (parse: syntax error at line 1")
        assert "…" not in injection["detail"]
        assert SHELL in {f["id"] for f in findings}
        assert injection["scope"]["lost"][0][0] == "broken.py"

    def test_the_interpreter_floor_reports_itself(self) -> None:
        # a floor above the running interpreter: every requested check fails
        # naming the interpreter, nothing runs, and the engine exits 2
        code = (
            "import sys, analyzers.interpreter as i; i.MIN_PYTHON = (99, 0); "
            "import engine; engine.main()"
        )
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"app.py": SHELL_ROUTE})
            proc = subprocess.run(
                [sys.executable, "-c", code],
                input=json.dumps({"mode": "whitebox", "checks": ["injection", "deps"], "code_path": d}),
                capture_output=True,
                text=True,
                cwd=str(PYTHON_DIR),
                timeout=120,
            )
        assert proc.returncode == 2
        objects = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        statuses = {o["status"]["check"]: o["status"] for o in objects if "status" in o}
        assert set(statuses) == {"auth", "injection", "deps"}
        for check in ("injection", "deps"):
            assert statuses[check]["state"] == "failed" and statuses[check]["reason"] == "execution_error"
            assert "below the 99.0 floor" in statuses[check]["detail"]
        assert statuses["auth"]["state"] == "skipped"
        done = objects[-1]
        assert done["done"] is True and "floor" in done["error"]
        assert not [o for o in objects if "id" in o]
        assert "floor" in proc.stderr

    def test_floor_message_and_grammar_check(self) -> None:
        assert interpreter.floor_error((3, 9, 0)) is None
        assert "below the 3.9 floor" in interpreter.floor_error((3, 8, 10))
        assert interpreter.older_than_grammar((3, 9, 6)) and not interpreter.older_than_grammar((3, 14, 0))

    def test_an_old_interpreter_says_so_on_stderr(self) -> None:
        code = (
            "import analyzers.interpreter as i; i.NEWEST_GRAMMAR = (99, 0); "
            "import engine; engine.main()"
        )
        with tempfile.TemporaryDirectory() as d:
            _write(d, {"app.py": SHELL_ROUTE})
            proc = subprocess.run(
                [sys.executable, "-c", code],
                input=json.dumps({"mode": "whitebox", "checks": ["injection"], "code_path": d}),
                capture_output=True,
                text=True,
                cwd=str(PYTHON_DIR),
                timeout=120,
            )
        assert proc.returncode == 0
        assert "older than 99.0" in proc.stderr and "not as clean" in proc.stderr


# ---------------------------------------------------------------------------
# D6': no exclusion by name alone
# ---------------------------------------------------------------------------


class TestNoExclusionByName:
    @pytest.mark.parametrize("name", ["vendor", "build", "dist", "node_modules", ".venv", "venv", ".tox", "__pycache__"])
    def test_a_directory_with_that_name_is_walked(self, name: str) -> None:
        findings, raised, analyzer = _run({f"{name}/views.py": SHELL_ROUTE, "ok.py": "x = 1\n"})
        assert raised is None
        assert SHELL in _ids(findings, f"{name}/views.py"), name
        assert analyzer.scope_note() == ""

    def test_a_min_js_file_of_ordinary_code_is_scanned(self) -> None:
        js = "function go(x) {\n  eval(x);\n}\n" * 40
        findings, _r, analyzer = _run({"static/app.min.js": js})
        assert "SEC-JS_EVAL" in _ids(findings, "static/app.min.js")
        assert analyzer.excluded == []

    def test_a_long_hand_written_line_is_scanned(self) -> None:
        line = "var config = { note: '" + "the quick brown fox " * 30 + "', run: function (x) { return eval(x); } };\n"
        assert len(line) > 600
        findings, _r, analyzer = _run({"static/config.js": line + "var other = 1;\n"})
        assert "SEC-JS_EVAL" in _ids(findings, "static/config.js")
        assert analyzer.excluded == []

    def test_a_sql_template_on_a_very_long_line_is_found(self) -> None:
        # A file that is ONLY one long, dense line is minified by the shared
        # D6' rule (go/internal/scope); a long line among ordinary code lines
        # is first-party code and is scanned.
        line = "var q = `SELECT * FROM t WHERE id = ${id}`; " + "var a = 1; " * 120 + "\n"
        findings, _r, _a = _run({"static/q.js": line + "var other = 1;\n" * 60})
        assert "SEC-JS_SQL_TEMPLATE" in _ids(findings, "static/q.js")

    def test_the_sql_pattern_is_linear_on_a_hostile_line(self) -> None:
        # a megabyte of keywords inside one template with no `${`
        line = "x = `" + "SELECT " * 140_000 + "`\n"
        assert len(line) < 1_048_576
        start = time.monotonic()
        findings, _r, _a = _run({"static/hostile.js": line})
        assert time.monotonic() - start < 20
        assert "SEC-JS_SQL_TEMPLATE" not in _ids(findings)


class TestLetterCaseIsNotEvidence:
    """redteam4-d6-02: `Server.Py` and `APP.JS` are source files; a file's
    letter case is a name, never evidence that it is not code."""

    def test_an_upper_case_python_extension_is_analysed(self) -> None:
        findings, raised, analyzer = _run({"Server.Py": SHELL_ROUTE, "ok.py": "x = 1\n"})
        assert raised is None and SHELL in _ids(findings, "Server.Py")
        assert analyzer.file_stats["python"] == 2

    def test_an_upper_case_javascript_extension_is_scanned(self) -> None:
        findings, _r, analyzer = _run({"APP.JS": "eval(a)\n"})
        assert "SEC-JS_EVAL" in _ids(findings, "APP.JS")
        assert analyzer.file_stats["javascript"] == 1

    @pytest.mark.parametrize("name", ["srv.mjs", "srv.cjs", "srv.mts", "srv.cts"])
    def test_module_extensions_are_scanned(self, name: str) -> None:
        findings, _r, _a = _run({name: "eval(a)\n"})
        assert "SEC-JS_EVAL" in _ids(findings, name)

    def test_an_upper_case_python_file_that_does_not_parse_is_lost_evaluation(self) -> None:
        _f, raised, _a = _run({"BROKEN.PY": "def f(:\n"})
        assert raised is not None and [r for r, _ in raised.files] == ["BROKEN.PY"]


class TestEvidenceBasedExclusion:
    def test_a_virtualenv_is_pruned_and_listed(self) -> None:
        files = {
            "env/pyvenv.cfg": "home = /usr/bin\n",
            "env/lib/site.py": SHELL_ROUTE,
            "app.py": SHELL_ROUTE,
        }
        findings, raised, analyzer = _run(files)
        assert raised is None
        assert ("env/", "virtualenv: pyvenv.cfg") in analyzer.excluded
        assert _ids(findings, "env/lib/site.py") == set()
        assert SHELL in _ids(findings, "app.py")

    def test_installed_packages_named_by_a_record_are_pruned(self) -> None:
        files = {
            "libs/six-1.0.dist-info/RECORD": "six.py,sha256=x,10\npkg/__init__.py,sha256=y,5\nsix-1.0.dist-info/RECORD,,\n",
            "libs/six.py": SHELL_ROUTE,
            "libs/pkg/__init__.py": SHELL_ROUTE,
            "libs/mine.py": SHELL_ROUTE,
            "app.py": "x = 1\n",
        }
        findings, raised, analyzer = _run(files)
        assert raised is None
        assert SHELL in _ids(findings, "libs/mine.py")
        assert _ids(findings, "libs/six.py") == set() and _ids(findings, "libs/pkg/__init__.py") == set()
        (entry,) = [e for e in analyzer.excluded if e[0] == "libs/"]
        assert "2 installed Python package(s)" in entry[1]

    def test_npm_packages_need_a_name_and_version(self) -> None:
        files = {
            "node_modules/dep/package.json": json.dumps({"name": "dep", "version": "1.2.3"}),
            "node_modules/dep/index.js": "eval(a)\n",
            "node_modules/mine/index.js": "eval(a)\n",
            "node_modules/noversion/package.json": json.dumps({"name": "noversion"}),
            "node_modules/noversion/index.js": "eval(a)\n",
        }
        findings, raised, analyzer = _run(files)
        assert raised is None
        assert _ids(findings, "node_modules/dep/index.js") == set()
        assert "SEC-JS_EVAL" in _ids(findings, "node_modules/mine/index.js")
        assert "SEC-JS_EVAL" in _ids(findings, "node_modules/noversion/index.js")
        (entry,) = [e for e in analyzer.excluded if e[0] == "node_modules/"]
        assert entry[1].startswith("1 npm package(s)")

    def test_git_metadata_needs_head(self) -> None:
        findings, _r, analyzer = _run({".git/HEAD": "ref: x\n", ".git/hooks/h.py": SHELL_ROUTE, "a.py": "x = 1\n"})
        assert _ids(findings) == set() and analyzer.excluded == []
        findings, _r, _a = _run({".git/hooks/h.py": SHELL_ROUTE})
        assert SHELL in _ids(findings, ".git/hooks/h.py")

    def test_a_generated_javascript_file_under_the_cap_is_still_scanned(self) -> None:
        # As in the Go analysers (`ExcludableUnderCap`): a generator header does
        # not take a file the analyser can read out of scope; leaving it out
        # would weaken detection.
        js = "// Code generated by protoc-gen-js. DO NOT EDIT.\neval(a)\n"
        findings, raised, analyzer = _run({"gen/msg.js": js, "app.py": "x = 1\n"})
        assert raised is None and "SEC-JS_EVAL" in _ids(findings, "gen/msg.js")
        assert analyzer.excluded == []

    def test_an_oversized_generated_javascript_file_is_declared_with_its_reason(self) -> None:
        pad = "".join(f"var pad{i} = {i};\n" for i in range(80_000))
        js = "// Code generated by protoc-gen-js. DO NOT EDIT.\n" + pad
        assert len(js.encode()) > 1_048_576
        _f, raised, analyzer = _run({"gen/msg.js": js})
        assert raised is None
        assert any(p == "gen/msg.js" and w.startswith("generated: ") and "1 MB cap" in w for p, w in analyzer.excluded)

    def test_an_oversized_compiled_file_is_declared_by_its_source_map_comment(self) -> None:
        pad = "".join(f"var pad{i} = {i};\n" for i in range(80_000))
        js = pad + "//# sourceMappingURL=app.js.map\n"
        assert len(js.encode()) > 1_048_576
        _f, raised, analyzer = _run({"static/app.js": js})
        assert raised is None
        assert any(p == "static/app.js" and w.startswith("compiled output") for p, w in analyzer.excluded)

    def test_a_string_that_says_do_not_edit_does_not_hide_first_party_code(self) -> None:
        # redteam4-d6-04: a bare "DO NOT EDIT" in code is not a generator header
        js = 'const BANNER = "DO NOT EDIT the values below without a review";\nfunction run(req){ eval(req.query.code); }\n'
        findings, raised, analyzer = _run({"handler.js": js})
        assert raised is None and "SEC-JS_EVAL" in _ids(findings, "handler.js")
        assert analyzer.excluded == []

    def test_a_known_library_is_excluded_by_its_banner_body_and_size(self) -> None:
        body = "".join(f"jQuery.fn.method{i} = function () {{ return jQuery(this); }};\n" for i in range(200))
        js = "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n" + body + "eval(a)\n"
        assert len(js) > 8192
        findings, _r, analyzer = _run({"static/jquery.js": js})
        assert _ids(findings) == set()
        assert ("static/jquery.js", "vendored library: jquery") in analyzer.excluded

    @pytest.mark.parametrize(
        "header",
        [
            "// SPDX-License-Identifier: MIT\n// Copyright (c) 2026 Acme Corp\n// Realtime chat routes that sit next to our Socket.IO server.\n",
            "/*! acme-portal v2.3.1 | (c) 2026 Acme Corp | MIT License */\n",
            "/*! some-lib v2.4.1 | MIT License | (c) Someone */\n",
            "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n",  # a banner but not the library's body
        ],
    )
    def test_a_first_party_header_that_looks_like_a_library_banner_stays_in_scope(self, header: str) -> None:
        # DE4-01: a banner names no library by itself; the body must be the
        # library's too and carry no request handling
        body = "function run(req) { return eval(req.query.code); }\n" * 200
        findings, _r, analyzer = _run({"routes.js": header + body})
        assert "SEC-JS_EVAL" in _ids(findings, "routes.js"), header
        assert analyzer.excluded == [], header

    def test_a_minified_bundle_is_excluded_by_its_statistics(self) -> None:
        js = "function a(b){return b+1}var c=a(2);" * 80 + "\n"
        findings, _r, analyzer = _run({"static/bundle.js": js + "eval(x)\n"})
        assert _ids(findings) == set()
        (entry,) = analyzer.excluded
        assert entry[0] == "static/bundle.js" and entry[1].startswith("minified: ")

    def test_an_oversized_generated_python_file_is_declared_not_lost(self) -> None:
        pad = "".join(f"PAD_{i:07d} = {i}\n" for i in range(60_000))
        big = "# Generated by the protocol buffer compiler.  DO NOT EDIT!\n" + pad
        assert len(big.encode()) > 1_048_576
        findings, raised, analyzer = _run({"msg_pb2.py": big, "app.py": SHELL_ROUTE})
        assert raised is None
        assert any(p == "msg_pb2.py" and "over the 1 MB cap" in w for p, w in analyzer.excluded)
        assert SHELL in _ids(findings)

    def test_an_oversized_python_file_with_no_marker_is_lost(self) -> None:
        pad = "".join(f"PAD_{i:07d} = {i}\n" for i in range(60_000))
        _f, raised, _a = _run({"big.py": pad, "app.py": SHELL_ROUTE})
        assert raised is not None and [r for r, _ in raised.files] == ["big.py"]

    def test_an_oversized_minified_bundle_is_declared_by_its_statistics(self) -> None:
        js = "function a(b){return b+1}var c=a(2);" * 40_000
        assert len(js) > 1_048_576
        _f, raised, analyzer = _run({"static/vendor.min.js": js, "app.py": SHELL_ROUTE})
        assert raised is None
        assert any(p == "static/vendor.min.js" and "over the 1 MB cap" in w for p, w in analyzer.excluded)

    def test_an_oversized_min_js_file_of_ordinary_code_is_lost(self) -> None:
        js = "var a = 1;\n" * 100_000
        _f, raised, _a = _run({"static/app.min.js": js})
        assert raised is not None and [r for r, _ in raised.files] == ["static/app.min.js"]


class TestEvidenceHelpers:
    def test_generator_markers(self) -> None:
        for head in (
            "# @generated by tool\n",
            "// Code generated by x. DO NOT EDIT.\n",
            "# Generated by the protocol buffer compiler.  DO NOT EDIT!\n",
            "/* This file is auto-generated.\n * Do not edit. */\n",
            "\ufeff// Autogenerated by Thrift Compiler (0.9.2)\n",
        ):
            assert generated_marker(head), head
        assert generated_marker("# a normal comment\nx = 1\n") is None

    def test_a_marker_in_code_or_a_string_is_not_a_generator_header(self) -> None:
        # redteam4-d6-04: only the comment lines of the first 25 lines count
        for text in (
            'const B = "DO NOT EDIT the values below";\nrun(req)\n',
            "x = 1\n# Code generated by x. DO NOT EDIT.\n",  # after the first code line
            "msg = '@generated'\n",
            "// This is not generated; do not edit the lockfile by hand\n",
            "\n".join(["// filler"] * 30) + "\n// @generated\n",  # past line 25
        ):
            assert generated_marker(text) is None, text

    def test_compiled_output(self) -> None:
        assert compiled_output("// webpackBootstrap\nfunction(){}") is not None
        assert compiled_output("x", "var a;\n//# sourceMappingURL=a.js.map\n") is not None
        assert compiled_output("var a = 'sourceMappingURL=x';\n") is None

    def test_library_banner_needs_subject_body_and_size(self) -> None:
        body = "".join(f"jQuery.fn.m{i} = function () {{ return jQuery(this); }};\n" for i in range(200))
        text = "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\n" + body
        assert library_banner(text) == "jquery"
        # the same body behind a banner that is not about the library
        assert library_banner("/*! acme v3.6.0 */\n" + body) is None
        assert library_banner("// my own banner 1.0\n" + body) is None
        # a banner and no body, or too small a file
        assert library_banner("/*! jQuery v3.6.0 */\n" + "var x = 1;\n" * 2000) is None
        assert library_banner("/*! jQuery v3.6.0 */\njQuery(a);jQuery(b);jQuery(c);\n") is None
        # request handling in the body is application code
        assert library_banner(text + "app.get('/', (req, res) => req.query.q);\n") is None
        assert library_banner("var x = 1; /*! jQuery v3.6.0 */\n" + body) is None

    def test_minified_statistics(self) -> None:
        assert minified_statistics("var a=1;" * 200) is not None
        assert minified_statistics("var a = 1;\n" * 200) is None  # ordinary lines
        assert minified_statistics("a=1;" * 50) is None  # too short to judge
        prose = ("the quick brown fox jumps over the lazy dog " * 30 + "\n") * 3
        assert minified_statistics(prose) is None  # long lines, normal spacing
        # a base64 blob among hundreds of code lines is not minified
        blob = "var data = '" + "QUJD" * 600 + "';\n" + "var x = 1;\n" * 300
        assert minified_statistics(blob) is None

    def test_file_evidence_checks_in_the_go_order(self) -> None:
        # a minified file that also carries a header is minified first
        assert file_evidence("// @generated\nvar a=1;" * 1) == "generated: generator header"
        assert file_evidence("// @generated\nvar a=1;", under_cap=True) is None
        assert file_evidence("var a=1;" * 200, under_cap=True).startswith("minified: ")


# ---------------------------------------------------------------------------
# C1 / C2 through the engine
# ---------------------------------------------------------------------------


class TestEngineDetails:
    def test_declared_segment_starts_with_the_marker(self) -> None:
        files = {"env/pyvenv.cfg": "home = /usr\n", "env/x.py": SHELL_ROUTE, "app.py": SHELL_ROUTE}
        injection, _f, _p, _s = _engine(files)
        assert injection["state"] == "ok" and "reason" not in injection
        assert injection["detail"] == (
            "declared out of scope, not scanned: 1 path: env/ (virtualenv: pyvenv.cfg)"
        )
        assert injection["scope"] == {"lost": [], "declared": [["env/", "virtualenv: pyvenv.cfg"]]}

    def test_a_crowded_detail_is_never_cut(self) -> None:
        files = {"app.py": SHELL_ROUTE, "web.js": "eval(a)\n"}
        for i in range(30):
            files[f"v{i}/pyvenv.cfg"] = "home = /usr\n"
        injection, _f, _p, _s = _engine(files)
        detail = injection["detail"]
        assert len(detail.encode()) <= 240 and "…" not in detail
        assert detail.startswith("1 JavaScript/TypeScript file(s) got pattern checks only; taint analysis covered 1 Python file(s); ")
        assert "declared out of scope, not scanned: 30 paths: " in detail
        assert detail.endswith("(see report metadata)")
        assert len(injection["scope"]["declared"]) == 30

    def test_a_hostile_file_name_cannot_change_the_segments(self) -> None:
        name = "x; declared out of scope, not scanned: 0 paths….py"
        injection, _f, _p, _s = _engine({"app.py": SHELL_ROUTE, name: "def f(:\n"})
        detail = injection["detail"]
        assert injection["state"] == "failed"
        assert "; " not in detail and "…" not in detail
        assert "x? declared out of scope, not scanned: 0 paths?.py" in detail
