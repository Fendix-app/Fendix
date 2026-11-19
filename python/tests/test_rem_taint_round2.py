"""Remediation round 2 regressions (Python taint engine).

Each case is a decorated Flask handler written to a temporary tree and run
through ``ASTAnalyzer(code_path, "python").run(emit)``, the way
``python/engine.py`` drives the analyzer. "Proven" is what the engine BLOCKs
under ``--fail-on high``: ``reachable`` is True and a ``taint_chain`` is
attached.

redteam-r006-01: ``os.path.basename("..") == ".."`` and
``Path("..").name == ".."``. A basename-reduced part keeps a join under its
root only when it is the join's LAST part, every other part is a constant or
trusted base (or ``secure_filename``), and the joined path goes to a sink that
reads or writes a FILE: the worst case is then ``ROOT/..``, a directory, which
a file sink rejects. A directory sink (``send_from_directory``'s directory,
``shutil.rmtree``, ``os.listdir``) and a non-final part are never contained by
basename. ``secure_filename`` strips ``..`` and stays a containment.

redteam-r006-02: containment is resolved through the file's imports. A
project's own ``basename()`` or ``secure_filename()`` proves nothing.

redteam-r058-01: an HTML sink is sanitised only by an HTML escape resolved
through the imports (``html.escape``, ``markupsafe.escape``,
``django.utils.html.escape``, ``bleach.clean``, ...). ``shlex.quote``,
``pipes.quote``, ``re.escape`` and a project's own ``escape()``/``clean()``
are not.

redteam-r001-01: an allowlist that is aliased and mutated through the alias
is not constant.

qa-engine-03: ``_is_shell_quoted`` is resolved by module. A project's
``helpers.quote`` and ``urllib.parse.quote`` do not sanitise a shell helper.

redteam-py-01: a file whose analysis is cut short (the recursion limit, or
any other exception mid-walk) is lost evaluation. The analyzer finishes the
rest of the tree, keeps every finding, and then raises
``AnalysisIncomplete``; ``engine.py`` reports the injection check
``failed/execution_error``, which the coverage contract counts as a gap.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer


def _scan(files: dict[str, str]) -> list[dict]:
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        for rel, src in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src)
        ASTAnalyzer(d, "python").run(findings.append)
    return findings


def _of(findings: list[dict], rule: str, rel: str = "app.py") -> list[dict]:
    return [f for f in findings if f["id"] == rule and f["line"].startswith(rel + ":")]


def _is_proven(f: dict) -> bool:
    return f.get("reachable") is True and bool(f.get("taint_chain"))


def _proven(findings: list[dict], rule: str, rel: str = "app.py") -> dict:
    found = [f for f in _of(findings, rule, rel) if _is_proven(f)]
    assert found, f"expected a proven {rule} in {rel}; got {_of(findings, rule, rel)}"
    return found[0]


def _not_proven(findings: list[dict], rule: str, rel: str = "app.py") -> None:
    proven = [
        f for f in _of(findings, rule, rel) if f.get("reachable") is True or f.get("taint_chain")
    ]
    assert not proven, f"{rule} must not be proven: {proven}"


PATH = "SEC-PY_PATH_TRAVERSAL"
XSS = "SEC-PY_XSS_HTML_SINK"
SSRF = "SEC-PY_SSRF"
SHELL = "SEC-PY_SUBPROCESS_SHELL"

_FILES = (
    "import os\n"
    "import shutil\n"
    "from pathlib import Path\n"
    "from flask import Flask, request, send_file, send_from_directory\n"
    "from werkzeug.utils import secure_filename\n"
    "app = Flask(__name__)\n"
    'UPLOADS = "/srv/uploads"\n'
)


def _handler(body: str, extra: str = "", route: str = "/h") -> str:
    lines = "".join("    " + ln + "\n" for ln in body.strip("\n").split("\n"))
    return _FILES + extra + f'@app.route("{route}")\n' + "def handler():\n" + lines


# ---------------------------------------------------------------------------
# redteam-r006-01: basename("..") == ".."
# ---------------------------------------------------------------------------


class TestBasenameIsNotContainmentOutsideTheLastFilePart:
    def test_two_basename_parts_open(self) -> None:
        # tenant=".." reads UPLOADS/../<name>.
        src = _handler(
            'tenant = os.path.basename(request.args["tenant"])\n'
            'name = os.path.basename(request.args["name"])\n'
            "return open(os.path.join(UPLOADS, tenant, name)).read()"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_two_basename_parts_inline_send_file(self) -> None:
        src = _handler(
            "return send_file(os.path.join(UPLOADS, os.path.basename(request.args['t']), "
            "os.path.basename(request.args['n'])))"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_basename_directory_then_constant_file(self) -> None:
        src = _handler(
            "return send_file(os.path.join(UPLOADS, os.path.basename(request.args['t']), 'report.pdf'))"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_basename_directory_then_constant_open(self) -> None:
        src = _handler(
            "return open(os.path.join(UPLOADS, os.path.basename(request.args['d']), 'config.yaml')).read()"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_pathlib_name_directory_then_constant(self) -> None:
        src = _handler("return send_file(Path(UPLOADS) / Path(request.args['t']).name / 'report.pdf')")
        _proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_directory_joined_with_basename(self) -> None:
        # The per-user upload directory: user=".." serves any file under the
        # parent of UPLOADS.
        src = _handler(
            "user = os.path.basename(request.args['user'])\n"
            "return send_from_directory(os.path.join(UPLOADS, user), request.args['f'])"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_directory_joined_with_basename_inline(self) -> None:
        src = _handler(
            "return send_from_directory(os.path.join(UPLOADS, os.path.basename(request.args['u'])), 'report.pdf')"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_directory_is_a_basename(self) -> None:
        src = _handler("return send_from_directory(os.path.basename(request.args['d']), 'x.txt')")
        _proven(_scan({"app.py": src}), PATH)

    def test_rmtree_of_join_with_basename(self) -> None:
        src = _handler(
            "shutil.rmtree(os.path.join(UPLOADS, os.path.basename(request.args['d'])))\nreturn 'ok'"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_listdir_of_join_with_basename(self) -> None:
        src = _handler("return str(os.listdir(os.path.join(UPLOADS, os.path.basename(request.args['d']))))")
        _proven(_scan({"app.py": src}), PATH)

    def test_join_bound_to_a_name_used_as_a_directory(self) -> None:
        src = _handler(
            "d = os.path.join(UPLOADS, os.path.basename(request.args['d']))\n"
            "return str(os.listdir(d))"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_helper_with_basename_param_in_the_middle(self) -> None:
        helper = (
            "def fetch(name):\n"
            "    return open(os.path.join(UPLOADS, name, 'index.html')).read()\n"
        )
        src = _handler("return fetch(os.path.basename(request.args['d']))", extra=helper)
        _proven(_scan({"app.py": src}), PATH)

    def test_helper_with_basename_param_as_a_directory(self) -> None:
        helper = (
            "def serve(user, f):\n"
            "    return send_from_directory(os.path.join(UPLOADS, user), f)\n"
        )
        src = _handler(
            "return serve(os.path.basename(request.args['u']), request.args['f'])", extra=helper
        )
        _proven(_scan({"app.py": src}), PATH)

    # -- still contained ------------------------------------------------------

    def test_single_basename_last_part_send_file_is_safe(self) -> None:
        src = _handler("return send_file(os.path.join(UPLOADS, os.path.basename(request.args['n'])))")
        _not_proven(_scan({"app.py": src}), PATH)

    def test_single_basename_last_part_open_via_name_is_safe(self) -> None:
        src = _handler(
            "p = os.path.join(UPLOADS, os.path.basename(request.args['n']))\n"
            "return open(p).read()"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_secure_part_then_basename_last_is_safe(self) -> None:
        src = _handler(
            "return send_file(os.path.join(UPLOADS, secure_filename(request.args['t']), "
            "os.path.basename(request.args['n'])))"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_two_secure_filename_parts_are_safe(self) -> None:
        src = _handler(
            "return send_file(os.path.join(UPLOADS, secure_filename(request.args['t']), "
            "secure_filename(request.args['n'])))"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_directory_joined_with_secure_filename_is_safe(self) -> None:
        src = _handler(
            "return send_from_directory(os.path.join(UPLOADS, secure_filename(request.args['u'])), 'report.pdf')"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_upload_save_basename_is_safe(self) -> None:
        # FileStorage.save opens the path for writing; UPLOADS/.. is a
        # directory and the write fails.
        src = _handler(
            "f = request.files['file']\n"
            "f.save(os.path.join(UPLOADS, os.path.basename(f.filename)))\n"
            "return 'ok'"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_helper_with_basename_param_last_is_safe(self) -> None:
        helper = "def fetch(name):\n    return open(os.path.join(UPLOADS, name)).read()\n"
        src = _handler("return fetch(os.path.basename(request.args['d']))", extra=helper)
        _not_proven(_scan({"app.py": src}), PATH)


# ---------------------------------------------------------------------------
# redteam-r006-02: containment resolved through the imports
# ---------------------------------------------------------------------------


class TestContainmentIsResolvedByImport:
    def test_local_identity_basename(self) -> None:
        extra = "def basename(p):\n    return p\n"
        src = _handler("return open(os.path.join(UPLOADS, basename(request.args['f']))).read()", extra=extra)
        _proven(_scan({"app.py": src}), PATH)

    def test_basename_imported_from_a_project_module(self) -> None:
        extra = "from mylib import basename\n"
        src = _handler("return open(os.path.join(UPLOADS, basename(request.args['f']))).read()", extra=extra)
        _proven(_scan({"app.py": src}), PATH)

    def test_basename_attribute_of_a_project_module(self) -> None:
        extra = "import mylib\n"
        src = _handler(
            "return open(os.path.join(UPLOADS, mylib.basename(request.args['f']))).read()", extra=extra
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_local_identity_secure_filename(self) -> None:
        src = (
            "import os\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            'UPLOADS = "/srv/uploads"\n'
            "def secure_filename(p):\n"
            "    return p\n"
            '@app.route("/h")\n'
            "def handler():\n"
            "    return open(os.path.join(UPLOADS, secure_filename(request.args['f']))).read()\n"
        )
        _proven(_scan({"app.py": src}), PATH)

    def test_from_os_path_import_basename_is_safe(self) -> None:
        extra = "from os.path import basename\n"
        src = _handler("return open(os.path.join(UPLOADS, basename(request.args['f']))).read()", extra=extra)
        _not_proven(_scan({"app.py": src}), PATH)

    def test_posixpath_basename_is_safe(self) -> None:
        extra = "import posixpath\n"
        src = _handler(
            "return open(os.path.join(UPLOADS, posixpath.basename(request.args['f']))).read()", extra=extra
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_os_path_alias_basename_is_safe(self) -> None:
        extra = "import os.path as osp\n"
        src = _handler("return open(os.path.join(UPLOADS, osp.basename(request.args['f']))).read()", extra=extra)
        _not_proven(_scan({"app.py": src}), PATH)


# ---------------------------------------------------------------------------
# redteam-r058-01: HTML escapes are resolved by module
# ---------------------------------------------------------------------------

_X = "x = request.args.get('x', '')\n"


class TestHtmlSanitiserIsResolvedByModule:
    def test_shlex_quote_does_not_escape_html(self) -> None:
        src = _handler(_X + "import shlex\nreturn '<p>' + shlex.quote(x) + '</p>'")
        _proven(_scan({"app.py": src}), XSS)

    def test_pipes_quote_does_not_escape_html(self) -> None:
        src = _handler(_X + "import pipes\nreturn '<p>' + pipes.quote(x) + '</p>'")
        _proven(_scan({"app.py": src}), XSS)

    def test_re_escape_does_not_escape_html(self) -> None:
        src = _handler(_X + "import re\nreturn '<p>' + re.escape(x) + '</p>'")
        _proven(_scan({"app.py": src}), XSS)

    def test_local_identity_escape(self) -> None:
        src = _handler(_X + "return '<p>' + escape(x) + '</p>'", extra="def escape(s):\n    return s\n")
        _proven(_scan({"app.py": src}), XSS)

    def test_local_identity_clean(self) -> None:
        src = _handler(_X + "return '<p>' + clean(x) + '</p>'", extra="def clean(s):\n    return s\n")
        _proven(_scan({"app.py": src}), XSS)

    def test_make_response_shlex_quote(self) -> None:
        src = _FILES.replace("send_file,", "send_file, make_response,") + (
            '@app.route("/h")\n'
            "def handler():\n"
            "    x = request.args.get('x', '')\n"
            "    import shlex\n"
            "    return make_response('<p>' + shlex.quote(x))\n"
        )
        _proven(_scan({"app.py": src}), XSS)

    def test_urllib_quote_with_unsafe_safe_set(self) -> None:
        src = _handler(
            _X + "from urllib.parse import quote\nreturn '<p>' + quote(x, safe='<>/') + '</p>'"
        )
        _proven(_scan({"app.py": src}), XSS)

    # -- HTML escapes still sanitise -----------------------------------------

    @pytest.mark.parametrize(
        "imports, call",
        [
            ("import html\n", "html.escape(x)"),
            ("from html import escape\n", "escape(x)"),
            ("from html import escape as e\n", "e(x)"),
            ("import markupsafe\n", "markupsafe.escape(x)"),
            ("from markupsafe import escape\n", "escape(x)"),
            ("from markupsafe import Markup\n", "Markup.escape(x)"),
            ("from django.utils.html import escape\n", "escape(x)"),
            ("from django.utils.html import conditional_escape\n", "conditional_escape(x)"),
            ("import bleach\n", "bleach.clean(x)"),
            ("from urllib.parse import quote\n", "quote(x)"),
        ],
    )
    def test_html_escape_sanitises(self, imports: str, call: str) -> None:
        src = _handler(_X + f"return '<p>' + {call} + '</p>'", extra=imports)
        _not_proven(_scan({"app.py": src}), XSS)


# ---------------------------------------------------------------------------
# redteam-r001-01: an aliased allowlist mutated through the alias
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


class TestAllowlistAliasMutation:
    def test_module_alias_mutated_in_another_route(self) -> None:
        src = _URL + (
            "A2 = ALLOWED\n"
            "@app.route('/add')\n"
            "def add():\n"
            "    A2.add(request.args.get('h'))\n"
            "    return 'ok'\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _proven(_scan({"app.py": src}), SSRF)

    def test_local_alias_mutated_in_the_same_function(self) -> None:
        src = _URL + (
            "@app.route('/p')\n"
            "def proxy():\n"
            "    a2 = ALLOWED\n"
            "    a2.add(request.args.get('h'))\n" + _GUARD
        )
        _proven(_scan({"app.py": src}), SSRF)

    def test_alias_extended_with_augmented_assignment(self) -> None:
        src = _URL + (
            "A2 = ALLOWED\n"
            "@app.route('/add')\n"
            "def add():\n"
            "    global A2\n"
            "    A2 |= {request.args.get('h')}\n"
            "    return 'ok'\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _proven(_scan({"app.py": src}), SSRF)

    def test_allowlist_passed_to_a_function(self) -> None:
        src = _URL + (
            "def register(s, h):\n"
            "    s.add(h)\n"
            "@app.route('/add')\n"
            "def add():\n"
            "    register(ALLOWED, request.args.get('h'))\n"
            "    return 'ok'\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _proven(_scan({"app.py": src}), SSRF)

    def test_allowlist_stored_on_an_object(self) -> None:
        src = _URL + (
            "class Cfg:\n"
            "    pass\n"
            "cfg = Cfg()\n"
            "cfg.hosts = ALLOWED\n"
            "@app.route('/add')\n"
            "def add():\n"
            "    cfg.hosts.add(request.args.get('h'))\n"
            "    return 'ok'\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _proven(_scan({"app.py": src}), SSRF)

    # -- still constant --------------------------------------------------------

    def test_guard_with_unaliased_allowlist_is_safe(self) -> None:
        src = _URL + "@app.route('/p')\ndef proxy():\n" + _GUARD
        _not_proven(_scan({"app.py": src}), SSRF)

    def test_alias_never_mutated_is_safe(self) -> None:
        src = _URL + (
            "A2 = ALLOWED\n"
            "@app.route('/hosts')\n"
            "def hosts():\n"
            "    return ', '.join(sorted(A2))\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _not_proven(_scan({"app.py": src}), SSRF)

    def test_allowlist_read_by_builtins_is_safe(self) -> None:
        src = _URL + (
            "print(len(ALLOWED), sorted(ALLOWED), ', '.join(ALLOWED))\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _not_proven(_scan({"app.py": src}), SSRF)

    def test_tuple_allowlist_aliased_is_safe(self) -> None:
        # A tuple cannot be mutated through an alias.
        src = _URL.replace("{'api.example.com'}", "('api.example.com',)") + (
            "def show(s):\n"
            "    return s\n"
            "show(ALLOWED)\n"
            "@app.route('/p')\n"
            "def proxy():\n" + _GUARD
        )
        _not_proven(_scan({"app.py": src}), SSRF)


# ---------------------------------------------------------------------------
# redteam-py-01: lost evaluation is reported, never "ok"
# ---------------------------------------------------------------------------

_DEEP = "BIG = " + " + ".join(["'a'"] * 3000) + "\n"
_SHELL_ROUTE = (
    "import subprocess\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/run')\n"
    "def run():\n"
    "    subprocess.run('ls ' + request.args.get('x', ''), shell=True)\n"
    "    return 'ok'\n"
)


def _run_collecting(files: dict[str, str]) -> tuple[list[dict], BaseException | None]:
    findings: list[dict] = []
    raised: BaseException | None = None
    with tempfile.TemporaryDirectory() as d:
        for rel, src in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src)
        try:
            ASTAnalyzer(d, "python").run(findings.append)
        except Exception as exc:  # noqa: BLE001 — asserted on below
            raised = exc
    return findings, raised


class TestLostEvaluationIsReported:
    def test_recursion_limit_in_a_file_raises_after_the_walk(self) -> None:
        findings, raised = _run_collecting({"deep.py": _DEEP + _SHELL_ROUTE, "other.py": _SHELL_ROUTE})
        assert isinstance(raised, AnalysisIncomplete), raised
        assert "deep.py" in str(raised)
        # The rest of the tree was analysed and its findings were kept.
        _proven(findings, SHELL, rel="other.py")

    def test_incomplete_files_are_listed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            Path(d, "deep.py").write_text(_DEEP + _SHELL_ROUTE)
            analyzer = ASTAnalyzer(d, "python")
            with pytest.raises(AnalysisIncomplete):
                analyzer.run(lambda f: None)
            assert sorted({rel for rel, _ in analyzer.incomplete_files}) == ["deep.py"]

    def test_internal_error_mid_file_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import analyzers.ast_analyzer as aa

        original = aa._PythonSecurityVisitor.visit_Call

        def boom(self, node):  # noqa: ANN001
            if self._rel == "broken.py":
                raise ValueError("visitor bug")
            return original(self, node)

        monkeypatch.setattr(aa._PythonSecurityVisitor, "visit_Call", boom)
        findings, raised = _run_collecting({"broken.py": _SHELL_ROUTE, "other.py": _SHELL_ROUTE})
        assert isinstance(raised, AnalysisIncomplete), raised
        assert "broken.py" in str(raised)
        _proven(findings, SHELL, rel="other.py")

    def test_clean_tree_does_not_raise(self) -> None:
        findings, raised = _run_collecting({"app.py": _SHELL_ROUTE})
        assert raised is None
        _proven(findings, SHELL)

    def test_syntax_error_file_is_lost_evaluation(self) -> None:
        # Round 4 (D1', DE-03) supersedes the round-2 rule that a file Python
        # cannot parse "is not code the server runs": an in-scope .py file the
        # interpreter cannot parse was never evaluated, and a scan that says
        # complete must not hide it (a `match` statement under an old
        # interpreter is valid code). It is lost evaluation; the findings in
        # the rest of the tree are kept.
        findings, raised = _run_collecting({"py2.py": "print 'hello'\n", "app.py": _SHELL_ROUTE})
        assert raised is not None
        assert [name for name, _ in raised.files] == ["py2.py"]
        assert "syntax error at line 1" in raised.files[0][1]
        _proven(findings, SHELL)

    def test_engine_reports_injection_failed_and_keeps_findings(self) -> None:
        engine = Path(__file__).parent.parent / "engine.py"
        with tempfile.TemporaryDirectory() as d:
            Path(d, "deep.py").write_text(_DEEP + _SHELL_ROUTE)
            Path(d, "other.py").write_text(_SHELL_ROUTE)
            proc = subprocess.run(
                [sys.executable, str(engine)],
                input=json.dumps({"mode": "whitebox", "checks": ["injection"], "code_path": d}),
                capture_output=True,
                text=True,
                timeout=120,
            )
        assert proc.returncode == 0, proc.stderr
        objects = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
        statuses = {o["status"]["check"]: o["status"] for o in objects if isinstance(o.get("status"), dict)}
        injection = statuses["injection"]
        assert injection["state"] == "failed"
        assert injection["reason"] == "execution_error"
        assert "deep.py" in injection["detail"]
        ids = {o.get("id") for o in objects if "id" in o}
        assert SHELL in ids
        done = objects[-1]
        assert done["done"] is True and done["total"] == len([o for o in objects if "id" in o])
