"""Remediation regressions R-001, R-002/R-058 and R-006 (Python taint engine).

Every case is a decorated Flask or FastAPI handler written to a temporary
tree and run through ``ASTAnalyzer(code_path, "python").run(emit)``, which is
exactly how ``python/engine.py`` drives the analyzer for a scan. A finding the
engine BLOCKs under ``--fail-on high`` is a proven one: ``reachable`` is True
and it carries a ``taint_chain``. "Not proven" means the finding is absent, or
present without a chain (the engine reports it below the gate).

R-001: the ``urlparse(u).netloc not in ALLOWED`` guard must sanitise only the
value it checked. A rebind of the guarded name after the parse, a stale parse
binding, a guard in a branch that does not dominate the sink, or an allowlist
that is not a collection of string constants must leave the flow proven.

R-002 / R-058: a sanitiser counts only for the sink class it neutralises,
inline and across the one-hop helper (same file or another file). Escaping is
an HTML sanitiser only; ``basename``/``secure_filename`` a path sanitiser only;
URL-encoding is not an SSRF or redirect guard; ``shlex.quote`` is a shell
sanitiser only.

R-006: ``send_from_directory(<trusted dir>, <request filename>)`` is safe
(Werkzeug ``safe_join``), and a join whose request-carrying components are
reduced to one path component (``basename``/``secure_filename``) is contained.
Unsafe joins, ``send_file(<request value>)`` and a request-controlled
``send_from_directory`` directory stay proven.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer


def _scan(files: dict[str, str]) -> list[dict]:
    """Run the analyzer over a temporary tree holding ``files`` exactly as the
    engine does (``ASTAnalyzer(code_path, "python").run(emit)``)."""
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        for rel, src in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(src)
        ASTAnalyzer(d, "python").run(findings.append)
    return findings


def _of(findings: list[dict], rule: str, line: int | None = None, rel: str = "app.py"):
    return [
        f
        for f in findings
        if f["id"] == rule and (line is None or f["line"] == f"{rel}:{line}")
    ]


def _proven(findings: list[dict], rule: str, line: int | None = None, rel: str = "app.py"):
    found = [
        f for f in _of(findings, rule, line, rel) if f.get("reachable") is True and f.get("taint_chain")
    ]
    assert found, f"expected a proven {rule} at {rel}:{line}; got {_of(findings, rule, None, rel)}"
    return found[0]


def _not_proven(findings: list[dict], rule: str, rel: str = "app.py") -> None:
    proven = [
        f for f in _of(findings, rule, None, rel) if f.get("reachable") is True or f.get("taint_chain")
    ]
    assert not proven, f"{rule} must not be proven: {proven}"


SSRF = "SEC-PY_SSRF"
REDIRECT = "SEC-PY_OPEN_REDIRECT"
SHELL = "SEC-PY_SUBPROCESS_SHELL"
SQL = "SEC-PY_SQL_INJECTION"
PATH = "SEC-PY_PATH_TRAVERSAL"
XSS = "SEC-PY_XSS_HTML_SINK"


# ---------------------------------------------------------------------------
# R-001: netloc host-allowlist guard sanitises only the value it checked
# ---------------------------------------------------------------------------

_FLASK_URL = (
    "from urllib.parse import urlparse\n"  # 1
    "import requests\n"  # 2
    "from flask import Flask, request, abort, redirect\n"  # 3
    "app = Flask(__name__)\n"  # 4
    'ALLOWED = {"api.example.com", "cdn.example.com"}\n'  # 5
)


class TestR001NetlocGuardIsValueBound:
    def test_rebind_from_request_after_guard_is_proven(self) -> None:
        # The CTO reproduction (fx/r001): guard on `target`, then `target`
        # is re-read from another query parameter.
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    target = request.args.get("url", "")\n'  # 8
            "    if urlparse(target).netloc not in ALLOWED:\n"  # 9
            "        abort(400)\n"  # 10
            '    target = request.args.get("fallback", target)\n'  # 11
            "    return requests.get(target, timeout=5).text\n"  # 12
        )
        _proven(_scan({"app.py": src}), SSRF, 12)

    def test_stale_parse_is_proven(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    target = request.args["url"]\n'  # 8
            "    parsed = urlparse(target)\n"  # 9
            '    target = request.args["mirror"]\n'  # 10
            "    if parsed.netloc not in ALLOWED:\n"  # 11
            "        abort(400)\n"  # 12
            "    return requests.get(target).text\n"  # 13
        )
        _proven(_scan({"app.py": src}), SSRF, 13)

    def test_parse_binding_rebound_after_guard_is_proven(self) -> None:
        # The guard checked the parse of `other`; the parse of `target` bound
        # to the same name after the guard was never checked, although it is
        # the binding live at the sink.
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    other = request.args["other"]\n'  # 8
            '    target = request.args["url"]\n'  # 9
            "    parsed = urlparse(other)\n"  # 10
            "    if parsed.netloc not in ALLOWED:\n"  # 11
            "        abort(400)\n"  # 12
            "    parsed = urlparse(target)\n"  # 13
            '    app.logger.info("fetching %s", parsed.path)\n'  # 14
            "    return requests.get(target).text\n"  # 15
        )
        _proven(_scan({"app.py": src}), SSRF, 15)

    def test_allowlist_holding_request_data_is_proven(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    target = request.args["url"]\n'  # 8
            '    if urlparse(target).netloc not in {request.args.get("host")}:\n'  # 9
            "        abort(400)\n"  # 10
            "    return requests.get(target).text\n"  # 11
        )
        _proven(_scan({"app.py": src}), SSRF, 11)

    def test_allowlist_with_non_constant_member_is_proven(self) -> None:
        src = (
            "import os\n"  # 1
            "from urllib.parse import urlparse\n"  # 2
            "import requests\n"  # 3
            "from flask import Flask, request, abort\n"  # 4
            "app = Flask(__name__)\n"  # 5
            'HOSTS = ["api.example.com", os.environ.get("EXTRA_HOST")]\n'  # 6
            '@app.route("/proxy")\n'  # 7
            "def proxy():\n"  # 8
            '    target = request.args["url"]\n'  # 9
            "    if urlparse(target).netloc not in HOSTS:\n"  # 10
            "        abort(400)\n"  # 11
            "    return requests.get(target).text\n"  # 12
        )
        _proven(_scan({"app.py": src}), SSRF, 12)

    def test_allowlist_mutated_with_request_data_is_proven(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    ALLOWED.add(request.args["host"])\n'  # 8
            '    target = request.args["url"]\n'  # 9
            "    if urlparse(target).netloc not in ALLOWED:\n"  # 10
            "        abort(400)\n"  # 11
            "    return requests.get(target).text\n"  # 12
        )
        _proven(_scan({"app.py": src}), SSRF, 12)

    def test_guard_in_non_dominating_branch_is_proven(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    target = request.args["url"]\n'  # 8
            '    if request.args.get("strict"):\n'  # 9
            "        if urlparse(target).netloc not in ALLOWED:\n"  # 10
            "            abort(400)\n"  # 11
            "    return requests.get(target).text\n"  # 12
        )
        _proven(_scan({"app.py": src}), SSRF, 12)

    def test_rebind_in_loop_after_sink_is_proven(self) -> None:
        # The second iteration requests a URL the guard never saw.
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'  # 6
            "def proxy():\n"  # 7
            '    target = request.args["url"]\n'  # 8
            "    if urlparse(target).netloc not in ALLOWED:\n"  # 9
            "        abort(400)\n"  # 10
            "    out = []\n"  # 11
            '    for alt in request.args.getlist("alt"):\n'  # 12
            "        out.append(requests.get(target).text)\n"  # 13
            "        target = alt\n"  # 14
            '    return "".join(out)\n'  # 15
        )
        _proven(_scan({"app.py": src}), SSRF, 13)

    def test_redirect_rebind_after_guard_is_proven(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/go")\n'  # 6
            "def go():\n"  # 7
            '    nxt = request.args.get("next", "/")\n'  # 8
            "    if urlparse(nxt).netloc not in ALLOWED:\n"  # 9
            '        return redirect("/")\n'  # 10
            '    nxt = request.args.get("fallback", nxt)\n'  # 11
            "    return redirect(nxt)\n"  # 12
        )
        _proven(_scan({"app.py": src}), REDIRECT, 12)

    def test_fastapi_param_rebind_after_guard_is_proven(self) -> None:
        src = (
            "from urllib.parse import urlparse\n"  # 1
            "import httpx\n"  # 2
            "from fastapi import FastAPI, HTTPException\n"  # 3
            "app = FastAPI()\n"  # 4
            'ALLOWED = {"api.example.com"}\n'  # 5
            '@app.get("/proxy")\n'  # 6
            "def proxy(url: str, override: str = \"\"):\n"  # 7
            "    if urlparse(url).netloc not in ALLOWED:\n"  # 8
            "        raise HTTPException(status_code=400)\n"  # 9
            "    if override:\n"  # 10
            "        url = override\n"  # 11
            "    return httpx.get(url).text\n"  # 12
        )
        _proven(_scan({"app.py": src}), SSRF, 12)

    # -- the genuinely safe shapes stay safe ----------------------------------

    def test_dominating_guard_on_unchanged_value_is_safe(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'
            "def proxy():\n"
            '    target = request.args.get("url", "")\n'
            "    if urlparse(target).netloc not in ALLOWED:\n"
            "        abort(400)\n"
            "    return requests.get(target, timeout=5).text\n"
        )
        assert not _of(_scan({"app.py": src}), SSRF)

    def test_bound_parse_guard_with_or_is_safe(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'
            "def proxy():\n"
            '    target = request.args["url"]\n'
            "    p = urlparse(target)\n"
            '    if p.scheme != "https" or p.netloc not in ALLOWED:\n'
            '        return "no", 400\n'
            "    return requests.get(target).text\n"
        )
        assert not _of(_scan({"app.py": src}), SSRF)

    def test_redirect_guard_is_safe(self) -> None:
        src = _FLASK_URL + (
            '@app.route("/go")\n'
            "def go():\n"
            '    nxt = request.args.get("next", "/")\n'
            "    if urlparse(nxt).netloc not in ALLOWED:\n"
            '        return redirect("/")\n'
            "    return redirect(nxt)\n"
        )
        assert not _of(_scan({"app.py": src}), REDIRECT)

    def test_fastapi_guard_is_safe(self) -> None:
        src = (
            "from urllib.parse import urlparse\n"
            "import httpx\n"
            "from fastapi import FastAPI, HTTPException\n"
            "app = FastAPI()\n"
            'ALLOWED = ("api.example.com",)\n'
            '@app.get("/proxy")\n'
            "def proxy(url: str):\n"
            "    if urlparse(url).netloc not in ALLOWED:\n"
            "        raise HTTPException(status_code=400)\n"
            "    return httpx.get(url).text\n"
        )
        assert not _of(_scan({"app.py": src}), SSRF)

    def test_rebind_before_the_parse_is_safe(self) -> None:
        # Stores BEFORE the parse do not matter: the guard checks whatever
        # value the name holds when it is parsed.
        src = _FLASK_URL + (
            '@app.route("/proxy")\n'
            "def proxy():\n"
            '    target = request.args.get("url")\n'
            "    target = target.strip()\n"
            "    if urlparse(target).netloc not in ALLOWED:\n"
            "        abort(400)\n"
            "    return requests.get(target).text\n"
        )
        assert not _of(_scan({"app.py": src}), SSRF)


# ---------------------------------------------------------------------------
# R-002 / R-058: sanitisers are typed by sink class
# ---------------------------------------------------------------------------

_HELPERS = (
    "import os\n"  # 1
    "import html\n"  # 2
    "import shlex\n"  # 3
    "import sqlite3\n"  # 4
    "import subprocess\n"  # 5
    "from urllib.parse import quote, urlparse\n"  # 6
    "import requests\n"  # 7
    "from flask import Flask, request, redirect\n"  # 8
    "from markupsafe import Markup\n"  # 9
    "from werkzeug.utils import secure_filename\n"  # 10
    "app = Flask(__name__)\n"  # 11
    'BASE = "/srv/docs"\n'  # 12
    'ALLOWED = {"api.example.com"}\n'  # 13
    "def run_tool(name):\n"  # 14
    '    return subprocess.run("tool --input " + name, shell=True, capture_output=True).stdout\n'  # 15
    "def fetch_doc(name):\n"  # 16
    "    return open(os.path.join(BASE, name)).read()\n"  # 17
    "def lookup(name):\n"  # 18
    '    db = sqlite3.connect("app.db")\n'  # 19
    "    return db.execute(\"SELECT * FROM t WHERE n = '\" + name + \"'\").fetchall()\n"  # 20
    "def fetch(u):\n"  # 21
    "    return requests.get(u).text\n"  # 22
    "def fetch_https(u):\n"  # 23
    '    return requests.get("https://" + u).text\n'  # 24
    "def render(s):\n"  # 25
    '    return Markup("<b>" + s + "</b>")\n'  # 26
    "def go(t):\n"  # 27
    "    return redirect(t)\n"  # 28
)
# `@app.route` is line 29, `def handler():` line 30, the body from line 31.


def _route(body: str, path: str = "/h") -> str:
    return _HELPERS + f'@app.route("{path}")\n' + "def handler():\n" + body


class TestR002HelperHopSanitisersAreSinkTyped:
    def test_basename_does_not_sanitise_shell_helper(self) -> None:
        # The CTO reproduction (fx/r002).
        f = _proven(_scan({"app.py": _route('    return run_tool(os.path.basename(request.args["f"]))\n')}), SHELL, 15)
        assert f["taint_chain"]

    def test_basename_bound_local_does_not_sanitise_sql_helper(self) -> None:
        # basename keeps `'`, so the quoted SQL context is still open.
        _proven(
            _scan({"app.py": _route('    t = os.path.basename(request.args["n"])\n    return lookup(t)\n')}),
            SQL,
            20,
        )

    def test_html_escape_does_not_sanitise_shell_helper(self) -> None:
        _proven(_scan({"app.py": _route('    return run_tool(html.escape(request.args["t"]))\n')}), SHELL, 15)

    def test_html_escape_local_does_not_sanitise_shell_helper(self) -> None:
        _proven(
            _scan({"app.py": _route('    t = html.escape(request.args["t"])\n    return run_tool(t)\n')}),
            SHELL,
            15,
        )

    def test_html_escape_does_not_sanitise_path_helper(self) -> None:
        _proven(_scan({"app.py": _route('    return fetch_doc(html.escape(request.args["d"]))\n')}), PATH, 17)

    def test_url_quote_does_not_sanitise_ssrf_helper(self) -> None:
        _proven(_scan({"app.py": _route('    return fetch(quote(request.args["u"]))\n')}), SSRF, 22)

    def test_html_escape_does_not_sanitise_redirect_helper(self) -> None:
        _proven(_scan({"app.py": _route('    return go(html.escape(request.args["next"]))\n')}), REDIRECT, 28)

    def test_netloc_guard_does_not_sanitise_shell_helper(self) -> None:
        src = _route(
            '    u = request.args["u"]\n'
            "    if urlparse(u).netloc not in ALLOWED:\n"
            '        return "no", 400\n'
            "    return run_tool(u)\n"
        )
        _proven(_scan({"app.py": src}), SHELL, 15)

    def test_netloc_guard_does_not_cover_helper_that_prefixes_scheme(self) -> None:
        # `"https://" + u` can name another host than u's netloc
        # (`evil.com://api.example.com/x` has netloc api.example.com).
        src = _route(
            '    u = request.args["u"]\n'
            "    if urlparse(u).netloc not in ALLOWED:\n"
            '        return "no", 400\n'
            "    return fetch_https(u)\n"
        )
        _proven(_scan({"app.py": src}), SSRF, 24)

    def test_cross_file_basename_does_not_sanitise_shell_helper(self) -> None:
        helpers = (
            "import subprocess\n"
            "def run_tool(name):\n"
            '    return subprocess.run("tool --input " + name, shell=True).stdout\n'
        )
        views = (
            "import os\n"
            "from flask import Flask, request\n"
            "from tools import run_tool\n"
            "app = Flask(__name__)\n"
            '@app.route("/tool")\n'
            "def tool():\n"
            '    return run_tool(os.path.basename(request.args["f"]))\n'
        )
        _proven(_scan({"tools.py": helpers, "app.py": views}), SHELL, 3, rel="tools.py")

    def test_cross_file_html_escape_does_not_sanitise_sql_helper(self) -> None:
        helpers = (
            "import sqlite3\n"
            "def lookup(name):\n"
            '    db = sqlite3.connect("x.db")\n'
            "    return db.execute(\"SELECT * FROM t WHERE id = \" + name).fetchall()\n"
        )
        views = (
            "import html\n"
            "from flask import Flask, request\n"
            "from repo import lookup\n"
            "app = Flask(__name__)\n"
            '@app.route("/l")\n'
            "def l():\n"
            '    return str(lookup(html.escape(request.args["id"])))\n'
        )
        _proven(_scan({"repo.py": helpers, "app.py": views}), SQL, 4, rel="repo.py")

    # -- same-class sanitisers across the hop stay honoured -------------------

    def test_shlex_quote_sanitises_shell_helper(self) -> None:
        findings = _scan({"app.py": _route('    return run_tool(shlex.quote(request.args["t"]))\n')})
        _not_proven(findings, SHELL)

    def test_basename_sanitises_path_helper(self) -> None:
        findings = _scan({"app.py": _route('    return fetch_doc(os.path.basename(request.args["d"]))\n')})
        _not_proven(findings, PATH)

    def test_secure_filename_sanitises_path_helper(self) -> None:
        findings = _scan({"app.py": _route('    return fetch_doc(secure_filename(request.args["d"]))\n')})
        _not_proven(findings, PATH)

    def test_html_escape_sanitises_html_helper(self) -> None:
        findings = _scan({"app.py": _route('    return render(html.escape(request.args["n"]))\n')})
        _not_proven(findings, XSS)

    def test_netloc_guard_sanitises_ssrf_helper(self) -> None:
        src = _route(
            '    u = request.args["u"]\n'
            "    if urlparse(u).netloc not in ALLOWED:\n"
            '        return "no", 400\n'
            "    return fetch(u)\n"
        )
        _not_proven(_scan({"app.py": src}), SSRF)

    def test_unsanitised_hops_stay_proven(self) -> None:
        findings = _scan({"app.py": _route('    return run_tool(request.args["t"])\n')})
        _proven(findings, SHELL, 15)

    # -- qa-engine-03: `_is_shell_quoted` is resolved by module ----------------

    _QUOTE_HDR = (
        "import subprocess\n"  # 1
        "import urllib.parse\n"  # 2
        "import helpers\n"  # 3
        "from flask import Flask, request\n"  # 4
        "app = Flask(__name__)\n"  # 5
        "def run_tool(name):\n"  # 6
        '    return subprocess.run("tool --input " + name, shell=True, capture_output=True).stdout\n'  # 7
        '@app.route("/x")\n'  # 8
        "def x():\n"  # 9
    )

    def test_project_module_quote_does_not_sanitise_shell_helper(self) -> None:
        # `helpers.quote` is a `.quote` attribute but not shlex's.
        files = {
            "app.py": self._QUOTE_HDR + '    return run_tool(helpers.quote(request.args["f"]))\n',
            "helpers.py": "def quote(s):\n    return s\n",
        }
        _proven(_scan(files), SHELL, 7)

    def test_urllib_quote_with_shell_safe_set_does_not_sanitise_shell_helper(self) -> None:
        src = self._QUOTE_HDR + (
            "    return run_tool(urllib.parse.quote(request.args[\"f\"], safe=';|&$() '))\n"
        )
        _proven(_scan({"app.py": src}), SHELL, 7)

    def test_shlex_module_quote_sanitises_shell_helper_control(self) -> None:
        src = self._QUOTE_HDR.replace("import helpers\n", "import shlex\n") + (
            '    return run_tool(shlex.quote(request.args["f"]))\n'
        )
        _not_proven(_scan({"app.py": src}), SHELL)


class TestR058InlineEscapingIsNotAUrlOrPathGuard:
    def test_requests_get_html_escape_is_proven(self) -> None:
        src = _route('    return requests.get(html.escape(request.args["u"])).text\n')
        _proven(_scan({"app.py": src}), SSRF, 31)

    def test_redirect_url_quote_is_proven(self) -> None:
        # quote("//evil.com") == "//evil.com"
        src = _route('    return redirect(quote(request.args["next"]))\n')
        _proven(_scan({"app.py": src}), REDIRECT, 31)

    def test_redirect_html_escape_is_proven(self) -> None:
        src = _route('    return redirect(html.escape(request.args["next"]))\n')
        _proven(_scan({"app.py": src}), REDIRECT, 31)

    def test_redirect_escaped_local_is_proven(self) -> None:
        src = _route('    nxt = quote(request.args["next"])\n    return redirect(nxt)\n')
        _proven(_scan({"app.py": src}), REDIRECT, 32)

    def test_open_html_escape_join_is_proven(self) -> None:
        src = _route('    return open(os.path.join(BASE, html.escape(request.args["d"]))).read()\n')
        _proven(_scan({"app.py": src}), PATH, 31)

    def test_shell_inline_escape_stays_proven(self) -> None:
        src = _route(
            '    return subprocess.run("tool " + html.escape(request.args["t"]), shell=True).stdout\n'
        )
        _proven(_scan({"app.py": src}), SHELL, 31)

    def test_inline_escape_still_sanitises_html_sink(self) -> None:
        src = _route('    return Markup("<b>" + html.escape(request.args["n"]) + "</b>")\n')
        _not_proven(_scan({"app.py": src}), XSS)


# ---------------------------------------------------------------------------
# R-006: send_from_directory and single-component containment
# ---------------------------------------------------------------------------

_FLASK_FILES = (
    "import os\n"  # 1
    "from flask import Flask, request, send_file, send_from_directory\n"  # 2
    "from werkzeug.utils import secure_filename\n"  # 3
    "app = Flask(__name__)\n"  # 4
    'UPLOADS = "/srv/uploads"\n'  # 5
    'ROOT = "/srv/reports"\n'  # 6
)


class TestR006SafeDownloadIdiomsDoNotBlock:
    def test_send_from_directory_constant_dir_path_converter(self) -> None:
        # The CTO reproduction (fx/r006).
        src = _FLASK_FILES + (
            '@app.route("/files/<path:filename>")\n'
            "def download(filename):\n"
            "    return send_from_directory(UPLOADS, filename)\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_literal_dir_default_converter(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/docs/<doc>")\n'
            "def docs(doc):\n"
            '    return send_from_directory("documents", doc)\n'
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_query_filename(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/static-file")\n'
            "def static_file():\n"
            '    return send_from_directory("static", request.args.get("f"))\n'
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_from_directory_keyword_form(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/k/<path:name>")\n'
            "def k(name):\n"
            "    return send_from_directory(directory=UPLOADS, path=name)\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_file_join_basename(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/report/<name>")\n'
            "def report(name):\n"
            "    return send_file(os.path.join(ROOT, os.path.basename(name)))\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_file_join_basename_local(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/report/<name>")\n'
            "def report(name):\n"
            "    safe = os.path.basename(name)\n"
            "    return send_file(os.path.join(ROOT, safe))\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_send_file_join_secure_filename(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/report/<name>")\n'
            "def report(name):\n"
            "    return send_file(os.path.join(ROOT, secure_filename(name)))\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_open_join_basename_query(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/read")\n'
            "def read():\n"
            '    return open(os.path.join(ROOT, os.path.basename(request.args["n"]))).read()\n'
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_upload_save_secure_filename(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/upload", methods=["POST"])\n'
            "def upload():\n"
            '    f = request.files["file"]\n'
            "    f.save(os.path.join(UPLOADS, secure_filename(f.filename)))\n"
            '    return "ok"\n'
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_fastapi_file_response_join_basename(self) -> None:
        src = (
            "import os\n"
            "from fastapi import FastAPI\n"
            "from fastapi.responses import FileResponse\n"
            "app = FastAPI()\n"
            'ROOT = "/srv/reports"\n'
            '@app.get("/r/{name}")\n'
            "def r(name: str):\n"
            "    return FileResponse(os.path.join(ROOT, os.path.basename(name)))\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    # -- unsafe constructions stay proven -------------------------------------

    def test_open_join_route_param_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/raw/<path:name>")\n'  # 7
            "def raw(name):\n"  # 8
            "    return open(os.path.join(ROOT, name)).read()\n"  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_send_file_request_value_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/sf")\n'  # 7
            "def sf():\n"  # 8
            '    return send_file(request.args["f"])\n'  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_send_from_directory_request_dir_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/sd")\n'  # 7
            "def sd():\n"  # 8
            '    return send_from_directory(request.args["d"], "report.pdf")\n'  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_send_from_directory_route_dir_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/sd/<path:folder>/<name>")\n'  # 7
            "def sd(folder, name):\n"  # 8
            "    return send_from_directory(folder, name)\n"  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_send_from_directory_dir_joined_with_request_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/sj/<name>")\n'  # 7
            "def sj(name):\n"  # 8
            '    return send_from_directory(os.path.join(UPLOADS, request.args["sub"]), name)\n'  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_join_request_base_with_basename_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/jb")\n'  # 7
            "def jb():\n"  # 8
            '    return send_file(os.path.join(request.args["d"], os.path.basename(request.args["f"])))\n'  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_join_uncontained_middle_component_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/jm/<sub>/<name>")\n'  # 7
            "def jm(sub, name):\n"  # 8
            "    return send_file(os.path.join(ROOT, sub, os.path.basename(name)))\n"  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 9)

    def test_basename_on_one_branch_only_is_proven(self) -> None:
        src = _FLASK_FILES + (
            '@app.route("/bb/<path:name>")\n'  # 7
            "def bb(name):\n"  # 8
            '    if request.args.get("flat"):\n'  # 9
            "        safe = name\n"  # 10
            "    else:\n"  # 11
            "        safe = os.path.basename(name)\n"  # 12
            "    return send_file(os.path.join(ROOT, safe))\n"  # 13
        )
        _proven(_scan({"app.py": src}), PATH, 13)


# ---------------------------------------------------------------------------
# Same root cause, adjacent shapes
# ---------------------------------------------------------------------------


class TestR001MembershipGuardIsValueBound:
    """The `if x not in ALLOWED: abort()` guard had the R-001 defect too: it
    was honoured by name, so a rebind after it, or an allowlist holding
    request data, sanitised whatever reached the sink."""

    _SRC = (
        "from flask import Flask, request, redirect, abort\n"  # 1
        "app = Flask(__name__)\n"  # 2
        'SAFE = {"/home", "/profile"}\n'  # 3
    )

    def test_rebind_after_membership_guard_is_proven(self) -> None:
        src = self._SRC + (
            '@app.route("/go")\n'  # 4
            "def go():\n"  # 5
            '    nxt = request.args.get("next", "/home")\n'  # 6
            "    if nxt not in SAFE:\n"  # 7
            "        abort(400)\n"  # 8
            '    nxt = request.args.get("fallback", nxt)\n'  # 9
            "    return redirect(nxt)\n"  # 10
        )
        _proven(_scan({"app.py": src}), REDIRECT, 10)

    def test_membership_allowlist_of_request_data_is_proven(self) -> None:
        src = self._SRC + (
            '@app.route("/go")\n'  # 4
            "def go():\n"  # 5
            '    nxt = request.args.get("next", "/home")\n'  # 6
            '    if nxt not in [request.args.get("allowed")]:\n'  # 7
            "        abort(400)\n"  # 8
            "    return redirect(nxt)\n"  # 9
        )
        _proven(_scan({"app.py": src}), REDIRECT, 9)

    def test_membership_guard_on_unchanged_value_is_safe(self) -> None:
        src = self._SRC + (
            '@app.route("/go")\n'
            "def go():\n"
            '    nxt = request.args.get("next", "/home")\n'
            "    if nxt not in SAFE:\n"
            "        abort(400)\n"
            "    return redirect(nxt)\n"
        )
        assert not _of(_scan({"app.py": src}), REDIRECT)


class TestR001GuardThenRebindBeforeHelperCall:
    def test_caller_rebinds_after_netloc_guard_is_proven(self) -> None:
        src = _route(
            '    u = request.args["u"]\n'
            "    if urlparse(u).netloc not in ALLOWED:\n"
            '        return "no", 400\n'
            '    u = request.args.get("mirror", u)\n'
            "    return fetch(u)\n"
        )
        _proven(_scan({"app.py": src}), SSRF, 22)


class TestR058RedirectToAFixedPathStaysSafe:
    """Escaping is no redirect sanitiser, but a target that starts with a
    literal same-origin path cannot leave the site whatever follows it."""

    def test_fixed_path_with_quoted_query_is_safe(self) -> None:
        src = _route('    return redirect("/search?q=" + quote(request.args["q"]))\n')
        assert not _of(_scan({"app.py": src}), REDIRECT, 31)

    def test_fixed_path_fstring_is_safe(self) -> None:
        src = _route('    return redirect(f"/search?q={quote(request.args[\'q\'])}")\n')
        assert not _of(_scan({"app.py": src}), REDIRECT, 31)

    def test_fixed_host_prefix_is_safe(self) -> None:
        src = _route('    return redirect("https://www.example.com/p/" + request.args["p"])\n')
        assert not _of(_scan({"app.py": src}), REDIRECT, 31)

    def test_bare_slash_prefix_is_proven(self) -> None:
        # quote("/evil.com") keeps the slash: "/" + it is "//evil.com".
        src = _route('    return redirect("/" + quote(request.args["p"]))\n')
        _proven(_scan({"app.py": src}), REDIRECT, 31)

    def test_slash_backslash_prefix_is_proven(self) -> None:
        src = _route('    return redirect("/\\\\" + request.args["p"])\n')
        _proven(_scan({"app.py": src}), REDIRECT, 31)


class TestR006PathContainmentAcrossTheHop:
    def test_caller_contained_join_is_not_proven(self) -> None:
        src = (
            "import os\n"
            "from flask import Flask, request, send_file\n"
            "app = Flask(__name__)\n"
            'ROOT = "/srv/reports"\n'
            "def serve(p):\n"
            "    return send_file(p)\n"
            '@app.route("/r")\n'
            "def r():\n"
            '    return serve(os.path.join(ROOT, os.path.basename(request.args["n"])))\n'
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_caller_uncontained_join_is_proven(self) -> None:
        src = (
            "import os\n"  # 1
            "from flask import Flask, request, send_file\n"  # 2
            "app = Flask(__name__)\n"  # 3
            'ROOT = "/srv/reports"\n'  # 4
            "def serve(p):\n"  # 5
            "    return send_file(p)\n"  # 6
            '@app.route("/r")\n'  # 7
            "def r():\n"  # 8
            '    return serve(os.path.join(ROOT, request.args["n"]))\n'  # 9
        )
        _proven(_scan({"app.py": src}), PATH, 6)


class TestR006PathlibJoins:
    _SRC = (
        "from pathlib import Path\n"  # 1
        "from flask import Flask, request, send_file\n"  # 2
        "from werkzeug.utils import secure_filename\n"  # 3
        "app = Flask(__name__)\n"  # 4
        'ROOT = "/srv/reports"\n'  # 5
    )

    def test_pathlib_div_secure_filename_is_not_proven(self) -> None:
        src = self._SRC + (
            '@app.route("/p/<name>")\n'
            "def p(name):\n"
            "    return send_file(Path(ROOT) / secure_filename(name))\n"
        )
        _not_proven(_scan({"app.py": src}), PATH)

    def test_pathlib_div_raw_route_param_is_proven(self) -> None:
        src = self._SRC + (
            '@app.route("/p/<path:name>")\n'  # 6
            "def p(name):\n"  # 7
            "    return send_file(Path(ROOT) / name)\n"  # 8
        )
        _proven(_scan({"app.py": src}), PATH, 8)

    def test_pathlib_request_base_is_proven(self) -> None:
        src = self._SRC + (
            '@app.route("/p")\n'  # 6
            "def p():\n"  # 7
            '    return send_file(Path(request.args["d"]) / secure_filename(request.args["f"]))\n'  # 8
        )
        _proven(_scan({"app.py": src}), PATH, 8)


class TestR001MembershipAttributeMembers:
    def test_attribute_of_self_is_not_a_constant_member(self) -> None:
        src = (
            "from flask import request, redirect, abort\n"  # 1
            "from flask.views import MethodView\n"  # 2
            "class Go(MethodView):\n"  # 3
            "    def get(self):\n"  # 4
            '        self.extra = request.args.get("extra")\n'  # 5
            '        nxt = request.args.get("next", "/")\n'  # 6
            '        if nxt not in ("/home", self.extra):\n'  # 7
            "            abort(400)\n"  # 8
            "        return redirect(nxt)\n"  # 9
        )
        _proven(_scan({"app.py": src}), REDIRECT, 9)
