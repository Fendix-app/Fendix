"""Integration test: route binding attaches to a reachable taint finding."""
from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import (
    ASTAnalyzer,
    route_param_source_names,
    route_param_sources,
)
from analyzers.route_extractor import extract_routes


def _scan(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        for name, content in files.items():
            p = Path(d) / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        findings: list[dict] = []
        ASTAnalyzer(d).run(findings.append)
        return findings


def test_flask_sqli_gets_route_binding():
    app = '''
from flask import Flask, request
import sqlite3
app = Flask(__name__)

@app.route("/users", methods=["GET"])
def list_users():
    uid = request.args.get("id")
    q = "SELECT * FROM users WHERE id = " + uid
    conn = sqlite3.connect("db")
    conn.cursor().execute(q)
'''
    findings = _scan({"app.py": app})
    sqli = [f for f in findings if f.get("reachable") and "route" in f]
    assert sqli, f"expected a reachable finding with a bound route; got {findings}"
    route = sqli[0]["route"]
    assert route["pattern"] == "/users"
    assert route["method"] == "GET"
    assert route["handler"] == "list_users"


def test_django_cross_file_route_binding():
    urls = '''
from django.urls import path
from . import views
urlpatterns = [path("orders/<int:oid>", views.get_order)]
'''
    views = '''
from django.db import connection
def get_order(request, oid):
    raw = request.GET.get("q")
    sql = "SELECT * FROM orders WHERE name = '" + raw + "'"
    connection.cursor().execute(sql)
'''
    findings = _scan({"urls.py": urls, "views.py": views})
    bound = [f for f in findings if "route" in f]
    assert bound, f"expected a route-bound finding across files; got {findings}"
    assert bound[0]["route"]["pattern"] == "orders/<int:oid>"
    assert bound[0]["route"]["handler"] == "views.get_order"


def test_no_route_when_not_a_handler():
    src = '''
from flask import request
def helper():
    x = request.args.get("id")
    __import__("os").system("echo " + x)
'''
    findings = _scan({"util.py": src})
    # A reachable finding may exist, but with no route (helper isn't a handler).
    for f in findings:
        assert "route" not in f, f"non-handler finding must not be route-bound: {f}"


# ---------------------------------------------------------------------------
# Task 3.1: route-handler parameters are request sources
# ---------------------------------------------------------------------------
#
# A handler's parameters carry request data (FastAPI query/path/body params,
# Flask and Django URL variables) without any `request.` expression in sight.
# They count as sources only when the function is a route handler bound to
# THIS file, and never for framework-injected values: `self`, a leading
# `request`/`req`, a Request/Response/... annotation, a Depends/Security
# dependency (Review Focus 2, R-pf27), or a value the framework coerces to a
# non-string scalar (R-pf33).


def _rule(findings: list[dict], rule: str) -> list[dict]:
    return [f for f in findings if f["rule_id"] == f"python.ast/{rule}"]


def _one(files: dict[str, str], rule: str = "PY_SQL_INJECTION") -> dict:
    found = _rule(_scan(files), rule)
    assert len(found) == 1, found
    return found[0]


def _assert_proven_from(f: dict, name: str) -> None:
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0]["expr"] == name, f["taint_chain"]


def _assert_unproven(f: dict) -> None:
    assert f.get("reachable") is not True, f
    assert "taint_chain" not in f, f


def _fastapi_sqli(params: str, prelude: str = "") -> str:
    return (
        "import sqlite3\n"
        "import uuid\n"
        "import datetime\n"
        "from datetime import date, time, timedelta\n"
        "from decimal import Decimal\n"
        "from typing import Annotated, Optional, Union\n"
        "from uuid import UUID\n"
        "from fastapi import APIRouter, Depends, Query, Security\n"
        "from pydantic import BaseModel\n"
        "router = APIRouter()\n"
        "class Item(BaseModel):\n"
        "    name: str\n"
        f"{prelude}"
        '@router.get("/u")\n'
        f"def h({params}):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        "    cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )


def test_fastapi_query_param_sqli_is_reachable():
    src = _fastapi_sqli("name: str = Query(...)")
    f = _one({"app.py": src})
    _assert_proven_from(f, "name")
    # The source link sits on the handler's `def` line.
    def_line = src.splitlines().index("def h(name: str = Query(...)):") + 1
    assert f["taint_chain"][0] == {"file": "app.py", "line": def_line, "expr": "name"}
    assert f["route"]["pattern"] == "/u"


def test_fastapi_annotated_query_param_is_reachable():
    f = _one({"app.py": _fastapi_sqli('name: Annotated[str, Query()] = ""')})
    _assert_proven_from(f, "name")


def test_flask_url_param_is_reachable():
    src = (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/u/<name>")\n'
        "def h(name):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        "    cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )
    f = _one({"app.py": src})
    _assert_proven_from(f, "name")
    assert f["route"]["pattern"] == "/u/<name>"


_DJANGO_VIEW = (
    "from django.db import connection\n"
    "def view(request, slug):\n"
    "    connection.cursor().execute(f\"SELECT * FROM t WHERE slug = '{slug}'\")\n"
)


def _django_urls(pattern: str) -> str:
    return (
        "from django.urls import path\n"
        "from . import views\n"
        f'urlpatterns = [path("{pattern}", views.view)]\n'
    )


def test_django_path_kwarg_is_reachable():
    f = _one({"urls.py": _django_urls("u/<str:slug>"), "views.py": _DJANGO_VIEW})
    _assert_proven_from(f, "slug")
    assert f["taint_chain"][0]["file"] == "views.py"
    assert f["route"]["pattern"] == "u/<str:slug>"


@pytest.mark.parametrize(
    "params",
    [
        "name: str = Depends(get_user)",
        "name: str = Security(get_user)",
        "name=Depends(get_user)",
    ],
)
def test_depends_param_is_not_a_source(params):
    # Review Focus 2: `user = Depends(get_user)` is what the server resolved,
    # not what the client sent.
    _assert_unproven(_one({"app.py": _fastapi_sqli(params)}))


def test_request_typed_param_itself_is_not_a_source():
    src = (
        "import os\n"
        "from fastapi import APIRouter, Request, Response, BackgroundTasks, WebSocket\n"
        "from starlette.requests import HTTPConnection\n"
        "from sqlalchemy.orm import Session\n"
        "router = APIRouter()\n"
        '@router.get("/r")\n'
        "def h(r: Request, resp: Response, tasks: BackgroundTasks, ws: WebSocket,\n"
        "      conn: HTTPConnection, db: Session):\n"
        "    os.system(r)\n"
        "    os.system(resp)\n"
        "    os.system(tasks)\n"
        "    os.system(ws)\n"
        "    os.system(conn)\n"
        "    os.system(db)\n"
        '@router.get("/q")\n'
        "def leading(request, q: str = ''):\n"
        "    os.system(request)\n"
        '@router.get("/s")\n'
        "def method_like(self, req):\n"
        "    os.system(self)\n"
        "    os.system(req)\n"
    )
    found = _rule(_scan({"app.py": src}), "PY_OS_SYSTEM")
    assert len(found) == 9, found
    for f in found:
        _assert_unproven(f)


def test_non_route_function_param_is_not_a_source():
    src = (
        "import sqlite3\n"
        "def f(name):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        "    cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )
    _assert_unproven(_one({"helpers.py": src}))


def test_same_named_non_handler_in_other_file_is_not_a_source():
    # RouteTable is keyed on the bare function name: util.index must not
    # borrow app.index's route, nor its parameters' source status.
    app = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/i/<name>")\n'
        "def index(name):\n"
        "    return name\n"
    )
    util = (
        "import sqlite3\n"
        "def index(name):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        "    cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )
    f = _one({"app.py": app, "util.py": util})
    _assert_unproven(f)
    assert "route" not in f


def test_same_named_method_in_handler_file_is_not_a_source():
    # Only the decorated def is the handler; a method of the same name in the
    # same file is not.
    src = (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/i/<name>")\n'
        "def index(name):\n"
        "    return name\n"
        "class Repo:\n"
        "    def index(self, name):\n"
        '        cur = sqlite3.connect("db").cursor()\n'
        "        cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )
    f = _one({"app.py": src})
    _assert_unproven(f)
    assert "route" not in f


# -- R-pf33: a parameter coerced to a non-string scalar is not a source -------


@pytest.mark.parametrize(
    "annotation",
    [
        "int",
        "float",
        "bool",
        "UUID",
        "uuid.UUID",
        "datetime.datetime",
        "date",
        "time",
        "timedelta",
        "Decimal",
        "Optional[int]",
        "Union[int, None]",
        "int | None",
        "None | uuid.UUID",
        "Annotated[int, Query(gt=0)]",
        "Annotated[Optional[int], Query()]",
        "'int'",
    ],
)
def test_fastapi_int_param_is_not_a_source(annotation):
    f = _one({"app.py": _fastapi_sqli(f"name: {annotation} = Query(...)")})
    _assert_unproven(f)
    # Still a route handler: the finding keeps its sink, only unproven.
    assert f["symbol"] == "h"


@pytest.mark.parametrize(
    "params",
    [
        "name: Optional[str] = None",
        "name: str | None = None",
        "name: Union[str, None] = None",
        "name: Union[int, str] = 0",
        "name: Annotated[Optional[str], Query()] = None",
        "name: list[str] = Query([])",
        "name: Item",
        "name",
    ],
)
def test_fastapi_optional_str_param_is_a_source(params):
    _assert_proven_from(_one({"app.py": _fastapi_sqli(params)}), "name")


@pytest.mark.parametrize(
    "pattern, proven",
    [
        ("/u/<int:name>", False),
        ("/u/<float:name>", False),
        ("/u/<uuid:name>", False),
        ("/u/<int(signed=True):name>", False),
        ("/u/<string:name>", True),
        ("/u/<path:name>", True),
    ],
)
def test_flask_int_converter_is_not_a_source(pattern, proven):
    src = (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        f'@app.route("{pattern}")\n'
        "def h(name):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        "    cur.execute(f\"SELECT * FROM u WHERE name = '{name}'\")\n"
    )
    f = _one({"app.py": src})
    if proven:
        _assert_proven_from(f, "name")
    else:
        _assert_unproven(f)


@pytest.mark.parametrize(
    "pattern, proven",
    [
        ("u/<int:slug>", False),
        ("u/<uuid:slug>", False),
        ("u/<slug:slug>", True),
        ("u/<path:slug>", True),
    ],
)
def test_django_int_converter_is_not_a_source(pattern, proven):
    f = _one({"urls.py": _django_urls(pattern), "views.py": _DJANGO_VIEW})
    if proven:
        _assert_proven_from(f, "slug")
        # A route is attached only to a proven finding, and here it is the
        # pattern's own.
        assert f["route"]["pattern"] == pattern
    else:
        _assert_unproven(f)


# -- R-pf27: Annotated dependencies, and same-file aliases of them ------------


@pytest.mark.parametrize(
    "params",
    [
        "name: Annotated[str, Depends(get_user)]",
        "name: Annotated[str, Security(get_user, scopes=['me'])]",
        "name: Annotated[str, Query(), Depends(get_user)]",
    ],
)
def test_annotated_depends_param_is_not_a_source(params):
    _assert_unproven(_one({"app.py": _fastapi_sqli(params)}))


@pytest.mark.parametrize(
    "alias",
    [
        "CurrentUser = Annotated[str, Depends(get_user)]\n",
        "CurrentUser: TypeAlias = Annotated[str, Security(get_user)]\n",
    ],
)
def test_annotated_alias_depends_param_is_not_a_source(alias):
    f = _one({"app.py": _fastapi_sqli("name: CurrentUser", prelude=alias)})
    _assert_unproven(f)


def test_annotated_alias_without_dependency_is_still_a_source():
    alias = "Name = Annotated[str, Query(max_length=50)]\n"
    f = _one({"app.py": _fastapi_sqli("name: Name", prelude=alias)})
    _assert_proven_from(f, "name")


# -- the helper hop: a handler parameter passed to a same-file helper ---------


def test_fastapi_param_through_same_file_helper_is_reachable():
    src = (
        "import subprocess\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "def _ping(host: str) -> str:\n"
        '    return subprocess.run(f"ping -c 1 {host}", shell=True).stdout\n'
        '@router.get("/cmdi/indirect")\n'
        'def ping_host(host: str = ""):\n'
        "    return {'output': _ping(host)}\n"
    )
    f = _one({"app.py": src}, "PY_SUBPROCESS_SHELL")
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0] == {"file": "app.py", "line": 7, "expr": "host"}
    assert f["taint_chain"][1] == {"file": "app.py", "line": 8, "expr": "_ping(host)"}


def test_coerced_param_through_same_file_helper_is_not_reachable():
    src = (
        "import subprocess\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "def _ping(count) -> str:\n"
        '    return subprocess.run(f"ping -c {count} h", shell=True).stdout\n'
        '@router.get("/cmdi/indirect")\n'
        "def ping_host(count: int = 1):\n"
        "    return {'output': _ping(count)}\n"
    )
    _assert_unproven(_one({"app.py": src}, "PY_SUBPROCESS_SHELL"))


# -- decision 3: sanitisers apply to a route parameter as to a request value --


_GUARDED_SHAPES = {
    # SSRF behind a membership guard: not reported at all.
    "ssrf_membership": (
        "PY_SSRF",
        ("import requests\n" "ALLOWED = {'https://api.example.com/a'}\n"),
        (
            "    if url not in ALLOWED:\n"
            "        raise ValueError('no')\n"
            "    return requests.get(url, timeout=5).text\n"
        ),
    ),
    # SSRF behind a urlparse(...).netloc allowlist: not reported at all.
    "ssrf_netloc": (
        "PY_SSRF",
        (
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "HOSTS = {'api.example.com'}\n"
        ),
        (
            "    parsed = urlparse(url)\n"
            "    if parsed.netloc not in HOSTS:\n"
            "        raise ValueError('no')\n"
            "    return requests.get(url, timeout=5).text\n"
        ),
    ),
    # Path traversal behind realpath + commonpath containment: not reported.
    "path_containment": (
        "PY_PATH_TRAVERSAL",
        ("import os\n" "BASE = '/srv/reports'\n"),
        (
            "    base = os.path.realpath(BASE)\n"
            "    full = os.path.realpath(os.path.join(base, url))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            "        raise ValueError('no')\n"
            "    with open(full) as fh:\n"
            "        return fh.read()\n"
        ),
    ),
    # XSS with the value escaped before Markup: not reported.
    "xss_escape": (
        "PY_XSS_HTML_SINK",
        "from markupsafe import Markup, escape\n",
        "    return Markup('<b>' + escape(url) + '</b>')\n",
    ),
    # A same-file helper behind a caller-side membership guard: reported in
    # the helper, never proven through the hop (R-pf32).
    "helper_membership": (
        "PY_SUBPROCESS_SHELL",
        (
            "import subprocess\n"
            "ALLOWED = {'a.example.com'}\n"
            "def _ping(host):\n"
            "    return subprocess.run(f'ping -c 1 {host}', shell=True).stdout\n"
        ),
        (
            "    if url not in ALLOWED:\n"
            "        raise ValueError('no')\n"
            "    return _ping(url)\n"
        ),
    ),
}


def _outcome(findings: list[dict], rule: str) -> list[tuple]:
    return [
        (f["line"].split(":")[1], f.get("reachable") is True, "taint_chain" in f)
        for f in _rule(findings, rule)
    ]


@pytest.mark.parametrize("shape", sorted(_GUARDED_SHAPES))
def test_guarded_fastapi_param_stays_as_a_request_value_would(shape):
    rule, prelude, body = _GUARDED_SHAPES[shape]
    as_param = (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        f"{prelude}"
        '@router.get("/g")\n'
        'def h(url: str = ""):\n'
        "    marker = None\n"
        f"{body}"
    )
    # The same handler reading the value off the request instead. Same line
    # count, so the sink lines match.
    as_request = (
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n"
        f"{prelude}"
        '@router.get("/g")\n'
        "def h(request: Request):\n"
        '    url = request.query_params.get("url", "")\n'
        f"{body}"
    )
    # Both must parse, or two empty outcomes would compare equal vacuously.
    ast.parse(as_param)
    ast.parse(as_request)
    param_outcome = _outcome(_scan({"app.py": as_param}), rule)
    request_outcome = _outcome(_scan({"app.py": as_request}), rule)
    assert param_outcome == request_outcome
    # And none of them is proven.
    assert all(not reachable for _line, reachable, _chain in param_outcome)
    if shape == "helper_membership":
        assert len(param_outcome) == 1  # reported in the helper, unproven


def test_unguarded_fastapi_param_is_proven_where_the_guarded_one_is_not():
    # Control for the guarded shapes: without the guard the same SSRF proves.
    src = (
        "import requests\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/g")\n'
        'def h(url: str = ""):\n'
        "    return requests.get(url, timeout=5).text\n"
    )
    _assert_proven_from(_one({"app.py": src}, "PY_SSRF"), "url")


# -- decision 5: the stricter binding keeps Django's correct routes -----------


def test_django_same_named_views_each_bind_their_own_route():
    # Two views modules each define `search`; urls.py routes both. Each
    # finding must carry its OWN route, resolved through the urlconf's
    # imports (`from app.views import a, b`), not the first `search` seen.
    urls = (
        "from django.urls import path\n"
        "from app.views import a, b\n"
        "urlpatterns = [\n"
        '    path("a/<str:q>/", a.search),\n'
        '    path("b/<str:q>/", b.search),\n'
        "]\n"
    )
    view = (
        "from django.db import connection\n"
        "def search(request, q):\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE q = '{q}'\")\n"
    )
    findings = _rule(
        _scan({"config/urls.py": urls, "app/views/a.py": view, "app/views/b.py": view}),
        "PY_SQL_INJECTION",
    )
    by_file = {f["line"].split(":")[0]: f for f in findings}
    assert set(by_file) == {"app/views/a.py", "app/views/b.py"}
    for rel, pattern in (("app/views/a.py", "a/<str:q>/"), ("app/views/b.py", "b/<str:q>/")):
        f = by_file[rel]
        _assert_proven_from(f, "q")
        assert f["route"]["pattern"] == pattern
        assert f["route"]["file"] == "config/urls.py"


@pytest.mark.parametrize(
    "imports, handler",
    [
        ("from app import views\n", "views.show"),
        ("from app.views import show\n", "show"),
        ("from app.views import show as show_view\n", "show_view"),
        ("import app.views\n", "app.views.show"),
        ("import app.views as v\n", "v.show"),
        ("from .views import show\n", "show"),
        ("from . import views\n", "views.show"),
    ],
)
def test_django_route_binds_through_each_import_form(imports, handler):
    urls = (
        "from django.urls import path\n"
        f"{imports}"
        f'urlpatterns = [path("r/<str:slug>/", {handler})]\n'
    )
    view = (
        "from django.db import connection\n"
        "def show(request, slug):\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{slug}'\")\n"
    )
    f = _one({"app/urls.py": urls, "app/views.py": view})
    _assert_proven_from(f, "slug")
    assert f["route"]["pattern"] == "r/<str:slug>/"


def test_django_route_does_not_bind_a_same_named_function_elsewhere():
    urls = (
        "from django.urls import path\n"
        "from app import views\n"
        'urlpatterns = [path("r/<str:slug>/", views.show)]\n'
    )
    other = (
        "from django.db import connection\n"
        "def show(request, slug):\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{slug}'\")\n"
    )
    f = _one({"app/urls.py": urls, "app/views.py": "def show(request, slug):\n    return slug\n", "app/other.py": other})
    _assert_unproven(f)
    assert "route" not in f


def test_django_route_does_not_bind_a_same_named_method_in_the_views_file():
    # `views.show` is the module-level def; a method `show` in the same file
    # is not what the route dispatches to.
    urls = (
        "from django.urls import path\n"
        "from app import views\n"
        'urlpatterns = [path("r/<str:slug>/", views.show)]\n'
    )
    views = (
        "from django.db import connection\n"
        "def show(request, slug):\n"
        "    return slug\n"
        "class Repo:\n"
        "    def show(self, request, slug):\n"
        "        connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{slug}'\")\n"
    )
    f = _one({"app/urls.py": urls, "app/views.py": views})
    _assert_unproven(f)
    assert "route" not in f


@pytest.mark.parametrize(
    "decorators, proven",
    [
        # Flask docs idiom: the bare route supplies `page` from `defaults=`,
        # the other coerces it. Neither passes it as a string.
        ('@app.route("/", defaults={"page": 1})\n@app.route("/p/<int:page>")\n', False),
        ('@app.route("/p/<int:page>")\n@app.route("/", defaults={"page": 1})\n', False),
        # One route passes it as a string: a source, whatever the order.
        ('@app.route("/p/<int:page>")\n@app.route("/q/<page>")\n', True),
        ('@app.route("/q/<page>")\n@app.route("/p/<int:page>")\n', True),
    ],
)
def test_flask_converters_apply_across_all_of_a_views_routes(decorators, proven):
    src = (
        "import sqlite3\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        f"{decorators}"
        "def h(page):\n"
        '    cur = sqlite3.connect("db").cursor()\n'
        '    cur.execute(f"SELECT * FROM u LIMIT 10 OFFSET {page}")\n'
    )
    f = _one({"app.py": src})
    if proven:
        _assert_proven_from(f, "page")
    else:
        _assert_unproven(f)


def test_django_views_first_positional_parameter_is_the_request_whatever_its_name():
    # Django calls a function view as view(request, *args, **kwargs): `r` is
    # the HttpRequest, and `r.user.id` is not client input. `slug` still is.
    views = (
        "from django.db import connection\n"
        "def view(r, slug):\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE u = '{r.user.id}'\")\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{slug}'\")\n"
    )
    findings = _rule(
        _scan({"urls.py": _django_urls("u/<str:slug>"), "views.py": views}),
        "PY_SQL_INJECTION",
    )
    by_line = {f["line"]: f for f in findings}
    assert set(by_line) == {"views.py:3", "views.py:4"}
    _assert_unproven(by_line["views.py:3"])
    _assert_proven_from(by_line["views.py:4"], "slug")


def test_fastapi_first_positional_parameter_is_a_source_when_not_named_request():
    # FastAPI has no implicit request argument: its first parameter is an
    # ordinary query parameter.
    f = _one({"app.py": _fastapi_sqli("name: str, other: str = ''")})
    _assert_proven_from(f, "name")


# ---------------------------------------------------------------------------
# Fix round 1: typed and dependency-injected route parameters (R-pf34, R-pf36)
# ---------------------------------------------------------------------------

_ENUMS = (
    "import enum\n"
    "from enum import Enum, IntEnum\n"
    "from typing import Literal, List, Set, Tuple\n"
    "from pydantic import conint, confloat, constr, PositiveInt, StrictInt\n"
    "from fastapi import Path\n"
    "class Sort(str, Enum):\n"
    "    asc = 'asc'\n"
    "    desc = 'desc'\n"
    "class Level(IntEnum):\n"
    "    low = 1\n"
    "class Colour(enum.StrEnum):\n"
    "    red = 'red'\n"
    "class Shade(Sort):\n"
    "    pass\n"
)


@pytest.mark.parametrize(
    "params",
    [
        # R-pf36: Literal (the textbook safe dynamic ORDER BY).
        'name: Literal["asc", "desc"] = "asc"',
        'name: Optional[Literal["asc", "desc"]] = None',
        # R-pf36: an Enum class of this file, whatever its Enum base.
        "name: Sort = Sort.asc",
        "name: Level = Level.low",
        "name: Colour = Colour.red",
        "name: Shade = Shade.asc",
        "name: Annotated[Sort, Query()] = Sort.asc",
        # R-pf36: pydantic constrained numbers.
        "name: conint(gt=0) = 1",
        "name: confloat(ge=0) = 0.0",
        "name: PositiveInt = 1",
        "name: StrictInt = 1",
        # R-pf36: containers of fixed-value types.
        "name: list[int] = Query([])",
        "name: List[int] = Query([])",
        "name: set[UUID] = Query(set())",
        "name: Tuple[int, ...] = Query(())",
        "name: Optional[list[int]] = None",
        "name: list[Sort] = Query([])",
        "name: list[Literal['a', 'b']] = Query([])",
    ],
)
def test_fixed_value_route_param_is_not_a_source(params):
    f = _one({"app.py": _fastapi_sqli(params, prelude=_ENUMS)})
    _assert_unproven(f)


@pytest.mark.parametrize(
    "params",
    [
        'name: str = ""',
        "name: Item",
        "name: list[str] = Query([])",
        "name: list[Item]",
        # R-pf36: a regex-constrained string still carries free text.
        "name: constr(pattern='^[a-z]+$') = 'a'",
        "name: str = Path(pattern='^[a-z]+$')",
        # A class of this file that is not an Enum.
        "name: Item = Depends",  # a bare reference, not a Depends(...) call
    ],
)
def test_str_and_model_route_params_stay_sources(params):
    _assert_proven_from(_one({"app.py": _fastapi_sqli(params, prelude=_ENUMS)}), "name")


def test_enum_imported_from_another_module_stays_a_source():
    # R-pf36 recognises an Enum defined in the handler's own file only.
    prelude = "from app.choices import Sort\n"
    _assert_proven_from(_one({"app.py": _fastapi_sqli("name: Sort", prelude=prelude)}), "name")


# -- R-pf36: Flask and Django pass only the URL variables their pattern names --


def test_flask_param_with_a_plain_default_is_not_a_source():
    src = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/report")\n'
        'def report(fmt="pdf"):\n'
        '    os.system(f"gen --fmt {fmt}")\n'
    )
    _assert_unproven(_one({"app.py": src}, "PY_OS_SYSTEM"))


def test_flask_param_named_by_one_route_is_a_source():
    src = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/report", defaults={"fmt": "pdf"})\n'
        '@app.route("/report/<fmt>")\n'
        "def report(fmt):\n"
        '    os.system(f"gen --fmt {fmt}")\n'
    )
    _assert_proven_from(_one({"app.py": src}, "PY_OS_SYSTEM"), "fmt")


def test_fastapi_param_with_a_plain_default_is_a_source():
    # FastAPI reads a parameter the path does not name from the query string.
    src = (
        "import os\n"
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        '@router.get("/report")\n'
        'def report(fmt="pdf"):\n'
        '    os.system(f"gen --fmt {fmt}")\n'
    )
    _assert_proven_from(_one({"app.py": src}, "PY_OS_SYSTEM"), "fmt")


@pytest.mark.parametrize(
    "imports, decorator, framework",
    [
        ("from flask import Flask\napp = Flask(__name__)\n", '@app.get("/report")', "flask"),
        ("from fastapi import FastAPI\napp = FastAPI()\n", '@app.get("/report")', "fastapi"),
        ("from .core import app\n", '@app.route("/report")', "flask"),
        ("from .core import app\n", '@app.get("/report/{x}")', "fastapi"),
        ("from .core import app\n", '@app.get("/report/<x>")', "flask"),
        ("from .core import app\n", '@app.get("/report")', ""),
    ],
)
def test_decorator_route_framework(imports, decorator, framework):
    src = f"{imports}{decorator}\ndef report(x='1'):\n    return x\n"
    [route] = extract_routes(src, "app.py").routes
    assert route.framework == framework


def test_django_extra_kwargs_value_is_not_a_source():
    urls = (
        "from django.urls import path\n"
        "from app import views\n"
        "urlpatterns = [path('about/', views.page, {'tpl': 'about'})]\n"
    )
    views = "import os\ndef page(request, tpl='x'):\n    os.system(f'render {tpl}')\n"
    f = _one({"app/urls.py": urls, "app/views.py": views}, "PY_OS_SYSTEM")
    _assert_unproven(f)


@pytest.mark.parametrize(
    "call, proven",
    [
        # Named groups: by name. A digit-only group is still a string (R-pf36).
        ("re_path(r'^r/(?P<slug>[0-9]+)/$', views.show)", True),
        # Unnamed groups fill the positional parameters after `request`.
        ("re_path(r'^r/([^/]+)/$', views.show)", True),
        ("re_path(r'^r/(?:x|y)/([^/]+)/$', views.show)", True),
        # Django passes only named groups when a pattern has both, and an
        # escaped or bracketed parenthesis is not a group.
        ("re_path(r'^r/(?P<other>\\w+)/([^/]+)/$', views.show)", False),
        ("re_path(r'^r/\\(x\\)/[()]/$', views.show)", False),
        ("path('r/', views.show)", False),
    ],
)
def test_django_regex_groups_name_the_sources(call, proven):
    urls = f"from django.urls import path, re_path\nfrom app import views\nurlpatterns = [{call}]\n"
    views = (
        "from django.db import connection\n"
        "def show(request, slug='x', other='y'):\n"
        "    connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{slug}'\")\n"
    )
    f = _one({"app/urls.py": urls, "app/views.py": views})
    if proven:
        _assert_proven_from(f, "slug")
    else:
        _assert_unproven(f)


# -- R-pf34: types imported from a deps/dependencies module are DI ------------


@pytest.mark.parametrize(
    "prelude, annotation",
    [
        ("from app.api.deps import CurrentUser\n", "CurrentUser"),
        ("from app.api.deps import CurrentUser as Me\n", "Me"),
        ("from app.dependencies.auth import User\n", "User"),
        ("from .deps import SessionDep\n", "SessionDep"),
        ("from ..api.dependencies import SessionDep\n", "SessionDep"),
        ("from app.api.deps import CurrentUser\n", "Optional[CurrentUser]"),
        ("from app.api.deps import CurrentUser\n", "Annotated[CurrentUser, 'x']"),
        ("from app.api import deps\n", "deps.CurrentUser"),
        ("from . import deps\n", "deps.CurrentUser"),
        ("import app.api.deps as d\n", "d.CurrentUser"),
        ("import app.api.deps\n", "app.api.deps.CurrentUser"),
        ("from app import dependencies\n", "dependencies.auth.User"),
    ],
)
def test_param_typed_from_a_deps_module_is_not_a_source(prelude, annotation):
    f = _one({"app/routes.py": _fastapi_sqli(f"name: {annotation}", prelude=prelude)})
    _assert_unproven(f)


@pytest.mark.parametrize(
    "prelude, annotation",
    [
        ("from app.models import User\n", "User"),
        ("from app import models\n", "models.User"),
        ("from app.depsx import User\n", "User"),
        # `deps` is the imported name here, not a module segment of `User`.
        ("from app.api import deps\n", "User"),
    ],
)
def test_param_typed_from_another_module_stays_a_source(prelude, annotation):
    f = _one({"app/routes.py": _fastapi_sqli(f"name: {annotation}", prelude=prelude)})
    _assert_proven_from(f, "name")


# -- unittest.mock decorators are not routes ------------------------------------


@pytest.mark.parametrize(
    "imports, decorator",
    [
        ("from unittest import mock\n", '@mock.patch("os.getenv")'),
        ("import mock\n", '@mock.patch("os.getenv")'),
        ("from unittest import mock as um\n", '@um.patch("os.getenv")'),
        ("import unittest.mock\n", '@unittest.mock.patch("os.getenv")'),
        ("from unittest import mock\n", '@mock.patch("/srv/x")'),
    ],
)
def test_mock_patch_decorator_is_not_a_route(imports, decorator):
    src = (
        f"import os\n{imports}{decorator}\n"
        'def check(m, cmd="ls"):\n'
        '    os.system(f"x {cmd}")\n'
    )
    assert extract_routes(src, "checks.py").routes == []
    f = _one({"checks.py": src}, "PY_OS_SYSTEM")
    _assert_unproven(f)
    assert "route" not in f


def test_decorator_with_a_non_path_first_argument_is_not_a_route():
    # Flask and Starlette require a route to start with "/".
    src = '@cache.get("users")\ndef h(name):\n    return name\n'
    assert extract_routes(src, "app.py").routes == []
    # FastAPI allows "" under a prefixed router.
    src = 'from fastapi import APIRouter\nrouter = APIRouter()\n@router.get("")\ndef h(name):\n    return name\n'
    assert [r.pattern for r in extract_routes(src, "app.py").routes] == [""]


# -- Django views re-exported by a package, and a scan root inside the package --

_REEXPORT_URLS = (
    "from django.urls import path\n"
    "from app import views\n"
    "urlpatterns = [path('r/<str:slug>/', views.show)]\n"
)
_REEXPORT_VIEW = (
    "from django.db import connection\n"
    "def {name}(request, slug):\n"
    "    connection.cursor().execute(f\"SELECT * FROM t WHERE s = '{{slug}}'\")\n"
)


@pytest.mark.parametrize(
    "init, items_name",
    [
        ("from .items import show\n", "show"),
        ("from .items import *\n", "show"),
        ("from app.views.items import show\n", "show"),
        ("from .items import show_item as show\n", "show_item"),
    ],
)
def test_django_view_re_exported_by_its_package_binds(init, items_name):
    files = {
        "app/urls.py": _REEXPORT_URLS,
        "app/views/__init__.py": init,
        "app/views/items.py": _REEXPORT_VIEW.format(name=items_name),
    }
    f = _one(files)
    _assert_proven_from(f, "slug")
    assert f["route"]["pattern"] == "r/<str:slug>/"
    assert f["route"]["file"] == "app/urls.py"


def test_django_re_export_follows_one_hop_only():
    files = {
        "app/urls.py": _REEXPORT_URLS,
        "app/views/__init__.py": "from .a import show\n",
        "app/views/a.py": "from .b import show\n",
        "app/views/b.py": _REEXPORT_VIEW.format(name="show"),
    }
    f = _one(files)
    _assert_unproven(f)
    assert "route" not in f


def _scan_at(root_name: str, files: dict[str, str]) -> list[dict]:
    """`_scan` with the scan root a directory named `root_name`, as when a
    user scans a package directory itself."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / root_name
        for name, content in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        findings: list[dict] = []
        ASTAnalyzer(str(root)).run(findings.append)
        return findings


def test_django_scan_root_inside_the_package_falls_back_to_the_scanned_module():
    # urls.py imports `app.views`, but the scan root IS the `app/` directory:
    # no scanned file is `app/views.py`, and the scanned module `views`
    # stands in for it because the prefix it drops, `app`, is the directory
    # the scan root is.
    findings = _scan_at(
        "app", {"urls.py": _REEXPORT_URLS, "views.py": _REEXPORT_VIEW.format(name="show")}
    )
    [f] = _rule(findings, "PY_SQL_INJECTION")
    _assert_proven_from(f, "slug")
    assert f["route"]["pattern"] == "r/<str:slug>/"
    # Also through a package re-export, inside the same scan root.
    findings = _scan_at(
        "app",
        {
            "urls.py": _REEXPORT_URLS,
            "views/__init__.py": "from .items import show\n",
            "views/items.py": _REEXPORT_VIEW.format(name="show"),
        },
    )
    [f] = _rule(findings, "PY_SQL_INJECTION")
    _assert_proven_from(f, "slug")


def test_django_scanned_suffix_does_not_stand_in_when_the_scan_root_is_elsewhere():
    # The same files under a scan root named `web`: `views.py` is not
    # `app.views`, so nothing binds.
    findings = _scan_at(
        "web", {"urls.py": _REEXPORT_URLS, "views.py": _REEXPORT_VIEW.format(name="show")}
    )
    [f] = _rule(findings, "PY_SQL_INJECTION")
    _assert_unproven(f)
    assert "route" not in f


def test_third_party_view_does_not_bind_a_project_def_of_the_same_name():
    # `serve` is django.views.static.serve, outside the scan. A project def
    # named `serve` is not the view, whatever it does with `path`.
    urls = (
        "from django.urls import re_path\n"
        "from django.views.static import serve\n"
        "urlpatterns = [re_path(r'^media/(?P<path>.*)$', serve, {'document_root': '/srv'})]\n"
    )
    helper = (
        "import os\n"
        "BASE = '/srv'\n"
        "def serve(path):\n"
        "    return open(os.path.join(BASE, path)).read()\n"
    )
    findings = _rule(_scan({"proj/urls.py": urls, "proj/files.py": helper}), "PY_PATH_TRAVERSAL")
    assert findings, "the sink is still reported"
    for f in findings:
        _assert_unproven(f)
        assert "route" not in f


def test_third_party_view_does_not_bind_a_scanned_module_matching_its_suffix():
    # Even a scanned top-level `static.py` is not `django.views.static`: the
    # prefix it would drop (`django.views`) is not where the scan root is.
    urls = (
        "from django.urls import re_path\n"
        "from django.views.static import serve\n"
        "urlpatterns = [re_path(r'^media/(?P<path>.*)$', serve)]\n"
    )
    helper = (
        "import os\n"
        "def serve(request, path):\n"
        "    return open(os.path.join('/srv', path)).read()\n"
    )
    findings = _rule(_scan({"urls.py": urls, "static.py": helper}), "PY_PATH_TRAVERSAL")
    assert findings
    for f in findings:
        _assert_unproven(f)
        assert "route" not in f


def test_view_with_an_unbound_head_does_not_bind_by_name():
    # `self.path(...)` is not a urlconf entry, and `self.handler` resolves to
    # nothing: a def named `handler` elsewhere is not its view.
    router = "class R:\n    def setup(self):\n        self.path('/x/<cmd>', self.handler)\n"
    handler = "import os\ndef handler(cmd):\n    os.system(cmd)\n"
    f = _one({"r.py": router, "h.py": handler}, "PY_OS_SYSTEM")
    _assert_unproven(f)
    assert "route" not in f


# -- fix round 2: Flask-family frameworks, and the project's dominant one ------

_REPORT = 'def report({sig}):\n    os.system(f"gen --fmt {{fmt}}")\n'


@pytest.mark.parametrize(
    "imports, sig",
    [
        ("from quart import Quart\napp = Quart(__name__)\n", 'fmt="pdf"'),
        ("from sanic import Sanic\napp = Sanic('a')\n", 'request, fmt="pdf"'),
    ],
)
def test_quart_and_sanic_plain_default_is_not_a_source(imports, sig):
    src = f"import os\n{imports}" + '@app.get("/report")\n' + _REPORT.format(sig=sig)
    [route] = extract_routes(src, "app.py").routes
    assert route.framework == "flask"
    _assert_unproven(_one({"app.py": src}, "PY_OS_SYSTEM"))


def test_sanic_typed_url_variable_reads_name_first():
    # Sanic writes `<name:type>`, the reverse of Flask's `<converter:name>`.
    head = "import os\nfrom sanic import Sanic\napp = Sanic('a')\n"
    src = head + '@app.get("/r/<fmt:str>")\n' + _REPORT.format(sig="request, fmt")
    _assert_proven_from(_one({"app.py": src}, "PY_OS_SYSTEM"), "fmt")
    src = head + '@app.get("/r/<fmt:int>")\n' + _REPORT.format(sig="request, fmt")
    _assert_unproven(_one({"app.py": src}, "PY_OS_SYSTEM"))


def test_ninja_route_reads_query_parameters():
    src = (
        "import os\nfrom ninja import NinjaAPI\napi = NinjaAPI()\n"
        '@api.get("/report")\n' + _REPORT.format(sig='request, fmt: str = "pdf"')
    )
    [route] = extract_routes(src, "app.py").routes
    assert route.framework == "fastapi"
    _assert_proven_from(_one({"app.py": src}, "PY_OS_SYSTEM"), "fmt")


def test_blueprint_file_without_a_framework_import_takes_the_projects_framework():
    # The views file imports only its blueprint; every other file is Flask.
    views = "import os\nfrom . import bp\n" + '@bp.get("/report")\n' + _REPORT.format(sig='fmt="pdf"')
    files = {
        "app/__init__.py": "from flask import Blueprint, Flask\nbp = Blueprint('r', __name__)\n",
        "app/auth.py": "from flask import request, session\n",
        "app/views.py": views,
    }
    _assert_unproven(_one(files, "PY_OS_SYSTEM"))


def test_unknown_framework_with_no_project_framework_keeps_fastapi_behaviour():
    # Nothing in the project names a framework: the route stays unknown and
    # is read like FastAPI, as before.
    src = (
        "import os\nfrom myapp.hooks import registry\n"
        '@registry.get("/report")\n' + _REPORT.format(sig='fmt="pdf"')
    )
    [route] = extract_routes(src, "app.py").routes
    assert route.framework == ""
    _assert_proven_from(_one({"app.py": src}, "PY_OS_SYSTEM"), "fmt")


def test_unknown_framework_tie_keeps_fastapi_behaviour():
    views = "import os\nfrom . import bp\n" + '@bp.get("/report")\n' + _REPORT.format(sig='fmt="pdf"')
    files = {
        "app/a.py": "from flask import Flask\n",
        "app/b.py": "from fastapi import FastAPI\n",
        "app/views.py": views,
    }
    _assert_proven_from(_one(files, "PY_OS_SYSTEM"), "fmt")


# -- route_param_sources: the whole rule set, for Task 3.8 ---------------------


def test_route_param_sources_applies_the_whole_rule_set():
    module = ast.parse(
        "from enum import Enum\n"
        "from typing import Annotated\n"
        "from fastapi import Depends\n"
        "from app.api.deps import SessionDep\n"
        "class Sort(str, Enum):\n"
        "    asc = 'asc'\n"
        "Me = Annotated[str, Depends(get_user)]\n"
        "def h(q: str, sort: Sort, me: Me, db: SessionDep, n: int, raw):\n"
        "    pass\n"
    )
    func = module.body[-1]
    [fastapi_route] = extract_routes('@router.get("/u/{raw}")\ndef h(): pass\n', "a.py").routes
    [flask_route] = extract_routes(
        'from flask import Flask\n@app.route("/u/<raw>")\ndef h(): pass\n', "a.py"
    ).routes
    assert route_param_sources(func, [fastapi_route], module) == {"q", "raw"}
    assert route_param_sources(func, [flask_route], module) == {"raw"}
    assert route_param_sources(func, [], module) == frozenset()


def test_unimported_dotted_view_gets_no_stand_in():
    # `app.views.show` with nothing importing `app`: its head is unbound, so
    # even inside a scan root named `app`, `views.py` does not stand in.
    urls = "from django.urls import path\nurlpatterns = [path('r/<str:slug>/', app.views.show)]\n"
    findings = _scan_at("app", {"urls.py": urls, "views.py": _REEXPORT_VIEW.format(name="show")})
    [f] = _rule(findings, "PY_SQL_INJECTION")
    _assert_unproven(f)
    assert "route" not in f


def test_django_route_with_no_module_binds_nothing():
    # `from . import show` at the scan root names no module for the view, so
    # a def named `show` elsewhere is not bound by its name.
    urls = (
        "from django.urls import path\n"
        "from . import show\n"
        "urlpatterns = [path('r/<str:slug>/', show)]\n"
    )
    f = _one({"urls.py": urls, "other.py": _REEXPORT_VIEW.format(name="show")})
    _assert_unproven(f)
    assert "route" not in f


# ---------------------------------------------------------------------------
# Task 3.8: the helper hop follows one call across files
# ---------------------------------------------------------------------------
#
# A view that passes request input to a helper imported from another module
# proves the helper's sink, one hop, as a same-file helper does. The chain
# starts at the call in the view's file. The caller-side sanitisers of the
# same-file hop apply in the caller's file (R-pf50 a), the caller's sources
# are the whole route-parameter rule set (R-pf50 b), and only a module-level
# function is matched (R-pf50 c).


def _flask_cross_file(view_body: str, helper: str, prelude: str = "") -> dict[str, str]:
    """The layout of corpus case `flask-sqli-cross_file`: a blueprint, the
    view in `app/sqli_cross_file.py`, the helper in `app/services/`."""
    return {
        "app/__init__.py": "",
        "app/blueprint.py": 'from flask import Blueprint\nbp = Blueprint("cases", __name__)\n',
        "app/services/__init__.py": "",
        "app/services/helpers.py": helper,
        "app/sqli_cross_file.py": (
            "from flask import abort, jsonify, request\n"
            "from app.blueprint import bp\n"
            "from app.services import helpers\n"
            f"{prelude}"
            '@bp.route("/x", endpoint="x")\n'
            "def view():\n"
            f"{view_body}"
        ),
    }


def _in_helper(files: dict[str, str], rule: str) -> dict:
    """The one `rule` finding in `app/services/helpers.py`. The view may
    report its own sink too (a proven `os.path.join` in it is one)."""
    found = [
        f
        for f in _rule(_scan(files), rule)
        if f["line"].startswith("app/services/helpers.py:")
    ]
    assert len(found) == 1, found
    return found[0]


def test_cross_file_sqli_is_reachable():
    files = {
        "app/__init__.py": "",
        "app/blueprint.py": 'from flask import Blueprint\nbp = Blueprint("cases", __name__)\n',
        "app/services/__init__.py": "",
        "app/services/user_queries.py": (
            "import sqlite3\n"
            "from contextlib import closing\n"
            'DB_PATH = "app.db"\n'
            "def find_users(username: str) -> list:\n"
            "    with closing(sqlite3.connect(DB_PATH)) as conn:\n"
            "        cursor = conn.cursor()\n"
            "        cursor.execute(f\"SELECT id FROM users WHERE username = '{username}'\")\n"
            "        return cursor.fetchall()\n"
        ),
        "app/sqli_cross_file.py": (
            "from flask import jsonify, request\n"
            "from app.blueprint import bp\n"
            "from app.services.user_queries import find_users\n"
            '@bp.route("/sqli/cross-file", endpoint="sqli_cross_file")\n'
            "def search_users():\n"
            '    username = request.args.get("username", "")\n'
            "    rows = find_users(username)\n"
            "    return jsonify(results=[list(row) for row in rows])\n"
        ),
    }
    f = _one(files)
    assert f["line"] == "app/services/user_queries.py:7"
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0]["file"] == "app/sqli_cross_file.py"
    assert f["taint_chain"][0] == {
        "file": "app/sqli_cross_file.py",
        "line": 7,
        "expr": "find_users(username)",
    }
    assert f["taint_chain"][-1]["file"] == "app/services/user_queries.py"
    # Identity: the helper is not a route handler, so nothing binds, and the
    # finding stays in the helper's file and function.
    assert "route" not in f
    assert f["symbol"] == "find_users"


_SSRF_HELPER = "import requests\ndef fetch(url):\n    return requests.get(url, timeout=5).text\n"
_PATH_HELPER = "def read(path):\n    with open(path) as fh:\n        return fh.read()\n"
_XSS_HELPER = (
    "from markupsafe import Markup\n"
    "def render(name):\n"
    '    return Markup(f"<b>{name}</b>")\n'
)

# Each guarded caller is reported in the helper and never proven across the
# hop; its control, the same view without the guard, is proven (R-pf50 a).
_CROSS_FILE_GUARDS = {
    "membership": (
        "PY_SSRF",
        _SSRF_HELPER,
        'ALLOWED = {"https://a.example/x"}\n',
        (
            '    url = request.args["u"]\n'
            "    if url not in ALLOWED:\n"
            "        abort(400)\n"
        ),
        "    return helpers.fetch(url)\n",
    ),
    "netloc": (
        "PY_SSRF",
        _SSRF_HELPER,
        'from urllib.parse import urlparse\nHOSTS = {"api.example.com"}\n',
        (
            '    url = request.args["u"]\n'
            "    if urlparse(url).netloc not in HOSTS:\n"
            "        abort(400)\n"
        ),
        "    return helpers.fetch(url)\n",
    ),
    "containment": (
        "PY_PATH_TRAVERSAL",
        _PATH_HELPER,
        'import os\nBASE = "/srv/reports"\n',
        (
            '    full = os.path.realpath(os.path.join(BASE, request.args["f"]))\n'
            "    if not full.startswith(BASE + os.sep):\n"
            "        abort(400)\n"
        ),
        "    return helpers.read(full)\n",
    ),
    "escape": (
        "PY_XSS_HTML_SINK",
        _XSS_HELPER,
        "from markupsafe import escape\n",
        '    name = escape(request.args["n"])\n',
        "    return helpers.render(name)\n",
    ),
}


@pytest.mark.parametrize("guard", sorted(_CROSS_FILE_GUARDS))
def test_caller_side_sanitiser_blocks_the_cross_file_proof(guard):
    rule, helper, prelude, guarded, call = _CROSS_FILE_GUARDS[guard]
    _assert_unproven(_in_helper(_flask_cross_file(guarded + call, helper, prelude), rule))


@pytest.mark.parametrize("guard", sorted(_CROSS_FILE_GUARDS))
def test_the_same_view_without_its_guard_proves_across_files(guard):
    rule, helper, prelude, _guarded, call = _CROSS_FILE_GUARDS[guard]
    unguarded = {
        "membership": '    url = request.args["u"]\n',
        "netloc": '    url = request.args["u"]\n',
        "containment": '    full = os.path.realpath(os.path.join(BASE, request.args["f"]))\n',
        "escape": '    name = request.args["n"]\n',
    }[guard]
    f = _in_helper(_flask_cross_file(unguarded + call, helper, prelude), rule)
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0]["file"] == "app/sqli_cross_file.py"


def _fastapi_cross_file(params: str, prelude: str = "") -> dict[str, str]:
    return {
        "app/__init__.py": "",
        "app/services/__init__.py": "",
        "app/services/q.py": (
            "import sqlite3\n"
            "def find(item_id):\n"
            '    cur = sqlite3.connect("db").cursor()\n'
            "    cur.execute(f\"SELECT * FROM items WHERE id = '{item_id}'\")\n"
        ),
        "app/main.py": (
            "from typing import Annotated\n"
            "from fastapi import APIRouter, Depends\n"
            "from app.services.q import find\n"
            "router = APIRouter()\n"
            "def current() -> str:\n"
            '    return "me"\n'
            f"{prelude}"
            '@router.get("/items")\n'
            f"def read_item({params}):\n"
            "    return find(item_id)\n"
        ),
    }


@pytest.mark.parametrize(
    "params",
    [
        "item_id: int = 0",
        "item_id: str = Depends(current)",
        "item_id: Annotated[str, Depends(current)]",
    ],
)
def test_fastapi_param_the_rule_set_excludes_does_not_prove_across_files(params):
    # R-pf50 b: the caller's sources are `route_param_sources`.
    _assert_unproven(_one(_fastapi_cross_file(params)))


def test_param_typed_by_a_dependency_alias_does_not_prove_across_files():
    # Only the module-aware rules of `route_param_sources` know the alias;
    # the signature alone (`route_param_source_names`) takes it for a source.
    alias = "Current = Annotated[str, Depends(current)]\n"
    files = _fastapi_cross_file("item_id: Current", prelude=alias)
    func = next(
        n
        for n in ast.walk(ast.parse(files["app/main.py"]))
        if isinstance(n, ast.FunctionDef) and n.name == "read_item"
    )
    assert "item_id" in route_param_source_names(func)
    _assert_unproven(_one(files))


def test_flask_param_its_url_does_not_name_does_not_prove_across_files():
    # A plain default the URL pattern does not name is the developer's value.
    helper = (
        "import subprocess\n"
        "def ping(host):\n"
        '    return subprocess.run(f"ping -c 1 {host}", shell=True).stdout\n'
    )
    files = _flask_cross_file("    return helpers.ping(host)\n", helper)
    files["app/sqli_cross_file.py"] = files["app/sqli_cross_file.py"].replace(
        "def view():", 'def view(host="localhost"):'
    )
    _assert_unproven(_in_helper(files, "PY_SUBPROCESS_SHELL"))
    named = dict(files)
    named["app/sqli_cross_file.py"] = files["app/sqli_cross_file.py"].replace(
        '@bp.route("/x"', '@bp.route("/x/<host>"'
    )
    assert _in_helper(named, "PY_SUBPROCESS_SHELL").get("reachable") is True


def test_fastapi_str_param_proves_across_files():
    f = _one(_fastapi_cross_file('item_id: str = ""'))
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0] == {"file": "app/main.py", "line": 9, "expr": "find(item_id)"}


def test_keyword_only_helper_parameter_proves_by_keyword_across_files():
    helper = (
        "import subprocess\n"
        "def ping(count, *, host):\n"
        '    return subprocess.run(f"ping -c {count} {host}", shell=True).stdout\n'
    )
    body = '    host = request.args["h"]\n    return helpers.ping(1, host=host)\n'
    f = _one(_flask_cross_file(body, helper), "PY_SUBPROCESS_SHELL")
    assert f.get("reachable") is True, f
    # The positional slot after `count` is never the keyword-only `host`.
    body = '    return helpers.ping(1, request.args["h"])\n'
    _assert_unproven(_one(_flask_cross_file(body, helper), "PY_SUBPROCESS_SHELL"))


def test_a_method_is_not_proven_by_an_imported_function_call():
    # R-pf50 c: `helpers.ping(...)` names the module-level `ping`; the method
    # `Pinger.ping` of the same module is never matched by it, nor is a
    # method whose caller is `self.ping(...)`.
    helper = (
        "import subprocess\n"
        "class Pinger:\n"
        "    def ping(self, host):\n"
        '        return subprocess.run(f"ping -c 1 {host}", shell=True).stdout\n'
        "    def run(self, host):\n"
        "        return self.ping(host)\n"
    )
    # Two arguments, so the method's `host` (index 1, after `self`) lines up
    # with a tainted positional argument: only the module-level rule keeps it
    # from matching.
    body = '    return helpers.ping("x", request.args["h"])\n'
    _assert_unproven(_one(_flask_cross_file(body, helper), "PY_SUBPROCESS_SHELL"))


def test_module_attribute_call_proves_a_module_level_function():
    helper = (
        "import subprocess\n"
        "def ping(host):\n"
        '    return subprocess.run(f"ping -c 1 {host}", shell=True).stdout\n'
    )
    body = '    return helpers.ping(request.args["h"])\n'
    f = _one(_flask_cross_file(body, helper), "PY_SUBPROCESS_SHELL")
    assert f.get("reachable") is True, f
    assert f["taint_chain"][0] == {
        "file": "app/sqli_cross_file.py",
        "line": 6,
        "expr": "request.args['h']",
    }


def test_a_same_file_caller_still_comes_first():
    # A helper with both a same-file and a cross-file tainted caller keeps the
    # same-file chain (Task 3.0), unchanged.
    helper = (
        "import subprocess\n"
        "from flask import request\n"
        "def ping(host):\n"
        '    return subprocess.run(f"ping -c 1 {host}", shell=True).stdout\n'
        "def local_view():\n"
        '    return ping(request.args["local"])\n'
    )
    body = '    return helpers.ping(request.args["h"])\n'
    f = _one(_flask_cross_file(body, helper), "PY_SUBPROCESS_SHELL")
    assert f["taint_chain"][0]["file"] == "app/services/helpers.py"


# -- fix round 1 (R-pf57 and minors) ------------------------------------------

_SQL_HELPER = (
    "import sqlite3\n"
    "def find(name):\n"
    "    sqlite3.connect('d').execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
)


def _pkg(files: dict[str, str]) -> dict[str, str]:
    out = dict(files)
    for rel in files:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault("/".join(parts[:i] + ["__init__.py"]), "")
    return out


def _sqli_in(files: dict[str, str], helper: str) -> dict:
    found = [
        f
        for f in _rule(_scan(files), "PY_SQL_INJECTION")
        if f["line"].startswith(helper + ":")
    ]
    assert len(found) == 1, found
    return found[0]


def test_a_test_file_caller_does_not_prove_the_helper():
    files = _pkg(
        {
            "app/services/h.py": _SQL_HELPER,
            "tests/test_h.py": (
                "from django.test import RequestFactory\n"
                "from app.services.h import find\n"
                "def test_find():\n"
                "    request = RequestFactory().get('/?n=x')\n"
                "    find(request.GET['n'])\n"
            ),
        }
    )
    _assert_unproven(_sqli_in(files, "app/services/h.py"))


def test_a_function_local_import_decides_which_helper_a_call_proves():
    views = (
        "from flask import Flask, request\n"
        "from app.services.h import find\n"
        "app = Flask(__name__)\n"
        "def other():\n"
        "    from app.legacy.h import find\n"
        "    return find('c')\n"
        "@app.route('/x')\n"
        "def v():\n"
        "    return find(request.args['n'])\n"
    )
    files = _pkg(
        {"app/services/h.py": _SQL_HELPER, "app/legacy/h.py": _SQL_HELPER, "app/views.py": views}
    )
    assert _sqli_in(files, "app/services/h.py").get("reachable") is True
    _assert_unproven(_sqli_in(files, "app/legacy/h.py"))


_DJANGO_URLS = (
    "from django.urls import path\n"
    "from app import views\n"
    "urlpatterns = [path('x/', views.v)]\n"
)


def test_a_template_built_from_request_input_does_not_prove_xss_across_files():
    # The HTML response sink traces without template sources (that page is
    # PY_SSTI's); a caller in another module is judged by the same rule as a
    # same-file caller, so neither proves the XSS.
    respond = (
        "from django.http import HttpResponse\n"
        "def respond(tpl):\n"
        "    return HttpResponse(tpl.render({}))\n"
    )
    cross = _pkg(
        {
            "app/services/r.py": respond,
            "app/views.py": (
                "from django.template import Template\n"
                "from app.services.r import respond\n"
                "def v(request):\n"
                "    return respond(Template(request.GET['t']))\n"
            ),
            "app/urls.py": _DJANGO_URLS,
        }
    )
    same = _pkg(
        {
            "app/views.py": (
                "from django.template import Template\n"
                + respond
                + "def v(request):\n"
                + "    return respond(Template(request.GET['t']))\n"
            ),
            "app/urls.py": _DJANGO_URLS,
        }
    )
    for files in (cross, same):
        [xss] = _rule(_scan(files), "PY_XSS_HTML_SINK")
        _assert_unproven(xss)
        assert _rule(_scan(files), "PY_SSTI")[0].get("reachable") is True


def test_a_failure_in_the_call_index_never_stops_the_helper_files_visit(monkeypatch):
    from analyzers.call_index import ProjectCallIndex

    def boom(self, rel):
        raise RuntimeError("caller unreadable")

    monkeypatch.setattr(ProjectCallIndex, "_caller", boom)
    helper = _SQL_HELPER + "def later(cmd):\n    import os\n    os.system('ls ' + cmd)\n"
    files = _pkg(
        {
            "app/services/h.py": helper,
            "app/views.py": (
                "from flask import Flask, request\n"
                "from app.services.h import find\n"
                "app = Flask(__name__)\n"
                "@app.route('/x')\n"
                "def v():\n"
                "    return find(request.args['n'])\n"
            ),
        }
    )
    findings = _scan(files)
    _assert_unproven(_sqli_in(files, "app/services/h.py"))
    assert _rule(findings, "PY_OS_SYSTEM"), findings


def test_a_helper_that_is_also_a_django_view_binds_its_route_once_proven():
    # R-pf31: newly proven, it takes the urlconf's route, whose file then
    # identifies it (the CHANGELOG says so).
    files = _pkg(
        {
            "app/services/q.py": (
                "import sqlite3\n"
                "def find(request, name):\n"
                "    sqlite3.connect('d').execute(f\"SELECT {name}\")\n"
            ),
            "app/views.py": (
                "from app.services.q import find\n"
                "def v(request):\n"
                "    return find(request, request.GET['n'])\n"
            ),
            "app/urls.py": (
                "from django.urls import path\n"
                "from app import views\n"
                "from app.services import q\n"
                "urlpatterns = [path('x/', views.v), path('y/', q.find)]\n"
            ),
        }
    )
    f = _sqli_in(files, "app/services/q.py")
    assert f.get("reachable") is True
    assert f["taint_chain"][0]["file"] == "app/views.py"
    assert f["route"]["file"] == "app/urls.py"
