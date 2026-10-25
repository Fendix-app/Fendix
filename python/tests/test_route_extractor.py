"""Tests for the route extractor (Proven Path v1)."""

from __future__ import annotations

import pytest

from analyzers.route_extractor import extract_routes


def test_flask_route_decorator():
    src = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/users/<id>", methods=["GET", "POST"])
def get_user(id):
    return id
'''
    table = extract_routes(src, "app.py")
    assert len(table.routes) == 1
    r = table.routes[0]
    assert r.pattern == "/users/<id>"
    assert r.method == "GET"  # first method in the list
    assert r.handler == "get_user"
    # The finding's enclosing function name binds to this route.
    bound = table.for_function("get_user")
    assert bound is not None and bound.pattern == "/users/<id>"


def test_flask_route_without_methods_is_any():
    src = '''
@app.route("/health")
def health():
    return "ok"
'''
    r = extract_routes(src, "app.py").routes[0]
    assert r.method == ""  # no methods= → unknown/any
    assert r.pattern == "/health"


def test_fastapi_verb_decorators():
    src = '''
from fastapi import FastAPI
app = FastAPI()
router = APIRouter()

@app.get("/items/{item_id}")
async def read_item(item_id: int):
    return item_id

@router.post("/items")
def create_item(body):
    return body
'''
    table = extract_routes(src, "api.py")
    methods = {r.handler: r.method for r in table.routes}
    assert methods == {"read_item": "GET", "create_item": "POST"}
    assert table.for_function("read_item").pattern == "/items/{item_id}"


def test_django_path_and_re_path():
    src = '''
from django.urls import path, re_path
from . import views

urlpatterns = [
    path("users/<int:id>", views.get_user),
    re_path(r"^orders/(?P<oid>\\d+)$", views.get_order),
    path("admin/", include("admin.urls")),  # include — must be skipped
]
'''
    table = extract_routes(src, "urls.py")
    handlers = {r.handler for r in table.routes}
    assert handlers == {"views.get_user", "views.get_order"}
    # Binding uses the final symbol component.
    assert table.for_function("get_user").pattern == "users/<int:id>"
    assert table.for_function("get_order") is not None
    # include() route is not emitted.
    assert all("include" not in r.handler for r in table.routes)


def test_blueprint_route():
    src = '''
bp = Blueprint("api", __name__)

@bp.route("/login", methods=["POST"])
def login():
    pass
'''
    r = extract_routes(src, "auth.py").routes[0]
    assert r.pattern == "/login" and r.method == "POST" and r.handler == "login"


def test_non_route_decorators_ignored():
    src = '''
@staticmethod
@functools.lru_cache()
@app.before_request
def not_a_route():
    pass
'''
    assert extract_routes(src, "x.py").routes == []


def test_syntax_error_returns_empty():
    assert extract_routes("def (((", "broken.py").routes == []


def test_as_dict_shape():
    src = '@app.get("/x")\ndef h(): pass\n'
    d = extract_routes(src, "a.py").routes[0].as_dict()
    assert set(d) == {"method", "pattern", "handler", "file", "line"}
    assert d["file"] == "a.py" and d["pattern"] == "/x"


def test_decorator_route_has_no_handler_modules():
    # A decorator route's handler is the decorated def in its own file.
    r = extract_routes('@app.get("/x")\ndef h(): pass\n', "a.py").routes[0]
    assert r.handler_modules == ()


@pytest.mark.parametrize(
    "rel, imports, view, func, modules",
    [
        ("config/urls.py", "from app.views import a\n", "a.search", "search", ("app.views.a",)),
        ("config/urls.py", "from app import views\n", "views.search", "search", ("app.views",)),
        ("config/urls.py", "import app.views\n", "app.views.search", "search", ("app.views",)),
        ("config/urls.py", "import app.views as v\n", "v.search", "search", ("app.views",)),
        ("config/urls.py", "from app.views import search as s\n", "s", "search", ("app.views",)),
        ("app/urls.py", "from . import views\n", "views.search", "search", ("app.views",)),
        ("app/urls.py", "from .views import search\n", "search", "search", ("app.views",)),
        ("app/sub/urls.py", "from ..views import search\n", "search", "search", ("app.views",)),
        ("urls.py", "from . import views\n", "views.search", "search", ("views",)),
        ("app/__init__.py", "from .views import search\n", "search", "search", ("app.views",)),
        # Not imported: defined in the urlconf itself, or from a star import.
        ("app/urls.py", "from app.views import *\n", "search", "search", ("app.urls", "app.views")),
        # A head nothing imports is taken as written.
        ("app/urls.py", "", "views.search", "search", ("views",)),
        # A relative import above the scan root resolves to nothing.
        ("urls.py", "from .. import views\n", "views.search", "search", ("views",)),
    ],
)
def test_django_view_module_resolves_through_imports(rel, imports, view, func, modules):
    src = f'from django.urls import path\n{imports}urlpatterns = [path("s/", {view})]\n'
    [r] = extract_routes(src, rel).routes
    assert r.handler == view  # reported as written
    assert r.handler_func == func
    assert r.handler_modules == modules


def test_routes_for_function_keeps_every_same_named_route():
    src = '''
from django.urls import path
from app.views import a, b
urlpatterns = [path("a/", a.search), path("b/", b.search)]
'''
    table = extract_routes(src, "config/urls.py")
    assert [r.pattern for r in table.routes_for_function("search")] == ["a/", "b/"]
    # for_function keeps its first-wins answer.
    assert table.for_function("search").pattern == "a/"
    assert table.routes_for_function("missing") == []


@pytest.mark.parametrize(
    "imports, view, resolved",
    [
        ("from app import views\n", "views.show", True),
        ("", "show", True),  # bare: defined in the urlconf, or star imported
        ("", "self.show", False),  # nothing binds `self`
        ("", "views.show", False),
    ],
)
def test_django_view_head_resolution_is_recorded(imports, view, resolved):
    src = f'from django.urls import path\n{imports}urlpatterns = [path("s/", {view})]\n'
    [r] = extract_routes(src, "app/urls.py").routes
    assert r.handler_resolved is resolved
