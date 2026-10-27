"""Task 3.8: the project call index behind the cross-file helper hop.

`ProjectCallIndex.build(root, route_table)` reads every Python file once and
records, for each call into a module of the project, the caller's file, scope
and arguments. `tainted_args(module, function, index, name)` answers the
one-hop question the same-file hop answers within a file: which callers pass
request input to that parameter. Each answer is a `CallSiteLink` in the
caller's file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from analyzers import ast_analyzer, call_index
from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.call_index import CallSiteLink, ProjectCallIndex

_QUERY = """\
def find(name):
    return "SELECT * FROM t WHERE n = '%s'" % name
"""


def _index(tmp_path: Path, files: dict[str, str]) -> ProjectCallIndex:
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    routes = ASTAnalyzer(str(tmp_path))._build_route_index(tmp_path)
    return ProjectCallIndex.build(tmp_path, routes)


def _package(files: dict[str, str]) -> dict[str, str]:
    """`files` with an empty `__init__.py` in every directory holding one."""
    out = dict(files)
    for rel in files:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.setdefault("/".join(parts[:i] + ["__init__.py"]), "")
    return out


# -- the shapes the brief names ------------------------------------------------


def test_from_import_call_with_request_arg_is_tainted(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from flask import request\n"
                    "from app.services.q import find\n"
                    "def view():\n"
                    '    return find(request.args["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == [
        CallSiteLink(file="app/views.py", line=4, expr="request.args['n']")
    ]


def test_module_attr_call_is_resolved(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from app.services import q\n"
                    "def view(request):\n"
                    '    name = request.GET["n"]\n'
                    "    return q.find(name)\n"
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == [
        CallSiteLink(file="app/views.py", line=4, expr="q.find(name)")
    ]


def test_route_param_argument_is_tainted(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/main.py": (
                    "from fastapi import APIRouter\n"
                    "from app.services.q import find\n"
                    "router = APIRouter()\n"
                    '@router.get("/u")\n'
                    'def view(name: str = ""):\n'
                    "    return find(name)\n"
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == [
        CallSiteLink(file="app/main.py", line=6, expr="find(name)")
    ]


@pytest.mark.parametrize(
    "params",
    [
        "item_id: int = 0",
        "item_id: str = Depends(current)",
        "item_id: Annotated[str, Depends(current)]",
    ],
)
def test_route_param_the_full_rule_set_excludes_is_not_tainted(tmp_path, params):
    # R-pf50 b: the caller's sources are `route_param_sources`, the whole rule
    # set: a coerced scalar or an injected dependency is not request text.
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/main.py": (
                    "from typing import Annotated\n"
                    "from fastapi import APIRouter, Depends\n"
                    "from app.services.q import find\n"
                    "router = APIRouter()\n"
                    "def current() -> str:\n"
                    '    return "me"\n'
                    '@router.get("/u")\n'
                    f"def view({params}):\n"
                    "    return find(item_id)\n"
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


def test_constant_argument_is_not_tainted(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from flask import request\n"
                    "from app.services.q import find\n"
                    "def view():\n"
                    '    request.args["n"]\n'
                    '    return find("admin")\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


def test_same_name_function_in_other_module_is_not_confused(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/other.py": _QUERY,
                "app/views.py": (
                    "from flask import request\n"
                    "from app.other import find\n"
                    "def view():\n"
                    '    return find(request.args["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []
    assert len(index.tainted_args("app.other", "find", 0, "name")) == 1


def test_two_hops_are_not_followed(tmp_path):
    # views -> a.helper -> b.sink: the index answers one hop. `helper`'s own
    # parameter is not request input, so `sink` has no tainted caller. This
    # is the documented limit.
    index = _index(
        tmp_path,
        _package(
            {
                "app/b.py": "def sink(value):\n    return value\n",
                "app/a.py": (
                    "from app.b import sink\n"
                    "def helper(x):\n"
                    "    return sink(x)\n"
                ),
                "app/views.py": (
                    "from flask import request\n"
                    "from app.a import helper\n"
                    "def view():\n"
                    '    return helper(request.args["x"])\n'
                ),
            }
        ),
    )
    assert len(index.tainted_args("app.a", "helper", 0, "x")) == 1
    assert index.tainted_args("app.b", "sink", 0, "value") == []


# -- import forms --------------------------------------------------------------


@pytest.mark.parametrize(
    "imports, call",
    [
        ("from app.services.q import find as lookup\n", "lookup(n)"),
        ("import app.services.q as qm\n", "qm.find(n)"),
        ("import app.services.q\n", "app.services.q.find(n)"),
        ("from .services.q import find\n", "find(n)"),
        ("from .services import q\n", "q.find(n)"),
        ("from . import services\n", "services.q.find(n)"),
    ],
)
def test_every_import_form_resolves(tmp_path, imports, call):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    f"{imports}"
                    "def view(request):\n"
                    '    n = request.GET["n"]\n'
                    f"    return {call}\n"
                ),
            }
        ),
    )
    assert [link.file for link in index.tainted_args("app.services.q", "find", 0, "name")] == [
        "app/views.py"
    ]


def test_relative_import_climbs_from_the_files_package(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/web/views.py": (
                    "from ..services.q import find\n"
                    "def view(request):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert len(index.tainted_args("app.services.q", "find", 0, "name")) == 1


def test_unimported_bare_call_is_not_resolved(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "def find(name):\n"
                    "    return name\n"
                    "def view(request):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


def test_a_local_binding_shadows_the_import(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request, find):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


# -- parameters ------------------------------------------------------------------


def test_keyword_argument_matches_a_positional_parameter(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": "def find(a, name):\n    return name\n",
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    return find("x", name=request.GET["n"])\n'
                ),
            }
        ),
    )
    assert len(index.tainted_args("app.services.q", "find", 1, "name")) == 1
    assert index.tainted_args("app.services.q", "find", 0, "a") == []


def test_keyword_only_parameter_matches_by_keyword_alone(tmp_path):
    # A negative index stands for a keyword-only parameter (R-pf50 c): the
    # positional argument at any index is not it.
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": "def find(a, *, name):\n    return name\n",
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    n = request.GET["n"]\n'
                    "    find(n, name=n)\n"
                    '    find(n, name="x")\n'
                    '    find("x", n)\n'
                ),
            }
        ),
    )
    # Line 6 passes `n` in the slot after `a`, which a keyword-only `name`
    # never takes.
    assert [link.line for link in index.tainted_args("app.services.q", "find", -1, "name")] == [4]


def test_arguments_are_matched_as_the_same_file_hop_matches_them(tmp_path):
    # One rule for both hops (`_call_argument`): the positional argument at
    # the parameter's index as written, `*args` included, else the keyword.
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": "def find(a, name):\n    return name\n",
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    "    rest = ['x']\n"
                    '    return find(*rest, request.GET["n"])\n'
                ),
            }
        ),
    )
    assert [link.line for link in index.tainted_args("app.services.q", "find", 1, "name")] == [4]
    assert index.tainted_args("app.services.q", "find", 0, "a") == []


def test_method_of_a_class_in_the_module_is_not_a_module_function(tmp_path):
    # `q.Store.find(x)` names a class attribute, never the module-level
    # function `find` (R-pf50 c).
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": (
                    "class Store:\n"
                    "    @staticmethod\n"
                    "    def find(name):\n"
                    "        return name\n"
                ),
                "app/views.py": (
                    "from app.services import q\n"
                    "def view(request):\n"
                    '    return q.Store.find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


# -- which assignment counts, and sanitisers in the caller (R-pf50 a) ------------


def test_a_constant_reassigned_before_the_call_is_not_tainted(tmp_path):
    # The same-file hop's rule: the last assignment before the call decides.
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    n = request.GET["n"]\n'
                    '    n = "admin"\n'
                    "    return find(n)\n"
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


def test_a_membership_guard_in_the_caller_proves_nothing(tmp_path):
    caller = (
        "from flask import request, abort\n"
        "from app.services.q import find\n"
        'ALLOWED = {"a", "b"}\n'
        "def view():\n"
        '    n = request.args["n"]\n'
        "GUARD"
        "    return find(n)\n"
    )
    guard = "    if n not in ALLOWED:\n        abort(400)\n"
    guarded = _index(
        tmp_path / "guarded",
        _package({"app/services/q.py": _QUERY, "app/views.py": caller.replace("GUARD", guard)}),
    )
    assert guarded.tainted_args("app.services.q", "find", 0, "name") == []
    control = _index(
        tmp_path / "control",
        _package({"app/services/q.py": _QUERY, "app/views.py": caller.replace("GUARD", "")}),
    )
    assert len(control.tainted_args("app.services.q", "find", 0, "name")) == 1


def test_a_call_inside_a_comprehension_needs_the_request_value_inline(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    n = request.GET["n"]\n'
                    "    a = [find(n) for _ in range(2)]\n"
                    '    b = [find(request.GET["m"]) for _ in range(2)]\n'
                ),
            }
        ),
    )
    assert [link.line for link in index.tainted_args("app.services.q", "find", 0, "name")] == [5]


# -- module resolution: scan root and suffixes ----------------------------------


def test_src_layout_resolves_through_a_unique_suffix(tmp_path):
    # Scanned from the repository root: the module is `src.app.services.q`,
    # but the code imports `app.services.q`.
    index = _index(
        tmp_path,
        _package(
            {
                "src/app/services/q.py": _QUERY,
                "src/app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert len(index.tainted_args("src.app.services.q", "find", 0, "name")) == 1


def test_an_ambiguous_suffix_resolves_nothing(tmp_path):
    # Two scanned modules end in `app.services.q`: an import of it names
    # neither.
    files = _package(
        {
            "one/app/services/q.py": _QUERY,
            "two/app/services/q.py": _QUERY,
            "one/app/views.py": (
                "from app.services.q import find\n"
                "def view(request):\n"
                '    return find(request.GET["n"])\n'
            ),
        }
    )
    index = _index(tmp_path, files)
    assert index.tainted_args("one.app.services.q", "find", 0, "name") == []
    assert index.tainted_args("two.app.services.q", "find", 0, "name") == []


def test_a_suffix_that_is_another_scanned_module_is_not_claimed(tmp_path):
    # `app/services/q.py` IS `app.services.q`; `src/app/services/q.py` only
    # ends with it, so the import names the former alone.
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "src/app/services/q.py": _QUERY,
                "app/views.py": (
                    "from app.services.q import find\n"
                    "def view(request):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert len(index.tainted_args("app.services.q", "find", 0, "name")) == 1
    assert index.tainted_args("src.app.services.q", "find", 0, "name") == []


def test_a_single_component_suffix_is_never_tried(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/q.py": _QUERY,
                "app/views.py": (
                    "from q import find\n"
                    "def view(request):\n"
                    '    return find(request.GET["n"])\n'
                ),
            }
        ),
    )
    assert index.tainted_args("app.q", "find", 0, "name") == []


def test_module_of_names_a_package_by_its_directory():
    assert ProjectCallIndex.module_of("app/services/q.py") == "app.services.q"
    assert ProjectCallIndex.module_of("app/services/__init__.py") == "app.services"


# -- one parse per file -----------------------------------------------------------


def test_the_analyzer_parses_each_file_once(tmp_path, monkeypatch):
    for rel, content in _package(
        {
            "app/services/q.py": _QUERY,
            "app/views.py": (
                "from app.services.q import find\n"
                "def view(request):\n"
                '    return find(request.GET["n"])\n'
            ),
        }
    ).items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    parsed: list[str] = []
    real_parse = ast.parse

    def counting_parse(source, filename="<unknown>", *args, **kwargs):
        parsed.append(str(filename))
        return real_parse(source, filename, *args, **kwargs)

    # The route pass (route_extractor) parses on its own, as it did before;
    # count the taint analyzer's parses: the index's and _analyze_python's.
    monkeypatch.setattr(ast_analyzer.ast, "parse", counting_parse)
    ASTAnalyzer(str(tmp_path)).run(lambda _f: None)
    analyzed = [p for p in parsed if p.endswith(".py")]
    assert sorted(analyzed) == sorted(set(analyzed)), analyzed
    assert len(analyzed) == 4  # q.py, views.py and two __init__.py


# -- fix round 1: bounded memory, test callers, scoped imports (R-pf57) --------


def _views(n: int, call: str = 'find(request.GET["n"])') -> dict[str, str]:
    files = {"app/services/q.py": _QUERY}
    for i in range(n):
        files[f"app/views/v{i}.py"] = (
            "from app.services.q import find\n"
            "def view(request):\n"
            f"    return {call}\n"
        )
    return _package(files)


def test_no_tree_is_kept_for_a_call_site(tmp_path, monkeypatch):
    # A record is the caller's file, the call's span and per-argument flags;
    # with no reuse budget, building keeps no parsed module at all.
    monkeypatch.setattr(call_index, "_PARSE_CACHE_MAX_BYTES", 0)
    index = _index(tmp_path, _views(3))
    assert index._reusable == {}
    assert index._callers == {}
    sites = index._sites[("app.services.q", "find")]
    assert len(sites) == 3
    assert all(not isinstance(v, ast.AST) for site in sites for v in vars(site).values())


def test_the_first_proving_caller_is_the_only_one_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(call_index, "_PARSE_CACHE_MAX_BYTES", 0)
    index = _index(tmp_path, _views(5))
    links = index.tainted_args("app.services.q", "find", 0, "name", first=True)
    assert [link.file for link in links] == ["app/views/v0.py"]
    assert list(index._callers) == ["app/views/v0.py"]


def test_the_caller_cache_is_bounded_and_an_evicted_caller_is_parsed_again(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(call_index, "_PARSE_CACHE_MAX_BYTES", 0)
    monkeypatch.setattr(call_index, "_CALLER_CACHE_MAX_BYTES", 1)
    index = _index(tmp_path, _views(3))
    parsed: list[str] = []
    real_parse = ast.parse

    def counting_parse(source, filename="<unknown>", *args, **kwargs):
        parsed.append(Path(str(filename)).name)
        return real_parse(source, filename, *args, **kwargs)

    monkeypatch.setattr(call_index.ast, "parse", counting_parse)
    links = index.tainted_args("app.services.q", "find", 0, "name")
    assert len(links) == 3
    # Over the cap only the latest caller stays.
    assert list(index._callers) == ["app/views/v2.py"]
    assert index._caller_bytes == index._callers["app/views/v2.py"].size
    assert parsed == ["v0.py", "v1.py", "v2.py"]
    # v0.py was evicted: a new query parses it again and still proves it.
    again = index.tainted_args("app.services.q", "find", 0, "name", skip_template_sources=True)
    assert [link.file for link in again] == [link.file for link in links]
    assert parsed[3:] == ["v0.py", "v1.py", "v2.py"]


def test_the_reuse_cache_stops_at_its_budget(tmp_path, monkeypatch):
    files = _views(4)
    files["app/services/q.py"] = (
        "import sqlite3\n"
        "def find(name):\n"
        "    sqlite3.connect('d').execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
    )
    one = len(files["app/views/v0.py"])
    monkeypatch.setattr(call_index, "_PARSE_CACHE_MAX_BYTES", 2 * one)
    index = _index(tmp_path, files)
    assert index._reusable_bytes <= 2 * one
    assert len(index._reusable) == 2
    # The analyzer still reports and proves the helper with the rest parsed
    # by `_analyze_python`.
    findings = []
    ASTAnalyzer(str(tmp_path)).run(findings.append)
    [sqli] = [f for f in findings if f["rule_id"] == "python.ast/PY_SQL_INJECTION"]
    assert sqli.get("reachable") is True


def test_a_test_file_is_never_a_caller(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/q.py": _QUERY,
                "tests/test_q.py": (
                    "from django.test import RequestFactory\n"
                    "from app.services.q import find\n"
                    "def test_find():\n"
                    "    request = RequestFactory().get('/?n=x')\n"
                    "    find(request.GET['n'])\n"
                ),
                "app/conftest.py": (
                    "from app.services.q import find\n"
                    "def helper(request):\n"
                    "    return find(request.GET['n'])\n"
                ),
            }
        ),
    )
    assert index.tainted_args("app.services.q", "find", 0, "name") == []


_LEGACY = {"app/services/h.py": _QUERY, "app/legacy/h.py": _QUERY}


def test_a_function_local_import_binds_only_inside_that_function(tmp_path):
    # Module-level import -> app.services.h; the local import in `other` does
    # not leak into `view`.
    index = _index(
        tmp_path,
        _package(
            {
                **_LEGACY,
                "app/views.py": (
                    "from app.services.h import find\n"
                    "def other():\n"
                    "    from app.legacy.h import find\n"
                    "    return find('c')\n"
                    "def view(request):\n"
                    "    return find(request.GET['n'])\n"
                ),
            }
        ),
    )
    assert [link.line for link in index.tainted_args("app.services.h", "find", 0, "name")] == [6]
    assert index.tainted_args("app.legacy.h", "find", 0, "name") == []


def test_a_function_local_import_shadows_the_module_import_inside_it(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                **_LEGACY,
                "app/views.py": (
                    "from app.services.h import find\n"
                    "def view(request):\n"
                    "    from app.legacy.h import find\n"
                    "    return find(request.GET['n'])\n"
                    "def other():\n"
                    "    return find('c')\n"
                ),
            }
        ),
    )
    assert [link.line for link in index.tainted_args("app.legacy.h", "find", 0, "name")] == [4]
    assert index.tainted_args("app.services.h", "find", 0, "name") == []


def test_the_template_source_rule_is_part_of_the_query(tmp_path):
    index = _index(
        tmp_path,
        _package(
            {
                "app/services/r.py": "def respond(tpl):\n    return tpl\n",
                "app/views.py": (
                    "from django.template import Template\n"
                    "from app.services.r import respond\n"
                    "def v(request):\n"
                    "    return respond(Template(request.GET['t']))\n"
                ),
            }
        ),
    )
    args = ("app.services.r", "respond", 0, "tpl")
    assert index.tainted_args(*args, skip_template_sources=True) == []
    assert len(index.tainted_args(*args)) == 1
    assert index.tainted_args(*args, skip_template_sources=True, first=True) == []


def test_a_failure_while_proving_proves_nothing(tmp_path, monkeypatch):
    index = _index(tmp_path, _views(2))

    def boom(self, rel):
        raise RuntimeError("caller unreadable")

    monkeypatch.setattr(ProjectCallIndex, "_caller", boom)
    assert index.tainted_args("app.services.q", "find", 0, "name") == []
