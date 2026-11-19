"""Round 4b: a guard ends control flow only when termination is PROVEN, a sink in
the guard's own body is never covered, and a tuple assignment evaluates its
right side before it binds (redteam4-py-01, DE4-08).

redteam4-py-01. A guard `if ".." in name or os.path.isabs(name): <body>` used to
count when its body "ended control flow" by the terminal NAME of a call
(`abort`, `exit`, `sys_exit`). A project's own `def abort(code): print(code)`,
`log.exit()` on any object, and a sink written inside the guard's own body all
suppressed a real path traversal. Termination is now proven from what the callee
is: `return`, `raise`, a known raising or exiting function resolved through the
file's imports (`sys.exit`, `flask.abort`, `os._exit`), the `exit`/`quit`
builtins nothing rebinds, or a function this file defines whose body ends
control flow on every path. The same rule serves every guard type.

DE4-08. `name, other = other, name` bound `name` to the NEW `other`, which reads
the guarded `name`: the swap hid a tainted value behind a guard. A tuple
assignment now takes its right-hand names at the binding in effect before the
statement, and rebinding a name keeps the value it held for every earlier
binding that reads it (alias-then-rebind).
"""

from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

import pytest

from analyzers.ast_analyzer import ASTAnalyzer

PT = "SEC-PY_PATH_TRAVERSAL"

_NO_ABORT_HEAD = (
    "import os\n"
    "import sys\n"
    "import logging\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "log = logging.getLogger('x')\n"
    "ALLOWED = {'a', 'b'}\n"
)
_FLASK_ABORT = "from flask import abort\n"


# OR-88 (CL2-1): a sink a recognised containment guard covers is reported at WARN,
# naming the guard (the `fix` text starts `_LOWERED_MARK`), not removed.
#   old `_rules`: the id of every finding
#   new `_rules`: the id of every finding that is not lowered by a guard, so a test
#                 that says a guard "covers" the sink (`PT not in _rules(...)`) keeps
#                 its meaning; `_lowered` is exactly the lowered ones.
_LOWERED_MARK = "A path-containment guard"


def _findings(src: str) -> list[dict]:
    findings: list[dict] = []
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "app.py").write_text(src)
        ASTAnalyzer(d, "python").run(findings.append)
    return findings


def _rules(src: str) -> set[str]:
    return {f["id"] for f in _findings(src) if not f.get("fix", "").startswith(_LOWERED_MARK)}


def _lowered(src: str) -> list[dict]:
    return [f for f in _findings(src) if f.get("fix", "").startswith(_LOWERED_MARK)]


def _all_ids(src: str) -> set[str]:
    """The id of EVERY finding, lowered ones included: a sink that is not reported at all."""
    return {f["id"] for f in _findings(src)}


# F-C6 (CL3): `PT not in _rules(...)` cannot tell a finding LOWERED by a guard from one
# REMOVED, because `_rules` leaves the lowered ones out. Each such assertion is paired with
# the OR-88 one that applies. Where a recognised containment guard covers the sink, the
# finding is still reported, lowered, with the guard named (`_lowered`). Where none is
# involved, `_all_ids` shows the sink is not reported at all, for this reason: a rejection
# of `..` and absolute names, a membership allow-list, or a store that does not reach the
# sink removes it as it did in v3.7.0 (a sanitiser, or no flow); none of the containment
# recognisers took part (no guard was accepted, checked with `_note_guard`).
_NO_GUARD = "removed, not lowered: no containment guard is involved (a sanitiser or no flow, as in v3.7.0)"


def _app(prelude: str, body: str, head: str = _NO_ABORT_HEAD) -> str:
    lines = textwrap.dedent(body).strip("\n").split("\n")
    return (
        head
        + textwrap.dedent(prelude)
        + "@app.route('/r')\ndef r():\n"
        + "".join("    " + line + "\n" for line in lines)
    )


_TRAVERSAL = """
name = request.args['f']
if '..' in name or os.path.isabs(name):
    {exit}
return open(name).read()
"""

_MEMBERSHIP = """
name = request.args['f']
if name not in ALLOWED:
    {exit}
return open(name).read()
"""


def _guarded(template: str, exit_stmt: str, prelude: str = "", head: str = _NO_ABORT_HEAD) -> str:
    return _app(prelude, template.format(exit=exit_stmt), head)


# (id, exit statement, prelude, head): none of these ends control flow
_NOT_TERMINATING = [
    (
        "user_abort_that_returns",
        "abort(400)",
        "def abort(code):\n    print(code)\n\n",
        _NO_ABORT_HEAD,
    ),
    ("log_exit_method", "log.exit()", "", _NO_ABORT_HEAD),
    ("any_object_abort_method", "log.abort(400)", "", _NO_ABORT_HEAD),
    ("free_abort_name", "abort(400)", "", _NO_ABORT_HEAD),
    ("free_exit_rebound", "exit()", "exit = print\n\n", _NO_ABORT_HEAD),
    (
        "imported_abort_replaced",
        "abort(400)",
        "def abort(code):\n    return None\n\n",
        _NO_ABORT_HEAD + _FLASK_ABORT,
    ),
    (
        "sys_exit_name_from_other_module",
        "sys_exit(1)",
        "",
        _NO_ABORT_HEAD,
    ),
    (
        "local_function_terminates_on_one_path_only",
        "stop(request.args.get('q'))",
        "def stop(q):\n    if q:\n        raise ValueError(q)\n\n",
        _NO_ABORT_HEAD,
    ),
    (
        "local_function_calls_a_returning_function",
        "stop()",
        "def stop():\n    log.exit()\n\n",
        _NO_ABORT_HEAD,
    ),
    ("decorated_local_function", "stop()", "@wrap\ndef stop():\n    raise SystemExit\n\n", _NO_ABORT_HEAD),
    (
        "async_local_function_is_never_run",
        "stop()",
        "async def stop():\n    raise SystemExit\n\n",
        _NO_ABORT_HEAD,
    ),
    ("only_a_pass", "pass", "", _NO_ABORT_HEAD),
]


@pytest.mark.parametrize(
    "label,exit_stmt,prelude,head",
    _NOT_TERMINATING,
    ids=[c[0] for c in _NOT_TERMINATING],
)
@pytest.mark.parametrize("template", [_TRAVERSAL, _MEMBERSHIP], ids=["traversal", "membership"])
def test_a_guard_whose_body_does_not_provably_end_control_flow_protects_nothing(
    template, label, exit_stmt, prelude, head
):
    assert PT in _rules(_guarded(template, exit_stmt, prelude, head)), label


# (id, exit statement, prelude, head): each provably leaves the function
_TERMINATING = [
    ("return", "return 'bad'", "", _NO_ABORT_HEAD),
    ("raise", "raise ValueError('bad')", "", _NO_ABORT_HEAD),
    ("flask_abort", "abort(400)", "", _NO_ABORT_HEAD + _FLASK_ABORT),
    ("flask_module_abort", "flask.abort(400)", "", _NO_ABORT_HEAD + "import flask\n"),
    (
        "werkzeug_abort_aliased",
        "stop(400)",
        "",
        _NO_ABORT_HEAD + "from werkzeug.exceptions import abort as stop\n",
    ),
    ("sys_exit", "sys.exit(1)", "", _NO_ABORT_HEAD),
    ("builtin_exit", "exit(1)", "", _NO_ABORT_HEAD),
    ("builtin_quit", "quit()", "", _NO_ABORT_HEAD),
    ("os_exit", "os._exit(1)", "", _NO_ABORT_HEAD),
    (
        "local_function_that_raises",
        "abort(400)",
        "def abort(code):\n    raise SystemExit(code)\n\n",
        _NO_ABORT_HEAD,
    ),
    (
        "local_function_that_exits_through_sys",
        "stop()",
        "def stop():\n    log.warning('bad')\n    sys.exit(2)\n\n",
        _NO_ABORT_HEAD,
    ),
    (
        "local_function_chain",
        "outer()",
        "def inner():\n    raise SystemExit\n\ndef outer():\n    inner()\n\n",
        _NO_ABORT_HEAD,
    ),
    (
        "local_function_both_branches_end",
        "stop(1)",
        "def stop(c):\n    if c:\n        raise SystemExit\n    else:\n        sys.exit(1)\n\n",
        _NO_ABORT_HEAD,
    ),
    (
        "if_else_both_end_in_the_body",
        "if request.args.get('v'):\n        return 'a'\n    else:\n        raise ValueError",
        "",
        _NO_ABORT_HEAD,
    ),
    (
        "work_then_return",
        "log.warning('bad name')\n    return 'bad'",
        "",
        _NO_ABORT_HEAD,
    ),
]


@pytest.mark.parametrize(
    "label,exit_stmt,prelude,head",
    _TERMINATING,
    ids=[c[0] for c in _TERMINATING],
)
@pytest.mark.parametrize("template", [_TRAVERSAL, _MEMBERSHIP], ids=["traversal", "membership"])
def test_a_guard_whose_body_provably_ends_control_flow_still_protects(
    template, label, exit_stmt, prelude, head
):
    assert PT not in _rules(_guarded(template, exit_stmt, prelude, head)), label
    assert PT not in _all_ids(_guarded(template, exit_stmt, prelude, head)), _NO_GUARD


def test_a_star_import_of_flask_still_supplies_abort():
    head = _NO_ABORT_HEAD + "from flask import *\n"
    assert PT not in _rules(_guarded(_TRAVERSAL, "abort(400)", "", head))
    assert PT not in _all_ids(_guarded(_TRAVERSAL, "abort(400)", "", head)), _NO_GUARD


# ---------------------------------------------------------------------------
# a sink inside the guard's own body is never covered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        # the sink is the first statement of the rejecting body
        """
        name = request.args['f']
        if '..' in name or os.path.isabs(name):
            data = open(name).read()
            raise ValueError(data)
        return 'ok'
        """,
        # the sink is after the terminator's line in the same body
        """
        name = request.args['f']
        if '..' in name or os.path.isabs(name):
            if request.args.get('v'):
                return open(name).read()
            raise ValueError
        return 'ok'
        """,
        # a membership guard, sink in the rejecting body
        """
        name = request.args['f']
        if name not in ALLOWED:
            log.warning(open(name).read())
            raise ValueError
        return 'ok'
        """,
        # the sink is in the (multi-line) test itself
        """
        name = request.args['f']
        if ('..' in name or
                open(name).read() == 'x'):
            raise ValueError
        return 'ok'
        """,
    ],
    ids=["traversal_body", "nested_in_body", "membership_body", "in_the_test"],
)
def test_a_sink_inside_the_guard_is_reported(body):
    head = _NO_ABORT_HEAD + _FLASK_ABORT
    assert PT in _rules(_app("", body, head))


def test_a_sink_in_the_else_of_the_guard_is_covered():
    # the else branch runs only when the rejecting test was False
    head = _NO_ABORT_HEAD + _FLASK_ABORT
    src = _app(
        "",
        """
        name = request.args['f']
        if name not in ALLOWED:
            return 'bad'
        else:
            return open(name).read()
        """,
        head,
    )
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_the_url_host_and_containment_guards_use_the_same_proof():
    head = (
        "import os\nimport requests\nfrom urllib.parse import urlparse\n"
        "from flask import Flask, request\napp = Flask(__name__)\n"
        "HOSTS = {'api.example.com'}\nBASE = '/srv/files'\n"
    )
    host = _app(
        "def abort(code):\n    print(code)\n\n",
        """
        url = request.args['u']
        p = urlparse(url)
        if p.scheme != 'https' or p.netloc not in HOSTS:
            abort(400)
        return requests.get(url).text
        """,
        head,
    )
    assert "SEC-PY_SSRF" in _rules(host)
    contained = _app(
        "def abort(code):\n    print(code)\n\n",
        """
        full = os.path.realpath(os.path.join(BASE, request.args['f']))
        if not full.startswith(BASE + os.sep):
            abort(400)
        return open(full).read()
        """,
        head,
    )
    assert PT in _rules(contained)
    ok = _app(
        "",
        """
        full = os.path.realpath(os.path.join(BASE, request.args['f']))
        if not full.startswith(BASE + os.sep):
            raise ValueError
        return open(full).read()
        """,
        head,
    )
    assert PT not in _rules(ok)
    # OR-88: the recognised guard lowers the finding to a WARN, it does not remove it.
    assert {f["id"] for f in _lowered(ok)} == {PT}
    assert any("startswith" in f["fix"] for f in _lowered(ok)), "the guard is named"


# ---------------------------------------------------------------------------
# DE4-08: tuple assignment and alias-then-rebind
# ---------------------------------------------------------------------------

_G = (
    "name = request.args['f']\n"
    "if '..' in name or os.path.isabs(name):\n"
    "    abort(400)\n"
)
_ABORT_HEAD = _NO_ABORT_HEAD + _FLASK_ABORT


@pytest.mark.parametrize(
    "label,body",
    [
        ("swap", "other = request.args['g']\n" + _G + "name, other = other, name\nreturn open(name).read()"),
        ("swap_with_a_fresh_name", "other = request.args['g']\n" + _G + "name, z = other, name\nreturn open(name).read()"),
        ("take_other_keep_a_constant", "other = request.args['g']\n" + _G + "name, y = other, 1\nreturn open(name).read()"),
        ("list_target", "other = request.args['g']\n" + _G + "[name, other] = [other, name]\nreturn open(name).read()"),
        (
            "unguarded_swap",
            "other = request.args['g']\nname = request.args['f']\nname, other = other, name\nreturn open(name).read()",
        ),
    ],
    ids=lambda c: c if isinstance(c, str) and " " not in c and "\n" not in c else None,
)
def test_a_tuple_assignment_reads_its_right_side_before_it_binds(label, body):
    assert PT in _rules(_app("", body, _ABORT_HEAD)), label


def test_the_control_without_a_swap_stays_guarded():
    ctrl = _app("", "other = request.args['g']\n" + _G + "return open(name).read()", _ABORT_HEAD)
    assert PT not in _rules(ctrl)
    assert PT not in _all_ids(ctrl), _NO_GUARD


def test_a_swap_of_two_route_parameters_is_tracked():
    head = _NO_ABORT_HEAD
    src = (
        head
        + "@app.route('/r/<name>/<other>')\n"
        "def r(name, other):\n"
        "    name, other = other, name\n"
        "    return open(name).read()\n"
    )
    assert PT in _rules(src)
    src = (
        head
        + "@app.route('/r/<name>')\n"
        "def r(name):\n"
        "    base = 'x'\n"
        "    name, base = base, name\n"
        "    return open(base).read()\n"
    )
    assert PT in _rules(src)
    safe = (
        head
        + "@app.route('/r/<name>')\n"
        "def r(name):\n"
        "    base = 'x'\n"
        "    name, base = base, name\n"
        "    return open(name).read()\n"
    )
    assert PT not in _rules(safe)
    assert PT not in _all_ids(safe), _NO_GUARD


@pytest.mark.parametrize(
    "body",
    [
        "name = request.args['f']\nbase = name\nname = 'x'\nreturn open(base).read()",
        "name = request.args['f']\nbase = name\nname += '/ok'\nreturn open(base).read()",
        "name = request.args['f']\nbase = '/srv/' + name\nname = 'x'\nreturn open(base).read()",
    ],
    ids=["rebind_constant", "augmented", "derived"],
)
def test_an_alias_keeps_the_value_the_name_held_when_it_was_taken(body):
    assert PT in _rules(_app("", body))


def test_an_alias_of_a_route_parameter_keeps_the_request_value():
    src = (
        _NO_ABORT_HEAD
        + "@app.route('/r/<name>')\n"
        "def r(name):\n"
        "    base = name\n"
        "    name = 'x'\n"
        "    return open(base).read()\n"
    )
    assert PT in _rules(src)


def test_rebinding_the_alias_target_is_not_taint():
    src = _app(
        "",
        "name = request.args['f']\nbase = name\nbase = 'x'\nreturn open(base).read()",
    )
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD
