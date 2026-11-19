"""Round 4: a guard protects only the definition that reaches it (redteam3-py-01).

`if ".." in name or os.path.isabs(name): abort()` is a statement about the
value `name` held when it ran. A later `name = unquote(name)` (percent-decoding
turns `%2e%2e%2f` into `../`), `name = "/" + name`, an augmented assignment, a
loop or `with` target, a walrus, an `except ... as`, a `match` capture or a
helper that returns a transformed value gives the sink a value the guard never
tested. One rule governs every guard type (`_PythonSecurityVisitor._guard_covers`
over `analyzers/reaching_defs.py`): a guard protects a use only if every
definition of the name that can supply the use also reached the guard.

Part 1 tests the dataflow itself. Part 2 drives the guard types end to end:
the ".." / isabs traversal guard, the membership allowlist guard, the URL-host
allowlist guard and the resolved-path containment guard.
"""

from __future__ import annotations

import ast
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.reaching_defs import ENTRY, ReachingDefs

# ---------------------------------------------------------------------------
# Part 1: reaching definitions
# ---------------------------------------------------------------------------


def _defs(src: str, name: str = "x"):
    """(ReachingDefs, {line: defs}) for the reads of `name` in the one def of
    `src`, keyed by the line of each read (the last read on a line wins)."""
    tree = ast.parse(textwrap.dedent(src))
    func = next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    rd = ReachingDefs(func, name)
    reads = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load):
            reads[node.lineno] = rd.defs_at(node)
    return rd, reads


def _lines(defs) -> set:
    """The lines of the definitions in `defs`, ENTRY as 0."""
    return {0 if d is ENTRY else d.lineno for d in defs}


def test_straight_line_kill():
    _, r = _defs(
        """
        def f(x):
            use(x)
            x = g(x)
            use(x)
        """
    )
    assert _lines(r[3]) == {0}
    assert _lines(r[5]) == {4}


def test_branch_join():
    _, r = _defs(
        """
        def f(x, c):
            if c:
                x = 1
            use(x)
        """
    )
    assert _lines(r[5]) == {0, 4}


def test_both_branches_kill_the_entry():
    _, r = _defs(
        """
        def f(x, c):
            if c:
                x = 1
            else:
                x = 2
            use(x)
        """
    )
    assert _lines(r[7]) == {4, 6}


def test_augmented_assignment_is_a_definition():
    _, r = _defs(
        """
        def f(x):
            x += "a"
            use(x)
        """
    )
    assert _lines(r[4]) == {3}


def test_loop_back_edge_carries_a_later_definition_to_an_earlier_read():
    _, r = _defs(
        """
        def f(x, items):
            for i in items:
                use(x)
                x = g(x)
        """
    )
    assert _lines(r[4]) == {0, 5}


def test_while_loop_back_edge():
    _, r = _defs(
        """
        def f(x):
            while cond():
                use(x)
                x = g(x)
        """
    )
    assert _lines(r[4]) == {0, 5}


def test_for_target_is_a_definition_and_may_not_run():
    _, r = _defs(
        """
        def f(x, items):
            for x in items:
                pass
            use(x)
        """
    )
    assert _lines(r[5]) == {0, 3}


def test_break_and_continue_flow():
    _, r = _defs(
        """
        def f(x, items):
            for i in items:
                if i:
                    x = 1
                    break
                use(x)
            use(x)
        """
    )
    # inside the loop the read sees the entry value and the carried-over `x = 1`
    # only through the back edge, which `break` skips
    assert _lines(r[7]) == {0}
    assert _lines(r[8]) == {0, 5}


def test_while_true_exits_only_through_break():
    _, r = _defs(
        """
        def f(x):
            while True:
                x = g(x)
                if done():
                    break
            use(x)
        """
    )
    assert _lines(r[7]) == {4}


def test_return_ends_the_path():
    _, r = _defs(
        """
        def f(x, c):
            if c:
                x = 1
                return x
            use(x)
        """
    )
    # the read in the taken branch sees only its own definition
    assert _lines(r[5]) == {4}
    # after the `if`, only the path that did not return reaches the read
    assert _lines(r[6]) == {0}


def test_try_handler_sees_every_point_of_the_body():
    _, r = _defs(
        """
        def f(x):
            try:
                x = g(x)
                use(x)
            except Exception:
                use(x)
        """
    )
    assert _lines(r[5]) == {4}
    assert _lines(r[7]) == {0, 4}


def test_after_try_except_both_paths_join():
    _, r = _defs(
        """
        def f(x):
            try:
                x = g(x)
            except Exception:
                pass
            use(x)
        """
    )
    assert _lines(r[7]) == {0, 4}


def test_finally_reads_see_exceptional_paths():
    _, r = _defs(
        """
        def f(x):
            try:
                x = g(x)
            finally:
                use(x)
            use(x)
        """
    )
    assert _lines(r[6]) == {0, 4}
    assert _lines(r[7]) == {4}


def test_except_as_binds_the_name():
    _, r = _defs(
        """
        def f(x):
            try:
                pass
            except Exception as x:
                use(x)
        """
    )
    assert _lines(r[6]) == {5}


def test_with_body_may_be_left_at_any_point():
    _, r = _defs(
        """
        def f(x):
            with cm() as c:
                x = g(x)
            use(x)
        """
    )
    assert _lines(r[5]) == {0, 4}


def test_with_target_is_a_definition():
    _, r = _defs(
        """
        def f(x):
            with cm() as x:
                use(x)
        """
    )
    assert _lines(r[4]) == {3}


def test_walrus_is_a_definition_after_its_value():
    _, r = _defs(
        """
        def f(x):
            if (x := g(x)):
                use(x)
        """
    )
    assert _lines(r[3]) == {0}  # the value is read before the walrus binds
    assert _lines(r[4]) == {3}


def test_walrus_in_a_short_circuit_operand_may_not_run():
    _, r = _defs(
        """
        def f(x, c):
            c and (x := g())
            use(x)
        """
    )
    assert _lines(r[4]) == {0, 3}


def test_walrus_in_a_comprehension_binds_the_function_variable():
    _, r = _defs(
        """
        def f(x, items):
            [(x := i) for i in items]
            use(x)
        """
    )
    assert _lines(r[4]) == {0, 3}


def test_comprehension_target_shadows_the_name():
    rd, r = _defs(
        """
        def f(x, items):
            y = [x for x in items]
            use(x)
        """
    )
    assert _lines(r[4]) == {0}
    assert rd.definitions == []


def test_match_capture_is_a_definition():
    if sys.version_info < (3, 10):
        pytest.skip("match needs Python 3.10")
    _, r = _defs(
        """
        def f(x, v):
            match v:
                case [x]:
                    use(x)
            use(x)
        """
    )
    assert _lines(r[5]) == {4}
    assert _lines(r[6]) == {0, 4}


def test_import_def_and_class_bind_the_name():
    _, r = _defs(
        """
        def f(x):
            import x
            use(x)
        """
    )
    assert _lines(r[4]) == {3}
    _, r = _defs(
        """
        def f(x):
            def x():
                pass
            use(x)
        """
    )
    assert _lines(r[5]) == {3}


def test_del_is_a_definition():
    _, r = _defs(
        """
        def f(x):
            del x
            use(x)
        """
    )
    assert _lines(r[4]) == {3}


def test_nonlocal_or_global_anywhere_makes_the_name_volatile():
    rd, _ = _defs(
        """
        def f(x):
            def bump():
                nonlocal x
                x = 1
            bump()
            use(x)
        """
    )
    assert rd.volatile
    rd, _ = _defs(
        """
        def f(x):
            global x
            use(x)
        """
    )
    assert rd.volatile


def test_lambda_body_reads_are_not_recorded():
    rd, r = _defs(
        """
        def f(x):
            g = lambda: x
            use(x)
        """
    )
    assert r[3] is None  # the lambda body runs later, in a scope of its own
    assert _lines(r[4]) == {0}


# ---------------------------------------------------------------------------
# Part 2: the guards, end to end
# ---------------------------------------------------------------------------

_HEAD = (
    "import os\n"
    "import requests\n"
    "from urllib.parse import unquote, urlparse\n"
    "from flask import Flask, request, abort\n"
    "app = Flask(__name__)\n"
    "BASE = '/srv/files'\n"
    "ALLOWED = {'a', 'b'}\n"
    "HOSTS = {'api.example.com'}\n"
)


def _handler(body: str, prelude: str = "") -> str:
    lines = textwrap.dedent(body).strip("\n").split("\n")
    return (
        _HEAD
        + prelude
        + "@app.route('/r')\ndef r():\n"
        + "".join("    " + line + "\n" for line in lines)
    )


# OR-88 (CL2-1): a sink a recognised containment guard covers is reported at WARN,
# naming the guard (the `fix` text starts `_LOWERED_MARK`), not removed.
#   old `_rules`: the id of every finding
#   new `_rules`: the id of every finding that is not lowered by a guard, so a test
#                 that says a guard "holds" (`PT not in _rules(...)`) keeps its
#                 meaning; `_lowered` is exactly the lowered ones.
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


PT = "SEC-PY_PATH_TRAVERSAL"
SSRF = "SEC-PY_SSRF"

_TRAVERSAL_GUARD = """
name = request.args['f']
if '..' in name or os.path.isabs(name):
    abort(400)
"""


def _traversal(after: str, sink: str = "return open(name).read()") -> str:
    return _handler(_TRAVERSAL_GUARD + textwrap.dedent(after).strip("\n") + "\n" + sink)


# (id, statements between the guard and the sink)
_TRAVERSAL_INVALIDATED = [
    ("unquote", "name = unquote(name)"),
    ("concat_slash", "name = '/' + name"),
    ("fstring", "name = f'/{name}'"),
    ("format", "name = '/{}'.format(name)"),
    ("percent", "name = '/%s' % name"),
    ("augassign", "name += '/x'"),
    ("noop_reassign", "name = name"),
    ("helper", "name = helper(name)"),
    ("join_base", "name = os.path.join(BASE, name)"),
    ("normpath", "name = os.path.normpath(name)"),
    ("branch", "if request.args.get('d'):\n    name = unquote(name)"),
    ("else_branch", "if request.args.get('d'):\n    pass\nelse:\n    name = unquote(name)"),
    ("for_target", "for name in request.args.getlist('g'):\n    pass"),
    ("with_target", "with helper() as name:\n    pass"),
    ("walrus", "if (name := unquote(name)):\n    pass"),
    ("walrus_in_comprehension", "[(name := unquote(name)) for _ in range(1)]"),
    ("try_except", "try:\n    name = unquote(name)\nexcept Exception:\n    pass"),
    ("try_finally", "try:\n    name = unquote(name)\nfinally:\n    pass"),
    ("except_as", "try:\n    pass\nexcept Exception as name:\n    pass"),
    ("while_target", "while name.endswith('%'):\n    name = unquote(name)"),
    ("import_alias", "import posixpath as name"),
    ("nested_def_nonlocal", "def bump():\n    nonlocal name\n    name = unquote(name)\nbump()"),
    ("match_capture", "match request.args.get('m'):\n    case name:\n        pass"),
    ("annotated", "name: str = unquote(name)"),
    ("tuple_target", "name, other = unquote(name), 1"),
    ("starred_target", "*name, = unquote(name)"),
]


@pytest.mark.parametrize("label,after", _TRAVERSAL_INVALIDATED, ids=[c[0] for c in _TRAVERSAL_INVALIDATED])
def test_a_definition_after_the_guard_invalidates_it(label, after):
    if label == "match_capture":
        if sys.version_info < (3, 10):
            pytest.skip("match needs Python 3.10")
    assert PT in _rules(_traversal(after)), label


def test_global_declared_name_is_never_proven():
    src = _handler(
        """
        global name
        name = request.args['f']
        if '..' in name or os.path.isabs(name):
            abort(400)
        return open(name).read()
        """
    )
    assert PT in _rules(src)


def test_a_rebind_in_a_loop_after_the_sink_reaches_the_sink_on_the_next_round():
    src = _handler(
        _TRAVERSAL_GUARD
        + """
for _ in range(2):
    data = open(name).read()
    name = unquote(name)
return data
"""
    )
    assert PT in _rules(src)


def test_a_rebind_before_the_loop_sink_invalidates_it():
    src = _handler(
        _TRAVERSAL_GUARD
        + """
for i in range(2):
    name = unquote(name)
    data = open(name).read()
return data
"""
    )
    assert PT in _rules(src)


def test_a_definition_in_an_alias_chain_after_the_guard_invalidates_it():
    assert PT in _rules(_traversal("name = unquote(name)\npath = name", "return open(path).read()"))


# What must stay clean: the guard still describes the value the sink reads.


def test_the_guard_alone_still_contains_the_path():
    assert PT not in _rules(_traversal(""))
    assert PT not in _all_ids(_traversal("")), _NO_GUARD


def test_an_unrelated_store_between_does_not_invalidate():
    assert PT not in _rules(_traversal("other = 1"))
    assert PT not in _all_ids(_traversal("other = 1")), _NO_GUARD


def test_an_alias_taken_after_the_guard_is_guarded():
    assert PT not in _rules(_traversal("path = name", "return open(path).read()"))
    assert PT not in _all_ids(_traversal("path = name", "return open(path).read()")), _NO_GUARD


def test_a_store_after_the_sink_does_not_reach_it():
    src = _handler(_TRAVERSAL_GUARD + "data = open(name).read()\nname = unquote(name)\nreturn data")
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_a_rebind_before_the_guard_is_what_the_guard_tests():
    src = _handler(
        """
        name = request.args['f']
        name = unquote(name)
        if '..' in name or os.path.isabs(name):
            abort(400)
        return open(name).read()
        """
    )
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_an_alias_taken_before_a_later_rebind_keeps_the_guarded_value():
    src = _handler(_TRAVERSAL_GUARD + "path = name\nname = unquote(name)\nreturn open(path).read()")
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_an_alias_taken_after_the_rebind_does_not():
    src = _handler(_TRAVERSAL_GUARD + "name = unquote(name)\npath = name\nreturn open(path).read()")
    assert PT in _rules(src)


def test_a_second_guard_after_the_rebind_restores_the_protection():
    src = _handler(
        _TRAVERSAL_GUARD
        + """
name = unquote(name)
if '..' in name or os.path.isabs(name):
    abort(400)
return open(name).read()
"""
    )
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_the_two_halves_must_each_reach_the_sink_unchanged():
    # the absolute-path half is tested on a value the sink no longer reads
    src = _handler(
        """
        name = request.args['f']
        if '..' in name:
            abort(400)
        name = unquote(name)
        if os.path.isabs(name):
            abort(400)
        return open(name).read()
        """
    )
    assert PT in _rules(src)


def test_branch_assigned_before_the_guard_is_tested_as_a_whole():
    src = _handler(
        """
        if request.args.get('a'):
            name = request.args['a']
        else:
            name = request.args['b']
        if '..' in name or os.path.isabs(name):
            abort(400)
        return open(name).read()
        """
    )
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


def test_guard_in_the_helper_does_not_protect_a_nested_function_rebind():
    src = _handler(
        _TRAVERSAL_GUARD
        + """
def reader():
    nm = unquote(name)
    return open(nm).read()
return reader()
"""
    )
    assert PT in _rules(src)


# --- membership (allowlist) guard -----------------------------------------

_MEMBERSHIP = """
name = request.args['f']
if name not in ALLOWED:
    abort(400)
"""


def _membership(after: str) -> str:
    return _handler(_MEMBERSHIP + textwrap.dedent(after).strip("\n") + "\nreturn open(name).read()")


def test_membership_guard_alone_holds():
    assert PT not in _rules(_membership(""))
    assert PT not in _all_ids(_membership("")), _NO_GUARD


@pytest.mark.parametrize(
    "after",
    [
        "name = unquote(name)",
        "name = '/' + name",
        "name += '/..'",
        "for name in request.args.getlist('g'):\n    pass",
        "if (name := unquote(name)):\n    pass",
        "try:\n    name = unquote(name)\nexcept Exception:\n    pass",
    ],
)
def test_membership_guard_is_invalidated_by_a_later_definition(after):
    assert PT in _rules(_membership(after))


def test_membership_guard_survives_a_store_after_the_sink():
    src = _handler(_MEMBERSHIP + "data = open(name).read()\nname = 'x'\nreturn data")
    assert PT not in _rules(src)
    assert PT not in _all_ids(src), _NO_GUARD


# --- URL-host allowlist guard ---------------------------------------------

_HOST = """
url = request.args['u']
p = urlparse(url)
if p.scheme != 'https' or p.netloc not in HOSTS:
    abort(400)
"""


def _host(after: str, before_guard: str = "") -> str:
    src = (
        "url = request.args['u']\n"
        + textwrap.dedent(before_guard).strip("\n")
        + ("\n" if before_guard else "")
        + "p = urlparse(url)\n"
        + textwrap.dedent(after).strip("\n")
    )
    return _handler(src)


def test_host_guard_alone_holds():
    src = _handler(_HOST + "return requests.get(url).text")
    assert SSRF not in _rules(src)


@pytest.mark.parametrize(
    "between",
    [
        "url = unquote(url)",
        "url = url + '@evil.example'",
        "url = 'http://' + url",
        "url += '/x'",
        "for url in request.args.getlist('u'):\n    pass",
        "if (url := unquote(url)):\n    pass",
    ],
)
def test_host_guard_is_invalidated_by_a_definition_after_it(between):
    src = _handler(_HOST + textwrap.dedent(between).strip("\n") + "\nreturn requests.get(url).text")
    assert SSRF in _rules(src)


def test_a_stale_parse_does_not_cover_a_rebound_name():
    src = _handler(
        """
        url = request.args['u']
        p = urlparse(url)
        url = request.args['v']
        if p.scheme != 'https' or p.netloc not in HOSTS:
            abort(400)
        return requests.get(url).text
        """
    )
    assert SSRF in _rules(src)


def test_host_guard_survives_a_store_after_the_sink():
    src = _handler(_HOST + "r = requests.get(url).text\nurl = 'x'\nreturn r")
    assert SSRF not in _rules(src)


# --- resolved-path containment guard --------------------------------------

_CONTAINED = """
f = request.args['f']
full = os.path.realpath(os.path.join(BASE, f))
if not full.startswith(BASE + os.sep):
    abort(400)
"""


def _contained(after: str) -> str:
    return _handler(_CONTAINED + textwrap.dedent(after).strip("\n") + "\nreturn open(full).read()")


def test_containment_guard_alone_holds():
    assert PT not in _rules(_contained(""))
    # OR-88: held, and reported at WARN with the guard named, not removed.
    assert {f["id"] for f in _lowered(_contained(""))} == {PT}
    assert any("startswith" in f["fix"] for f in _lowered(_contained(""))), "the guard is named"


@pytest.mark.parametrize(
    "after",
    [
        "full = full + '/../../etc/passwd'",
        "full = unquote(full)",
        "full = os.path.join(full, f)",
        "full += '/x'",
        "for full in request.args.getlist('g'):\n    pass",
        "if (full := unquote(full)):\n    pass",
        "try:\n    full = unquote(full)\nexcept Exception:\n    pass",
    ],
)
def test_containment_guard_is_invalidated_by_a_later_definition(after):
    assert PT in _rules(_contained(after))


def test_containment_guard_must_test_the_resolved_definition():
    src = _handler(
        """
        f = request.args['f']
        full = os.path.realpath(os.path.join(BASE, f))
        full = unquote(f)
        if not full.startswith(BASE + os.sep):
            abort(400)
        return open(full).read()
        """
    )
    assert PT in _rules(src)


def test_containment_try_form_is_invalidated_by_a_later_definition():
    src = _handler(
        """
        from pathlib import Path
        f = request.args['f']
        full = Path(BASE, f).resolve()
        try:
            full.relative_to(BASE)
        except ValueError:
            abort(400)
        full = Path(unquote(f))
        return open(full).read()
        """
    )
    assert PT in _rules(src)


def test_a_free_name_is_never_proven():
    # a module global: a callee can rebind it between the guard and the use
    rd, _ = _defs(
        """
        def f():
            if '..' in TARGET:
                abort()
            refresh()
            open(TARGET)
        """,
        "TARGET",
    )
    assert rd.volatile
    rd, _ = _defs(
        """
        def f(TARGET):
            open(TARGET)
        """,
        "TARGET",
    )
    assert not rd.volatile
