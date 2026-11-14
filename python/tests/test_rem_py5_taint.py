"""Round 5 Python taint: lazy bodies, ambiguous bindings and star imports.

C4B-22. A generator expression is evaluated when it is consumed, not where it is
written: `g = (open(name).read() for _ in [1]); name = request.args['g'];
next(g)` opens the NEW `name`. The body was read at the definition, where a
guard on `name` still held, so a path traversal hid behind it. A list, set or
dict comprehension runs where it is written and stays as it was.

C4B-23. The engine reads a name's value at a use from its last binding in
source order. When the name is tainted on one branch (an `if`/`else` arm, a
`try` body) and rebound to something safe on another, the last binding wins and
the taint was dropped without a word. A sink that consulted such a name and was
not reported is now lost evaluation through `AnalysisIncomplete` (the injection
check fails with the file named), so the scan cannot read complete.

Review item 3. `from flask import *` supplies `abort`, but a second star import
of a module the engine does not know can supply a returning `abort` that wins
(the last star import binds the name). A star import proves a guard only when
every star import in the file is of a module known to supply the never-returning
function; a relative star import (`from .flask import *`) is a project module,
not flask.
"""

from __future__ import annotations

import tempfile
import textwrap
from pathlib import Path

import pytest

from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

PT = "SEC-PY_PATH_TRAVERSAL"
OS = "SEC-PY_OS_SYSTEM"

HEAD = (
    "import os\n"
    "import subprocess\n"
    "from flask import Flask, request, abort\n"
    "app = Flask(__name__)\n"
)
GUARD = "name = request.args['f']\nif '..' in name or os.path.isabs(name):\n    abort(400)\n"


def _app(body: str, head: str = HEAD) -> str:
    lines = textwrap.dedent(body).strip("\n").split("\n")
    return head + "@app.route('/r')\ndef r():\n" + "".join("    " + line + "\n" for line in lines)


def _scan(src: str, extra: dict | None = None):
    """(rule ids, [(file, reason)] lost)."""
    findings: list[dict] = []
    lost: list = []
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "app.py").write_text(src)
        for rel, text in (extra or {}).items():
            path = Path(d) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        analyzer = ASTAnalyzer(d, "python")
        try:
            analyzer.run(findings.append)
        except AnalysisIncomplete as exc:
            lost = list(exc.files)
    return {f["id"] for f in findings}, lost


# ---------------------------------------------------------------------------
# C4B-22
# ---------------------------------------------------------------------------


class TestGeneratorExpressionIsLazy:
    def test_a_guard_does_not_cover_a_generator_that_runs_after_a_rebind(self) -> None:
        src = _app(GUARD + "g = (open(name).read() for _ in [1])\nname = request.args['g']\nreturn next(g)")
        ids, lost = _scan(src)
        assert PT in ids and lost == []

    def test_the_condition_and_later_iterables_of_a_generator_are_lazy_too(self) -> None:
        src = _app(
            GUARD
            + "g = (x for x in ['a'] if open(name).read())\nname = request.args['g']\nreturn next(g, '')"
        )
        ids, _lost = _scan(src)
        assert PT in ids

    def test_a_list_comprehension_runs_where_it_is_written(self) -> None:
        src = _app(GUARD + "g = [open(name).read() for _ in [1]]\nname = request.args['g']\nreturn g[0]")
        ids, lost = _scan(src)
        assert PT not in ids and lost == []

    @pytest.mark.parametrize("opener", ["{", "set("])
    def test_set_and_dict_comprehensions_run_where_they_are_written(self, opener: str) -> None:
        body = "{open(name).read() for _ in [1]}" if opener == "{" else "{k: open(name).read() for k in [1]}"
        src = _app(GUARD + f"g = {body}\nname = request.args['g']\nreturn str(g)")
        ids, lost = _scan(src)
        assert PT not in ids and lost == []

    def test_a_generator_consumed_before_the_rebind_still_reads_the_guarded_value(self) -> None:
        # No rebind at all: the guard holds for a generator written after it.
        src = _app(GUARD + "g = (open(name).read() for _ in [1])\nreturn next(g)")
        ids, lost = _scan(src)
        assert PT not in ids and lost == []

    def test_an_unguarded_lazy_read_of_a_name_rebound_to_input_is_not_silent(self) -> None:
        # `name` is a constant where the generator is written and request input
        # where it runs. A finding or a lost-evaluation note; never silence.
        src = _app("name = 'static.txt'\ng = (open(name).read() for _ in [1])\nname = request.args['g']\nreturn next(g)")
        ids, lost = _scan(src)
        assert PT in ids or [rel for rel, _why in lost] == ["app.py"]

    def test_an_unguarded_lazy_read_of_a_name_that_stays_constant_is_clean(self) -> None:
        src = _app("name = 'static.txt'\ng = (open(name).read() for _ in [1])\nreturn next(g)")
        ids, lost = _scan(src)
        assert PT not in ids and lost == []


# ---------------------------------------------------------------------------
# C4B-23
# ---------------------------------------------------------------------------

_TRY = (
    "name = 'start'\n"
    "try:\n"
    "    name = request.args['g']\n"
    "    int('x')\n"
    "    name = 'safe'\n"
    "except Exception:\n"
    "    pass\n"
    "return open(name).read()"
)
_IF_ELSE = (
    "if request.args.get('z'):\n"
    "    name = request.args['g']\n"
    "else:\n"
    "    name = 'safe'\n"
    "return open(name).read()"
)
_IF_NO_ELSE = (
    "name = request.args['g']\n"
    "if request.args.get('z'):\n"
    "    name = 'safe'\n"
    "return open(name).read()"
)
_OS_SYSTEM_IF_ELSE = (
    "if request.args.get('z'):\n"
    "    cmd = request.args['c']\n"
    "else:\n"
    "    cmd = 'ls'\n"
    "os.system(cmd)\n"
    "return 'ok'"
)


class TestAmbiguousBindingIsLostEvaluation:
    @pytest.mark.parametrize(
        "body", [_TRY, _IF_ELSE, _IF_NO_ELSE], ids=["try_partial_rebind", "if_else", "if_no_else"]
    )
    def test_a_branch_tainted_path_is_a_finding_or_a_named_gap(self, body: str) -> None:
        ids, lost = _scan(_app(body))
        assert PT in ids or [rel for rel, _why in lost] == ["app.py"], (ids, lost)

    def test_the_gap_names_the_name_and_the_line(self) -> None:
        _ids, lost = _scan(_app(_IF_ELSE))
        (rel, why), = lost
        assert rel == "app.py" and "name" in why and "line" in why

    def test_a_command_sink_that_a_constant_last_binding_suppresses_is_not_silent(self) -> None:
        ids, lost = _scan(_app(_OS_SYSTEM_IF_ELSE))
        assert OS in ids or [rel for rel, _why in lost] == ["app.py"], (ids, lost)

    @pytest.mark.parametrize(
        "body",
        [
            # a sequential rebind kills the earlier value: nothing is ambiguous
            "name = request.args['g']\nname = 'safe'\nreturn open(name).read()",
            # both arms are constants
            "if request.args.get('z'):\n    name = 'a'\nelse:\n    name = 'b'\nreturn open(name).read()",
            # the tainted value is rebound in the SAME block before any use
            "if request.args.get('z'):\n    name = request.args['g']\n    name = 'safe'\nelse:\n    name = 'b'\nreturn open(name).read()",
            # no sink consults the name
            "if request.args.get('z'):\n    name = request.args['g']\nelse:\n    name = 'safe'\nreturn str(name)",
        ],
        ids=["sequential", "both_constant", "killed_in_block", "no_sink"],
    )
    def test_nothing_ambiguous_is_nothing_lost(self, body: str) -> None:
        ids, lost = _scan(_app(body))
        assert PT not in ids and lost == [], (ids, lost)

    @pytest.mark.parametrize(
        "body",
        [
            "name = request.args['g']\nfor _ in range(3):\n    name = 'safe'\nreturn open(name).read()",
            "name = request.args['g']\nwhile request.args.get('z'):\n    name = 'safe'\nreturn open(name).read()",
            "name = request.args['g']\nwith open('/dev/null') as fh:\n    name = 'safe'\nreturn open(name).read()",
            "name = 'static.txt'\nf = lambda: open(name).read()\nname = request.args['g']\nreturn f()",
            "name = request.args['g']\nmatch request.args.get('z'):\n    case 'a':\n        name = 'safe'\n    case _:\n        pass\nreturn open(name).read()",
        ],
        ids=["for", "while", "with", "lambda", "match"],
    )
    def test_other_control_flow_shapes_are_a_finding_or_a_named_gap(self, body: str) -> None:
        ids, lost = _scan(_app(body))
        assert PT in ids or [rel for rel, _why in lost] == ["app.py"], (ids, lost)

    def test_a_call_that_is_no_sink_is_not_a_gap_however_ambiguous_its_argument(self) -> None:
        # The gap is recorded only when the call WOULD be reported with the
        # tainted definition in place of the last binding; logging, formatting
        # and response helpers that no rule reports are not lost evaluation.
        body = (
            "if request.args.get('z'):\n"
            "    name = request.args['g']\n"
            "else:\n"
            "    name = 'safe'\n"
            "print(name)\n"
            "msg = 'bad ' + name\n"
            "print(msg.upper())\n"
            "return str(len(name))"
        )
        ids, lost = _scan(_app(body))
        assert ids == set() and lost == []

    def test_ambiguity_reaches_a_sink_through_a_derived_name(self) -> None:
        body = (
            "if request.args.get('z'):\n"
            "    name = request.args['g']\n"
            "else:\n"
            "    name = 'safe'\n"
            "path = '/srv/' + name\n"
            "return open(path).read()"
        )
        ids, lost = _scan(_app(body))
        assert PT in ids or [rel for rel, _why in lost] == ["app.py"], (ids, lost)

    def test_a_tainted_last_binding_is_an_ordinary_finding_with_no_gap(self) -> None:
        body = "name = 'start'\nif request.args.get('z'):\n    name = request.args['g']\nreturn open(name).read()"
        ids, lost = _scan(_app(body))
        assert PT in ids and lost == []

    def test_a_route_parameter_overwritten_on_one_branch_is_ambiguous(self) -> None:
        src = (
            HEAD
            + "@app.route('/r/<name>')\n"
            + "def r(name):\n"
            + "    if request.args.get('z'):\n"
            + "        name = 'safe'\n"
            + "    return open(name).read()\n"
        )
        ids, lost = _scan(src)
        assert PT in ids or [rel for rel, _why in lost] == ["app.py"], (ids, lost)


# ---------------------------------------------------------------------------
# Review item 3: star imports
# ---------------------------------------------------------------------------

_GUARDED = GUARD.replace("abort(400)", "abort(400)")


def _star(head_extra: str, extra_files: dict | None = None):
    src = (
        "import os\n"
        "from flask import Flask, request\n"
        + head_extra
        + "app = Flask(__name__)\n"
        + "@app.route('/r')\ndef r():\n"
        + "".join("    " + line + "\n" for line in (_GUARDED + "return open(name).read()").split("\n"))
    )
    return _scan(src, extra_files)


class TestStarImportProof:
    def test_a_single_star_import_of_a_known_module_still_supplies_abort(self) -> None:
        ids, lost = _star("from flask import *\n")
        assert PT not in ids and lost == []

    def test_known_modules_that_all_supply_it_still_prove_the_guard(self) -> None:
        ids, lost = _star("from flask import *\nfrom werkzeug.exceptions import *\n")
        assert PT not in ids and lost == []

    def test_an_unknown_second_star_import_can_supply_a_returning_abort(self) -> None:
        ids, _lost = _star("from flask import *\nfrom helpers import *\n", {"helpers.py": "def abort(code):\n    print(code)\n"})
        assert PT in ids

    def test_a_star_import_that_comes_later_in_the_file_still_counts(self) -> None:
        # The view is defined before the line that rebinds `abort` at import.
        src = (
            "import os\n"
            "from flask import Flask, request\n"
            "from flask import *\n"
            "app = Flask(__name__)\n"
            "@app.route('/r')\ndef r():\n"
            + "".join("    " + line + "\n" for line in (_GUARDED + "return open(name).read()").split("\n"))
            + "from helpers import *\n"
        )
        ids, _lost = _scan(src, {"helpers.py": "def abort(code):\n    print(code)\n"})
        assert PT in ids

    def test_a_relative_star_import_is_a_project_module_not_flask(self) -> None:
        ids, _lost = _star("from .flask import *\n", {"flask.py": "def abort(code):\n    print(code)\n"})
        assert PT in ids

    def test_a_lone_relative_star_import_proves_nothing(self) -> None:
        ids, _lost = _star("from . import *\n")
        assert PT in ids

    def test_an_unknown_single_star_import_proves_nothing(self) -> None:
        ids, _lost = _star("from helpers import *\n", {"helpers.py": "def abort(code):\n    print(code)\n"})
        assert PT in ids

    def test_a_star_import_in_a_try_with_an_unknown_fallback_proves_nothing(self) -> None:
        ids, _lost = _star("try:\n    from flask import *\nexcept ImportError:\n    from helpers import *\n", {"helpers.py": "def abort(code):\n    print(code)\n"})
        assert PT in ids


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def _many_ambiguous(n: int) -> str:
    lines = []
    for i in range(n):
        lines += [
            f"if request.args.get('a{i}'):",
            f"    v{i} = request.args['x{i}']",
            "else:",
            f"    v{i} = 'c{i}'",
        ]
    lines += [f"open(v{i}).read()" for i in range(n)]
    lines.append("return 'ok'")
    return _app("\n".join(lines))


class TestBounds:
    def test_a_file_of_many_ambiguous_bindings_lists_a_few_and_counts_the_rest(self) -> None:
        _ids, lost = _scan(_many_ambiguous(60))
        reasons = [why for _rel, why in lost]
        assert len(reasons) <= 21
        assert reasons[-1] == "ambiguous bindings: 40 more not listed"

    def test_a_function_over_the_analysis_bound_is_a_named_gap_not_clean(self) -> None:
        import time

        start = time.monotonic()
        _ids, lost = _scan(_many_ambiguous(260))
        assert time.monotonic() - start < 30
        assert any("not analysed: over 200 names" in why for _rel, why in lost), lost

    def test_a_function_that_reads_no_request_input_is_never_analysed(self) -> None:
        body = "\n".join(
            line
            for i in range(30)
            for line in (f"if os.environ.get('a{i}'):", f"    v{i} = os.environ['x{i}']", "else:", f"    v{i} = 'c{i}'", f"open(v{i}).read()")
        )
        ids, lost = _scan(_app(body + "\nreturn 'ok'").replace("@app.route('/r')\ndef r():", "def r():"))
        assert lost == []
