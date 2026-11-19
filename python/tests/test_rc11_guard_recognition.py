"""RC-11 G (Round 6 closure): evidence-based path-containment guard recognition.

A reachable path-traversal finding BLOCKed correctly guarded code, because the
analyzer looked for a containment guard only among the function's top-level
statements and accepted only an inline `realpath` + `commonpath` against a
constant base. The real case is `backend/scanning/validators.py`
`delete_spec_upload`: a project-local helper (`_path_is_within`, which realpaths
both sides) called as `if not helper(upload_root, target): return` inside a
`try:`, before the `os.unlink`.

Approved G: recognise a guard by what its body does, never by its name. A helper
counts when its body resolves both sides (realpath / `Path.resolve`, never
`abspath`) and tests containment separator-safely (`commonpath` ==, `startswith`
with a separator, `is_relative_to`, `relative_to` in a `try`); the guard has to
dominate the sink on every path to it, check the value that reaches the sink,
check it against the base the path was built from (or a narrower one), and not
take that base from request input. Anything else keeps reporting.

The fixtures in `fixtures/rc11_g/` are scanned as text and never executed or
imported: 52 packages from the decision package (27 safe, 23 vulnerable, 2
conditional; every label was confirmed by a runtime oracle that tries hostile
inputs against a real directory tree) and 23 hold-out packages written for this
change, 16 vulnerable and 7 safe, judged by the same oracle (r6-closure/ws-c3/
rc11/holdout/out/oracle.json). The hold-outs are the overfitting guard: a helper
named `is_safe_path` that checks nothing, `startswith(base)` with no separator,
a guard on one branch, a guard on another variable, a guard before a rebinding,
a guard without normalisation, a helper that returns instead of raising with the
result ignored, a guard that dominates a different sink, an exception swallowed
around the guard, an absolute part joined after the guard, a trusted root WIDER
than the base, and a root computed from a request value.

What the manifest's `expect` means (the analyzer-level contract; the decision
layer then maps a proven chain to BLOCK):

* `proven`: a vulnerable (or conditionally vulnerable) fixture still carries a
  taint chain. The count of these may never fall: a recognised guard must not
  hide a hole.
* `recognised`: a safe fixture reports no taint chain.
* `known_false_positive`: a safe fixture the policy does not recognise (6 of 27
  in the approved G simulation). Not asserted either way here; the aggregate
  test caps the set so a new false positive cannot appear unnoticed.
* `known_false_negative`: a vulnerable fixture the engine already did not report
  before this change (2 of 23); pinned so a change in either direction is seen.
* `lowered` (CL2-1, owner ruling OR-88, "the recognisers may lower a finding,
  never remove it"): a vulnerable fixture whose sink a recognised guard covers
  (a decoy: the guard is rebound, patched, rooted at a parent or a symlink, ...).
  rc.3 cleared it, so the scan showed nothing. It is now reported at WARN: an
  unproven finding, never a taint chain, that names the guard. A vulnerable
  fixture is a clean scan only where v3.7.0 was already silent (fx46, fx47).

The `verify-acc-rc3` group is the independent verifier's rc.3 matrix (41 packages,
`verify-acc/rc3/fx/rc11{c,d,e}`, each judged by the runtime oracle; y11 and y12
are left out, their label disagrees with the oracle): the C-1 reflection decoys
x01 to x07, the CL-A1/CL-A2 decoys x08 to x18, y01 to y10, z01 and z02, and the
controls t01 to t08 and z03.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

FIXTURES = Path(__file__).parent / "fixtures" / "rc11_g"
MANIFEST = json.loads((FIXTURES / "MANIFEST.json").read_text(encoding="utf-8"))
PATH_RULE = "python.ast/PY_PATH_TRAVERSAL"


def _findings(fid: str) -> list[dict]:
    """The path-traversal findings of one fixture package, scanned alone (the
    package directory sits under the scan root, as the engine scans it)."""
    out: list[dict] = []
    with tempfile.TemporaryDirectory() as root:
        shutil.copytree(FIXTURES / fid, Path(root) / fid, ignore=shutil.ignore_patterns("__pycache__"))
        analyzer = ASTAnalyzer(root, "python")
        try:
            analyzer.run(out.append)
        except AnalysisIncomplete:
            pass
    return [f for f in out if f["rule_id"] == PATH_RULE]


def _proven(fid: str) -> bool:
    return any(f.get("taint_chain") for f in _findings(fid))


def _ids(expect: str) -> list[str]:
    return sorted(fid for fid, spec in MANIFEST.items() if spec["expect"] == expect)


def test_the_manifest_has_the_expected_shape() -> None:
    groups = {}
    for spec in MANIFEST.values():
        groups.setdefault((spec["group"], spec["label"]), []).append(spec)
    assert {k: len(v) for k, v in groups.items()} == {
        ("r6d-53", "SAFE"): 27,
        ("r6d-53", "VULN"): 23,
        ("r6d-53", "COND"): 2,
        ("ws-c3-holdout", "SAFE"): 7,
        ("ws-c3-holdout", "VULN"): 16,
        ("verify-acc", "SAFE"): 3,
        ("verify-acc", "VULN"): 46,
        ("verify-acc", "COND"): 1,
        ("verify-acc-rc3", "SAFE"): 9,
        ("verify-acc-rc3", "VULN"): 30,
    }
    assert sum(1 for f in MANIFEST if (FIXTURES / f).is_dir()) == len(MANIFEST)


@pytest.mark.parametrize("fid", _ids("proven"))
def test_a_vulnerable_fixture_keeps_its_proven_finding(fid: str) -> None:
    assert _proven(fid), f"{fid}: {MANIFEST[fid]['why']}"


@pytest.mark.parametrize("fid", _ids("recognised") + _ids("recognised_same_code_as_a_safe_fixture"))
def test_a_safe_fixture_with_a_real_guard_reports_no_proven_finding(fid: str) -> None:
    assert not _proven(fid), f"{fid}: {MANIFEST[fid]['why']}"


@pytest.mark.parametrize("fid", _ids("known_false_negative"))
def test_the_known_false_negatives_are_pinned(fid: str) -> None:
    # Missed before this change and missed after it; the count may not grow.
    assert not _proven(fid), fid


def test_no_new_false_positive_among_the_safe_fixtures() -> None:
    safe = [fid for fid, spec in MANIFEST.items() if spec["label"] == "SAFE"]
    proven = {fid for fid in safe if _proven(fid)}
    allowed = set(_ids("known_false_positive"))
    assert proven <= allowed, sorted(proven - allowed)


_OLD_GROUPS = ("r6d-53", "ws-c3-holdout", "verify-acc")


def test_the_vulnerable_count_never_falls_below_the_approved_floor() -> None:
    vuln = [fid for fid, spec in MANIFEST.items() if spec["label"] == "VULN" and spec["group"] in _OLD_GROUPS]
    missed = [fid for fid in vuln if not _proven(fid)]
    # 85 vulnerable fixtures; the four the engine never proved (fx46, fx47, and
    # v18, v21, which v3.7.0 and rc.1 only WARN on too) are the only misses.
    assert sorted(missed) == _ids("known_false_negative")
    assert len(vuln) - len(missed) >= 81


def test_the_verifiers_rc3_decoys_keep_what_rc3_proved_and_the_rest_are_lowered() -> None:
    vuln = [fid for fid, spec in MANIFEST.items() if spec["label"] == "VULN" and spec["group"] == "verify-acc-rc3"]
    assert len(vuln) == 30
    assert sorted(f for f in vuln if _proven(f)) == sorted(f for f in vuln if MANIFEST[f]["expect"] == "proven")
    assert len([f for f in vuln if MANIFEST[f]["expect"] == "lowered"]) == 19


# OR-88 (CL2-1). Every assertion below is new: rc.3 cleared these decoys outright.
# The vulnerable fixtures that no guard is recognised for were already reported.
_NO_GUARD_INVOLVED = {"fx46_pathlib_resolve_no_check", "fx47_pathlib_str_startswith"}


@pytest.mark.parametrize(
    "fid",
    sorted(
        fid
        for fid, spec in MANIFEST.items()
        if spec["label"] in ("VULN", "COND") and fid not in _NO_GUARD_INVOLVED
    ),
)
def test_a_vulnerable_fixture_is_never_a_clean_scan(fid: str) -> None:
    # The structural rule: a recogniser may lower a finding, never remove it. Every
    # vulnerable or conditional fixture carries at least one path-traversal finding,
    # whatever guard the analyzer believes it sees. (fx46 and fx47 are the two
    # fixtures v3.7.0 itself never reported; no guard is involved there.)
    assert _findings(fid), f"{fid}: {MANIFEST[fid]['why']}"


_LOWERED_MARK = "A path-containment guard"


@pytest.mark.parametrize("fid", _ids("lowered"))
def test_a_decoy_a_guard_is_recognised_for_is_reported_at_warn_naming_the_guard(fid: str) -> None:
    found = _findings(fid)
    assert found, fid
    # WARN, not BLOCK: no taint chain, the unproven MEDIUM/MEDIUM form the decision
    # layer never blocks on, the same grade a chainless `open(x)` has always had.
    assert not any(f.get("taint_chain") for f in found), fid
    assert {(f["severity"], f["confidence"]) for f in found} == {("MEDIUM", "MEDIUM")}, fid
    assert all(f["title"] == "Potential unsafe dynamic filesystem path" for f in found), fid
    # ... and says which guard it believed (the existing `fix` field).
    assert any(f["fix"].startswith(_LOWERED_MARK) for f in found), (fid, [f["fix"][:80] for f in found])


# Safe fixtures with nothing to lower: v3.7.0 itself reports no path-traversal finding
# for them (checked against the v3.7.0 analyzer), so no recogniser removes one. Three
# read the file with `Path.read_bytes()`, which is not a modelled sink; `fx44` reduces
# the name with `secure_filename`, a sanitiser and not a containment guard.
_SILENT_AT_V370 = {
    "fx40_pathlib_resolve_is_relative_to_ok",
    "fx41_pathlib_relative_to_try_ok",
    "fx44_secure_filename_ok",
    "fx54d_pathlib_resolve_relative_to_direct",
}


@pytest.mark.parametrize(
    "fid",
    sorted(set(_ids("recognised") + _ids("recognised_same_code_as_a_safe_fixture")) - _SILENT_AT_V370),
)
def test_a_safe_fixture_with_a_recognised_guard_is_reported_at_warn_not_removed(fid: str) -> None:
    # OR-88: "the scan never shows 0 findings because of a guard". The safe packages
    # with a real guard (s01, s02, t04 and the other controls) are WARN, never BLOCK.
    found = _findings(fid)
    assert found, fid
    assert not any(f.get("taint_chain") for f in found), fid
    assert any(f["fix"].startswith(_LOWERED_MARK) for f in found), (fid, [f["fix"][:80] for f in found])


def test_the_conditional_symlink_escape_stays_reported() -> None:
    # An abspath (lexical) guard is not accepted as symlink-safe.
    assert _proven("fx11_abspath_symlink_escape")


# ---------------------------------------------------------------------------
# What a helper's BODY establishes (`_g_summarize_helper`), shape by shape
# ---------------------------------------------------------------------------

_HEADER = "import os\nfrom pathlib import Path\n\n"

_SUMMARIES = [
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n",
        ("bool", 0, 1),
        id="commonpath-equals-root",
    ),
    pytest.param(
        "def f(root, target):\n    root = os.path.realpath(root)\n    target = os.path.realpath(target)\n    return os.path.commonpath([root, target]) == root\n",
        ("bool", 0, 1),
        id="parameters-rebound-to-their-resolved-values",
    ),
    pytest.param(
        "def f(target, root):\n    r = os.path.realpath(root)\n    return os.path.realpath(target).startswith(r + os.sep)\n",
        ("bool", 1, 0),
        id="startswith-root-plus-separator-parameters-swapped",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.realpath(target).startswith(os.path.join(r, ''))\n",
        ("bool", 0, 1),
        id="startswith-join-root-empty",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    t = os.path.realpath(target)\n    return t == r or t.startswith(r + os.sep)\n",
        ("bool", 0, 1),
        id="equal-or-prefix",
    ),
    pytest.param(
        "def f(root, target):\n    return Path(target).resolve().is_relative_to(Path(root).resolve())\n",
        ("bool", 0, 1),
        id="pathlib-is-relative-to",
    ),
    pytest.param(
        "def f(root, target):\n    try:\n        Path(target).resolve().relative_to(Path(root).resolve())\n        return True\n    except ValueError:\n        return False\n",
        ("bool", 0, 1),
        id="pathlib-relative-to-in-a-try",
    ),
    pytest.param(
        "def f(root, target):\n    try:\n        r = os.path.realpath(root)\n        return os.path.commonpath([r, os.path.realpath(target)]) == r\n    except ValueError:\n        return False\n",
        ("bool", 0, 1),
        id="fails-closed-on-value-error",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    if os.path.commonpath([r, os.path.realpath(target)]) != r:\n        raise PermissionError('escape')\n",
        ("raises", 0, 1),
        id="raises-when-outside",
    ),
    # Not containment checks: each keeps the finding.
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    if os.path.commonpath([r, os.path.realpath(target)]) != r:\n        raise PermissionError('escape')\n    return target\n",
        None,
        id="raises-and-also-returns-a-value",
    ),
    pytest.param("def f(root, target):\n    return os.path.exists(target)\n", None, id="existence-only"),
    pytest.param(
        "def f(root, target):\n    r = os.path.abspath(root)\n    return os.path.abspath(target).startswith(r + os.sep)\n",
        None,
        id="abspath-is-lexical",
    ),
    pytest.param(
        "def f(root, target):\n    return os.path.normpath(target).startswith(os.path.normpath(root) + os.sep)\n",
        None,
        id="normpath-is-lexical",
    ),
    pytest.param(
        "def f(root, target):\n    return os.path.commonpath([root, target]) == root\n",
        None,
        id="commonpath-without-resolving",
    ),
    pytest.param(
        "def f(root, target):\n    return os.path.realpath(target).startswith(os.path.realpath(root))\n",
        None,
        id="startswith-without-a-separator",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonprefix([r, os.path.realpath(target)]) == r\n",
        None,
        id="commonprefix-is-a-string-prefix",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) != r\n",
        None,
        id="inverted-comparison",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(root)]) == r\n",
        None,
        id="the-root-against-itself",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, target]) == r\n",
        None,
        id="target-not-resolved",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    if os.path.commonpath([r, os.path.realpath(target)]) != r:\n        return None\n    return target\n",
        None,
        id="returns-the-path-instead-of-raising",
    ),
    pytest.param(
        "import functools\n\n@functools.lru_cache\ndef f(root, target):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n",
        None,
        id="decorated",
    ),
    pytest.param(
        "def f(root, target, *rest):\n    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n",
        None,
        id="variadic",
    ),
    pytest.param(
        "def f(root, target):\n    r = os.path.realpath(root)\n    ok = os.path.commonpath([r, os.path.realpath(target)]) == r\n    print(ok)\n",
        None,
        id="result-discarded",
    ),
]


@pytest.mark.parametrize("body, expected", _SUMMARIES)
def test_a_helper_is_read_by_its_body(body: str, expected: tuple | None) -> None:
    import ast

    from analyzers.ast_analyzer import _g_module_names, _g_summarize_helper

    source = body if body.startswith("import") else _HEADER + body
    if "import os" not in source:
        source = "import os\n" + source
    tree = ast.parse(source)
    fdef = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    assert _g_summarize_helper(fdef, _g_module_names(tree)) == expected


# ---------------------------------------------------------------------------
# Finding the helper: this file, another module of the project, relative imports
# ---------------------------------------------------------------------------

_GOOD_HELPER = (
    "import os\n\n\ndef is_within(root, target):\n"
    "    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n"
)
_CALLER = (
    "import os\n{imp}\nBASE = '/srv/uploads'\n\n\n"
    "def serve(request):\n    name = request.GET.get('name')\n    target = os.path.join(BASE, name)\n"
    "    if not is_within(BASE, target):\n        return None\n    return open(target).read()\n"
)


def _scan_tree(files: dict[str, str]) -> list[dict]:
    out: list[dict] = []
    with tempfile.TemporaryDirectory() as root:
        for rel, text in files.items():
            path = Path(root) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        try:
            ASTAnalyzer(root, "python").run(out.append)
        except AnalysisIncomplete:
            pass
    return [f for f in out if f["rule_id"] == PATH_RULE]


@pytest.mark.parametrize(
    "files, proven",
    [
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": _GOOD_HELPER, "pkg/views.py": _CALLER.replace("{imp}", "from .guards import is_within")},
            False,
            id="relative-import-one-level",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": _GOOD_HELPER, "pkg/views.py": _CALLER.replace("{imp}", "from pkg.guards import is_within")},
            False,
            id="absolute-import",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": _GOOD_HELPER, "pkg/views.py": _CALLER.replace("{imp}", "from pkg import guards\nis_within = guards.is_within")},
            True,
            id="a-name-bound-to-an-attribute-is-not-followed",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/sub/__init__.py": "", "pkg/guards.py": _GOOD_HELPER, "pkg/sub/views.py": _CALLER.replace("{imp}", "from ..guards import is_within")},
            False,
            id="relative-import-two-levels",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/views.py": _CALLER.replace("{imp}", "from somelib.guards import is_within")},
            True,
            id="helper-outside-the-project-is-not-read",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/views.py": _CALLER.replace("{imp}", "from .missing import is_within")},
            True,
            id="helper-module-not-found",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": _GOOD_HELPER + "\n\ndef is_within(root, target):\n    return True\n", "pkg/views.py": _CALLER.replace("{imp}", "from .guards import is_within")},
            True,
            id="a-name-defined-twice-is-not-read",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": "def is_within(root, target):\n    return True\n\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1], "pkg/views.py": _CALLER.replace("{imp}", "from .guards import is_within")},
            True,
            id="a-name-defined-twice-the-good-one-last-is-still-not-read",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": _GOOD_HELPER + "\nis_within = None\n", "pkg/views.py": _CALLER.replace("{imp}", "from .guards import is_within")},
            True,
            id="a-name-also-assigned-is-not-read",
        ),
        pytest.param(
            {"pkg/__init__.py": "", "pkg/guards.py": "def is_within(root, target:\n", "pkg/views.py": _CALLER.replace("{imp}", "from .guards import is_within")},
            True,
            id="helper-module-does-not-parse",
        ),
        pytest.param(
            {"pkg/guards.py": _GOOD_HELPER, "pkg/views.py": _CALLER.replace("{imp}", "from pkg.guards import is_within"), "pkg/__init__.py": "", "guards.py": "x = 1\n"},
            False,
            id="unrelated-module-of-the-same-leaf-name",
        ),
    ],
)
def test_the_helper_is_found_where_it_is_imported_from(files: dict[str, str], proven: bool) -> None:
    findings = _scan_tree(files)
    assert any(f.get("taint_chain") for f in findings) is proven


def test_a_helper_defined_in_the_same_file_is_read() -> None:
    source = _CALLER.replace("{imp}", "") + "\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1]
    assert not any(f.get("taint_chain") for f in _scan_tree({"views.py": source}))


def test_a_local_name_shadowing_the_helper_is_not_followed() -> None:
    source = (
        "import os\nBASE = '/srv/uploads'\n\n\n"
        + _GOOD_HELPER.split("\n\n\n", 1)[1]
        + "\n\ndef serve(request, is_within):\n    name = request.GET.get('name')\n"
        "    target = os.path.join(BASE, name)\n    if not is_within(BASE, target):\n        return None\n"
        "    return open(target).read()\n"
    )
    assert any(f.get("taint_chain") for f in _scan_tree({"views.py": source}))


def test_a_guard_checking_another_value_of_the_same_name_pattern_is_reported() -> None:
    source = _CALLER.replace("{imp}", "").replace("is_within(BASE, target)", "is_within(BASE, name)") + "\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1]
    assert any(f.get("taint_chain") for f in _scan_tree({"views.py": source}))


# ---------------------------------------------------------------------------
# Bases the guard is allowed to trust (an unproven base bounds nothing)
# ---------------------------------------------------------------------------

_INLINE = (
    "import os\n{pre}\n\n\ndef serve(request):\n    name = request.GET.get('name')\n"
    "    base = os.path.realpath({base})\n    full = os.path.realpath(os.path.join(base, name))\n"
    "    if os.path.commonpath([base, full]) != base:\n        return None\n    return open(full).read()\n"
)


@pytest.mark.parametrize(
    "pre, base, proven",
    [
        pytest.param("BASE = '/srv/uploads'", "BASE", False, id="module-constant"),
        pytest.param("from django.conf import settings", "settings.MEDIA_ROOT", False, id="settings-attribute"),
        pytest.param("from .tenants import root_for", "root_for('x')", True, id="call-of-an-unresolvable-function"),
        pytest.param("", "os.environ['UPLOADS']", True, id="environment"),
        pytest.param("BASE = '/'", "BASE", True, id="module-constant-that-is-the-filesystem-root"),
        pytest.param("BASE = ''", "BASE", True, id="empty-constant"),
        pytest.param("import sys", "sys.argv[1]", True, id="argv"),
        pytest.param("import settings_obj as cfg", "cfg.upload_dir", True, id="lowercase-attribute-is-not-a-constant"),
        pytest.param("BASE = '/srv/uploads'\nBASE = os.environ.get('B', '/')", "BASE", True, id="module-constant-bound-twice"),
    ],
)
def test_which_bases_a_recognised_guard_may_trust(pre: str, base: str, proven: bool) -> None:
    source = _INLINE.replace("{pre}", pre).replace("{base}", base)
    assert any(f.get("taint_chain") for f in _scan_tree({"views.py": source})) is proven


def test_an_assert_is_not_a_guard() -> None:
    # `python -O` removes asserts, so a containment `assert` protects nothing in
    # production, whatever the helper does.
    source = (
        "import os\nBASE = '/srv/uploads'\n\n\n"
        + _GOOD_HELPER.split("\n\n\n", 1)[1]
        + "\n\ndef serve(request):\n    name = request.GET.get('name')\n    target = os.path.join(BASE, name)\n"
        "    assert is_within(BASE, target)\n    return open(target).read()\n"
    )
    assert any(f.get("taint_chain") for f in _scan_tree({"views.py": source}))


# ---------------------------------------------------------------------------
# CL-3 (verifier A-1, A-2, C-8): the inline guard names the root it checks
# against, and a helper a module rebinds is not the helper it imported
# ---------------------------------------------------------------------------

_INLINE_ROOT = (
    "import os\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n    name = request.GET.get('name')\n"
    "    target = os.path.realpath(os.path.join(BASE, name))\n    root = os.path.realpath({root})\n"
    "    if {test}:\n        return None\n    return open(target).read()\n"
)
_TESTS = {
    "commonpath": "os.path.commonpath([root, target]) != root",
    "startswith": "not target.startswith(root + os.sep)",
}


def _proven_source(files: dict[str, str]) -> bool:
    return any(f.get("taint_chain") for f in _scan_tree(files))


@pytest.mark.parametrize("test", sorted(_TESTS))
@pytest.mark.parametrize(
    "root, proven",
    [
        pytest.param("'/srv/uploads'", False, id="the-same-constant"),
        pytest.param("BASE", False, id="the-same-name"),
        pytest.param("'/srv/uploads/'", False, id="trailing-slash"),
        pytest.param("'/srv/uploads/../uploads'", False, id="equal-after-normalisation"),
        pytest.param("'/srv/uploads/sub'", False, id="a-directory-below"),
        pytest.param("'/srv'", True, id="the-parent"),
        pytest.param("'/srv/uploads2'", True, id="a-sibling-with-the-same-prefix"),
        pytest.param("'/srv/other'", True, id="a-sibling"),
        pytest.param("'/'", True, id="the-filesystem-root"),
        pytest.param("'/srv/uploads/..'", True, id="the-parent-spelled-with-dotdot"),
        pytest.param("os.path.dirname(BASE)", True, id="the-parent-computed"),
    ],
)
def test_the_inline_guard_must_check_the_base_the_path_was_joined_from(
    test: str, root: str, proven: bool
) -> None:
    source = _INLINE_ROOT.replace("{root}", root).replace("{test}", _TESTS[test])
    assert _proven_source({"views.py": source}) is proven


def test_a_helper_called_with_the_same_constant_as_the_join_base_is_recognised() -> None:
    source = (
        "import os\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n    name = request.GET.get('name')\n"
        "    target = os.path.join(BASE, name)\n    if not is_within('/srv/uploads', target):\n        return None\n"
        "    return open(target).read()\n\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1]
    )
    assert not _proven_source({"views.py": source})


def test_a_path_with_no_join_base_is_still_checked_against_a_fixed_root() -> None:
    source = (
        "import os\n\n\ndef serve(request):\n    name = request.GET.get('name')\n"
        "    target = os.path.realpath(name)\n    if not target.startswith('/srv/uploads' + os.sep):\n"
        "        return None\n    return open(target).read()\n"
    )
    assert not _proven_source({"views.py": source})


_REBIND_VIEW = (
    "import os\nfrom .guards import is_within\n{rebind}\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n"
    "    name = request.GET.get('name')\n    target = os.path.join(BASE, name)\n"
    "    if not is_within(BASE, target):\n        return None\n    return open(target).read()\n"
)


@pytest.mark.parametrize(
    "rebind",
    [
        pytest.param("is_within = lambda root, target: True", id="assignment-of-a-lambda"),
        pytest.param("def is_within(root, target):\n    return True", id="a-def"),
        pytest.param("from .other import is_within", id="a-later-import"),
        pytest.param("import other as is_within", id="an-import-as"),
        pytest.param("is_within, other = (lambda r, t: True), 1", id="tuple-unpacking"),
        pytest.param("(is_within := lambda r, t: True)", id="walrus"),
        pytest.param("del is_within", id="del"),
        pytest.param("def patch():\n    global is_within\n    is_within = lambda r, t: True", id="global-in-a-function"),
        pytest.param("def other_function():\n    is_within = None", id="a-local-of-another-function"),
        pytest.param("for is_within in [lambda r, t: True]:\n    pass", id="for-target"),
        pytest.param("with open('x') as is_within:\n    pass", id="with-target"),
        pytest.param("try:\n    pass\nexcept Exception as is_within:\n    pass", id="except-as"),
        pytest.param("is_within += 1", id="augmented-assignment"),
        pytest.param("class is_within:\n    pass", id="a-class"),
    ],
)
def test_a_helper_the_module_rebinds_is_not_the_imported_guard(rebind: str) -> None:
    files = {
        "pkg/__init__.py": "",
        "pkg/guards.py": _GOOD_HELPER,
        "pkg/other.py": "x = 1\n",
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", rebind),
    }
    assert _proven_source(files)


def test_the_unrebound_import_is_the_control_for_the_rebinding_tests() -> None:
    files = {
        "pkg/__init__.py": "",
        "pkg/guards.py": _GOOD_HELPER,
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", ""),
    }
    assert not _proven_source(files)


def test_a_same_file_helper_the_module_rebinds_is_not_trusted() -> None:
    source = (
        "import os\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n    name = request.GET.get('name')\n"
        "    target = os.path.join(BASE, name)\n    if not is_within(BASE, target):\n        return None\n"
        "    return open(target).read()\n\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1]
        + "\n\nis_within = lambda root, target: True\n"
    )
    assert _proven_source({"views.py": source})


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param("os.sep = ''", id="os-sep"),
        pytest.param("os.path.realpath = lambda p: p", id="os-path-realpath"),
        pytest.param("os.path.commonpath = lambda ps: ps[0]", id="os-path-commonpath"),
        pytest.param("setattr(os, 'sep', '')", id="setattr-on-os"),
        pytest.param("os.path = __import__('posixpath')", id="os-path-replaced"),
        pytest.param("def patch():\n    os.sep = ''", id="inside-a-function"),
    ],
)
def test_a_module_that_patches_the_path_library_is_not_trusted(patch: str) -> None:
    inline = (
        "import os\n" + patch + "\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n"
        "    name = request.GET.get('name')\n    target = os.path.realpath(os.path.join(BASE, name))\n"
        "    if not target.startswith(BASE + os.sep):\n        return None\n    return open(target).read()\n"
    )
    assert _proven_source({"views.py": inline})
    helper = (
        "import os\nBASE = '/srv/uploads'\n" + patch + "\n\n\ndef serve(request):\n"
        "    name = request.GET.get('name')\n    target = os.path.join(BASE, name)\n"
        "    if not is_within(BASE, target):\n        return None\n    return open(target).read()\n\n\n"
        + _GOOD_HELPER.split("\n\n\n", 1)[1]
    )
    assert _proven_source({"views.py": helper})


def test_a_module_that_only_sets_an_environment_variable_is_still_trusted() -> None:
    source = (
        "import os\nos.environ['X'] = '1'\nBASE = '/srv/uploads'\n\n\ndef serve(request):\n"
        "    name = request.GET.get('name')\n    target = os.path.realpath(os.path.join(BASE, name))\n"
        "    if not target.startswith(BASE + os.sep):\n        return None\n    return open(target).read()\n"
    )
    assert not _proven_source({"views.py": source})


def test_a_helper_in_a_module_that_patches_the_path_library_is_not_trusted() -> None:
    files = {
        "pkg/__init__.py": "",
        "pkg/guards.py": "import os\nos.sep = ''\n\n\n" + _GOOD_HELPER.split("\n\n\n", 1)[1],
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", ""),
    }
    assert _proven_source(files)


@pytest.mark.parametrize("fid", sorted(_SILENT_AT_V370))
def test_the_fixtures_v370_never_reported_stay_silent(fid: str) -> None:
    # Lowering restores what a recogniser removed; it adds nothing v3.7.0 did not report.
    assert _findings(fid) == [], fid


# ---------------------------------------------------------------------------
# CL2-1: two structural defects the verifier named, both small (a helper's name or its
# parameters that something else can rebind). Each now keeps the finding PROVEN (BLOCK)
# instead of lowering it to a WARN.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "star",
    [
        pytest.param("from .other import *", id="star-import-after-the-guard-import"),
        pytest.param("from os.path import *", id="star-import-of-a-library"),
    ],
)
def test_a_star_import_in_the_calling_module_means_the_helper_is_not_trusted(star: str) -> None:
    # `from m import *` can bind any name, `is_within` included, and where it sits
    # relative to the guard import is not something a static read can rely on.
    files = {
        "pkg/__init__.py": "",
        "pkg/guards.py": _GOOD_HELPER,
        "pkg/other.py": "x = 1\n",
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", star),
    }
    assert _proven_source(files)


def test_a_star_import_in_the_helper_module_means_the_helper_is_not_trusted() -> None:
    files = {
        "pkg/__init__.py": "",
        "pkg/other.py": "x = 1\n",
        "pkg/guards.py": "from .other import *\n" + _GOOD_HELPER,
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", ""),
    }
    assert _proven_source(files)


@pytest.mark.parametrize(
    "signature, imports",
    [
        pytest.param("root, target, realpath=lambda p: p", "from os.path import realpath", id="realpath-parameter"),
        pytest.param("root, target, commonpath=lambda ps: ps[0]", "from os.path import commonpath", id="commonpath-parameter"),
        pytest.param("root, target, os=None", "", id="module-name-parameter"),
    ],
)
def test_a_helper_parameter_named_like_an_imported_name_is_not_trusted(signature: str, imports: str) -> None:
    helper = (
        "import os\n{imports}\n\n\ndef is_within({signature}):\n"
        "    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n"
    ).replace("{imports}", imports).replace("{signature}", signature)
    files = {
        "pkg/__init__.py": "",
        "pkg/guards.py": helper,
        "pkg/views.py": _REBIND_VIEW.replace("{rebind}", ""),
    }
    assert _proven_source(files)


def test_a_helper_parameter_with_an_unrelated_name_is_still_trusted() -> None:
    helper = (
        "import os\n\n\ndef is_within(root, target, strict=True):\n"
        "    r = os.path.realpath(root)\n    return os.path.commonpath([r, os.path.realpath(target)]) == r\n"
    )
    files = {"pkg/__init__.py": "", "pkg/guards.py": helper, "pkg/views.py": _REBIND_VIEW.replace("{rebind}", "")}
    assert not _proven_source(files)


# ---------------------------------------------------------------------------
# CL2-1: the lowering itself. A sink is lowered only when the recognisers accepted a
# guard AND the sink, re-read as if no guard were recognised, would be reported.
# ---------------------------------------------------------------------------

_OPEN_SRC = "from flask import request\n\n\ndef read():\n    return open(request.args['f']).read()\n"


def _scan_source(src: str) -> list[dict]:
    return _scan_tree({"mod.py": src})


def test_a_guard_the_recognisers_noted_creates_no_finding_when_the_unguarded_sink_is_not_reported(monkeypatch) -> None:
    from analyzers import ast_analyzer

    visitor = ast_analyzer._PythonSecurityVisitor

    def noted_but_nothing_to_report(self, node):
        if not self._guards_off:
            self._note_guard(node)  # a recogniser accepted something ...
        return None  # ... and the sink would not be reported with or without it

    monkeypatch.setattr(visitor, "_path_traversal_evidence", noted_but_nothing_to_report)
    assert _scan_source(_OPEN_SRC) == []


def test_a_guarded_sink_is_lowered_to_the_unproven_form_even_when_the_unguarded_read_proves_a_chain(monkeypatch) -> None:
    from analyzers import ast_analyzer

    visitor = ast_analyzer._PythonSecurityVisitor
    real = visitor._path_traversal_evidence

    def guarded_when_read_normally(self, node):
        if not self._guards_off:
            self._note_guard(node)
            return None
        return real(self, node)  # the unguarded read: a proven chain

    monkeypatch.setattr(visitor, "_path_traversal_evidence", guarded_when_read_normally)
    (found,) = _scan_source(_OPEN_SRC)
    assert not found.get("taint_chain")
    assert (found["severity"], found["confidence"]) == ("MEDIUM", "MEDIUM")
    assert found["fix"].startswith(_LOWERED_MARK)


def test_the_guards_stay_on_after_a_sink_is_lowered(monkeypatch) -> None:
    # `_guards_off` is restored, so the next sink is read with the recognisers on.
    from analyzers import ast_analyzer

    seen: list[int] = []
    visitor = ast_analyzer._PythonSecurityVisitor
    real = visitor._path_traversal_evidence

    def spy(self, node):
        if getattr(node.func, "id", None) != "open":
            return real(self, node)
        seen.append(self._guards_off)
        if not self._guards_off:
            self._note_guard(node)
            return None
        return real(self, node)

    monkeypatch.setattr(visitor, "_path_traversal_evidence", spy)
    two = _OPEN_SRC + "\n\ndef read2():\n    return open(request.args['g']).read()\n"
    _scan_source(two)
    assert seen == [0, 1, 0, 1]


@pytest.mark.parametrize(
    "guard, named",
    [
        pytest.param(
            "    full = os.path.realpath(os.path.join('/srv/reports', f))\n"
            "    if not full.startswith('/srv/reports' + os.sep):\n"
            "        abort(400)\n",
            "not full.startswith('/srv/reports' + os.sep)",
            id="if-startswith",
        ),
        pytest.param(
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE)\n"
            "    except ValueError:\n"
            "        abort(400)\n",
            "`relative_to` check on `full`",
            id="try-relative-to",
        ),
    ],
)
def test_the_older_inline_recogniser_lowers_on_its_own(monkeypatch, guard: str, named: str) -> None:
    # The helper-and-inline recogniser (`_g_guard_covers`) and the older inline one
    # (`_path_containment_guard`) each name the guard; with the first switched off the
    # second still lowers the sink to a WARN instead of letting it go.
    from analyzers import ast_analyzer

    monkeypatch.setattr(ast_analyzer._PythonSecurityVisitor, "_g_guard_covers_value", lambda self, *a, **k: False)
    src = (
        "import os\nfrom pathlib import Path\nfrom flask import abort, request\n\nBASE = Path('/srv/reports')\n\n\n"
        "def read():\n    f = request.args['f']\n" + guard + "    return open(full).read()\n"
    )
    found = _scan_source(src)
    assert found, "the guarded sink was removed, not lowered"
    assert not any(f.get("taint_chain") for f in found)
    assert any(f["fix"].startswith(_LOWERED_MARK) for f in found)
    assert any(named in f["fix"] for f in found), (named, [f["fix"][:200] for f in found])
