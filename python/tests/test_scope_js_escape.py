"""Release Closure Sprint, WS-C2, R6-E7a: a unicode escape in identifier
position makes a JavaScript or TypeScript file lost evaluation.

The Python half of ``go/internal/scope/jsescape.go``: the same lexer, pinned by
the same vectors (``go/internal/scope/testdata/jsescape_vectors.json``), whose
ground truth is the TypeScript scanner and, for a payload that can run, Node
itself, never the lexer under test. ``expect`` differs from the oracle only in
the conservative direction.
"""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

import pytest

from analyzers import scope_evidence as se

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "go" / "internal" / "scope" / "testdata" / "jsescape_vectors.json").read_text(
        encoding="utf-8"
    )
)
ROWS = VECTORS["vectors"]
BS = chr(92)


def test_vector_file_is_from_the_typescript_oracle() -> None:
    assert VECTORS["schema"] == 1 and VECTORS["oracle"]["name"] == "typescript"
    assert VECTORS["oracle"]["version"].startswith("5.")
    kinds = {k: sum(1 for r in ROWS if r["id"].startswith(k + "-")) for k in ("ident", "none", "doubt")}
    assert kinds["ident"] >= 55 and kinds["none"] >= 90 and kinds["doubt"] >= 8, kinds
    for r in ROWS:
        if r["oracle"] != r["expect"]:
            assert r["expect"] and r.get("deviation"), f"{r['id']}: a deviation must be conservative and say why"
        if r.get("node_runs") is True:
            assert r["expect"], f"{r['id']}: Node ran the payload and the vector expects it clean"


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r["id"])
def test_agrees_with_the_typescript_oracle_on_every_vector(row: dict) -> None:
    got = se.js_identifier_escape(row["text"], "v" + row["ext"])
    assert not got.undecided, row["id"]
    assert got.lost == row["expect"], f"{row['id']} ({row['note']}): lost={got.lost}, want {row['expect']} (oracle {row['oracle']})\n{row['text']}"
    if got.lost:
        assert got.offset >= 0


def test_only_javascript_and_typescript_are_read_by_name() -> None:
    src = BS + "u0065val(x)"
    for name in ("a.js", "a.jsx", "a.mjs", "a.cjs", "a.es6", "a.ts", "a.tsx", "a.mts", "a.cts", "A.JS", "dir/B.Tsx"):
        assert se.js_source(name) and se.js_identifier_escape(src, name).lost, name
    for name in ("a.vue", "a.py", "a.json", "a.html", "a.java", "a.go", "a.md", "Makefile", "a.js.map"):
        assert not se.js_source(name) and not se.js_identifier_escape(src, name).lost, name


def test_bytes_are_read_as_utf8() -> None:
    assert se.js_identifier_escape((BS + "u0065val(x)").encode(), "a.js").lost
    assert not se.js_identifier_escape(("x = '" + BS + "u0041'; /[" + BS + "u0042]/").encode(), "a.js").lost


def test_the_first_offset_is_the_escape() -> None:
    src = "var s = '" + BS + "u0041'; /[" + BS + "u0042]/; ev" + BS + "u0061l(1)"
    got = se.js_identifier_escape(src, "a.js")
    assert got.found and got.offset == src.index("ev" + BS + "u0061") + 2


def test_random_text_terminates_and_never_raises() -> None:
    atoms = [BS, "u", "0", "00", "65", "{", "}", "(", ")", "[", "]", "`", "'", '"', "$", "\n", "\r", " ", "/", "//", "/*", "*/",
             "<", ">", "<!--", "-->", "!", "--", "++", "=", "=>", ";", ",", ".", "?.", ":", "?", " ", "x", "eval", "of", "await",
             "yield", "if", "for", "return", "#", "@", BS + "u0041", BS + "u{41}", BS + "u0065val", "</", "/>", "<a>", "</a>",
             "<>", "</>", "é", "﻿"]  # fmt: skip
    exts = ["a.js", "a.jsx", "a.mjs", "a.ts", "a.tsx"]
    rng = random.Random(263)
    start = time.time()
    for i in range(3000):
        text = "".join(rng.choice(atoms) for _ in range(rng.randint(1, 60)))
        got = se.js_identifier_escape(text, exts[i % len(exts)])
        assert not got.found or 0 <= got.offset < len(text)
    assert time.time() - start < 60


def test_giving_up_is_lost_never_clean() -> None:
    tail = '"' + BS + 'u0041";'
    for name, src in {
        "forks": "{}/ a / " * 3000 + tail,
        "nesting": "(" * 30000 + tail,
        "templ": "`${" * 12000 + tail,
        "jsx": "x=<a>" * 12000 + tail,
        "html": "a <!-- b\n" * 12000 + tail,
    }.items():
        start = time.time()
        got = se.js_identifier_escape(src, "a.js")
        assert time.time() - start < 20, name
        assert not got.undecided or got.lost, name


def test_deep_ordinary_code_is_decided() -> None:
    src = "".join(f"f{i}(function(){{return [" for i in range(400)) + '"' + BS + 'u0041",/[' + BS + "u0042]/" + "]})" * 400 + ";"
    assert not se.js_identifier_escape(src, "bundle.js").lost


# ---------------------------------------------------------------------------
# Release Closure Sprint, correction loop CL2-3 (verifier finding R3-SEC-A2, owner ruling
# OR-88 item 3): a lexer that gives up never answers "clean", and no limit may make it resume
# a reading that can skip code. The Go twin has the same table
# (go/internal/scope/jsescape_giveup_test.go).
#
# The inputs end in an escape that sits in a string, so no reading of them finds an escape in
# code: only a give-up can make the file lost, and the test says at which limit it happened.
# ---------------------------------------------------------------------------

TAIL = '"' + BS + 'u0041";'


def _lexer(src: str, name: str) -> "se._JSLexer":
    jsx, tsx, html = se._JS_FLAVOURS[name[name.rfind(".") :].lower()]
    return se._JSLexer(src, jsx, tsx, html)


GIVE_UPS = [
    ("depth: brackets nested past the depth limit", "a.js", "(" * (se._JS_MAX_DEPTH + 500) + TAIL, "depth"),
    ("steps: more tokens read than the budget", "a.js", "{}/ a / " * 2500 + TAIL, "steps"),
    ("type arguments: a template with a substitution among them", "a.tsx", "const a = <Select<`a${B}c`> />;\n" + TAIL, "type arguments"),
]


@pytest.mark.parametrize("name,file,src,why", GIVE_UPS, ids=[g[0] for g in GIVE_UPS])
def test_every_give_up_names_its_limit_and_is_lost(name: str, file: str, src: str, why: str) -> None:
    lx = _lexer(src, file)
    got = lx.decide()
    assert not got.found, f"the escape is in a string: nothing may be found, got {got}"
    assert got.undecided and got.lost, f"giving up must be lost evaluation: {got} (limit {lx.why!r}), want a give-up at {why!r}"
    assert lx.why == why
    assert se.js_identifier_escape(src, file) == got


def test_the_states_limit_gives_up_as_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    # the states limit sits behind the step budget (every reading costs steps to the end of the file), so a
    # lowered limit reaches it; the same file decides within the real limits
    src = "{}/ a / " * 50 + TAIL
    assert not se.js_identifier_escape(src, "a.js").lost
    monkeypatch.setattr(se, "_JS_MAX_STATES", 3)
    lx = _lexer(src, "a.js")
    got = lx.decide()
    assert not got.found and got.undecided and got.lost and lx.why == "states", (got, lx.why)


def test_the_depth_limit_gives_up_as_lost(monkeypatch: pytest.MonkeyPatch) -> None:
    src = "(" * 40 + TAIL
    monkeypatch.setattr(se, "_JS_MAX_DEPTH", 30)
    lx = _lexer(src, "a.js")
    got = lx.decide()
    assert not got.found and got.undecided and lx.why == "depth", (got, lx.why)


def test_an_open_type_argument_list_ends_its_reading_and_other_readings_still_run() -> None:
    # No valid file has a type argument list that nothing closes, so the reading that holds it ends, as an
    # unterminated comment ends one: it is not a give-up and not lost evaluation by itself (giving up there made
    # a vendored react-dom.production.min.js and a PNG named .js read as lost in the Tier B census).
    for name, (file, src) in {
        "no closing >": ("a.tsx", "const a = <Select<A|A|A|A\n" + TAIL),
        "unterminated comment": ("a.tsx", "const a = <Select</* A\n" + TAIL),
        "in a .js file": ("a.js", "const a = <b<c;\n" + TAIL),
        "after a closing brace": ("a.js", "function f() {}\n<b<c;\n" + TAIL),
    }.items():
        lx = _lexer(src, file)
        got = lx.decide()
        assert not got.lost and lx.why == "", (name, got, lx.why)
    # after a `}` the `<` is read both ways: the reading that takes `<b<c` for an operator finds the escaped call
    code = "function f() {}\n<b<c\n" + BS + "u0065val(1);\n"
    assert se.js_identifier_escape(code, "a.js").found


@pytest.mark.parametrize("sep", ["\u2028", "\u2029"])
def test_a_type_argument_string_may_hold_a_line_separator(sep: str) -> None:
    # ES2019 allows U+2028 and U+2029 in a string, as in code: a `>` after one is part of the string
    src = 'const a = <Select<"a' + sep + '>b"> items={[]} />;\n' + BS + "u0065xec(1);\n"
    assert se.js_identifier_escape(src, "a.tsx").found


@pytest.mark.parametrize("members", [100, 30000, 33000, 40000, 120000, 400000])
def test_a_type_argument_list_of_any_length_is_read_to_its_end(members: int) -> None:
    # R3-SEC-A2: the list used to be abandoned after 64 KiB and the rest of the file read as JSX text
    head = "type A = string;\nconst Select = (p: any) => null;\nconst a = <Select<" + "A|" * members + "A> items={[]} />;\n"
    code = head + BS + "u0065xec('dig ' + host);\n"
    got = se.js_identifier_escape(code, "Page.tsx")
    assert got.found and got.offset == len(head), (members, got)
    only_in_a_string = head + 'const s = "' + BS + 'u0041";\n'
    assert not se.js_identifier_escape(only_in_a_string, "Page.tsx").lost, members


@pytest.mark.parametrize(
    "chain", ["const in out T", "const in out const T", "in in in in in in in in in in T", "const const const const const T"]
)
def test_an_endless_modifier_chain_is_read_both_ways(chain: str) -> None:
    src = "const f = <" + chain + ",>(x: T) => x;\n" + BS + "u0065val('1');\n"
    assert se.js_identifier_escape(src, "a.tsx").lost, chain


def test_a_long_type_argument_list_in_the_python_engine_is_lost_evaluation(tmp_path: Path) -> None:
    from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

    head = "import { exec } from 'node:child_process';\nconst host = 'x';\nconst a = <Select<" + "A|" * 40000 + "A> items={[]} />;\n"
    (tmp_path / "Page.tsx").write_text(head + BS + "u0065xec('dig ' + host);\n", encoding="utf-8")
    (tmp_path / "ctl.tsx").write_text(head + "exec('dig ' + host);\n", encoding="utf-8")
    with pytest.raises(AnalysisIncomplete) as caught:
        ASTAnalyzer(str(tmp_path), "python").run(lambda _f: None)
    files = dict(caught.value.files)
    assert files.get("Page.tsx") == se.JS_ESCAPE_UNREADABLE, files
    assert "ctl.tsx" not in files, files


# ---------------------------------------------------------------------------
# The Python engine's own JavaScript checks. `ASTAnalyzer._analyze_js_heuristic`
# (python/analyzers/ast_analyzer.py, owned by another workstream) must record a
# file with an escape in identifier position as lost evaluation through the existing
# `_record_incomplete`; the patch request is in the WS-C2 report. Until that hook
# lands the test is skipped by an explicit condition, and starts running when
# ast_analyzer imports js_identifier_escape.
# ---------------------------------------------------------------------------


def _hook_landed() -> bool:
    from analyzers import ast_analyzer

    return hasattr(ast_analyzer, "js_identifier_escape")


@pytest.mark.skipif(not _hook_landed(), reason="the ast_analyzer hook for R6-E7a is a patch request to its owner (WS-C2 report)")
def test_the_python_engine_records_an_escaped_identifier_as_lost_evaluation(tmp_path: Path) -> None:
    from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

    (tmp_path / "app.js").write_text(BS + "u0065xec('dig ' + host);\n", encoding="utf-8")
    (tmp_path / "ok.js").write_text("const re = /[" + BS + "u00C0-" + BS + "u1FFF]/; const s = '" + BS + "u0041'; a / b / c;\n", encoding="utf-8")
    with pytest.raises(AnalysisIncomplete) as caught:
        ASTAnalyzer(str(tmp_path), "python").run(lambda _f: None)
    files = dict(caught.value.files)
    assert "app.js" in files and files["app.js"] == se.JS_ESCAPE_UNREADABLE, files
    assert "ok.js" not in files, files
