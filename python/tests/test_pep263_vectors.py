"""Round 6, WS-E1 (R5-01, R6-E1, R6-E6): the PEP 263 source-encoding vectors.

Two generated files drive this test and the Go readers' tests
(``go/internal/scope/pep263_vectors_test.go``):

- ``go/internal/scope/testdata/pep263_vectors.json``: vectors, each with its
  bytes, what CPython did with them on the import path, as a script and under
  ``python -x``, and the outcome every reader must report;
- ``go/internal/scope/testdata/pep263_codec_names.json``: all 454 codec names
  CPython knows plus their measured case and separator variants, with the
  verdict, codec and run-time takeover immunity of ``# coding: <name>``, and a
  plain control file that must keep its finding in every tree (OR-53).

A taken-over, non-immune name (``d2_documented_false_clean``) was D2's
documented false clean (OR-59). The owner approved D2-A (OR-85: "implement the
approved codec policy"), under which only the takeover-immune spellings stay
UTF-8-equivalent, so the vector is now a real assertion: the name is foreign and
Semgrep and secrets record the file as lost evaluation.

Both are written by ``go/internal/scope/testdata/gen_pep263_vectors.py`` on the
engine image's CPython 3.14.5 and never edited by hand. The policy asserted is
D2-A; set ``FENDIX_PEP263_POLICY=d2`` to assert the superseded D2 reading, which
holds only in a tree whose ``PEP263_POLICY`` was switched back to ``"d2"``. The
shipped policy itself is pinned, whatever the variable says, by
``test_shipped_policy_*`` below.

Checked here:

1. Reproducibility: on the reference interpreter the generator is re-run and
   its output byte-compared with the committed files, so every measured field,
   verdict and expectation is re-derived from CPython (R-19; elsewhere it skips,
   or fails with ``FENDIX_REQUIRE_PEP263_GROUND_TRUTH=1``).
2. The shared predicate, ``analyzers.scope_evidence.python_source_encoding``,
   on every vector and every codec name.
3. The Python engine end to end (``ASTAnalyzer``) on every vector and every
   codec name, with a plain ``ok.py`` beside each vector that must stay
   analysed.
"""

from __future__ import annotations

import base64
import codecs
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from analyzers import scope_evidence
from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

TESTDATA = Path(__file__).resolve().parents[2] / "go" / "internal" / "scope" / "testdata"
GENERATOR = TESTDATA / "gen_pep263_vectors.py"
VECTORS_PATH = TESTDATA / "pep263_vectors.json"
NAMES_PATH = TESTDATA / "pep263_codec_names.json"
DOC = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
NAMES = json.loads(NAMES_PATH.read_text(encoding="utf-8"))
VECTORS = DOC["vectors"]
REFERENCE = DOC["reference_interpreter"]["version"]
SHELL_ID = "SEC-PY_SUBPROCESS_SHELL"
D2A = os.environ.get("FENDIX_PEP263_POLICY") != "d2"


def _ids(v: dict) -> str:
    return v["id"]


def _expect(row: dict) -> dict:
    return row.get("expect_under_d2a") if D2A and row.get("expect_under_d2a") else row["expect"]


def _predicate_verdicts(row: dict) -> list | None:
    if D2A and row.get("predicate_verdicts_under_d2a"):
        return row["predicate_verdicts_under_d2a"]
    return row.get("predicate_verdicts")


def _files(v: dict) -> dict[str, bytes]:
    files = {rel: base64.b64decode(b64) for rel, b64 in v["files"].items()}
    e = v.get("expand")
    if e:
        rest = files[v["target"]]
        term = e["terminator"].encode()
        n = e.get("line1_comment_bytes") or e["line1_fill_to_total"] - len(term) - len(rest)
        files[v["target"]] = b"#" + b"x" * (n - 1) + term + rest
    assert len(files[v["target"]]) == v["target_bytes"], v["id"]
    return files


def _materialise(files: dict[str, bytes], root: Path) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def _on_reference_interpreter() -> None:
    here = platform.python_version()
    if platform.python_implementation() == "CPython" and here == REFERENCE:
        return
    msg = f"the vectors' ground truth is CPython {REFERENCE}; this interpreter is {platform.python_implementation()} {here}"
    if os.environ.get("FENDIX_REQUIRE_PEP263_GROUND_TRUTH") == "1":
        pytest.fail(msg)
    pytest.skip(msg)


# ---------------------------------------------------------------------------
# The generated files
# ---------------------------------------------------------------------------


def test_vector_files_are_from_the_reference_interpreter() -> None:
    assert DOC["schema"] == 2 and NAMES["schema"] == 1
    assert REFERENCE == "3.14.5", "ground truth must come from the engine image's CPython 3.14.5 (R-19)"
    assert NAMES["reference_interpreter"]["version"] == REFERENCE
    assert sum(1 for r in NAMES["names"] if r["variant_of"] is None) == 454
    assert NAMES["control"]["file"] == "ok.py"
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids))
    for must in ("c7-cr-secret", "c7-long1-secret", "c8-ue-cr-secret", "c7-cr", "custom-codec"):
        assert must in ids


def test_generated_files_reproduce_byte_for_byte(tmp_path: Path) -> None:
    """Re-run the generator on the reference interpreter: every measured field,
    verdict and expectation is re-derived from CPython, and nothing in the
    committed files may differ (E1-B5: no trusted hand-edited expect)."""
    _on_reference_interpreter()
    r = subprocess.run([sys.executable, "-I", str(GENERATOR), str(tmp_path)], capture_output=True, timeout=900)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-2000:]
    for name in ("pep263_vectors.json", "pep263_codec_names.json"):
        assert (tmp_path / name).read_bytes() == (TESTDATA / name).read_bytes(), f"{name} differs from a fresh generation"


# ---------------------------------------------------------------------------
# The shared predicate
# ---------------------------------------------------------------------------


def _predicate():
    fn = getattr(scope_evidence, "python_source_encoding", None)
    if fn is None:
        pytest.fail(
            "analyzers.scope_evidence.python_source_encoding(data: bytes) does not exist: the Python half of the one "
            "PEP 263 predicate shared with go/internal/scope/pysource.go (R5-01, R6-E1). Contract: returns an object with "
            "`verdict` in {plain, transparent, foreign, unknown, refused} and `codec`, the codecs.lookup name of the codec "
            "CPython applies (None for plain, unknown and refused)."
        )
    return fn


def _check_predicate(data: bytes, allowed: list, codec: str | None, what: str) -> None:
    got = _predicate()(data)
    verdict = getattr(got, "verdict", None)
    assert verdict in allowed, f"{what}: predicate says {verdict!r}, CPython 3.14.5 allows {allowed}"
    if verdict in ("foreign", "transparent") and codec:
        assert getattr(got, "codec", None) is not None and codecs.lookup(got.codec).name == codecs.lookup(codec).name, (
            f"{what}: predicate codec {getattr(got, 'codec', None)!r}, CPython applies {codec!r}"
        )


@pytest.mark.parametrize("v", VECTORS, ids=_ids)
def test_predicate_agrees_with_cpython(v: dict) -> None:
    allowed = _predicate_verdicts(v)
    if not allowed:
        pytest.skip("a takeover or non-Python vector: the name table carries the spelling's verdict")
    _check_predicate(_files(v)[v["target"]], allowed, (v["cpython"] or {}).get("codec"), f"{v['id']} ({v['note']})")


@pytest.mark.parametrize("row", NAMES["names"], ids=lambda r: r["name"])
def test_predicate_on_every_codec_name(row: dict) -> None:
    data = f"# coding: {row['name']}\n".encode() + NAMES["body"].encode()
    _check_predicate(data, _predicate_verdicts(row), row["codec"], f"# coding: {row['name']}")


# ---------------------------------------------------------------------------
# The Python engine end to end
# ---------------------------------------------------------------------------


def _python_engine(files: dict[str, bytes], target: str, finding_id: str | None) -> tuple[str, list[dict], list]:
    """(outcome, findings, incomplete files) of one ASTAnalyzer run."""
    findings: list[dict] = []
    incomplete: list = []
    with tempfile.TemporaryDirectory() as d:
        _materialise(files, Path(d))
        try:
            ASTAnalyzer(d, "python").run(findings.append)
        except AnalysisIncomplete as exc:
            incomplete = exc.files
        except Exception as exc:  # noqa: BLE001 - an escaping error is an outcome to report, not a test crash
            # One file must never abort the analysis of the whole tree (for
            # example `# coding: idna`, whose codec refuses errors="replace").
            return f"crashed: {type(exc).__name__}: {exc}", findings, incomplete
    if any(rel == target for rel, _ in incomplete):
        return "lost", findings, incomplete
    if finding_id and any(f["id"] == finding_id and f["line"].startswith(target + ":") for f in findings):
        return "finding", findings, incomplete
    return "decoded", findings, incomplete


def _allowed(got: str, want: list) -> bool:
    # A crash is never allowed: it costs every other file in the tree (OR-53).
    return got in want


def _d2_false_clean(v: dict) -> None:
    """A taken-over, non-immune name was D2's documented false clean (OR-59).
    Under the shipped D2-A it is a real assertion (OR-85); only when the
    superseded D2 reading is asserted (FENDIX_PEP263_POLICY=d2) is it recorded
    as an expected failure, never a pass."""
    if v.get("d2_documented_false_clean") and not D2A:
        pytest.xfail(
            f"D2_DOCUMENTED_FALSE_CLEAN (OR-59): {v['id']} is taken over at run time and CPython runs its hidden "
            "program; D2 as first approved reads it clean. Asserted under the shipped D2-A"
        )


@pytest.mark.parametrize("v", VECTORS, ids=_ids)
def test_python_engine_reads_the_program_cpython_runs(v: dict) -> None:
    _d2_false_clean(v)
    want = _expect(v)["python_engine"]
    got, findings, incomplete = _python_engine(_files(v), v["target"], v.get("python_engine_finding"))
    at_target = sorted({f["id"] for f in findings if f["line"].startswith(v["target"] + ":")})
    if want == ["not_target"]:
        assert got in ("decoded", "finding"), f"{v['id']}: the Python engine does not select {v['target']}; got {got}"
    else:
        assert _allowed(got, want), (
            f"{v['id']} ({v['note']}; CPython {v['cpython']}): python engine {got}, want {want}; "
            f"findings at the target: {at_target}; incomplete: {incomplete}"
        )
    for control in v.get("controls", []):
        assert any(f["id"] == SHELL_ID and f["line"].startswith(control + ":") for f in findings), (
            f"{v['id']}: the plain {control} beside the vector lost its finding ({got})"
        )


CONTROL = NAMES["control"]


@pytest.mark.parametrize("row", NAMES["names"], ids=lambda r: r["name"])
def test_python_engine_on_every_codec_name(row: dict) -> None:
    """Each name in a tree beside the plain control file (OR-53): the name's
    file reads as the table says, and the control's finding is reported. A run
    that crashes, or that special-cases one codec name, fails here."""
    want = _expect(row)["python_engine"]
    data = f"# coding: {row['name']}\n".encode() + NAMES["body"].encode()
    files = {"n.py": data, CONTROL["file"]: base64.b64decode(CONTROL["b64"])}
    got, findings, incomplete = _python_engine(files, "n.py", None)
    assert _allowed(got, want), (
        f"# coding: {row['name']} (CPython: {row['verdict']}, codec {row['codec']}): python engine {got}, want {want}; "
        f"incomplete: {incomplete}"
    )
    assert any(f["id"] == CONTROL["finding"] and f["line"].startswith(CONTROL["file"] + ":") for f in findings), (
        f"# coding: {row['name']}: the plain {CONTROL['file']} beside it lost its finding ({got})"
    )


def test_bare_cr_utf7_injection_is_reported() -> None:
    """Must-pass (EXECUTION-PLAN §5, WS-E1): the Python engine reports the
    command injection in redteam5's bare-CR utf-7 fixture, byte for byte."""
    v = next(x for x in VECTORS if x["id"] == "c7-cr")
    got, findings, incomplete = _python_engine(_files(v), v["target"], SHELL_ID)
    assert got == "finding", f"c7-cr: {got}; findings {[f['id'] for f in findings]}; incomplete {incomplete}"


def test_runtime_registered_codec_is_lost_evaluation() -> None:
    """Must-pass (R6-E6): a file declaring a codec that only a run-time
    registration elsewhere in the repository provides is lost evaluation, not
    UTF-8 read clean."""
    v = next(x for x in VECTORS if x["id"] == "custom-codec")
    got, _, incomplete = _python_engine(_files(v), v["target"], None)
    assert got == "lost", f"custom-codec: {got}; incomplete {incomplete}"


# ---------------------------------------------------------------------------
# The shipped policy (Release Closure Sprint, WS-C2: D2-A, owner ruling OR-85).
# These do not read FENDIX_PEP263_POLICY: a tree left at "d2" cannot pass them.
# ---------------------------------------------------------------------------

_IMMUNE = [
    "utf-8", "utf_8", "utf8", "UTF-8", "Utf-8", "UTF8", "utf-8-sig", "utf-8-x", "UTF-8-SIG",
    "latin-1", "latin1", "latin_1", "iso-8859-1", "iso8859-1", "iso8859_1", "iso_8859_1", "iso_8859_1_1987",
    "iso-latin-1", "latin-1-x", "LATIN-1", "Latin1", "ISO-8859-1", "ISO8859_1",
    "ascii", "us-ascii", "us_ascii", "ASCII", "US-ASCII", "Us_Ascii",
]  # fmt: skip
_TAKEOVER_ABLE = [
    "utf", "UTF", "u8", "U8", "cp65001", "latin", "l1", "8859", "cp819", "646", "us", "cp367", "iso8859", "ibm819",
    "csisolatin1", "iso_ir_100", "ansi_x3.4_1968", "iso646_us", "utf8_ucs2",
    "cp1252", "CP1252", "windows-1252", "cp1250", "cp1251", "cp437", "cp850", "koi8-r", "koi8_u", "mac_roman",
    "iso8859_15", "iso-8859-15", "latin2", "latin9", "euc_jp", "euc_kr", "gb2312", "cp866", "tis_620",
]  # fmt: skip


def test_shipped_policy_is_d2a() -> None:
    assert scope_evidence.PEP263_POLICY == "d2a"


@pytest.mark.parametrize("name", _IMMUNE)
def test_shipped_policy_keeps_an_immune_spelling_transparent(name: str) -> None:
    got = scope_evidence.python_source_encoding(f"# coding: {name}\nx = 1\n".encode())
    assert got.verdict == "transparent" and not got.lost, f"# coding: {name}: {got}"


@pytest.mark.parametrize("name", _TAKEOVER_ABLE)
def test_shipped_policy_reads_a_takeover_able_spelling_as_foreign(name: str) -> None:
    got = scope_evidence.python_source_encoding(f"# coding: {name}\nx = 1\n".encode())
    assert got.verdict == "foreign" and got.lost, f"# coding: {name}: {got}"


def test_shipped_policy_matches_the_measured_immune_table() -> None:
    immune = [r["name"] for r in NAMES["names"] if r.get("takeover_immune") is True]
    assert len(immune) == 37, "the 37 spellings measured takeover-immune on CPython 3.14.5"
    for r in NAMES["names"]:
        data = f"# coding: {r['name']}\n".encode() + NAMES["body"].encode()
        got = scope_evidence.python_source_encoding(data)
        if r.get("takeover_immune") is True:
            assert got.verdict == "transparent", r["name"]
        elif r["verdict"] == "transparent":
            assert got.verdict == "foreign" and got.lost, f"{r['name']}: {got}"


def test_the_python_engine_still_decodes_a_takeover_able_file_it_cannot_trust_semgrep_with() -> None:
    """Foreign is lost for Semgrep and secrets only: the Python engine decodes
    the file with the codec CPython names and analyses it (D2-A keeps D2's
    other clause)."""
    body = b"import subprocess\nsubprocess.call(cmd, shell=True)\n"
    got, findings, incomplete = _python_engine({"a.py": b"# coding: cp1252\n" + body}, "a.py", SHELL_ID)
    assert got in ("finding", "decoded"), f"{got}; incomplete {incomplete}"


# ---------------------------------------------------------------------------
# Correction loop CL-2, finding A-2: a cookie naming one of CPython's non-text
# transform codecs (hex, base64, zlib, uu, bz2, quopri, rot13, undefined and
# their aliases) is refused by the registry, and the registry is what a module of
# the scanned repository rewrites. It is lost evaluation like any other
# non-immune cookie; only a refusal that does not go through the registry (a
# byte-order mark beside another codec) stays a refusal.
# ---------------------------------------------------------------------------

REFUSED_ROWS = [r for r in NAMES["names"] if r["verdict"] == "refused"]


def test_the_generated_table_has_66_refused_spellings() -> None:
    assert len(REFUSED_ROWS) == 66


@pytest.mark.parametrize("row", REFUSED_ROWS, ids=lambda r: r["name"])
def test_a_refused_codec_spelling_is_lost_evaluation(row: dict) -> None:
    got = scope_evidence.python_source_encoding(f"# coding: {row['name']}\n".encode() + NAMES["body"].encode())
    assert got.lost, f"# coding: {row['name']}: {got}"


@pytest.mark.parametrize("name", ["hex", "base64", "zlib", "uu", "bz2", "quopri", "quoted-printable", "rot13", "undefined", "zip"])
def test_the_python_engine_records_a_refused_codec_file_as_lost(name: str) -> None:
    got, _findings, incomplete = _python_engine({"n.py": f"# coding: {name}\nx = 1\n".encode()}, "n.py", None)
    assert got == "lost", f"# coding: {name}: {got}; incomplete {incomplete}"


def test_a_byte_order_mark_beside_another_codec_is_still_not_lost() -> None:
    for cookie in ("latin-1", "cp1252", "utf-7", "hex"):
        got = scope_evidence.python_source_encoding(b"\xef\xbb\xbf# coding: " + cookie.encode() + b"\nx = 1\n")
        assert got.verdict == "refused" and not got.lost, f"BOM beside {cookie}: {got}"
