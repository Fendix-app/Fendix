"""The Python engine's own checks, as the security catalog publishes them.

The catalog (docs/security-catalog-contract.json) is generated in Go, and the
Go module cannot embed files from ../python, so the registry is mirrored into
go/internal/catalog/python_engine_checks.json. These tests keep three things
in step: the analyzer's emit sites, analyzers/check_registry.py, and that copy.
"""

from __future__ import annotations

import ast
import inspect
import tempfile
from pathlib import Path

from analyzers import ast_analyzer
from analyzers.ast_analyzer import _JS_PATTERNS, ASTAnalyzer
from analyzers.check_registry import CHECKS, export_json

GO_COPY = (
    Path(__file__).resolve().parents[2]
    / "go"
    / "internal"
    / "catalog"
    / "python_engine_checks.json"
)

# _emit_finding(pat_id, title, severity, confidence, cwe, fix, lineno, ...)
_POSITIONAL = ("pat_id", "title", "severity", "confidence", "cwe")
_DEFAULT_CATEGORY = (
    inspect.signature(ast_analyzer._PythonSecurityVisitor._emit_finding)
    .parameters["category"]
    .default
)


def _literal(args: dict, key: str, default=None):
    """The argument's literal value, the default when it is not passed, or None
    when it is passed as an expression the test cannot evaluate."""
    value = args.get(key)
    if value is None:
        return default
    return value.value if isinstance(value, ast.Constant) else None


def _emit_sites() -> list[dict]:
    """Every _emit_finding(...) call in the analyzer, with its literal arguments.

    A pattern id that is not a string literal fails here rather than being
    skipped: a check the registry cannot see is a check the catalog omits.
    """
    tree = ast.parse(Path(ast_analyzer.__file__).read_text(encoding="utf-8"))
    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        )
        if name != "_emit_finding":
            continue
        args = dict(zip(_POSITIONAL, node.args))
        args.update({kw.arg: kw.value for kw in node.keywords if kw.arg})
        pat_id = args.get("pat_id")
        assert isinstance(pat_id, ast.Constant) and isinstance(pat_id.value, str), (
            f"ast_analyzer.py:{node.lineno}: _emit_finding's pattern id is not a "
            "string literal, so this test cannot see which check it emits. Pass "
            "the id as a literal."
        )
        sites.append(
            {
                "line": node.lineno,
                "id": pat_id.value,
                "title": _literal(args, "title"),  # None for an f-string title
                "severity": _literal(args, "severity"),
                "cwe": _literal(args, "cwe"),
                "category": _literal(args, "category", _DEFAULT_CATEGORY),
            }
        )
    assert sites, "found no _emit_finding calls; has the analyzer been renamed?"
    return sites


def _by_id() -> dict:
    return {c.id: c for c in CHECKS}


def test_every_emitted_check_is_registered():
    emitted = {site["id"] for site in _emit_sites()}
    emitted |= {pattern[0] for pattern in _JS_PATTERNS}
    assert emitted == {c.id for c in CHECKS}


def test_registry_ids_are_unique():
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_go_copy_matches_registry():
    assert GO_COPY.read_bytes() == export_json().encode("utf-8"), (
        "go/internal/catalog/python_engine_checks.json is stale; from python/ run "
        "`python -m analyzers.check_registry > ../go/internal/catalog/python_engine_checks.json`"
    )


def test_python_checks_match_their_emit_sites():
    """CWE, category and default severity are what the analyzer emits.

    A check emitted from several sites must emit the same values from all of
    them, or the catalog has no single value to publish. The default severity
    is the unproven one: a call that passes proven_severity escalates only when
    a taint chain is collected.
    """
    checks = _by_id()
    sites = _emit_sites()
    for site in sites:
        check = checks[site["id"]]
        where = f"{site['id']} (ast_analyzer.py:{site['line']})"
        assert check.cwe == site["cwe"], where
        assert check.category == site["category"], where
        assert check.default_severity == site["severity"], where
        assert check.languages == ("python",), where
        assert check.rule_id == f"python.ast/{check.id}", where

    for check in CHECKS:
        titles = {s["title"] for s in sites if s["id"] == check.id}
        literal_titles = titles - {None}
        if literal_titles:
            assert check.title in literal_titles, (
                f"{check.id}: title {check.title!r} is none of the analyzer's "
                f"literal titles {sorted(literal_titles)}"
            )


def test_javascript_checks_match_their_patterns():
    checks = _by_id()
    for pat_id, title, _pattern, severity, _confidence, cwe in _JS_PATTERNS:
        check = checks[pat_id]
        assert check.title == title, pat_id
        assert check.default_severity == severity, pat_id
        assert check.cwe == cwe, pat_id
        assert check.category == "injection", pat_id
        assert check.languages == ("javascript", "typescript"), pat_id
        assert check.rule_id == f"SEC-{pat_id}", pat_id


_PY_SOURCE = """
def lookup(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
"""

_JS_SOURCE = """
eval(userInput);
el.innerHTML = userInput;
document.write(userInput);
db.query(`SELECT * FROM users WHERE id = ${id}`);
"""


def test_registry_matches_what_the_analyzer_actually_emits():
    """The emit-site tests read source; this one runs the analyzer.

    Both emitters (Python _emit_finding and the JS pattern loop) must produce
    the rule_id, category and severity the registry publishes.
    """
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "repo.py").write_text(_PY_SOURCE)
        (Path(td) / "app.js").write_text(_JS_SOURCE)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)

    checks = _by_id()
    fired = {}
    for finding in findings:
        check = checks[finding["id"].removeprefix("SEC-")]
        fired[check.id] = finding
        assert finding["rule_id"] == check.rule_id, check.id
        assert finding["category"] == check.category, check.id
        assert finding["severity"] == check.default_severity, check.id
        assert finding["references"] == [check.cwe], check.id
    expected = {
        "PY_SQL_INJECTION",
        "JS_EVAL",
        "JS_INNER_HTML",
        "JS_DOCUMENT_WRITE",
        "JS_SQL_TEMPLATE",
    }
    assert expected <= set(fired), f"fixture fired only {sorted(fired)}"
