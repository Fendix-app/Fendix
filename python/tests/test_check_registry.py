"""The Python engine's own checks, as the security catalog publishes them.

The catalog (docs/security-catalog-contract.json) is generated in Go, and the
Go module cannot embed files from ../python, so the registry is mirrored into
go/internal/catalog/python_engine_checks.json. These tests keep four things
in step: the analyzer's emit sites, analyzers/check_registry.py, that copy,
and the published contract.
"""

from __future__ import annotations

import ast
import inspect
import json
import tempfile
from pathlib import Path

from analyzers import ast_analyzer
from analyzers.ast_analyzer import _JS_PATTERNS, ASTAnalyzer
from analyzers.check_registry import CHECKS, export_json

REPO_ROOT = Path(__file__).resolve().parents[2]
GO_COPY = REPO_ROOT / "go" / "internal" / "catalog" / "python_engine_checks.json"
CONTRACT = REPO_ROOT / "docs" / "security-catalog-contract.json"
# The analyzer the scan reports the engine's injection pass under.
CATALOG_ANALYZER = "python-engine/injection"

_EMIT_SIGNATURE = inspect.signature(ast_analyzer._PythonSecurityVisitor._emit_finding)
# _emit_finding's parameter names in call order, without `self`.
_POSITIONAL = tuple(name for name in _EMIT_SIGNATURE.parameters if name != "self")
_DEFAULT_CATEGORY = _EMIT_SIGNATURE.parameters["category"].default

# Checks whose every emit site builds its title with an f-string, so the
# registry's title cannot be compared verbatim. Each must at least name what
# it flags.
_FSTRING_TITLE_TERMS = {"PY_EVAL": "eval", "PY_OS_POPEN": "os.popen"}


def _literal(args: dict, key: str, default=None, constants: dict | None = None):
    """The argument's literal value, the default when it is not passed, or None
    when it is passed as an expression the test cannot evaluate. A name bound
    to a constant at the analyzer's module level (``_XSS_HTML_SINK_TITLE``, which
    two emit sites share) counts as that constant."""
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, ast.Name) and constants and value.id in constants:
        return constants[value.id]
    return value.value if isinstance(value, ast.Constant) else None


def _module_constants(tree: ast.Module) -> dict:
    """Module-level names the analyzer binds to a constant."""
    constants = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = stmt.value.value
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and isinstance(stmt.value, ast.Constant)
        ):
            constants[stmt.target.id] = stmt.value.value
    return constants


def _emit_sites() -> list[dict]:
    """Every _emit_finding(...) call in the analyzer, with its literal arguments.

    A pattern id that is not a string literal fails here rather than being
    skipped: a check the registry cannot see is a check the catalog omits.
    """
    tree = ast.parse(Path(ast_analyzer.__file__).read_text(encoding="utf-8"))
    constants = _module_constants(tree)
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
                # None for an f-string title
                "title": _literal(args, "title", None, constants),
                "severity": _literal(args, "severity", None, constants),
                "confidence": _literal(args, "confidence", None, constants),
                # Passing taint_chain= at all means a chain was attempted.
                "chain_attempted": "taint_chain" in args,
                "cwe": _literal(args, "cwe", None, constants),
                "category": _literal(args, "category", _DEFAULT_CATEGORY, constants),
            }
        )
    assert sites, "found no _emit_finding calls; has the analyzer been renamed?"
    return sites


def _by_id() -> dict:
    return {c.id: c for c in CHECKS}


def _emitted_identity(function: str):
    """Render functions for the `id` and `rule_id` a finding built in
    `function` carries, read from the f-strings in the analyzer's source.

    Returns (finding_id, rule_id), each mapping a pattern id to the string the
    analyzer emits. Reading the emitter keeps these tests from restating its
    naming scheme.
    """
    tree = ast.parse(Path(ast_analyzer.__file__).read_text(encoding="utf-8"))
    (func,) = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == function
    ]
    dicts = []
    for node in ast.walk(func):
        if isinstance(node, ast.Dict):
            keys = {
                k.value: v
                for k, v in zip(node.keys, node.values)
                if isinstance(k, ast.Constant)
            }
            if "id" in keys and "rule_id" in keys:
                dicts.append(keys)
    assert len(dicts) == 1, f"{function}: expected one finding dict, found {len(dicts)}"

    def render(template: ast.AST):
        assert isinstance(template, ast.JoinedStr), ast.dump(template)
        for part in template.values:
            assert isinstance(part, ast.Constant) or (
                isinstance(part, ast.FormattedValue)
                and isinstance(part.value, ast.Name)
                and part.value.id == "pat_id"
                and part.format_spec is None
            ), f"{function}: unexpected template part {ast.dump(part)}"
        return lambda pat_id: "".join(
            part.value if isinstance(part, ast.Constant) else pat_id
            for part in template.values
        )

    return render(dicts[0]["id"]), render(dicts[0]["rule_id"])


PY_FINDING_ID, PY_RULE_ID = _emitted_identity("_emit_finding")
JS_FINDING_ID, JS_RULE_ID = _emitted_identity("_analyze_js_heuristic")


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
    """CWE, category, default severity and confidence are what the analyzer
    emits for an unproven finding.

    A check emitted from several sites must emit the same values from all of
    them, or the catalog has no single value to publish. The default severity
    is the declared one: a call that passes proven_severity escalates only when
    a taint chain is collected. The confidence is the declared one after
    _emit_finding's demotion: a site that attempts a chain and collects none
    drops HIGH to MEDIUM.
    """
    checks = _by_id()
    sites = _emit_sites()
    for site in sites:
        check = checks[site["id"]]
        where = f"{site['id']} (ast_analyzer.py:{site['line']})"
        assert check.cwe == site["cwe"], where
        assert check.category == site["category"], where
        assert check.default_severity == site["severity"], where
        unproven = site["confidence"]
        if site["chain_attempted"] and unproven == "HIGH":
            unproven = "MEDIUM"
        assert check.confidence == unproven, where
        assert check.languages == ("python",), where
        assert check.rule_id == PY_RULE_ID(check.id), where
        assert check.finding_id == PY_FINDING_ID(check.id), where

    for check in CHECKS:
        titles = {s["title"] for s in sites if s["id"] == check.id}
        literal_titles = titles - {None}
        if literal_titles:
            assert check.title in literal_titles, (
                f"{check.id}: title {check.title!r} is none of the analyzer's "
                f"literal titles {sorted(literal_titles)}"
            )
        elif check.id.startswith("PY_"):
            assert check.id in _FSTRING_TITLE_TERMS, (
                f"{check.id}: every emit site builds its title with an f-string; "
                "add the term its title must contain to _FSTRING_TITLE_TERMS"
            )
            assert _FSTRING_TITLE_TERMS[check.id] in check.title, check.id
    fstring_only = {
        c.id
        for c in CHECKS
        if c.id.startswith("PY_")
        and not {s["title"] for s in sites if s["id"] == c.id} - {None}
    }
    assert set(_FSTRING_TITLE_TERMS) == fstring_only


def test_javascript_checks_match_their_patterns():
    checks = _by_id()
    for pat_id, title, _pattern, severity, confidence, cwe in _JS_PATTERNS:
        check = checks[pat_id]
        assert check.title == title, pat_id
        assert check.default_severity == severity, pat_id
        assert check.confidence == confidence, pat_id
        assert check.cwe == cwe, pat_id
        assert check.category == "injection", pat_id
        assert check.languages == ("javascript", "typescript"), pat_id
        assert check.rule_id == JS_RULE_ID(pat_id), pat_id
        assert check.finding_id == JS_FINDING_ID(pat_id), pat_id


def test_catalog_names_each_check_by_the_rule_id_its_findings_carry():
    """Every catalog id is the analyzer's emitted rule_id, and every
    finding_id its emitted finding id, as for every other analyzer.

    Expected values come from the emitters' own f-strings and their emitted
    pattern ids, not from the registry, so this checks the whole chain:
    analyzer -> registry -> Go copy -> published contract.
    """
    expected = {PY_RULE_ID(s["id"]): PY_FINDING_ID(s["id"]) for s in _emit_sites()}
    expected.update({JS_RULE_ID(p[0]): JS_FINDING_ID(p[0]) for p in _JS_PATTERNS})
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    published = {
        c["id"]: c.get("finding_id")
        for c in contract["checks"]
        if c["analyzer"] == CATALOG_ANALYZER
    }
    assert published == expected


# Unproven on purpose: no request source reaches any of these sinks, so each
# finding carries the confidence the catalog lists for its check.
_PY_SOURCE = """
import os
import pickle

import yaml


def lookup(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)


def run(cmd):
    os.system(cmd)


def restore(data):
    return pickle.loads(data)


def parse(text):
    return yaml.load(text)
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
    the id, rule_id, category, severity and confidence the registry publishes.
    The Python fixture covers a chain-attempted sink (SQL, os.system: HIGH
    demoted to MEDIUM) and sinks that attempt none (pickle, yaml: HIGH kept).
    """
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "repo.py").write_text(_PY_SOURCE)
        (Path(td) / "app.js").write_text(_JS_SOURCE)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)

    by_rule_id = {c.rule_id: c for c in CHECKS}
    fired = {}
    for finding in findings:
        check = by_rule_id[finding["rule_id"]]
        fired[check.id] = finding
        assert finding["id"] == check.finding_id, check.id
        assert finding["category"] == check.category, check.id
        assert finding["severity"] == check.default_severity, check.id
        assert not finding.get("taint_chain"), f"{check.id}: fixture must be unproven"
        assert finding["confidence"] == check.confidence, check.id
        assert finding["references"] == [check.cwe], check.id
    expected = {
        "PY_SQL_INJECTION",
        "PY_OS_SYSTEM",
        "PY_PICKLE_LOAD",
        "PY_YAML_UNSAFE_LOAD",
        "JS_EVAL",
        "JS_INNER_HTML",
        "JS_DOCUMENT_WRITE",
        "JS_SQL_TEMPLATE",
    }
    assert expected <= set(fired), f"fixture fired only {sorted(fired)}"
