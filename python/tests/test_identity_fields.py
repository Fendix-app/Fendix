"""Every Python-emitted finding must carry the identity the v2 fingerprint keys on.

The end-to-end baseline experiment caught what the Go unit corpus could not:
the Python dependency analyzer emits findings with no rule_id and no
dependency block, so four different CVEs across three different packages
collapsed into ONE identity —

    cat=deps + manifest=requirements.txt

and nothing else. Suppressing one of those findings would have suppressed all
four, silently. Identity can only key on what the emitter actually sends.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer
from analyzers.deps import DepsAnalyzer

REQUIREMENTS = """flask==0.12.2
requests==2.19.0
urllib3==1.24.1
"""


def _deps_findings() -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "requirements.txt").write_text(REQUIREMENTS)
        findings: list[dict] = []
        DepsAnalyzer(td).run(findings.append)
        return findings


def _vulnerable(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f["severity"] != "INFO"]


def test_dependency_findings_carry_their_advisory_id():
    for f in _vulnerable(_deps_findings()):
        assert f.get("rule_id"), (
            f"no rule_id on {f['title']!r} — identity has no advisory to key on"
        )


def test_dependency_findings_carry_the_package_they_are_about():
    for f in _vulnerable(_deps_findings()):
        dep = f.get("dependency")
        assert dep, f"no dependency block on {f['title']!r}"
        assert dep.get("ecosystem") == "PyPI", f"ecosystem = {dep.get('ecosystem')!r}"
        assert dep.get("package"), f"no package name on {f['title']!r}"
        assert dep.get("version"), f"no version on {f['title']!r}"


def test_distinct_advisories_do_not_share_one_identity():
    """The exact collision the A/B experiment surfaced.

    Four CVEs across three packages must be four identities, not one.
    """
    findings = _vulnerable(_deps_findings())
    assert len(findings) >= 4, f"fixture produced only {len(findings)} findings"

    identities = set()
    for f in findings:
        dep = f.get("dependency") or {}
        identities.add((f.get("rule_id"), dep.get("ecosystem"), dep.get("package")))

    assert len(identities) == len(findings), (
        f"{len(findings)} distinct advisories collapsed into {len(identities)} identities: "
        f"{sorted(identities)}"
    )


def test_unpinned_advisories_are_distinct_from_pinned_ones():
    """An unpinned-dependency advisory is a different claim from a vulnerable
    pin, so it must not share the pinned finding's identity."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "requirements.txt").write_text("flask>=0.10\nrequests==2.19.0\n")
        findings: list[dict] = []
        DepsAnalyzer(td).run(findings.append)

    info = [f for f in findings if f["severity"] == "INFO"]
    assert info, "fixture should produce at least one unpinned advisory"
    for f in info:
        assert f.get("rule_id"), f"no rule_id on unpinned advisory {f['title']!r}"


AST_SOURCE = """
import requests
from flask import request

def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""


def test_ast_findings_carry_an_explicit_rule_id():
    """The AST analyzer's rule identity lived only in the positional-looking
    `id` field. Identity fell back to parsing it, which works only because
    SEC-PY_SSRF happens not to look like the orchestrator's SEC-001 counter —
    too fragile a thing to leave implicit."""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "views.py").write_text(AST_SOURCE)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)

    assert findings, "fixture produced no findings"
    for f in findings:
        assert f.get("rule_id"), f"no rule_id on {f['title']!r}"


SINK_ONLY_SSRF_SRC = """
import os
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/thumb")
def make_thumb():
    src = os.environ.get("THUMB_SOURCE", "")
    return requests.get(src).content
"""

PROVEN_SSRF_SRC = SINK_ONLY_SSRF_SRC.replace(
    'src = os.environ.get("THUMB_SOURCE", "")', 'src = request.args.get("src")'
)


def _injection(source: str) -> dict:
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "svc.py").write_text(source)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)
    inj = [f for f in findings if f["category"] == "injection"]
    assert inj, f"no injection finding: {[f['id'] for f in findings]}"
    return inj[0]


def test_sink_is_emitted_even_without_a_proven_chain():
    """Identity keys on the vulnerable operation, and a chainless finding still
    HAS one — the analyzer builds the sink string either way. Withholding it
    when the chain is unproven forced identity to fall back to the evidence
    text, so proving a flow later re-identified the finding."""
    f = _injection(SINK_ONLY_SSRF_SRC)
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert f.get("sink"), f"no sink on a chainless finding: {f['title']!r}"


def test_the_sink_is_identical_with_and_without_a_proven_chain():
    """The operation `requests.get(src)` is the same operation whether or not
    the analyzer can prove where `src` came from."""
    sink_only = _injection(SINK_ONLY_SSRF_SRC)
    proven = _injection(PROVEN_SSRF_SRC)

    assert proven.get("taint_chain"), "fixture is meant to prove a chain"
    assert sink_only.get("sink") == proven.get("sink"), (
        f"the same operation reported two sinks: "
        f"{sink_only.get('sink')!r} vs {proven.get('sink')!r}"
    )


def test_symbol_is_emitted_with_and_without_a_proven_chain():
    """The enclosing function is the same function either way.

    It must not be read off the bound route: a route is attached only when a
    chain was proven, so a symbol taken from there appears exactly when the
    proof does — and identity would move on an evidence improvement.
    """
    sink_only = _injection(SINK_ONLY_SSRF_SRC)
    proven = _injection(PROVEN_SSRF_SRC)

    assert sink_only.get("symbol") == "make_thumb", (
        f"chainless finding has no symbol: {sink_only.get('symbol')!r}"
    )
    assert proven.get("symbol") == sink_only.get("symbol"), (
        f"symbol changed with the proof: {sink_only.get('symbol')!r} vs {proven.get('symbol')!r}"
    )


# --- JavaScript/TypeScript pattern checks -----------------------------------
#
# The regex pass over .js/.ts files used to emit no rule_id, so identity fell
# back to parsing the `id` field. That works only because SEC-JS_SQL_TEMPLATE
# does not look like the orchestrator's SEC-001 counter, and it is the same
# implicit dependency test_ast_findings_carry_an_explicit_rule_id retired for
# Python. The rule_id is deliberately the id VERBATIM: identity already derives
# rule=SEC-JS_SQL_TEMPLATE from it today, and any other string would move the
# fingerprint of every JS-pattern finding in an existing baseline (the Go side
# pins that in TestJSPatternFingerprintUnchanged).


def _collect_src_js(src: str, name: str = "app.ts") -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / name).write_text(src)
        findings: list[dict] = []
        ASTAnalyzer(td).run(findings.append)
        return findings


def test_js_pattern_findings_carry_rule_id():
    f = _collect_src_js("const r = await pool.query(`SELECT * FROM u WHERE n = '${name}'`);\n")
    assert [x["rule_id"] for x in f] == ["SEC-JS_SQL_TEMPLATE"]


JS_ALL_PATTERNS_SRC = """\
eval(userInput);
el.innerHTML = userInput;
document.write(userInput);
const r = await pool.query(`SELECT * FROM u WHERE n = '${name}'`);
"""


def test_every_js_pattern_rule_id_equals_its_id():
    """All four checks, not just the SQL one, and the rule_id is the id itself
    so the fingerprint cannot move."""
    f = _collect_src_js(JS_ALL_PATTERNS_SRC)
    assert sorted(x["id"] for x in f) == [
        "SEC-JS_DOCUMENT_WRITE",
        "SEC-JS_EVAL",
        "SEC-JS_INNER_HTML",
        "SEC-JS_SQL_TEMPLATE",
    ]
    for x in f:
        assert x.get("rule_id") == x["id"], (
            f"{x['id']}: rule_id {x.get('rule_id')!r} differs from id"
        )
