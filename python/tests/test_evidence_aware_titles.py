"""RC-6: a finding's title must never claim evidence stronger than it holds.

The analyzer already knows the difference — it downgrades confidence when a
reachability-dependent sink has no proven source->sink path — but the title is
passed in as one fixed string, so the same words are printed either way. A
chainless path-traversal match therefore reported "user input flows to
filesystem path" while asserting nothing of the kind, and a PROVEN SSRF
reported "Potential SSRF" while holding a complete taint chain.

The invariant under test: the wording of a finding is a function of the
evidence that finding carries.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from analyzers.ast_analyzer import ASTAnalyzer


def _analyze(source: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "views.py"
        target.write_text(source)
        findings: list[dict] = []
        ASTAnalyzer(str(td)).run(findings.append)
        return findings


def _one(findings: list[dict], finding_id: str) -> dict:
    matches = [f for f in findings if f["id"] == finding_id]
    assert matches, f"expected a {finding_id} finding, got {[f['id'] for f in findings]}"
    return matches[0]


# --- claims that outran the evidence ------------------------------------

SINK_ONLY_PATH = """
def read_report(name):
    # No request source anywhere: the argument is whatever the caller passes.
    return open(name).read()
"""

PROVEN_PATH = """
from flask import request

def read_report():
    name = request.args.get("name")
    return open(name).read()
"""


def test_sink_only_path_traversal_does_not_claim_a_flow():
    f = _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert "user input flows to" not in f["title"], (
        f"title claims a proven flow the finding does not hold: {f['title']!r}"
    )
    assert "user-controlled" not in f["title"], (
        f"title asserts user control that was never established: {f['title']!r}"
    )


def test_proven_path_traversal_states_the_flow():
    f = _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert f.get("taint_chain"), "fixture is meant to prove a source->sink path"
    assert "Potential" not in f["title"], (
        f"a proven taint path is not 'potential': {f['title']!r}"
    )


SINK_ONLY_SSRF = """
import requests

def fetch(url):
    return requests.get(url)
"""

PROVEN_SSRF = """
import requests
from flask import request

def fetch():
    url = request.args.get("url")
    return requests.get(url)
"""


def test_sink_only_ssrf_is_marked_potential():
    f = _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert f["title"].startswith("Potential"), (
        f"a sink-only observation must be hedged: {f['title']!r}"
    )


def test_proven_ssrf_drops_the_hedge():
    f = _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF")
    assert f.get("taint_chain"), "fixture is meant to prove a source->sink path"
    assert not f["title"].startswith("Potential"), (
        f"a proven source->sink path is no longer merely potential: {f['title']!r}"
    )
    assert "user-controlled" in f["title"], (
        f"a proven flow should say so plainly: {f['title']!r}"
    )


SINK_ONLY_REDIRECT = """
from flask import redirect

def go(target):
    return redirect(target)
"""


def test_sink_only_open_redirect_does_not_claim_user_control():
    f = _one(_analyze(SINK_ONLY_REDIRECT), "SEC-PY_OPEN_REDIRECT")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert "user-controlled" not in f["title"], (
        f"title asserts user control that was never established: {f['title']!r}"
    )


# --- the vocabulary is consistent, not per-rule improvisation -----------

def test_hedged_and_proven_titles_are_drawn_from_one_vocabulary():
    """Every reachability-dependent family hedges the same way.

    A reader scanning a report should be able to tell proven from observed at
    a glance, which only works if the marker is the same word everywhere.
    """
    chainless = [
        _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF"),
        _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL"),
        _one(_analyze(SINK_ONLY_REDIRECT), "SEC-PY_OPEN_REDIRECT"),
    ]
    for f in chainless:
        assert f["title"].startswith("Potential "), (
            f"{f['id']} hedges differently from its siblings: {f['title']!r}"
        )

    proven = [
        _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF"),
        _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL"),
    ]
    for f in proven:
        assert not f["title"].startswith("Potential "), (
            f"{f['id']} still hedges despite a proven chain: {f['title']!r}"
        )


def test_retitling_does_not_change_the_finding_identity_inputs():
    """RC-6 must not undo RC-5.

    Identity is keyed on rule, file, symbol and sink — never on the title —
    so the hedged and proven forms of one finding differ in wording and in
    nothing that identity reads.
    """
    sink_only = _one(_analyze(SINK_ONLY_SSRF), "SEC-PY_SSRF")
    proven = _one(_analyze(PROVEN_SSRF), "SEC-PY_SSRF")

    assert sink_only["title"] != proven["title"], "fixtures should differ in wording"
    assert sink_only["id"] == proven["id"], "the rule identity must not move with the title"
    assert sink_only["category"] == proven["category"]


# --- the claim, not just the wording, follows the evidence ---------------
#
# RC-6 made the WORDING evidence-aware. These lock the second half: a
# sink-only observation must not carry a blocking-grade severity either, and
# the name of the vulnerability class must not appear until the flow is real.


def test_sink_only_path_traversal_does_not_name_the_vulnerability_class():
    """A dynamic path is not automatically a traversal.

    Without a chain the analyzer has established only that a NON-CONSTANT
    value reaches a filesystem API — nothing about external control. Calling
    that "path traversal" names a class the evidence has not reached.
    """
    f = _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert not f.get("taint_chain"), "fixture is meant to be chainless"
    assert "path traversal" not in f["title"].lower(), (
        f"sink-only observation names the vulnerability class: {f['title']!r}"
    )
    assert f["title"] == "Potential unsafe dynamic filesystem path"


def test_sink_only_path_traversal_is_not_blocking_grade():
    """MEDIUM keeps it below the default --fail-on HIGH.

    Evidence is preserved — the finding is still emitted, still CWE-22, still
    carrying its evidence line — only the strength of the claim moves.
    """
    f = _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert f["severity"] == "MEDIUM", (
        f"an unproven filesystem path must not reach a blocking severity: {f['severity']}"
    )
    assert "CWE-22" in f["references"], "the advisory must survive de-escalation"


def test_proven_path_traversal_escalates_severity_and_ships_a_flow():
    """With a proven request->sink chain the claim is earned, so it is made."""
    f = _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL")
    assert f.get("taint_chain"), "fixture is meant to prove a source->sink path"
    assert f["severity"] == "HIGH", (
        f"a proven flow should carry the full severity: {f['severity']}"
    )
    assert "Path traversal" in f["title"]
    assert f.get("reachable") is True
    # The chain is what the SARIF exporter renders as codeFlows, matching the
    # SSRF source->sink representation.
    assert len(f["taint_chain"]) >= 1


def test_severity_escalation_does_not_move_identity():
    """The severity split must not re-file a finding as a new vulnerability."""
    sink_only = _one(_analyze(SINK_ONLY_PATH), "SEC-PY_PATH_TRAVERSAL")
    proven = _one(_analyze(PROVEN_PATH), "SEC-PY_PATH_TRAVERSAL")

    assert sink_only["severity"] != proven["severity"], "fixtures should differ in grade"
    assert sink_only["id"] == proven["id"], "rule identity must not move with severity"
    assert sink_only["rule_id"] == proven["rule_id"]
    assert sink_only["category"] == proven["category"]


# --- containment guards -------------------------------------------------

CONTAINED_BASENAME = """
import os
from flask import request

def read_report():
    name = os.path.basename(request.args.get("name"))
    return open(name).read()
"""

CONTAINED_SECURE_FILENAME = """
from flask import request
from werkzeug.utils import secure_filename

def upload():
    name = secure_filename(request.args.get("name"))
    return open(name).read()
"""

# The guard must reject an absolute path as well as "..": `open(name)` of
# "/etc/passwd" has no ".." in it (redteam2-py-02).
TRAVERSAL_REJECTED = """
import os
from flask import request, abort

def read_report():
    name = request.args.get("name")
    if ".." in name or os.path.isabs(name):
        abort(400)
    return open(name).read()
"""

DOTDOT_ONLY_REJECTED = """
from flask import request, abort

def read_report():
    name = request.args.get("name")
    if ".." in name:
        abort(400)
    return open(name).read()
"""

# `resolve()` does NOT contain — Path("/srv/../etc/passwd").resolve() is
# "/etc/passwd". Recognising the call alone would suppress the very traversal
# it appears to defend against.
RESOLVE_WITHOUT_CONTAINMENT = """
from pathlib import Path
from flask import request

def read_report():
    name = request.args.get("name")
    return open(Path(name).resolve()).read()
"""

# Django's UploadedFile.name is the filename the UPLOADER chose. An attribute
# called `name` is not a pathlib component accessor.
UPLOAD_NAME_IS_NOT_CONTAINMENT = """
import os

def h(request):
    return os.path.join('/d', request.FILES['f'].name)
"""


def test_basename_contains_traversal():
    findings = _analyze(CONTAINED_BASENAME)
    assert not [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"], (
        "basename() reduces the value to a single component; traversal cannot survive it"
    )


def test_secure_filename_contains_traversal():
    findings = _analyze(CONTAINED_SECURE_FILENAME)
    assert not [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"], (
        "secure_filename() strips separators and traversal sequences"
    )


def test_dominating_traversal_rejection_guard_contains():
    findings = _analyze(TRAVERSAL_REJECTED)
    assert not [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"], (
        "an early-exit guard rejecting '..' and absolute paths before the sink contains the flow"
    )


def test_dotdot_only_guard_does_not_contain_an_absolute_path():
    f = _one(_analyze(DOTDOT_ONLY_REJECTED), "SEC-PY_PATH_TRAVERSAL")
    assert f, "a '..' check alone lets open('/etc/passwd') through (redteam2-py-02)"


def test_bare_resolve_is_not_treated_as_containment():
    f = _one(_analyze(RESOLVE_WITHOUT_CONTAINMENT), "SEC-PY_PATH_TRAVERSAL")
    assert f, "resolve() without a containment assertion must not suppress the finding"


def test_upload_filename_attribute_is_not_containment():
    """Regression: `.name` on a Django upload is attacker-controlled input."""
    findings = _analyze(UPLOAD_NAME_IS_NOT_CONTAINMENT)
    assert [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"], (
        "request.FILES['f'].name is the uploader's filename, not a pathlib component"
    )
