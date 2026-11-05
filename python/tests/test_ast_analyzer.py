"""Tests for the ASTAnalyzer.

Verifies Python AST and JavaScript heuristic detection of dangerous patterns.
"""
from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from analyzers.ast_analyzer import ASTAnalyzer

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ast_target"


def _collect(path: str) -> list[dict]:
    findings: list[dict] = []
    ASTAnalyzer(path).run(findings.append)
    return findings


def _ids(findings: list[dict]) -> set[str]:
    return {f["id"] for f in findings}


# ---------------------------------------------------------------------------
# Python AST detection tests
# ---------------------------------------------------------------------------

class TestPythonAST:
    def test_os_system_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_OS_SYSTEM" in _ids(findings)

    def test_eval_with_dynamic_arg_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_EVAL" in _ids(findings)

    def test_subprocess_shell_true_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SUBPROCESS_SHELL" in _ids(findings)

    def test_sql_percent_formatting_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SQL_INJECTION" in _ids(findings)

    def test_sql_fstring_detected(self) -> None:
        """f-string SQL query should also be detected."""
        findings = _collect(str(FIXTURES_DIR))
        sql_findings = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        assert len(sql_findings) >= 2  # % formatting and f-string

    def test_safe_eval_literal_not_flagged(self) -> None:
        """eval('1 + 1') with a literal should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text("result = eval('1 + 1')\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_EVAL" not in _ids(findings)

    def test_safe_sql_not_flagged(self) -> None:
        """Parameterized query should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text(
                "cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)

    def test_subprocess_no_shell_not_flagged(self) -> None:
        """subprocess.run(list, shell=False) should not be flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.py").write_text(
                "import subprocess\nsubprocess.run(['ls', '-la'], shell=False)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SUBPROCESS_SHELL" not in _ids(findings)

    def test_clean_file_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            import shutil
            shutil.copy(FIXTURES_DIR / "clean.py", Path(tmpdir) / "clean.py")
            findings = _collect(tmpdir)
            assert findings == []


# ---------------------------------------------------------------------------
# TASK-087: Static analyzer expansion — pickle, yaml, weak crypto, open
# redirect, SSRF, auth-header trust, multi-step SQLi via assignment
# ---------------------------------------------------------------------------

class TestPickleDeserialization:
    def test_pickle_loads_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_PICKLE_LOAD" in _ids(findings)

    def test_pickle_finding_severity(self) -> None:
        findings = [f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert findings, "no pickle finding emitted"
        assert findings[0]["severity"] == "CRITICAL"
        assert "CWE-502" in findings[0]["references"]

    def test_pickle_alias_detected(self) -> None:
        """import pickle as p; p.loads(data) — aliased import must be detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "import pickle as p\n"
                "def deserialize(blob):\n"
                "    return p.loads(blob)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_PICKLE_LOAD" in _ids(findings), (
                f"Aliased pickle not detected; got {_ids(findings)}"
            )

    def test_cpickle_alias_detected(self) -> None:
        """import cPickle as cp; cp.loads(data)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "import cPickle as cp\n"
                "def deserialize(blob):\n"
                "    return cp.loads(blob)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_PICKLE_LOAD" in _ids(findings)


class TestYamlUnsafeLoad:
    def test_yaml_load_default_loader_detected(self) -> None:
        """yaml.load() without Loader= flagged."""
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(findings)

    def test_yaml_unsafe_load_detected(self) -> None:
        """yaml.unsafe_load() flagged regardless of args."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "u.py").write_text("import yaml\nyaml.unsafe_load(s)\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(findings)

    def test_yaml_load_with_safeloader_not_flagged(self) -> None:
        """yaml.load(s, Loader=yaml.SafeLoader) is the safe form."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" not in _ids(findings)

    def test_yaml_safe_load_helper_not_flagged(self) -> None:
        """yaml.safe_load() is the recommended helper — not flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text("import yaml\nyaml.safe_load(s)\n")
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" not in _ids(findings)

    def test_yaml_alias_load_detected(self) -> None:
        """import yaml as y; y.load(stream) — aliased import flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "import yaml as y\n"
                "def parse(stream):\n"
                "    return y.load(stream)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" in _ids(findings), (
                f"Aliased yaml.load not detected; got {_ids(findings)}"
            )

    def test_yaml_alias_safe_load_not_flagged(self) -> None:
        """import yaml as y; y.load(stream, Loader=y.SafeLoader) is still safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "import yaml as y\n"
                "def parse(stream):\n"
                "    return y.load(stream, Loader=y.SafeLoader)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_YAML_UNSAFE_LOAD" not in _ids(findings)


class TestWeakCryptoForPasswords:
    def test_md5_password_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_finding_emits_secrets_category(self) -> None:
        f = next(
            (f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_WEAK_CRYPTO_PASSWORD"),
            None,
        )
        assert f is not None
        assert f["category"] == "secrets"

    def test_md5_for_non_password_not_flagged(self) -> None:
        """hashlib.md5(data) where the var name doesn't suggest a password is fine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import hashlib\ndef checksum(payload):\n    return hashlib.md5(payload).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" not in _ids(findings)

    def test_hashlib_new_md5_detected(self) -> None:
        """hashlib.new('md5', password) is also flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import hashlib\ndef store(password):\n    return hashlib.new('md5', password).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_md5_with_pw_abbrev_detected(self) -> None:
        """hashlib.md5(pw.encode()) — `pw` is a common abbrev for password."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import hashlib\ndef store(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" in _ids(findings)

    def test_md5_with_power_arg_not_flagged(self) -> None:
        """`power` contains 'pw' as substring but is not a password — no FP."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import hashlib\ndef checksum(power):\n    return hashlib.md5(power).hexdigest()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_WEAK_CRYPTO_PASSWORD" not in _ids(findings)


class TestOpenRedirect:
    def test_open_redirect_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_OPEN_REDIRECT" in _ids(findings)

    def test_constant_redirect_not_flagged(self) -> None:
        """redirect('/dashboard') with a fixed string is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "from flask import redirect\ndef home():\n    return redirect('/home')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_OPEN_REDIRECT" not in _ids(findings)


class TestSSRF:
    def test_ssrf_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_SSRF" in _ids(findings)

    def test_ssrf_constant_url_not_flagged(self) -> None:
        """requests.get('https://...') with a literal URL is not SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import requests\ndef ping():\n    return requests.get('https://api.example.com/x')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" not in _ids(findings)

    def test_ssrf_resolved_constant_var_not_flagged(self) -> None:
        """requests.get(URL) where URL was assigned a literal earlier — not SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import requests\ndef ping():\n    URL = 'https://api.example.com/x'\n    return requests.get(URL)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" not in _ids(findings)

    def test_ssrf_urllib_request_urlopen_tainted(self) -> None:
        """urllib.request.urlopen(tainted) is SSRF — gap surfaced by Track 4 (Juliet)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import urllib.request\n"
                "from flask import request\n"
                "def fetch():\n"
                "    u = request.args.get('u')\n"
                "    return urllib.request.urlopen(u).read()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" in _ids(findings)
            ssrf = next(f for f in findings if f["id"] == "SEC-PY_SSRF")
            assert "urllib.request.urlopen" in ssrf.get("evidence", "") + ssrf.get("title", "") + str(ssrf.get("metadata", {}))

    def test_ssrf_urllib_request_urlretrieve_tainted(self) -> None:
        """urllib.request.urlretrieve(tainted) is SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import urllib.request\n"
                "from flask import request\n"
                "def fetch():\n"
                "    u = request.args.get('u')\n"
                "    return urllib.request.urlretrieve(u, '/tmp/out')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" in _ids(findings)

    def test_ssrf_urllib_literal_url_not_flagged(self) -> None:
        """urllib.request.urlopen('https://...') with a literal URL is not SSRF."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "import urllib.request\n"
                "def fetch():\n"
                "    return urllib.request.urlopen('https://api.example.com/x').read()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" not in _ids(findings)

    def test_ssrf_six_moves_urllib_request_urlopen_tainted(self) -> None:
        """six.moves.urllib.request.urlopen(tainted) is SSRF (Python 2 compat shim)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "import six\n"
                "from flask import request\n"
                "def fetch():\n"
                "    u = request.args.get('u')\n"
                "    return six.moves.urllib.request.urlopen(u).read()\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SSRF" in _ids(findings)


class TestAuthHeaderTrust:
    def test_auth_header_trust_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)

    def test_finding_emits_auth_bypass_category(self) -> None:
        f = next(
            (f for f in _collect(str(FIXTURES_DIR)) if f["id"] == "SEC-PY_AUTH_HEADER_TRUST"),
            None,
        )
        assert f is not None
        assert f["category"] == "auth_bypass"

    def test_session_check_not_flagged(self) -> None:
        """if request.session.get(...) is a verified session, not a header — safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "from flask import request\ndef view():\n    if request.session.get('uid'):\n        return 'ok'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" not in _ids(findings)

    def test_subscript_form_detected(self) -> None:
        """if request.headers['X-Admin']: is also flagged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "from flask import request\ndef view():\n    if request.headers['X-Admin']:\n        return 'admin'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)

    def test_handler_arg_named_req_detected(self) -> None:
        """Flask-style handler arg named `req` (common abbreviation)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bad.py").write_text(
                "def view(req):\n    if req.headers.get('X-Admin') == 'true':\n        return 'admin'\n    return 'no'\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_AUTH_HEADER_TRUST" in _ids(findings)


class TestTaintChain:
    """TASK-114: AST analyzer records a taint chain when it can prove
    user input flows from a request source to a dangerous sink. The
    chain is later used by the Go correlator to escalate matched
    findings to `Reachable=true`."""

    def test_inline_request_input_in_sink_yields_chain(self) -> None:
        """cursor.execute(request.args.get('q')) — chain records source→sink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler(cursor):\n"
                "    cursor.execute(request.args.get('q'))\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert len(sql) == 1, f"expected 1 SQLi finding, got {len(sql)}"
            f = sql[0]
            assert f.get("reachable") is True
            assert isinstance(f.get("taint_chain"), list)
            assert len(f["taint_chain"]) >= 2, f["taint_chain"]
            # First link references request input; last link is the sink.
            assert "request.args" in f["taint_chain"][0]["expr"]
            assert "execute" in f["taint_chain"][-1]["expr"]

    def test_multi_step_assignment_yields_chain(self) -> None:
        """q = request.args.get('q'); sql = '...' + q; cursor.execute(sql) — full chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler(cursor):\n"
                "    q = request.args.get('q')\n"
                "    sql = 'SELECT * FROM u WHERE id=' + q\n"
                "    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert len(sql) == 1
            chain = sql[0].get("taint_chain") or []
            assert sql[0].get("reachable") is True
            # 3 links: source assignment, intermediate assignment, sink.
            assert len(chain) >= 3, f"expected ≥3 chain links, got {chain}"
            assert "request.args" in chain[0]["expr"]
            assert any("execute" in link["expr"] for link in chain)

    def test_constant_value_yields_no_chain(self) -> None:
        """sql = 'static + ' + str(uuid); cursor.execute(sql) — no source, no chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import uuid\n"
                "def handler(cursor):\n"
                "    sql = 'SELECT * FROM logs WHERE id=' + str(uuid.uuid4())\n"
                "    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            # SQLi still flagged (BinOp + Call concat is still suspicious),
            # but no chain because no request source was traced.
            assert len(sql) == 1
            assert sql[0].get("reachable") is not True
            assert sql[0].get("taint_chain") is None or sql[0]["taint_chain"] == []

    def test_ssrf_chain_recorded(self) -> None:
        """requests.get(request.GET['url']) — SSRF with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import requests\n"
                "def handler(request):\n"
                "    return requests.get(request.GET['url'])\n"
            )
            findings = _collect(tmpdir)
            ssrf = [f for f in findings if f["id"] == "SEC-PY_SSRF"]
            assert len(ssrf) == 1
            assert ssrf[0].get("reachable") is True
            assert any("request.GET" in link["expr"] for link in ssrf[0]["taint_chain"])

    def test_open_redirect_chain_recorded(self) -> None:
        """redirect(request.args.get('next')) — open redirect with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request, redirect\n"
                "def handler():\n"
                "    return redirect(request.args.get('next'))\n"
            )
            findings = _collect(tmpdir)
            redir = [f for f in findings if f["id"] == "SEC-PY_OPEN_REDIRECT"]
            assert len(redir) == 1
            assert redir[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in redir[0]["taint_chain"])


class TestXSSHTMLSink:
    """TASK-120 — reachable XSS taint chains.

    The Python AST analyzer recognises three HTML-render sinks that
    bypass auto-escaping: `Markup` (Flask/MarkupSafe), `mark_safe`
    (Django), and `render_template_string` (Flask/Jinja2). When user
    input flows into the first argument, the chain is recorded and
    `reachable: true` is set — same shape as TASK-114's SQLi/SSRF/
    open-redirect chains.
    """

    def test_markup_with_request_arg_emits_chain(self) -> None:
        """Markup(request.args.get('x')) — reflective XSS with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    return Markup(request.args.get('msg'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1, f"got {[f['id'] for f in findings]}"
            assert xss[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in xss[0]["taint_chain"])

    def test_mark_safe_with_request_arg_emits_chain(self) -> None:
        """Django mark_safe(request.GET['x']) — XSS bypassing auto-escape."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from django.utils.safestring import mark_safe\n"
                "def handler(request):\n"
                "    return mark_safe(request.GET['msg'])\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True
            assert any("request.GET" in link["expr"] for link in xss[0]["taint_chain"])

    def test_render_template_string_with_request_arg_emits_chain(self) -> None:
        """render_template_string(user_input) — SSTI + XSS path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import render_template_string, request\n"
                "def handler():\n"
                "    return render_template_string(request.args.get('tpl'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True

    def test_multi_step_assignment_resolves(self) -> None:
        """msg = request.args.get('x'); html = Markup(msg) — chain across hop."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    msg = request.args.get('msg')\n"
                "    return Markup(msg)\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            assert xss[0].get("reachable") is True
            # Chain should have at least 2 links: source assignment + sink.
            assert len(xss[0]["taint_chain"]) >= 2

    def test_attribute_form_flask_markup_detected(self) -> None:
        """flask.Markup(request.args['x']) — attribute call form."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import flask\n"
                "def handler():\n"
                "    return flask.Markup(flask.request.args['msg'])\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            # Attribute-form call resolves the sink name; the request
            # input is recognised via flask.request.args reference.
            assert len(xss) == 1, f"expected 1 XSS finding, got {[f['id'] for f in findings]}"

    def test_constant_arg_not_flagged(self) -> None:
        """Markup('<b>static</b>') — literal-only, no flow → no finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def banner():\n"
                "    return Markup('<b>welcome</b>')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_XSS_HTML_SINK" not in _ids(findings)

    def test_variable_resolving_to_constant_not_flagged(self) -> None:
        """html = '<b>static</b>'; Markup(html) — still safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def banner():\n"
                "    html = '<b>welcome</b>'\n"
                "    return Markup(html)\n"
            )
            findings = _collect(tmpdir)
            # Constant-only chain isn't flagged: the variable resolves
            # to a Constant in scope, so _is_xss_html_sink returns False.
            assert "SEC-PY_XSS_HTML_SINK" not in _ids(findings)

    def test_no_user_input_chain_emits_finding_without_reachable(self) -> None:
        """Markup(other_func()) — non-literal arg → finding, but no chain.

        Matches the SQLi/SSRF/open-redirect posture: a non-literal arg
        to a known sink is suspicious regardless of whether we can trace
        the source. The finding fires; `reachable: true` is only set
        when the chain traces all the way back to a request source.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup\n"
                "def render(x):\n"
                "    return Markup(some_helper(x))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            # No request source traced — finding fires but isn't escalated.
            assert xss[0].get("reachable") is not True
            assert xss[0].get("taint_chain") is None or xss[0]["taint_chain"] == []

    def test_finding_shape_matches_other_reachable_findings(self) -> None:
        """XSS finding has the same fields as SQLi/SSRF/open-redirect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import Markup, request\n"
                "def handler():\n"
                "    return Markup(request.args.get('x'))\n"
            )
            findings = _collect(tmpdir)
            xss = [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"]
            assert len(xss) == 1
            f = xss[0]
            assert f["severity"] == "HIGH"
            assert f["confidence"] == "MEDIUM"
            assert f["source"] == "whitebox"
            assert f["category"] == "injection"
            assert "CWE-79" in f["references"]
            assert f["reachable"] is True
            assert isinstance(f["taint_chain"], list)
            for link in f["taint_chain"]:
                assert set(link.keys()) >= {"file", "line", "expr"}


_DJANGO_VIEW = (
    "from django.http import HttpResponse\n"
    "def greet(request):\n"
    '    name = request.GET.get("name", "")\n'
)
_FLASK_VIEW = (
    "from flask import Response, make_response, request\n"
    "def greet():\n"
    '    name = request.args.get("name", "")\n'
)
_STARLETTE_VIEW = (
    "from fastapi import FastAPI\n"
    "from starlette.responses import Response\n"
    "app = FastAPI()\n"
    '@app.get("/greet")\n'
    'def greet(name: str = ""):\n'
)


class TestHTMLResponseSink:
    """Task 3.2: an HTML response constructor is an XSS sink.

    Django ``HttpResponse``, Flask ``make_response`` and ``Response``, and
    Starlette/FastAPI ``HTMLResponse`` and ``Response`` send their body to the
    browser, which renders it as HTML unless the response declares a non-HTML
    content type. Request text reaching that body unescaped is reflected XSS,
    reported under the existing PY_XSS_HTML_SINK rule (no new rule id).
    """

    @staticmethod
    def _xss(src: str) -> list[dict]:
        return [f for f in _collect_src(src) if f["id"] == "SEC-PY_XSS_HTML_SINK"]

    def _proven(self, src: str, source: str) -> dict:
        found = self._xss(src)
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is True, f
        assert any(source in link["expr"] for link in f["taint_chain"]), f["taint_chain"]
        return f

    def _clean(self, src: str) -> None:
        found = self._xss(src)
        assert found == [], found

    # -- the three framework shapes -------------------------------------------

    def test_django_httpresponse_fstring_is_xss(self) -> None:
        f = self._proven(
            _DJANGO_VIEW + '    return HttpResponse(f"<h1>{name}</h1>")\n', "request.GET"
        )
        assert f["line"] == "mod.py:4"
        assert f["sink"] == "HttpResponse(f'<h1>{name}</h1>')"
        assert f["severity"] == "HIGH"
        assert "CWE-79" in f["references"]

    def test_flask_make_response_is_xss(self) -> None:
        f = self._proven(
            _FLASK_VIEW + '    return make_response(f"<h1>{name}</h1>")\n', "request.args"
        )
        assert f["sink"] == "make_response(f'<h1>{name}</h1>')"

    def test_fastapi_htmlresponse_is_xss(self) -> None:
        # `name` is a route parameter, which Task 3.1 made a request source.
        f = self._proven(
            "from fastapi import FastAPI\n"
            "from fastapi.responses import HTMLResponse\n"
            "app = FastAPI()\n"
            '@app.get("/greet")\n'
            'def greet(name: str = ""):\n'
            '    return HTMLResponse(f"<h1>{name}</h1>")\n',
            "name",
        )
        assert f["taint_chain"][0] == {"file": "mod.py", "line": 5, "expr": "name"}
        assert f["sink"] == "HTMLResponse(f'<h1>{name}</h1>')"

    def test_body_passed_by_keyword_is_xss(self) -> None:
        # FastAPI's own docs write `HTMLResponse(content=html, status_code=200)`.
        self._proven(
            "from fastapi import FastAPI\n"
            "from fastapi.responses import HTMLResponse\n"
            "app = FastAPI()\n"
            '@app.get("/greet")\n'
            'def greet(name: str = ""):\n'
            '    html = "<h1>" + name + "</h1>"\n'
            "    return HTMLResponse(content=html, status_code=200)\n",
            "name",
        )

    def test_same_file_helper_is_proven_through_the_caller(self) -> None:
        # The parity corpus's `indirect` shape: the sink sits in a helper.
        f = self._proven(
            "from django.http import HttpResponse\n"
            "def _render_greeting(name):\n"
            '    return HttpResponse(f"<h1>Hello, {name}!</h1>")\n'
            "def greet(request):\n"
            '    name = request.GET.get("name", "")\n'
            "    return _render_greeting(name)\n",
            "request.GET",
        )
        assert f["line"] == "mod.py:3"

    def test_helper_with_no_caller_is_reported_unproven(self) -> None:
        # The `cross_file` shape: the caller lives in another file.
        found = self._xss(
            "from django.http import HttpResponse\n"
            "def render_greeting(name: str):\n"
            '    return HttpResponse(f"<h1>Hello, {name}!</h1>")\n'
        )
        assert len(found) == 1, found
        assert found[0].get("reachable") is None
        assert found[0]["sink"] == "HttpResponse(f'<h1>Hello, {name}!</h1>')"

    @pytest.mark.parametrize(
        "lines",
        [
            '    return HttpResponse("<p>{}</p>".format(name))\n',
            '    return HttpResponse("<p>%s</p>" % name)\n',
            '    return HttpResponse("".join(["<p>", name, "</p>"]))\n',
            "    return HttpResponse(str(name))\n",
            "    return HttpResponse(name.strip())\n",
            '    return HttpResponse(name if name else "-")\n',
            '    html = "<ul>"\n    html += f"<li>{name}</li>"\n    return HttpResponse(html)\n',
            '    return HttpResponse(request.GET["name"])\n',
            '    return HttpResponse(content=f"<p>{name}</p>")\n',
            '    return HttpResponse(name or "anonymous")\n',
        ],
        ids=[
            "format", "percent", "join", "str", "method", "ifexp", "accumulator",
            "inline-source", "content-keyword", "boolop",
        ],
    )
    def test_body_shapes_that_carry_request_text_are_xss(self, lines: str) -> None:
        self._proven(_DJANGO_VIEW + lines, "request.GET")

    def test_parameter_accumulated_into_a_body_is_reported(self) -> None:
        # `html += ...` with no earlier binding still holds the parameter.
        found = self._xss(
            "from django.http import HttpResponse\n"
            "def page(html):\n"
            '    html += "</p>"\n'
            "    return HttpResponse(html)\n"
        )
        assert len(found) == 1, found

    @pytest.mark.parametrize(
        "ret",
        [
            "HttpResponse(name)",
            'HttpResponse(f"<p>{name}</p>")',
            'HttpResponse("<p>" + LABELS[name] + "</p>")',
        ],
        ids=["bare", "fstring", "allowlist-lookup"],
    )
    def test_allowlisted_value_is_not_xss(self, ret: str) -> None:
        self._clean(
            'ALLOWED = {"en", "fr"}\n'
            'LABELS = {"en": "English", "fr": "French"}\n'
            + _DJANGO_VIEW
            + "    if name not in ALLOWED:\n"
            + "        return HttpResponse(status=400)\n"
            + f"    return {ret}\n"
        )

    # -- content type ---------------------------------------------------------

    def test_httpresponse_with_json_content_type_is_not_xss(self) -> None:
        self._clean(
            _DJANGO_VIEW + '    return HttpResponse(name, content_type="application/json")\n'
        )

    def test_starlette_response_plain_media_type_is_not_xss(self) -> None:
        self._clean(_STARLETTE_VIEW + '    return Response(name, media_type="text/plain")\n')

    def test_starlette_response_without_media_type_is_xss(self) -> None:
        # No media type means no Content-Type header, and the browser sniffs
        # the body as HTML.
        self._proven(_STARLETTE_VIEW + "    return Response(name)\n", "name")

    @pytest.mark.parametrize(
        "call",
        [
            'HttpResponse(f"<p>{name}</p>", content_type="text/plain")',
            'HttpResponse(f"<p>{name}</p>", content_type="application/json")',
            'HttpResponse(f"{name}", content_type="text/csv")',
            'HttpResponse(f"<p>{name}</p>", "text/plain")',
            'HttpResponse(f"<p>{name}</p>", headers={"Content-Type": "text/plain"})',
        ],
    )
    def test_non_html_content_types_are_not_xss(self, call: str) -> None:
        self._clean(_DJANGO_VIEW + f"    return {call}\n")

    @pytest.mark.parametrize(
        "call",
        [
            'HttpResponse(f"<p>{name}</p>", content_type="text/html; charset=utf-8")',
            'HttpResponse(f"<p>{name}</p>", content_type="TEXT/HTML")',
            'HttpResponse(f"<p>{name}</p>", content_type="application/xhtml+xml")',
            'HttpResponse(f"<p>{name}</p>", content_type=None)',
            'HttpResponse(f"<p>{name}</p>", content_type="")',
            'HttpResponse(f"<p>{name}</p>", headers={"content-type": "text/html"})',
        ],
    )
    def test_html_content_types_are_xss(self, call: str) -> None:
        self._proven(_DJANGO_VIEW + f"    return {call}\n", "request.GET")

    @pytest.mark.parametrize(
        "call",
        [
            'make_response(f"<p>{name}</p>", 200, {"Content-Type": "text/plain"})',
            'make_response(f"<p>{name}</p>", {"Content-Type": "application/json"})',
            'Response(f"<p>{name}</p>", mimetype="application/json")',
            'Response(response=f"<p>{name}</p>", content_type="text/plain")',
        ],
    )
    def test_flask_non_html_responses_are_not_xss(self, call: str) -> None:
        self._clean(_FLASK_VIEW + f"    return {call}\n")

    @pytest.mark.parametrize(
        "call",
        [
            'make_response(f"<p>{name}</p>", 200, {"X-Frame-Options": "DENY"})',
            'Response(response=f"<p>{name}</p>")',
            'Response(f"<p>{name}</p>", mimetype="text/html")',
        ],
    )
    def test_flask_html_responses_are_xss(self, call: str) -> None:
        self._proven(_FLASK_VIEW + f"    return {call}\n", "request.args")

    def test_htmlresponse_is_html_whatever_it_declares(self) -> None:
        # The brief's rule: HTMLResponse is HTML. Overriding its media type is
        # an odd call, and reporting it fails toward the safe side.
        self._proven(
            "from fastapi import FastAPI\n"
            "from fastapi.responses import HTMLResponse\n"
            "app = FastAPI()\n"
            '@app.get("/greet")\n'
            'def greet(name: str = ""):\n'
            '    return HTMLResponse(f"<p>{name}</p>", media_type="text/plain")\n',
            "name",
        )

    @pytest.mark.parametrize(
        "view, build, late",
        [
            (_FLASK_VIEW, "make_response", 'resp.headers["Content-Type"] = "application/json"'),
            (_FLASK_VIEW, "make_response", 'resp.mimetype = "application/json"'),
            (_FLASK_VIEW, "Response", 'resp.content_type = "text/plain; charset=utf-8"'),
            (_DJANGO_VIEW, "HttpResponse", 'resp["Content-Type"] = "application/json"'),
            (_DJANGO_VIEW, "HttpResponse", 'resp["content-type"] = JSON'),
            (_STARLETTE_VIEW, "Response", 'resp.media_type = "application/json"'),
        ],
        ids=["flask-headers", "flask-mimetype", "flask-content_type", "django", "django-name", "starlette"],
    )
    def test_content_type_set_after_construction_is_not_xss(
        self, view: str, build: str, late: str
    ) -> None:
        self._clean(
            'import json\nJSON = "application/json"\n'
            + view
            + f'    resp = {build}(json.dumps({{"n": name}}))\n'
            + '    resp.headers["X-Frame-Options"] = "DENY"\n'
            + f"    {late}\n"
            + "    return resp\n"
        )

    @pytest.mark.parametrize(
        "late",
        [
            'resp["Content-Type"] = "text/html"',
            'resp["Content-Type"] = kind',
            'resp["Content-Type"] = "application/json"\n    resp["Content-Type"] = "text/html"',
            'other = HttpResponse("")\n    other["Content-Type"] = "application/json"',
        ],
        ids=["html", "variable", "html-later", "another-response"],
    )
    def test_late_html_or_unknown_content_type_is_xss(self, late: str) -> None:
        self._proven(
            _DJANGO_VIEW
            + "    kind = pick_type()\n"
            + '    resp = HttpResponse(f"<p>{name}</p>")\n'
            + f"    {late}\n"
            + "    return resp\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "body",
        [
            # the type is set on a later binding, after this response returned
            (
                '    if request.args.get("fmt") == "html":\n'
                '        resp = make_response(f"<p>{name}</p>")\n'
                "        return resp\n"
                '    resp = make_response(json.dumps({"n": name}))\n'
                '    resp.headers["Content-Type"] = "application/json"\n'
                "    return resp\n"
            ),
            # the type is set on a sibling branch's response
            (
                '    if request.args.get("fmt") == "html":\n'
                '        resp = make_response(f"<p>{name}</p>")\n'
                "    else:\n"
                '        resp = make_response(json.dumps({"n": name}))\n'
                '        resp.mimetype = "application/json"\n'
                "    return resp\n"
            ),
            # the type is set in only one branch, or only on an error path
            (
                '    resp = make_response(f"<p>{name}</p>")\n'
                '    if request.args.get("fmt") == "json":\n'
                '        resp.mimetype = "application/json"\n'
                "    return resp\n"
            ),
            (
                '    resp = make_response(f"<p>{name}</p>")\n'
                "    try:\n"
                "        pass\n"
                "    except Exception:\n"
                '        resp.mimetype = "text/plain"\n'
                "    return resp\n"
            ),
            # the response may return before the type is set
            (
                "    for i in range(2):\n"
                '        resp = make_response(f"<p>{name}</p>")\n'
                "        if i:\n"
                "            return resp\n"
                '        resp.mimetype = "text/plain"\n'
                "    return resp\n"
            ),
            # the name is rebound before the type is set
            (
                '    resp = make_response(f"<p>{name}</p>")\n'
                "    page = resp\n"
                '    resp = make_response("")\n'
                '    resp.mimetype = "text/plain"\n'
                "    return page\n"
            ),
            # a branch may set HTML after a JSON type
            (
                '    resp = make_response(f"<p>{name}</p>")\n'
                '    resp.mimetype = "application/json"\n'
                '    if request.args.get("html"):\n'
                '        resp.mimetype = "text/html"\n'
                "    return resp\n"
            ),
        ],
        ids=[
            "rebinding-after-return", "sibling-branch", "one-branch-only", "except-only",
            "after-return-in-loop", "rebound-name", "branch-after-json",
        ],
    )
    def test_late_content_type_counts_only_in_the_bindings_own_block(self, body: str) -> None:
        found = self._xss("import json\n" + _FLASK_VIEW + body)
        html = [f for f in found if "<p>" in f["sink"]]
        assert len(html) == 1, found
        assert html[0].get("reachable") is True, html[0]

    @pytest.mark.parametrize(
        "ctor, late",
        [
            ('HttpResponse(f"<p>{name}</p>", content_type="text/plain")', 'resp["Content-Type"] = "text/html"'),
            ('HttpResponse(f"<p>{name}</p>", content_type="application/json")', "resp['content-type'] = kind"),
        ],
        ids=["late-html", "late-variable"],
    )
    def test_late_content_type_overrides_the_construction(self, ctor: str, late: str) -> None:
        # A late type decides by itself, whatever the constructor declared.
        self._proven(
            _DJANGO_VIEW
            + "    kind = pick_type()\n"
            + f"    resp = {ctor}\n"
            + f"    {late}\n"
            + "    return resp\n",
            "request.GET",
        )

    def test_last_late_content_type_wins(self) -> None:
        self._clean(
            _FLASK_VIEW
            + '    resp = make_response(f"<p>{name}</p>")\n'
            + '    resp.mimetype = "text/html"\n'
            + '    if request.args.get("x"):\n'
            + '        resp.headers["X-Mode"] = "x"\n'
            + '    resp.mimetype = "text/plain"\n'
            + "    return resp\n"
        )

    def test_content_type_set_before_construction_does_not_count(self) -> None:
        self._proven(
            _DJANGO_VIEW
            + '    resp = HttpResponse("")\n'
            + '    resp["Content-Type"] = "application/json"\n'
            + '    resp = HttpResponse(f"<p>{name}</p>")\n'
            + "    return resp\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "view, call",
        [
            (_FLASK_VIEW, "Response(name, status=204)"),
            (_FLASK_VIEW, "Response(name, 304)"),
            (_FLASK_VIEW, "make_response(name, 204)"),
            (_DJANGO_VIEW, "HttpResponse(name, status=HTTPStatus.NO_CONTENT)"),
            (_STARLETTE_VIEW, "Response(name, status_code=204)"),
        ],
        ids=["flask-kw", "flask-304", "make_response", "django-httpstatus", "starlette"],
    )
    def test_bodyless_status_is_not_xss(self, view: str, call: str) -> None:
        # The browser renders no body for 204 or 304 (Werkzeug drops it).
        self._clean("from http import HTTPStatus\n" + view + f"    return {call}\n")

    @pytest.mark.parametrize(
        "view, call",
        [
            (_FLASK_VIEW, 'Response(json.dumps({"n": name}), 200, None, "application/json")'),
            (_FLASK_VIEW, 'Response(json.dumps({"n": name}), 200, None, None, "text/plain")'),
            (_STARLETTE_VIEW, 'Response(json.dumps({"n": name}), 200, None, "application/json")'),
            (
                _FLASK_VIEW,
                'Response(json.dumps({"n": name}), headers=[("Content-Type", "application/json")])',
            ),
            (_FLASK_VIEW, 'Response(json.dumps({"n": name}), 200, [("content-type", "text/csv")])'),
            (
                _FLASK_VIEW,
                'make_response((json.dumps({"n": name}), 200, {"Content-Type": "application/json"}))',
            ),
        ],
        ids=[
            "flask-mimetype", "flask-content_type", "starlette-media_type",
            "headers-list", "headers-positional", "make_response-tuple",
        ],
    )
    def test_positional_and_list_content_types_are_not_xss(self, view: str, call: str) -> None:
        self._clean("import json\n" + view + f"    return {call}\n")

    def test_svg_content_type_is_xss(self) -> None:
        # SVG documents run <script>, so image/svg+xml is HTML-capable.
        self._proven(
            _DJANGO_VIEW
            + '    return HttpResponse(f"<svg>{name}</svg>", content_type="image/svg+xml")\n',
            "request.GET",
        )

    @pytest.mark.parametrize(
        "view, call",
        [
            (_DJANGO_VIEW, "HttpResponse(name, content_type=kind)"),
            (_FLASK_VIEW, "Response(name, mimetype=kind)"),
            (_FLASK_VIEW, "Response(name, content_type=kind)"),
            (_STARLETTE_VIEW, "Response(name, media_type=kind)"),
        ],
        ids=["django-content_type", "flask-mimetype", "flask-content_type", "starlette-media_type"],
    )
    def test_variable_content_type_is_xss(self, view: str, call: str) -> None:
        # A content type the engine cannot read might be text/html.
        f = self._xss(view + "    kind = pick_type()\n" + f"    return {call}\n")
        assert len(f) == 1, f
        assert f[0].get("reachable") is True, f

    def test_content_type_constant_is_resolved(self) -> None:
        self._clean(
            'JSON = "application/json"\n'
            + _DJANGO_VIEW
            + "    return HttpResponse(name, content_type=JSON)\n"
        )

    # -- sanitised and non-HTML bodies ----------------------------------------

    def test_escaped_value_is_not_xss(self) -> None:
        self._clean(
            "from django.utils.html import escape\n"
            + _DJANGO_VIEW
            + '    return HttpResponse(f"<h1>{escape(name)}</h1>")\n'
        )

    def test_repeated_constant_is_not_xss(self) -> None:
        # `_expr_is_fully_escaped`: a constant repeated any number of times
        # holds only its own characters.
        self._clean(
            "from django.http import HttpResponse\n"
            "def indent(request, depth):\n"
            '    return HttpResponse("&nbsp;" * depth)\n'
        )

    def test_jsonresponse_is_not_xss(self) -> None:
        self._clean(
            "from django.http import JsonResponse\n"
            "def greet(request):\n"
            '    name = request.GET.get("name", "")\n'
            '    return JsonResponse({"n": name})\n'
        )

    def test_make_response_jsonify_is_not_xss(self) -> None:
        self._clean(
            "from flask import jsonify\n"
            + _FLASK_VIEW
            + "    return make_response(jsonify(user=name))\n"
        )

    def test_make_response_of_a_dict_is_not_xss(self) -> None:
        # Flask serialises a dict or list body to JSON.
        self._clean(_FLASK_VIEW + '    return make_response({"error": name}, 400)\n')

    def test_httpresponse_json_dumps_is_not_xss(self) -> None:
        # R-pf38: json.dumps is safe here only because the response is JSON.
        self._clean(
            "import json\n"
            + _DJANGO_VIEW
            + '    return HttpResponse(json.dumps({"n": name}), content_type="application/json")\n'
        )

    @pytest.mark.parametrize(
        "view, call, source",
        [
            (_DJANGO_VIEW, 'HttpResponse(json.dumps({"n": name}))', "request.GET"),
            (_FLASK_VIEW, 'make_response(json.dumps({"n": name}))', "request.args"),
            (_FLASK_VIEW, 'Response(json.dumps({"n": name}))', "request.args"),
            (_DJANGO_VIEW, 'HttpResponse(json.dumps({"n": name}).encode())', "request.GET"),
        ],
        ids=["django", "flask-make_response", "flask-Response", "django-encoded"],
    )
    def test_httpresponse_json_dumps_default_content_type_is_xss(
        self, view: str, call: str, source: str
    ) -> None:
        # R-pf38: with no content type these responses are text/html, and
        # json.dumps does not escape `<`.
        self._proven("import json\n" + view + f"    return {call}\n", source)

    @pytest.mark.parametrize(
        "call",
        [
            'make_response(render_template("x.html", name=name))',
            'make_response(render_template("x.html", name=name).encode("utf-8"))',
            'Response(render_template("x.html", name=name))',
        ],
    )
    def test_response_of_render_template_is_not_xss(self, call: str) -> None:
        # An autoescaped template wraps the value.
        self._clean(
            "from flask import render_template\n" + _FLASK_VIEW + f"    return {call}\n"
        )

    @pytest.mark.parametrize(
        "lines",
        [
            '    return HttpResponse(render_to_string("x.html", {"n": name}))\n',
            '    return HttpResponse(loader.render_to_string("x.html", {"n": name}))\n',
            '    return HttpResponse(f"<div>{render_to_string(\'x.html\', {\'n\': name})}</div>")\n',
        ],
        ids=["render_to_string", "loader.render_to_string", "interpolated"],
    )
    def test_django_template_render_is_not_xss(self, lines: str) -> None:
        self._clean(
            "from django.template import loader\n"
            "from django.template.loader import render_to_string\n"
            + _DJANGO_VIEW
            + lines
        )

    @pytest.mark.parametrize(
        "imports, ret",
        [
            ("from jinja2 import Template", "HttpResponse(Template(src).render(name=name))"),
            (
                "from jinja2 import Environment",
                "HttpResponse(Environment().from_string(src).render(name=name))",
            ),
            (
                "import jinja2",
                'HttpResponse(jinja2.Environment().get_template("x.html").render(name=name))',
            ),
            ("from mako.template import Template", "HttpResponse(Template(src).render(name=name))"),
        ],
        ids=["jinja2-Template", "jinja2-from_string", "jinja2-get_template", "mako"],
    )
    def test_template_render_method_is_xss(self, imports: str, ret: str) -> None:
        # R-pf40: `.render(...)` on a raw Jinja2 or Mako template is not a
        # sanitiser: neither autoescapes by default.
        self._proven(
            imports + "\n" + _DJANGO_VIEW + '    src = "<p>{{ name }}</p>"\n' + f"    return {ret}\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "src",
        [
            (
                "from django.template import loader\n"
                "def v(request):\n"
                '    q = request.GET.get("q", "")\n'
                '    template = loader.get_template("polls/index.html")\n'
                '    context = {"q": q}\n'
                "    return HttpResponse(template.render(context, request))\n"
            ),
            (
                "from django.template.loader import get_template\n"
                "def v(request):\n"
                '    q = request.GET.get("q", "")\n'
                '    return HttpResponse(get_template("s.html").render({"q": q}, request))\n'
            ),
            (
                "from django.template.loader import select_template\n"
                "def v(request):\n"
                '    q = request.GET.get("q", "")\n'
                '    return HttpResponse(select_template(["a.html"]).render({"q": q}))\n'
            ),
            (
                "from django.template import Context, Template\n"
                "def v(request):\n"
                '    q = request.GET.get("q", "")\n'
                '    return HttpResponse(Template("<p>{{ q }}</p>").render(Context({"q": q})))\n'
            ),
            (
                "from django.template import engines\n"
                "def v(request):\n"
                '    q = request.GET.get("q", "")\n'
                '    engine = engines["jinja2"]\n'
                '    return HttpResponse(engine.from_string("<p>{{ q }}</p>").render({"q": q}))\n'
            ),
            (
                "from django.template import Context, Template, loader\n"
                "from .models import Question\n"
                "def index(request):\n"
                '    latest = Question.objects.order_by("-pub_date")[:5]\n'
                '    template = loader.get_template("polls/index.html")\n'
                '    context = {"latest_question_list": latest}\n'
                "    return HttpResponse(template.render(context, request))\n"
            ),
        ],
        ids=[
            "loader.get_template", "get_template", "select_template", "Template",
            "engines-jinja2", "tutorial",
        ],
    )
    def test_django_template_object_render_is_not_xss(self, src: str) -> None:
        # R-pf40 (corrected): `.render` on a Django template object autoescapes,
        # including Django's Jinja2 backend. The tutorial's view gets no
        # finding at all, not even an unproven one.
        self._clean("from django.http import HttpResponse\n" + src)

    @pytest.mark.parametrize(
        "template",
        ['"x.txt"', '"emails/body.md"', '"x"'],
    )
    def test_flask_template_flask_does_not_autoescape_is_xss(self, template: str) -> None:
        # Flask autoescapes only .html/.htm/.xml/.xhtml/.svg templates.
        self._proven(
            "from flask import render_template\n"
            + _FLASK_VIEW
            + f"    return make_response(render_template({template}, name=name))\n",
            "request.args",
        )

    @pytest.mark.parametrize(
        "template",
        ['"x.HTML"', '"x.htm"', '"feed.xml"', '"x.xhtml"', '"icon.svg"', "page", '["a.html", "b.txt"]'],
    )
    def test_flask_template_flask_autoescapes_is_not_xss(self, template: str) -> None:
        # An HTML/XML template name, or one the engine cannot read.
        self._clean(
            "from flask import render_template\n"
            + _FLASK_VIEW
            + '    page = request.args.get("page", "x.html")\n'
            + f"    return make_response(render_template({template}, name=name))\n"
        )

    @pytest.mark.parametrize(
        "defined",
        [
            "def render_to_string(template, context):\n    return template + str(context)\n",
            "def jsonify(**kw):\n    return str(kw)\n",
        ],
        ids=["render_to_string", "jsonify"],
    )
    def test_renderer_must_come_from_its_framework(self, defined: str) -> None:
        # A same-file function that shares a renderer's name is not one.
        call = (
            "render_to_string('x.html', {'n': name})"
            if "render_to_string" in defined
            else "jsonify(n=name)"
        )
        self._proven(
            defined + _DJANGO_VIEW + f'    return HttpResponse(f"<div>{{{call}}}</div>")\n',
            "request.GET",
        )

    def test_helper_output_is_not_claimed(self) -> None:
        # The engine sees no return values: an opaque helper (here the
        # full-stack-fastapi-template's password-recovery page) is the
        # renderer, and its escaping is out of sight.
        self._clean(
            "from fastapi import APIRouter\n"
            "from fastapi.responses import HTMLResponse\n"
            "from app.utils import generate_reset_password_email\n"
            "router = APIRouter()\n"
            '@router.post("/password-recovery-html-content/{email}")\n'
            "def recover_password_html_content(email: str):\n"
            "    email_data = generate_reset_password_email(email=email)\n"
            "    return HTMLResponse(\n"
            '        content=email_data.html_content, headers={"subject:": email_data.subject}\n'
            "    )\n"
        )

    @pytest.mark.parametrize(
        "lines",
        [
            '    return HttpResponse(f"<div>{build(name)}</div>")\n',
            '    return HttpResponse("<div>%s</div>" % build(name))\n',
            '    return HttpResponse("<div>{}</div>".format(build(name)))\n',
            '    return HttpResponse("<div>" + build(name) + "</div>")\n',
            '    html = f"<div>{build(name)}</div>"\n    return HttpResponse(html)\n',
        ],
        ids=["fstring", "percent", "format", "concat", "bound-fstring"],
    )
    def test_helper_call_inside_an_interpolated_part_is_xss(self, lines: str) -> None:
        # R-pf41: only a helper whose result IS the body is opaque. Inside an
        # interpolated part a call carries its arguments' text.
        self._proven(_DJANGO_VIEW + lines, "request.GET")

    @pytest.mark.parametrize(
        "lines, source",
        [
            (
                (
                    "    form = NameForm(request.POST)\n"
                    "    if form.is_valid():\n"
                    '        n = form.cleaned_data["name"]\n'
                    '        return HttpResponse(f"<p>{n}</p>")\n'
                ),
                "request.POST",
            ),
            (
                (
                    "    form = NameForm(request.POST)\n"
                    '    return HttpResponse(form.cleaned_data["name"])\n'
                ),
                "request.POST",
            ),
            (
                (
                    "    form = NameForm(request.POST)\n"
                    '    return HttpResponse(f"<p>{form.name.data}</p>")\n'
                ),
                "request.POST",
            ),
            (
                '    m = Model(**request.POST)\n    return HttpResponse(f"<p>{m.name}</p>")\n',
                "request.POST",
            ),
        ],
        ids=["django-form", "django-form-whole-body", "flask-wtf", "pydantic"],
    )
    def test_class_constructor_carries_its_arguments(self, lines: str, source: str) -> None:
        # A capitalised callee builds an object from its arguments.
        self._proven(_DJANGO_VIEW + lines, source)

    @pytest.mark.parametrize(
        "imports, ret",
        [
            ("import textwrap", 'HttpResponse(textwrap.dedent(f"<p>{name}</p>"))'),
            ("from urllib.parse import unquote", "HttpResponse(unquote(name))"),
            ("from urllib.parse import unquote_plus", "HttpResponse(unquote_plus(name))"),
            ("import html", "HttpResponse(html.unescape(name))"),
            ("", 'HttpResponse(", ".join(map(str, request.GET.getlist("n"))))'),
        ],
        ids=["dedent", "unquote", "unquote_plus", "html.unescape", "map"],
    )
    def test_text_passthrough_functions_carry_text(self, imports: str, ret: str) -> None:
        # Whole-body results that hand their argument's text through.
        self._proven(imports + "\n" + _DJANGO_VIEW + f"    return {ret}\n", "request.GET")

    @pytest.mark.parametrize(
        "ret",
        [
            "HttpResponse(int(name))",
            'HttpResponse(f"<p>{int(name)} items, {len(name)} chars</p>")',
        ],
    )
    def test_numbers_hold_no_text(self, ret: str) -> None:
        self._clean(_DJANGO_VIEW + f"    return {ret}\n")

    @pytest.mark.parametrize(
        "imports, ret",
        [
            ("from uuid import UUID", "HttpResponse(UUID(name))"),
            ("import uuid", "HttpResponse(str(uuid.UUID(name)))"),
            ("import decimal", 'HttpResponse(f"<p>{decimal.Decimal(name)}</p>")'),
            ("from decimal import Decimal", 'HttpResponse(f"<p>Total {Decimal(name) * 2}</p>")'),
            ("from fractions import Fraction", 'HttpResponse(f"<p>{Fraction(name)}</p>")'),
            ("from datetime import date", 'HttpResponse(f"<p>{date.fromisoformat(name)}</p>")'),
            ("import datetime", 'HttpResponse(f"<p>{datetime.date.fromisoformat(name)}</p>")'),
            (
                "from datetime import datetime",
                'HttpResponse(f"<p>{datetime.strptime(name, \'%Y\')}</p>")',
            ),
            ("", 'HttpResponse(f"<p>{round(float(name), 2)} {abs(int(name))}</p>")'),
        ],
        ids=[
            "UUID", "uuid.UUID", "decimal.Decimal", "Decimal", "Fraction",
            "date.fromisoformat", "datetime.date.fromisoformat", "datetime.strptime",
            "round-abs",
        ],
    )
    def test_value_parsers_hold_no_text(self, imports: str, ret: str) -> None:
        self._clean(imports + "\n" + _DJANGO_VIEW + f"    return {ret}\n")

    def test_path_still_carries_text(self) -> None:
        # Path is a class constructor whose `.name` is the request's text.
        self._proven(
            "from pathlib import Path\n" + _DJANGO_VIEW + "    return HttpResponse(Path(name).name)\n",
            "request.GET",
        )

    def test_value_parser_named_by_the_project_still_carries(self) -> None:
        # A same-named class the project imports is not uuid.UUID.
        self._proven(
            "from app.types import UUID\n" + _DJANGO_VIEW + "    return HttpResponse(UUID(name))\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "ret",
        ['HttpResponse(f"<p>{name * 2}</p>")', "HttpResponse(2 * name)", "mark_safe(name * 2)"],
        ids=["httpresponse-fstring", "httpresponse-left", "mark_safe"],
    )
    def test_repeated_value_carries_text(self, ret: str) -> None:
        # Only a constant string is inert when repeated.
        self._proven(
            "from django.utils.safestring import mark_safe\n"
            + _DJANGO_VIEW
            + f"    return {ret}\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "ret",
        ['HttpResponse("<br>" * len(name))', 'mark_safe("<br>" * count)'],
        ids=["httpresponse", "mark_safe"],
    )
    def test_repeated_constant_string_is_inert(self, ret: str) -> None:
        self._clean(
            "from django.utils.safestring import mark_safe\n"
            + _DJANGO_VIEW
            + "    count = int(request.GET.get('n', '1'))\n"
            + f"    return {ret}\n"
        )

    def test_map_carries_its_iterable_not_its_function(self) -> None:
        self._clean(
            'LABELS = ("a", "b")\n'
            + _DJANGO_VIEW
            + '    return HttpResponse(", ".join(map(str.upper, LABELS)))\n'
        )

    def test_shadowed_module_name_is_a_local_value(self) -> None:
        # `import html` does not make the local `html` a module.
        self._proven(
            "import html\n"
            + _DJANGO_VIEW
            + '    html = f"<p>{name}</p>"\n'
            + "    return HttpResponse(html.encode())\n",
            "request.GET",
        )

    def test_helper_method_output_is_not_claimed(self) -> None:
        # `self.render_page(...)` is a helper like `render_page(...)`; a method
        # on a value (`name.strip()`) still carries the value's text.
        self._clean(
            "from django.http import HttpResponse\n"
            "class Greeting:\n"
            "    def get(self, request):\n"
            '        name = request.GET.get("name", "")\n'
            "        html = self.render_page(name)\n"
            "        return HttpResponse(html)\n"
        )

    def test_flask_response_wrapping_a_redirect_is_not_xss(self) -> None:
        # make_response(redirect(...)) only adds a cookie to the redirect.
        self._clean(
            "from flask import redirect\n"
            + _FLASK_VIEW
            + "    resp = make_response(redirect(name))\n"
            + '    resp.set_cookie("seen", "1")\n'
            + "    return resp\n"
        )

    def test_constant_bodies_are_not_xss(self) -> None:
        # The parity corpus's `safe_lookalike` shape.
        self._clean(
            "from django.http import HttpResponse\n"
            'SERVICE_NAME = "Inventory Service"\n'
            "def about_page(request):\n"
            '    HttpResponse("OK", status=200)\n'
            "    HttpResponse(status=204)\n"
            '    return HttpResponse(f"<h1>{SERVICE_NAME}</h1><p>All systems operational.</p>")\n'
        )

    def test_unpacked_arguments_are_not_judged(self) -> None:
        # make_response(*rv): which argument is the body is out of sight.
        self._clean(_FLASK_VIEW + "    rv = (name, 200)\n    return make_response(*rv)\n")

    # -- which Response ---------------------------------------------------------

    @pytest.mark.parametrize(
        "imports, call",
        [
            ("from flask import Response", "Response(name)"),
            ("from werkzeug.wrappers import Response", "Response(name)"),
            ("from werkzeug import Response", "Response(name)"),
            ("from starlette.responses import Response", "Response(name)"),
            ("from fastapi import Response", "Response(name)"),
            ("from fastapi.responses import Response", "Response(name)"),
            ("import flask", "flask.Response(name)"),
            ("from fastapi import responses", "responses.Response(name)"),
            ("from flask import Response as R", "R(name)"),
            ("from flask import make_response as mk", "mk(name)"),
        ],
    )
    def test_framework_response_resolves_through_imports(
        self, imports: str, call: str
    ) -> None:
        self._proven(
            imports + "\n"
            "def greet(request):\n"
            '    name = request.GET.get("name", "")\n'
            f"    return {call}\n",
            "request.GET",
        )

    @pytest.mark.parametrize(
        "imports",
        [
            "from rest_framework.response import Response",
            "from aiohttp.web import Response",
            "",
        ],
    )
    def test_other_response_classes_are_not_xss(self, imports: str) -> None:
        # DRF renders its data as JSON; a Response the file never imports from
        # a web framework is not one this sink knows.
        self._clean(
            imports + "\n"
            "def greet(request):\n"
            '    name = request.GET.get("name", "")\n'
            "    return Response(name)\n"
        )

    @pytest.mark.parametrize(
        "header",
        [
            (
                "from django.http import JsonResponse\n"
                "def make_response(message, status=200):\n"
                '    return JsonResponse({"message": message}, status=status)\n'
            ),
            "from .utils import make_response\n",
            "from . import make_response\n",
            "from app.http import HttpResponse\n",
            "from mylib.responses import HTMLResponse\n",
            "from flask import HTMLResponse\n",
            "class HttpResponse:\n    def __init__(self, body):\n        self.body = body\n",
        ],
        ids=[
            "same-file-def", "relative-import", "package-import", "project-HttpResponse",
            "project-HTMLResponse", "wrong-framework", "same-file-class",
        ],
    )
    def test_project_constructors_are_not_xss(self, header: str) -> None:
        ctor = next(c for c in ("make_response", "HTMLResponse", "HttpResponse") if c in header)
        self._clean(
            header
            + "def greet(request):\n"
            + '    name = request.GET.get("name", "")\n'
            + f'    return {ctor}(f"Hello {{name}}")\n'
        )

    def test_own_method_named_like_a_constructor_is_not_xss(self) -> None:
        self._clean(
            "class View:\n"
            "    def make_response(self, body):\n"
            "        return body\n"
            "    def get(self, request):\n"
            '        name = request.GET.get("name", "")\n'
            '        return self.make_response(f"<p>{name}</p>")\n'
        )

    def test_method_named_like_a_constructor_does_not_shadow_the_import(self) -> None:
        # A method never shadows a bare name: `make_response(...)` below is
        # still Flask's.
        self._proven(
            "from flask import make_response, request\n"
            "class Cache:\n"
            "    def make_response(self, body):\n"
            "        return body\n"
            "def greet():\n"
            '    name = request.args.get("name", "")\n'
            '    return make_response(f"<p>{name}</p>")\n',
            "request.args",
        )

    def test_flask_app_make_response_is_xss(self) -> None:
        # Flask's `app.make_response(rv)` builds a text/html response from a str.
        self._proven(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "def greet():\n"
            '    name = request.args.get("name", "")\n'
            '    return app.make_response(f"<p>{name}</p>")\n',
            "request.args",
        )

    def test_user_defined_response_class_is_not_xss(self) -> None:
        self._clean(
            "class Response:\n"
            "    def __init__(self, body):\n"
            "        self.body = body\n"
            "def greet(request):\n"
            '    name = request.GET.get("name", "")\n'
            '    return Response(f"<h1>{name}</h1>")\n'
        )

    # -- one finding per flow ---------------------------------------------------

    def test_make_response_of_markup_reports_once(self) -> None:
        # The existing Markup branch already reports this flow; the response
        # constructor around it must not add a second finding, and the
        # existing finding keeps its sink (its fingerprint).
        found = self._xss(
            "from markupsafe import Markup\n"
            + _FLASK_VIEW
            + '    return make_response(Markup(f"<b>{name}</b>"))\n'
        )
        assert len(found) == 1, found
        assert found[0]["sink"] == "Markup(f'<b>{name}</b>')"
        assert found[0].get("reachable") is True

    def test_markup_inside_an_fstring_body_reports_once(self) -> None:
        found = self._xss(
            "from markupsafe import Markup\n"
            + _DJANGO_VIEW
            + '    return HttpResponse(f"<div>{Markup(name)}</div>")\n'
        )
        assert len(found) == 1, found
        assert found[0]["sink"] == "Markup(name)"

    def test_markup_beside_raw_text_reports_once(self) -> None:
        # The body holds a second, raw use of `name`, but the line already
        # carries the Markup finding for this flow.
        found = self._xss(
            "from markupsafe import Markup\n"
            + _DJANGO_VIEW
            + '    return HttpResponse(f"{Markup(name)}<p>{name}</p>")\n'
        )
        assert len(found) == 1, found
        assert found[0]["sink"] == "Markup(name)"

    def test_escaped_markup_body_is_not_xss(self) -> None:
        self._clean(
            "from markupsafe import Markup, escape\n"
            + _FLASK_VIEW
            + "    return make_response(Markup(escape(name)))\n"
        )


class TestCmdInjectionReachable:
    """TASK-121 — reachable command-injection taint chains.

    Extends the existing os.system / subprocess(shell=True) sinks and
    adds os.popen as a third sink, each recording a taint_chain +
    reachable: true when intra-function dataflow proves a request
    source reaches the sink.
    """

    def test_os_system_with_request_arg_emits_chain(self) -> None:
        """os.system(request.args.get('cmd')) — cmd injection with chain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    os.system(request.args.get('cmd'))\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_SYSTEM"]
            assert len(cmd) == 1, f"got {[f['id'] for f in findings]}"
            assert cmd[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in cmd[0]["taint_chain"])

    def test_os_system_with_literal_no_finding(self) -> None:
        """os.system('ls') — literal arg is safe-shape; no finding emitted.

        Updated 2026-05-13 during the accuracy evaluation: pre-fix the
        finding fired on every os.system call regardless of arg content
        (a deliberate TASK-121 conservatism). That surfaced as a real
        false positive against the labeled corpus, so cmdi now follows
        the same posture as SSRF/XSS/path-traversal — skip on Constant
        args, only emit when the arg is variable.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\ndef listdir():\n    os.system('ls')\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_SYSTEM"]
            assert cmd == [], f"expected no cmdi findings on literal-string os.system; got {cmd}"

    def test_subprocess_shell_true_with_request_arg_emits_chain(self) -> None:
        """subprocess.run(req.args['cmd'], shell=True) — chain captured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import subprocess\n"
                "def handler(request):\n"
                "    subprocess.run(request.args['cmd'], shell=True)\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_SUBPROCESS_SHELL"]
            assert len(cmd) == 1, f"got {[f['id'] for f in findings]}"
            assert cmd[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in cmd[0]["taint_chain"])

    def test_subprocess_shell_true_with_literal_no_finding(self) -> None:
        """subprocess.run('ls', shell=True) — literal arg is safe-shape; no finding.

        Updated 2026-05-13: cmdi posture aligned with the other reachable
        sinks per the accuracy evaluation. A literal-string command isn't
        exploitable; emitting HIGH for it was a real false positive.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import subprocess\n"
                "def f():\n"
                "    subprocess.run('ls', shell=True)\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_SUBPROCESS_SHELL"]
            assert cmd == [], f"expected no findings on literal subprocess(shell=True); got {cmd}"

    def test_os_popen_with_request_arg_emits_chain(self) -> None:
        """os.popen(request.GET['x']) — new sink in TASK-121, chain captured."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "def handler(request):\n"
                "    return os.popen(request.GET['cmd']).read()\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_POPEN"]
            assert len(cmd) == 1, f"got {[f['id'] for f in findings]}"
            assert cmd[0].get("reachable") is True
            assert any("request.GET" in link["expr"] for link in cmd[0]["taint_chain"])

    def test_os_popen_with_literal_no_finding(self) -> None:
        """os.popen('ls') — literal arg is safe-shape; no finding emitted.

        Updated 2026-05-13: cmdi posture aligned with the other reachable
        sinks per the accuracy evaluation.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\ndef listdir():\n    os.popen('ls').read()\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_POPEN"]
            assert cmd == [], f"expected no findings on literal os.popen; got {cmd}"

    def test_os_popen2_3_4_variants_all_detected(self) -> None:
        """os.popen2/3/4(tainted) — all deprecated variants are cmdi sinks.

        Surfaced by Track 4 heavy-eval (bandit examples corpus).
        """
        for variant in ("popen2", "popen3", "popen4"):
            with tempfile.TemporaryDirectory() as tmpdir:
                Path(tmpdir, f"h_{variant}.py").write_text(
                    f"import os\n"
                    f"from flask import request\n"
                    f"def handler():\n"
                    f"    cmd = request.args.get('cmd')\n"
                    f"    os.{variant}(cmd)\n"
                )
                findings = _collect(tmpdir)
                hits = [f for f in findings if f["id"] == "SEC-PY_OS_POPEN"]
                assert len(hits) == 1, (
                    f"os.{variant}(request.args.get('cmd')) should fire SEC-PY_OS_POPEN; "
                    f"got {[f['id'] for f in findings]}"
                )
                assert variant in hits[0]["title"], (
                    f"expected '{variant}' in title; got: {hits[0]['title']}"
                )

    def test_multi_step_assignment_resolves_for_cmd_injection(self) -> None:
        """cmd = request.args['x']; os.system(cmd) — chain across hop."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    cmd = request.args['cmd']\n"
                "    os.system(cmd)\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_SYSTEM"]
            assert len(cmd) == 1
            assert cmd[0].get("reachable") is True
            assert len(cmd[0]["taint_chain"]) >= 2

    def test_cmd_injection_finding_shape(self) -> None:
        """Cmd-injection findings have the same shape as XSS/SQLi/SSRF/redirect."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    os.system(request.args.get('cmd'))\n"
            )
            findings = _collect(tmpdir)
            cmd = [f for f in findings if f["id"] == "SEC-PY_OS_SYSTEM"]
            assert len(cmd) == 1
            f = cmd[0]
            assert f["severity"] == "HIGH"
            assert f["confidence"] == "HIGH"  # cmd-injection is HIGH confidence (vs MEDIUM for XSS)
            assert f["source"] == "whitebox"
            assert f["category"] == "injection"
            assert "CWE-78" in f["references"]
            assert f["reachable"] is True
            assert isinstance(f["taint_chain"], list)


class TestSQLConcatViaAssignment:
    """TASK-087 closes the multi-step SQLi gap.

    Previously, `cursor.execute(name)` was not flagged — the visitor only
    checked the literal first argument shape, not what the variable held.
    With intra-function scope tracking, an assignment of a BinOp/JoinedStr/Call
    earlier in the same function is now resolved at the execute() site.
    """

    def test_concat_via_var_detected(self) -> None:
        """sql = 'SELECT...' + var; cursor.execute(sql) — flagged."""
        findings = _collect(str(FIXTURES_DIR))
        sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        # Fixture has 4 SQLi patterns: %, f-string, inline +, multi-step assignment.
        assert len(sql) >= 4, f"expected ≥4 SQLi findings, got {len(sql)}: {[f['endpoint'] for f in sql]}"

    def test_assigned_constant_not_flagged(self) -> None:
        """sql = 'SELECT * FROM users'; cursor.execute(sql) — fine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "def f(cursor):\n    sql = 'SELECT * FROM users'\n    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)


class TestSQLEvasionPatterns:
    """Evasion patterns that bypass simple string-concat detection.

    Each pattern assembles a tainted SQL string via a non-obvious construction
    and then passes it to cursor.execute(). The AST engine must detect all of
    them via its scope-resolution taint chain.
    """

    def test_join_parts_list_detected(self) -> None:
        """parts = ['SELECT...', user_id]; sql = ''.join(parts); cursor.execute(sql)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "from flask import request\n"
                "def q(cursor):\n"
                "    user_id = request.args.get('id')\n"
                "    parts = ['SELECT * FROM users WHERE id = ', user_id]\n"
                "    query = ''.join(parts)\n"
                "    cursor.execute(query)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"join-parts SQLi not detected; got {_ids(findings)}"

    def test_format_named_kwargs_detected(self) -> None:
        """'SELECT ... WHERE name = \"{name}\"'.format(name=user_input) detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "from flask import request\n"
                "def q(cursor):\n"
                "    name = request.args.get('name')\n"
                "    sql = \"SELECT * FROM users WHERE name = '{name}'\".format(name=name)\n"
                "    cursor.execute(sql)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"dict-format SQLi not detected; got {_ids(findings)}"

    def test_string_template_substitute_detected(self) -> None:
        """string.Template('... $val').substitute(val=user_input) detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "t.py").write_text(
                "from string import Template\n"
                "from flask import request\n"
                "def q(cursor):\n"
                "    user_input = request.args.get('val')\n"
                "    t = Template(\"SELECT * FROM t WHERE col = '$val'\")\n"
                "    query = t.substitute(val=user_input)\n"
                "    cursor.execute(query)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"Template-substitute SQLi not detected; got {_ids(findings)}"


class TestDjangoORMSQLInjection:
    """Track 4 / bandit B610/B611: Django ORM raw-SQL sinks.

    PyGoat had SQLi labs that fendix wasn't catching because the AST
    matcher only looked at cursor.execute(). The three Django-specific
    shapes added in lockstep:
      - <qs>.raw("..." + tainted)
      - <qs>.extra(where=[tainted], select={"x": tainted}, tables=[tainted])
      - RawSQL(tainted, [...])
    """

    def test_qs_raw_with_concat_emits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def view(request):\n"
                "    name = request.GET['u']\n"
                "    User.objects.raw('SELECT * FROM auth_user WHERE name=' + name)\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"expected SEC-PY_SQL_INJECTION; got {[f['id'] for f in findings]}"
            assert "raw" in sql[0]["title"].lower()

    def test_qs_raw_with_literal_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "def view():\n"
                "    User.objects.raw('SELECT * FROM auth_user')\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)

    def test_extra_where_with_tainted_list_elem_emits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def view(request):\n"
                "    where_clause = request.GET['w']\n"
                "    User.objects.filter(username='admin').extra(where=[where_clause])\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"expected SEC-PY_SQL_INJECTION; got {[f['id'] for f in findings]}"

    def test_extra_select_with_tainted_dict_value_emits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def view(request):\n"
                "    expr = '%secure' % request.GET['x']\n"
                "    User.objects.filter(username='admin').extra(select={'test': expr})\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"expected SEC-PY_SQL_INJECTION; got {[f['id'] for f in findings]}"

    def test_extra_all_literal_safe(self) -> None:
        """extra(where=['1=1'], select={'x': 'safe'}) — all literals; no finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "def view():\n"
                "    User.objects.filter(username='admin').extra(\n"
                "        select={'test': 'secure'},\n"
                "        where=['secure'],\n"
                "        tables=['secure']\n"
                "    )\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)

    def test_rawsql_with_tainted_first_arg_emits(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from django.db.models.expressions import RawSQL\n"
                "def view(request):\n"
                "    raw = '%secure' % request.GET['x']\n"
                "    User.objects.annotate(val=RawSQL(raw, []))\n"
            )
            findings = _collect(tmpdir)
            sql = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
            assert sql, f"expected SEC-PY_SQL_INJECTION; got {[f['id'] for f in findings]}"
            assert "RawSQL" in sql[0]["title"]

    def test_rawsql_with_literal_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "ok.py").write_text(
                "from django.db.models.expressions import RawSQL\n"
                "def view():\n"
                "    User.objects.annotate(val=RawSQL('secure', []))\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-PY_SQL_INJECTION" not in _ids(findings)


# ---------------------------------------------------------------------------
# JavaScript heuristic detection tests
# ---------------------------------------------------------------------------

class TestJavaScriptHeuristic:
    def test_eval_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_EVAL" in _ids(findings)

    def test_inner_html_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_INNER_HTML" in _ids(findings)

    def test_document_write_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_DOCUMENT_WRITE" in _ids(findings)

    def test_sql_template_literal_detected(self) -> None:
        findings = _collect(str(FIXTURES_DIR))
        assert "SEC-JS_SQL_TEMPLATE" in _ids(findings)

    @staticmethod
    def _sql_template_ids(source: str, name: str = "app.ts") -> set[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, name).write_text(source)
            return _ids(_collect(tmpdir))

    @pytest.mark.parametrize(
        "line",
        [
            "const r = await sql`SELECT * FROM u WHERE id = ${id}`;",
            "const r = await prisma.$queryRaw`SELECT * FROM u WHERE id = ${id}`;",
            "const r = await Prisma.sql`SELECT * FROM u WHERE id = ${id}`;",
            "const r = db.sql`UPDATE u SET n = ${n} WHERE id = ${id}`;",
            "const r = await tx.$executeRaw`DELETE FROM u WHERE id = ${id}`;",
        ],
        ids=["postgres-js", "prisma-queryRaw", "Prisma.sql", "member-tag", "executeRaw"],
    )
    def test_tagged_template_sql_is_parameterized_not_flagged(self, line: str) -> None:
        """A tagged template hands the pieces and values to the tag, which
        binds them as parameters (postgres.js, slonik, Prisma)."""
        assert "SEC-JS_SQL_TEMPLATE" not in self._sql_template_ids(line + "\n")

    def test_template_over_a_module_constant_not_flagged(self) -> None:
        src = (
            "const DEFAULT_ROLE = 'member';\n"
            "async function f(pool) {\n"
            "  return pool.query(`SELECT id FROM users WHERE role = '${DEFAULT_ROLE}'`);\n"
            "}\n"
        )
        assert "SEC-JS_SQL_TEMPLATE" not in self._sql_template_ids(src)

    def test_template_over_an_exported_typed_constant_not_flagged(self) -> None:
        src = (
            'export const TABLE: string = "users";\n'
            "const q = pool.query(`SELECT id FROM ${TABLE} WHERE active = true`);\n"
        )
        assert "SEC-JS_SQL_TEMPLATE" not in self._sql_template_ids(src)

    def test_template_over_a_variable_still_flagged(self) -> None:
        src = "const r = await pool.query(`SELECT * FROM u WHERE n = '${name}'`);\n"
        assert "SEC-JS_SQL_TEMPLATE" in self._sql_template_ids(src)

    def test_template_mixing_a_constant_and_a_variable_still_flagged(self) -> None:
        src = (
            "const ROLE = 'member';\n"
            "const r = pool.query(`SELECT * FROM u WHERE role = '${ROLE}' AND n = '${name}'`);\n"
        )
        assert "SEC-JS_SQL_TEMPLATE" in self._sql_template_ids(src)

    @pytest.mark.parametrize(
        "decl",
        [
            "let ROLE = 'member';",
            "var ROLE = 'member';",
            "  const ROLE = 'member';",  # inside a function: not a module-level constant
            "const ROLE = req.query.role;",
        ],
        ids=["let", "var", "indented", "not-a-literal"],
    )
    def test_only_a_module_level_const_string_counts_as_constant(self, decl: str) -> None:
        src = decl + "\nconst r = pool.query(`SELECT * FROM u WHERE role = '${ROLE}'`);\n"
        assert "SEC-JS_SQL_TEMPLATE" in self._sql_template_ids(src)

    def test_untagged_template_after_a_call_still_flagged(self) -> None:
        for line in (
            "return `SELECT * FROM u WHERE id = ${id}`;",
            "const q = `DELETE FROM u WHERE id = ${id}`;",
            "db.query(`INSERT INTO u VALUES (${a})`);",
        ):
            assert "SEC-JS_SQL_TEMPLATE" in self._sql_template_ids(line + "\n"), line

    def test_safe_textcontent_not_flagged(self) -> None:
        """textContent assignment should not trigger innerHTML finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "safe.js").write_text(
                "document.getElementById('x').textContent = userInput;\n"
            )
            findings = _collect(tmpdir)
            assert "SEC-JS_INNER_HTML" not in _ids(findings)


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------

class TestFindingStructure:
    def test_required_fields_present(self) -> None:
        required = {"id", "title", "severity", "source", "category",
                    "endpoint", "evidence", "fix", "references", "confidence", "line"}
        findings = _collect(str(FIXTURES_DIR))
        for f in findings:
            missing = required - f.keys()
            assert not missing, f"Finding {f.get('id')} missing: {missing}"

    def test_source_is_whitebox(self) -> None:
        for f in _collect(str(FIXTURES_DIR)):
            assert f["source"] == "whitebox"

    def test_line_field_format(self) -> None:
        for f in _collect(str(FIXTURES_DIR)):
            assert ":" in f["line"]
            parts = f["line"].rsplit(":", 1)
            assert parts[1].isdigit()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_nonexistent_path_no_findings(self) -> None:
        assert _collect("/nonexistent/path") == []

    def test_empty_directory_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            assert _collect(tmpdir) == []

    def test_syntax_error_file_skipped_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "broken.py").write_text("def (((broken syntax\n")
            findings = _collect(tmpdir)
            # Should not raise; may produce zero findings for the broken file
            assert isinstance(findings, list)

    def test_skips_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir, "node_modules", "lib")
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("eval(userInput);\n")
            assert _collect(tmpdir) == []

    def test_self_referencing_binding_does_not_skip_the_file(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `url += "/x"` on a parameter binds `url` to `url + "/x"`, and
        # `desc = "<p>" + desc` reads `desc` too. The sanitiser check followed
        # such a binding without end, hit the recursion limit, and every later
        # finding in the file was lost.
        findings = _collect_src(
            "import requests\n"
            "from markupsafe import Markup\n"
            "def f(url):\n"
            '    url += "/x"\n'
            "    return requests.get(url)\n"
            "def g(html):\n"
            '    html += "</p>"\n'
            "    return Markup(html)\n"
            "def h(desc):\n"
            '    desc = "<p>" + desc + "</p>"\n'
            "    return Markup(desc)\n"
        )
        assert "recursion limit" not in capsys.readouterr().err
        assert [(f["id"], f["line"]) for f in findings] == [
            ("SEC-PY_SSRF", "mod.py:5"),
            ("SEC-PY_XSS_HTML_SINK", "mod.py:8"),
            ("SEC-PY_XSS_HTML_SINK", "mod.py:11"),
        ]

    def test_self_assignment_does_not_skip_the_file(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `html = html` binds `html` to itself; the escape check followed it
        # without end and the rest of the file was lost.
        findings = _collect_src(
            "from markupsafe import Markup\n"
            "def f(html):\n"
            "    html = html\n"
            "    return Markup(html)\n"
            "def g(request):\n"
            "    return Markup(request.args['x'])\n"
        )
        assert "recursion limit" not in capsys.readouterr().err
        assert [(f["id"], f["line"], f.get("reachable")) for f in findings] == [
            ("SEC-PY_XSS_HTML_SINK", "mod.py:4", None),
            ("SEC-PY_XSS_HTML_SINK", "mod.py:6", True),
        ]


class TestPathTraversalReachable:
    """TASK-134 / Phase 17d — path-traversal reachable taint chains.

    Recognises four filesystem-path sinks: `open`, `Path` / `pathlib.Path`,
    `send_file`, `send_from_directory`. When user input flows into the
    path argument, the chain is recorded and `reachable: true` is set —
    same shape as TASK-114/120/121.
    """

    def test_open_with_request_arg_emits_chain(self) -> None:
        """open(request.args['name']) — direct path traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler():\n"
                "    with open(request.args['name']) as f:\n"
                "        return f.read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1, f"got {[f['id'] for f in findings]}"
            assert pt[0].get("reachable") is True
            assert any("request.args" in link["expr"] for link in pt[0]["taint_chain"])

    def test_pathlib_path_with_request_arg_emits_chain(self) -> None:
        """Path(request.GET['file']) — pathlib-style traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from pathlib import Path\n"
                "from flask import request\n"
                "def handler():\n"
                "    return Path(request.GET['file']).read_text()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            assert pt[0].get("reachable") is True

    def test_send_file_with_request_arg_emits_chain(self) -> None:
        """flask.send_file(request.args.get('p')) — Flask file-serve traversal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import send_file, request\n"
                "def download():\n"
                "    return send_file(request.args.get('p'))\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            assert pt[0].get("reachable") is True

    def test_send_from_directory_uses_second_arg(self) -> None:
        """send_from_directory(safe_dir, request.args['f']) — arg index 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import send_from_directory, request\n"
                "UPLOAD_DIR = '/var/uploads'\n"
                "def download():\n"
                "    return send_from_directory(UPLOAD_DIR, request.args['f'])\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            assert pt[0].get("reachable") is True
            # The chain should reference the user-controlled SECOND arg.
            assert any("request.args" in link["expr"] for link in pt[0]["taint_chain"])

    def test_open_literal_arg_no_finding(self) -> None:
        """open('config.yaml') — constant string is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def load():\n"
                "    with open('config.yaml') as f:\n"
                "        return f.read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == []

    def test_open_constant_in_scope_no_finding(self) -> None:
        """open(name) where name resolves to constant in scope is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def load():\n"
                "    name = 'config.yaml'\n"
                "    with open(name) as f:\n"
                "        return f.read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == []

    def test_open_with_non_literal_no_traced_source_still_emits(self) -> None:
        """open(func()) — non-literal but no request source emits finding without reachable=true."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def get_name(): return 'x'\n"
                "def load():\n"
                "    with open(get_name()) as f:\n"
                "        return f.read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            # Suspicious shape emits; reachable=true requires proven chain
            # back to a request source.
            assert len(pt) >= 1
            assert not pt[0].get("reachable")

    def test_multi_step_assignment_hop(self) -> None:
        """name = request.args['f']; open(name) — chain across 2 hops."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler():\n"
                "    name = request.args['file']\n"
                "    return open(name).read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            assert pt[0].get("reachable") is True
            # At least 2 links: the open() sink and the request.args source.
            assert len(pt[0]["taint_chain"]) >= 2

    def test_finding_shape_parity(self) -> None:
        """Severity / confidence / category / CWE match TASK-114/120/121 shape."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "from flask import request\n"
                "def handler():\n"
                "    return open(request.args['f']).read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            f = pt[0]
            assert f["severity"] == "HIGH"
            assert f["confidence"] == "MEDIUM"
            assert f["category"] == "injection"
            assert f["source"] == "whitebox"
            assert "CWE-22" in f["references"]

    def test_os_path_join_standalone_sink(self) -> None:
        """os.path.join('/base/', user_input) — join itself is a traversal sink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    user_input = request.args.get('val')\n"
                "    return os.path.join('/base/', user_input)\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1, f"got {[f['id'] for f in findings]}"
            assert pt[0].get("reachable") is True

    def test_os_path_abspath_standalone_sink(self) -> None:
        """os.path.abspath(user_input) — abspath is a traversal sink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    user_input = request.args.get('val')\n"
                "    return os.path.abspath(user_input)\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1

    def test_os_path_join_constant_args_no_finding(self) -> None:
        """os.path.join('/base', 'subdir') — all constants, no finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "def handler():\n"
                "    return os.path.join('/base', 'subdir')\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == []

    def test_os_path_join_first_arg_only_no_finding(self) -> None:
        """os.path.join(user_input) — single-arg join; arg at index 1 not present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    user_input = request.args.get('val')\n"
                "    return os.path.join(user_input)\n"
            )
            findings = _collect(tmpdir)
            # Single-arg join: index 1 doesn't exist, no path-traversal finding.
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == []

    def test_os_path_expanduser_on_param_no_finding(self) -> None:
        """os.path.expanduser(f) on a plain function param — no taint, no finding.

        Regression for FP found benchmarking against psf/requests v2.32.4:
        `loc = os.path.expanduser(f)` was emitted as a path-traversal warning
        even though `f` is a fixed parameter to an internal helper.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "def proxy_bypass_macosx_sysconf(f):\n"
                "    loc = os.path.expanduser(f)\n"
                "    return loc\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == [], (
                f"Expected no finding on untainted os.path.expanduser; "
                f"got {[f.get('endpoint') for f in pt]}"
            )

    def test_os_path_abspath_on_param_no_finding(self) -> None:
        """os.path.abspath on an opaque parameter — no taint, no finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "def resolve(p):\n"
                "    return os.path.abspath(p)\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert pt == []

    def test_os_path_expanduser_still_emits_when_tainted(self) -> None:
        """Same sink, but with request.args input — must still emit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "import os\n"
                "from flask import request\n"
                "def handler():\n"
                "    user_input = request.args.get('p')\n"
                "    return os.path.expanduser(user_input)\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            assert pt[0].get("reachable") is True

    def test_open_with_param_still_emits(self) -> None:
        """open() / send_file() keep the conservative posture — still emit
        on an unproven arg because passing a parameter directly to an
        actual file-IO sink is suspicious shape even without a proven
        taint flow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "h.py").write_text(
                "def load(name):\n"
                "    with open(name) as f:\n"
                "        return f.read()\n"
            )
            findings = _collect(tmpdir)
            pt = [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
            assert len(pt) >= 1
            # No taint chain proven, so reachable should not be True
            assert not pt[0].get("reachable")


# ---------------------------------------------------------------------------
# F-H5b: untrusted-repo robustness — a crafted "assignment bomb" file (a long
# linear taint chain) must not abort the whole injection pass, and a real
# command-injection sink in a SEPARATE file must still be reported. The
# per-file visit is isolated and the taint walker is depth-capped.
# ---------------------------------------------------------------------------

def _bomb_chain_source(depth: int) -> str:
    """Build a file with a `depth`-long linear assignment chain ending in a
    tainted os.system() sink. Without the hop cap, tracing the chain would
    recurse `depth` levels deep and blow the stack on a large `depth`.
    """
    lines = [
        "import os",
        "from flask import request",
        "def handler():",
        "    a0 = request.args.get('cmd')",
    ]
    for i in range(1, depth):
        lines.append(f"    a{i} = a{i - 1}")
    lines.append(f"    os.system(a{depth - 1})")
    return "\n".join(lines) + "\n"


class TestAssignmentBombResilience:
    def test_deep_chain_does_not_raise(self) -> None:
        """A 5000-hop linear assignment chain must analyze cleanly — no
        RecursionError propagating out of run()."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bomb.py").write_text(_bomb_chain_source(5000))
            # Must not raise.
            findings = _collect(tmpdir)
            # The sink is still flagged (deep chain, but it IS os.system on a
            # variable that ultimately traces to request input).
            assert "SEC-PY_OS_SYSTEM" in _ids(findings)

    def test_deep_chain_taint_chain_is_capped(self) -> None:
        """If a taint_chain is attached, its length is bounded by the hop cap."""
        from analyzers.ast_analyzer import _MAX_TAINT_HOPS

        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bomb.py").write_text(_bomb_chain_source(5000))
            findings = _collect(tmpdir)
            for f in findings:
                chain = f.get("taint_chain")
                if chain is not None:
                    assert len(chain) <= _MAX_TAINT_HOPS

    def test_bomb_alongside_real_sink_still_reports_real_sink(self) -> None:
        """The crafted bomb file sits next to a SEPARATE file with a real
        command-injection sink (tainted request input → shell exec). The real
        sink must STILL be reported (total > 0) even though the bomb file is
        in the same scan tree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Crafted recursion-bomb file.
            Path(tmpdir, "bomb.py").write_text(_bomb_chain_source(8000))
            # Separate, ordinary command-injection vuln the existing rules
            # detect: request input flowing straight into subprocess shell.
            Path(tmpdir, "real_vuln.py").write_text(
                "import subprocess\n"
                "from flask import request\n"
                "def run():\n"
                "    cmd = request.args.get('q')\n"
                "    subprocess.run(cmd, shell=True)\n"
            )
            findings = _collect(tmpdir)
            assert len(findings) > 0
            assert "SEC-PY_SUBPROCESS_SHELL" in _ids(findings)

    def test_engine_exits_zero_with_bomb_and_real_sink(self) -> None:
        """End-to-end: the engine subprocess must exit 0 and still report the
        real sink when a recursion-bomb file is present in the scan tree."""
        import json
        import subprocess
        import sys

        engine = Path(__file__).parent.parent / "engine.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "bomb.py").write_text(_bomb_chain_source(8000))
            Path(tmpdir, "real_vuln.py").write_text(
                "import subprocess\n"
                "from flask import request\n"
                "def run():\n"
                "    cmd = request.args.get('q')\n"
                "    subprocess.run(cmd, shell=True)\n"
            )
            request = {
                "mode": "whitebox",
                "checks": ["injection"],
                "code_path": tmpdir,
            }
            proc = subprocess.run(
                [sys.executable, str(engine)],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert proc.returncode == 0, proc.stderr
            lines = [ln for ln in proc.stdout.strip().split("\n") if ln]
            objects = [json.loads(ln) for ln in lines]
            terminator = objects[-1]
            assert terminator["done"] is True
            # Real sink still reported despite the bomb file.
            assert terminator["total"] > 0
            ids = {o.get("id") for o in objects if "id" in o}
            assert "SEC-PY_SUBPROCESS_SHELL" in ids


# ---------------------------------------------------------------------------
# F-L12: symlinked source FILES are skipped so out-of-tree file content can't
# surface in 'evidence'. Mirrors the Go textscan symlink skip.
# ---------------------------------------------------------------------------

class TestSymlinkSkip:
    def test_symlinked_file_is_not_read(self) -> None:
        """A symlink inside the scan tree pointing at an out-of-tree file with
        a dangerous sink must NOT be analyzed — no findings from its content."""
        with tempfile.TemporaryDirectory() as outside, \
                tempfile.TemporaryDirectory() as scan_root:
            # Out-of-tree file with an unmistakable sink.
            target = Path(outside) / "secret.py"
            target.write_text(
                "import os\n"
                "def x(c):\n"
                "    os.system(c)\n"
            )
            link = Path(scan_root) / "linked.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("symlinks not supported in this environment")
            findings = _collect(scan_root)
            # The symlinked file's path must never appear in any finding,
            # and its os.system sink must not be reported.
            for f in findings:
                assert "linked.py" not in f.get("endpoint", "")
                assert "linked.py" not in f.get("line", "")
            assert "SEC-PY_OS_SYSTEM" not in _ids(findings)

    def test_real_file_alongside_symlink_still_analyzed(self) -> None:
        """A genuine in-tree file next to a skipped symlink is still scanned."""
        with tempfile.TemporaryDirectory() as outside, \
                tempfile.TemporaryDirectory() as scan_root:
            target = Path(outside) / "secret.py"
            target.write_text("import os\ndef x(c):\n    os.system(c)\n")
            link = Path(scan_root) / "linked.py"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                pytest.skip("symlinks not supported in this environment")
            # Real file with a dynamic-eval sink — must be flagged.
            Path(scan_root, "real.py").write_text(
                "def f(e):\n    return eval(e)\n"
            )
            findings = _collect(scan_root)
            assert "SEC-PY_EVAL" in _ids(findings)
            # And nothing from the symlink.
            assert "SEC-PY_OS_SYSTEM" not in _ids(findings)


class TestSecretInLogFanOutPerf:
    """Regression lock for the O(fan-out) pathology in
    ``_expr_references_secret`` (Product-Constitution Rule 6).

    Before the memoized fix, ``_expr_references_secret`` restarted a full
    ``ast.walk`` per resolved binding with no ``seen`` set, so a log call whose
    interpolated names resolved to a deeply-nested synthesized ``BinOp`` tree
    (the ``acc += acc`` accumulator DOUBLES the tree per rebind) re-walked the
    same subtrees combinatorially. A single real 907-line file took ~45 s and a
    whole-repo scan ~50 min. The fix threads a shared ``id(node)`` set so every
    node is inspected at most once — the same nodes, never twice.
    """

    @staticmethod
    def _scan(src: str) -> set[str]:
        import tempfile as _t
        with _t.TemporaryDirectory() as d:
            Path(d, "m.py").write_text(src)
            findings: list[dict] = []
            ASTAnalyzer(d).run(findings.append)
        return {f["id"] for f in findings}

    def test_secret_in_log_true_positive_preserved(self) -> None:
        # os.getenv of a secret-named key flowing into a log call is still flagged.
        ids = self._scan(
            "import os, logging\n"
            "def h():\n"
            "    k = os.getenv('API_KEY')\n"
            "    logging.info(f'key={k}')\n"
        )
        assert "SEC-PY_SECRET_IN_LOG" in ids

    def test_nonsecret_log_not_flagged(self) -> None:
        # A plain user value logged is not a secret leak (no FP).
        ids = self._scan(
            "import logging\n"
            "def h(user):\n"
            "    logging.info(f'user={user}')\n"
        )
        assert "SEC-PY_SECRET_IN_LOG" not in ids

    def test_deep_accumulator_completes_fast(self) -> None:
        # ``acc += acc`` builds a synthesized BinOp tree of 2**K nodes; the
        # pre-fix code hung indefinitely for K>=12. The memoized walk finishes
        # this in milliseconds — assert a generous ceiling the old code could
        # never meet. No secret is present, so no finding is expected.
        import time as _time
        K = 30
        src = (
            "import logging\n"
            "def build(user):\n"
            "    acc = user\n"
            + "".join("    acc += acc\n" for _ in range(K))
            + "    logging.info(f'out {acc}')\n"
        )
        t0 = _time.perf_counter()
        ids = self._scan(src)
        elapsed = _time.perf_counter() - t0
        assert "SEC-PY_SECRET_IN_LOG" not in ids
        # 5 s is orders of magnitude above the ~2 ms real cost yet far below the
        # unbounded pre-fix time — a clean, non-flaky regression fence.
        assert elapsed < 5.0, f"secret-in-log fan-out regressed: {elapsed:.2f}s"

    def test_deep_accumulator_with_secret_still_flagged(self) -> None:
        # Same deep accumulator, but seeded from a real env secret: correctness
        # (the TP) must survive the memoized traversal, not just the perf.
        K = 25
        src = (
            "import os, logging\n"
            "def build():\n"
            "    acc = os.getenv('API_KEY')\n"
            + "".join("    acc += acc\n" for _ in range(K))
            + "    logging.info(f'out {acc}')\n"
        )
        assert "SEC-PY_SECRET_IN_LOG" in self._scan(src)


def _collect_src(src: str) -> list[dict]:
    """Run the analyzer over a one-file temp tree and return its findings."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mod.py").write_text(src)
        return _collect(d)


class TestDoubleSanitizePercentFormat:
    """B5 double-sanitize: `%`-format with an escaped value is safe.

    The original fix recognised f-strings and `+` concat but not `%`-format,
    whose right operand is an ``ast.Tuple`` with no handler — so it fell
    through to "not escaped". Measured on django-cms 3.11.0,
    ``mark_safe("%s%s" % (indent, escape(title)))`` was reported as reflected
    XSS despite the explicit ``escape()``.
    """

    def test_escaped_percent_format_not_flagged(self) -> None:
        findings = _collect_src(
            "from django.utils.html import escape, mark_safe\n"
            "def render(title, depth):\n"
            "    indent = '&nbsp;' * depth\n"
            "    return mark_safe('%s%s' % (indent, escape(title)))\n"
        )
        xss = [f for f in findings if "XSS" in f["title"]]
        assert not xss, f"escaped %-format flagged as XSS: {[f['title'] for f in findings]}"

    def test_unescaped_percent_format_still_flagged(self) -> None:
        """The Tuple arm must not become a blanket exemption."""
        findings = _collect_src(
            "from django.utils.html import mark_safe\n"
            "def render(request):\n"
            "    title = request.GET.get('t')\n"
            "    return mark_safe('<b>%s</b>' % (title,))\n"
        )
        assert [f for f in findings if "XSS" in f["title"]], (
            "unescaped %-format into mark_safe must still be reported"
        )


class TestUnprovenDataflowConfidence:
    """A reachability-dependent sink with no proven source->sink path is a
    SHAPE match, not a proof, and must not claim the confidence of one.

    Measured over 216K LOC of real OSS, every finding the taint analyzer
    produced was chainless, and most outside test code were false positives on
    developer-controlled input (config.from_pyfile, setup.py, PYTHONSTARTUP,
    docs examples, CI scripts) — reported at the same HIGH/CRITICAL as a proven
    exploit path.
    """

    def test_unproven_sqli_is_downgraded(self) -> None:
        # No request source anywhere: the sink shape matches, the dataflow does not.
        findings = _collect_src(
            "import sqlite3\n"
            "def load(conn, path):\n"
            "    sql = 'SELECT * FROM t WHERE a=' + path\n"
            "    conn.cursor().execute(sql)\n"
        )
        sqli = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        assert sqli, "the sink shape should still be reported (evidence preserved)"
        for f in sqli:
            assert f["confidence"] == "MEDIUM", f"unproven SQLi confidence={f['confidence']}"
            assert not f.get("reachable"), "no chain was proven"

    def test_proven_sqli_keeps_high_confidence(self) -> None:
        findings = _collect_src(
            "from flask import request\n"
            "def view(conn):\n"
            "    name = request.args.get('n')\n"
            "    conn.cursor().execute('SELECT * FROM t WHERE a=' + name)\n"
        )
        sqli = [f for f in findings if f["id"] == "SEC-PY_SQL_INJECTION"]
        assert sqli, "proven SQLi must still be detected"
        assert any(f["confidence"] == "HIGH" and f.get("reachable") for f in sqli), (
            f"a proven taint path must keep HIGH confidence: "
            f"{[(f['confidence'], f.get('reachable')) for f in sqli]}"
        )

    def test_unconditional_sink_is_not_downgraded(self) -> None:
        """pickle.loads is dangerous whatever reaches it — it never attempts a
        chain, so the downgrade must not touch it."""
        findings = _collect_src("import pickle\ndef f(blob):\n    return pickle.loads(blob)\n")
        pk = [f for f in findings if f["id"] == "SEC-PY_PICKLE_LOAD"]
        assert pk, "pickle.loads must still be reported"
        assert pk[0]["confidence"] == "HIGH", (
            f"unconditional sink downgraded to {pk[0]['confidence']}"
        )


class TestUrlHostAllowlistGuard:
    """A dominating ``urlparse(url).netloc not in ALLOWED`` early exit is an
    SSRF / open-redirect guard.

    Falling through ``if p.netloc not in ALLOWED: return`` means the URL's
    whole authority IS in a literal allowlist, so the request or redirect that
    follows cannot reach an attacker-chosen host. The recognition is held to
    the same dominance discipline as the other guards: a top-level ``if``
    before the sink whose body ends control flow, over a literal collection.
    Only ``or`` may combine the host check with other conditions; with ``and``
    the host check can be skipped. A ``.hostname`` check does not count.
    """

    _PREFIX = (
        "import os\n"
        "import logging\n"
        "from urllib.parse import urlparse\n"
        "import requests\n"
        "from flask import abort, redirect, request\n"
        'ALLOWED = {"api.example.com", "cdn.example.com"}\n'
    )

    def _ssrf(self, body: str, prefix: str | None = None) -> list[dict]:
        findings = _collect_src((self._PREFIX if prefix is None else prefix) + body)
        return [f for f in findings if f["id"] == "SEC-PY_SSRF"]

    def _redirect(self, body: str, prefix: str | None = None) -> list[dict]:
        findings = _collect_src((self._PREFIX if prefix is None else prefix) + body)
        return [f for f in findings if f["id"] == "SEC-PY_OPEN_REDIRECT"]

    def test_ssrf_hostname_allowlist_guard_does_not_sanitise(self) -> None:
        # Backslash differential: urlparse's hostname of
        # `http://10.0.0.1\@api.example.com` is api.example.com, but requests
        # connects to 10.0.0.1.
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    p = urlparse(url)\n"
            '    if p.scheme != "https" or p.hostname not in ALLOWED:\n'
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a urlparse hostname allowlist is bypassable and must not sanitise"

    def test_ssrf_inline_urlparse_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            "        abort(400)\n"
            "    return requests.get(url, timeout=5).text\n"
        )
        assert not ssrf, f"inline urlparse guard not honoured: {ssrf}"

    def test_ssrf_netloc_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    p = urlparse(url)\n"
            "    if p.netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert not ssrf, f"netloc allowlist guard not honoured: {ssrf}"

    def test_ssrf_guard_after_sink_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    resp = requests.get(url, timeout=5)\n"
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return resp.text\n"
        )
        assert ssrf, "a guard after the sink cannot protect it"

    def test_ssrf_guard_without_exit_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        logging.warning("unexpected host %s", url)\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a guard that only logs and falls through protects nothing"

    def test_ssrf_guard_on_scheme_only_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    p = urlparse(url)\n"
            '    if p.scheme != "https":\n'
            '        return "https only", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a scheme check does not bound the host"

    def test_ssrf_guard_against_env_list_does_not_sanitise(self) -> None:
        prefix = self._PREFIX.replace(
            'ALLOWED = {"api.example.com", "cdn.example.com"}\n',
            'ALLOWED = os.environ["ALLOWED_HOSTS"].split(",")\n',
        )
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n",
            prefix=prefix,
        )
        assert ssrf, "an allowlist read from the environment is not provably bounded"

    def test_ssrf_guard_joined_with_and_does_not_sanitise(self) -> None:
        # With `and`, `http://evil.example` fails the first operand, the whole
        # test is False, and the request goes out without the host ever being
        # checked against the allowlist.
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    p = urlparse(url)\n"
            '    if p.scheme != "https" and p.netloc not in ALLOWED:\n'
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a host check joined with `and` can be skipped"

    def test_redirect_netloc_allowlist_guard_is_sanitiser(self) -> None:
        findings = _collect_src(
            self._PREFIX + "def login_redirect():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return redirect("/")\n'
            "    return redirect(url)\n"
        )
        redir = [f for f in findings if f["id"] == "SEC-PY_OPEN_REDIRECT"]
        assert not redir, f"netloc allowlist guard not honoured for redirect: {redir}"

    def test_host_allowlist_guard_does_not_sanitise_xss(self) -> None:
        # The guard bounds the host only: `https://api.example.com/<script>`
        # passes it, so the same value rendered unescaped is still XSS.
        findings = _collect_src(
            self._PREFIX + "from django.utils.safestring import mark_safe\n"
            "def render_link():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            "        abort(400)\n"
            "    return mark_safe(url)\n"
        )
        assert [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"], (
            f"a host allowlist must not count as an XSS sanitiser: {_ids(findings)}"
        )

    # -- the empty string is not a host (R-pf22) -----------------------------

    def test_redirect_allowlist_with_empty_string_does_not_sanitise(self) -> None:
        # `/\evil.com` and `https:evil.com` have netloc "", and browsers send
        # both to evil.com, so an allowlist holding "" admits them.
        prefix = self._PREFIX.replace(
            'ALLOWED = {"api.example.com", "cdn.example.com"}\n',
            'ALLOWED = {"", "api.example.com"}\n',
        )
        redir = self._redirect(
            "def login_redirect():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return redirect("/")\n'
            "    return redirect(url)\n",
            prefix=prefix,
        )
        assert redir, "an allowlist containing the empty string admits host-less URLs"

    def test_redirect_dict_allowlist_with_empty_key_does_not_sanitise(self) -> None:
        prefix = self._PREFIX.replace(
            'ALLOWED = {"api.example.com", "cdn.example.com"}\n',
            'ALLOWED = {"": "/", "api.example.com": "/home"}\n',
        )
        redir = self._redirect(
            "def login_redirect():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return redirect("/")\n'
            "    return redirect(url)\n",
            prefix=prefix,
        )
        assert redir, "a dict allowlist keyed by the empty string admits host-less URLs"

    # -- the guard describes the whole URL string (R-pf23) -------------------

    def test_ssrf_guard_does_not_sanitise_non_leftmost_concat(self) -> None:
        # url=`evil.com://api.example.com/x` has netloc api.example.com, but
        # requests sends `https://evil.com://api.example.com/x` to evil.com.
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            '    return requests.get("https://" + url, timeout=5).text\n'
        )
        assert ssrf, "a guarded URL placed after a prefix no longer fixes the host"

    def test_ssrf_guard_does_not_sanitise_percent_format(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            '    return requests.get("https://%s" % url, timeout=5).text\n'
        )
        assert ssrf, "a guarded URL substituted into a template no longer fixes the host"

    def test_ssrf_guard_sanitises_leftmost_concat(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            '    return requests.get(url + "/v1", timeout=5).text\n'
        )
        assert not ssrf, f"a suffix after the guarded URL keeps its host: {ssrf}"

    # -- the guard must end before the sink ----------------------------------

    def test_ssrf_sink_inside_rejecting_branch_is_reported(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).netloc not in ALLOWED:\n"
            "        requests.get(url, timeout=5)\n"
            '        return "host not allowed", 400\n'
            '    return "ok"\n'
        )
        assert ssrf, "a sink inside the branch that rejects the host is unguarded"

    # -- shapes pinned by review ----------------------------------------------

    def test_ssrf_urlsplit_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "from urllib.parse import urlsplit\n"
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlsplit(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert not ssrf, f"urlsplit netloc guard not honoured: {ssrf}"

    def test_ssrf_qualified_urlparse_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "import urllib.parse\n"
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urllib.parse.urlparse(url).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert not ssrf, f"qualified urllib.parse.urlparse guard not honoured: {ssrf}"

    def test_ssrf_guard_on_other_name_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            '    other = request.args.get("other")\n'
            "    if urlparse(other).netloc not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a guard on a different value says nothing about the sink argument"

    def test_ssrf_guard_nested_in_branch_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch(strict):\n"
            '    url = request.args.get("url")\n'
            "    if strict:\n"
            "        if urlparse(url).netloc not in ALLOWED:\n"
            '            return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert ssrf, "a guard inside a branch that may not run does not dominate the sink"

    def test_redirect_hostname_allowlist_does_not_sanitise(self) -> None:
        redir = self._redirect(
            "def login_redirect():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).hostname not in ALLOWED:\n"
            '        return redirect("/")\n'
            "    return redirect(url)\n"
        )
        assert redir, "browsers read `\\` as `/`, so a hostname allowlist is bypassable"


class TestPathContainmentAssertion:
    """A resolved path asserted to stay under a fixed base is not traversal.

    The guard has two halves, and both are required. The path must be
    RESOLVED (``os.path.realpath`` / ``Path.resolve()``), which collapses
    ``..`` and follows symlinks; ``abspath`` and ``os.path.join`` do neither
    for symlinks, and ``commonpath``, ``startswith`` and ``is_relative_to``
    are lexical. The containment check must then end at a path component
    (``B + os.sep``, never a bare ``B``) and leave the function when it fails.
    The usual dominance discipline applies: a top-level guard before the sink
    whose rejecting body ends control flow.
    """

    _PREFIX = (
        "import logging\n"
        "import os\n"
        "from pathlib import Path\n"
        "from flask import abort, request\n"
        'REPORTS_DIR = "/srv/reports"\n'
        'BASE = Path("/srv/reports")\n'
    )

    def _pt(self, body: str, prefix: str | None = None) -> list[dict]:
        findings = _collect_src((self._PREFIX if prefix is None else prefix) + body)
        return [f for f in findings if f["id"] == "SEC-PY_PATH_TRAVERSAL"]

    @staticmethod
    def _at(findings: list[dict], line: int) -> list[dict]:
        return [f for f in findings if f["line"] == f"mod.py:{line}"]

    # -- the brief's eight -----------------------------------------------------

    def test_realpath_commonpath_guard_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            '        return "invalid filename", 400\n'
            "    with open(full) as fh:\n"
            "        return fh.read()\n"
        )
        assert not pt, f"realpath + commonpath guard not honoured: {pt}"

    def test_startswith_base_plus_sep_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not pt, f"realpath + separator-checked startswith not honoured: {pt}"

    def test_pathlib_is_relative_to_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    if not full.is_relative_to(BASE):\n"
            '        raise ValueError("outside the reports directory")\n'
            "    return open(full).read()\n"
        )
        assert not pt, f"resolve() + is_relative_to guard not honoured: {pt}"

    def test_pathlib_relative_to_in_try_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE)\n"
            "    except ValueError:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert not pt, f"resolve() + relative_to in try not honoured: {pt}"

    def test_startswith_without_separator_does_not_contain(self) -> None:
        # Review Focus 5: `/srv/reports_evil/x` starts with `/srv/reports`.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "a prefix check without a separator admits sibling directories"

    def test_commonpath_without_realpath_does_not_contain(self) -> None:
        # commonpath is lexical: `/srv/reports/../../etc/passwd` passes it.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.join(base, f)\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "commonpath over an unresolved join contains nothing"

    def test_resolve_alone_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 10), "resolving a path without asserting containment is not a guard"

    def test_join_consumed_only_by_realpath_is_not_its_own_sink(self) -> None:
        # The corpus shape: the resolved join is bound once and every use of it
        # sits behind the containment guard.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert not self._at(pt, 10), (
            f"a guarded resolved join is checked where it is used, not at the join: {pt}"
        )

    # -- pinned by the plan's decisions -----------------------------------------

    def test_join_inside_realpath_still_reported_at_unguarded_sink(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    return open(full).read()\n"
        )
        at_open = self._at(pt, 10)
        assert at_open, f"an unguarded resolved path is still traversal at the sink: {pt}"
        assert at_open[0].get("reachable") is True

    def test_abspath_with_commonpath_does_not_contain(self) -> None:
        # abspath collapses `..` but follows no symlink: a link under the base
        # that points outside it passes the check.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.abspath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "abspath does not resolve symlinks, so it does not contain"

    # -- the join is dropped only when a containment guard checks it (R-pf24) ----

    @staticmethod
    def _joins(findings: list[dict], line: int) -> list[dict]:
        return [
            f
            for f in findings
            if f["line"] == f"mod.py:{line}" and f.get("sink", "").startswith("os.path.join(")
        ]

    def test_join_inside_path_resolve_not_its_own_sink_when_guarded(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = Path(os.path.join(REPORTS_DIR, f)).resolve()\n"
            "    if not full.is_relative_to(BASE):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not self._joins(pt, 9), pt
        assert not self._at(pt, 12), f"the guarded open is contained: {pt}"

    def test_unguarded_resolved_join_is_still_its_own_sink(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    return open(full).read()\n"
        )
        assert self._joins(pt, 9), f"no guard checks the resolved join: {pt}"

    def test_join_inside_abspath_is_still_its_own_sink(self) -> None:
        # abspath is not a resolution, so no guard can make its join safe.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.abspath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert self._joins(pt, 10), pt

    def test_join_inside_realpath_reaching_unmodelled_consumer_is_reported(self) -> None:
        # os.remove is not a modelled sink: the join is the only place left to
        # report the flow.
        pt = self._pt(
            "def delete_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    os.remove(full)\n"
            '    return "ok"\n'
        )
        joins = self._joins(pt, 9)
        assert joins, f"a resolved join that reaches os.remove unchecked is traversal: {pt}"
        assert joins[0].get("reachable") is True

    def test_inline_realpath_join_reaching_unmodelled_consumer_is_reported(self) -> None:
        pt = self._pt(
            "def delete_report():\n"
            '    os.remove(os.path.realpath(os.path.join(REPORTS_DIR, request.args["f"])))\n'
            '    return "ok"\n'
        )
        joins = self._joins(pt, 8)
        assert joins, f"an inline resolved join is checked nowhere: {pt}"
        assert joins[0].get("reachable") is True

    def test_helper_returning_resolved_join_is_reported(self) -> None:
        pt = self._pt(
            "def report_path():\n"
            '    f = request.args["f"]\n'
            "    return os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
        )
        joins = self._joins(pt, 9)
        assert joins, f"a resolved join returned to the caller is checked nowhere: {pt}"
        assert joins[0].get("reachable") is True

    def test_resolved_join_used_before_its_guard_is_reported(self) -> None:
        pt = self._pt(
            "def delete_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    os.remove(full)\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._joins(pt, 9), f"os.remove runs before the guard: {pt}"

    def test_resolved_join_used_in_rejecting_branch_is_reported(self) -> None:
        pt = self._pt(
            "def delete_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        os.remove(full)\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._joins(pt, 9), f"the rejecting branch uses the uncontained path: {pt}"

    def test_unresolved_join_is_still_its_own_sink(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.join(REPORTS_DIR, f)\n"
            "    return open(full).read()\n"
        )
        assert [f for f in self._at(pt, 9) if f.get("sink", "").startswith("os.path.join(")]

    # -- accepted spellings -------------------------------------------------------

    @pytest.mark.parametrize(
        "prefix_arg",
        ['REPORTS_DIR + "/"', 'os.path.join(REPORTS_DIR, "")', "REPORTS_DIR + os.path.sep"],
    )
    def test_startswith_other_separator_spellings_contain(self, prefix_arg: str) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            f"    if not full.startswith({prefix_arg}):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not pt, f"`startswith({prefix_arg})` not honoured: {pt}"

    @pytest.mark.parametrize(
        "test",
        [
            "os.path.commonpath([full, base]) != base",
            "base != os.path.commonpath([base, full])",
        ],
    )
    def test_commonpath_operand_order_contains(self, test: str) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    base = os.path.realpath(REPORTS_DIR)\n"
            "    full = os.path.realpath(os.path.join(base, f))\n"
            f"    if {test}:\n"
            '        return "invalid filename", 400\n'
            "    return open(full).read()\n"
        )
        assert not pt, f"`{test}` not honoured: {pt}"

    def test_commonpath_against_inline_constant_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            '    full = os.path.realpath(os.path.join("/srv/reports", f))\n'
            '    if os.path.commonpath(["/srv/reports", full]) != "/srv/reports":\n'
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not pt, f"constant base not honoured: {pt}"

    def test_resolved_pathlib_base_contains(self) -> None:
        pt = self._pt(
            "ROOT = Path(REPORTS_DIR).resolve()\n"
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (ROOT / f).resolve()\n"
            "    if not full.is_relative_to(ROOT):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not pt, f"a resolved pathlib base not honoured: {pt}"

    @pytest.mark.parametrize(
        "clause",
        [
            "except (TypeError, ValueError):",
            "except Exception:",
            "except BaseException:",
            "except:",
        ],
    )
    def test_relative_to_with_broader_handler_contains(self, clause: str) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE)\n"
            f"    {clause}\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert not pt, f"`{clause}` not honoured: {pt}"

    def test_sink_in_else_of_guard_contains(self) -> None:
        # The else branch runs only when the containment test passed.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    else:\n"
            "        return open(full).read()\n"
        )
        assert not pt, f"a sink in the guard's else branch is contained: {pt}"

    # -- rejected separators and arguments ----------------------------------------

    def test_startswith_backslash_separator_does_not_contain(self) -> None:
        # On POSIX `\` is a filename character: `/srv/reports\evil` is a file
        # in /srv that starts with `/srv/reports\`.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            '    if not full.startswith(REPORTS_DIR + "\\\\"):\n'
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "a backslash is not a separator on POSIX"

    def test_startswith_with_start_offset_does_not_contain(self) -> None:
        # `startswith(p, 4)` tests `full[4:]`: `/xyz/srv/reports/a` passes.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep, 4):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "a startswith that skips the start of the path checks nothing"

    def test_commonpath_against_different_base_does_not_contain(self) -> None:
        # Passing means the common path is `/srv`, i.e. NOT under /srv/reports.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            '    if os.path.commonpath([REPORTS_DIR, full]) != "/srv":\n'
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "commonpath compared with another directory contains nothing"

    def test_is_relative_to_on_unresolved_path_does_not_contain(self) -> None:
        # is_relative_to is lexical: BASE / "../../etc/passwd" is relative to BASE.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = BASE / f\n"
            "    if not full.is_relative_to(BASE):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "is_relative_to over an unresolved path contains nothing"

    def test_relative_to_walk_up_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE, walk_up=True)\n"
            "    except ValueError:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 14), "relative_to(walk_up=True) accepts paths outside the base"

    # -- the base must be fixed ------------------------------------------------

    def test_base_from_request_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            '    base = request.args["base"]\n'
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if not full.startswith(base + os.sep):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "a base the request chooses contains nothing"

    def test_base_from_environment_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            '    base = os.path.realpath(os.environ["REPORTS_DIR"])\n'
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "a base read from the environment is not provably bounded"

    @pytest.mark.parametrize("root", ['"/"', '""', '"/srv/.."'])
    def test_root_base_does_not_contain(self, root: str) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            f"    base = os.path.realpath({root})\n"
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if os.path.commonpath([base, full]) != base:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), f"a base of {root} is the filesystem root"

    # -- dominance ---------------------------------------------------------------

    def test_guard_after_sink_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    data = open(full).read()\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    return data\n"
        )
        assert self._at(pt, 10), "a guard after the sink cannot protect it"

    def test_guard_without_exit_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            '        logging.warning("outside the base: %s", full)\n'
            "    return open(full).read()\n"
        )
        assert self._at(pt, 12), "a guard that only logs protects nothing"

    def test_guard_nested_in_branch_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report(strict):\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if strict:\n"
            "        if not full.startswith(REPORTS_DIR + os.sep):\n"
            "            abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "a guard inside a branch that may not run does not dominate"

    def test_sink_inside_rejecting_branch_is_reported(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            '        logging.warning("%s", open(full).read())\n'
            "        abort(400)\n"
            '    return "ok"\n'
        )
        assert self._at(pt, 11), "a sink inside the branch that rejects the path is unguarded"

    def test_guard_on_another_path_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            '    other = os.path.realpath(os.path.join(REPORTS_DIR, request.args["g"]))\n'
            "    if not other.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "a guard on another value says nothing about the sink argument"

    def test_path_rebound_after_guard_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            '    full = os.path.realpath(os.path.join(REPORTS_DIR, request.args["g"]))\n'
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "the guard checked the old value, not the one opened"

    def test_unresolved_binding_on_another_branch_does_not_contain(self) -> None:
        # With `raw` set, `/srv/reports/../../etc/passwd` reaches commonpath
        # unresolved and passes it.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            '    if request.args.get("raw"):\n'
            "        full = f\n"
            "    else:\n"
            "        full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if os.path.commonpath([REPORTS_DIR, full]) != REPORTS_DIR:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 15), "a path resolved on one branch only is not resolved"

    def test_relative_to_handler_that_falls_through_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE)\n"
            "    except ValueError:\n"
            '        logging.warning("outside the base: %s", full)\n'
            "    return open(full).read()\n"
        )
        assert self._at(pt, 14), "a handler that logs and falls through protects nothing"

    def test_relative_to_caught_first_by_handler_that_falls_through(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        full.relative_to(BASE)\n"
            "    except Exception:\n"
            "        pass\n"
            "    except ValueError:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 16), "the first matching handler decides, and it falls through"

    def test_relative_to_under_condition_in_try_does_not_contain(self) -> None:
        pt = self._pt(
            "def read_report(strict):\n"
            '    f = request.args["f"]\n'
            "    full = (BASE / f).resolve()\n"
            "    try:\n"
            "        if strict:\n"
            "            full.relative_to(BASE)\n"
            "    except ValueError:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 15), "a relative_to that may not run asserts nothing"

    def test_base_parameter_shadowing_a_constant_does_not_contain(self) -> None:
        # The scope chain finds the module-level `base`, but the guard compares
        # against the parameter, which the caller chooses.
        pt = self._pt(
            'base = "/srv/reports"\n'
            "def read_report(base):\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(base, f))\n"
            "    if not full.startswith(base + os.sep):\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 13), "a parameter named like a constant is not that constant"

    def test_base_from_enclosing_function_does_not_contain(self) -> None:
        pt = self._pt(
            'base = "/srv/reports"\n'
            "def make_reader(base):\n"
            "    def read_report():\n"
            '        f = request.args["f"]\n'
            "        full = os.path.realpath(os.path.join(base, f))\n"
            "        if not full.startswith(base + os.sep):\n"
            "            abort(400)\n"
            "        return open(full).read()\n"
            "    return read_report\n"
        )
        assert self._at(pt, 14), "a closure over the caller's base is not a fixed base"

    def test_alias_bound_on_a_branch_does_not_contain(self) -> None:
        # `p` is the checked path on one branch and raw input on the other.
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            '    if request.args.get("raw"):\n'
            '        p = request.args["g"]\n'
            "    else:\n"
            "        p = full\n"
            "    return open(p).read()\n"
        )
        assert self._at(pt, 16), "an alias assigned on a branch is not always the checked path"

    def test_plain_alias_of_contained_path_contains(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    p = full\n"
            "    return open(p).read()\n"
        )
        assert not pt, f"an alias bound once to the checked path is contained: {pt}"

    # -- module-level bases (R-pf25a) -------------------------------------------

    def test_module_base_rebound_through_global_does_not_contain(self) -> None:
        pt = self._pt(
            'RD = "/srv/reports"\n'
            "def setrd():\n"
            "    global RD\n"
            '    RD = request.args["r"]\n'
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(RD, f))\n"
            "    if os.path.commonpath([RD, full]) != RD:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
        )
        assert self._at(pt, 16), "a base another function rebinds through `global` is not fixed"

    def test_module_base_reassigned_after_handler_does_not_contain(self) -> None:
        pt = self._pt(
            'RD = "/srv/reports"\n'
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(RD, f))\n"
            "    if os.path.commonpath([RD, full]) != RD:\n"
            "        abort(400)\n"
            "    return open(full).read()\n"
            'RD = os.environ.get("REPORTS_DIR", "/")\n'
        )
        assert self._at(pt, 13), "the handler runs with the module's last binding of the base"

    def test_class_attribute_does_not_stand_for_module_base(self) -> None:
        # A method reads the module global REPORTS_ROOT ("/"), never the class
        # attribute of the same name.
        pt = self._pt(
            'REPORTS_ROOT = "/"\n'
            "class Reports:\n"
            '    REPORTS_ROOT = "/srv/reports"\n'
            "    def get(self):\n"
            '        f = request.args["f"]\n'
            "        full = os.path.realpath(os.path.join(REPORTS_ROOT, f))\n"
            "        if os.path.commonpath([REPORTS_ROOT, full]) != REPORTS_ROOT:\n"
            "            abort(400)\n"
            "        return open(full).read()\n"
        )
        assert self._at(pt, 15), "a class attribute is not the name a method reads"

    # -- inner parameters shadowing the checked path (R-pf25b) ------------------

    def test_lambda_parameter_shadowing_checked_path_is_reported(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            '    return (lambda full: open(full).read())(request.args["g"])\n'
        )
        assert self._at(pt, 12), "the lambda's `full` is its argument, not the checked path"

    def test_lambda_default_shadowing_checked_path_is_reported(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            '    rd = lambda full=request.args["g"]: open(full).read()\n'
            "    return rd()\n"
        )
        assert self._at(pt, 12), "the lambda's default is raw input, not the checked path"

    def test_nested_def_parameter_shadowing_checked_path_is_reported(self) -> None:
        pt = self._pt(
            "def read_report():\n"
            '    f = request.args["f"]\n'
            "    full = os.path.realpath(os.path.join(REPORTS_DIR, f))\n"
            "    if not full.startswith(REPORTS_DIR + os.sep):\n"
            "        abort(400)\n"
            "    def rd(full):\n"
            "        return open(full).read()\n"
            '    return rd(request.args["g"])\n'
        )
        assert self._at(pt, 13), "the nested function's `full` is its parameter"


# ---------------------------------------------------------------------------
# One hop into a same-file helper whose caller assigns the value first
# ---------------------------------------------------------------------------

_SHELL_PRELUDE = "import subprocess\nfrom flask import request\n"
_PING = 'def _ping(host):\n    subprocess.run(f"ping -c 1 {host}", shell=True)\n'
_PING_SINK = "subprocess(shell=True, cmd=f'ping -c 1 {host}')"


def _link(line: int, expr: str) -> dict:
    return {"file": "mod.py", "line": line, "expr": expr}


class TestHelperTaintThroughCallerAssignment:
    """A helper's parameter is tainted when a caller in the same file passes a
    value it assigned from request input, not only when the request expression
    is written inline as the argument. Lines below count from the two-line
    prelude, so the first line of each snippet is line 3."""

    @staticmethod
    def _shell(src: str) -> dict:
        found = [
            f
            for f in _collect_src(_SHELL_PRELUDE + src)
            if f["id"] == "SEC-PY_SUBPROCESS_SHELL"
        ]
        assert len(found) == 1, found
        return found[0]

    def _proven(self, src: str) -> list[dict]:
        f = self._shell(src)
        assert f.get("reachable") is True, f
        return f["taint_chain"]

    def _unproven(self, src: str) -> None:
        f = self._shell(src)
        assert f.get("reachable") is None, f
        assert "taint_chain" not in f, f

    def test_helper_param_tainted_via_caller_assignment_same_name(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET.get("host")\n'
            + "    return _ping(host)\n"
        )
        assert chain[0] == _link(6, "request.GET.get('host')")
        assert [(link["line"], link["expr"]) for link in chain[1:]] == [
            (7, "_ping(host)"),
            (4, _PING_SINK),
        ]

    def test_helper_param_tainted_via_caller_assignment_other_name(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    target = request.GET.get("host")\n'
            + "    return _ping(target)\n"
        )
        assert chain[0]["expr"] == "request.GET.get('host')"
        assert chain[0]["line"] == 6

    def test_helper_param_tainted_via_two_caller_assignments(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    raw = request.GET["h"]\n'
            + "    host = raw.strip()\n"
            + "    return _ping(host)\n"
        )
        assert [(link["line"], link["expr"]) for link in chain] == [
            (6, "request.GET['h']"),
            (7, "raw.strip()"),
            (8, "_ping(host)"),
            (4, _PING_SINK),
        ]

    def test_helper_called_with_constant_everywhere_is_not_reachable(self) -> None:
        self._unproven(
            _PING
            + "def first():\n"
            + '    return _ping("localhost")\n'
            + "def second():\n"
            + '    return _ping("127.0.0.1")\n'
        )

    def test_helper_defined_after_caller_still_resolves(self) -> None:
        chain = self._proven(
            "def view(request):\n"
            + '    host = request.GET.get("host")\n'
            + "    return _ping(host)\n"
            + _PING
        )
        assert chain[0] == _link(4, "request.GET.get('host')")
        assert chain[-1]["line"] == 7

    def test_name_bound_only_to_a_constant_is_not_reachable(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = "localhost"\n'
            + "    return _ping(host)\n"
        )

    def test_one_tainted_caller_among_constant_callers_is_enough(self) -> None:
        chain = self._proven(
            _PING
            + "def health():\n"
            + '    host = "localhost"\n'
            + "    return _ping(host)\n"
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + "    return _ping(host)\n"
        )
        assert chain[0] == _link(9, "request.GET['h']")

    # -- which assignment counts: the last one before the call ---------------

    def test_constant_reassigned_before_the_call_is_not_reachable(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + '    host = "localhost"\n'
            + "    return _ping(host)\n"
        )

    def test_constant_assigned_after_the_call_keeps_the_proof(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + "    out = _ping(host)\n"
            + '    host = "localhost"\n'
            + "    return out\n"
        )
        assert chain[0]["line"] == 6

    def test_request_assigned_after_the_call_is_not_reachable(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = "localhost"\n'
            + "    out = _ping(host)\n"
            + '    host = request.GET["h"]\n'
            + "    return out\n"
        )

    def test_assignment_holding_the_call_does_not_bind_its_argument(self) -> None:
        # The call runs before `host` is rebound, so it still sees "localhost".
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = "localhost"\n'
            + '    host = request.GET.get("h", _ping(host))\n'
        )

    # -- whose bindings a call site reads ------------------------------------

    def test_same_named_functions_do_not_share_bindings(self) -> None:
        # Reader.handle assigns `host` from request BEFORE Pinger.handle's call
        # in source order, so only keying bindings by node keeps it out.
        self._unproven(
            _PING
            + "class Reader:\n"
            + "    def handle(self, request):\n"
            + '        host = request.GET["h"]\n'
            + "        return host\n"
            + "class Pinger:\n"
            + "    def handle(self, host):\n"
            + "        return _ping(host)\n"
        )

    def test_bare_name_call_does_not_reach_a_same_named_method(self) -> None:
        # `handle(h, p)` calls the module function; Pinger.handle's `host`
        # (index 1, after `self`) must not take `p`.
        self._unproven(
            "def handle(host, port):\n"
            + "    return host, port\n"
            + "class Pinger:\n"
            + "    def handle(self, host):\n"
            + '        subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            + "def view():\n"
            + '    h = "localhost"\n'
            + '    p = request.args["p"]\n'
            + "    return handle(h, p)\n"
        )

    def test_inline_bare_name_call_does_not_reach_a_same_named_method(self) -> None:
        self._unproven(
            "def handle(host, port):\n"
            + "    return host, port\n"
            + "class Pinger:\n"
            + "    def handle(self, host):\n"
            + '        subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            + "def view():\n"
            + '    return handle("localhost", request.args["p"])\n'
        )

    def test_module_level_call_resolves_module_bindings(self) -> None:
        chain = self._proven(
            _PING + 'host = request.args.get("host")\n' + "_ping(host)\n"
        )
        assert chain[0] == _link(5, "request.args.get('host')")
        assert chain[1] == _link(6, "_ping(host)")

    def test_function_local_does_not_reach_a_module_level_call(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + "    return host\n"
            + "_ping(host)\n"
        )

    def test_nested_function_assignment_does_not_reach_the_enclosing_call(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = "localhost"\n'
            + "    def remember():\n"
            + '        host = request.GET["h"]\n'
            + "        return host\n"
            + "    return _ping(host)\n"
        )

    def test_call_inside_nested_function_reads_its_bindings(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + "    def run():\n"
            + '        host = request.GET["h"]\n'
            + "        return _ping(host)\n"
            + "    return run()\n"
        )
        assert chain[0]["line"] == 7

    def test_comprehension_variable_shadows_the_caller_binding(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + '    return [_ping(host) for host in ("a", "b")]\n'
        )

    def test_lambda_parameter_shadows_the_caller_binding(self) -> None:
        self._unproven(
            _PING
            + "def view(request):\n"
            + '    host = request.GET["h"]\n'
            + "    ping = lambda host: _ping(host)\n"
            + '    return ping("localhost")\n'
        )

    def test_caller_parameter_is_not_traced_into_its_own_callers(self) -> None:
        # Single hop: middle's `h` would need a second hop into view.
        self._unproven(
            _PING
            + "def middle(h):\n"
            + "    host = h\n"
            + "    return _ping(host)\n"
            + "def view(request):\n"
            + '    return middle(request.GET["h"])\n'
        )

    # -- binding shapes the caller may use -----------------------------------

    def test_keyword_argument_bound_in_caller(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    target = request.GET["h"]\n'
            + "    return _ping(host=target)\n"
        )
        assert chain[0]["expr"] == "request.GET['h']"

    def test_keyword_only_parameter_bound_in_caller(self) -> None:
        # Task 3.4 (R-pf48): a parameter after `*` is passed by keyword alone,
        # as the full-stack-fastapi-template email renderer's are.
        chain = self._proven(
            'def _ping(*, host):\n    subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            + "def view(request):\n"
            + '    target = request.GET["h"]\n'
            + "    return _ping(host=target)\n"
        )
        assert chain[0]["expr"] == "request.GET['h']"

    def test_keyword_only_parameter_with_a_constant_caller_is_not_reachable(self) -> None:
        self._unproven(
            'def _ping(*, host):\n    subprocess.run(f"ping -c 1 {host}", shell=True)\n'
            + "def view(request):\n"
            + '    return _ping(host="example.com")\n'
        )

    def test_annotated_assignment_in_caller(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    host: str = request.GET["h"]\n'
            + "    return _ping(host)\n"
        )
        assert chain[0] == _link(6, "request.GET['h']")

    def test_augmented_assignment_in_caller_keeps_its_line(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    host = "10.0.0."\n'
            + '    host += request.GET["octet"]\n'
            + "    return _ping(host)\n"
        )
        assert chain[0] == _link(7, "'10.0.0.' + request.GET['octet']")

    def test_for_target_in_caller(self) -> None:
        chain = self._proven(
            _PING
            + "def view(request):\n"
            + '    for host in request.GET.getlist("h"):\n'
            + "        _ping(host)\n"
        )
        assert chain[0] == _link(6, "request.GET.getlist('h')")


class TestHelperHopHonoursCallerSanitisers:
    """R-pf32: the hop must not prove what the direct path treats as safe. A
    caller that passes its value through a guard or sanitiser the direct sink
    honours leaves the helper's finding reported but unproven. Each guarded
    shape has a control without the guard, which is proven."""

    @staticmethod
    def _at(src: str, rule: str, line: int) -> dict:
        found = [
            f
            for f in _collect_src(src)
            if f["id"] == rule and f["line"] == f"mod.py:{line}"
        ]
        assert len(found) == 1, found
        return found[0]

    def _proven(self, src: str, rule: str, line: int) -> list[dict]:
        f = self._at(src, rule, line)
        assert f.get("reachable") is True, f
        return f["taint_chain"]

    def _unproven(self, src: str, rule: str, line: int) -> None:
        f = self._at(src, rule, line)
        assert f.get("reachable") is not True, f
        assert "taint_chain" not in f, f

    # -- SSRF: membership guard ------------------------------------------------

    _SSRF = (
        "import requests\n"
        "from flask import request\n"
        'ALLOWED = {"a.example", "b.example"}\n'
        "def _fetch(url):\n"
        "    return requests.get(url).text\n"
        "def view():\n"
        '    host = request.args["h"]\n'
    )

    def test_ssrf_membership_guard_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._SSRF
            + "    if host not in ALLOWED:\n"
            + '        return "no", 400\n'
            + "    return _fetch(host)\n",
            "SEC-PY_SSRF",
            5,
        )

    def test_ssrf_without_guard_in_caller_is_proven(self) -> None:
        chain = self._proven(self._SSRF + "    return _fetch(host)\n", "SEC-PY_SSRF", 5)
        assert chain[0] == _link(7, "request.args['h']")

    # -- SSRF: urlparse(...).netloc allowlist guard ---------------------------

    _SSRF_NETLOC = (
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "from flask import request\n"
        'ALLOWED_HOSTS = {"api.example.com"}\n'
        "def _fetch(u):\n"
        "    return requests.get(u).text\n"
        "def view():\n"
        '    url = request.args["u"]\n'
    )

    def test_ssrf_netloc_guard_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._SSRF_NETLOC
            + "    if urlparse(url).netloc not in ALLOWED_HOSTS:\n"
            + '        return "no", 400\n'
            + "    return _fetch(url)\n",
            "SEC-PY_SSRF",
            6,
        )

    def test_ssrf_without_netloc_guard_in_caller_is_proven(self) -> None:
        self._proven(self._SSRF_NETLOC + "    return _fetch(url)\n", "SEC-PY_SSRF", 6)

    def test_ssrf_fixed_host_in_caller_is_not_proven(self) -> None:
        # The direct sink skips a URL whose scheme and host are constant.
        self._unproven(
            "import requests\n"
            "from flask import request\n"
            "def _fetch(url):\n"
            "    return requests.get(url).text\n"
            "def view():\n"
            '    url = "https://api.example.com/users/" + request.args["id"]\n'
            "    return _fetch(url)\n",
            "SEC-PY_SSRF",
            4,
        )

    # -- open redirect: membership guard ---------------------------------------

    _REDIRECT = (
        "from flask import request, redirect\n"
        'SAFE = {"/home", "/profile"}\n'
        "def _go(target):\n"
        "    return redirect(target)\n"
        "def view():\n"
        '    nxt = request.args["next"]\n'
    )

    def test_redirect_membership_guard_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._REDIRECT
            + "    if nxt not in SAFE:\n"
            + '        return redirect("/")\n'
            + "    return _go(nxt)\n",
            "SEC-PY_OPEN_REDIRECT",
            4,
        )

    def test_redirect_without_guard_in_caller_is_proven(self) -> None:
        chain = self._proven(
            self._REDIRECT + "    return _go(nxt)\n", "SEC-PY_OPEN_REDIRECT", 4
        )
        assert chain[0] == _link(6, "request.args['next']")

    # -- path traversal: resolved path checked against its base ---------------

    _PATH = (
        "import os\n"
        "from flask import request, abort\n"
        'BASE = "/srv/reports"\n'
        "def _read(path):\n"
        "    return open(path).read()\n"
        "def view():\n"
        '    f = request.args["f"]\n'
        "    full = os.path.realpath(os.path.join(BASE, f))\n"
    )

    def test_path_containment_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._PATH
            + "    if not full.startswith(BASE + os.sep):\n"
            + "        abort(400)\n"
            + "    return _read(full)\n",
            "SEC-PY_PATH_TRAVERSAL",
            5,
        )

    def test_path_without_containment_in_caller_is_proven(self) -> None:
        chain = self._proven(
            self._PATH + "    return _read(full)\n", "SEC-PY_PATH_TRAVERSAL", 5
        )
        assert chain[0] == _link(7, "request.args['f']")

    # -- XSS: escaped before the call ------------------------------------------

    _XSS = (
        "from flask import request\n"
        "from markupsafe import Markup, escape\n"
        "def _render(s):\n"
        '    return Markup(f"<b>{s}</b>")\n'
        "def view():\n"
    )

    def test_xss_escaped_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._XSS
            + '    name = escape(request.args["n"])\n'
            + "    return _render(name)\n",
            "SEC-PY_XSS_HTML_SINK",
            4,
        )

    def test_xss_escaped_inline_in_caller_is_not_proven(self) -> None:
        self._unproven(
            self._XSS + '    return _render(escape(request.args["n"]))\n',
            "SEC-PY_XSS_HTML_SINK",
            4,
        )

    def test_xss_escaped_fstring_in_caller_is_not_proven(self) -> None:
        # Only the fully-escaped-expression check (B5) accepts an f-string
        # whose every interpolation is escaped.
        self._unproven(
            self._XSS
            + "    label = f\"<i>{escape(request.args['n'])}</i>\"\n"
            + "    return _render(label)\n",
            "SEC-PY_XSS_HTML_SINK",
            4,
        )

    def test_xss_not_escaped_in_caller_is_proven(self) -> None:
        chain = self._proven(
            self._XSS + '    name = request.args["n"]\n' + "    return _render(name)\n",
            "SEC-PY_XSS_HTML_SINK",
            4,
        )
        assert chain[0] == _link(6, "request.args['n']")


# ---------------------------------------------------------------------------
# Task 3.3: a string a Flask view returns is an HTML response body
# ---------------------------------------------------------------------------

_FLASK_APP = (
    "import json\n"
    "from flask import Flask, Response, jsonify, make_response, redirect, render_template, request\n"
    "from markupsafe import Markup, escape\n"
    "app = Flask(__name__)\n"
)


def _flask_view(*lines: str, prelude: str = "") -> str:
    """A Flask app with one view, `search` (def on line 6), whose `q` holds
    request input (line 7) and whose further body is ``lines`` (from line 8)."""
    return (
        prelude
        + _FLASK_APP
        + '@app.route("/search")\n'
        + "def search():\n"
        + '    q = request.args.get("q", "")\n'
        + "".join(f"    {line}\n" for line in lines)
    )


class TestFlaskViewReturnedBody:
    """Task 3.3: Flask hands a view's return value to ``make_response``, which
    sends a ``str`` (or ``bytes``) as ``text/html``. A string a Flask or Quart
    view returns is therefore an HTML response body, judged by the same body
    analysis as ``make_response(...)`` (Task 3.2): the same sanitisers,
    opacity, value types and ``json.dumps`` rule, and a ``(body, status,
    headers)`` tuple is checked on its body and its headers' content type.
    FastAPI and Django Ninja serialise a returned string as JSON, and Django
    must return an ``HttpResponse``, so their returns are not sinks."""

    @staticmethod
    def _xss(src: str) -> list[dict]:
        return [f for f in _collect_src(src) if f["id"] == "SEC-PY_XSS_HTML_SINK"]

    @staticmethod
    def _xss_in(files: dict[str, str]) -> list[dict]:
        with tempfile.TemporaryDirectory() as d:
            for name, content in files.items():
                p = Path(d) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            found = _collect(d)
        return [f for f in found if f["id"] == "SEC-PY_XSS_HTML_SINK"]

    def _proven(self, src: str) -> dict:
        found = self._xss(src)
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is True, f
        assert f["taint_chain"], f
        return f

    # -- the brief's cases ----------------------------------------------------

    def test_flask_route_returning_fstring_is_xss(self) -> None:
        f = self._proven(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            '@app.route("/search")\n'
            "def search():\n"
            "    return f\"<p>{request.args['q']}</p>\"\n"
        )
        assert f["line"] == "mod.py:5"
        assert f["symbol"] == "search"
        assert f["sink"].startswith("return f")
        assert "request.args" in f["taint_chain"][0]["expr"]
        assert f["severity"] == "HIGH"
        assert "CWE-79" in f["references"]
        assert f["route"]["pattern"] == "/search"
        assert f["route"]["framework"] == "flask"

    @pytest.mark.parametrize(
        "src",
        [
            (
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                '@app.get("/search")\n'
                'def search(q: str = ""):\n'
                '    return f"<p>{q}</p>"\n'
            ),
            (
                "from fastapi import FastAPI, Request\n"
                "app = FastAPI()\n"
                '@app.get("/search")\n'
                "def search(request: Request):\n"
                "    return f\"<p>{request.query_params['q']}</p>\"\n"
            ),
            (
                "from ninja import NinjaAPI\n"
                "api = NinjaAPI()\n"
                '@api.get("/search")\n'
                'def search(request, q: str = ""):\n'
                '    return f"<p>{q}</p>"\n'
            ),
        ],
        ids=["fastapi-param", "fastapi-request", "ninja"],
    )
    def test_fastapi_route_returning_str_is_not_xss(self, src: str) -> None:
        # FastAPI and Django Ninja serialise a returned string as JSON.
        assert self._xss(src) == []

    def test_flask_route_returning_dict_is_not_xss(self) -> None:
        # Flask sends a returned dict as JSON (jsonify).
        assert self._xss(_flask_view('return {"q": request.args["q"]}')) == []

    # -- what is reported -----------------------------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            ['return f"<p>{q}</p>"'],
            ['return "<p>" + q + "</p>"'],
            ["return q"],
            ['return "<p>%s</p>" % q'],
            ['return "<p>{}</p>".format(q)'],
            ['html = f"<p>{q}</p>"', "return html"],
            ['html = "<ul>"', 'html += f"<li>{q}</li>"', "return html"],
            ['return q if q else "-"'],
            ['return request.args.get("q", "")'],
            ['return request.args["q"]'],
            # R-pf38: json.dumps leaves `<` as it is, and the default type is HTML.
            ['return json.dumps({"q": q})'],
            # Flask's render_template does not autoescape a .txt template.
            ['return render_template("search.txt", q=q)'],
            # the body of a (body, status[, headers]) tuple
            ['return f"<p>{q}</p>", 200'],
            ['return f"<p>{q}</p>", 404'],
            ['return f"<p>{q}</p>", 200, {"X-Frame-Options": "DENY"}'],
            ['return f"<p>{q}</p>", {"Content-Type": "text/html; charset=utf-8"}'],
        ],
        ids=[
            "fstring", "concat", "name", "percent", "format", "bound", "accumulator",
            "ifexp", "inline-get", "inline-subscript", "json-dumps", "txt-template",
            "tuple-status", "tuple-404", "tuple-headers", "tuple-html-type",
        ],
    )
    def test_a_returned_string_is_xss(self, lines: list[str]) -> None:
        f = self._proven(_flask_view(*lines))
        assert f["sink"].startswith("return "), f["sink"]
        assert f["route"]["framework"] == "flask"
        assert f["symbol"] == "search"

    def test_tuple_sink_names_the_body(self) -> None:
        # The status and headers are not part of the sink, so adding them does
        # not re-identify the finding.
        bare = self._proven(_flask_view('return f"<p>{q}</p>"'))
        tupled = self._proven(_flask_view('return f"<p>{q}</p>", 200'))
        assert bare["sink"] == tupled["sink"] == "return f'<p>{q}</p>'"

    def test_url_variable_returned_is_xss(self) -> None:
        # Flask's own quickstart warns about exactly this view.
        f = self._proven(
            _FLASK_APP + '@app.route("/hello/<name>")\n'
            "def hello(name):\n"
            '    return f"<p>Hello, {name}!</p>"\n'
        )
        assert f["taint_chain"][0] == {"file": "mod.py", "line": 6, "expr": "name"}

    def test_quart_view_returning_a_string_is_xss(self) -> None:
        # Quart sends a returned str as text/html, as Flask does.
        self._proven(
            "from quart import Quart, request\n"
            "app = Quart(__name__)\n"
            '@app.route("/search")\n'
            "async def search():\n"
            '    q = request.args.get("q", "")\n'
            '    return f"<p>{q}</p>"\n'
        )

    def test_flask_get_shortcut_returning_a_string_is_xss(self) -> None:
        f = self._proven(
            _FLASK_APP + '@app.get("/search")\n'
            "def search():\n"
            "    return f\"<p>{request.args['q']}</p>\"\n"
        )
        assert f["route"]["method"] == "GET"

    # -- what is not reported -------------------------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            # Flask sends a dict or list as JSON.
            ["return [q]"],
            ["return {k: v for k, v in request.args.items()}"],
            ["return [v for v in request.args.values()]"],
            ['data = {"q": q}', "return data"],
            ['data = {"q": q}', 'return data or {"q": ""}'],
            ["data = request.get_json()", "return data"],
            ["return request.get_json()"],
            ["return request.json"],
            ["return request.args"],
            ["return request.args.to_dict()"],
            ['return request.form.getlist("tag")'],
            ['return {"q": q}, 201'],
            # renderers, helpers and response objects
            ["return jsonify(q=q)"],
            ["return jsonify(q=q), 400"],
            ['return render_template("search.html", q=q)'],
            ["return redirect(q)"],
            ['return Response(f"<p>{q}</p>", mimetype="application/json")'],
            ['resp = Response(f"<p>{q}</p>", mimetype="text/plain")', "return resp"],
            [
                'resp = make_response(json.dumps({"q": q}))',
                'resp.mimetype = "application/json"',
                "return resp",
            ],
            # escaped values and values that hold no text
            ["return escape(q)"],
            ['return f"<p>{escape(q)}</p>"'],
            ['return "<p>" + escape(q) + "</p>"'],
            ["return str(int(q))"],
            ['return f"<p>{len(q)} characters</p>"'],
            ['return "<p>ok</p>"'],
            # a tuple that declares a non-HTML type, or a status with no body
            ['return f"<p>{q}</p>", 200, {"Content-Type": "text/plain"}'],
            ['return f"<p>{q}</p>", {"Content-Type": "application/json"}'],
            ['return json.dumps({"q": q}), 200, {"Content-Type": "application/json"}'],
            ['return f"<p>{q}</p>", 200, [("Content-Type", "text/plain; charset=utf-8")]'],
            ['return f"<p>{q}</p>", 204'],
            ["return '', 204"],
        ],
        ids=[
            "list", "dictcomp", "listcomp", "bound-dict", "boolop-dicts", "bound-json",
            "get-json", "json", "args", "to-dict", "getlist", "dict-tuple",
            "jsonify", "jsonify-tuple", "html-template", "redirect", "response-json",
            "bound-response", "late-json-type",
            "escape", "escaped-fstring", "escaped-concat", "int", "len", "constant",
            "tuple-text-plain", "tuple-json-no-status", "tuple-json-dumps",
            "tuple-header-pairs", "tuple-204", "empty-204",
        ],
    )
    def test_returned_values_flask_does_not_send_as_html_text_are_not_xss(
        self, lines: list[str]
    ) -> None:
        assert self._xss(_flask_view(*lines)) == []

    def test_allowlisted_value_is_not_xss(self) -> None:
        assert (
            self._xss(
                _flask_view(
                    "if q not in ALLOWED:",
                    '    return "unknown", 400',
                    'return f"<p>{q}</p>"',
                    prelude='ALLOWED = {"en", "fr"}\n',
                )
            )
            == []
        )

    @pytest.mark.parametrize(
        "lines",
        [
            ["count = db.count()", 'return f"<p>{count} results</p>"'],
            ["try:", "    run(q)", "except Exception as e:", "    return str(e), 500"],
            ['return f"<p>{SERVICE_NAME}</p>"'],
        ],
        ids=["server-value", "exception-text", "constant-global"],
    )
    def test_a_string_not_built_from_request_input_is_not_reported(
        self, lines: list[str]
    ) -> None:
        # Every view returns some string. Only a proven request flow is
        # reported: a returned value the engine cannot trace to the request
        # is not a finding, not even a warning.
        src = _flask_view(*lines, prelude='SERVICE_NAME = "Inventory"\n')
        assert self._xss(src) == []

    def test_typed_url_variable_is_not_reported(self) -> None:
        src = (
            _FLASK_APP + '@app.route("/items/<int:item_id>")\n'
            "def item(item_id):\n"
            '    return f"<p>Item {item_id}</p>"\n'
        )
        assert self._xss(src) == []

    # -- only the view's own returns ------------------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            ["def render():", '    return f"<p>{q}</p>"', "return jsonify(html=render())"],
            [
                "class Page:",
                "    def html(self):",
                '        return f"<p>{q}</p>"',
                "return jsonify(html=Page().html())",
            ],
            [
                "async def render():",
                '    return f"<p>{q}</p>"',
                "return jsonify(html=1)",
            ],
        ],
        ids=["nested-def", "nested-class-method", "nested-async-def"],
    )
    def test_a_return_nested_inside_the_view_is_not_the_views(
        self, lines: list[str]
    ) -> None:
        assert self._xss(_flask_view(*lines)) == []

    def test_a_helper_that_is_not_a_route_is_not_reported(self) -> None:
        src = (
            _FLASK_APP + "def page(q):\n"
            '    return f"<p>{q}</p>"\n'
            '@app.route("/search")\n'
            "def search():\n"
            '    return jsonify(html=page(request.args.get("q", "")))\n'
        )
        assert self._xss(src) == []

    def test_a_generator_views_return_is_not_its_body(self) -> None:
        # A view that yields streams what it yields; its `return` value is
        # discarded.
        assert self._xss(_flask_view('yield "<p>"', 'return f"<p>{q}</p>"')) == []

    def test_unknown_framework_route_is_not_reported(self) -> None:
        # A route nothing places in a framework is read like FastAPI.
        src = (
            "from myapp.hooks import registry, request\n"
            '@registry.get("/search")\n'
            "def search():\n"
            "    return f\"<p>{request.args['q']}</p>\"\n"
        )
        assert self._xss(src) == []

    def test_django_view_returning_a_string_is_not_reported(self) -> None:
        # Django must be given an HttpResponse; a str return is an error.
        found = self._xss_in(
            {
                "app/urls.py": "from django.urls import path\n"
                "from app import views\n"
                'urlpatterns = [path("s/", views.search)]\n',
                "app/views.py": "def search(request):\n"
                "    return f\"<p>{request.GET['q']}</p>\"\n",
            }
        )
        assert found == []

    # -- one finding per flow -------------------------------------------------

    @pytest.mark.parametrize(
        "ret, sink",
        [
            ('make_response(f"<p>{q}</p>")', "make_response(f'<p>{q}</p>')"),
            ('make_response(f"<p>{q}</p>"), 200', "make_response(f'<p>{q}</p>')"),
            ('Response(f"<p>{q}</p>")', "Response(f'<p>{q}</p>')"),
            ('Markup(f"<p>{q}</p>")', "Markup(f'<p>{q}</p>')"),
            ('f"<div>{Markup(q)}</div>"', "Markup(q)"),
            ('make_response(Response(f"<p>{q}</p>"))', "Response(f'<p>{q}</p>')"),
        ],
        ids=["make_response", "make_response-tuple", "Response", "Markup", "inner-Markup", "nested"],
    )
    def test_a_returned_sink_is_reported_once(self, ret: str, sink: str) -> None:
        found = self._xss(_flask_view(f"return {ret}"))
        assert [f["sink"] for f in found] == [sink]

    # -- the shared Flask body rules, as make_response sees them ---------------

    @pytest.mark.parametrize(
        "lines",
        [
            ['data = {"q": q}', "return make_response(data)"],
            ["return make_response({k: v for k, v in request.args.items()})"],
            ["return make_response(request.get_json())"],
            ["return make_response(request.args.to_dict(), 200)"],
        ],
        ids=["bound-dict", "dictcomp", "get-json", "to-dict"],
    )
    def test_make_response_of_json_data_is_not_xss(self, lines: list[str]) -> None:
        # make_response is what Flask applies to a returned value, so it sends
        # the same dicts and lists as JSON.
        assert self._xss(_flask_view(*lines)) == []

    # -- a method on a value, as the whole body --------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            # what a real Flask app returns from a method: a response object
            ["return app.send_static_file(q)"],
            ["storage = get_storage()", "return storage.download(q)"],
            ["return make_response(app.send_static_file(q))"],
            ["uploader = get_uploader()", "return make_response(uploader.serve(q), 200)"],
        ],
        ids=["send_static_file", "helper-object", "make_response-method", "make_response-tuple"],
    )
    def test_a_whole_body_method_that_is_not_a_text_method_is_not_claimed(
        self, lines: list[str]
    ) -> None:
        # R-pf41: a whole body that is a helper's result is opaque, and a method
        # on an object is a helper unless it is one of str's own methods.
        assert self._xss(_flask_view(*lines)) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["return q.upper()"],
            ["return q.strip().encode()"],
            ['return ", ".join([q, "x"])'],
            ['return q.replace("a", "b")'],
            ['data = request.get_json()', 'return data.get("name", "")'],
            ['return f"<p>{storage.download(q)}</p>"'],
        ],
        ids=["upper", "chained", "join", "replace", "mapping-get", "method-in-fstring"],
    )
    def test_text_methods_carry_their_text(self, lines: list[str]) -> None:
        self._proven(_flask_view(*lines))

    @pytest.mark.parametrize(
        "lines",
        [
            "    return HttpResponse(exporter.export(name))\n",
            # allauth's SAML metadata view: a method on a constructed object
            (
                "    settings = Saml2Settings(config=name)\n"
                "    metadata = settings.get_sp_metadata()\n"
                '    return HttpResponse(content=metadata, content_type="text/xml")\n'
            ),
        ],
        ids=["method-on-global", "method-on-constructed-object"],
    )
    def test_whole_body_helper_method_is_opaque_for_django_too(self, lines: str) -> None:
        # The rule is the shared body analysis's, not the return sink's.
        assert self._xss(_DJANGO_VIEW + lines) == []


class TestFlaskViewReturnedBodyFixRound1:
    """Task 3.3 fix round 1: the shared body rules keep request-rooted and
    str-method bodies reportable, honour Werkzeug's ``type=`` conversion,
    treat comparisons and bool/int str methods as holding no text, drop the
    body of a redirect with a ``Location`` header, read every binding of a
    body name, and make a FastAPI route whose response class is HTML a sink."""

    _xss = staticmethod(TestFlaskViewReturnedBody._xss)

    def _proven(self, src: str) -> dict:
        found = self._xss(src)
        assert len(found) == 1, found
        assert found[0].get("reachable") is True, found[0]
        return found[0]

    # -- 1. request-rooted receivers and the str split family ------------------

    @pytest.mark.parametrize(
        "src",
        [
            _DJANGO_VIEW + "    return HttpResponse(request.FILES['f'].read())\n",
            _DJANGO_VIEW + "    up = request.FILES.get('f')\n    return HttpResponse(up.read())\n",
            _DJANGO_VIEW + "    return HttpResponse(request.FILES['f'].read().decode())\n",
            _DJANGO_VIEW + "    return HttpResponse(name.split(',')[0])\n",
            _DJANGO_VIEW + "    return HttpResponse(name.split(','))\n",
            _DJANGO_VIEW + "    return HttpResponse(name.partition(':')[2])\n",
            _flask_view("return make_response(request.files['f'].read())"),
            _flask_view("return make_response(request.files['f'].read(), 200)"),
            _flask_view("return make_response(q.splitlines()[0])"),
            _flask_view("return make_response(q.rpartition('/')[2])"),
        ],
        ids=[
            "dj-files-read", "dj-files-get-read", "dj-files-read-decode", "dj-split-index",
            "dj-split-list", "dj-partition", "mr-files-read", "mr-files-read-status",
            "mr-splitlines", "mr-rpartition",
        ],
    )
    def test_request_rooted_and_split_bodies_are_xss(self, src: str) -> None:
        self._proven(src)

    @pytest.mark.parametrize(
        "lines",
        [
            ["return request.files['f'].read()"],
            ["f = request.files.get('f')", "return f.read()"],
            ["return request.files['f'].stream.read()"],
            ["return request.files['f'].read().decode('utf-8')"],
            ["return q.split(',')[0]"],
            ["return q.rsplit('/', 1)[-1]"],
            ["return request.headers.get('X-Forwarded-For', '').split(',')[0]"],
            ["return q.partition(':')[2]"],
        ],
        ids=[
            "files-read", "files-get-read", "files-stream-read", "files-read-decode",
            "split-index", "rsplit-index", "header-split", "partition",
        ],
    )
    def test_request_rooted_and_split_returns_are_xss(self, lines: list[str]) -> None:
        f = self._proven(_flask_view(*lines))
        assert f["sink"].startswith("return ")

    @pytest.mark.parametrize(
        "lines",
        [
            ["return q.split(',')"],
            ["return make_response(q.splitlines())"],
            ["return request.args.get('q', '').rsplit(',')"],
        ],
        ids=["split", "mr-splitlines", "request-rsplit"],
    )
    def test_a_split_list_flask_sends_as_json_is_not_xss(self, lines: list[str]) -> None:
        assert self._xss(_flask_view(*lines)) == []

    # -- 2. Werkzeug's type= conversion ---------------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            ["page = request.args.get('page', 1, type=int)", "return f'<p>Page {page}</p>'"],
            ["return f\"<p>{request.args.get('page', type=int)}</p>\""],
            ["page = request.args.get('page', 1, int)", "return f'<p>Page {page}</p>'"],
            ["n = request.args.get('n', 0.0, type=float)", "return make_response(f'<p>{n}</p>')"],
            ["on = request.form.get('on', False, type=bool)", "return f'<p>{on}</p>', 200"],
            ["u = request.args.get('u', type=uuid.UUID)", "return f'<p>{u}</p>'"],
            [
                "page = request.args.get('page', 1, type=int)",
                "return make_response(f'<p>Page {page}</p>')",
            ],
        ],
        ids=["int-bound", "int-inline", "int-positional", "float-mr", "bool-tuple", "uuid", "int-mr"],
    )
    def test_request_get_with_a_value_type_is_not_xss(self, lines: list[str]) -> None:
        assert self._xss(_flask_view(*lines, prelude="import uuid\n")) == []

    def test_request_get_with_type_str_is_xss(self) -> None:
        self._proven(_flask_view("s = request.args.get('s', '', type=str)", "return f'<p>{s}</p>'"))

    # -- 3. comparisons and bool/int str methods hold no text ------------------

    @pytest.mark.parametrize(
        "ret",
        [
            "f\"<p>{q == 'x'}</p>\"",
            "make_response(f\"<p>{q == 'x'}</p>\")",
            "f'<p>{q.isdigit()}</p>'",
            "f\"<p>{q.count('a')} a</p>\"",
            "f\"<p>{q.startswith('a')}</p>\"",
            "f\"<p>{q.find('a')}</p>\"",
            "f'<p>{not q}</p>'",
            "f\"<p>{'yes' if q.isalnum() else 'no'}</p>\"",
        ],
        ids=["compare", "compare-mr", "isdigit", "count", "startswith", "find", "not", "ifexp-test"],
    )
    def test_values_that_hold_no_text_are_not_xss(self, ret: str) -> None:
        assert self._xss(_flask_view(f"return {ret}")) == []

    # -- 4. a redirect with a Location header renders no body ------------------

    @pytest.mark.parametrize(
        "src",
        [
            _flask_view("return f'Redirecting to {q}', 302, {'Location': '/x'}"),
            _flask_view("return f'Redirecting to {q}', 301, [('location', '/x')]"),
            _flask_view("return make_response(f'Redirecting to {q}', 303, {'Location': '/x'})"),
            _DJANGO_VIEW
            + "    return HttpResponse(f'Moved: {name}', status=302, headers={'Location': '/x'})\n",
        ],
        ids=["return-302", "return-301-pairs", "mr-303", "django-302"],
    )
    def test_redirect_with_location_is_not_xss(self, src: str) -> None:
        assert self._xss(src) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["return f'Redirecting to {q}', 302"],
            ["return f'<p>{q}</p>', 200, {'Location': '/x'}"],
        ],
        ids=["302-without-location", "location-without-redirect-status"],
    )
    def test_redirect_needs_both_status_and_location(self, lines: list[str]) -> None:
        self._proven(_flask_view(*lines))

    # -- 5. every binding of a body name counts ---------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            ["body = f'<p>{q}</p>'", "if request.args.get('fmt') == 'json':", "    body = {'q': q}", "return make_response(body)"],
            ["body = {'q': q}", "if request.args.get('fmt') == 'html':", "    body = f'<p>{q}</p>'", "return make_response(body)"],
            ["body = f'<p>{q}</p>'", "if request.args.get('fmt') == 'json':", "    body = {'q': q}", "return body"],
            ["body = {'q': q}", "if request.args.get('fmt') == 'html':", "    body = f'<p>{q}</p>'", "return body"],
        ],
        ids=["mr-text-first", "mr-dict-first", "return-text-first", "return-dict-first"],
    )
    def test_a_body_name_with_any_text_binding_is_text(self, lines: list[str]) -> None:
        self._proven(_flask_view(*lines))

    def test_a_body_name_bound_only_to_json_data_is_not_xss(self) -> None:
        src = _flask_view(
            "body = {'q': q}", "if request.args.get('many'):", "    body = [q]", "return body"
        )
        assert self._xss(src) == []

    # -- 6. a FastAPI route whose response class is HTML ------------------------

    _FASTAPI = (
        "from fastapi import APIRouter, FastAPI\n"
        "from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse\n"
    )

    @pytest.mark.parametrize(
        "head, deco",
        [
            ("app = FastAPI()\n", "@app.get('/s', response_class=HTMLResponse)"),
            ("router = APIRouter(default_response_class=HTMLResponse)\n", "@router.get('/s')"),
            ("app = FastAPI(default_response_class=HTMLResponse)\n", "@app.get('/s')"),
        ],
        ids=["decorator", "router-default", "app-default"],
    )
    def test_fastapi_html_response_class_return_is_xss(self, head: str, deco: str) -> None:
        f = self._proven(
            self._FASTAPI + head + deco + "\ndef s(q: str = ''):\n    return f'<p>{q}</p>'\n"
        )
        assert f["sink"] == "return f'<p>{q}</p>'"
        assert f["route"]["framework"] == "fastapi"

    @pytest.mark.parametrize(
        "head, deco, ret",
        [
            ("app = FastAPI()\n", "@app.get('/s', response_class=PlainTextResponse)", "f'<p>{q}</p>'"),
            (
                "app = FastAPI(default_response_class=HTMLResponse)\n",
                "@app.get('/s', response_class=JSONResponse)",
                "f'<p>{q}</p>'",
            ),
            ("app = FastAPI()\n", "@app.get('/s', response_class=HTMLResponse)", "JSONResponse({'q': q})"),
            ("app = FastAPI()\n", "@app.get('/s', response_class=HTMLResponse)", "{'q': q}"),
            ("app = FastAPI()\n", "@app.get('/s', response_class=HTMLResponse)", "f'<p>{SITE}</p>'"),
        ],
        ids=["plain-text", "decorator-overrides-default", "response-object", "dict", "unproven"],
    )
    def test_fastapi_non_html_or_unproven_return_is_not_xss(
        self, head: str, deco: str, ret: str
    ) -> None:
        src = self._FASTAPI + "SITE = 'x'\n" + head + deco + f"\ndef s(q: str = ''):\n    return {ret}\n"
        assert self._xss(src) == []

    def test_fastapi_html_route_returning_a_constructor_is_reported_once(self) -> None:
        found = self._xss(
            self._FASTAPI
            + "app = FastAPI()\n@app.get('/s', response_class=HTMLResponse)\n"
            + "def s(q: str = ''):\n    return HTMLResponse(f'<p>{q}</p>')\n"
        )
        assert [f["sink"] for f in found] == ["HTMLResponse(f'<p>{q}</p>')"]


class TestFlaskViewReturnedBodyFixRound2:
    """Task 3.3 fix round 2: ``find``/``rfind``/``index``/``rindex``/``count``
    hold no text only on a value known to be a ``str`` (an XML element's or a
    BeautifulSoup tree's ``find`` returns markup), and a redirect status must
    be an int or an imported status constant."""

    _xss = staticmethod(TestFlaskViewReturnedBody._xss)
    _proven = TestFlaskViewReturnedBodyFixRound1._proven

    @pytest.mark.parametrize(
        "src",
        [
            (
                "from bs4 import BeautifulSoup\n"
                "from django.http import HttpResponse\n"
                "def v(request):\n"
                "    soup = BeautifulSoup(request.body, 'html.parser')\n"
                "    return HttpResponse(f\"<div>{soup.find('div')}</div>\")\n"
            ),
            (
                "import xml.etree.ElementTree as ET\n"
                "from django.http import HttpResponse\n"
                "def v(request):\n"
                "    root = ET.fromstring(request.body)\n"
                "    return HttpResponse(f\"<p>{root.find('name').text}</p>\")\n"
            ),
            _flask_view("doc = parse(request.data)", "return f\"<p>{doc.index('a')}</p>\""),
            _flask_view("items = request.args.getlist('t')", "return f'<p>{items.count(q)}</p>'"),
        ],
        ids=["bs4-find", "etree-find", "unknown-index", "list-count"],
    )
    def test_index_methods_on_values_not_known_to_be_str_carry_text(self, src: str) -> None:
        self._proven(src)

    @pytest.mark.parametrize(
        "src",
        [
            _flask_view("q2 = request.args['q']", "return f\"<p>{q2.find('x')}</p>\""),
            _flask_view("return f\"<p>{q.count('a')}</p>\""),
            _flask_view("return f\"<p>{request.form.get('n', '').rfind('/')}</p>\""),
            _flask_view("return f\"<p>{q.strip().index(':')}</p>\""),
            _flask_view("return f\"<p>{str(request.data).count('a')}</p>\""),
            _flask_view("return f\"<p>{'abc'.find(q)}</p>\""),
            _DJANGO_VIEW + "    return HttpResponse(f\"<p>{request.GET['n'].count('a')}</p>\")\n",
            (
                _FLASK_APP + '@app.route("/u/<name>")\n'
                "def u(name):\n"
                "    return f\"<p>{name.find('x')}</p>\"\n"
            ),
            (
                "from fastapi import FastAPI\n"
                "from fastapi.responses import HTMLResponse\n"
                "app = FastAPI()\n"
                "@app.get('/s', response_class=HTMLResponse)\n"
                "def s(q: str = ''):\n"
                "    return f\"<p>{q.find('x')}</p>\"\n"
            ),
        ],
        ids=[
            "args-subscript", "args-get", "form-get", "str-method-result", "str-call",
            "str-literal", "django-GET", "flask-url-variable", "fastapi-str-param",
        ],
    )
    def test_index_methods_on_known_strings_hold_no_text(self, src: str) -> None:
        assert self._xss(src) == []

    def test_bool_str_tests_hold_no_text_on_any_receiver(self) -> None:
        src = _flask_view("doc = parse(request.data)", "return f\"<p>{doc.startswith('a')}</p>\"")
        assert self._xss(src) == []

    # -- a redirect status must be an int or an imported status constant -------

    @pytest.mark.parametrize(
        "lines",
        [
            ["FOUND = 200", "return f'<p>{q}</p>', FOUND, {'Location': '/x'}"],
            ["SEE_OTHER = status_for(q)", "return f'<p>{q}</p>', SEE_OTHER, {'Location': '/x'}"],
        ],
        ids=["local-FOUND", "local-SEE_OTHER"],
    )
    def test_a_local_name_is_not_a_redirect_status(self, lines: list[str]) -> None:
        self._proven(_flask_view(*lines))

    @pytest.mark.parametrize(
        "prelude, status",
        [
            ("from http import HTTPStatus\n", "HTTPStatus.FOUND"),
            ("import http\n", "http.HTTPStatus.SEE_OTHER"),
            ("from starlette import status\n", "status.HTTP_302_FOUND"),
            ("from starlette.status import HTTP_307_TEMPORARY_REDIRECT\n", "HTTP_307_TEMPORARY_REDIRECT"),
        ],
        ids=["HTTPStatus", "http.HTTPStatus", "starlette-status", "imported-name"],
    )
    def test_an_imported_redirect_status_with_location_is_not_xss(
        self, prelude: str, status: str
    ) -> None:
        src = _flask_view(f"return f'<p>{{q}}</p>', {status}, {{'Location': '/x'}}", prelude=prelude)
        assert self._xss(src) == []


# ---------------------------------------------------------------------------
# Task 3.4: server-side template injection (python.ast/PY_SSTI)
# ---------------------------------------------------------------------------

_SSTI_TITLE = "Template built from request input (server-side template injection)"
_SSTI_HEDGED_TITLE = (
    "Template built from a non-constant value (possible server-side template injection)"
)


def _ssti_view(*lines: str, prelude: str = "") -> str:
    """A function, `preview` (def on line 2 after ``prelude``), whose `src`
    holds request input and whose further body is ``lines``."""
    return (
        prelude
        + "from flask import abort, request\n"
        + "def preview():\n"
        + '    src = request.args.get("template", "")\n'
        + "".join(f"    {line}\n" for line in lines)
    )


class TestServerSideTemplateInjection:
    """Task 3.4: a template compiled from request input runs the attacker's
    template code on the server (CWE-1336), reported as the new rule
    python.ast/PY_SSTI. The sinks are `jinja2.Template(src)`,
    `<Environment>.from_string(src)` (a sandboxed environment too),
    `django.template.Template(src)`, `django.template.engines[...]
    .from_string(src)` and `mako.template.Template(src)` /
    `Template(text=src)`, each resolved through the file's imports. Loading a
    template by name, or from a file, is not one; nor is a constant template or
    one picked from constant templates. Flask's `render_template_string`
    keeps its existing rule, PY_XSS_HTML_SINK."""

    @staticmethod
    def _ssti(src: str) -> list[dict]:
        return [f for f in _collect_src(src) if f["id"] == "SEC-PY_SSTI"]

    def _proven(self, src: str, source: str = "request") -> dict:
        found = self._ssti(src)
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is True, f
        assert any(source in link["expr"] for link in f["taint_chain"]), f["taint_chain"]
        return f

    def _clean(self, src: str) -> None:
        found = self._ssti(src)
        assert found == [], found

    # -- the brief's cases ----------------------------------------------------

    def test_jinja2_template_from_request_is_ssti(self) -> None:
        f = self._proven(
            _ssti_view("return jinja2.Template(src).render()", prelude="import jinja2\n"),
            "request.args",
        )
        assert f["rule_id"] == "python.ast/PY_SSTI"
        assert f["title"] == _SSTI_TITLE
        assert f["severity"] == "CRITICAL"
        assert f["confidence"] == "HIGH"
        assert f["category"] == "injection"
        assert f["references"] == ["CWE-1336"]
        assert f["line"] == "mod.py:5"
        assert f["sink"] == "jinja2.Template(src)"
        assert f["taint_chain"][-1] == {"file": "mod.py", "line": 5, "expr": "jinja2.Template(src)"}

    def test_environment_from_string_is_ssti(self) -> None:
        f = self._proven(
            _ssti_view(
                "return env.from_string(src).render()",
                prelude="from jinja2 import Environment, FileSystemLoader\n"
                'env = Environment(loader=FileSystemLoader("templates"))\n',
            ),
            "request.args",
        )
        assert f["sink"] == "jinja2.Environment.from_string(src)"

    def test_django_template_from_request_is_ssti(self) -> None:
        f = self._proven(
            "from django.http import JsonResponse\n"
            "from django.template import Context, Template\n"
            "def preview(request):\n"
            '    src = request.GET.get("template", "")\n'
            '    return JsonResponse({"p": Template(src).render(Context({}))})\n',
            "request.GET",
        )
        assert f["sink"] == "django.template.Template(src)"

    @pytest.mark.parametrize(
        "prelude, lines",
        [
            (
                'NOTIFICATION = "Hi {{ name }}, your order has shipped."\n',
                ['name = request.args.get("name", "")',
                 "return jinja2.Template(NOTIFICATION).render(name=name)"],
            ),
            ("", ['return jinja2.Template("Hi {{ name }}").render(name=src)']),
            ('HEAD = "<h1>{{ title }}</h1>"\n', ['return jinja2.Template(HEAD + "<p>{{ body }}</p>").render()']),
            (
                'SHORT = "Hi"\nLONG = "Hello there, {{ name }}"\n',
                ["return jinja2.Template(SHORT if src else LONG).render(name=src)"],
            ),
            (
                'BANNER = "{{ service }} is down"\n',
                ['tpl = BANNER', "return jinja2.Environment().from_string(tpl).render(service=src)"],
            ),
        ],
        ids=["module-constant", "literal", "constant-concat", "constant-choice", "bound-constant"],
    )
    def test_constant_template_is_not_ssti(self, prelude: str, lines: list[str]) -> None:
        self._clean(_ssti_view(*lines, prelude="import jinja2\n" + prelude))

    def test_render_template_string_keeps_existing_rule(self) -> None:
        found = _collect_src(
            "from flask import render_template_string, request\n"
            "def preview():\n"
            '    src = request.args.get("template", "")\n'
            "    return render_template_string(src)\n"
        )
        ids = [f["id"] for f in found]
        assert ids.count("SEC-PY_XSS_HTML_SINK") == 1, ids
        assert "SEC-PY_SSTI" not in ids, ids

    # -- the sink set, resolved through imports --------------------------------

    @pytest.mark.parametrize(
        "imports, call, sink",
        [
            ("from jinja2 import Template", "Template(src)", "jinja2.Template(src)"),
            ("from jinja2 import Template as T", "T(src)", "jinja2.Template(src)"),
            ("import jinja2 as j2", "j2.Template(src)", "jinja2.Template(src)"),
            ("from jinja2 import Template", "Template(source=src)", "jinja2.Template(src)"),
            (
                "from jinja2 import Environment",
                "Environment(autoescape=True).from_string(src)",
                "jinja2.Environment.from_string(src)",
            ),
            (
                "import jinja2",
                "jinja2.Environment().from_string(source=src)",
                "jinja2.Environment.from_string(src)",
            ),
            (
                "from jinja2.sandbox import SandboxedEnvironment",
                "SandboxedEnvironment().from_string(src)",
                "jinja2.sandbox.SandboxedEnvironment.from_string(src)",
            ),
            (
                "from jinja2 import sandbox",
                "sandbox.ImmutableSandboxedEnvironment().from_string(src)",
                "jinja2.sandbox.ImmutableSandboxedEnvironment.from_string(src)",
            ),
            (
                "from jinja2.nativetypes import NativeEnvironment",
                "NativeEnvironment().from_string(src)",
                "jinja2.nativetypes.NativeEnvironment.from_string(src)",
            ),
            ("from jinja2.environment import Template", "Template(src)", "jinja2.Template(src)"),
            (
                "from jinja2.nativetypes import NativeTemplate",
                "NativeTemplate(src)",
                "jinja2.nativetypes.NativeTemplate(src)",
            ),
            ("import django.template", "django.template.Template(src)", "django.template.Template(src)"),
            (
                "from django.template import Template",
                "Template(template_string=src)",
                "django.template.Template(src)",
            ),
            (
                "from django.template import engines",
                'engines["django"].from_string(src)',
                "django.template.engines.from_string(src)",
            ),
            ("from mako.template import Template", "Template(src)", "mako.template.Template(src)"),
            ("from mako.template import Template", "Template(text=src)", "mako.template.Template(src)"),
            ("import mako.template", "mako.template.Template(src)", "mako.template.Template(src)"),
        ],
        ids=[
            "jinja2-Template", "jinja2-Template-as", "jinja2-module-alias", "jinja2-source-kw",
            "Environment-inline", "jinja2.Environment-source-kw", "SandboxedEnvironment",
            "ImmutableSandboxedEnvironment", "NativeEnvironment", "jinja2.environment.Template",
            "NativeTemplate",
            "django.template.Template", "django-template_string-kw", "django-engines",
            "mako-Template", "mako-text-kw", "mako-dotted-import",
        ],
    )
    def test_template_built_from_request_is_ssti(self, imports: str, call: str, sink: str) -> None:
        f = self._proven(_ssti_view(f"return {call}", prelude=imports + "\n"), "request.args")
        assert f["sink"] == sink

    @pytest.mark.parametrize(
        "prelude, lines, sink",
        [
            (
                "from jinja2 import Environment\n",
                ["env = Environment()", "return env.from_string(src).render()"],
                "jinja2.Environment.from_string(src)",
            ),
            (
                "from jinja2.sandbox import SandboxedEnvironment\nsandbox = SandboxedEnvironment()\n",
                ["return sandbox.from_string(src).render()"],
                "jinja2.sandbox.SandboxedEnvironment.from_string(src)",
            ),
            (
                "from django.template import engines\n",
                ['engine = engines["jinja2"]', "return engine.from_string(src).render()"],
                "django.template.engines.from_string(src)",
            ),
        ],
        ids=["local-Environment", "module-SandboxedEnvironment", "bound-engines"],
    )
    def test_from_string_on_a_bound_environment_is_ssti(
        self, prelude: str, lines: list[str], sink: str
    ) -> None:
        f = self._proven(_ssti_view(*lines, prelude=prelude), "request.args")
        assert f["sink"] == sink
        if "Sandboxed" in sink:
            assert "SandboxedEnvironment" in f["fix"]

    @pytest.mark.parametrize(
        "prelude, line",
        [
            (
                "class Template:\n    def __init__(self, text):\n        self.text = text\n",
                "return Template(src)",
            ),
            ("from .templating import Template\n", "return Template(src)"),
            ("from string import Template\n", "return Template(src).substitute()"),
            ("from .cache import loader\n", "return loader.from_string(src)"),
            ("import jinja2\n", "return jinja2.Environment.from_string(src)"),
        ],
        ids=["own-class", "own-module", "string.Template", "unknown-receiver", "unbound-method"],
    )
    def test_a_template_class_that_is_not_a_template_engine_is_not_ssti(
        self, prelude: str, line: str
    ) -> None:
        self._clean(_ssti_view(line, prelude=prelude))

    @pytest.mark.parametrize(
        "prelude, line",
        [
            (
                (
                    "from jinja2 import Environment, FileSystemLoader\n"
                    'env = Environment(loader=FileSystemLoader("templates"))\n'
                ),
                "return env.get_template(src).render()",
            ),
            ("from django.template import loader\n", "return loader.get_template(src).render({})"),
            ("from flask import render_template\n", "return render_template(src)"),
            (
                "from mako.lookup import TemplateLookup\n",
                'return TemplateLookup(directories=["t"]).get_template(src).render()',
            ),
            ("from mako.template import Template\n", "return Template(filename=src).render()"),
        ],
        ids=["jinja2-get_template", "django-loader", "flask-render_template", "mako-lookup", "mako-filename"],
    )
    def test_loading_a_template_by_name_is_not_ssti(self, prelude: str, line: str) -> None:
        self._clean(_ssti_view(line, prelude=prelude))

    # -- sanitisers -----------------------------------------------------------

    @pytest.mark.parametrize(
        "lines",
        [
            ['tpl = TEMPLATES[src]', "return Template(tpl).render()"],
            ["return Template(TEMPLATES.get(src, DEFAULT)).render()"],
            ["if src not in ALLOWED:", "    abort(404)", "return Template(src).render()"],
        ],
        ids=["dict-lookup", "dict-get-default", "membership-guard"],
    )
    def test_template_picked_among_constant_templates_is_not_ssti(self, lines: list[str]) -> None:
        self._clean(
            _ssti_view(
                *lines,
                prelude="from jinja2 import Template\n"
                'TEMPLATES = {"welcome": "Hi {{ n }}", "bye": "Bye {{ n }}"}\n'
                'DEFAULT = "Hello"\n'
                'ALLOWED = {"Hi {{ n }}", "Bye {{ n }}"}\n',
            )
        )

    @pytest.mark.parametrize(
        "lines",
        [
            ["return Template(html.escape(src)).render()"],
            ["return Template(LAYOUTS[src]).render()"],
            ["t = Template(src).render()", "if src not in ALLOWED:", "    abort(404)", "return t"],
        ],
        ids=["html-escape", "lookup-of-non-constant-templates", "guard-after-sink"],
    )
    def test_what_does_not_pick_a_constant_template_is_ssti(self, lines: list[str]) -> None:
        self._proven(
            _ssti_view(
                *lines,
                prelude="import html\nfrom jinja2 import Template\n"
                'ALLOWED = {"Hi {{ n }}"}\n'
                "LAYOUTS = {'a': load_layout('a')}\n",
            ),
            "request.args",
        )

    @pytest.mark.parametrize(
        "prelude, body",
        [
            (
                "from pathlib import Path\n",
                [
                    "def render_email_template(*, template_name, context):",
                    '    template_str = (Path(__file__).parent / "email-templates" / template_name).read_text()',
                    "    template: Template = Template(template_str)",
                    "    return template.render(context)",
                    "def send(request):",
                    '    return render_email_template(template_name="reset.html", context={})',
                ],
            ),
            (
                "",
                [
                    "def render(path, ctx):",
                    "    with open(path) as fh:",
                    "        return Template(fh.read()).render(ctx)",
                ],
            ),
            (
                "import pkgutil\n",
                ['def render(ctx):', '    return Template(pkgutil.get_data("app", "t.html").decode()).render(ctx)'],
            ),
            (
                "import importlib.resources\n",
                ["def render(ctx):", '    return Template(importlib.resources.read_text("app", "t.html")).render(ctx)'],
            ),
            (
                "from importlib.resources import files\n",
                ["def render(ctx):", '    return Template(files("app").joinpath("t.html").read_text()).render(ctx)'],
            ),
            (
                "import codecs, io\n",
                [
                    "def render(path, ctx):",
                    "    a = io.open(path).read()",
                    '    b = codecs.open(path, encoding="utf-8").read()',
                    "    return Template(a).render(ctx) + Template(b).render(ctx)",
                ],
            ),
        ],
        ids=[
            "fastapi-template-email", "open-read", "package-data", "importlib-resources",
            "importlib-files", "io-codecs-open",
        ],
    )
    def test_template_read_from_a_file_is_not_ssti(self, prelude: str, body: list[str]) -> None:
        self._clean("from jinja2 import Template\n" + prelude + "\n".join(body) + "\n")

    def test_uploaded_template_is_ssti(self) -> None:
        self._proven(
            _ssti_view(
                'upload = request.files["template"]',
                "return Template(upload.read().decode()).render()",
                prelude="from jinja2 import Template\n",
            ),
            "request.files",
        )

    # -- proof ----------------------------------------------------------------

    def test_unproven_template_source_is_reported_at_high(self) -> None:
        found = self._ssti(
            "from jinja2 import Template\n"
            "def build(src):\n"
            "    return Template(src)\n"
        )
        assert len(found) == 1, found
        f = found[0]
        assert f["severity"] == "HIGH"
        assert f["confidence"] == "MEDIUM"
        assert f["title"] == _SSTI_HEDGED_TITLE
        assert f.get("reachable") is None, f
        assert "taint_chain" not in f, f
        assert f["sink"] == "jinja2.Template(src)"

    def test_same_file_helper_is_proven_through_the_caller(self) -> None:
        # The parity corpus's `indirect` shape.
        f = self._proven(
            "from django.http import JsonResponse\n"
            "from django.template import Context, Template\n"
            "def _render_preview(template_src, name):\n"
            '    return Template(template_src).render(Context({"name": name}))\n'
            "def preview_notification(request):\n"
            '    template_src = request.GET.get("template", "")\n'
            '    name = request.GET.get("name", "")\n'
            '    return JsonResponse({"preview": _render_preview(template_src, name)})\n',
            "request.GET",
        )
        assert f["line"] == "mod.py:4"

    def test_fastapi_route_parameter_is_proven(self) -> None:
        # The parity corpus's FastAPI `direct` shape: an aliased query parameter.
        f = self._proven(
            "from typing import Annotated\n"
            "from fastapi import APIRouter, Query\n"
            "from jinja2 import Template\n"
            "router = APIRouter()\n"
            '@router.get("/ssti/direct")\n'
            'def preview(template_src: Annotated[str, Query(alias="template")] = "", name: str = ""):\n'
            "    rendered = Template(template_src).render(name=name)\n"
            '    return {"preview": rendered}\n',
            "template_src",
        )
        assert f["taint_chain"][0] == {"file": "mod.py", "line": 6, "expr": "template_src"}

    # -- one finding per flow with the HTML response sink (Task 3.2) ----------

    @pytest.mark.parametrize(
        "lines",
        [
            ["return HTMLResponse(Template(template).render())"],
            ["t = Template(template)", "return HTMLResponse(t.render())"],
            ["page = Template(template).render()", "return HTMLResponse(content=page)"],
        ],
        ids=["inline", "bound-template", "bound-page"],
    )
    def test_template_source_reaching_an_html_response_is_ssti_only(
        self, lines: list[str]
    ) -> None:
        found = _collect_src(
            "from fastapi import FastAPI\n"
            "from fastapi.responses import HTMLResponse\n"
            "from jinja2 import Template\n"
            "app = FastAPI()\n"
            '@app.get("/preview")\n'
            'def preview(template: str = ""):\n'
            + "".join(f"    {line}\n" for line in lines)
        )
        assert [f["id"] for f in found] == ["SEC-PY_SSTI"], found
        assert found[0]["reachable"] is True

    def test_flask_view_returning_a_template_built_from_request_is_ssti_only(self) -> None:
        found = _collect_src(
            _FLASK_APP
            + "from jinja2 import Template\n"
            + '@app.route("/preview")\n'
            + "def preview():\n"
            + '    src = request.args.get("template", "")\n'
            + "    return Template(src).render()\n"
        )
        assert [f["id"] for f in found] == ["SEC-PY_SSTI"], found

    def test_render_args_tainted_separately_keep_the_xss_finding(self) -> None:
        found = _collect_src(
            "from fastapi import FastAPI\n"
            "from fastapi.responses import HTMLResponse\n"
            "from jinja2 import Template\n"
            "app = FastAPI()\n"
            '@app.get("/preview")\n'
            'def preview(template: str = "", name: str = ""):\n'
            "    return HTMLResponse(Template(template).render(name=name))\n"
        )
        by_id = {f["id"]: f for f in found}
        assert sorted(by_id) == ["SEC-PY_SSTI", "SEC-PY_XSS_HTML_SINK"], found
        assert by_id["SEC-PY_SSTI"]["taint_chain"][0]["expr"] == "template"
        xss = by_id["SEC-PY_XSS_HTML_SINK"]
        assert xss["reachable"] is True
        assert xss["taint_chain"][0] == {"file": "mod.py", "line": 6, "expr": "name"}
        assert xss["sink"] == "HTMLResponse(Template(template).render(name=name))"

    def test_xss_is_not_proven_through_the_template_source(self) -> None:
        # The template source is request input and the render argument is not
        # proven: the page is reported (its argument may carry text) but only
        # PY_SSTI is proven.
        found = _collect_src(
            "from django.http import HttpResponse\n"
            "from jinja2 import Template\n"
            "def page(src, name):\n"
            "    return HttpResponse(Template(src).render(name=name))\n"
            "def view(request):\n"
            '    return page(request.GET["t"], load_name())\n'
        )
        by_id = {f["id"]: f for f in found}
        assert sorted(by_id) == ["SEC-PY_SSTI", "SEC-PY_XSS_HTML_SINK"], found
        assert by_id["SEC-PY_SSTI"]["reachable"] is True
        assert by_id["SEC-PY_XSS_HTML_SINK"].get("reachable") is None
        assert "taint_chain" not in by_id["SEC-PY_XSS_HTML_SINK"]

    # -- import resolution ----------------------------------------------------

    @pytest.mark.parametrize(
        "imports, ret",
        [
            (
                "import django.template.loader",
                'HttpResponse(django.template.loader.get_template("s.html").render({"q": q}))',
            ),
            (
                "import django.template",
                (
                    'HttpResponse(django.template.Template("<p>{{ q }}</p>")'
                    '.render(django.template.Context({"q": q})))'
                ),
            ),
            (
                "import django.template",
                (
                    'HttpResponse(django.template.engines["django"].from_string("<p>{{ q }}</p>")'
                    '.render({"q": q}))'
                ),
            ),
            (
                "import http.client",
                'HttpResponse(q, status=http.client.FOUND, headers={"Location": "/"})',
            ),
            (
                "import starlette.status\nfrom starlette.responses import HTMLResponse",
                'HTMLResponse(q, status_code=starlette.status.HTTP_302_FOUND, headers={"location": "/"})',
            ),
        ],
        ids=[
            "django.template.loader", "django.template.Template", "django.template.engines",
            "http.client-redirect", "starlette.status-redirect",
        ],
    )
    def test_plain_dotted_import_binds_the_top_package(self, imports: str, ret: str) -> None:
        # `import a.b` binds `a`, so `a.b.c` is `a.b.c`: a Django template
        # object's `.render` autoescapes (R-pf40), and a redirect status
        # named through the module drops the body. None of these is XSS.
        found = _collect_src(
            imports + "\n"
            "from django.http import HttpResponse\n"
            "def v(request):\n"
            '    q = request.GET.get("q", "")\n'
            f"    return {ret}\n"
        )
        assert found == [], found

    # -- fix round 1 (R-pf45 and the review's probes) -------------------------

    def test_proven_and_unproven_titles(self) -> None:
        proven = self._proven(_ssti_view("return Template(src)", prelude="from jinja2 import Template\n"))
        assert proven["title"] == _SSTI_TITLE
        unproven = self._ssti("from jinja2 import Template\ndef build(src):\n    return Template(src)\n")
        assert [f["title"] for f in unproven] == [_SSTI_HEDGED_TITLE]

    @pytest.mark.parametrize(
        "prelude, lines",
        [
            ("from urllib.request import urlopen\n", ["return Template(urlopen(src).read().decode()).render()"]),
            (
                "import urllib.request\n",
                ["tpl = urllib.request.urlopen(src).read().decode()", "return Template(tpl).render()"],
            ),
            ("import requests\n", ["return Template(requests.get(src).raw.read().decode()).render()"]),
            (
                "import zipfile\n",
                [
                    'z = zipfile.ZipFile(request.files["theme"])',
                    'return Template(z.read("index.html").decode()).render()',
                ],
            ),
            ("import io\n", ["return Template(io.BytesIO(request.get_data()).read().decode()).render()"]),
            (
                "import io\n",
                ['buf = io.StringIO(request.get_json()["tpl"])', "return Template(buf.read()).render()"],
            ),
            ("import io\n", ["return Template(io.StringIO(src).read()).render()"]),
            ("import pkgutil\n", ['return Template(pkgutil.get_data("pkg", src).decode()).render()']),
            (
                "import importlib.resources\n",
                ['return Template(importlib.resources.read_text("pkg", src)).render()'],
            ),
        ],
        ids=[
            "urlopen", "urllib.request.urlopen-bound", "requests-raw", "zipfile-upload",
            "BytesIO-body", "StringIO-json", "StringIO-arg", "pkgutil-request-name",
            "importlib-read_text-request-name",
        ],
    )
    def test_a_read_that_is_not_a_file_system_read_is_ssti(
        self, prelude: str, lines: list[str]
    ) -> None:
        self._proven(_ssti_view(*lines, prelude="from jinja2 import Template\n" + prelude))

    @pytest.mark.parametrize(
        "prelude, line",
        [
            ("from pathlib import Path\n", "return Template((Path('tpl') / src).read_text()).render()"),
            ("from pathlib import Path\n", "return Template(Path('tpl').joinpath(src).read_text()).render()"),
            (
                "import importlib.resources\n",
                "return Template(importlib.resources.files('app').joinpath(src).read_text()).render()",
            ),
            (
                "import importlib.resources\n",
                "return Template((importlib.resources.files('app') / src).read_text()).render()",
            ),
        ],
        ids=["Path-div", "Path-joinpath", "files-joinpath", "files-div"],
    )
    def test_a_request_segment_joined_onto_a_path_is_ssti(self, prelude: str, line: str) -> None:
        # R-pf48: PY_PATH_TRAVERSAL does not model pathlib joins, so a derived
        # path is trusted only when no segment it adds is proven request input.
        self._proven(_ssti_view(line, prelude="from jinja2 import Template\n" + prelude))

    def test_email_renderer_called_with_a_request_name_is_ssti(self) -> None:
        # The full-stack-fastapi-template shape, called with request input:
        # the parameter segment is proven through the caller.
        f = self._proven(
            "from pathlib import Path\n"
            "from flask import request\n"
            "from jinja2 import Template\n"
            "def render_email_template(*, template_name, context):\n"
            '    template_str = (Path(__file__).parent / "email-templates" / template_name).read_text()\n'
            "    return Template(template_str).render(context)\n"
            "def send():\n"
            '    return render_email_template(template_name=request.args["t"], context={})\n',
            "request.args",
        )
        assert f["line"] == "mod.py:6"

    def test_fastapi_string_wrapped_in_stringio_is_ssti(self) -> None:
        self._proven(
            "import io\n"
            "from fastapi import FastAPI\n"
            "from jinja2 import Template\n"
            "app = FastAPI()\n"
            '@app.get("/r")\n'
            "def r(tpl: str):\n"
            "    return Template(io.StringIO(tpl).read()).render()\n",
            "tpl",
        )

    @pytest.mark.parametrize(
        "prelude, lines, sink",
        [
            ("", ['return Template(open(request.args["t"]).read()).render()'], "open(request.args['t'])"),
            ("", ['p = request.args["t"]', "return Template(open(p).read()).render()"], "open(p)"),
            (
                "",
                ['p = request.args["t"]', "with open(p) as fh:", "    src = fh.read()", "return Template(src).render()"],
                "open(p)",
            ),
            (
                "from pathlib import Path\n",
                ['p = request.args["t"]', "return Template(Path(p).read_text()).render()"],
                "Path(p)",
            ),
            (
                "from pathlib import Path\n",
                ['return Template(Path(request.args["t"]).read_text()).render()'],
                "Path(request.args['t'])",
            ),
        ],
        ids=["open-inline", "open-bound", "with-open", "Path-bound", "Path-inline"],
    )
    def test_a_request_chosen_template_file_is_path_traversal(
        self, prelude: str, lines: list[str], sink: str
    ) -> None:
        # A file-system read is the developer's template; which file is read
        # is PY_PATH_TRAVERSAL's, which still reports and proves it.
        found = _collect_src(
            "from flask import request\nfrom jinja2 import Template\n"
            + prelude
            + "def v():\n"
            + "".join(f"    {line}\n" for line in lines)
        )
        assert "SEC-PY_SSTI" not in [f["id"] for f in found], found
        traversal = [f for f in found if f["id"] == "SEC-PY_PATH_TRAVERSAL"]
        assert [f["sink"] for f in traversal] == [sink], found
        assert traversal[0]["reachable"] is True

    @pytest.mark.parametrize(
        "src",
        [
            (
                "from flask import request\nfrom markupsafe import Markup\nfrom jinja2 import Template\n"
                "def v():\n    name = request.args['n']\n    return Markup(Template(name).render())\n"
            ),
            (
                "from django.utils.safestring import mark_safe\n"
                "from django.template import Context, Template\n"
                "def v(request):\n    name = request.GET['n']\n"
                "    return mark_safe(Template(name).render(Context()))\n"
            ),
            (
                "from flask import render_template_string, request\nfrom jinja2 import Template\n"
                "def v():\n    name = request.args['n']\n"
                "    return render_template_string(Template(name).render())\n"
            ),
            (
                "from flask import request\nfrom markupsafe import Markup\nfrom jinja2 import Template\n"
                "def v():\n    t = Template(request.args['n'])\n    page = t.render()\n"
                "    return Markup(page)\n"
            ),
        ],
        ids=["Markup", "mark_safe", "render_template_string", "Markup-bound"],
    )
    def test_released_html_render_sinks_keep_their_xss_beside_ssti(self, src: str) -> None:
        # R-pf47: Markup, mark_safe and render_template_string are released
        # PY_XSS_HTML_SINK sinks whose findings are frozen: they keep the
        # base finding, proof and sink, and PY_SSTI is reported beside them.
        import ast

        found = _collect_src(src)
        by_id = {f["id"]: f for f in found}
        assert sorted(by_id) == ["SEC-PY_SSTI", "SEC-PY_XSS_HTML_SINK"], found
        xss = by_id["SEC-PY_XSS_HTML_SINK"]
        assert xss["reachable"] is True, xss
        returned = src.strip().splitlines()[-1].strip().removeprefix("return ")
        assert xss["sink"] == ast.unparse(ast.parse(returned)), xss
        assert by_id["SEC-PY_SSTI"]["reachable"] is True

    @pytest.mark.parametrize(
        "lines, sink, ids",
        [
            (
                ["name = request.args['n']", "src = request.args['t']",
                 "return Markup(build_html(name, Template(src).render()))"],
                "Markup(build_html(name, Template(src).render()))",
                ["SEC-PY_SSTI", "SEC-PY_XSS_HTML_SINK"],
            ),
            (
                ["return Markup(Template(open(request.args['p']).read()).render())"],
                "Markup(Template(open(request.args['p']).read()).render())",
                ["SEC-PY_PATH_TRAVERSAL", "SEC-PY_XSS_HTML_SINK"],
            ),
        ],
        ids=["helper-with-tainted-name", "file-template-request-path"],
    )
    def test_released_markup_keeps_its_proof(
        self, lines: list[str], sink: str, ids: list[str]
    ) -> None:
        found = _collect_src(
            "from flask import request\nfrom markupsafe import Markup\nfrom jinja2 import Template\n"
            "def v():\n" + "".join(f"    {line}\n" for line in lines)
        )
        assert sorted(f["id"] for f in found) == ids, found
        (xss,) = [f for f in found if f["id"] == "SEC-PY_XSS_HTML_SINK"]
        assert xss["sink"] == sink
        assert xss["reachable"] is True, xss

    def test_html_render_sink_keeps_xss_for_tainted_render_args(self) -> None:
        found = _collect_src(
            "from flask import request\nfrom markupsafe import Markup\nfrom jinja2 import Template\n"
            "def v():\n"
            "    src = request.args['t']\n"
            "    name = request.args['n']\n"
            "    return Markup(Template(src).render(name=name))\n"
        )
        by_id = {f["id"]: f for f in found}
        assert sorted(by_id) == ["SEC-PY_SSTI", "SEC-PY_XSS_HTML_SINK"], found
        xss = by_id["SEC-PY_XSS_HTML_SINK"]
        assert xss["reachable"] is True
        assert xss["taint_chain"][0]["expr"] == "request.args['n']", xss["taint_chain"]

    @pytest.mark.parametrize(
        "lines",
        [
            ["a = [request.args['t']]", "return Template(*a).render()"],
            ["return MakoTemplate(filename=request.args['t']).render()"],
        ],
        ids=["star-args", "mako-filename"],
    )
    def test_a_construction_without_a_source_is_not_a_template_object(
        self, lines: list[str]
    ) -> None:
        # No source argument: not an SSTI sink, and the XSS body rules read
        # the call as before (a class constructor carries its arguments).
        found = _collect_src(
            _FLASK_APP
            + "from jinja2 import Template\nfrom mako.template import Template as MakoTemplate\n"
            + '@app.route("/x")\n'
            + "def v():\n"
            + "".join(f"    {line}\n" for line in lines)
        )
        assert [f["id"] for f in found] == ["SEC-PY_XSS_HTML_SINK"], found

    @pytest.mark.parametrize(
        "mutation",
        [
            "TEMPLATES['x'] = request.args['t']",
            "TEMPLATES.update(x=request.args['t'])",
            "TEMPLATES.setdefault('x', request.args['t'])",
        ],
        ids=["item-assignment", "update", "setdefault"],
    )
    def test_a_mutated_template_dict_is_not_trusted(self, mutation: str) -> None:
        # Reported in every form; an item assignment is a binding the trace
        # follows, so it is also proven.
        found = self._ssti(
            "from flask import request\nfrom jinja2 import Template\n"
            "TEMPLATES = {'a': '<p>a</p>'}\n"
            "def v():\n"
            f"    {mutation}\n"
            "    return Template(TEMPLATES['x']).render()\n"
        )
        assert len(found) == 1, found
        assert (found[0].get("reachable") is True) == mutation.startswith("TEMPLATES["), found


# ---------------------------------------------------------------------------
# Task 3.5: more open-redirect sinks
# ---------------------------------------------------------------------------

_FASTAPI_ROUTE = (
    "from fastapi import FastAPI\n"
    "app = FastAPI()\n"
    '@app.get("/login")\n'
    'def login(next_url: str = "/"):\n'
)
_FLASK_REDIRECT_VIEW = (
    "from flask import Flask, Response, make_response, request, url_for\n"
    "app = Flask(__name__)\n"
    '@app.route("/login")\n'
    "def login():\n"
    '    nxt = request.args.get("next", "/")\n'
)
_DJANGO_REDIRECT_VIEW = (
    "from django.http import HttpResponse, HttpResponsePermanentRedirect, HttpResponseRedirect\n"
    "def login(request):\n"
    '    nxt = request.GET.get("next", "/")\n'
)


class TestOpenRedirectSinks:
    """Task 3.5: Starlette/FastAPI ``RedirectResponse`` and Django
    ``HttpResponsePermanentRedirect`` are redirect constructors, resolved
    through the file's imports like ``redirect`` and ``HttpResponseRedirect``;
    and a ``Location`` header on a framework response that redirects is the
    same sink, set in the constructor's headers, assigned afterwards
    (``resp.headers["Location"] = x``, Django ``resp["Location"] = x``) or
    returned in a Flask ``(body, status, headers)`` tuple. All are reported
    under the existing PY_OPEN_REDIRECT rule, with the same constant,
    sanitiser and ``urlparse(...).netloc`` allowlist checks."""

    @staticmethod
    def _redirects(src: str) -> list[dict]:
        return [f for f in _collect_src(src) if f["id"] == "SEC-PY_OPEN_REDIRECT"]

    def _proven(self, src: str, source: str) -> dict:
        found = self._redirects(src)
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is True, f
        assert any(source in link["expr"] for link in f["taint_chain"]), f["taint_chain"]
        return f

    def _clean(self, src: str) -> None:
        found = self._redirects(src)
        assert found == [], found

    # -- the brief's cases ----------------------------------------------------

    def test_redirectresponse_is_open_redirect(self) -> None:
        f = self._proven(
            "from fastapi.responses import RedirectResponse\n"
            + _FASTAPI_ROUTE
            + "    return RedirectResponse(next_url)\n",
            "next_url",
        )
        assert f["line"] == "mod.py:6"
        assert f["sink"] == "redirect(next_url)"
        assert f["title"] == "Open redirect — user-controlled redirect target"
        assert f["severity"] == "HIGH"
        assert f["references"] == ["CWE-601"]
        assert f["taint_chain"][0] == {"file": "mod.py", "line": 5, "expr": "next_url"}

    def test_permanent_redirect_is_open_redirect(self) -> None:
        f = self._proven(
            _DJANGO_REDIRECT_VIEW + "    return HttpResponsePermanentRedirect(nxt)\n",
            "request.GET",
        )
        assert f["sink"] == "redirect(nxt)"

    def test_response_location_header_kwarg_is_open_redirect(self) -> None:
        f = self._proven(
            _FLASK_REDIRECT_VIEW
            + '    return Response(status=302, headers={"Location": nxt})\n',
            "request.args",
        )
        assert f["line"] == "mod.py:6"
        assert f["sink"] == "Location: nxt"
        assert f["title"] == "Open redirect — user-controlled redirect target"
        assert f["references"] == ["CWE-601"]
        assert f["taint_chain"][-1] == {"file": "mod.py", "line": 6, "expr": "Location: nxt"}

    def test_headers_location_assignment_is_open_redirect(self) -> None:
        f = self._proven(
            _FLASK_REDIRECT_VIEW
            + "    resp = Response(status=302)\n"
            + '    resp.headers["Location"] = nxt\n'
            + "    return resp\n",
            "request.args",
        )
        assert f["line"] == "mod.py:7"
        assert f["sink"] == "Location: nxt"

    @pytest.mark.parametrize(
        "lines",
        [
            ['return Response(status=302, headers={"Location": "/home"})'],
            ['return Response(status=302, headers={"Location": HOME})'],
            ['return Response(status=302, headers={"Location": url_for("index")})'],
            ["resp = Response(status=302)", 'resp.headers["Location"] = "/home"', "return resp"],
            ['return "", 302, {"Location": "/home"}'],
        ],
        ids=["literal", "constant-name", "url_for", "assignment", "flask-tuple"],
    )
    def test_location_header_constant_is_not_redirect(self, lines: list[str]) -> None:
        self._clean(
            'HOME = "/home"\n'
            + _FLASK_REDIRECT_VIEW
            + "".join(f"    {line}\n" for line in lines)
        )

    @pytest.mark.parametrize(
        "sink",
        [
            'return Response(status=302, headers={"Location": nxt})',
            'resp = Response(status=302)\n    resp.headers["Location"] = nxt\n    return resp',
            'return "", 302, {"Location": nxt}',
        ],
        ids=["kwarg", "assignment", "flask-tuple"],
    )
    def test_location_header_host_allowlisted_is_not_redirect(self, sink: str) -> None:
        # Task 2.1's guard: falling through it fixes the authority to a host
        # of a literal allowlist.
        guarded = (
            "from urllib.parse import urlparse\n"
            'ALLOWED = {"example.com", "www.example.com"}\n'
            + _FLASK_REDIRECT_VIEW
            + "    if urlparse(nxt).netloc not in ALLOWED:\n"
            + '        return "bad host", 400\n'
            + f"    {sink}\n"
        )
        self._clean(guarded)
        # Control: the same sink without the guard is proven.
        self._proven(_FLASK_REDIRECT_VIEW + f"    {sink}\n", "request.args")

    def test_location_allowlist_holding_empty_string_does_not_sanitise(self) -> None:
        # R-pf22: `/\evil.com` has netloc "", so "" in the allowlist admits it.
        self._proven(
            "from urllib.parse import urlparse\n"
            'ALLOWED = {"example.com", ""}\n'
            + _FLASK_REDIRECT_VIEW
            + "    if urlparse(nxt).netloc not in ALLOWED:\n"
            + '        return "bad host", 400\n'
            + '    return Response(status=302, headers={"Location": nxt})\n',
            "request.args",
        )

    def test_location_hostname_guard_does_not_sanitise(self) -> None:
        # `.hostname` disagrees with browsers on a backslash authority.
        self._proven(
            "from urllib.parse import urlparse\n"
            'ALLOWED = {"example.com"}\n'
            + _FLASK_REDIRECT_VIEW
            + "    if urlparse(nxt).hostname not in ALLOWED:\n"
            + '        return "bad host", 400\n'
            + '    return Response(status=302, headers={"Location": nxt})\n',
            "request.args",
        )

    def test_location_membership_guard_is_sanitiser(self) -> None:
        self._clean(
            'SAFE = {"/home", "/profile"}\n'
            + _FLASK_REDIRECT_VIEW
            + "    if nxt not in SAFE:\n"
            + '        return "no", 400\n'
            + '    return Response(status=302, headers={"Location": nxt})\n'
        )

    # -- redirect constructors resolve through imports ------------------------

    @pytest.mark.parametrize(
        "imports, call",
        [
            ("from starlette.responses import RedirectResponse\n", "RedirectResponse(next_url)"),
            ("from fastapi.responses import RedirectResponse as Go\n", "Go(next_url)"),
            ("from fastapi.responses import RedirectResponse\n", "RedirectResponse(url=next_url)"),
            (
                "from fastapi.responses import RedirectResponse\n",
                "RedirectResponse(next_url, status_code=302)",
            ),
            ("import starlette.responses\n", "starlette.responses.RedirectResponse(next_url)"),
            ("from fastapi import responses\n", "responses.RedirectResponse(next_url)"),
        ],
        ids=["starlette", "alias", "url-keyword", "status-code", "module-attr", "submodule-attr"],
    )
    def test_redirectresponse_forms_are_open_redirect(self, imports: str, call: str) -> None:
        f = self._proven(imports + _FASTAPI_ROUTE + f"    return {call}\n", "next_url")
        assert f["sink"] == "redirect(next_url)"

    @pytest.mark.parametrize(
        "src",
        [
            (
                "from werkzeug.utils import redirect\n"
                "from flask import request\n"
                "def go():\n"
                '    return redirect(request.args["next"])\n'
            ),
            (
                "from quart import redirect, request\n"
                "async def go():\n"
                '    return redirect(request.args["next"])\n'
            ),
            (
                "from flask import request, redirect as flask_redirect\n"
                "def go():\n"
                '    return flask_redirect(request.args["next"])\n'
            ),
            (
                "from flask import redirect, request\n"
                "def go():\n"
                '    return redirect(location=request.args["next"])\n'
            ),
            (
                "from django.http import HttpResponseRedirect\n"
                "def go(request):\n"
                '    return HttpResponseRedirect(redirect_to=request.GET["next"])\n'
            ),
            (
                "from django import shortcuts\n"
                "def go(request):\n"
                '    return shortcuts.redirect(request.GET["next"])\n'
            ),
            (
                "from django.http.response import HttpResponsePermanentRedirect\n"
                "def go(request):\n"
                '    return HttpResponsePermanentRedirect(request.GET["next"])\n'
            ),
        ],
        ids=[
            "werkzeug", "quart", "flask-alias", "location-keyword", "redirect_to-keyword",
            "django-shortcuts-module", "django-http-response",
        ],
    )
    def test_framework_redirect_functions_are_open_redirect(self, src: str) -> None:
        self._proven(src, "request.")

    @pytest.mark.parametrize(
        "src",
        [
            # A same-file def or class of the same name is the project's own.
            (
                "from flask import request\n"
                "def redirect(url):\n"
                "    return url\n"
                "def go():\n"
                '    return redirect(request.args["next"])\n'
            ),
            (
                "from flask import request\n"
                "class RedirectResponse:\n"
                "    def __init__(self, url):\n"
                "        self.url = url\n"
                "def go():\n"
                '    return RedirectResponse(request.args["next"])\n'
            ),
            # Imported from a module that is not a web framework.
            (
                "from flask import request\n"
                "from app.utils import redirect\n"
                "def go():\n"
                '    return redirect(request.args["next"])\n'
            ),
            (
                "from flask import request\n"
                "from .responses import RedirectResponse\n"
                "def go():\n"
                '    return RedirectResponse(request.args["next"])\n'
            ),
            (
                "from flask import request\n"
                "from app import helpers\n"
                "def go():\n"
                '    return helpers.redirect(request.args["next"])\n'
            ),
            (
                "from flask import request\n"
                "from app.http import HttpResponsePermanentRedirect\n"
                "def go():\n"
                '    return HttpResponsePermanentRedirect(request.args["next"])\n'
            ),
        ],
        ids=[
            "same-file-def", "same-file-class", "project-import", "relative-import",
            "project-module-attr", "project-permanent",
        ],
    )
    def test_project_own_redirect_is_not_a_sink(self, src: str) -> None:
        self._clean(src)

    def test_unimported_redirect_name_keeps_matching_by_name(self) -> None:
        # Unchanged: a bare `redirect` the file neither imports nor defines
        # (a star import) and a method on another value (Tornado's
        # `self.redirect`) still count by name.
        found = self._redirects(
            "from flask import *\n"
            "class Handler:\n"
            "    def get(self):\n"
            '        return self.redirect(request.args["next"])\n'
            "def go():\n"
            '    return redirect(request.args["next"])\n'
        )
        assert [f["line"] for f in found] == ["mod.py:4", "mod.py:6"], found

    # -- existing findings keep their identity --------------------------------

    @pytest.mark.parametrize(
        "src, line, sink, evidence",
        [
            (
                (
                    "from flask import redirect, request\n"
                    "def go():\n"
                    '    nxt = request.args.get("next")\n'
                    "    return redirect(nxt)\n"
                ),
                4,
                "redirect(nxt)",
                "return redirect(nxt)",
            ),
            (
                (
                    "from django.http import HttpResponseRedirect\n"
                    "def go(request):\n"
                    '    nxt = request.GET.get("next")\n'
                    "    return HttpResponseRedirect(nxt)\n"
                ),
                4,
                "redirect(nxt)",
                "return HttpResponseRedirect(nxt)",
            ),
        ],
        ids=["flask-redirect", "django-HttpResponseRedirect"],
    )
    def test_existing_redirect_findings_are_unchanged(
        self, src: str, line: int, sink: str, evidence: str
    ) -> None:
        f = self._proven(src, "request.")
        assert f["rule_id"] == "python.ast/PY_OPEN_REDIRECT"
        assert f["line"] == f"mod.py:{line}"
        assert f["sink"] == sink
        assert f["evidence"] == evidence
        assert f["fix"] == (
            "Validate redirect targets against an allow-list of safe URLs/paths "
            "before passing to redirect(). Reject anything outside your domain."
        )

    # -- Location header forms --------------------------------------------------

    @pytest.mark.parametrize(
        "imports, call",
        [
            ("from starlette.responses import Response\n",
             'Response(status_code=302, headers={"Location": next_url})'),
            ("from fastapi import Response\n",
             'Response(None, 307, {"location": next_url})'),
            ("from fastapi.responses import HTMLResponse\n",
             'HTMLResponse("", status_code=303, headers=[("LOCATION", next_url)])'),
        ],
        ids=["starlette-kwarg", "positional-lowercase", "list-of-pairs"],
    )
    def test_starlette_location_header_is_open_redirect(self, imports: str, call: str) -> None:
        f = self._proven(imports + _FASTAPI_ROUTE + f"    return {call}\n", "next_url")
        assert f["sink"] == "Location: next_url"

    @pytest.mark.parametrize(
        "lines",
        [
            ['return HttpResponse(status=302, headers={"Location": nxt})'],
            ["resp = HttpResponse(status=302)", 'resp["Location"] = nxt', "return resp"],
            ["resp = HttpResponse(status=302)", 'resp.headers["Location"] = nxt', "return resp"],
            ["resp = HttpResponseRedirect('/')", 'resp["Location"] = nxt', "return resp"],
        ],
        ids=["kwarg", "item-assignment", "headers-assignment", "redirect-response-overwritten"],
    )
    def test_django_location_header_is_open_redirect(self, lines: list[str]) -> None:
        f = self._proven(
            _DJANGO_REDIRECT_VIEW + "".join(f"    {line}\n" for line in lines),
            "request.GET",
        )
        assert f["sink"] == "Location: nxt"

    @pytest.mark.parametrize(
        "lines",
        [
            ['return make_response("", 302, {"Location": nxt})'],
            ['return make_response(("", 302, {"Location": nxt}))'],
            ['headers = {"Location": nxt}', "return Response(status=302, headers=headers)"],
            ["resp = Response()", "resp.status_code = 302", 'resp.headers["Location"] = nxt',
             "return resp"],
            ['resp = Response(status=302)', 'resp.headers["location"] = nxt', "return resp"],
            ['return Response(headers={"Location": nxt}, status=STATUS)'],
            ['resp = make_response("", 302)', 'resp.headers["Location"] = "/" + nxt', "return resp"],
        ],
        ids=[
            "make_response", "make_response-tuple", "headers-name", "late-status",
            "lowercase-assignment", "unknown-status", "relative-prefix",
        ],
    )
    def test_flask_location_header_is_open_redirect(self, lines: list[str]) -> None:
        self._proven(
            "STATUS = get_status()\n"
            + _FLASK_REDIRECT_VIEW
            + "".join(f"    {line}\n" for line in lines),
            "request.args",
        )

    def test_flask_tuple_location_is_open_redirect(self) -> None:
        f = self._proven(
            _FLASK_REDIRECT_VIEW + '    return "", 302, {"Location": nxt}\n',
            "request.args",
        )
        assert f["line"] == "mod.py:6"
        assert f["sink"] == "Location: nxt"

    @pytest.mark.parametrize(
        "ret",
        [
            '"", 200, {"Location": nxt}',
            '"", {"Location": nxt}',
            '"", 201, [("Location", nxt)]',
        ],
        ids=["status-200", "no-status", "created"],
    )
    def test_flask_tuple_location_without_redirect_status_is_not_a_sink(self, ret: str) -> None:
        self._clean(_FLASK_REDIRECT_VIEW + f"    return {ret}\n")

    def test_tuple_return_outside_a_flask_view_is_not_a_sink(self) -> None:
        # A FastAPI route serialises a returned tuple as JSON.
        self._clean(_FASTAPI_ROUTE + '    return "", 302, {"Location": next_url}\n')

    @pytest.mark.parametrize(
        "lines",
        [
            # A REST API's 201 Created names the new resource; browsers do not
            # follow it.
            ['return Response(status=201, headers={"Location": nxt})'],
            ['return Response(status=HTTPStatus.CREATED, headers={"Location": nxt})'],
            ['return Response(status=status.HTTP_201_CREATED, headers={"Location": nxt})'],
            # No status: the default 200, which nothing can change afterwards.
            ['return Response(headers={"Location": nxt})'],
            ["resp = Response(status=201)", 'resp.headers["Location"] = nxt', "return resp"],
            ["resp = Response()", 'resp.headers["Location"] = nxt', "return resp"],
            ["resp = Response(status=302)", "resp.status_code = 201",
             'resp.headers["Location"] = nxt', "return resp"],
        ],
        ids=[
            "201", "HTTPStatus.CREATED", "status-module", "no-status", "assignment-201",
            "assignment-no-status", "late-201",
        ],
    )
    def test_location_without_redirect_status_is_not_a_sink(self, lines: list[str]) -> None:
        self._clean(
            "from http import HTTPStatus\n"
            "from starlette import status\n"
            + _FLASK_REDIRECT_VIEW
            + "".join(f"    {line}\n" for line in lines)
        )

    @pytest.mark.parametrize(
        "lines",
        [
            # A plain dict named `headers` is not a response.
            ["headers = {}", 'headers["Location"] = nxt', "return headers"],
            # A response class the project defines itself.
            ["resp = MyResponse(status=302)", 'resp.headers["Location"] = nxt', "return resp"],
            # A Django-style item assignment on a Flask response sets no header.
            ["resp = Response(status=302)", 'resp["Location"] = nxt', "return resp"],
            # Another header.
            ['return Response(status=302, headers={"X-Next": nxt})'],
        ],
        ids=["plain-dict", "project-class", "flask-item-assignment", "other-header"],
    )
    def test_location_on_something_else_is_not_a_sink(self, lines: list[str]) -> None:
        self._clean(
            "class MyResponse:\n"
            "    def __init__(self, status):\n"
            "        self.headers = {}\n"
            + _FLASK_REDIRECT_VIEW
            + "".join(f"    {line}\n" for line in lines)
        )

    def test_location_header_through_a_same_file_helper_is_proven(self) -> None:
        f = self._proven(
            "from fastapi.responses import Response\n"
            "def _go(target: str):\n"
            '    return Response(status_code=302, headers={"Location": target})\n'
            + _FASTAPI_ROUTE
            + "    return _go(next_url)\n",
            "next_url",
        )
        assert f["line"] == "mod.py:3"

    def test_redirectresponse_through_a_same_file_helper_is_proven(self) -> None:
        # The parity corpus's `indirect` shape.
        f = self._proven(
            "from fastapi.responses import RedirectResponse\n"
            "def _redirect_after_login(next_url: str):\n"
            "    return RedirectResponse(next_url)\n"
            + _FASTAPI_ROUTE
            + "    return _redirect_after_login(next_url)\n",
            "next_url",
        )
        assert f["line"] == "mod.py:3"

    def test_unproven_location_header_is_reported_unproven(self) -> None:
        found = self._redirects(
            "from starlette.responses import Response\n"
            "def go(target):\n"
            '    return Response(status_code=302, headers={"Location": target})\n'
        )
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is not True
        assert f["title"] == "Potential open redirect — dynamic redirect target"
        assert f["sink"] == "Location: target"

    def test_relative_prefix_is_reported_like_redirect(self) -> None:
        # `"/" + "/evil.com"` is `//evil.com`, a protocol-relative URL; the
        # Location forms follow redirect() exactly.
        for sink in (
            'return redirect("/" + nxt)',
            'return Response(status=302, headers={"Location": "/" + nxt})',
        ):
            self._proven(
                _FLASK_REDIRECT_VIEW.replace("url_for\n", "url_for, redirect\n") + f"    {sink}\n",
                "request.args",
            )

    def test_location_and_xss_are_reported_separately(self) -> None:
        found = _collect_src(
            _FLASK_REDIRECT_VIEW
            + '    return Response(f"<p>{nxt}</p>", status=STATUS, headers={"Location": nxt})\n'
        )
        assert sorted(f["id"] for f in found) == [
            "SEC-PY_OPEN_REDIRECT",
            "SEC-PY_XSS_HTML_SINK",
        ], found


# ---------------------------------------------------------------------------
# Task 3.6: Starlette/FastAPI FileResponse(path) is a path-traversal sink
# ---------------------------------------------------------------------------

_FILE_ROUTE = (
    "import os\n"
    "from pathlib import Path\n"
    "from fastapi import FastAPI, HTTPException\n"
    "app = FastAPI()\n"
    'REPORTS_DIR = "/srv/reports"\n'
    'BASE = Path("/srv/reports")\n'
    '@app.get("/report")\n'
    'def report(filename: str = ""):\n'
)


class TestFileResponsePathSink:
    """Task 3.6: Starlette's and FastAPI's ``FileResponse(path)`` opens and
    sends the file at ``path``, so a path the request chooses is path
    traversal, reported under the existing PY_PATH_TRAVERSAL rule. It must
    resolve through the file's imports to ``starlette.responses`` or
    ``fastapi.responses``. Django's ``FileResponse`` takes an open file, whose
    ``open(...)`` is the sink, so it is never one itself."""

    @staticmethod
    def _pt(src: str) -> list[dict]:
        return [f for f in _collect_src(src) if f["id"] == "SEC-PY_PATH_TRAVERSAL"]

    @classmethod
    def _file_response(cls, src: str) -> list[dict]:
        return [f for f in cls._pt(src) if f["sink"].startswith("FileResponse(")]

    def _proven(self, src: str, sink: str) -> dict:
        found = self._file_response(src)
        assert len(found) == 1, found
        f = found[0]
        assert f["sink"] == sink, f
        assert f.get("reachable") is True, f
        return f

    # -- the brief's cases ----------------------------------------------------

    def test_starlette_fileresponse_path_is_traversal(self) -> None:
        f = self._proven(
            "from starlette.responses import FileResponse\n"
            + _FILE_ROUTE
            + "    return FileResponse(os.path.join(REPORTS_DIR, filename))\n",
            "FileResponse(os.path.join(REPORTS_DIR, filename))",
        )
        assert f["line"] == "mod.py:10"
        assert f["rule_id"] == "python.ast/PY_PATH_TRAVERSAL"
        assert f["title"] == "Path traversal — user-controlled input reaches filesystem path"
        assert f["severity"] == "HIGH"
        assert f["references"] == ["CWE-22"]
        assert f["taint_chain"][0] == {"file": "mod.py", "line": 9, "expr": "filename"}
        # The inner join keeps its own finding, as inside open(...).
        assert {g["sink"] for g in self._pt(
            "from starlette.responses import FileResponse\n"
            + _FILE_ROUTE
            + "    return FileResponse(os.path.join(REPORTS_DIR, filename))\n"
        )} == {"FileResponse(os.path.join(REPORTS_DIR, filename))", "os.path.join(filename)"}

    def test_django_fileresponse_of_open_reports_once(self) -> None:
        found = self._pt(
            "from django.http import FileResponse\n"
            "def download(request):\n"
            '    path = request.GET["f"]\n'
            '    return FileResponse(open(path, "rb"), as_attachment=True)\n'
        )
        assert [(f["line"], f["sink"]) for f in found] == [("mod.py:4", "open(path)")], found
        assert found[0].get("reachable") is True

    # -- resolution -------------------------------------------------------------

    @pytest.mark.parametrize(
        "imports, call",
        [
            ("from fastapi.responses import FileResponse\n", "FileResponse(filename)"),
            ("from fastapi.responses import FileResponse as Download\n", "Download(filename)"),
            ("import starlette.responses\n", "starlette.responses.FileResponse(filename)"),
            ("from fastapi import responses\n", "responses.FileResponse(filename)"),
            ("from fastapi.responses import FileResponse\n",
             'FileResponse(path=filename, filename="report.pdf")'),
            ("from fastapi.responses import FileResponse\n",
             'FileResponse(filename, media_type="application/pdf")'),
        ],
        ids=["fastapi", "alias", "module-attr", "submodule-attr", "path-keyword", "media-type"],
    )
    def test_fileresponse_forms_are_traversal(self, imports: str, call: str) -> None:
        self._proven(imports + _FILE_ROUTE + f"    return {call}\n", "FileResponse(filename)")

    @pytest.mark.parametrize(
        "src",
        [
            # Django takes an open file; a path string is not opened.
            (
                "from django.http import FileResponse\n"
                "def download(request):\n"
                '    return FileResponse(request.GET["f"])\n'
            ),
            # Starlette's FileResponse given an open file: the open() is the sink.
            (
                "from starlette.responses import FileResponse\n"
                "def download(request):\n"
                '    return FileResponse(open(request.query_params["f"], "rb"))\n'
            ),
            # A project's own class.
            (
                "from flask import request\n"
                "class FileResponse:\n"
                "    def __init__(self, path):\n"
                "        self.path = path\n"
                "def download():\n"
                '    return FileResponse(request.args["f"])\n'
            ),
            (
                "from flask import request\n"
                "from app.responses import FileResponse\n"
                "def download():\n"
                '    return FileResponse(request.args["f"])\n'
            ),
            # A bare name the file does not import cannot be resolved.
            (
                "from flask import request\n"
                "def download():\n"
                '    return FileResponse(request.args["f"])\n'
            ),
        ],
        ids=["django-path", "starlette-open", "same-file-class", "project-import", "unimported"],
    )
    def test_other_fileresponses_are_not_sinks(self, src: str) -> None:
        assert self._file_response(src) == []

    # -- what keeps it quiet ----------------------------------------------------

    @pytest.mark.parametrize(
        "call",
        [
            'FileResponse("static/index.html")',
            "FileResponse(os.path.join(REPORTS_DIR, 'latest.txt'))",
            "FileResponse(BASE / 'latest.txt')",
        ],
        ids=["literal", "constant-join", "constant-pathlib"],
    )
    def test_constant_path_is_not_a_sink(self, call: str) -> None:
        assert self._pt(
            "from fastapi.responses import FileResponse\n" + _FILE_ROUTE + f"    return {call}\n"
        ) == []

    @pytest.mark.parametrize(
        "lines",
        [
            [
                "base = os.path.realpath(REPORTS_DIR)",
                "full = os.path.realpath(os.path.join(base, filename))",
                "if os.path.commonpath([base, full]) != base:",
                '    raise HTTPException(status_code=400, detail="invalid filename")',
                "return FileResponse(full)",
            ],
            [
                "full = os.path.realpath(os.path.join(REPORTS_DIR, filename))",
                "if not full.startswith(REPORTS_DIR + os.sep):",
                "    raise HTTPException(status_code=400)",
                "return FileResponse(full)",
            ],
            [
                "full = (BASE / filename).resolve()",
                "if not full.is_relative_to(BASE):",
                "    raise HTTPException(status_code=400)",
                "return FileResponse(full)",
            ],
            [
                "full = (BASE / filename).resolve()",
                "try:",
                "    full.relative_to(BASE)",
                "except ValueError:",
                "    raise HTTPException(status_code=400)",
                "return FileResponse(full)",
            ],
            ["name = os.path.basename(filename)", "return FileResponse(name)"],
        ],
        ids=["realpath-commonpath", "startswith-sep", "is_relative_to", "relative_to-try", "basename"],
    )
    def test_path_containment_guard_suppresses_fileresponse(self, lines: list[str]) -> None:
        # Task 2.2's guards, exactly as they suppress open(path).
        body = "".join(f"    {line}\n" for line in lines)
        src = "from fastapi.responses import FileResponse\n" + _FILE_ROUTE + body
        assert self._pt(src) == []
        # Control: open() on the same path is quiet under the same guard.
        assert self._pt(src.replace("return FileResponse(", "return open(")) == []

    @pytest.mark.parametrize(
        "lines, line",
        [
            (
                [
                    "full = os.path.realpath(os.path.join(REPORTS_DIR, filename))",
                    "if not full.startswith(REPORTS_DIR):",
                    "    raise HTTPException(status_code=400)",
                    "return FileResponse(full)",
                ],
                13,
            ),
            (
                [
                    "base = os.path.realpath(REPORTS_DIR)",
                    "full = os.path.realpath(os.path.join(base, filename))",
                    "if os.path.commonpath([base, full]) != base:",
                    "    return FileResponse(full)",
                    "return FileResponse(full)",
                ],
                13,
            ),
            (
                [
                    "full = os.path.join(REPORTS_DIR, filename)",
                    "if os.path.commonpath([REPORTS_DIR, full]) != REPORTS_DIR:",
                    "    raise HTTPException(status_code=400)",
                    "return FileResponse(full)",
                ],
                13,
            ),
        ],
        ids=["startswith-without-sep", "sink-in-rejecting-body", "commonpath-without-realpath"],
    )
    def test_incomplete_guard_does_not_suppress_fileresponse(
        self, lines: list[str], line: int
    ) -> None:
        found = self._file_response(
            "from fastapi.responses import FileResponse\n"
            + _FILE_ROUTE
            + "".join(f"    {ln}\n" for ln in lines)
        )
        assert [f["line"] for f in found if f.get("reachable")] == [f"mod.py:{line}"], found

    def test_unproven_fileresponse_is_reported_unproven(self) -> None:
        found = self._file_response(
            "from starlette.responses import FileResponse\n"
            "def send(path):\n"
            "    return FileResponse(path)\n"
        )
        assert len(found) == 1, found
        f = found[0]
        assert f.get("reachable") is not True
        assert f["severity"] == "MEDIUM"
        assert f["title"] == "Potential unsafe dynamic filesystem path"

    def test_fileresponse_through_a_same_file_helper_is_proven(self) -> None:
        f = self._proven(
            "from starlette.responses import FileResponse\n"
            "def _send(name: str):\n"
            "    return FileResponse(name)\n"
            + _FILE_ROUTE
            + "    return _send(filename)\n",
            "FileResponse(name)",
        )
        assert f["line"] == "mod.py:3"


_WEAK_HASH = "SEC-PY_WEAK_CRYPTO_PASSWORD"
_JWT_WEAK = "SEC-PY_JWT_WEAK"


class TestWeakHashAndJwtTaintProof:
    """Task 3.9: PY_WEAK_CRYPTO_PASSWORD and PY_JWT_WEAK carry a taint chain
    when request input reaches the hashed value or the decoded token. A proven
    finding is reachable, an independent signal, so it may block; an unproven
    one is reported exactly as before.

    Identity does not move with the proof. Both rules name their sink as the
    evidence line on both paths: PY_JWT_WEAK is a code finding, whose
    fingerprint hashed the evidence line while it had no sink, and
    PY_WEAK_CRYPTO_PASSWORD is a `secrets` finding, keyed on its rule and
    file alone. PY_JWT_WEAK binds no route declared in another file (a Django
    urlconf), because a bound route's file replaces the finding's own in its
    fingerprint."""

    @staticmethod
    def _found(src: str | dict[str, str], rule: str) -> list[dict]:
        if isinstance(src, str):
            return [f for f in _collect_src(src) if f["id"] == rule]
        with tempfile.TemporaryDirectory() as d:
            for name, content in src.items():
                p = Path(d) / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content)
            return [f for f in _collect(d) if f["id"] == rule]

    def _one(self, src: str | dict[str, str], rule: str) -> dict:
        found = self._found(src, rule)
        assert len(found) == 1, found
        return found[0]

    def _proven(self, src: str | dict[str, str], rule: str) -> dict:
        f = self._one(src, rule)
        assert f.get("reachable") is True, f
        return f

    def _unproven(self, src: str | dict[str, str], rule: str) -> dict:
        f = self._one(src, rule)
        assert f.get("reachable") is not True, f
        assert "taint_chain" not in f, f
        return f

    # -- the brief's cases ----------------------------------------------------

    def test_md5_of_request_password_is_reachable(self) -> None:
        f = self._proven(
            "import hashlib\n"
            "from flask import request\n"
            "def register():\n"
            '    password = request.form["password"]\n'
            "    return hashlib.md5(password.encode()).hexdigest()\n",
            _WEAK_HASH,
        )
        assert f["taint_chain"] == [
            _link(4, "request.form['password']"),
            _link(5, "hashlib.md5(password.encode())"),
        ]
        assert f["line"] == "mod.py:5"

    def test_jwt_decode_of_authorization_header_is_reachable(self) -> None:
        f = self._proven(
            "import jwt\n"
            "from flask import request\n"
            "def current_user():\n"
            '    token = request.headers["Authorization"]\n'
            '    return jwt.decode(token, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )
        assert f["taint_chain"] == [
            _link(4, "request.headers['Authorization']"),
            _link(5, "jwt.decode(token, options={'verify_signature': False})"),
        ]

    def test_md5_of_constant_stays_unreachable(self) -> None:
        self._unproven(
            "import hashlib\n"
            'DEFAULT_PASSWORD = "changeme"\n'
            "def seed():\n"
            "    return hashlib.md5(DEFAULT_PASSWORD.encode()).hexdigest()\n",
            _WEAK_HASH,
        )

    def test_jwt_decode_of_constant_stays_unreachable(self) -> None:
        self._unproven(
            "import jwt\n"
            'SAMPLE_TOKEN = "header.payload.signature"\n'
            "def sample_claims():\n"
            '    return jwt.decode(SAMPLE_TOKEN, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )

    # -- identity -------------------------------------------------------------

    _HASH_HEAD = "import hashlib\nfrom flask import request\ndef register():\n"
    _HASH_SINK = "    return hashlib.md5(password.encode()).hexdigest()\n"
    _JWT_HEAD = "import jwt\nfrom flask import request\ndef current_user():\n"
    _JWT_SINK = '    return jwt.decode(token, options={"verify_signature": False})\n'

    @staticmethod
    def _without_proof(f: dict) -> dict:
        return {k: v for k, v in f.items() if k not in ("reachable", "taint_chain", "route")}

    def test_weak_hash_fingerprint_fields_unchanged(self) -> None:
        # The same sink, with and without a request source. models.Fingerprint
        # keys a `secrets` finding on category, rule and the endpoint's file
        # (secretIdentity), and a code finding on file, symbol and sink; none
        # of them, nor the title, severity or confidence, may follow the proof.
        proven = self._proven(
            self._HASH_HEAD + '    password = request.form["password"]\n' + self._HASH_SINK,
            _WEAK_HASH,
        )
        unproven = self._unproven(
            self._HASH_HEAD + "    password = load_password()\n" + self._HASH_SINK,
            _WEAK_HASH,
        )
        assert self._without_proof(proven) == self._without_proof(unproven)
        assert proven["category"] == "secrets"
        assert proven["rule_id"] == "python.ast/PY_WEAK_CRYPTO_PASSWORD"
        assert proven["endpoint"] == unproven["endpoint"] == "mod.py:5"
        assert proven["symbol"] == unproven["symbol"] == "register"
        assert proven["sink"] == unproven["sink"] == proven["evidence"]
        assert proven["title"] == "Weak hash (MD5/SHA1) used for password — credential exposure risk"
        assert proven["severity"] == "HIGH"
        assert proven["confidence"] == "MEDIUM"

    def test_jwt_fingerprint_fields_unchanged(self) -> None:
        # PY_JWT_WEAK is a code finding: its fingerprint hashes the sink, and
        # the evidence line when there is none, which is what every finding
        # this rule reported before Task 3.9 had. The sink is that line.
        proven = self._proven(
            self._JWT_HEAD + '    token = request.headers["Authorization"]\n' + self._JWT_SINK,
            _JWT_WEAK,
        )
        unproven = self._unproven(
            self._JWT_HEAD + "    token = read_cached_token()\n" + self._JWT_SINK,
            _JWT_WEAK,
        )
        assert self._without_proof(proven) == self._without_proof(unproven)
        assert proven["category"] == "auth_bypass"
        assert proven["symbol"] == unproven["symbol"] == "current_user"
        assert proven["sink"] == unproven["sink"] == proven["evidence"]
        assert proven["sink"] == 'return jwt.decode(token, options={"verify_signature": False})'
        assert proven["title"] == (
            "Weak JWT verification — decode with verify=False or unpinned algorithm"
        )
        assert proven["severity"] == "HIGH"
        assert proven["confidence"] == "MEDIUM"

    def test_proven_jwt_in_a_django_view_binds_no_urlconf_route(self) -> None:
        # A route declared in the urlconf would make the urlconf the
        # finding's file in its fingerprint, re-filing it on proof.
        f = self._proven(
            {
                "app/urls.py": "from django.urls import path\n"
                "from app import views\n"
                'urlpatterns = [path("me/", views.current_user)]\n',
                "app/views.py": "import jwt\n"
                "def current_user(request):\n"
                '    token = request.headers.get("Authorization", "")\n'
                '    return jwt.decode(token, options={"verify_signature": False})\n',
            },
            _JWT_WEAK,
        )
        assert "route" not in f, f
        assert f["endpoint"] == "app/views.py:4"
        assert {link["file"] for link in f["taint_chain"]} == {"app/views.py"}

    def test_proven_jwt_in_a_flask_route_binds_its_route(self) -> None:
        # A decorator route is declared in the handler's own file: binding it
        # leaves the finding's file as it was.
        f = self._proven(
            "import jwt\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            '@app.route("/me")\n'
            "def current_user():\n"
            '    token = request.headers["Authorization"]\n'
            '    return jwt.decode(token, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )
        assert f["route"]["file"] == "mod.py", f

    # -- route parameters, helpers and caller-side sanitisers ------------------

    def test_md5_of_fastapi_form_parameter_is_reachable(self) -> None:
        f = self._proven(
            "import hashlib\n"
            "from typing import Annotated\n"
            "from fastapi import APIRouter, Form\n"
            "router = APIRouter()\n"
            '@router.post("/register")\n'
            "def register(password: Annotated[str, Form()]):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n",
            _WEAK_HASH,
        )
        assert f["taint_chain"][0] == _link(6, "password")

    def test_jwt_decode_of_fastapi_header_parameter_is_reachable(self) -> None:
        f = self._proven(
            "import jwt\n"
            "from typing import Annotated\n"
            "from fastapi import APIRouter, Header\n"
            "router = APIRouter()\n"
            '@router.get("/me")\n'
            'def current_user(authorization: Annotated[str, Header()] = ""):\n'
            '    token = authorization.removeprefix("Bearer ")\n'
            '    return jwt.decode(token, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )
        assert f["taint_chain"][0] == _link(6, "authorization")

    _HASH_HELPER = (
        "import hashlib\n"
        "from flask import request\n"
        'ALLOWED = {"a", "b"}\n'
        "def _hash_password(password):\n"
        "    return hashlib.md5(password.encode()).hexdigest()\n"
        "def register():\n"
        '    pw = request.form["password"]\n'
    )

    def test_md5_of_request_value_through_a_same_file_helper_is_proven(self) -> None:
        f = self._proven(self._HASH_HELPER + "    return _hash_password(pw)\n", _WEAK_HASH)
        assert f["line"] == "mod.py:5"
        assert f["taint_chain"][0] == _link(7, "request.form['password']")
        assert f["taint_chain"][-1] == _link(5, "hashlib.md5(password.encode())")

    def test_md5_through_a_helper_behind_a_caller_sanitiser_is_not_proven(self) -> None:
        f = self._unproven(
            self._HASH_HELPER
            + "    if pw not in ALLOWED:\n"
            + '        return "no", 400\n'
            + "    return _hash_password(pw)\n",
            _WEAK_HASH,
        )
        assert f["line"] == "mod.py:5"

    def test_md5_through_a_keyword_only_helper_parameter_is_proven(self) -> None:
        f = self._proven(
            "import hashlib\n"
            "from flask import request\n"
            "def _hash_password(*, password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
            "def register():\n"
            '    return _hash_password(password=request.form["password"])\n',
            _WEAK_HASH,
        )
        assert f["taint_chain"][0] == _link(6, "request.form['password']")

    def test_jwt_decode_through_a_same_file_helper_is_proven(self) -> None:
        f = self._proven(
            "import jwt\n"
            "from flask import request\n"
            "def _decode_token(token):\n"
            '    return jwt.decode(token, options={"verify_signature": False})\n'
            "def current_user():\n"
            '    token = request.headers.get("Authorization", "")\n'
            "    return _decode_token(token)\n",
            _JWT_WEAK,
        )
        assert f["line"] == "mod.py:4"
        assert f["taint_chain"][0] == _link(6, "request.headers.get('Authorization', '')")

    # -- argument positions ---------------------------------------------------

    def test_hashlib_new_traces_its_data_argument(self) -> None:
        f = self._proven(
            "import hashlib\n"
            "from flask import request\n"
            "def register():\n"
            '    password = request.form["password"]\n'
            '    return hashlib.new("sha1", password.encode()).hexdigest()\n',
            _WEAK_HASH,
        )
        assert f["taint_chain"][-1] == _link(5, "hashlib.new('sha1', password.encode())")

    def test_jwt_decode_traces_the_jwt_keyword(self) -> None:
        f = self._proven(
            "import jwt\n"
            "from flask import request\n"
            "def current_user():\n"
            '    token = request.headers["Authorization"]\n'
            '    return jwt.decode(jwt=token, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )
        assert f["taint_chain"][0] == _link(4, "request.headers['Authorization']")

    def test_jwt_decode_does_not_trace_the_key(self) -> None:
        # A request value used as the key is not the token being trusted.
        self._unproven(
            "import jwt\n"
            "from flask import request\n"
            'SAMPLE_TOKEN = "header.payload.signature"\n'
            "def check():\n"
            '    key = request.args["k"]\n'
            '    return jwt.decode(SAMPLE_TOKEN, key, options={"verify_signature": False})\n',
            _JWT_WEAK,
        )


class TestPython39Compatibility:
    """The docs promise Python 3.9+. `ast.MatchAs`, `ast.MatchStar` and
    `ast.MatchMapping` do not exist before 3.10, so a bare reference in
    `_binds_name` raised AttributeError and lost the whole file's findings."""

    _SRC = (
        "from fastapi import FastAPI\n"
        "from fastapi.responses import HTMLResponse\n"
        "app = FastAPI()\n"
        '@app.get("/greet")\n'
        'def greet(name: str = ""):\n'
        '    return HTMLResponse(f"<h1>{name}</h1>")\n'
    )

    @pytest.fixture
    def no_match_nodes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for cls in ("MatchAs", "MatchStar", "MatchMapping"):
            monkeypatch.delattr(ast, cls, raising=False)

    def test_binds_name_without_the_match_node_classes(self, no_match_nodes) -> None:
        from analyzers.ast_analyzer import _binds_name

        assign = ast.parse("full = 1").body[0].targets[0]
        assert _binds_name(assign, "full") is True
        # A node that is none of the earlier kinds reaches the `match` checks.
        assert _binds_name(ast.parse("print(full)").body[0], "full") is False

    def test_a_file_is_still_analysed_without_the_match_node_classes(self, no_match_nodes) -> None:
        found = [f for f in _collect_src(self._SRC) if f["id"] == "SEC-PY_XSS_HTML_SINK"]
        assert len(found) == 1, found
