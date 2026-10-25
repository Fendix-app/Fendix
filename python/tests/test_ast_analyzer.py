"""Tests for the ASTAnalyzer.

Verifies Python AST and JavaScript heuristic detection of dangerous patterns.
"""
from __future__ import annotations

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
    """A dominating ``urlparse(url).hostname not in ALLOWED`` early exit is an
    SSRF / open-redirect guard.

    Falling through ``if p.hostname not in ALLOWED: return`` means the host IS
    in a literal allowlist, so the request or redirect that follows cannot reach
    an attacker-chosen host. The recognition is held to the same dominance
    discipline as the other guards: a top-level ``if`` before the sink whose
    body ends control flow, over a literal collection. Only ``or`` may combine
    the host check with other conditions; with ``and`` the host check can be
    skipped.
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

    def test_ssrf_hostname_allowlist_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    p = urlparse(url)\n"
            '    if p.scheme != "https" or p.hostname not in ALLOWED:\n'
            '        return "host not allowed", 400\n'
            "    return requests.get(url, timeout=5).text\n"
        )
        assert not ssrf, f"hostname allowlist guard not honoured: {ssrf}"

    def test_ssrf_inline_urlparse_guard_is_sanitiser(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).hostname not in ALLOWED:\n"
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
            "    if urlparse(url).hostname not in ALLOWED:\n"
            '        return "host not allowed", 400\n'
            "    return resp.text\n"
        )
        assert ssrf, "a guard after the sink cannot protect it"

    def test_ssrf_guard_without_exit_does_not_sanitise(self) -> None:
        ssrf = self._ssrf(
            "def fetch():\n"
            '    url = request.args.get("url")\n'
            "    if urlparse(url).hostname not in ALLOWED:\n"
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
            "    if urlparse(url).hostname not in ALLOWED:\n"
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
            '    if p.scheme != "https" and p.hostname not in ALLOWED:\n'
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
            "    if urlparse(url).hostname not in ALLOWED:\n"
            "        abort(400)\n"
            "    return mark_safe(url)\n"
        )
        assert [f for f in findings if f["id"] == "SEC-PY_XSS_HTML_SINK"], (
            f"a host allowlist must not count as an XSS sanitiser: {_ids(findings)}"
        )
