"""The Python engine's own checks, as the security catalog publishes them.

One entry per pattern id that ast_analyzer.py emits: the PY_* checks raised
through ``_PythonSecurityVisitor._emit_finding`` and the JS_* checks in
``_JS_PATTERNS``. Every field restates what the emit site sends, and
tests/test_check_registry.py fails when the two drift apart.

``id`` is the bare pattern id the analyzer is written in terms of. The catalog
names each check by its ``rule_id`` instead, as it does for every other
analyzer, and publishes ``finding_id`` as the check's finding_id.

The catalog itself is generated in Go (go/cmd/catalog-contract). The Go module
cannot embed files from ../python, so ``export_json()`` is mirrored into
go/internal/catalog/python_engine_checks.json. Regenerate it from python/ with:

    python -m analyzers.check_registry > ../go/internal/catalog/python_engine_checks.json
"""

from __future__ import annotations

import dataclasses
import json
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    cwe: str
    category: str
    languages: tuple[str, ...]
    # The severity the emit site passes. Where the site also passes
    # proven_severity, this is the unproven value: the finding escalates only
    # when a taint chain is collected.
    default_severity: str
    # The rule_id the finding carries, which identity and SARIF key on. It is
    # the check's catalog id.
    rule_id: str
    # The id the analyzer gives the finding (the finding's "id" field).
    finding_id: str


def _py(id: str, title: str, cwe: str, category: str, default_severity: str) -> Check:
    return Check(
        id,
        title,
        cwe,
        category,
        ("python",),
        default_severity,
        rule_id=f"python.ast/{id}",
        finding_id=f"SEC-{id}",
    )


def _js(id: str, title: str, cwe: str, default_severity: str) -> Check:
    # The JS pattern loop emits category "injection" for every pattern, and a
    # rule_id equal to the finding id (see the comment at its emit site).
    return Check(
        id,
        title,
        cwe,
        "injection",
        ("javascript", "typescript"),
        default_severity,
        rule_id=f"SEC-{id}",
        finding_id=f"SEC-{id}",
    )


# Titles are the emit site's literal title. Two sites build theirs with an
# f-string (PY_EVAL names eval/exec/<receiver>.eval, PY_OS_POPEN names the
# popen variant), so those two are written out here.
CHECKS: tuple[Check, ...] = (
    _py(
        "PY_AUTH_HEADER_TRUST",
        "Auth decision based on a client-controllable header",
        "CWE-290",
        "auth_bypass",
        "HIGH",
    ),
    _py(
        "PY_EVAL",
        "Unsafe eval() or exec() with a dynamic argument",
        "CWE-95",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_JWT_WEAK",
        "Weak JWT verification — decode with verify=False or unpinned algorithm",
        "CWE-347",
        "auth_bypass",
        "HIGH",
    ),
    _py(
        "PY_LLM_PROMPT_INJECTION",
        "Prompt injection — untrusted input flows into an LLM prompt",
        "CWE-77",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_OPEN_REDIRECT",
        "Potential open redirect — dynamic redirect target",
        "CWE-601",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_OS_POPEN",
        "Unsafe os.popen() family call — command injection risk",
        "CWE-78",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_OS_SYSTEM",
        "Unsafe os.system() call — command injection risk",
        "CWE-78",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_PATH_TRAVERSAL",
        "Potential unsafe dynamic filesystem path",
        "CWE-22",
        "injection",
        "MEDIUM",
    ),
    _py(
        "PY_PICKLE_LOAD",
        "Unsafe pickle deserialization — RCE risk",
        "CWE-502",
        "injection",
        "CRITICAL",
    ),
    _py(
        "PY_SECRET_IN_LOG",
        "Secret written to logs — credential exposure",
        "CWE-532",
        "secrets",
        "MEDIUM",
    ),
    _py(
        "PY_SQL_INJECTION",
        "SQL query built via string formatting — injection risk",
        "CWE-89",
        "injection",
        "CRITICAL",
    ),
    _py(
        "PY_SSRF",
        "Potential SSRF — dynamic URL passed to HTTP client",
        "CWE-918",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_SUBPROCESS_SHELL",
        "subprocess called with shell=True — command injection risk",
        "CWE-78",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_WEAK_CRYPTO_PASSWORD",
        "Weak hash (MD5/SHA1) used for password — credential exposure risk",
        "CWE-916",
        "secrets",
        "HIGH",
    ),
    _py(
        "PY_XSS_HTML_SINK",
        "Reflected XSS — user input passed to HTML render sink",
        "CWE-79",
        "injection",
        "HIGH",
    ),
    _py(
        "PY_YAML_UNSAFE_LOAD",
        "Unsafe yaml.load() — RCE risk",
        "CWE-502",
        "injection",
        "HIGH",
    ),
    _js(
        "JS_DOCUMENT_WRITE",
        "Unsafe use of document.write() — XSS risk",
        "CWE-79",
        "MEDIUM",
    ),
    _js("JS_EVAL", "Unsafe use of eval() in JavaScript", "CWE-95", "HIGH"),
    _js("JS_INNER_HTML", "Unsafe assignment to innerHTML — XSS risk", "CWE-79", "HIGH"),
    _js(
        "JS_SQL_TEMPLATE",
        "SQL query built via template literal — injection risk",
        "CWE-89",
        "HIGH",
    ),
)


def export_json() -> str:
    """The registry as the Go catalog reads it, byte for byte."""
    rows = [dataclasses.asdict(check) for check in CHECKS]
    for row in rows:
        row["languages"] = list(row["languages"])
    return json.dumps(rows, indent=2, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    sys.stdout.write(export_json())
