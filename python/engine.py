#!/usr/bin/env python3
"""Fendix Python Engine.

Reads a ScanRequest JSON from stdin, runs white-box analyzers,
and streams Finding JSON objects to stdout (one per line).
Terminates with {"done": true, "total": N}.

Usage:
    echo '{"mode":"whitebox","code_path":"./src","checks":["secrets"]}' | python engine.py
"""

import json
import sys
from typing import Callable, Optional, Tuple

# Tuple, not `tuple[...]` / `X | None`: this module is exec'd directly by a
# Python 3.9 interpreter (no `from __future__ import annotations` here), and
# PEP 604 union syntax and the bare `tuple` generic alias for annotations
# both require 3.10+ at runtime for annotations that get evaluated eagerly.
StatusTuple = Tuple[str, Optional[str], Optional[str]]

# Declared on the done line as "protocol". The Go spawner (internal/engine)
# uses this to decide whether to enforce the one-status-line-per-check
# contract: protocol >= 2 means every check in expectedPythonChecks
# (auth/injection/deps) must report exactly once, or the run is malformed/
# truncated. A legacy (absent or <2) protocol value gets status lines
# ignored entirely, so bumping this number is a real contract change, not
# cosmetic versioning.
PROTOCOL_VERSION = 2


def _log(msg: str) -> None:
    """Write a diagnostic message to stderr (never stdout)."""
    print(f"[fendix-engine] {msg}", file=sys.stderr, flush=True)


def emit(finding: dict) -> None:
    """Write a single finding as a JSON line to stdout."""
    print(json.dumps(finding), flush=True)


def _status(
    check: str,
    state: str,
    reason: Optional[str] = None,
    detail: Optional[str] = None,
    scope: Optional[dict] = None,
) -> None:
    """Emit one protocol-v2 status line for `check`.

    The Go side records this as the python-engine/<check> child entry (see
    internal/engine/spawner.go, internal/engine/orchestrator.go). A status
    line is never a finding: it carries no "id"/"title", so it never counts
    toward done.total and the existing finding-counting tests are unaffected.
    Optional fields are omitted rather than sent as null/empty so the wire
    shape matches the Go struct's `omitempty` tags exactly.

    `scope`, when given, is the complete list of the files whose analysis was
    lost and the paths left out on purpose (`status_detail.scope_payload`).
    The detail names only the first few within its byte budget; this is the
    whole record, an additive field the Go side may copy into the report's
    metadata (an unknown key in a status line is ignored today).
    """
    payload: dict = {"check": check, "state": state}
    if reason:
        payload["reason"] = reason
    if detail:
        payload["detail"] = detail
    if scope:
        payload["scope"] = scope
    print(json.dumps({"status": payload}), flush=True)


def _run_check(check: str, label: str, fn: Callable[[], None], verbose: bool) -> StatusTuple:
    """Run a single check function and classify its outcome for the status line.

    The callable is expected to perform its own analyzer IMPORT as well as the
    analysis. Importing at the call site instead of here is what previously
    turned one missing optional dependency into a total engine failure: the
    spec parser's top-level ``import yaml`` raised ImportError outside this
    guard, so an environment without PyYAML aborted ``main()`` with exit 1 and
    reported ZERO findings — including from the AST taint analyzer, which needs
    no third-party package at all. Now a missing dependency degrades to one
    skipped check (state="skipped", reason="dependency_missing") instead of
    killing the whole engine, matching the Go side's per-scanner status model
    (fail loudly, recover gracefully). Any other exception is an execution
    error rather than a missing dependency — the two are distinguished because
    the coverage contract's remediation advice differs (install a package vs.
    investigate a bug).

    `check` is the coverage-contract identity (auth/injection/deps); `label`
    is only for the human-readable stderr log.
    """
    try:
        if verbose:
            _log(f"starting check: {label}")
        fn()
        if verbose:
            _log(f"finished check: {label}")
        return ("ok", None, None)
    except ImportError as exc:
        _log(
            f"check '{label}' skipped: missing dependency ({exc}). "
            "Install python/requirements.txt to enable it."
        )
        return ("skipped", "dependency_missing", str(exc))
    except Exception as exc:  # noqa: BLE001
        _log(f"check '{label}' failed: {exc}")
        # AnalysisIncomplete carries its own detail, fitted to the byte budget
        # so the Go side never cuts a listing (C2); any other exception's
        # message is cut at the budget and made safe for a segment (C1).
        fitted = getattr(exc, "status_detail", None)
        if isinstance(fitted, str) and fitted:
            return ("failed", "execution_error", fitted)
        from analyzers import status_detail

        text = status_detail.clean(f"{type(exc).__name__}: {exc}", status_detail.DETAIL_BUDGET)
        return ("failed", "execution_error", text)


def _injection_support(stats: dict) -> StatusTuple:
    """Classify the injection check's outcome given the file counts the AST
    analyzer observed (ASTAnalyzer.file_stats).

    Taint analysis (the dataflow tracing in ast_analyzer.py) only understands
    Python's AST; JavaScript/TypeScript files fall back to regex heuristics
    that catch patterns but never trace dataflow. Reporting a JS-only tree as
    a plain "ok" would silently overstate coverage — the contract calls that
    unsupported_target instead, so a report can distinguish "checked and
    clean" from "not the kind of code this check understands". A mixed tree
    still gets a real taint pass over its Python files, so it stays "ok" with
    a detail noting the JS files got pattern checks only.

    `stats["excluded"]` (ASTAnalyzer.excluded) is what the analyzer left out
    of scope on purpose, each path with the evidence that says it is not the
    project's own code (D6'). It is appended to the detail as one segment that
    starts "declared out of scope, not scanned:", fitted to the byte budget
    and never cut (C1, C2), so nothing is excluded silently.
    """
    from analyzers import status_detail

    py = int(stats.get("python", 0))
    js = int(stats.get("javascript", 0))
    excluded = list(stats.get("excluded") or [])
    if py == 0 and js > 0:
        return (
            "skipped",
            "unsupported_target",
            status_detail.fit(
                lead=[f"{js} JavaScript/TypeScript file(s): pattern checks ran, taint analysis does not apply"],
                declared=excluded,
            )
            or None,
        )
    if js > 0:
        return (
            "ok",
            None,
            status_detail.fit(
                lead=[
                    f"{js} JavaScript/TypeScript file(s) got pattern checks only; "
                    f"taint analysis covered {py} Python file(s)"
                ],
                declared=excluded,
            )
            or None,
        )
    return ("ok", None, status_detail.fit(declared=excluded) or None)


def main() -> None:
    """Entry point: read ScanRequest from stdin, run checks, emit findings."""
    try:
        raw = sys.stdin.read()
        request = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        _log(f"invalid ScanRequest JSON: {exc}")
        print(json.dumps({"done": True, "total": 0, "error": str(exc)}), flush=True)
        sys.exit(2)

    # A top-level JSON array/scalar parses fine but isn't a ScanRequest object;
    # route it through the same done-line+error path instead of crashing with an
    # AttributeError and empty stdout (audit contract robustness).
    if not isinstance(request, dict):
        _log(f"ScanRequest must be a JSON object, got {type(request).__name__}")
        print(
            json.dumps(
                {
                    "done": True,
                    "total": 0,
                    "error": f"ScanRequest must be a JSON object, got {type(request).__name__}",
                }
            ),
            flush=True,
        )
        sys.exit(2)

    # `"checks": null` (explicit JSON null) yields None from .get with a default;
    # coerce to an empty list so the membership tests below never raise on a
    # non-iterable (audit contract robustness).
    checks = request.get("checks") or []
    code_path = request.get("code_path", "")
    spec_path = request.get("spec", "")
    language = request.get("language")
    verbose = bool(request.get("verbose", False))

    counter = 0

    # The interpreter floor (DE-03). The engine parses the scanned code with
    # the interpreter it runs on, so an interpreter that is too old either
    # cannot run the engine at all or cannot parse valid code. Below the
    # floor it reports itself: every requested check failed, nothing run,
    # exit 2. Between the floor and the newest grammar it says so on stderr,
    # and each file it cannot parse is lost evaluation naming the interpreter
    # (never a clean result).
    from analyzers import interpreter

    floor = interpreter.floor_error()
    if floor:
        _log(floor)
    elif interpreter.older_than_grammar():
        _log(
            f"python {interpreter.version_text()} is older than "
            f"{'.'.join(str(p) for p in interpreter.NEWEST_GRAMMAR)}: a file written in newer "
            "syntax cannot be parsed and is reported as lost evaluation, not as clean"
        )

    def emit_finding(f: dict) -> None:
        """Emit a single finding to stdout and increment the counter."""
        nonlocal counter
        counter += 1
        emit(f)

    # secrets and semgrep checks moved to native Go in TASK-115 / TASK-116
    # (internal/scanner/secrets/, internal/scanner/semgrep/). The Python
    # wrappers were deleted in TASK-118. Asking for them here is a no-op
    # — the Go path runs unconditionally when --code is set, regardless
    # of what shows up in the Python check list.
    if ("secrets" in checks or "semgrep" in checks) and verbose:
        print(
            "[fendix-engine] secrets/semgrep checks now run in Go (TASK-115/TASK-116) — "
            "ignoring Python request",
            file=sys.stderr,
            flush=True,
        )

    # Each analyzer is imported INSIDE its _run_check callable so a missing
    # optional dependency (e.g. PyYAML for the spec parser) skips just that
    # analyzer instead of killing the whole engine. See _run_check's docstring.
    injection_stats: dict = {}

    def _run_spec_auth() -> None:
        from analyzers.spec_parser import SpecParser

        SpecParser(spec_path).check_auth(emit_finding)

    def _run_injection() -> None:
        from analyzers.ast_analyzer import AnalysisIncomplete, ASTAnalyzer

        analyzer = ASTAnalyzer(code_path, language or "python")
        try:
            analyzer.run(emit_finding)
        except AnalysisIncomplete as exc:
            injection_stats["scope"] = analyzer.scope_payload()
            raise
        injection_stats.update(getattr(analyzer, "file_stats", {}))
        injection_stats["excluded"] = list(analyzer.excluded)
        injection_stats["scope"] = analyzer.scope_payload()

    def _run_deps() -> None:
        from analyzers.deps import DepsAnalyzer

        DepsAnalyzer(code_path).run(emit_finding)

    # This loop is the completeness guarantee behind protocol v2: every
    # expected check (auth/injection/deps) emits exactly one status line on
    # every path — not requested, missing input, or actually run — so the Go
    # side can tell "the Python engine chose to skip this" from "the Python
    # engine silently produced nothing" (a protocol violation under v2).
    for check_id, needs_input, missing_detail, label, fn in (
        ("auth", spec_path, "no spec supplied", "auth (spec)", _run_spec_auth),
        ("injection", code_path, "no code_path supplied", "injection (ast)", _run_injection),
        ("deps", code_path, "no code_path supplied", "deps", _run_deps),
    ):
        if check_id not in checks:
            _status(check_id, "skipped", "disabled_by_flag", "not in checks")
            continue
        if not needs_input:
            _status(check_id, "skipped", "not_applicable", missing_detail)
            continue
        if floor:
            _status(check_id, "failed", "execution_error", floor)
            continue
        state, reason, detail = _run_check(check_id, label, fn, verbose)
        if check_id == "injection" and state == "ok":
            # A clean run still needs classifying: a JavaScript-only tree got
            # pattern checks, not taint analysis, so "ok" would overstate
            # what was actually verified. See _injection_support's docstring.
            state, reason, detail = _injection_support(injection_stats)
        _status(
            check_id,
            state,
            reason,
            detail,
            injection_stats.get("scope") if check_id == "injection" else None,
        )

    if verbose:
        _log(f"engine completed {counter} findings")

    done: dict = {"done": True, "total": counter, "protocol": PROTOCOL_VERSION}
    if floor:
        done["error"] = floor
    print(json.dumps(done), flush=True)
    if floor:
        sys.exit(2)


if __name__ == "__main__":
    main()
