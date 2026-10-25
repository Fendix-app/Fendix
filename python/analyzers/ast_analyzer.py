"""AST analyzer — Python and JavaScript AST-based security analysis.

Performs deeper analysis than regex by parsing the abstract syntax tree
to detect security-relevant patterns like unsafe eval, exec, SQL construction,
and dangerous subprocess usage.

JavaScript analysis uses regex-backed heuristics since a full JS AST parser
is not a Python stdlib dependency.
"""

from __future__ import annotations

import ast
import os
import posixpath
import re
import sys
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Literal

# Skip directories (same as secrets analyzer)
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
    }
)

_MAX_FILE_BYTES = 1_048_576  # 1 MB

# Hard cap on taint-chain hops (F-H5b). A crafted "assignment bomb" — a long
# linear chain `a0 = source; a1 = a0; a2 = a1; ...; sink(aN)` — would otherwise
# drive `_trace_to_source` into deep recursion and a RecursionError. We cap the
# number of hops the walker takes (and therefore the emitted taint_chain
# length) so one hostile file can't abort the whole injection pass. The cap is
# comfortably above any real-world dataflow depth.
_MAX_TAINT_HOPS = 50

# Nodes that open a scope of their own. A call inside one runs in that scope,
# not in the enclosing function's, so the enclosing function's bindings must
# not resolve its arguments (a lambda or comprehension variable shadows them).
_SCOPE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)

# Sentinel distinguishing "this sink never depends on dataflow" from "this sink
# tried to prove dataflow and failed". _emit_finding cannot tell those apart
# from `taint_chain=None` alone, and they warrant very different confidence:
# `pickle.loads` is dangerous whatever reaches it, whereas `cursor.execute(x)`
# is only a vulnerability if `x` carries user input.
_CHAIN_NOT_ATTEMPTED = object()

# ---------------------------------------------------------------------------
# JavaScript heuristic patterns (regex-based; no JS AST required)
# ---------------------------------------------------------------------------

_JS_PATTERNS: list[tuple[str, str, re.Pattern[str], str, str, str]] = [
    (
        "JS_EVAL",
        "Unsafe use of eval() in JavaScript",
        re.compile(r"\beval\s*\("),
        "HIGH",
        "HIGH",
        "CWE-95",
    ),
    (
        "JS_INNER_HTML",
        "Unsafe assignment to innerHTML — XSS risk",
        re.compile(r"\.innerHTML\s*="),
        "HIGH",
        "MEDIUM",
        "CWE-79",
    ),
    (
        "JS_DOCUMENT_WRITE",
        "Unsafe use of document.write() — XSS risk",
        re.compile(r"\bdocument\.write\s*\("),
        "MEDIUM",
        "MEDIUM",
        "CWE-79",
    ),
    (
        "JS_SQL_TEMPLATE",
        "SQL query built via template literal — injection risk",
        re.compile(r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{"),
        "HIGH",
        "HIGH",
        "CWE-89",
    ),
]


class ASTAnalyzer:
    """Analyzes source code ASTs for security-relevant patterns.

    For Python files: uses the stdlib ``ast`` module.
    For JavaScript files: uses regex heuristics.
    Language is auto-detected by file extension if not explicitly specified.
    """

    def __init__(self, code_path: str, language: str = "python") -> None:
        """Initialize with root directory and optional language hint."""
        self.code_path = code_path
        self.language = language.lower() if language else "python"
        # Per-language file counts observed during `run`. engine.py reads
        # this after the walk to decide whether the injection check's
        # outcome is "ok" (taint analysis actually ran) or
        # "unsupported_target" (a JavaScript-only tree only got regex
        # heuristics) — see engine.py's _injection_support.
        self.file_stats: dict = {"python": 0, "javascript": 0}

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Walk code_path and emit findings for security patterns detected."""
        root = Path(self.code_path)
        if not root.exists():
            return

        # Proven Path v1: pre-pass builds a project-wide handler→route index
        # so a finding's sink can be bound to the route that reaches it —
        # even when the route is declared in urls.py and the view lives in a
        # different file (Django). Best-effort and metadata-only; a failure
        # here leaves binding off and never blocks the security pass.
        self._routes_by_func = self._build_route_index(root)

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname

                # F-L12: skip symlinked source FILES. os.walk already does not
                # follow symlinked DIRECTORIES (it lstat-walks, so a dir symlink
                # shows up in dirnames but is never descended into), but a
                # symlinked FILE is still yielded here and would be read —
                # surfacing out-of-tree file content (e.g. a /tmp link to
                # /etc/passwd) in 'evidence'. Mirror the Go textscan symlink
                # skip (internal/scanner/textscan): refuse symlinked files
                # unconditionally. islink() does not raise on a broken link.
                try:
                    if fpath.is_symlink():
                        continue
                except OSError:
                    continue

                rel = str(fpath.relative_to(root))

                if fpath.suffix == ".py":
                    self.file_stats["python"] += 1
                    self._analyze_python(fpath, rel, emit_fn)
                elif fpath.suffix in {".js", ".ts", ".jsx", ".tsx"}:
                    self.file_stats["javascript"] += 1
                    self._analyze_js_heuristic(fpath, rel, emit_fn)

    def _build_route_index(self, root: Path):
        """Walk the tree once and merge every file's routes into one
        function-name → Route index. Keyed on the handler function's name so
        a Django urls.py route binds to its view defined elsewhere. Returns a
        RouteTable; on any import/IO failure returns an empty one (binding
        simply stays off)."""
        try:
            from analyzers.route_extractor import RouteTable, extract_routes
        except Exception:  # noqa: BLE001 — binding is optional
            return None
        index = RouteTable()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(dirpath) / fname
                try:
                    if fpath.is_symlink() or fpath.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    src = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel = str(fpath.relative_to(root))
                try:
                    routes = extract_routes(src, rel).routes
                except (RecursionError, Exception):  # noqa: BLE001 — binding is best-effort
                    # audit #18: one crafted/large file must not abort the
                    # route index (and thus the whole injection pass). Skip it.
                    continue
                for route in routes:
                    index.add(route)
        return index

    # ------------------------------------------------------------------
    # Python AST analysis
    # ------------------------------------------------------------------

    def _analyze_python(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Parse and analyze a Python file's AST."""
        try:
            if filepath.stat().st_size > _MAX_FILE_BYTES:
                return
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(filepath))
        except (OSError, SyntaxError):
            return

        # F-H5b: isolate the per-file AST walk. A crafted file (deeply nested
        # expression, a recursive node shape ast.parse accepted, or any other
        # visitor edge case) could raise RecursionError or another exception
        # mid-walk. Without this guard that single hostile file would abort the
        # whole os.walk in `run()` and zero findings would be reported for the
        # rest of the tree. Catch, log to stderr, and continue to the next file
        # — findings already emitted for this file stay emitted (emit_fn is
        # called incrementally), and the engine still exits cleanly.
        visitor = _PythonSecurityVisitor(
            source.splitlines(),
            rel,
            emit_fn,
            route_table=getattr(self, "_routes_by_func", None),
        )
        visitor._module_root = tree  # enable 1-hop interprocedural call-site index
        try:
            visitor.visit(tree)
        except RecursionError:
            print(
                f"[fendix-engine] ast_analyzer: recursion limit hit on {rel}; "
                "skipping rest of file",
                file=sys.stderr,
            )
        except Exception as exc:  # noqa: BLE001 — never let one file abort the pass
            print(
                f"[fendix-engine] ast_analyzer: failed to analyze {rel}: {exc}",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------
    # JavaScript heuristic analysis
    # ------------------------------------------------------------------

    def _analyze_js_heuristic(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Apply regex heuristics to a JavaScript/TypeScript file."""
        try:
            if filepath.stat().st_size > _MAX_FILE_BYTES:
                return
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        lines = source.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if len(line) > 500:  # skip minified lines
                continue
            for pat_id, title, pattern, severity, confidence, cwe in _JS_PATTERNS:
                if pattern.search(line):
                    emit_fn(
                        {
                            "id": f"SEC-{pat_id}",
                            # Identity is rule=<this string> today (the Go side
                            # falls back to a non-positional `id`), so rule_id
                            # must be the id VERBATIM or every JS-pattern
                            # fingerprint in an existing baseline moves. See
                            # TestJSPatternFingerprintUnchanged.
                            "rule_id": f"SEC-{pat_id}",
                            "title": title,
                            "severity": severity,
                            "source": "whitebox",
                            "category": "injection",
                            "endpoint": f"{rel}:{lineno}",
                            "evidence": line.strip()[:200],
                            "fix": _JS_FIX.get(
                                pat_id, "Review and sanitize this usage."
                            ),
                            "references": [cwe],
                            "confidence": confidence,
                            "line": f"{rel}:{lineno}",
                        }
                    )


# Fixes for JS patterns
_JS_FIX: dict[str, str] = {
    "JS_EVAL": (
        "Replace eval() with safer alternatives. Never pass user-controlled input to eval()."
    ),
    "JS_INNER_HTML": (
        "Use textContent or createElement() instead of innerHTML. "
        "If HTML is required, sanitize with DOMPurify."
    ),
    "JS_DOCUMENT_WRITE": (
        "Replace document.write() with DOM manipulation methods like "
        "document.createElement() and appendChild()."
    ),
    "JS_SQL_TEMPLATE": (
        "Use parameterized queries or an ORM instead of building SQL with template literals."
    ),
}


# ---------------------------------------------------------------------------
# Python AST visitor
# ---------------------------------------------------------------------------


class _PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor that emits findings for dangerous Python patterns."""

    def __init__(
        self,
        source_lines: list[str],
        rel_path: str,
        emit_fn: Callable[[dict], None],
        route_table=None,
    ) -> None:
        self._lines = source_lines
        self._rel = rel_path
        self._emit = emit_fn
        # Proven Path v1: route table for this file (or None). When a finding
        # with a taint chain sits inside a registered handler, we bind the
        # route so the report can show route → handler → sink. None disables
        # binding (findings emit exactly as before).
        self._route_table = route_table
        # Stack of variable-assignment scopes. Outermost element is module
        # scope; each FunctionDef pushes a new scope. Used by `_is_sql_injection`
        # to resolve `cursor.execute(name)` to the value `name` was assigned —
        # closes the multi-step string-concat SQLi gap (TASK-087).
        self._scopes: list[dict[str, ast.AST]] = [{}]
        # Stack of enclosing FunctionDef nodes — used by the whitelist-
        # sanitiser scan to find membership guards earlier in the same
        # function body. Top of stack is the innermost function being
        # visited.
        self._func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        # Maps local alias → canonical module name, populated by visit_Import.
        # Lets `import pickle as p; p.loads(data)` be detected despite the alias.
        self._module_aliases: dict[str, str] = {}
        # 1-hop interprocedural taint: func-name → call sites in this file
        # (built lazily on first need). When a sink uses a function PARAMETER
        # whose taint must come from a caller, we check whether any call site
        # passes a tainted argument at that parameter's position/keyword. Bounded
        # to a SINGLE hop (we don't recurse into the caller's callers).
        self._callsite_index: dict | None = None
        # Each def, lambda, class and comprehension node → the scope node it
        # sits in (the module at the top). Filled with the call-site index.
        self._scope_parents: dict[ast.AST, ast.AST] = {}
        # The callers' own bindings for that hop: the module node and each def
        # node → the bindings made in its scope, in source order (see
        # `_build_function_bindings`). Keyed by node, so same-named functions
        # never share bindings. Built lazily, once per file, from _module_root.
        self._function_bindings: (
            dict[ast.AST, list[tuple[tuple[int, int], str, ast.AST]]] | None
        ) = None
        self._interproc_depth: int = 0
        self._module_root = None  # set in _analyze_python before the walk
        # Maps a bare local name → (module, symbol), populated by
        # visit_ImportFrom. Lets `from os import system; system(cmd)` and
        # `from pickle import loads as pl; pl(x)` resolve back to os.system /
        # pickle.loads despite the call being a bare ast.Name (audit #8-13).
        self._from_imports: dict[str, tuple[str, str]] = {}
        # `os.path.join(...)` calls written as the direct argument of a path
        # resolution (`realpath(join(...))`, `Path(join(...)).resolve()`),
        # mapped to that resolving call. `_note_resolved_join` records them
        # when the enclosing call is visited, which is always before the join.
        self._resolved_joins: dict[ast.Call, ast.Call] = {}

    def _line_text(self, lineno: int) -> str:
        """Return the source line (1-indexed), or empty string."""
        if 1 <= lineno <= len(self._lines):
            return self._lines[lineno - 1].strip()[:200]
        return ""

    def _emit_finding(
        self,
        pat_id: str,
        title: str,
        severity: str,
        confidence: str,
        cwe: str,
        fix: str,
        lineno: int,
        category: str = "injection",
        taint_chain=_CHAIN_NOT_ATTEMPTED,
        proven_title: str | None = None,
        proven_severity: str | None = None,
        sink: str | None = None,
    ) -> None:
        finding: dict = {
            "id": f"SEC-{pat_id}",
            # The rule that fired, stated explicitly. It used to live only
            # inside `id`, which the identity layer had to parse — and that
            # worked only because "SEC-PY_SSRF" happens not to look like the
            # orchestrator's positional "SEC-001" counter. Identity should not
            # rest on a naming coincidence.
            "rule_id": f"python.ast/{pat_id}",
            "title": title,
            "severity": severity,
            "source": "whitebox",
            # Proven Path v1: this AST taint analyzer is the tree-sitter
            # sidecar tier — the highest-trust SAST tier. Preserved
            # end-to-end so the correlator can weight it above semgrep_shim
            # and the F1 gate can't be bypassed via correlation.
            "source_tier": "tree_sitter_sidecar",
            "category": category,
            "endpoint": f"{self._rel}:{lineno}",
            "evidence": self._line_text(lineno),
            "fix": fix,
            "references": [cwe],
            "confidence": confidence,
            "line": f"{self._rel}:{lineno}",
        }
        # Test-file demotion: a finding in test/fixture code is almost always
        # exercising the sink deliberately, not a production vulnerability.
        # Keep it (a real bug in a test helper still surfaces) but force LOW
        # confidence and tag it so the report sorts it below real findings and
        # the correlator won't escalate it. Real-data corpus showed 98-100% of
        # clean-library noise lives in tests/.
        if _is_test_path(self._rel):
            finding["confidence"] = "LOW"
            finding["in_test"] = True
        # Reachability-dependent sink with NO proven source->sink path: this is
        # a SHAPE match, not a proof, and it must not claim the confidence of
        # one. Measured over 216K LOC of real OSS (flask, requests, httpx,
        # fastapi, django-cms), every one of the 19 findings the taint analyzer
        # produced was chainless — and roughly 13 of the 14 outside test code
        # were false positives on developer-controlled input: `config.from_pyfile`,
        # `setup.py` reading its own version file, a PYTHONSTARTUP hook, docs
        # examples, CI scripts. They were reported at the same HIGH/CRITICAL as
        # a proven exploit path.
        #
        # Dropping HIGH to MEDIUM here feeds the existing severity cap
        # (models.MaxSeverityForConfidence: MEDIUM caps at HIGH), so an
        # unproven SQLi lands at HIGH instead of CRITICAL while a proven one
        # keeps CRITICAL. Evidence is preserved and nothing is suppressed
        # (Rule 3) — only the strength of the claim changes.
        #
        # A test-path finding is already forced to LOW above; never raise it.
        attempted_chain = taint_chain is not _CHAIN_NOT_ATTEMPTED
        chain = None if not attempted_chain else taint_chain
        if attempted_chain and not chain and finding["confidence"] == "HIGH":
            finding["confidence"] = "MEDIUM"

        # RC-6: the wording is a function of the evidence, decided here rather
        # than at each call site, because here is the only place that knows
        # whether the chain was proven. A reachability-dependent finding
        # arrives with the HEDGED title in `title` and, when it has one, the
        # proven wording in `proven_title`; the hedged form is what ships
        # unless a chain was actually collected.
        #
        # Both forms are pure presentation. Identity is keyed on rule, file,
        # symbol and sink (models.Fingerprint), so a finding that strengthens
        # from "Potential SSRF" to "SSRF" keeps the record it already had
        # instead of being filed as a new vulnerability.
        if chain and proven_title:
            finding["title"] = proven_title

        # Some rules need the SEVERITY to follow the evidence too, not just the
        # wording. Path traversal is the case that forced this: a dynamic path
        # reaching `open()` is a shape, and shipping it at the same severity as
        # a proven request→filesystem flow let an unproven observation reach a
        # blocking threshold on evidence that never established external
        # control.
        #
        # A rule that wants this passes the WEAK severity in `severity` and the
        # proven one in `proven_severity`, exactly mirroring title/proven_title,
        # so the escalate-on-proof rule lives in one place instead of at each
        # call site. Rules that omit it are unaffected.
        #
        # Severity is presentation to the identity layer (models.Fingerprint
        # keys on rule, file, symbol and sink), so strengthening here cannot
        # re-file the finding as a new vulnerability.
        if chain and proven_severity:
            finding["severity"] = proven_severity

        # The vulnerable OPERATION, emitted whether or not the flow was
        # proven. It is what the fingerprint keys on, and the analyzer builds
        # the same string in both cases — withholding it on the unproven half
        # forced identity to fall back to the evidence text, so an analyzer
        # that later proved the flow re-filed the finding as a new
        # vulnerability. Falls back to the chain's own sink for callers that
        # prove a chain without naming one.
        if sink:
            finding["sink"] = sink
        elif chain:
            finding["sink"] = chain[-1].get("expr", "")

        # The enclosing function, emitted unconditionally. It is the other
        # half of the operation's identity, and it must NOT be read off the
        # bound route below: a route is bound only when a chain was proven AND
        # the function is a registered handler, so a symbol taken from there
        # appears and disappears with the proof. The function stack knows the
        # enclosing function either way.
        if self._func_stack:
            finding["symbol"] = self._func_stack[-1].name

        if chain:
            # TASK-114: when the visitor proves user input flows from a
            # source (request.args/POST/form/etc.) through one or more
            # intra-function assignments to this sink, attach the chain
            # so the correlator can escalate severity and the report
            # surfaces *why* this is a real exploit path. Each entry is
            # {file, line, expr}; the engine treats this as opaque metadata.
            finding["taint_chain"] = chain
            finding["reachable"] = True
            # Proven Path v1: bind the route that reaches this sink, when the
            # enclosing function is a registered handler. route → handler →
            # source→sink chain is the v1 proof.
            route = self._bound_route()
            if route is not None:
                finding["route"] = route.as_dict()
        self._emit(finding)

    def _bound_route(self):
        """Return the Route whose handler is the innermost enclosing
        function, or None when there's no route table or no match."""
        if self._route_table is None or not self._func_stack:
            return None
        func_name = self._func_stack[-1].name
        return self._route_table.for_function(func_name)

    # ------------------------------------------------------------------
    # Taint-chain helpers (TASK-114)
    # ------------------------------------------------------------------

    def _collect_taint_chain(
        self, sink_arg: ast.AST, sink_lineno: int, sink_expr: str, extra_source=None
    ) -> list[dict] | None:
        """Walk back from ``sink_arg`` through scope assignments to a request source.

        Returns an ordered chain (source first, sink last) when reachable,
        else None. The walker recurses through complex assignments — a
        chain like ``q = request.args.get('q'); sql = '...' + q;
        cursor.execute(sql)`` resolves via two hops: first ``sql`` ->
        BinOp containing Name ``q``, then ``q`` -> Call referencing
        ``request.args``.

        Each link is ``{"file": str, "line": int, "expr": str}``.
        """
        # Inline case: the sink's argument is itself a request-input
        # reference (no intermediate variables). The chain is two links:
        # source @ sink-lineno → sink @ sink-lineno.
        if _is_taint_source(sink_arg, extra_source):
            return [
                self._link(sink_lineno, _ast_expr_text(sink_arg)),
                self._link(sink_lineno, sink_expr),
            ]

        prefix = self._trace_to_source(sink_arg, frozenset(), 0, extra_source)
        if prefix is None:
            return None
        # Cap the emitted chain length too (F-H5b). The `visited` set already
        # bounds the prefix to the number of distinct Names, but a crafted file
        # could declare thousands of distinct intermediates; trim to the most
        # recent _MAX_TAINT_HOPS links (source-first ordering preserved) so the
        # taint_chain stays small and the report/IPC line stays well under the
        # 1MiB readFindings cap.
        chain = prefix + [self._link(sink_lineno, sink_expr)]
        if len(chain) > _MAX_TAINT_HOPS:
            chain = chain[-_MAX_TAINT_HOPS:]
        return chain

    def _trace_to_source(
        self, expr: ast.AST, visited: frozenset[str], depth: int, extra_source=None
    ) -> list[dict] | None:
        """Recursively trace Names in ``expr`` through scope assignments.

        Returns the chain prefix (oldest assignment first) up to and
        including the assignment that introduced the request source.
        ``visited`` guards against assignment cycles (``a = b; b = a``).
        ``depth`` is the current hop count; once it reaches
        ``_MAX_TAINT_HOPS`` we stop descending and return None cleanly
        (F-H5b) so a long linear assignment chain can't drive Python into a
        RecursionError. Returning None just means "no proven source within
        the hop budget" — the sink still emits, only without a taint_chain.

        A Name with no binding in scope may be a parameter of the enclosing
        function whose taint comes from a caller (audit recall gap; benchmark
        cmdi-interprocedural): `_param_is_tainted_via_caller` tries one hop.
        """
        return self._trace_names(
            expr,
            self._scope_binding,
            visited,
            depth,
            extra_source,
            self._param_is_tainted_via_caller,
        )

    def _trace_in_bindings(
        self,
        expr: ast.AST,
        bindings: dict[str, ast.AST],
        visited: frozenset[str],
        depth: int,
        extra_source=None,
    ) -> list[dict] | None:
        """`_trace_to_source` over a caller's ``bindings`` instead of the
        scopes being visited. A Name the bindings do not hold (a parameter of
        the caller, a global) ends the trace: that is the single hop, and the
        caller's own callers are never searched."""
        return self._trace_names(expr, bindings.get, visited, depth, extra_source, None)

    def _scope_binding(self, key: str) -> ast.AST | None:
        """The value `key` is bound to in the scopes being visited, innermost
        first (audit #17), or None."""
        for scope in reversed(self._scopes):
            if key in scope:
                return scope[key]
        return None

    def _trace_names(
        self,
        expr: ast.AST,
        lookup: Callable[[str], ast.AST | None],
        visited: frozenset[str],
        depth: int,
        extra_source,
        on_unbound_name: Callable[..., list[dict] | None] | None,
    ) -> list[dict] | None:
        """The walk behind `_trace_to_source` and `_trace_in_bindings`: resolve
        every Name, and attribute/subscript read bound via `_bind_target`
        (``self.q``, ``d['k']``, audit #26/#27), with ``lookup``, following
        each binding back until one references a source.
        ``on_unbound_name(name, extra_source, depth)``, when given, is asked
        about a bare Name that ``lookup`` does not resolve."""
        if depth >= _MAX_TAINT_HOPS:
            return None
        for n in ast.walk(expr):
            key = None
            if isinstance(n, ast.Name):
                key = n.id
            elif isinstance(n, (ast.Attribute, ast.Subscript)):
                key = _binding_key(n)
            if key is None or key in visited:
                continue
            assigned = lookup(key)
            if assigned is not None:
                lineno = getattr(assigned, "lineno", 0)
                link = self._link(lineno, _ast_expr_text(assigned))
                if _is_taint_source(assigned, extra_source):
                    return [link]
                deeper = self._trace_names(
                    assigned,
                    lookup,
                    visited | {key},
                    depth + 1,
                    extra_source,
                    on_unbound_name,
                )
                if deeper is not None:
                    return deeper + [link]
                # Binding resolved but didn't lead to a source; this key is
                # settled, move on to the next Name.
                continue
            if on_unbound_name is not None and isinstance(n, ast.Name):
                inter = on_unbound_name(n.id, extra_source, depth)
                if inter is not None:
                    return inter
        return None

    def _build_callsite_index(self) -> dict[str, list[tuple[ast.Call, ast.AST]]]:
        """Index every `name(...)` call in the file by callee name (1-hop
        interprocedural taint), each with the scope the call runs in: the
        innermost enclosing def, lambda, class or comprehension, else the
        module. Built once from the module root captured by the visitor;
        bare-name callees only (the common helper-call shape). Call sites keep
        `ast.walk`'s breadth-first order. Also records `self._scope_parents`."""
        index: dict[str, list[tuple[ast.Call, ast.AST]]] = {}
        root = self._module_root
        if root is None:
            return index
        queue = deque([(root, root)])
        while queue:
            node, scope = queue.popleft()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                index.setdefault(node.func.id, []).append((node, scope))
            if node is not root and isinstance(node, _SCOPE_NODES):
                self._scope_parents[node] = scope
                scope = node
            queue.extend((child, scope) for child in ast.iter_child_nodes(node))
        return index

    def _build_function_bindings(
        self,
    ) -> dict[ast.AST, list[tuple[tuple[int, int], str, ast.AST]]]:
        """Map the module and every def in it to the bindings made directly in
        its own scope, for the 1-hop caller check.

        Each binding is ``(position, key, value)``, sorted by ``position``: the
        point after which the binding is visible. That is the end of an
        assignment, so ``x = f(x)`` still passes the old ``x`` to ``f``, and
        the end of a ``for`` iterable or a ``with`` context expression, so the
        loop or block body sees its target. Keyed by node, never by name, so
        two same-named methods keep separate bindings. An assignment inside a
        nested def, lambda or class belongs to that scope alone.

        Targets are bound with the visitor's own rules (`_bind_target`, and
        ``x += v`` as a BinOp over the prior value, located at the ``+=`` so its
        link keeps the line), plus annotated assignments with a value."""
        root = self._module_root
        if root is None:
            return {}
        return {
            scope: self._scope_bindings(scope)
            for scope in ast.walk(root)
            if scope is root
            or isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

    def _scope_bindings(
        self, scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[tuple[int, int], str, ast.AST]]:
        """The bindings `_build_function_bindings` records for one scope."""
        steps: list[tuple[tuple[int, int], ast.AST]] = []
        for stmt in scope.body:
            for n in _same_scope_nodes(stmt):
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    steps.append((_end_position(n), n))
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    steps.append((_end_position(n.iter), n))
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    steps.extend(
                        (_end_position(item.context_expr), item)
                        for item in n.items
                        if item.optional_vars is not None
                    )
        steps.sort(key=lambda step: step[0])
        current: dict[str, ast.AST] = {}
        bindings: list[tuple[tuple[int, int], str, ast.AST]] = []
        for position, n in steps:
            bound: dict[str, ast.AST] = {}
            if isinstance(n, ast.Assign):
                for target in n.targets:
                    self._bind_target(target, n.value, bound)
            elif isinstance(n, ast.AnnAssign):
                if n.value is not None:
                    self._bind_target(n.target, n.value, bound)
            elif isinstance(n, ast.AugAssign):
                key = _binding_key(n.target)
                if key is not None:
                    prior = current.get(key, n.target)
                    bound[key] = ast.copy_location(
                        ast.BinOp(left=prior, op=n.op, right=n.value), n
                    )
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                self._bind_target(n.target, n.iter, bound)
            else:  # ast.withitem
                self._bind_target(n.optional_vars, n.context_expr, bound)
            current.update(bound)
            bindings.extend((position, key, value) for key, value in bound.items())
        return bindings

    def _bindings_before(self, scope: ast.AST, call: ast.Call) -> dict[str, ast.AST]:
        """`{key: value}` for `scope` as it stands when `call` runs: for every
        key, the last binding that takes effect at or before the call's start,
        in source order. The same rule applies to every name the trace meets,
        as `self._scopes` does at a sink. A lambda, class or comprehension
        scope records no bindings, so only an inline source proves there."""
        if self._function_bindings is None:
            self._function_bindings = self._build_function_bindings()
        at = (call.lineno, call.col_offset)
        bindings: dict[str, ast.AST] = {}
        for position, key, value in self._function_bindings.get(scope, ()):
            if position > at:
                break
            bindings[key] = value
        return bindings

    def _caller_args(
        self, param_name: str
    ) -> Iterator[tuple[ast.Call, ast.AST, ast.AST]]:
        """Yield ``(call, scope, arg)`` for every call in this file of the
        innermost enclosing function that passes an argument for its parameter
        ``param_name``: the positional argument at the parameter's index, or
        the keyword of that name. ``scope`` is where the call runs (see
        `_build_callsite_index`). Yields nothing once a hop is under way
        (`_interproc_depth`): one hop, never into the caller's callers.

        A method is never the callee of a bare-name call, which reaches a
        function of that name instead, so a method has no callers here."""
        if self._interproc_depth >= 1 or not self._func_stack:
            return
        func = self._func_stack[-1]
        params = [a.arg for a in func.args.posonlyargs + func.args.args]
        if param_name not in params:
            return
        idx = params.index(param_name)
        if self._callsite_index is None:
            self._callsite_index = self._build_callsite_index()
        if isinstance(self._scope_parents.get(func), ast.ClassDef):
            return
        for call, scope in self._callsite_index.get(func.name, []):
            arg = None
            if idx < len(call.args):
                arg = call.args[idx]
            else:
                for kw in call.keywords:
                    if kw.arg == param_name:
                        arg = kw.value
                        break
            if arg is not None:
                yield call, scope, arg

    def _param_is_tainted_via_caller(
        self, param_name: str, extra_source, depth: int
    ) -> list[dict] | None:
        """1-hop interprocedural: if `param_name` is a parameter of the enclosing
        function, return a taint-chain prefix when ANY call site of that function
        in this file passes a tainted argument at the matching position/keyword.

        The argument is tainted when it is request input itself, or when it
        traces to request input through the CALLER's bindings as they stand at
        the call (`_bindings_before`). The trace starts with a fresh `visited`:
        the caller's names are not the helper's. Its prefix runs from the
        caller's request expression through the caller's assignments to the
        call. Single hop — the caller's own parameters are not traced into the
        caller's callers.

        A caller whose argument a sanitiser of the direct path accepts proves
        nothing (`_caller_arg_is_sanitised`): the hop must not prove what the
        same code written inline would not."""
        for call, scope, arg in self._caller_args(param_name):
            self._interproc_depth += 1
            try:
                prefix = self._caller_arg_chain(call, scope, arg, extra_source, depth)
            finally:
                self._interproc_depth -= 1
            if prefix is not None:
                return prefix
        return None

    def _caller_arg_chain(
        self, call: ast.Call, scope: ast.AST, arg: ast.AST, extra_source, depth: int
    ) -> list[dict] | None:
        """The chain prefix one caller's argument proves, or None: the
        argument as an inline source, or traced through the caller's bindings
        before the call and followed by the call itself. None as well when a
        sanitiser accepts the argument in the caller."""
        if _is_taint_source(arg, extra_source):
            prefix = [self._link(call.lineno, _ast_expr_text(arg))]
        else:
            prefix = self._trace_in_bindings(
                arg,
                self._bindings_before(scope, call),
                frozenset(),
                depth + 1,
                extra_source,
            )
            if prefix is None:
                return None
            prefix = prefix + [self._link(call.lineno, _ast_expr_text(call))]
        if self._caller_arg_is_sanitised(scope, call, arg):
            return None
        return prefix

    def _caller_arg_is_sanitised(
        self, scope: ast.AST, call: ast.Call, arg: ast.AST
    ) -> bool:
        """True when any sanitiser a direct sink honours accepts `arg` where
        the caller passes it: a dict/collection allowlist lookup, an escaping
        call, a safe URL builder, a membership guard or a `urlparse(...).netloc`
        allowlist guard (`_arg_is_sanitised` with `url_sink`), a fully escaped
        HTML expression (`_expr_is_fully_escaped`), path containment
        (`_path_is_contained`), or a URL whose scheme and host are fixed
        (`_url_authority_is_constant`).

        The hop does not know which sink the helper holds, so it takes the
        union of every sink's sanitisers: a sanitised argument leaves the
        helper's finding unproven rather than proven. Guards must dominate the
        call, exactly as they must dominate a sink."""
        with self._caller_context(scope, call):
            return (
                self._arg_is_sanitised(arg, call.lineno, url_sink=True)
                or self._expr_is_fully_escaped(arg)
                or self._path_is_contained(arg, call.lineno)
                or self._url_authority_is_constant(arg)
            )

    @contextmanager
    def _caller_context(self, scope: ast.AST, call: ast.Call):
        """Visit `call` as the direct path would when it reaches the call: the
        caller's enclosing defs as `self._func_stack`, and the module's and
        those defs' bindings before the call as `self._scopes`. The sanitiser
        predicates take the function being visited and the bindings in scope
        from these two, so they run unchanged in the caller. Restored on
        exit."""
        defs = self._enclosing_defs(scope)
        saved = self._func_stack, self._scopes
        self._func_stack = defs
        self._scopes = [
            self._bindings_before(s, call) for s in (self._module_root, *defs)
        ]
        try:
            yield
        finally:
            self._func_stack, self._scopes = saved

    def _enclosing_defs(
        self, scope: ast.AST
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """The defs that code in `scope` runs inside, outermost first, as
        `self._func_stack` holds them while that code is visited: `scope`
        itself when it is a def, and every def around it."""
        defs = []
        node = scope
        while node is not None and node is not self._module_root:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs.append(node)
            node = self._scope_parents.get(node)
        return defs[::-1]

    def _resolve_param_to_caller_arg(self, param_name: str) -> ast.AST | None:
        """1-hop: if `param_name` is a parameter of the enclosing function and a
        call site passes a NON-CONSTANT argument at that position/keyword, return
        that argument expression (so shape-based sink predicates can inspect what
        the caller actually passes). Returns None if no caller, or all callers
        pass constants. Single hop; no recursion into callers' callers."""
        for _call, _scope, arg in self._caller_args(param_name):
            if not isinstance(arg, ast.Constant):
                return arg
        return None

    def _name_is_enclosing_param(self, name: str) -> bool:
        """True if `name` is a parameter of the innermost enclosing function."""
        if not self._func_stack:
            return False
        func = self._func_stack[-1]
        a = func.args
        params = (
            a.posonlyargs
            + a.args
            + a.kwonlyargs
            + ([a.vararg] if a.vararg else [])
            + ([a.kwarg] if a.kwarg else [])
        )
        return any(p.arg == name for p in params)

    def _name_is_safe_object_param(self, name_node: ast.Name) -> bool:
        """True if `name_node` is an enclosing-function parameter that does NOT
        reference request input (directly or via a caller arg at this 1 hop).

        Used to trust attribute reads like `<param>.name` on objects the caller
        constructed (file handles, tempfile objects). It deliberately does not
        trust the parameter as a raw path *string* — only object-attribute
        access through it — so a `def f(path): open(path)` traversal still
        fires (that path is checked directly, not via this helper)."""
        if not self._name_is_enclosing_param(name_node.id):
            return False
        # If a visible call site passes request input into this parameter, the
        # object is attacker-influenced — do not trust it.
        caller_arg = self._resolve_param_to_caller_arg(name_node.id)
        if caller_arg is not None and _references_request_input(caller_arg):
            return False
        return True

    def _link(self, lineno: int, expr: str) -> dict:
        return {"file": self._rel, "line": int(lineno), "expr": expr}

    # ─── sanitiser recognition (surfaced by Track 4 heavy-eval) ─────
    #
    # Two real-world sanitiser shapes the engine learned to recognise:
    #
    #   shape 1 — dict-lookup whitelist:
    #       allowed = {"a": "/A", "b": "/B"}
    #       return open(allowed.get(name, "/dev/null")).read()    # SAFE
    #       return redirect(allowed[user_choice])                  # SAFE
    #
    #   shape 2 — set-membership guard:
    #       allowed = {"/home", "/profile"}
    #       if target not in allowed:
    #           return redirect("/")
    #       return redirect(target)                                # SAFE
    #
    # Both forms are flagged-as-tainted by the pure-taint-chain
    # detector because user input does flow to the sink. The
    # sanitiser pass below recognises the explicit AST shape of the
    # whitelist and suppresses the finding.
    #
    # We deliberately keep the recognition narrow — only literal
    # set/dict/list collections count as whitelists. A whitelist
    # built from an env var or another function call would still
    # flag, because we can't prove it's bounded.

    def _arg_is_whitelisted_lookup(self, arg: ast.AST) -> bool:
        """Return True if `arg` is `<const_collection>.get(x[, default])`
        or `<const_collection>[x]` and the collection resolves to a
        literal dict/list in the current scope chain (or `arg` is a
        literal dict/list construction itself).
        """
        # Direct: allowed.get(name) or allowed[name]
        target_name: str | None = None
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "get"
            and isinstance(arg.func.value, ast.Name)
        ):
            target_name = arg.func.value.id
        elif isinstance(arg, ast.Subscript) and isinstance(arg.value, ast.Name):
            target_name = arg.value.id
        if target_name is None:
            return False
        # Resolve through scope chain — innermost wins
        for scope in reversed(self._scopes):
            if target_name in scope:
                assigned = scope[target_name]
                return isinstance(assigned, (ast.Dict, ast.Set, ast.List, ast.Tuple))
        return False

    def _name_is_membership_guarded(self, name: str, sink_line: int) -> bool:
        """Return True if the innermost enclosing FunctionDef body contains an
        early-return guard of the shape ``if <name> not in <const_collection>:
        return/raise/abort`` that DOMINATES the sink at ``sink_line``.

        B2 (guard-dominance, both directions): the guard must be a top-level
        (function-body) statement whose ``lineno`` precedes the sink. The old
        ``ast.walk(func)`` matched ANY such guard anywhere in the function —
        including a guard AFTER the sink or inside a non-dominating branch
        (``if strict:``) — which over-suppressed real vulns (FN). Iterating
        only ``func.body`` and gating on ``stmt.lineno < sink_line`` fixes both:
        a nested guard never appears in the body-only loop, and a later guard
        is line-gated out.
        """
        if not self._func_stack:
            return False
        func = self._func_stack[-1]
        for stmt in func.body:
            if not isinstance(stmt, ast.If):
                continue
            # Dominance: the guard must appear textually BEFORE the sink. A
            # guard after the sink (or in a non-top-level branch, which never
            # enters this body-only loop) cannot constrain it.
            if stmt.lineno >= sink_line:
                continue
            test = stmt.test
            # `if X not in C:` or `if not (X in C):` shape
            checked_name: str | None = None
            collection: ast.AST | None = None
            if (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.NotIn)
                and isinstance(test.left, ast.Name)
            ):
                checked_name = test.left.id
                collection = test.comparators[0] if test.comparators else None
            elif (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Compare)
                and len(test.operand.ops) == 1
                and isinstance(test.operand.ops[0], ast.In)
                and isinstance(test.operand.left, ast.Name)
            ):
                checked_name = test.operand.left.id
                collection = (
                    test.operand.comparators[0] if test.operand.comparators else None
                )
            if checked_name != name or collection is None:
                continue
            if not self._collection_is_literal(collection):
                continue
            # Check the if-body ends control flow — return/raise/abort
            if any(
                isinstance(s, (ast.Return, ast.Raise))
                or (
                    isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Call)
                    and (
                        (
                            isinstance(s.value.func, ast.Name)
                            and s.value.func.id in {"abort", "exit"}
                        )
                        or (
                            isinstance(s.value.func, ast.Attribute)
                            and s.value.func.attr in {"abort", "exit"}
                        )
                    )
                )
                for s in stmt.body
            ):
                return True
        return False

    # URL-host allowlist guard (SSRF / open redirect only):
    #
    #     p = urlparse(url)
    #     if p.scheme != "https" or p.netloc not in ALLOWED_HOSTS:
    #         return ...
    #     requests.get(url)                                       # SAFE
    #
    # Falling through the guard means the URL's authority is exactly one of a
    # literal set, so the request or redirect cannot reach a host the attacker
    # chose. This bounds the HOST and nothing else (the path and query stay
    # free-form), so it is honoured only for sinks whose risk is the
    # destination host; an XSS or path sink given the same value is still
    # reported. The parse call is matched on its terminal name, covering
    # `urllib.parse.urlparse(x)`, `from urllib.parse import urlparse` and
    # `urlsplit` in either form.
    #
    # DELIBERATELY ABSENT: `.hostname`. urlparse and the clients disagree on
    # the host of an authority holding a backslash:
    # `http://169.254.169.254\@api.example.com/` has urlparse hostname
    # `api.example.com`, but urllib3/requests and browsers (which read `\` as
    # `/`) go to 169.254.169.254. `.netloc` is the whole authority, so an exact
    # match against a set of bare hosts leaves no room for userinfo, a
    # backslash or a port.
    #
    # Two more limits keep the guard honest:
    #   * An allowlist holding "" is not a host guard: `/\evil.com` and
    #     `https:evil.com` have netloc "", and browsers send both to evil.com.
    #   * The guard describes the whole URL string, so `_arg_is_sanitised`
    #     honours it only for the sink argument itself or the LEFTMOST operand
    #     of a `+` (`url + "/v1"` keeps the host). A URL built around it
    #     (`"https://" + url`, `"https://%s" % url`) can name another host:
    #     `evil.com://api.example.com/x` has netloc api.example.com.
    _URL_PARSE_CALL_NAMES = frozenset({"urlparse", "urlsplit"})

    def _url_host_is_allowlisted(self, name: str, sink_line: int) -> bool:
        """Return True if the innermost enclosing function body contains a
        DOMINATING early-exit guard that rejects `name` unless its parsed
        authority is in a literal collection::

            if urlparse(name).netloc not in ALLOWED:
                return / raise / abort(...)

        The parsed value may be written inline or bound to a local first
        (`p = urlparse(name)`). The host check may be one operand of an `or`
        (`if p.scheme != "https" or p.netloc not in ALLOWED:`): falling
        through an `or` means every operand was False, so the host is in the
        allowlist. It must NOT sit under an `and`, where a False first operand
        skips the host check entirely.

        Dominance follows `_name_is_membership_guarded` (top-level statements
        of the function body only, a body that ends control flow), and is
        stricter in one way: the whole `if` must END before the sink, so a sink
        inside the rejecting branch itself is not suppressed. The collection
        must be literal for the same reason as there: an allowlist read from
        the environment or a call cannot be proven bounded.
        """
        return self._has_dominating_exit_guard(
            sink_line,
            lambda test: self._test_rejects_unlisted_host(test, name),
            before_sink="ends",
        )

    def _test_rejects_unlisted_host(self, test: ast.AST, name: str) -> bool:
        """True when `test` is True whenever `name`'s parsed netloc is outside
        a literal collection: the `not in` comparison itself, or an `or` with
        that comparison among its operands."""
        if isinstance(test, ast.BoolOp):
            return isinstance(test.op, ast.Or) and any(
                self._test_rejects_unlisted_host(v, name) for v in test.values
            )
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and len(test.comparators) == 1
        ):
            return False
        host = test.left
        if not (isinstance(host, ast.Attribute) and host.attr == "netloc"):
            return False
        if not self._is_url_parse_of(host.value, name):
            return False
        allowed = test.comparators[0]
        if not self._collection_is_literal(allowed):
            return False
        # Check the RESOLVED collection (usually a module-level Name): an
        # allowlist holding "" admits every host-less URL.
        if isinstance(allowed, ast.Name):
            allowed = self._resolve_binding(allowed)
        members = allowed.keys if isinstance(allowed, ast.Dict) else allowed.elts
        return not any(isinstance(m, ast.Constant) and m.value == "" for m in members)

    def _is_url_parse_of(self, expr: ast.AST, name: str) -> bool:
        """True when `expr` is `urlparse(name)` / `urlsplit(name)`, inline or
        through a Name bound to that call in the scope chain."""
        if isinstance(expr, ast.Name):
            expr = self._resolve_binding(expr)
        if not (isinstance(expr, ast.Call) and expr.args):
            return False
        fn = expr.func
        called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if called not in self._URL_PARSE_CALL_NAMES:
            return False
        first = expr.args[0]
        return isinstance(first, ast.Name) and first.id == name

    def _collection_is_literal(self, expr: ast.AST) -> bool:
        """Return True if `expr` is a literal dict/set/list/tuple, or a
        Name that resolves to one in the scope chain.
        """
        if isinstance(expr, (ast.Dict, ast.Set, ast.List, ast.Tuple)):
            return True
        if isinstance(expr, ast.Name):
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return isinstance(
                        scope[expr.id], (ast.Dict, ast.Set, ast.List, ast.Tuple)
                    )
        return False

    # Escaping/encoding neutralizers that make a value safe to render (#24).
    _ESCAPE_FUNCS = frozenset({"escape", "clean", "quote", "quote_plus", "escapejs"})

    def _is_escaped_call(self, expr: ast.AST) -> bool:
        """True if `expr` is a call to a recognized escaping/encoding function
        (html.escape, markupsafe.escape, bleach.clean, urllib.parse.quote,
        django escape/escapejs), or a Name bound to such a call (#24)."""
        if isinstance(expr, ast.Call):
            f = expr.func
            name = (
                f.attr
                if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else "")
            )
            return name in self._ESCAPE_FUNCS
        if isinstance(expr, ast.Name):
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return self._is_escaped_call(scope[expr.id])
        return False

    def _expr_is_fully_escaped(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if every dynamic sub-expression of ``expr`` is an escaped call —
        so ``f"<b>{html.escape(x)}</b>"``, ``escape(x) + '<br>'`` and
        ``"%s%s" % (indent, escape(x))`` are safe XSS args (B5 double-sanitize
        FP). Constants are inert; a JoinedStr is safe iff every FormattedValue
        is escaped; a BinOp iff both sides are; a Tuple iff every element is.

        The Tuple arm is what makes ``%``-formatting work. Its right operand is
        an ast.Tuple, and without a case for it the BinOp arm fell through to
        ``return False`` — so the B5 fix covered f-strings and ``+`` concat but
        silently never recognised ``%``-format, the single most common way
        Django/Jinja code assembles a label. Measured on django-cms 3.11.0:
        ``mark_safe("%s%s" % (indent, escape(title)))`` was reported as
        reflected XSS despite the explicit ``escape()``.

        A Constant repeated with ``*`` (``"&nbsp;" * depth``) is also inert: the
        result can only ever contain characters from the constant, whatever the
        multiplier evaluates to."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if self._is_escaped_call(expr):
            return True
        if isinstance(expr, ast.JoinedStr):
            return all(
                self._expr_is_fully_escaped(v.value, _depth + 1)
                for v in expr.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(expr, ast.Tuple):
            return all(
                self._expr_is_fully_escaped(e, _depth + 1) for e in expr.elts
            )
        if isinstance(expr, ast.BinOp):
            # `<const> * <anything>` yields only the constant's own characters.
            if isinstance(expr.op, ast.Mult) and (
                isinstance(expr.left, ast.Constant) or isinstance(expr.right, ast.Constant)
            ):
                return True
            return self._expr_is_fully_escaped(
                expr.left, _depth + 1
            ) and self._expr_is_fully_escaped(expr.right, _depth + 1)
        if isinstance(expr, ast.Name):
            # A Name bound to an inert/escaped expression is itself inert
            # (`indent = "&nbsp;" * n` then `... % (indent, escape(x))`).
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return self._expr_is_fully_escaped(scope[expr.id], _depth + 1)
        return False

    # ─── traversal containment (CWE-22 specific) ────────────────────
    #
    # The generic sanitiser set above models "this value was narrowed to a
    # bounded set". Traversal has a second, different safety shape: the value
    # stays free-form but is stripped of directory structure, or is rejected
    # when it contains one.
    #
    # DELIBERATELY ABSENT: a bare `Path(x).resolve()`. Resolving is not
    # containing — `Path("/srv/data/../../etc/passwd").resolve()` returns
    # `/etc/passwd`. `resolve()` only becomes a guard when it is paired with a
    # containment ASSERTION (`.relative_to(base)` in a try/except, or a checked
    # `startswith`; see `_path_containment_asserted`), and recognising the call
    # alone would suppress exactly the traversal it appears to defend against.
    # The engine does not treat a function NAME as proof of what the function
    # achieved; that is the same discipline that keeps `.. in x` below gated on
    # control flow rather than on the mere presence of a comparison.

    # Calls that reduce a value to a single path component. Each genuinely
    # removes directory structure — basename() returns the trailing component,
    # Werkzeug's secure_filename() strips separators and traversal sequences —
    # so a traversal payload cannot survive them.
    # Matched on the TERMINAL name so every import style is covered at once:
    # `os.path.basename(x)`, `posixpath.basename(x)`, `from os.path import
    # basename; basename(x)`, `werkzeug.utils.secure_filename(x)` and
    # `from werkzeug.utils import secure_filename; secure_filename(x)`. Both
    # names are unambiguous enough that a terminal match carries no realistic
    # collision risk, unlike the `open`/`Path` receivers the sink predicate has
    # to disambiguate.
    _CONTAINMENT_CALL_NAMES = frozenset({"basename", "secure_filename"})

    def _path_is_contained(
        self, arg: ast.AST, sink_line: int, *, aliases_are_sole: bool = True
    ) -> bool:
        """Return True when `arg` cannot carry directory traversal into a
        filesystem sink, either because it was reduced to a bare filename or
        because a dominating guard rejects traversal sequences.

        Resolves through the scope chain the same way `_arg_is_sanitised` does,
        so `name = os.path.basename(raw); open(name)` is recognised.

        `aliases_are_sole` is False once the resolution has passed through a
        name with more than one binding. The scope chain records only the
        last binding in source order, so `p` in
        `if raw: p = request.args["g"]` / `else: p = full` resolves to `full`
        although it is raw input on the other branch. An asserted containment
        (`_path_containment_asserted`) holds for one binding of one name, so
        it is honoured only while every alias on the way is bound once.
        """
        if isinstance(arg, ast.Call):
            fn = arg.func
            called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if called in self._CONTAINMENT_CALL_NAMES:
                return True
        # `Path(x).name` / `PurePath(x).name` — pathlib's single-component
        # accessor, same effect as basename().
        #
        # The RECEIVER must be a pathlib construction. Matching `.name` on any
        # receiver is wrong and was actively harmful: Django's
        # `request.FILES['f'].name` is an attribute called `name` whose value is
        # the filename the UPLOADER chose, i.e. the attacker-controlled input
        # this rule exists to catch. A bare attribute name says nothing about
        # what produced it.
        if isinstance(arg, ast.Attribute) and arg.attr == "name":
            recv = arg.value
            if isinstance(recv, ast.Call):
                fn = recv.func
                ctor = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if ctor in ("Path", "PurePath", "PurePosixPath", "PureWindowsPath"):
                    return True
            return False
        if isinstance(arg, ast.Name):
            if self._name_is_traversal_rejected(arg.id, sink_line):
                return True
            if aliases_are_sole and self._path_containment_asserted(arg.id, sink_line):
                return True
            for scope in reversed(self._scopes):
                if arg.id in scope:
                    bound = scope[arg.id]
                    # Self-referential binding (`x = f(x)`) — stop rather than
                    # loop, matching _arg_is_sanitised.
                    if isinstance(bound, ast.Name) and bound.id == arg.id:
                        return False
                    sole = aliases_are_sole and (
                        not isinstance(bound, ast.Name)
                        or self._is_sole_binding(arg.id, bound)
                    )
                    return self._path_is_contained(
                        bound, sink_line, aliases_are_sole=sole
                    )
        return False

    def _name_is_traversal_rejected(self, name: str, sink_line: int) -> bool:
        """Return True if the enclosing function body contains a DOMINATING
        early-exit guard that rejects traversal in `name`, of the shape::

            if ".." in name:
                raise / return / abort(...)

        Dominance is enforced exactly as `_name_is_membership_guarded` does it
        (top-level statements of the function body only, `lineno` strictly
        before the sink), so a guard placed after the sink — or nested inside a
        branch that may not run — cannot suppress the finding. A guard that
        does not end control flow is ignored for the same reason: testing for
        '..' and continuing anyway protects nothing.
        """

        def rejects_traversal(test: ast.AST) -> bool:
            # `if ".." in name:` — a traversal sequence being looked for.
            return bool(
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.In)
                and isinstance(test.left, ast.Constant)
                and isinstance(test.left.value, str)
                and ".." in test.left.value
                and test.comparators
                and isinstance(test.comparators[0], ast.Name)
                and test.comparators[0].id == name
            )

        return self._has_dominating_exit_guard(sink_line, rejects_traversal)

    # ─── asserted containment (CWE-22) ──────────────────────────────
    #
    # The guard that keeps a FREE-FORM path under a base directory: resolve
    # the path, assert that it is still under the base, and leave the function
    # when it is not. Both halves are required.
    #
    #   * Resolving. `os.path.realpath` and `Path.resolve()` collapse `..` AND
    #     follow symlinks. `abspath` / `normpath` only collapse `..`, so a
    #     symlink under the base that points outside it passes the check; an
    #     unresolved join collapses nothing, and `commonpath`, `startswith` and
    #     `is_relative_to` are lexical: `/srv/reports/../../etc/passwd` passes
    #     all three.
    #   * Ending the prefix at a component. `startswith("/srv/reports")` also
    #     admits `/srv/reports_evil/x`. `B + os.sep`, `B + "/"` and
    #     `os.path.join(B, "")` end it at a separator. `B + "\\"` is not
    #     accepted: on POSIX a backslash is an ordinary filename character, and
    #     `/srv/reports\x` is a file in /srv.
    #
    # The base must be fixed by the code: a string constant narrower than the
    # filesystem root, `os.path.realpath` of one, or `Path(...)` /
    # `Path(...).resolve()` of one, inline or through a Name (a constant may
    # itself be a Name bound to one). A module-level Name counts only when the
    # module binds it once and no function declares it `global`. A base from
    # the request, the environment, a parameter or any other call cannot be
    # shown to bound anything, and `/` bounds nothing.
    #
    # Accepted guards, each a top-level statement of the function placed after
    # the path's binding and before the sink:
    #
    #   if os.path.commonpath([B, full]) != B: <exit>   (either operand order)
    #   if not full.startswith(B + os.sep): <exit>      (or B + "/", join(B, ""))
    #   if not full.is_relative_to(B): <exit>
    #   try: full.relative_to(B)
    #   except ValueError: <exit>                       (every handler exits)

    def _path_containment_asserted(self, name: str, sink_line: int) -> bool:
        """Return True when `name` is a resolved path that a dominating guard
        asserts is under a fixed base directory, leaving the function when it
        is not (the accepted shapes are listed above).

        `name` must be bound exactly once in the function, by a top-level
        `name = os.path.realpath(...)` or `name = <pathlib path>.resolve()`
        that comes before the guard. Any other store of the name (on a branch,
        as a loop target, after the guard) could put an unresolved or
        unchecked value under the same name, so it disqualifies the guard.

        Dominance follows `_has_dominating_exit_guard`. A sink inside the
        rejecting body is not covered. A sink in the guard's `else` is, since
        that branch runs only when the containment test passed. The `try`
        form must end before the sink.
        """
        return self._path_containment_guard(name, sink_line) is not None

    def _path_containment_guard(self, name: str, sink_line: int) -> ast.stmt | None:
        """The first guard `_path_containment_asserted` accepts for `name`
        before `sink_line` (an `if` or a `try`), or None."""
        if not self._func_stack:
            return None
        bound = self._resolve_binding(ast.Name(id=name, ctx=ast.Load()))
        if bound is None or not self._is_resolved_path(bound):
            return None
        binding = self._sole_top_level_assign(self._func_stack[-1], name)
        if binding is None or binding.value is not bound:
            return None
        after = binding.end_lineno

        def rejects_uncontained(test: ast.AST) -> bool:
            return test.lineno > after and self._test_rejects_uncontained(test, name)

        def asserts_relative(stmt: ast.Try) -> bool:
            return stmt.lineno > after and self._try_asserts_relative(stmt, name)

        return self._dominating_exit_guard(
            sink_line,
            rejects_uncontained,
            before_sink="body_ends",
            try_pred=asserts_relative,
        )

    def _resolved_join_is_guarded(self, join: ast.Call) -> bool:
        """True when the `os.path.join(...)` sink `join` is resolved in place
        and a containment guard checks the result before anything uses it.

        That holds only when the resolving call (`realpath(join(...))` or
        `Path(join(...)).resolve()`) is the sole top-level binding of a name,
        `_path_containment_guard` accepts a guard on that name, and every
        other use of the name comes after the guard's rejecting body (or after
        the whole `try`). Otherwise the join stays a sink. The resolved value
        may go where no sink is modelled (`os.remove`, `shutil.copy`,
        Starlette's `FileResponse`), inline or returned to the caller, so the
        join can be the only place the flow is reported.
        """
        resolved = self._resolved_joins.get(join)
        if resolved is None or not self._func_stack:
            return False
        func = self._func_stack[-1]
        name = next(
            (
                stmt.targets[0].id
                for stmt in func.body
                if isinstance(stmt, ast.Assign)
                and stmt.value is resolved
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ),
            None,
        )
        if name is None:
            return False
        guard = self._path_containment_guard(name, func.end_lineno + 1)
        if guard is None:
            return False
        if isinstance(guard, ast.If):
            checking = [guard.test]
            unchecked_until = guard.body[-1].end_lineno
        else:
            checking = [
                stmt
                for stmt in guard.body
                if self._is_relative_to_call(stmt, name, guard.lineno)
            ]
            unchecked_until = guard.end_lineno
        checked_uses = {id(n) for part in checking for n in ast.walk(part)}
        return all(
            id(use) in checked_uses or use.lineno > unchecked_until
            for stmt in func.body
            for use in ast.walk(stmt)
            if isinstance(use, ast.Name)
            and use.id == name
            and isinstance(use.ctx, ast.Load)
        )

    def _test_rejects_uncontained(self, test: ast.AST, name: str) -> bool:
        """True when `test` is True whenever `name` is outside a fixed base:
        `os.path.commonpath([B, name]) != B`, `not name.startswith(B + os.sep)`
        or `not name.is_relative_to(B)`."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            call = test.operand
            if not self._is_one_arg_method_call(call, name):
                return False
            if call.func.attr == "startswith":
                base = self._component_prefix_base(call.args[0])
                return base is not None and self._is_fixed_base(base, test.lineno)
            if call.func.attr == "is_relative_to":
                return self._is_fixed_base(call.args[0], test.lineno)
            return False
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotEq)
        ):
            left, right = test.left, test.comparators[0]
            for common, base in ((left, right), (right, left)):
                if self._is_commonpath_with(common, name, base):
                    return self._is_fixed_base(base, test.lineno)
        return False

    def _try_asserts_relative(self, stmt: ast.Try, name: str) -> bool:
        """True when `stmt` is a `try` whose body calls `name.relative_to(B)`
        as one of its own statements, with a handler that catches ValueError
        (`ValueError`, a tuple holding it, `Exception`, `BaseException` or a
        bare `except`), and where EVERY handler ends control flow.

        Every handler, not just the ValueError one: a handler that falls
        through for an exception raised before `relative_to` runs, or while it
        is evaluated (an AttributeError when `name` is a str), skips the
        assertion and reaches the sink.
        """
        if not stmt.handlers:
            return False
        if not any(self._is_relative_to_call(s, name, stmt.lineno) for s in stmt.body):
            return False
        if not any(_handler_catches_value_error(h.type) for h in stmt.handlers):
            return False
        return all(self._body_ends_control_flow(h.body) for h in stmt.handlers)

    def _is_relative_to_call(self, stmt: ast.stmt, name: str, guard_line: int) -> bool:
        """True when `stmt` is `name.relative_to(B)`, alone or assigned, with a
        fixed base and no other argument (`walk_up=True` admits `..`)."""
        if not isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign)):
            return False
        call = stmt.value
        return (
            self._is_one_arg_method_call(call, name)
            and call.func.attr == "relative_to"
            and self._is_fixed_base(call.args[0], guard_line)
        )

    @staticmethod
    def _is_one_arg_method_call(expr: ast.AST, name: str) -> bool:
        """True when `expr` is `name.<method>(arg)`: one positional argument,
        no keyword. Extra arguments change the meaning: `startswith(p, 4)`
        tests `name[4:]`, and `relative_to(B, walk_up=True)` accepts `..`."""
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id == name
            and len(expr.args) == 1
            and not isinstance(expr.args[0], ast.Starred)
            and not expr.keywords
        )

    def _component_prefix_base(self, expr: ast.AST) -> ast.AST | None:
        """Return `B` when `expr` is `B + os.sep`, `B + os.path.sep`,
        `B + "/"` or `os.path.join(B, "")`: a prefix that ends at a path
        component. Anything else, including a bare `B`, returns None."""
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            sep = expr.right
            if (isinstance(sep, ast.Constant) and sep.value == "/") or _is_os_sep(sep):
                return expr.left
            return None
        if (
            self._is_os_path_call(expr, "join")
            and len(expr.args) == 2
            and not expr.keywords
            and isinstance(expr.args[1], ast.Constant)
            and expr.args[1].value == ""
        ):
            return expr.args[0]
        return None

    def _is_commonpath_with(self, expr: ast.AST, name: str, base: ast.AST) -> bool:
        """True when `expr` is `os.path.commonpath([base, name])`, in either
        order, with the same `base` expression as the other operand."""
        if not (
            self._is_os_path_call(expr, "commonpath")
            and len(expr.args) == 1
            and not expr.keywords
        ):
            return False
        paths = expr.args[0]
        if not isinstance(paths, (ast.List, ast.Tuple)) or len(paths.elts) != 2:
            return False
        want = ast.dump(base)
        first, second = paths.elts
        return any(
            isinstance(p, ast.Name) and p.id == name and ast.dump(q) == want
            for p, q in ((first, second), (second, first))
        )

    def _is_fixed_base(self, expr: ast.AST, guard_line: int) -> bool:
        """True when `expr` is a base directory the code fixes: a string
        constant narrower than the root, `os.path.realpath` of one, or
        `Path(...)` / `Path(...).resolve()` of one, inline or bound to a
        Name."""
        if isinstance(expr, ast.Name):
            value = self._value_at_guard(expr.id, guard_line)
            return value is not None and self._is_fixed_base_value(value, guard_line)
        return self._is_fixed_base_value(expr, guard_line)

    def _is_fixed_base_value(self, expr: ast.AST, guard_line: int) -> bool:
        if isinstance(expr, ast.Constant):
            return _is_bounding_dir(expr.value)
        if not isinstance(expr, ast.Call):
            return False
        fn = expr.func
        if isinstance(fn, ast.Attribute) and fn.attr == "resolve" and not expr.args:
            # Path(<fixed>).resolve(): check the constructor underneath.
            expr = fn.value
            if not self._is_pathlib_ctor_call(expr):
                return False
        if not (
            self._is_os_path_call(expr, "realpath") or self._is_pathlib_ctor_call(expr)
        ):
            return False
        if len(expr.args) != 1 or expr.keywords:
            return False
        arg = expr.args[0]
        if isinstance(arg, ast.Name):
            arg = self._value_at_guard(arg.id, guard_line)
        return isinstance(arg, ast.Constant) and _is_bounding_dir(arg.value)

    def _value_at_guard(self, name: str, guard_line: int) -> ast.AST | None:
        """The value `name` holds when the guard at `guard_line` runs.

        A name the function stores must be stored exactly once, by a top-level
        assignment before the guard; otherwise the value the guard compares
        against is not the one the scope chain records. A name the function
        never stores is a module-level name (`_module_binding`), unless it is
        a parameter of this or an enclosing function, or a local of an
        enclosing one: the caller chooses a parameter, and a same-named module
        constant would otherwise answer for it."""
        func = self._func_stack[-1]
        if _stores_of(func, name):
            binding = self._sole_top_level_assign(func, name)
            if binding is None or binding.end_lineno >= guard_line:
                return None
            return binding.value
        for enclosing in self._func_stack:
            if name in _param_names(enclosing):
                return None
            if enclosing is not func and _stores_of(enclosing, name):
                return None
        return self._module_binding(name)

    def _module_binding(self, name: str) -> ast.AST | None:
        """The value of the module-level `name`, when the module binds it
        exactly once, by a top-level `name = <value>`, and no function in the
        module declares it `global`.

        The scope chain cannot answer this. It holds the module's bindings
        seen so far, so a reassignment after the function, or one made through
        `global` in another function, is missing from it, and it holds class
        scopes, which a method never reads a bare name from: inside a method,
        `REPORTS_ROOT` is the module global even when the class has an
        attribute of that name."""
        module = self._module_root
        if module is None:
            return None
        if any(
            isinstance(n, ast.Global) and name in n.names for n in ast.walk(module)
        ):
            return None
        stores = [
            n for stmt in module.body for n in _same_scope_nodes(stmt) if _binds_name(n, name)
        ]
        if len(stores) != 1:
            return None
        for stmt in module.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and stmt.targets[0] is stores[0]
            ):
                return stmt.value
        return None

    def _is_sole_binding(self, name: str, value: ast.AST) -> bool:
        """True when `name = value` is the only binding of `name` in the
        innermost function, as a top-level statement."""
        if not self._func_stack:
            return False
        binding = self._sole_top_level_assign(self._func_stack[-1], name)
        return binding is not None and binding.value is value

    @staticmethod
    def _sole_top_level_assign(func: ast.AST, name: str) -> ast.Assign | None:
        """The statement binding `name` in `func`, when it is the only binding
        of the name anywhere in the function and is a top-level
        `name = <value>`; None otherwise."""
        stores = _stores_of(func, name)
        if len(stores) != 1:
            return None
        for stmt in func.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and stmt.targets[0] is stores[0]
            ):
                return stmt
        return None

    def _is_resolved_path(self, expr: ast.AST) -> bool:
        """True when `expr` is `os.path.realpath(...)` or
        `<pathlib path>.resolve()`: a path with `..` collapsed and symlinks
        followed. `abspath` and `normpath` follow no symlink, so they are not
        resolved paths."""
        if self._is_os_path_call(expr, "realpath"):
            return True
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "resolve"
            and not expr.args
            and self._is_pathlib_path(expr.func.value)
        )

    def _is_pathlib_path(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True when `expr` builds a pathlib path: a `Path(...)` call, a `/`
        whose left operand is one, `.joinpath()` / `.resolve()` /
        `.absolute()` of one, or a Name bound to one."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Call):
            if self._is_pathlib_ctor_call(expr):
                return True
            fn = expr.func
            return (
                isinstance(fn, ast.Attribute)
                and fn.attr in ("joinpath", "resolve", "absolute")
                and self._is_pathlib_path(fn.value, _depth + 1)
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return self._is_pathlib_path(expr.left, _depth + 1)
        if isinstance(expr, ast.Name):
            bound = self._resolve_binding(expr)
            return bound is not None and self._is_pathlib_path(bound, _depth + 1)
        return False

    def _is_pathlib_ctor_call(self, expr: ast.AST) -> bool:
        """True when `expr` is `pathlib.Path(...)`, or a bare `Path(...)` that
        is pathlib's (imported from pathlib, or not imported from elsewhere)."""
        if not isinstance(expr, ast.Call):
            return False
        fn = expr.func
        if isinstance(fn, ast.Name):
            origin = self._from_imports.get(fn.id)
            if origin is None:
                return fn.id == "Path"
            return origin == ("pathlib", "Path")
        return (
            isinstance(fn, ast.Attribute)
            and fn.attr == "Path"
            and isinstance(fn.value, ast.Name)
            and self._module_aliases.get(fn.value.id, fn.value.id) == "pathlib"
        )

    def _is_os_path_call(self, expr: ast.AST, attr: str) -> bool:
        """True when `expr` calls `os.path.<attr>`, written that way or as a
        bare name imported from os.path (`from os.path import realpath`)."""
        if not isinstance(expr, ast.Call):
            return False
        fn = expr.func
        if isinstance(fn, ast.Name):
            return self._from_imports.get(fn.id) == ("os.path", attr)
        return _os_path_attr(fn) == attr

    def _note_resolved_join(self, node: ast.Call) -> None:
        """Remember an `os.path.join(...)` that is the direct argument of
        `os.path.realpath(...)` or `Path(...).resolve()`, with the resolving
        call, for `_resolved_join_is_guarded`.

        `abspath` is not recorded: it follows no symlink, so no containment
        guard can make the join under it safe.
        """
        if self._is_os_path_call(node, "realpath"):
            inner = node.args[0] if node.args else None
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "resolve"
            and self._is_pathlib_ctor_call(node.func.value)
        ):
            ctor_args = node.func.value.args
            inner = ctor_args[0] if len(ctor_args) == 1 else None
        else:
            return
        if inner is not None and self._is_os_path_call(inner, "join"):
            self._resolved_joins[inner] = node

    def _has_dominating_exit_guard(
        self,
        sink_line: int,
        test_pred: Callable[[ast.AST], bool],
        *,
        before_sink: _GuardExtent = "starts",
        try_pred: Callable[[ast.Try], bool] | None = None,
    ) -> bool:
        """True when `_dominating_exit_guard` finds a guard."""
        return (
            self._dominating_exit_guard(
                sink_line, test_pred, before_sink=before_sink, try_pred=try_pred
            )
            is not None
        )

    def _dominating_exit_guard(
        self,
        sink_line: int,
        test_pred: Callable[[ast.AST], bool],
        *,
        before_sink: _GuardExtent = "starts",
        try_pred: Callable[[ast.Try], bool] | None = None,
    ) -> ast.stmt | None:
        """The first top-level `if` of the innermost function body that starts
        before `sink_line`, has a test `test_pred` accepts, and has a body that
        ends control flow; None when there is none. A nested `if` never
        appears in the body-only loop, so a guard inside a branch that may not
        run cannot count.

        `before_sink` says how much of the `if` must lie before the sink:
          * "starts": the `if` starts before it;
          * "ends": the whole `if`, `else`/`elif` included, ends before it, so
            a sink inside the guard's own branch is not covered;
          * "body_ends": the rejecting body ends before it. A sink in the
            guard's `else`/`elif` is covered, since those run only when the
            test was False.

        `try_pred`, when given, also accepts a top-level `try` that ends before
        the sink and that `try_pred` accepts.
        """
        if not self._func_stack:
            return None
        func = self._func_stack[-1]
        for stmt in func.body:
            if stmt.lineno >= sink_line:
                continue
            if isinstance(stmt, ast.Try):
                if try_pred is not None and stmt.end_lineno < sink_line and try_pred(stmt):
                    return stmt
                continue
            if not isinstance(stmt, ast.If):
                continue
            if before_sink == "ends" and stmt.end_lineno >= sink_line:
                continue
            if before_sink == "body_ends" and stmt.body[-1].end_lineno >= sink_line:
                continue
            if test_pred(stmt.test) and self._body_ends_control_flow(stmt.body):
                return stmt
        return None

    @staticmethod
    def _body_ends_control_flow(body: list) -> bool:
        """True when a guard body returns, raises, or calls abort()/exit()."""
        for s in body:
            if isinstance(s, (ast.Return, ast.Raise)):
                return True
            if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                fn = s.value.func
                called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if called in ("abort", "exit", "sys_exit"):
                    return True
        return False

    def _arg_is_sanitised(
        self, arg: ast.AST, sink_line: int = 1_000_000, *, url_sink: bool = False
    ) -> bool:
        """Composite check: dict-lookup whitelist OR membership-guarded Name.

        Called by the sink predicates (_is_ssrf / _is_open_redirect /
        path-traversal / XSS) to suppress findings where user input has
        been narrowed through a recognised sanitiser pattern.

        ``sink_line`` is the line of the sink being evaluated; it is threaded
        into the membership-guard check so a guard must DOMINATE the sink to
        suppress it (B2). Callers that cannot supply a line default to a large
        sentinel (behaviour unchanged for those), but every real sink predicate
        passes ``node.lineno``.

        ``url_sink`` is True for sinks whose risk is the destination host
        (SSRF, open redirect). It additionally honours a URL-host allowlist
        guard (`_url_host_is_allowlisted`), which bounds the host and nothing
        else, so it must not count for XSS or path sinks. That guard describes
        a whole URL string, so ``url_sink`` survives only into a scope-resolved
        binding of the argument and the LEFTMOST operand of a ``+``; every
        other operand, and every ``%``-format value, is checked without it.

        Handles three shapes:
          1. arg IS the dict-lookup or guarded Name itself
          2. arg is a Name that was assigned a sanitised expr earlier
             in the same scope (e.g., `base = allowed.get(t); requests.get(base + "/p")`)
          3. arg is a BinOp where every Name/Subscript operand is sanitised
             (e.g., `requests.get(allowed.get(t) + "/p")`)
        """
        if self._arg_is_whitelisted_lookup(arg):
            return True
        if self._is_escaped_call(arg):  # audit #24
            return True
        # Server-controlled internal URL builders (reverse/url_for) produce a
        # route string, not attacker input — safe to interpolate into an href.
        if self._is_safe_url_builder(arg):
            return True
        if isinstance(arg, ast.Name):
            if self._name_is_membership_guarded(arg.id, sink_line) or (
                url_sink and self._url_host_is_allowlisted(arg.id, sink_line)
            ):
                return True
            # Resolve through scope and check the assigned expr is sanitised.
            # Recurse through the full sanitiser set (not just whitelist) so an
            # escaped/%-formatted/builder value assigned to a local is honoured —
            # guard against a self-referential binding (`x = f(x)`) to avoid a
            # loop.
            for scope in reversed(self._scopes):
                if arg.id in scope:
                    bound = scope[arg.id]
                    if isinstance(bound, ast.Name) and bound.id == arg.id:
                        return False
                    return self._arg_is_sanitised(bound, sink_line, url_sink=url_sink)
            return False
        if isinstance(arg, ast.BinOp):
            # printf-style `"<template>" % (a, b)`: safe iff the template is a
            # constant string AND every substituted value is constant or itself
            # sanitised (escape()/reverse()/whitelist). The Django admin idiom
            # `'<a href="%s">%s</a>' % (reverse(...), escape(repr))` is the
            # canonical safe case (TwiScope SEC-170).
            if isinstance(arg.op, ast.Mod):
                template = arg.left
                if isinstance(template, ast.Constant) and isinstance(
                    template.value, str
                ):
                    rhs = arg.right
                    values = (
                        list(rhs.elts)
                        if isinstance(rhs, (ast.Tuple, ast.List))
                        else [rhs]
                    )
                    return all(
                        isinstance(v, ast.Constant) or self._arg_is_sanitised(v, sink_line)
                        for v in values
                    )
                return False
            # Every non-Constant subexpression must itself be sanitised. Only
            # the leftmost operand of a `+` can still be the whole URL whose
            # host a URL-host guard fixed (`url + "/v1"`).
            left_url_sink = url_sink and isinstance(arg.op, ast.Add)
            return all(
                isinstance(sub, ast.Constant)
                or self._arg_is_sanitised(sub, sink_line, url_sink=sub_url_sink)
                for sub, sub_url_sink in ((arg.left, left_url_sink), (arg.right, False))
            )
        # audit #16: a fully-constant f-string or an os.path.* / known dunder
        # call over constant args is a safe path (config loaders, __file__-
        # relative package data), not user input.
        if self._expr_is_constant_path(arg):
            return True
        return False

    # Dunder names that are build-time constants for path purposes (#16).
    _CONST_PATH_DUNDERS = frozenset({"__file__", "__name__", "__doc__"})
    _CONST_PATH_FUNCS = frozenset(
        {"join", "expanduser", "expandvars", "abspath", "dirname", "normpath"}
    )

    def _expr_is_constant_path(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if `expr` builds a path from only constants / known dunders /
        os.path.* over constant parts — i.e. no user input can enter (#16)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.Name):
            if expr.id in self._CONST_PATH_DUNDERS:
                return True
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return self._expr_is_constant_path(scope[expr.id], _depth + 1)
            return False
        if isinstance(expr, ast.BinOp):
            return self._expr_is_constant_path(
                expr.left, _depth + 1
            ) and self._expr_is_constant_path(expr.right, _depth + 1)
        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(
                    v, ast.FormattedValue
                ) and not self._expr_is_constant_path(v.value, _depth + 1):
                    return False
            return True
        if isinstance(expr, ast.Call):
            f = expr.func
            if _os_path_attr(f) in self._CONST_PATH_FUNCS:
                return all(
                    self._expr_is_constant_path(a, _depth + 1) for a in expr.args
                )
            return False
        return False

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Detect dangerous function calls."""
        self._note_resolved_join(node)
        # eval() / exec(), and library code-eval sinks (PIL.ImageMath.eval,
        # asteval.Interpreter().eval, simpleeval). Attribute form matched via a
        # small sink set so e.g. ImageMath.eval(user_input) (PyGoat RCE) fires.
        _is_eval = (
            isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"eval"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in _CODE_EVAL_RECEIVERS
        )
        if _is_eval:
            # Only flag if argument is not a plain string literal
            if not (node.args and isinstance(node.args[0], ast.Constant)):
                _eval_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else f"{node.func.value.id}.{node.func.attr}"
                    if isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else "eval"
                )
                self._emit_finding(
                    "PY_EVAL",
                    f"Unsafe {_eval_name}() with dynamic argument",
                    "HIGH",
                    "MEDIUM",
                    "CWE-95",
                    (
                        f"Replace {_eval_name}() with a safer alternative. "
                        "Never pass user-controlled data to eval/exec."
                    ),
                    node.lineno,
                )

        # os.system() — extended in TASK-121 to capture taint chains
        # when user input flows in. Constant-arg skip added during the
        # 2026-05-13 accuracy evaluation to match the posture of the
        # other reachable sinks (SSRF/XSS/path-traversal/open-redirect):
        # a literal-string `os.system("echo hello")` isn't exploitable
        # and was flagging as HIGH for no benefit. Variable args
        # (Name, Call, BinOp, JoinedStr) still emit; the chain decides
        # whether the variable traces back to a request source.
        elif self._call_module_attr(node) == (
            "os",
            "system",
        ) and self._cmdi_arg_is_dangerous(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"os.system({_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_OS_SYSTEM",
                "Unsafe os.system() call — command injection risk",
                "HIGH",
                "HIGH",
                "CWE-78",
                (
                    "Replace os.system() with subprocess.run() using a list of arguments "
                    "and shell=False."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # os.popen() / popen2 / popen3 / popen4 — same shape as
        # os.system; deprecated forms that's still common in older
        # codebases. Reads a shell command and returns a pipe, but the
        # shell-injection surface is identical. Track 4 heavy-eval
        # (bandit examples) surfaced os.popen2/3/4 as a gap — those
        # are deprecated but real in legacy code; same CWE, same fix.
        elif (
            lambda r: (
                r is not None
                and r[0] == "os"
                and r[1] in {"popen", "popen2", "popen3", "popen4"}
            )
        )(self._call_module_attr(node)) and self._cmdi_arg_is_dangerous(node):
            popen_variant = self._call_module_attr(node)[1]
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"os.{popen_variant}({_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_OS_POPEN",
                f"Unsafe os.{popen_variant}() call — command injection risk",
                "HIGH",
                "HIGH",
                "CWE-78",
                (
                    f"Replace os.{popen_variant}() with subprocess.run(..., shell=False) "
                    "using a list of arguments. The os.popen family is deprecated "
                    "and equivalent to a shell call."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # subprocess with shell=True — extended in TASK-121 to capture
        # taint chains. The first positional arg is the command string
        # when shell=True; that's where user input flows in. Constant-
        # arg skip parity added during the 2026-05-13 accuracy
        # evaluation.
        elif self._is_subprocess_shell_true(node) and self._cmdi_arg_is_dangerous(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"subprocess(shell=True, cmd={_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_SUBPROCESS_SHELL",
                "subprocess called with shell=True — command injection risk",
                "HIGH",
                "HIGH",
                "CWE-78",
                (
                    "Remove shell=True and pass arguments as a list. "
                    "Never build shell commands from user input."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # cursor.execute() with string formatting (or with a variable assigned
        # from a formatted/concatenated string elsewhere in the function).
        elif self._is_sql_injection(node):
            chain = None
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    f"cursor.execute({_ast_expr_text(node.args[0])})",
                )
            self._emit_finding(
                "PY_SQL_INJECTION",
                "SQL query built via string formatting — injection risk",
                "CRITICAL",
                "HIGH",
                "CWE-89",
                (
                    "Use parameterized queries: cursor.execute('SELECT ... WHERE x = %s', (val,)). "
                    "Never build SQL with % formatting or f-strings."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # Django ORM SQL-injection sinks — bandit B610/B611. Surfaced by
        # Track 4 (PyGoat advertised SQLi labs but fendix returned zero).
        # Three Django-specific shapes feed raw SQL fragments past the ORM:
        #   <qs>.raw("SELECT ... " + tainted)
        #   <qs>.extra(where=[tainted], select={"x": tainted}, tables=[tainted])
        #   RawSQL(tainted, [])  /  django.db.models.expressions.RawSQL
        # Suppression posture matches cursor.execute: literal strings /
        # literal collections are safe; non-literal first arg or non-literal
        # kwarg value emits.
        elif self._is_django_orm_sql_sink(node):
            sink_label = self._django_orm_sql_sink_label(node)
            tainted_arg = self._django_orm_sql_tainted_arg(node)
            chain = None
            if tainted_arg is not None:
                chain = self._collect_taint_chain(
                    tainted_arg,
                    node.lineno,
                    f"{sink_label}({_ast_expr_text(tainted_arg)})",
                )
            self._emit_finding(
                "PY_SQL_INJECTION",
                f"Django ORM SQL injection — {sink_label} with non-literal SQL",
                "CRITICAL",
                "HIGH",
                "CWE-89",
                (
                    "Pass parameters via the ORM's params= kwarg or use parameterized "
                    "RawSQL. Never interpolate user input into raw SQL strings, "
                    "extra(where=[...]), or extra(select={...}) values."
                ),
                node.lineno,
                taint_chain=chain,
            )

        # pickle.load() / pickle.loads() — always dangerous on untrusted input.
        # Unlike yaml.load there's no "safe" variant; the right answer is
        # always JSON or msgpack.
        elif self._is_pickle_load(node):
            self._emit_finding(
                "PY_PICKLE_LOAD",
                "Unsafe pickle deserialization — RCE risk",
                "CRITICAL",
                "HIGH",
                "CWE-502",
                (
                    "Never deserialize untrusted data with pickle. "
                    "Use JSON for cross-process data; if you must, sign and verify a HMAC first."
                ),
                node.lineno,
            )

        # yaml.load() without Loader=SafeLoader (or yaml.unsafe_load).
        # PyYAML's load() defaults to FullLoader since 5.1 but pre-5.1 was
        # equivalent to UnsafeLoader; explicitly check for SafeLoader to match
        # what's universally safe.
        elif self._is_unsafe_yaml_load(node):
            self._emit_finding(
                "PY_YAML_UNSAFE_LOAD",
                "Unsafe yaml.load() — RCE risk",
                "HIGH",
                "HIGH",
                "CWE-502",
                (
                    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader. "
                    "yaml.load() and yaml.unsafe_load() can execute arbitrary Python on untrusted input."
                ),
                node.lineno,
            )

        # hashlib.md5/sha1 used to hash a value that looks password-related.
        # MD5 and SHA1 are fast, unsalted, and rainbow-table-friendly; both are
        # disqualified by NIST/OWASP for password storage. We require a
        # password-y identifier in the arg subtree to keep noise low — md5 of
        # a file checksum is fine.
        elif self._is_weak_password_hash(node):
            self._emit_finding(
                "PY_WEAK_CRYPTO_PASSWORD",
                "Weak hash (MD5/SHA1) used for password — credential exposure risk",
                "HIGH",
                "MEDIUM",
                "CWE-916",
                (
                    "Use a password hashing function: argon2 (preferred), bcrypt, or scrypt. "
                    "MD5 and SHA1 are unsuitable for password storage — they're fast and "
                    "vulnerable to rainbow tables."
                ),
                node.lineno,
                category="secrets",
            )

        # redirect()/HttpResponseRedirect() with request-derived input.
        # Pattern: flask.redirect(request.args.get('url'))  or
        #          HttpResponseRedirect(request.GET['next'])
        elif self._is_open_redirect(node):
            chain = None
            # Built once, OUTSIDE the chain attempt, so the operation is named
            # whether or not the flow can be proven — see _emit_finding's sink.
            sink_expr = (
                f"redirect({_ast_expr_text(node.args[0])})" if node.args else ""
            )
            if node.args:
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    sink_expr,
                )
            self._emit_finding(
                "PY_OPEN_REDIRECT",
                "Potential open redirect — dynamic redirect target",
                "HIGH",
                "MEDIUM",
                "CWE-601",
                (
                    "Validate redirect targets against an allow-list of safe URLs/paths "
                    "before passing to redirect(). Reject anything outside your domain."
                ),
                node.lineno,
                taint_chain=chain,
                proven_title="Open redirect — user-controlled redirect target",
                sink=sink_expr,
            )

        # XSS HTML-render sinks (TASK-120). Three patterns:
        #   - Markup(x) / flask.Markup(x) / markupsafe.Markup(x) — bypasses
        #     Jinja2 auto-escaping; equivalent to inserting `|safe` in a
        #     template. When `x` is user input, the rendered HTML executes
        #     attacker-controlled markup.
        #   - mark_safe(x) — same idea on the Django side
        #     (django.utils.safestring.mark_safe). Bypasses {{ }} escaping.
        #   - render_template_string(x) — Jinja2 server-side template
        #     injection (SSTI) when the template body itself is
        #     user-controlled; reflective XSS in the typical case.
        # The HTML emitted from any of these flows back to the browser, so
        # proven user-input dataflow into the call site implies a real
        # reachable XSS path — the correlator escalates severity per
        # TASK-114.
        elif self._is_xss_html_sink(node) and not (
            node.args and self._expr_is_fully_escaped(node.args[0])
        ):
            # B5 (double-sanitize): an escaped value wrapped in Markup — bare,
            # in an f-string, or concatenated (Markup(f"<b>{html.escape(x)}</b>"),
            # Markup(escape(x) + '<br>')) — is already safe HTML. Only fall
            # through to emit when the arg is NOT fully escaped.
            chain = None
            sink_expr = ""
            if node.args:
                sink_name = self._xss_sink_name(node)
                sink_expr = f"{sink_name}({_ast_expr_text(node.args[0])})"
                chain = self._collect_taint_chain(
                    node.args[0],
                    node.lineno,
                    sink_expr,
                )
            self._emit_finding(
                "PY_XSS_HTML_SINK",
                "Reflected XSS — user input passed to HTML render sink",
                "HIGH",
                "MEDIUM",
                "CWE-79",
                (
                    "Sanitize user input before passing to Markup/mark_safe/"
                    "render_template_string. Prefer template auto-escaping "
                    "(remove the Markup wrapper) or html.escape() the value "
                    "before marking it safe."
                ),
                node.lineno,
                taint_chain=chain,
                sink=sink_expr,
            )

        # HTTP-client sink with non-literal first arg → potential SSRF.
        # MEDIUM confidence because legitimate HTTP-client use is common; the
        # signal is that the URL itself is dynamic.
        elif self._is_ssrf(node):
            chain = None
            ctor_arg = self._ssrf_ctor_base_url_arg(node)
            sink_name = (
                self._ssrf_sink_name(node)
                or f"requests.{getattr(node.func, 'attr', '?')}"
            )
            url_arg = (
                ctor_arg
                if ctor_arg is not None
                else (node.args[0] if node.args else None)
            )
            sink_expr = ""
            if url_arg is not None:
                label = sink_name if ctor_arg is None else "http_client(base_url=…)"
                sink_expr = f"{label}({_ast_expr_text(url_arg)})"
                chain = self._collect_taint_chain(
                    url_arg,
                    node.lineno,
                    sink_expr,
                )
            self._emit_finding(
                "PY_SSRF",
                "Potential SSRF — dynamic URL passed to HTTP client",
                "HIGH",
                "MEDIUM",
                "CWE-918",
                (
                    "Validate the URL against an allow-list before fetching. "
                    "Disallow internal addresses (127.0.0.1, 169.254.169.254, RFC1918 ranges) "
                    "and use a SSRF-aware HTTP client wrapper."
                ),
                node.lineno,
                taint_chain=chain,
                proven_title="SSRF — user-controlled URL reaches HTTP client",
                sink=sink_expr,
            )

        # Path-traversal sinks (TASK-134 / Phase 17d). Recognises:
        #   - open(x), open(x, "r") / open(x, "w") / ...
        #   - pathlib.Path(x) — the resulting Path is typically passed to
        #     open() or used as send_from_directory arg
        #   - flask.send_file(x), flask.send_from_directory(safe_dir, x)
        #   - django.http.FileResponse(open(x, "rb"))  — caught via the
        #     inner open() match
        #
        # When `x` comes from request input, the attacker can read (or
        # depending on mode, overwrite) arbitrary paths on the server's
        # filesystem with `../` traversal. CWE-22.
        #
        # Conservative posture (parity with SQLi/SSRF/XSS):
        #   - Constant string arg → safe, skip
        #   - Name resolving to constant in scope → safe, skip
        #   - Anything else → emit; if `_collect_taint_chain` proves a
        #     flow back to a request source, mark reachable: true. The
        #     correlator then escalates severity for the
        #     correlated-reachable case (TASK-114) and step 5.4
        #     escalates the non-correlated-reachable case (TASK-125).
        elif self._is_path_traversal_sink(node):
            chain = None
            sink_expr = ""
            sink_name = self._path_traversal_sink_name(node)
            if node.args:
                # The user-controlled arg is usually the FIRST positional
                # except for send_from_directory(safe_dir, x) and
                # os.path.join(base, x) where it's the second.
                # _path_traversal_arg_index handles that.
                arg_idx = self._path_traversal_arg_index(node)
                if arg_idx < len(node.args):
                    sink_expr = f"{sink_name}({_ast_expr_text(node.args[arg_idx])})"
                    chain = self._collect_taint_chain(
                        node.args[arg_idx],
                        node.lineno,
                        sink_expr,
                    )
            # `os.path.*` sinks (join/abspath/expanduser/expandvars) only
            # become path-traversal vulns when the argument actually
            # carries user input. They appear constantly in library code
            # over fixed paths (e.g. `os.path.expanduser(fixed_param)`),
            # so emitting on a bare non-constant argument generated noisy
            # FPs on clean codebases like `psf/requests`. For the open()
            # / Path() / send_file() family the conservative posture (emit
            # on any non-constant arg) still holds — passing user input
            # to those is suspicious enough to be worth flagging even
            # without a proven taint flow.
            if sink_name.startswith("os.path.") and chain is None:
                pass
            else:
                # Two claims, two gradings. Without a chain, all Fendix has
                # observed is that a NON-CONSTANT value reaches a filesystem
                # API — it has not established that the value is externally
                # controlled, and a dynamic path is not automatically a
                # traversal. Saying "path traversal" there names a
                # vulnerability class the evidence has not reached, so the
                # unproven form says what was actually seen and stays MEDIUM,
                # below the default --fail-on HIGH, i.e. non-blocking.
                #
                # With a chain, request data demonstrably reaches path
                # construction past the recognised guards, and the finding
                # takes the traversal wording and HIGH. The chain also ships as
                # taint_chain, which the SARIF exporter renders as codeFlows —
                # the same source→sink representation SSRF gets.
                self._emit_finding(
                    "PY_PATH_TRAVERSAL",
                    "Potential unsafe dynamic filesystem path",
                    "MEDIUM",
                    "MEDIUM",
                    "CWE-22",
                    (
                        "Validate the path against an allow-list of permitted filenames or a "
                        "base directory. Use pathlib.Path.resolve() and confirm the resolved "
                        "path is still under the intended root before opening. Reject any "
                        "input containing '..' or absolute paths."
                    ),
                    node.lineno,
                    taint_chain=chain,
                    proven_title="Path traversal — user-controlled input reaches filesystem path",
                    proven_severity="HIGH",
                    sink=sink_expr,
                )

        # LLM prompt-injection sink (Sanad A1/A2). An untrusted value reaching
        # an LLM chat-completion call / prompt arg is prompt injection. Request
        # input → HIGH (direct, A1); datastore/RAG-retrieved content → MEDIUM
        # (indirect/second-order, A2). The datastore source is recognized ONLY
        # here (sink-gated via extra_source) so it can't leak into SQL/XSS/SSRF.
        elif self._is_llm_prompt_sink(node):
            arg = self._llm_prompt_tainted_arg(node)
            if arg is not None:
                sink_name = self._llm_sink_name(node)
                req_chain = self._collect_taint_chain(
                    arg, node.lineno, f"{sink_name}({_ast_expr_text(arg)})"
                )
                if req_chain is not None:
                    self._emit_finding(
                        "PY_LLM_PROMPT_INJECTION",
                        "Prompt injection — untrusted input flows into an LLM prompt",
                        "HIGH",
                        "HIGH",
                        "CWE-77",
                        (
                            "Never concatenate untrusted input into an LLM prompt. "
                            "Isolate user/query content in a separate message role, "
                            "delimit and escape it, and instruct the model to treat "
                            "fenced content as data, not instructions."
                        ),
                        node.lineno,
                        taint_chain=req_chain,
                    )
                else:
                    ds_chain = self._collect_taint_chain(
                        arg,
                        node.lineno,
                        f"{sink_name}({_ast_expr_text(arg)})",
                        extra_source=_references_datastore_read,
                    )
                    if ds_chain is not None:
                        self._emit_finding(
                            "PY_LLM_PROMPT_INJECTION",
                            "Indirect prompt injection — retrieved/stored content "
                            "flows into an LLM prompt",
                            "HIGH",
                            "MEDIUM",
                            "CWE-77",
                            (
                                "Treat retrieved (RAG/datastore) content as untrusted. "
                                "Delimit and escape each snippet, inspect for injection "
                                "markers, and keep it in a data-only message segment."
                            ),
                            node.lineno,
                            category="injection",
                            taint_chain=ds_chain,
                        )

        # JWT crypto-misuse (Sanad C2): jwt.decode(..., verify=False) or
        # algorithms driven by a non-literal/None (algorithm-confusion surface).
        elif self._is_jwt_misuse(node):
            self._emit_finding(
                "PY_JWT_WEAK",
                "Weak JWT verification — decode with verify=False or unpinned algorithm",
                "HIGH",
                "MEDIUM",
                "CWE-347",
                (
                    "Always verify signatures: never pass verify=False. Pin the "
                    "expected algorithm(s) explicitly (e.g. algorithms=['RS256']) "
                    "and reject a config that permits a symmetric fallback."
                ),
                node.lineno,
                category="auth_bypass",
            )

        # Secret-in-log (Sanad A4): a secret-looking value (os.getenv("*_KEY"/
        # "_SECRET"/"_TOKEN") or a password-y identifier) passed to a logging
        # sink or interpolated into a log message.
        elif self._is_secret_in_log(node):
            self._emit_finding(
                "PY_SECRET_IN_LOG",
                "Secret written to logs — credential exposure",
                "MEDIUM",
                "MEDIUM",
                "CWE-532",
                (
                    "Never log secrets/API keys/tokens. Mask the value (show only "
                    "a prefix) or omit it; scrub secrets from exception bodies "
                    "before logging."
                ),
                node.lineno,
                category="secrets",
            )

        self.generic_visit(node)

    def _is_jwt_misuse(self, node: ast.Call) -> bool:
        """True for jwt.decode(...) with verify=False, or with no explicit
        algorithms= pinning (unpinned algorithm — confusion surface)."""
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "decode"):
            return False
        # receiver resolves to the jwt module (direct, aliased, or from-import).
        resolved = self._call_module_attr(node)
        if resolved is None or resolved[0] != "jwt":
            # also accept a bare `decode` from `from jwt import decode`
            if not (
                isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "jwt"
            ):
                return False
        for kw in node.keywords:
            if (
                kw.arg == "verify"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
            ):
                return True
            # options={"verify_signature": False}
            if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    if (
                        isinstance(k, ast.Constant)
                        and k.value == "verify_signature"
                        and isinstance(v, ast.Constant)
                        and v.value is False
                    ):
                        return True
        return False

    # Logging sinks + secret-source identifiers for the secret-in-log rule.
    _LOG_METHODS = frozenset(
        {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
    )

    def _is_secret_in_log(self, node: ast.Call) -> bool:
        """True if a logging call carries an actual secret value. Tight by
        design (real-corpus FP control): only the INTERPOLATED expressions of a
        log message are inspected — never the literal text — and a secret means
        an os.getenv/os.environ.get of a secret-named key, or a password-y
        identifier (whole-token), or a variable bound to one."""
        f = node.func
        is_log = (isinstance(f, ast.Attribute) and f.attr in self._LOG_METHODS) or (
            isinstance(f, ast.Name) and f.id in self._LOG_METHODS
        )
        if not is_log or not node.args:
            return False
        return any(self._arg_references_secret(arg) for arg in node.args)

    def _arg_references_secret(self, arg: ast.AST) -> bool:
        """Inspect a single log argument. For an f-string, only the dynamic
        FormattedValue expressions count (the constant text is never a secret)."""
        if isinstance(arg, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue)
                and self._arg_references_secret(v.value)
                for v in arg.values
            )
        return self._expr_references_secret(arg)

    def _expr_references_secret(
        self, expr: ast.AST, _depth: int = 0, _seen: set[int] | None = None
    ) -> bool:
        """True if `expr` resolves to a secret: os.getenv/os.environ.get of a
        secret-named key, a password-y identifier, or a Name bound to one.

        Performance (Product-Constitution Rule 6): this used to restart a full
        ``ast.walk`` per resolved binding with no memoization, so a large scope
        whose log call interpolated names bound to deeply-nested expressions
        (e.g. an ``acc += acc`` accumulator, whose synthesized ``BinOp`` tree
        DOUBLES per rebind, or many names sharing bindings) re-walked the same
        subtrees combinatorially — a single 907-line file (TwiScope
        delivery_tasks.py) took ~45 s, blowing up a whole-repo scan to ~50 min.
        A shared ``_seen`` set of ``id(node)`` collapses the exponential
        shared-subtree re-walks into linear work: every AST node object is
        visited at most once across the whole query. Correctness is unchanged —
        the same set of nodes is inspected, just never twice."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if _seen is None:
            _seen = set()
        for n in ast.walk(expr):
            # Each unique AST node is inspected once per top-level query; a
            # binding resolved from two sibling names, or a deep tree reached by
            # two paths, is not re-walked (this is the O(fan-out) fix).
            nid = id(n)
            if nid in _seen:
                continue
            _seen.add(nid)
            # A path/file-location identifier holds a *location*, not the secret
            # value (TwiScope SEC-263): `GOOGLE_APPLICATION_CREDENTIALS` is a path
            # to a creds file, and logging that path leaks nothing. Skip both the
            # direct env read and any binding it resolves to.
            if isinstance(n, ast.Name) and _name_is_location_ref(n.id):
                continue
            if self._is_env_secret_read(n) and not _env_read_is_location(n):
                return True
            if isinstance(n, ast.Name) and _looks_like_password_id(n.id):
                return True
            if isinstance(n, ast.Name):
                bound = self._resolve_binding(n)
                if bound is not None and bound is not n:
                    # A Name bound to a (possibly awaited) Call holds that call's
                    # RETURN value, not its arguments (TwiScope SEC-263,
                    # email_sender): logging `result = await send_mail(password=pw)`
                    # logs the bool result, not `pw`. Only treat the binding as
                    # secret if the call is itself a direct secret read (env
                    # getter) — do NOT walk its argument list.
                    unwrapped = bound.value if isinstance(bound, ast.Await) else bound
                    if isinstance(unwrapped, ast.Call):
                        if self._is_env_secret_read(
                            unwrapped
                        ) and not _env_read_is_location(unwrapped):
                            return True
                        continue
                    if self._expr_references_secret(bound, _depth + 1, _seen):
                        return True
        return False

    @staticmethod
    def _is_env_secret_read(n: ast.AST) -> bool:
        """True ONLY for os.getenv("<secret>") / os.environ.get("<secret>") /
        os.environ["<secret>"] with a secret-named key (whole-token). A bare
        obj.get("messages") on an arbitrary object is NOT an env read."""
        # os.environ["KEY"] subscript form.
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
            v = n.value
            if isinstance(v, ast.Attribute) and v.attr == "environ":
                return _key_is_secret(n.slice.value)
            return False
        if not (
            isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Constant)
        ):
            return False
        f = n.func
        if not isinstance(f, ast.Attribute):
            return False
        is_getenv = (
            f.attr == "getenv" and isinstance(f.value, ast.Name) and f.value.id == "os"
        )
        is_environ_get = (
            f.attr == "get"
            and isinstance(f.value, ast.Attribute)
            and f.value.attr == "environ"
        )
        return (is_getenv or is_environ_get) and _key_is_secret(n.args[0].value)

    # ------------------------------------------------------------------
    # Statement-level visitors (for scope tracking and If-based patterns)
    # ------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        """Push a new scope for assignment tracking, recurse, then pop."""
        self._scopes.append({})
        self._func_stack.append(node)
        self.generic_visit(node)
        self._func_stack.pop()
        self._scopes.pop()

    # async def is the same shape — share the implementation.
    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """Record assignments so later sinks can resolve the bound value.

        Handles (audit #25-28): single Name, attribute (`self.q = ...`),
        subscript (`d['k'] = ...`), and tuple/list unpacking. For tuple
        unpacking from a tuple/list RHS we bind element-wise; otherwise each
        target is bound to the whole RHS (conservative — preserves taint)."""
        if not self._scopes:
            self.generic_visit(node)
            return
        scope = self._scopes[-1]
        for target in node.targets:
            self._bind_target(target, node.value, scope)
        self.generic_visit(node)

    def _bind_target(self, target: ast.AST, value: ast.AST, scope: dict) -> None:
        """Bind one assignment target to `value` in `scope`."""
        if isinstance(target, ast.Name):
            scope[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elts = target.elts
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(
                elts
            ):
                for t, v in zip(elts, value.elts):
                    self._bind_target(t, v, scope)
            else:
                # Non-decomposable RHS — bind every target to the whole RHS so
                # taint is preserved (conservative).
                for t in elts:
                    self._bind_target(t, value, scope)
            return
        key = _binding_key(target)
        if key is not None:
            scope[key] = value

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        """Record `x += value` (audit #1). Rebinds the target to a synthesized
        BinOp(prior_or_Name, op, value) so an accumulator that starts as a
        constant and appends tainted input is correctly seen as tainted — and
        does NOT remain a stale constant that suppresses the sink."""
        if self._scopes:
            scope = self._scopes[-1]
            key = (
                node.target.id
                if isinstance(node.target, ast.Name)
                else _binding_key(node.target)
            )
            if key is not None:
                prior = scope.get(key, node.target)
                scope[key] = ast.BinOp(left=prior, op=node.op, right=node.value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        """Push a scope for the class body so class-level assignments don't
        leak into module scope and falsely shadow handler-local names (#17)."""
        self._scopes.append({})
        self.generic_visit(node)
        self._scopes.pop()

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        """Bind a for-loop target to the iterable so taint flows through
        `for x in request.args.values(): sink(x)` (audit for/with gap). The
        target is bound to the iterable expression — if the iterable traces to
        a request source, the loop variable does too."""
        if self._scopes:
            self._bind_target(node.target, node.iter, self._scopes[-1])
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        """Bind `with ctx as x` targets to the context expression so taint
        flows through `with open(request.args['f']) as fh: ...` style code
        and `with get_payload() as p` (audit for/with gap)."""
        if self._scopes:
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind_target(
                        item.optional_vars, item.context_expr, self._scopes[-1]
                    )
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        """Populate _module_aliases so aliased imports are tracked."""
        for alias in node.names:
            local_name = alias.asname if alias.asname else alias.name.split(".")[0]
            self._module_aliases[local_name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        """Track `from <mod> import <sym> [as <local>]` so bare-name calls of
        dangerous symbols resolve back to their module (audit #8-13)."""
        module = node.module or ""
        for alias in node.names:
            local_name = alias.asname or alias.name
            self._from_imports[local_name] = (module, alias.name)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        """Detect auth-header-trust patterns at if-statement boundaries."""
        if _is_request_header_trust(node.test):
            self._emit_finding(
                "PY_AUTH_HEADER_TRUST",
                "Auth decision based on a client-controllable header",
                "HIGH",
                "MEDIUM",
                "CWE-290",
                (
                    "Never trust client-supplied headers (X-Admin, X-Role, etc.) for auth. "
                    "Use a verified session token or signed JWT instead."
                ),
                node.lineno,
                category="auth_bypass",
            )
        self.generic_visit(node)

    def _call_module_attr(self, node: ast.Call) -> tuple[str, str] | None:
        """Resolve a call to (canonical_module, attr) regardless of import shape.

        Handles three forms (audit #8-13):
          * `mod.attr(...)`            -> (canonical(mod), attr)  via _module_aliases
          * `bare(...)` after `from mod import bare`  -> (mod, orig_symbol)
          * `bare(...)` after `from mod import x as bare` -> (mod, x)
        Returns None when the receiver can't be resolved to a known module.
        """
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = self._module_aliases.get(func.value.id, func.value.id)
            return (base, func.attr)
        if isinstance(func, ast.Name) and func.id in self._from_imports:
            module, symbol = self._from_imports[func.id]
            return (module, symbol)
        return None

    # ─── LLM prompt-injection sink (Sanad A1/A2) ──────────────────────
    #
    # Two shapes count as "reaching the model":
    #   1. provider chat-completion CALLS — *.chat.completions.create(...),
    #      *.completions.create, *.messages.create (Anthropic),
    #      *.chat(...)/*.generate(...)/*.invoke(...) (Ollama/LangChain).
    #   2. prompt-assembly via a *prompt*/messages/system variable assigned a
    #      tainted f-string/concat (handled in visit_Assign → recorded so the
    #      var resolves to its tainted value when it reaches a call here).
    _LLM_CALL_ATTRS = frozenset(
        {"create", "chat", "generate", "invoke", "complete", "completion"}
    )
    _LLM_PROMPT_KWARGS = frozenset(
        {"messages", "prompt", "input", "text", "content", "system"}
    )

    def _is_llm_prompt_sink(self, node: ast.Call) -> bool:
        """True if `node` is an LLM chat/completion call (and a tainted prompt
        arg is present). Recognises the *.chat.completions.create /
        *.messages.create / *.chat / *.generate / *.invoke shapes."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        attr = func.attr
        # *.chat.completions.create(...)  / *.completions.create(...)
        if attr == "create":
            v = func.value
            if isinstance(v, ast.Attribute) and v.attr in {"completions", "messages"}:
                return self._llm_prompt_tainted_arg(node) is not None
            return False
        # *.chat(...) / *.generate(...) / *.invoke(...) / *.complete(...)
        if attr in {"chat", "generate", "invoke", "complete", "completion"}:
            return self._llm_prompt_tainted_arg(node) is not None
        return False

    def _llm_sink_name(self, node: ast.Call) -> str:
        f = node.func
        if isinstance(f, ast.Attribute):
            if isinstance(f.value, ast.Attribute):
                return f"{f.value.attr}.{f.attr}"
            return f.attr
        return "llm"

    def _llm_prompt_tainted_arg(self, node: ast.Call) -> ast.AST | None:
        """Return the non-constant prompt/messages arg of an LLM call, or None
        if every candidate is a constant (safe static template)."""
        candidates: list[ast.AST] = []
        # messages=[{"content": <x>}, ...] — pull each element's content value.
        for kw in node.keywords:
            if kw.arg in self._LLM_PROMPT_KWARGS:
                candidates.extend(self._extract_message_contents(kw.value))
        # First positional for *.chat/.generate/.invoke(prompt).
        if node.args:
            candidates.append(node.args[0])
        for c in candidates:
            if self._llm_value_is_dynamic(c):
                return c
        return None

    def _extract_message_contents(self, value: ast.AST) -> list[ast.AST]:
        """From a messages=[...] list literal, return each dict's content value;
        for a bare prompt string return [value]."""
        out: list[ast.AST] = []
        if isinstance(value, (ast.List, ast.Tuple)):
            for elt in value.elts:
                if isinstance(elt, ast.Dict):
                    for k, v in zip(elt.keys, elt.values):
                        if isinstance(k, ast.Constant) and k.value in {
                            "content",
                            "text",
                        }:
                            out.append(v)
                else:
                    out.append(elt)
        else:
            out.append(value)
        return out

    def _llm_value_is_dynamic(self, expr: ast.AST) -> bool:
        """True if `expr` is a non-constant prompt value (a constant template is
        safe). Reuses the const-fold so a fully-static f-string is not flagged."""
        if isinstance(expr, ast.Constant):
            return False
        if isinstance(expr, (ast.JoinedStr, ast.BinOp)):
            return not self._sql_expr_is_constant(expr)
        if isinstance(expr, ast.Name):
            bound = self._resolve_binding(expr)
            if bound is None:
                return False  # unresolved bare name → not provably dynamic
            return self._llm_value_is_dynamic(bound)
        # Call (.format / retrieval), Subscript (rows[0]['text']), Attribute → dynamic.
        return isinstance(expr, (ast.Call, ast.Subscript, ast.Attribute))

    def _cmdi_arg_is_dangerous(self, node: ast.Call) -> bool:
        """Return True if the first positional arg to a cmdi sink is non-literal.

        Parity helper for os.system / os.popen / subprocess(shell=True).
        A literal-string argument (or a Name that resolves to a Constant
        in the local scope) is the safe shape — `os.system("echo hi")` is
        not exploitable. Variable args (Name not-in-scope, Call, BinOp,
        JoinedStr) are the dangerous case; `_collect_taint_chain`
        decides whether the variable actually traces back to a request
        source.

        Added 2026-05-13 during the accuracy evaluation — pre-fix all
        os.system/popen/subprocess(shell=True) calls fired unconditionally,
        which surfaced as a false positive on safe literal-string calls.
        Brings cmdi posture into line with SSRF / XSS / path-traversal /
        open-redirect (all of which already skip Constant args).
        """
        if not node.args:
            return False
        first = node.args[0]
        # Constant literal is safe (e.g. `os.system("echo hello")`)
        if isinstance(first, ast.Constant):
            return False
        # Name that resolves to a constant in the local scope is also safe.
        # Innermost scope wins: stop at the first scope that defines the name
        # so an outer-scope same-name constant can't veto an inner tainted
        # binding (audit #17).
        if isinstance(first, ast.Name):
            for scope in reversed(self._scopes):
                if first.id in scope:
                    bound = scope[first.id]
                    # Safe if the bound value folds to a constant (covers a
                    # constant accumulator built with += — audit-fix follow-up).
                    return not self._expr_folds_to_constant(bound)
        # An inline BinOp/JoinedStr that folds to constant is also safe
        # (e.g. os.system("echo " + "hi")).
        if isinstance(
            first, (ast.BinOp, ast.JoinedStr)
        ) and self._expr_folds_to_constant(first):
            return False
        return True

    def _is_subprocess_shell_true(self, node: ast.Call) -> bool:
        """Return True for subprocess.<fn>(..., shell=True), the always-shell
        helpers subprocess.getoutput / getstatusoutput, or
        asyncio.create_subprocess_shell. Resolves through import aliases and
        from-imports (audit #10 + sink-breadth gaps)."""
        resolved = self._call_module_attr(node)
        if resolved is None:
            return False
        module, attr = resolved
        if module == "subprocess" and attr in {"getoutput", "getstatusoutput"}:
            return True
        if module == "asyncio" and attr == "create_subprocess_shell":
            return True
        if module != "subprocess":
            return False
        if attr not in {"run", "call", "Popen", "check_output", "check_call"}:
            return False
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value
            ):
                return True
        return False

    _SQL_EXEC_METHODS = {"execute", "executemany", "executescript"}

    def _is_sql_injection(self, node: ast.Call) -> bool:
        """Return True if the call is cursor.execute/executemany/executescript(<unsafe>).

        Unsafe means a non-constant-foldable BinOp/JoinedStr/Call
        (`%`/`+`/f-string/.format()), OR a Name/Subscript/Attribute that
        resolves to one of those via intra-function tracking (TASK-087 +
        audit #15/#25-28). A fully-constant f-string / literal concat /
        literal .format() is folded away and treated as safe (audit #15)."""
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self._SQL_EXEC_METHODS
        ):
            return False
        if not node.args:
            return False
        first_arg = node.args[0]
        if isinstance(first_arg, ast.NamedExpr):  # walrus: execute(q := ...)
            first_arg = first_arg.value
        if isinstance(first_arg, ast.Constant):
            return False
        if isinstance(first_arg, ast.Call) and self._is_psycopg_sql_composable(
            first_arg
        ):
            return False  # psycopg2.sql.SQL(...).format(Identifier(...)) is safe
        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
            return not self._sql_expr_is_constant(first_arg)
        # Name / Subscript / Attribute lookup in scope chain — innermost wins.
        if isinstance(first_arg, (ast.Name, ast.Subscript, ast.Attribute)):
            assigned = self._resolve_binding(first_arg)
            if assigned is not None and isinstance(
                assigned, (ast.BinOp, ast.JoinedStr, ast.Call)
            ):
                return not self._sql_expr_is_constant(assigned)
            # 1-hop interprocedural: a bare PARAMETER may receive a built SQL
            # string from a caller. Resolve to the caller's arg and re-test.
            if assigned is None and isinstance(first_arg, ast.Name):
                caller_arg = self._resolve_param_to_caller_arg(first_arg.id)
                if caller_arg is not None and isinstance(
                    caller_arg, (ast.BinOp, ast.JoinedStr, ast.Call)
                ):
                    return not self._sql_expr_is_constant(caller_arg)
        return False

    def _sql_expr_is_constant(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if a string-building expression folds to a constant (no taint
        can enter): all-constant BinOp, an f-string with no dynamic field, or
        a `<const>.format(<const>...)` call. Audit #15 (literal-SQL FP)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.BinOp):
            # `"<tmpl>" % (a, b)` — constant iff template + every value is const
            # (B1: %-format with a const tuple/list, e.g. cursor.execute(
            # '...%s...' % ('a','b'))).
            if isinstance(expr.op, ast.Mod):
                if not self._sql_expr_is_constant(expr.left, _depth + 1):
                    return False
                rhs = expr.right
                values = (
                    list(rhs.elts) if isinstance(rhs, (ast.Tuple, ast.List)) else [rhs]
                )
                return all(self._sql_expr_is_constant(v, _depth + 1) for v in values)
            return self._sql_expr_is_constant(
                expr.left, _depth + 1
            ) and self._sql_expr_is_constant(expr.right, _depth + 1)
        if isinstance(expr, ast.IfExp):
            # `<c> if cond else <c>` — constant iff both branches fold (B1).
            return self._sql_expr_is_constant(
                expr.body, _depth + 1
            ) and self._sql_expr_is_constant(expr.orelse, _depth + 1)
        if isinstance(expr, ast.JoinedStr):
            # Constant iff every FormattedValue interpolates a constant-folding expr.
            for v in expr.values:
                if isinstance(v, ast.FormattedValue):
                    if not self._sql_expr_is_constant(v.value, _depth + 1):
                        return False
            return True
        if isinstance(expr, ast.Name):
            assigned = self._resolve_binding(expr)
            return assigned is not None and self._sql_expr_is_constant(
                assigned, _depth + 1
            )
        if isinstance(expr, ast.Call):
            # "<sep>".join([<const>, ...]) — constant iff sep + every element
            # const (B1: 'SELECT ' + ', '.join(['a','b']) + ' FROM t').
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "join":
                if not self._sql_expr_is_constant(expr.func.value, _depth + 1):
                    return False
                if expr.args and isinstance(expr.args[0], (ast.List, ast.Tuple)):
                    return all(
                        self._sql_expr_is_constant(e, _depth + 1)
                        for e in expr.args[0].elts
                    )
                return False
            # "<lit>".format(<lit>, ...) — constant iff receiver + all args constant.
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
                if not self._sql_expr_is_constant(expr.func.value, _depth + 1):
                    return False
                # Both positional AND keyword args must be constant — a tainted
                # name=value kwarg (`"...{name}".format(name=user)`) is dynamic.
                if not all(
                    self._sql_expr_is_constant(a, _depth + 1) for a in expr.args
                ):
                    return False
                return all(
                    kw.value is not None
                    and self._sql_expr_is_constant(kw.value, _depth + 1)
                    for kw in expr.keywords
                )
            return False
        return False

    def _is_psycopg_sql_composable(self, node: ast.AST) -> bool:
        """True if `node` is a psycopg2.sql Composable expression — sql.SQL(...),
        sql.SQL(...).format(...), sql.Identifier(...), sql.Composed([...]) — which
        is the SAFE parameterized-identifier API, NOT str.format injection
        (TwiScope FP-6: 5 false CRITICALs)."""
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        # sql.SQL(...).format(...) — the receiver of .format is itself a sql.* call.
        if isinstance(f, ast.Attribute) and f.attr == "format":
            return self._is_psycopg_sql_composable(f.value)
        # sql.SQL(...) / sql.Identifier(...) / sql.Composed(...) — Attribute on `sql`.
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            base = self._module_aliases.get(f.value.id, f.value.id)
            return base == "sql" and f.attr in {
                "SQL",
                "Identifier",
                "Composed",
                "Literal",
                "Placeholder",
            }
        # Bare SQL(...)/Identifier(...) after `from psycopg2.sql import SQL`.
        if isinstance(f, ast.Name) and f.id in self._from_imports:
            mod, sym = self._from_imports[f.id]
            return mod.endswith("psycopg2.sql") or mod == "sql"
        return False

    def _expr_folds_to_constant(self, expr: ast.AST) -> bool:
        """General 'does this string-building expr contain only constants'
        check, shared by the cmdi / SQL suppression paths. A constant
        accumulator (`x = 'a'; x += 'b'`) folds to constant and is NOT a sink
        (prevents the visit_AugAssign synthesized-BinOp false positive)."""
        return self._sql_expr_is_constant(expr)

    def _resolve_binding(self, target: ast.AST) -> ast.AST | None:
        """Resolve a Name / Subscript / Attribute target to its most recent
        assigned value via the scope chain (innermost wins). Audit #25-28."""
        if isinstance(target, ast.Name):
            for scope in reversed(self._scopes):
                if target.id in scope:
                    return scope[target.id]
            return None
        key = _binding_key(target)
        if key is None:
            return None
        for scope in reversed(self._scopes):
            if key in scope:
                return scope[key]
        return None

    # ─── Django ORM SQL-injection sinks (bandit B610/B611) ──────────

    def _is_django_orm_sql_sink(self, node: ast.Call) -> bool:
        """Return True if the call is a Django-ORM raw-SQL sink with
        a non-literal SQL argument.

        Three shapes:
          1. `<qs>.raw(<expr>)`            — Django Manager.raw()
          2. `<qs>.extra(where=[...], select={...}, tables=[...])` with non-literal value
          3. `RawSQL(<expr>, [...])` or `<mod>.RawSQL(...)` — raw SQL expression
        """
        return self._django_orm_sql_tainted_arg(node) is not None

    def _django_orm_sql_tainted_arg(self, node: ast.Call) -> ast.AST | None:
        """Return the AST node of the tainted SQL fragment, or None if safe.

        We return the FIRST non-literal SQL fragment we find so taint-chain
        reconstruction has something concrete to walk back from.
        """
        # Shape 3: RawSQL(sql, params) — bare-name or attribute call.
        is_rawsql = (isinstance(node.func, ast.Name) and node.func.id == "RawSQL") or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "RawSQL"
        )
        if is_rawsql:
            # First positional, or sql= kwarg, must be non-literal.
            sql_arg: ast.AST | None = None
            if node.args:
                sql_arg = node.args[0]
            for kw in node.keywords:
                if kw.arg == "sql":
                    sql_arg = kw.value
                    break
            if sql_arg is None:
                return None
            if self._sql_value_is_safe(sql_arg):
                return None
            return sql_arg

        # Shape 1: <qs>.raw(<sql>)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "raw"
            and node.args
        ):
            sql_arg = node.args[0]
            if self._sql_value_is_safe(sql_arg):
                return None
            return sql_arg

        # Shape 2: <qs>.extra(...) — any of select/where/tables non-literal
        if isinstance(node.func, ast.Attribute) and node.func.attr == "extra":
            for kw in node.keywords:
                if kw.arg not in {"select", "where", "tables"}:
                    continue
                value = kw.value
                # `where=` and `tables=` take a list; if the list is a List
                # literal we have to check every element.
                if isinstance(value, ast.List):
                    for elt in value.elts:
                        if not self._sql_value_is_safe(elt):
                            return elt
                    continue
                # `select=` takes a dict; check every value.
                if isinstance(value, ast.Dict):
                    for v in value.values:
                        if v is not None and not self._sql_value_is_safe(v):
                            return v
                    continue
                # Bare Name/Call/BinOp/etc — fall through to the value-safety check.
                if not self._sql_value_is_safe(value):
                    return value
        return None

    def _sql_value_is_safe(self, value: ast.AST) -> bool:
        """Return True if `value` is a literal-shape SQL fragment.

        Mirrors the suppression posture used by every other reachable
        sink: a constant string, or a Name that resolves to a constant
        in the current scope chain, is safe. Anything else (Call, BinOp,
        JoinedStr, .format(), %) is non-literal and counts as tainted.
        """
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, ast.Name):
            for scope in reversed(self._scopes):
                if value.id in scope:
                    return isinstance(scope[value.id], ast.Constant)
        return False

    def _django_orm_sql_sink_label(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name) and node.func.id == "RawSQL":
            return "RawSQL"
        if isinstance(node.func, ast.Attribute):
            return f"<qs>.{node.func.attr}"
        return "django_orm"

    _DESER_MODULES = {"pickle", "cPickle", "_pickle", "marshal", "dill"}

    def _is_pickle_load(self, node: ast.Call) -> bool:
        """Return True for an unsafe-deserialization load() call: pickle/cPickle/
        _pickle/marshal/dill .load|.loads and jsonpickle.decode, resolved through
        import aliases and from-imports (audit #11/#13 + deser sink-breadth)."""
        resolved = self._call_module_attr(node)
        if resolved is None:
            return False
        module, attr = resolved
        # Round-trip: pickle.loads(pickle.dumps(x)) / jsonpickle.decode(
        # jsonpickle.encode(x)) deserializes data produced in the same
        # expression — no untrusted input crosses the boundary. Real-data FP
        # (httpx/requests test suites). Suppress.
        if node.args and self._arg_is_serialize_roundtrip(node.args[0]):
            return False
        if module == "jsonpickle" and attr in {"decode", "loads"}:
            return True
        return module in self._DESER_MODULES and attr in {"load", "loads"}

    def _arg_is_serialize_roundtrip(self, arg: ast.AST) -> bool:
        """True if `arg` is a serialize call (pickle.dumps / marshal.dumps /
        jsonpickle.encode / *.dumps) — i.e. the loads() consumes freshly
        serialized data, not untrusted input."""
        if not isinstance(arg, ast.Call):
            return False
        f = arg.func
        name = (
            f.attr
            if isinstance(f, ast.Attribute)
            else (f.id if isinstance(f, ast.Name) else "")
        )
        return name in {"dumps", "dump", "encode"}

    def _is_unsafe_yaml_load(self, node: ast.Call) -> bool:
        """Return True for yaml.load() without SafeLoader, or yaml.unsafe_load*.
        Resolves through import aliases and from-imports (audit #12)."""
        resolved = self._call_module_attr(node)
        if resolved is None:
            return False
        module_name, attr = resolved
        if module_name != "yaml":
            return False
        # Always-unsafe variants.
        if attr in {"unsafe_load", "unsafe_load_all", "load_all"}:
            return True
        if attr != "load":
            return False
        # yaml.load(stream) — check for Loader= keyword that names a safe loader.
        loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
        if loader_kw is None:
            return True
        return not _is_safe_loader_expr(loader_kw.value)

    def _is_weak_password_hash(self, node: ast.Call) -> bool:
        """Return True if hashlib.md5/sha1 is hashing a password-like value."""
        if not isinstance(node.func, ast.Attribute):
            return False
        if not (
            isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib"
        ):
            return False
        algo: str | None = None
        if node.func.attr in {"md5", "sha1"}:
            algo = node.func.attr
        elif node.func.attr == "new" and node.args:
            # hashlib.new("md5", data) — first arg is the algo name.
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if first.value.lower() in {"md5", "sha1"}:
                    algo = first.value.lower()
        if algo is None:
            return False
        # Find the data argument: arg[0] for md5/sha1, arg[1] for new(algo, data).
        data_arg = None
        if node.func.attr in {"md5", "sha1"} and node.args:
            data_arg = node.args[0]
        elif node.func.attr == "new" and len(node.args) >= 2:
            data_arg = node.args[1]
        if data_arg is None:
            return False
        return _arg_subtree_looks_like_password(data_arg)

    def _is_open_redirect(self, node: ast.Call) -> bool:
        """Return True if redirect(...)/HttpResponseRedirect(...) gets non-literal input.

        Posture upgraded to match SSRF/XSS/path-traversal (surfaced by
        the accuracy corpus, 2026-05-13): emit on any non-literal arg,
        and let `_collect_taint_chain` decide reachability. Pre-upgrade
        only direct `redirect(request.args.get("x"))` was caught; the
        far more common `next_url = request.args.get("x"); return
        redirect(next_url)` pattern was silently missed because the
        first arg was a Name, not a request-access subtree.
        """
        is_redirect_func = (
            isinstance(node.func, ast.Name)
            and node.func.id in {"redirect", "HttpResponseRedirect"}
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"redirect", "HttpResponseRedirect"}
        )
        if not (is_redirect_func and node.args):
            return False
        first = node.args[0]
        # Constant literal redirect target is safe.
        if isinstance(first, ast.Constant):
            return False
        # Name that resolves to a constant in scope is also safe.
        if isinstance(first, ast.Name):
            for scope in reversed(self._scopes):
                if first.id in scope:
                    if isinstance(scope[first.id], ast.Constant):
                        return False
                    break  # innermost binding wins (audit #17)
        # Whitelisted dict lookup / set-membership / URL-host allowlist guard
        # → sanitised.
        if self._arg_is_sanitised(first, node.lineno, url_sink=True):
            return False
        # Framework URL builders produce safe internal URLs from a route NAME,
        # not user input: Flask url_for(...), Django reverse(...). A redirect to
        # one of these is not an open redirect (real-data FP on flask/django).
        if self._is_safe_url_builder(first):
            return False
        return True

    def _is_safe_url_builder(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if `expr` is (or resolves to) a call to a known safe internal
        URL builder — Flask url_for / Django reverse / reverse_lazy — whose
        result is a server-controlled route, not attacker input.

        Also true when the LEADING segment of an f-string / `+` concatenation is
        such a builder (TwiScope SEC-141): `f"{reverse('x')}?q={user}"`. The
        builder fixes scheme+host+path; only the query string is appended, which
        cannot redirect to a different origin, so it stays a safe internal URL.
        """
        if _depth >= _MAX_TAINT_HOPS:
            return False
        _SAFE_URL_BUILDERS = {"url_for", "reverse", "reverse_lazy"}
        if isinstance(expr, ast.Call):
            f = expr.func
            name = (
                f.attr
                if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else "")
            )
            return name in _SAFE_URL_BUILDERS
        if isinstance(expr, ast.Name):
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    bound = scope[expr.id]
                    # Self-referential query append: `url = f"{url}?q={x}"`. The
                    # binding overwrote the original reverse()/url_for() value, so
                    # resolving the name finds only the f-string. It is still safe
                    # iff the extension is query/fragment-only (origin-preserving).
                    if self._is_query_append_of(bound, expr.id):
                        return True
                    return self._is_safe_url_builder(bound, _depth + 1)
        # `<builder> + "?..."` — leading operand decides the origin.
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._is_safe_url_builder(expr.left, _depth + 1)
        # f-string whose first segment is the builder result.
        if isinstance(expr, ast.JoinedStr) and expr.values:
            first = expr.values[0]
            if isinstance(first, ast.FormattedValue):
                return self._is_safe_url_builder(first.value, _depth + 1)
        return False

    def _is_query_append_of(self, expr: ast.AST, name: str) -> bool:
        """True if `expr` extends the variable `name` with ONLY a query/fragment
        suffix — `f"{name}?a={x}"` or `name + "?a=" + x`. Appending a `?`/`#`/`&`
        segment to a URL cannot change its scheme/host/path, so if `name` was a
        safe internal target the extended value is too. We require the leading
        segment to be `name` itself and the first appended literal to start with
        a query/fragment delimiter."""
        if isinstance(expr, ast.JoinedStr) and len(expr.values) >= 2:
            first, second = expr.values[0], expr.values[1]
            if (
                isinstance(first, ast.FormattedValue)
                and isinstance(first.value, ast.Name)
                and first.value.id == name
                and isinstance(second, ast.Constant)
                and isinstance(second.value, str)
                and second.value[:1] in {"?", "#", "&"}
            ):
                return True
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left, right = expr.left, expr.right
            if (
                isinstance(left, ast.Name)
                and left.id == name
                and isinstance(right, ast.Constant)
                and isinstance(right.value, str)
                and right.value[:1] in {"?", "#", "&"}
            ):
                return True
        return False

    # SSRF sinks the engine recognises. Each entry is the
    # display name we use in the finding title.
    _SSRF_REQUESTS_METHODS = {
        "get",
        "post",
        "put",
        "delete",
        "head",
        "patch",
        "options",
        "request",
    }
    _SSRF_URLLIB_METHODS = {"urlopen", "urlretrieve"}

    # Receiver Names we treat as HTTP-client instances ONLY when they resolve
    # to a recognized client construction (TwiScope FP-3: redis/cache/db clients
    # share .get/.delete/.post and must not be matched as SSRF sinks).
    _HTTP_CLIENT_CTOR_MODULES = {"requests", "httpx", "aiohttp"}
    _HTTP_CLIENT_CTOR_NAMES = {"Session", "Client", "AsyncClient", "ClientSession"}

    def _receiver_is_http_client(self, name_node: ast.Name) -> bool:
        """True if `name_node` resolves to an HTTP-client construction
        (requests.Session(), httpx.Client(), aiohttp.ClientSession(), or a
        bare Session()/Client() from a recognized from-import). Resolves the
        binding through the scope chain. Conservative: an unresolved receiver
        is NOT treated as an HTTP client (kills redis/cache .get/.delete FPs)."""
        assigned = self._resolve_binding(name_node)
        return assigned is not None and self._is_http_client_ctor(assigned)

    def _call_arg_references_request(self, node: ast.Call) -> bool:
        """True if any positional arg of `node` (or a Name resolving to one)
        references request input — used to keep recall on unresolved HTTP-client
        receivers while still suppressing redis/cache .get/.delete (whose args
        are keys, not request input)."""
        for a in node.args:
            if _references_request_input(a):
                return True
            if isinstance(a, ast.Name):
                assigned = self._resolve_binding(a)
                if assigned is not None and _references_request_input(assigned):
                    return True
        return False

    def _ssrf_ctor_base_url_arg(self, node: ast.Call) -> ast.AST | None:
        """If `node` is an HTTP-client CONSTRUCTOR with a non-constant `base_url=`
        kwarg, return that arg node; else None. Catches the
        `httpx.AsyncClient(base_url=config.get(...))` SSRF shape that the
        call-verb sink set misses (Sanad A3). Constant base_url → None (safe)."""
        if not self._is_http_client_ctor(node):
            return None
        for kw in node.keywords:
            if kw.arg != "base_url":
                continue
            val = kw.value
            if isinstance(val, ast.Constant):
                return None  # hardcoded base_url is safe
            # Resolve a Name/Attribute base_url to its assigned value. The
            # name-heuristic in _attr_is_const_baseurl trusts `self.base_url`
            # blindly, but here it may have been assigned config.get()/os.getenv
            # (tainted) — so resolve first and only trust a CONSTANT binding.
            if isinstance(val, (ast.Name, ast.Attribute)):
                bound = self._resolve_binding(val)
                if bound is not None:
                    if isinstance(
                        bound, ast.Constant
                    ) or self._url_authority_is_constant(bound):
                        return None
                    return bound  # resolved to a tainted expr → sink
                # Unresolved attribute: fall back to the name-heuristic only for
                # bare module/settings constants, NOT self.* (which we can't prove
                # constant). A self.base_url we couldn't resolve is treated as a
                # potential sink (conservative — this is the Sanad A3 case).
                if (
                    isinstance(val, ast.Attribute)
                    and isinstance(val.value, ast.Name)
                    and val.value.id == "self"
                ):
                    return val
            if self._url_authority_is_constant(val):
                return None  # settings/literal authority → safe
            return val
        return None

    def _is_http_client_ctor(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
            base = self._module_aliases.get(f.value.id, f.value.id)
            return (
                base in self._HTTP_CLIENT_CTOR_MODULES
                and f.attr in self._HTTP_CLIENT_CTOR_NAMES
            )
        if isinstance(f, ast.Name):
            resolved = self._from_imports.get(f.id)
            if (
                resolved
                and resolved[0] in self._HTTP_CLIENT_CTOR_MODULES
                and resolved[1] in self._HTTP_CLIENT_CTOR_NAMES
            ):
                return True
            return f.id in self._HTTP_CLIENT_CTOR_NAMES
        return False

    def _is_ssrf(self, node: ast.Call) -> bool:
        """Return True if an HTTP-client sink is called with a non-literal URL.

        Sanitisers: dict-lookup whitelists (`allowed[name]`,
        `allowed.get(name)`) and set-membership guards (`if name not in
        allowed: return ...`) suppress the finding.

        Recognised sinks (audit sink-breadth + #8):
          - requests / httpx.get / post / put / delete / head / patch / options / request
          - aiohttp ClientSession.get / post / ... (via the verb method name)
          - urllib3 PoolManager.request (url is arg index 1)
          - urllib.request.urlopen / urlretrieve  (qualified or from-imported)
          - six.moves.urllib.request.urlopen / urlretrieve  (Python 2 compat shim)

        A constant string first arg is correctly suppressed (mirrors
        the cmdi / path-traversal / open-redirect / XSS sink posture).
        """
        # Constructor form: httpx.AsyncClient(base_url=<non-const>) etc. (Sanad A3).
        if self._ssrf_ctor_base_url_arg(node) is not None:
            return True
        if not self._ssrf_sink_name(node):
            return False
        if not node.args:
            return False
        url_idx = self._ssrf_url_arg_index(node)
        if url_idx >= len(node.args):
            return False
        first = node.args[url_idx]
        # Constant string URL is fine — no user input involved.
        if isinstance(first, ast.Constant):
            return False
        # Name that resolves to a constant in the local scope is also fine.
        if isinstance(first, ast.Name):
            for scope in reversed(self._scopes):
                if first.id in scope:
                    if isinstance(scope[first.id], ast.Constant):
                        return False
                    break  # innermost binding wins (audit #17)
        if self._arg_is_sanitised(first, node.lineno, url_sink=True):
            return False
        # TwiScope FP-1/FP-2: constant scheme+host with taint only in path/query
        # is not SSRF.
        if self._url_authority_is_constant(first):
            return False
        return True

    @staticmethod
    def _literal_url_fixes_host(s: str) -> bool:
        """True only if literal `s` fixes the scheme AND host. The authority
        (everything after 'http(s)://' up to the first '/', '?' or '#') must be
        BOTH non-empty AND terminated by one of those delimiters. So:
          "https://"                      -> False (empty authority: host is in
                                             the tainted tail -> SSRF)
          "https://api"                   -> False (unterminated: `+ ".evil.com"`
                                             extends the host -> SSRF)
          "https://api.twitter.com/2/"    -> True  (fixed host; taint only in the
                                             path -> not SSRF)
        Fixes the v0.26-disclosed multi-hop SSRF FN, where a bare-scheme prefix
        was wrongly treated as a constant host.

        Deliberately conservative: the authority terminates only on '/', '?' or
        '#', NOT ':'. So `"https://host:8080" + tainted` is treated as host-NOT-
        fixed and flagged — a recall-preserving over-fire (better than risking a
        miss on host/userinfo control like `"https://user:" + tainted`).
        Documented, not a bug."""
        for scheme in ("http://", "https://"):
            if s.startswith(scheme):
                rest = s[len(scheme):]
                for i, ch in enumerate(rest):
                    if ch in "/?#":
                        return i > 0  # non-empty authority, terminated
                return False  # no terminator -> host unterminated/extendable
        return False

    def _url_authority_is_constant(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if the URL expression's scheme+authority is fixed — a literal
        'http(s)://host/...' string, a settings.* / module-UPPER_CASE / self.*url
        constant, or a `<base> + <path>` / f-string whose LEADING segment is one
        of those. Taint in only the path/query of a constant-host URL is not SSRF."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return self._literal_url_fixes_host(expr.value)
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name) and expr.value.id == "settings":
                return True
            return self._attr_is_const_baseurl(expr)
        if isinstance(expr, ast.Name):
            if expr.id.isupper():
                return True
            assigned = self._resolve_binding(expr)
            return assigned is not None and self._url_authority_is_constant(
                assigned, _depth + 1
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._url_authority_is_constant(expr.left, _depth + 1)
        if isinstance(expr, ast.JoinedStr) and expr.values:
            first = expr.values[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return self._literal_url_fixes_host(first.value)
            if isinstance(first, ast.FormattedValue):
                return self._url_authority_is_constant(first.value, _depth + 1)
        if isinstance(expr, ast.Call):
            f = expr.func
            # getattr(settings, "X_URL", default) — the attribute form
            # `settings.X_URL` is already trusted above; getattr is the same
            # Django-settings read, so treat it identically. (os.getenv is
            # deliberately NOT trusted here — env URLs are an SSRF source by
            # engine policy; see TestConfigEnvSSRFSource.)
            if (
                isinstance(f, ast.Name)
                and f.id == "getattr"
                and expr.args
                and isinstance(expr.args[0], ast.Name)
                and expr.args[0].id == "settings"
            ):
                return True
            # str-method chains that preserve the authority: a constant/config
            # base passed through .rstrip("/") / .strip() / .format(...) / .lower()
            # keeps its scheme+host. Trust iff the receiver's authority is const.
            if (
                isinstance(f, ast.Attribute)
                and f.attr
                in {"rstrip", "lstrip", "strip", "format", "lower", "upper", "removesuffix"}
            ):
                return self._url_authority_is_constant(f.value, _depth + 1)
        return False

    @staticmethod
    def _attr_is_const_baseurl(expr: ast.Attribute) -> bool:
        """True for self.base_url / self.BaseURL / cfg.x_api_url style attributes
        naming a configured base URL/endpoint (configured infra, not request input)."""
        attr = expr.attr.lower()
        return any(k in attr for k in ("url", "base", "endpoint", "host"))

    # HTTP client modules whose verb methods are SSRF sinks (audit breadth).
    _SSRF_CLIENT_MODULES = {"requests", "httpx"}

    def _ssrf_url_arg_index(self, node: ast.Call) -> int:
        """urllib3 PoolManager.request(method, url) puts the URL at index 1."""
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "request":
            # requests.request(method, url) and urllib3 .request(method, url)
            # both take the URL second; requests.<verb>() takes it first.
            return 1
        if isinstance(func, ast.Name) and node.func.id in self._from_imports:
            _, sym = self._from_imports[node.func.id]
            if sym == "request":
                return 1
        return 0

    def _ssrf_sink_name(self, node: ast.Call) -> str | None:
        """Return a display name for the SSRF sink (e.g. 'requests.get',
        'urllib.request.urlopen'), or None if `node` is not a recognised sink.
        """
        func = node.func
        # Bare-name urlopen/urlretrieve via `from urllib.request import urlopen`.
        if isinstance(func, ast.Name) and func.id in self._from_imports:
            module, sym = self._from_imports[func.id]
            if module.endswith("urllib.request") and sym in self._SSRF_URLLIB_METHODS:
                return f"urllib.request.{sym}"
            if (
                module in self._SSRF_CLIENT_MODULES
                and sym in self._SSRF_REQUESTS_METHODS
            ):
                return f"{module}.{sym}"
        if not isinstance(func, ast.Attribute):
            return None
        # requests.<method> / httpx.<method> (incl. aliased module).
        if isinstance(func.value, ast.Name):
            base = self._module_aliases.get(func.value.id, func.value.id)
            if (
                base in self._SSRF_CLIENT_MODULES
                and func.attr in self._SSRF_REQUESTS_METHODS
            ):
                return f"{base}.{func.attr}"
        # aiohttp / urllib3 / httpx client-instance verb call: <session>.get(url),
        # <pool>.request("GET", url). We key on the method name; instance type is
        # unknown statically, so this is a heuristic (MEDIUM-confidence already).
        if (
            isinstance(func.value, ast.Name)
            and func.attr in (self._SSRF_REQUESTS_METHODS | {"request"})
            and (
                self._receiver_is_http_client(func.value)
                # Unresolved receiver (e.g. a `session`/`http` param) still counts
                # when the URL arg is request-tainted — a tainted URL into any
                # .get/.post is worth flagging. The redis/cache FP has a NON-tainted
                # key arg, so it stays suppressed.
                or self._call_arg_references_request(node)
            )
        ):
            return f"{func.value.id}.{func.attr}"
        # urllib.request.<method>  — Attribute(Attribute(Name('urllib'), 'request'), 'X')
        if (
            func.attr in self._SSRF_URLLIB_METHODS
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "request"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "urllib"
        ):
            return f"urllib.request.{func.attr}"
        # six.moves.urllib.request.<method>
        if (
            func.attr in self._SSRF_URLLIB_METHODS
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "request"
            and isinstance(func.value.value, ast.Attribute)
            and func.value.value.attr == "urllib"
            and isinstance(func.value.value.value, ast.Attribute)
            and func.value.value.value.attr == "moves"
            and isinstance(func.value.value.value.value, ast.Name)
            and func.value.value.value.value.id == "six"
        ):
            return f"six.moves.urllib.request.{func.attr}"
        return None

    def _is_xss_html_sink(self, node: ast.Call) -> bool:
        """Return True if node is a known HTML-render sink with a non-literal arg.

        Recognises:
          - Markup(x) / flask.Markup(x) / markupsafe.Markup(x)
          - mark_safe(x) / django.utils.safestring.mark_safe(x)
          - render_template_string(x)

        A constant string arg is fine — that's a developer marking a
        literal block of HTML as safe, not a flow from user input.
        Variable args (Name, Call, BinOp, JoinedStr) are the dangerous
        case; let `_collect_taint_chain` decide whether the variable
        actually traces back to a request source.
        """
        if not node.args:
            return False
        if not self._xss_sink_name(node):
            return False
        first = node.args[0]
        # Constant literal is safe — `Markup("<b>static</b>")` is fine.
        if isinstance(first, ast.Constant):
            return False
        # Name that resolves to a constant in scope is also safe.
        if isinstance(first, ast.Name):
            for scope in reversed(self._scopes):
                if first.id in scope:
                    if isinstance(scope[first.id], ast.Constant):
                        return False
                    break  # innermost binding wins (audit #17)
        # Whitelisted dict lookup / set-membership guard → sanitised.
        if self._arg_is_sanitised(first, node.lineno):
            return False
        return True

    def _xss_sink_name(self, node: ast.Call) -> str:
        """Return the canonical sink-function name, or '' if not an XSS sink.

        Accepts both bare-name calls (`Markup(x)`, `mark_safe(x)`) and
        attribute calls (`flask.Markup(x)`, `markupsafe.Markup(x)`,
        `django.utils.safestring.mark_safe(x)`). Returned as the leaf
        function name only — callers use it for the taint-chain expr.
        """
        if isinstance(node.func, ast.Name):
            if node.func.id in _XSS_HTML_SINK_NAMES:
                return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in _XSS_HTML_SINK_NAMES:
                return node.func.attr
        return ""

    def _is_path_traversal_sink(self, node: ast.Call) -> bool:
        """Return True if node is a path-handling sink with a non-literal path arg.

        Recognises (TASK-134):
          - open(x[, mode]) — stdlib file open
          - Path(x) / pathlib.Path(x) — pathlib constructor (the resulting
            Path is typically opened or sent next; flagging the construct
            site lets the chain prove user-input flow regardless of where
            the actual filesystem access happens)
          - send_file(x) / flask.send_file(x) — Flask file response
          - send_from_directory(safe_dir, x) / flask.send_from_directory —
            Flask file-by-name; the path arg is the SECOND positional

        A constant string arg is safe — `open("config.yaml")` is fine.
        Variable args (Name, Call, BinOp, JoinedStr) are the dangerous
        case; `_collect_taint_chain` decides whether the variable
        actually traces back to a request source.
        """
        sink_name = self._path_traversal_sink_name(node)
        if not sink_name:
            return False
        if not node.args:
            return False
        # A join resolved in place and checked by a containment guard before
        # any use is safe; the guard sits below the join's line, so it could
        # never dominate the join itself (`_resolved_join_is_guarded`).
        if sink_name == "os.path.join" and self._resolved_join_is_guarded(node):
            return False
        arg_idx = self._path_traversal_arg_index(node)
        if arg_idx >= len(node.args):
            return False
        target = node.args[arg_idx]
        # Constant literal is safe.
        if isinstance(target, ast.Constant):
            return False
        # Name that resolves to a constant in scope is also safe.
        if isinstance(target, ast.Name):
            for scope in reversed(self._scopes):
                if target.id in scope:
                    if isinstance(scope[target.id], ast.Constant):
                        return False
                    break  # innermost binding wins (audit #17)
        # Whitelisted dict lookup / set-membership guard → sanitised.
        if self._arg_is_sanitised(target, node.lineno):
            return False
        # Traversal-specific containment: basename-family normalisation, or a
        # dominating guard that rejects '..' outright. These neutralise
        # traversal specifically, which the generic sanitiser set above does
        # not model.
        if self._path_is_contained(target, node.lineno):
            return False
        # TwiScope FP-4: a path that provably comes from a NON-request source —
        # __file__-relative Path, os.getenv, tempfile.*.name, settings.*, a
        # BASE_DIR-style constant — is not user-controlled traversal. Never
        # suppress when the path references request input (recall guard).
        if not _references_request_input(target) and self._path_is_trusted_source(
            target
        ):
            chain = (
                self._collect_taint_chain(target, node.lineno, "")
                if node.args
                else None
            )
            if chain is None:  # no proven request flow either → trusted, suppress
                return False
        return True

    def _path_is_trusted_source(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True if `expr` is built only from trusted (non-request) path sources:
        __file__ / Path(__file__)... , os.getenv/os.environ.get, settings.*,
        tempfile.NamedTemporaryFile().name / mkstemp, UPPER_CASE module
        constants, or os.path.* over such. Conservative: an unknown variable is
        NOT trusted (keeps the conservative emit the audit wanted)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant):
            return True
        if isinstance(expr, ast.Name):
            if expr.id in {"__file__"} or expr.id.isupper():
                return True
            assigned = self._resolve_binding(expr)
            return assigned is not None and self._path_is_trusted_source(
                assigned, _depth + 1
            )
        if isinstance(expr, ast.Attribute):
            # settings.X, self.BASE_DIR, <tmp>.name, os.environ
            if isinstance(expr.value, ast.Name) and expr.value.id == "settings":
                return True
            if expr.attr in {
                "name"
            }:  # NamedTemporaryFile().name / TemporaryFile().name
                if self._is_tempfile_obj(expr.value):
                    return True
                # TwiScope FP (SEC-073): `<param>.name` where `<param>` is an
                # enclosing-function parameter NOT bound to request input. A
                # helper like `def send(temp_file): open(temp_file.name)` takes
                # an already-constructed file/tempfile object from its caller;
                # the `.name` is that object's path, not attacker-controlled
                # text. Traversal needs the *string* to come from the request,
                # which `_references_request_input` would have caught upstream.
                if isinstance(
                    expr.value, ast.Name
                ) and self._name_is_safe_object_param(expr.value):
                    return True
                return False
            if (
                expr.attr.isupper()
                or "dir" in expr.attr.lower()
                or "root" in expr.attr.lower()
            ):
                return True
            return False
        if isinstance(expr, ast.Call):
            f = expr.func
            # os.getenv(...) / os.environ.get(...)
            if isinstance(f, ast.Attribute):
                if (
                    f.attr in {"getenv"}
                    and isinstance(f.value, ast.Name)
                    and f.value.id == "os"
                ):
                    return True
                if (
                    f.attr == "get"
                    and isinstance(f.value, ast.Attribute)
                    and f.value.attr == "environ"
                ):
                    return True
                # Path(__file__).resolve().parent... chain — trusted iff the
                # base of the chain is Path(__file__) / a trusted arg.
                if f.attr in {"resolve", "parent", "absolute", "joinpath"}:
                    return self._path_is_trusted_source(f.value, _depth + 1)
                # os.path.join(trusted, trusted)
                if (
                    f.attr in {"join", "abspath", "dirname", "normpath", "expanduser"}
                    and isinstance(f.value, ast.Attribute)
                    and f.value.attr == "path"
                ):
                    return all(
                        self._path_is_trusted_source(a, _depth + 1) for a in expr.args
                    )
            # Path(__file__) / pathlib.Path(__file__)
            name = (
                f.attr
                if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else "")
            )
            if name == "Path" and expr.args:
                return self._path_is_trusted_source(expr.args[0], _depth + 1)
            return False
        if isinstance(expr, ast.BinOp):
            return self._path_is_trusted_source(
                expr.left, _depth + 1
            ) and self._path_is_trusted_source(expr.right, _depth + 1)
        if isinstance(expr, ast.JoinedStr):
            return all(
                self._path_is_trusted_source(v.value, _depth + 1)
                for v in expr.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(expr, ast.Subscript):
            if _references_request_input(expr):
                return False
            return self._path_is_trusted_source(expr.value, _depth + 1)
        return False

    def _is_tempfile_obj(self, expr: ast.AST) -> bool:
        """True if `expr` (or what it resolves to) is a tempfile.* object."""
        target = self._resolve_binding(expr) if isinstance(expr, ast.Name) else expr
        if isinstance(target, ast.Call):
            f = target.func
            name = (
                f.attr
                if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else "")
            )
            return name in {
                "NamedTemporaryFile",
                "TemporaryFile",
                "SpooledTemporaryFile",
                "mkstemp",
            }
        return False

    def _path_traversal_sink_name(self, node: ast.Call) -> str:
        """Return the canonical path-traversal sink-function name, or ''.

        Accepts bare-name calls (`open(x)`, `Path(x)`, `send_file(x)`),
        single-attribute calls (`pathlib.Path(x)`, `flask.send_file(x)`),
        and double-attribute `os.path.X` calls (`os.path.join(base, x)`,
        `os.path.abspath(x)`, `os.path.expanduser(x)`).
        """
        if isinstance(node.func, ast.Name):
            if node.func.id in _PATH_TRAVERSAL_SINK_NAMES:
                # B7 (fabricated-chain): a bare `open`/`Path` from-imported from
                # a NON-filesystem module (webbrowser, selenium, …) is not the
                # builtin path sink — it was fabricating CWE-22 chains on
                # `from webbrowser import open; open(url)`.
                resolved = self._from_imports.get(node.func.id)
                if node.func.id in {"open", "Path"} and resolved is not None:
                    mod = resolved[0]
                    _FS_MODULES = {"io", "os", "codecs", "gzip", "bz2", "lzma", "pathlib"}
                    if mod not in _FS_MODULES:
                        return ""
                return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Double-attribute form: os.path.join / os.path.abspath etc.
            os_path_attr = _os_path_attr(node.func)
            if os_path_attr in _OS_PATH_SINK_ATTRS:
                return f"os.path.{os_path_attr}"
            # Attribute-form sink — audit #14: scope `open`/`Path` to a
            # filesystem-receiver allow-list so `webbrowser.open`, `driver.open`,
            # selenium/zipfile/socket `.open` etc. don't masquerade as CWE-22.
            # `send_file`/`send_from_directory` keep matching on any receiver
            # (they are framework-specific names with negligible collision).
            attr = node.func.attr
            if attr in {"send_file", "send_from_directory"}:
                return attr
            if attr in {"open", "Path"} and isinstance(node.func.value, ast.Name):
                base = self._module_aliases.get(node.func.value.id, node.func.value.id)
                _FS_OPEN_RECEIVERS = {"io", "os", "codecs", "gzip", "bz2", "lzma"}
                if attr == "open" and base in _FS_OPEN_RECEIVERS:
                    return "open"
                if attr == "Path" and base in {"pathlib"}:
                    return "Path"
        return ""

    def _path_traversal_arg_index(self, node: ast.Call) -> int:
        """Return the positional-arg index of the path argument.

        `send_from_directory(safe_dir, filename)` and `os.path.join(base, x)`
        put the user-controlled component at index 1; everything else at 0.
        """
        sink_name = self._path_traversal_sink_name(node)
        if sink_name in {"send_from_directory", "os.path.join"}:
            return 1
        return 0


# ---------------------------------------------------------------------------
# Module-level helpers (no visitor state required)
# ---------------------------------------------------------------------------

# Loader names that yaml.load accepts as safe (i.e. don't construct arbitrary
# Python objects). Compared by attribute or name, not value.
_SAFE_LOADER_NAMES: frozenset[str] = frozenset(
    {
        "SafeLoader",
        "CSafeLoader",
        "BaseLoader",
        "CBaseLoader",
    }
)


# HTML-render sinks recognised by `_is_xss_html_sink` (TASK-120). Compared
# by attribute or bare name so both `Markup(x)` and `flask.Markup(x)` /
# `markupsafe.Markup(x)` match. Same applies to `mark_safe` (Django) and
# `render_template_string` (Flask/Jinja2 SSTI + reflective XSS).
# Library receivers whose .eval() executes code (RCE) — PIL.ImageMath.eval,
# asteval, simpleeval. Matched in attribute form alongside builtin eval/exec.
_CODE_EVAL_RECEIVERS: frozenset[str] = frozenset(
    {"ImageMath", "aeval", "asteval", "simple_eval", "evaluator", "interpreter"}
)


_XSS_HTML_SINK_NAMES: frozenset[str] = frozenset(
    {
        "Markup",
        "mark_safe",
        "render_template_string",
    }
)


# Path-traversal sinks recognised by `_is_path_traversal_sink` (TASK-134).
# Bare-name `open(x)` is the stdlib builtin; attribute form `pathlib.Path(x)`
# or `flask.send_file(x)` are also matched. send_from_directory's path arg
# is the SECOND positional — see `_path_traversal_arg_index`.
_PATH_TRAVERSAL_SINK_NAMES: frozenset[str] = frozenset(
    {
        "open",
        "Path",
        "send_file",
        "send_from_directory",
    }
)

# `os.path.X` function names treated as path-traversal sinks when the
# path argument is non-constant user input. `join` uses arg index 1
# (base is trusted, joined component is user-controlled); the rest use 0.
_OS_PATH_SINK_ATTRS: frozenset[str] = frozenset(
    {
        "join",
        "abspath",
        "expanduser",
        "expandvars",
    }
)


# How much of a guarding `if` must lie before the sink it protects; see
# `_PythonSecurityVisitor._dominating_exit_guard`.
_GuardExtent = Literal["starts", "ends", "body_ends"]


def _os_path_attr(func: ast.AST) -> str:
    """Return `X` when `func` is the double attribute `os.path.X`, else ""."""
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "path"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id == "os"
    ):
        return func.attr
    return ""


def _is_bounding_dir(value: object) -> bool:
    """True when the constant `value` names a directory narrower than the
    filesystem root. Empty, `/`, `.`, a bare drive and a path whose `..`
    climbs back to one of those (`/srv/..`) bound nothing: `realpath` of them
    is the root or the working directory, which may itself be `/`."""
    if not isinstance(value, str) or not value:
        return False
    posix = value.replace("\\", "/")
    if re.fullmatch(r"[A-Za-z]:/*", posix):
        return False
    return any(p not in ("", ".", "..") for p in posixpath.normpath(posix).split("/"))


def _is_os_sep(expr: ast.AST) -> bool:
    """True when `expr` is `os.sep` or `os.path.sep`."""
    if not (isinstance(expr, ast.Attribute) and expr.attr == "sep"):
        return False
    recv = expr.value
    if isinstance(recv, ast.Attribute) and recv.attr == "path":
        recv = recv.value
    return isinstance(recv, ast.Name) and recv.id == "os"


# Exception classes whose handler catches the ValueError `relative_to` raises.
_VALUE_ERROR_CATCHERS: frozenset[str] = frozenset(
    {"ValueError", "Exception", "BaseException"}
)


def _handler_catches_value_error(exc_type: ast.AST | None) -> bool:
    """True when an `except` clause with this type catches ValueError: a bare
    `except`, `ValueError` or one of its bases, or a tuple holding one."""
    if exc_type is None:
        return True
    names = exc_type.elts if isinstance(exc_type, ast.Tuple) else [exc_type]
    return any(isinstance(n, ast.Name) and n.id in _VALUE_ERROR_CATCHERS for n in names)


def _binds_name(node: ast.AST, name: str) -> bool:
    """True when `node` binds, deletes or declares `name`: an assignment,
    loop, `with`, walrus or `del` target, `global`/`nonlocal`, a def or class
    of that name, a parameter of a lambda or def, `except ... as name`, an
    import alias, or a match capture.

    A lambda or nested-def parameter binds the name in its own scope, so a
    `full` read inside `lambda full: open(full)` is not the outer `full`.
    Callers searching a function pass its body, never its own parameters."""
    if isinstance(node, ast.Name):
        return node.id == name and not isinstance(node.ctx, ast.Load)
    if isinstance(node, ast.arg):
        return node.arg == name
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return name in node.names
    if isinstance(
        node,
        (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler),
    ):
        return node.name == name
    if isinstance(node, ast.alias):
        return (node.asname or node.name.split(".")[0]) == name
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name == name
    if isinstance(node, ast.MatchMapping):
        return node.rest == name
    return False


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every parameter name of `func`, `*args` and `**kwargs` included."""
    a = func.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    params += [p for p in (a.vararg, a.kwarg) if p is not None]
    return {p.arg for p in params}


def _end_position(node: ast.AST) -> tuple[int, int]:
    """Where `node` ends in the source, as a comparable (line, column)."""
    return (node.end_lineno or 0, node.end_col_offset or 0)


def _same_scope_nodes(node: ast.AST):
    """Yield `node` and its descendants that run in the same scope. A def,
    lambda or class is yielded (its name binds here) but not entered."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            stack.extend(ast.iter_child_nodes(current))


def _stores_of(func: ast.AST, name: str) -> list[ast.AST]:
    """Every node in `func`'s body that binds `name` (see `_binds_name`).
    Nested defs are searched too, which can only over-count."""
    return [n for stmt in func.body for n in ast.walk(stmt) if _binds_name(n, name)]


# Path fragments that mark a file as test/fixture code (confidence demotion).
_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|conftest)([_/.]|$)|(^|/)test_[^/]*\.py$|_test\.py$|/fixtures?/",
)


def _is_test_path(rel_path: str) -> bool:
    """True if `rel_path` looks like test / fixture code, per common layout
    conventions (tests/ dir, test_*.py, *_test.py, conftest.py, fixtures/)."""
    return bool(_TEST_PATH_RE.search(rel_path.replace("\\", "/")))


def _binding_key(target: ast.AST) -> str | None:
    """Return a stable scope key for an attribute/subscript assignment target,
    so `self.q = ...` and `d['k'] = ...` can be recorded and later resolved
    (audit #26/#27). Returns None for shapes we don't track (computed keys, etc.).

      self.q          -> "self.q"
      d['k']          -> "d['k']"
      obj.a.b         -> "obj.a.b"
    """
    if isinstance(target, ast.Attribute):
        base = (
            _binding_key(target.value)
            if not isinstance(target.value, ast.Name)
            else target.value.id
        )
        return f"{base}.{target.attr}" if base else None
    if isinstance(target, ast.Subscript):
        base = (
            target.value.id
            if isinstance(target.value, ast.Name)
            else _binding_key(target.value)
        )
        if base is None:
            return None
        sl = target.slice
        if isinstance(sl, ast.Constant):
            return f"{base}[{sl.value!r}]"
        return None
    if isinstance(target, ast.Name):
        return target.id
    return None


def _is_safe_loader_expr(expr: ast.expr) -> bool:
    """Return True if the expression names a safe YAML loader.

    Accepts both attribute form (`yaml.SafeLoader`) and bare name (`SafeLoader`
    after a `from yaml import SafeLoader`).
    """
    if isinstance(expr, ast.Attribute):
        return expr.attr in _SAFE_LOADER_NAMES
    if isinstance(expr, ast.Name):
        return expr.id in _SAFE_LOADER_NAMES
    return False


# Long, distinctive password-related substrings — substring match is safe.
_PASSWORD_SUBSTR_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
)

# Short password abbreviations — substring match would false-positive
# (e.g. "pw" matching "power"), so require these as whole snake_case parts.
_PASSWORD_WORD_TOKENS: frozenset[str] = frozenset({"pw", "pwd"})

# Token splitter: snake_case, kebab-case, dotted, camelCase boundary.
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


# Whole-token secret markers for env-var names (matched against the snake/camel
# parts of the key — NOT bare substrings, which matched log text on real code).
_SECRET_ENV_TOKENS: frozenset[str] = frozenset(
    {
        "key",
        "secret",
        "token",
        "password",
        "passwd",
        "passphrase",
        "credential",
        "credentials",
        "apikey",
        "auth",
    }
)


def _key_is_secret(key) -> bool:
    """True if an env-var key name contains a secret token as a whole part
    (api_key, DB_PASSWORD, jwt-secret) — not a bare substring (avoids matching
    'apiversion'/'keyboard')."""
    if not isinstance(key, str):
        return False
    parts = set(_TOKEN_SPLIT_RE.split(key.lower()))
    return bool(parts & _SECRET_ENV_TOKENS)


# Tokens that mark an identifier/key as naming a *location* (a path/URI to a
# resource) rather than the secret value itself. Logging a path is not a leak.
_LOCATION_TOKENS: frozenset[str] = frozenset(
    {"path", "file", "filepath", "dir", "directory", "location", "uri", "url"}
)


def _name_is_location_ref(name: str) -> bool:
    """True if `name`'s whole snake/camel/dotted parts include a location token
    (cred_path, key_file, secret_dir). Such a variable holds a path, not the
    secret, so it is safe to log."""
    parts = set(_TOKEN_SPLIT_RE.split(name.lower()))
    return bool(parts & _LOCATION_TOKENS)


def _env_read_is_location(n: ast.AST) -> bool:
    """True if an os.getenv/os.environ read names a path-valued key — one whose
    parts include a location token (GOOGLE_APPLICATION_CREDENTIALS contains
    'credentials' AND is a documented *path* var; we key on co-occurring path
    semantics). Conservative: only the well-known `*_CREDENTIALS` path family and
    explicit path/file/dir keys qualify, so DB_PASSWORD etc. stay flagged."""
    key = None
    if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
        key = n.slice.value
    elif (
        isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Constant)
    ):
        key = n.args[0].value
    if not isinstance(key, str):
        return False
    parts = set(_TOKEN_SPLIT_RE.split(key.lower()))
    if parts & _LOCATION_TOKENS:
        return True
    # GOOGLE_APPLICATION_CREDENTIALS / *_CREDENTIALS: the standard env var for a
    # *path* to a service-account JSON file, not the credential value.
    return "credentials" in parts


# Trailing tokens that mark an identifier as naming password *metadata* — the
# label/field/prompt for a password input, not the credential value itself.
# `password_field_label` holds the UI string "Password", not a secret; hashing
# or logging it is not a weakness (B6 heuristic-overfire).
_PASSWORD_METADATA_SUFFIXES: frozenset[str] = frozenset(
    {"label", "name", "field", "prompt", "hint", "placeholder"}
)


def _looks_like_password_id(name: str) -> bool:
    """Return True if an identifier name suggests a password/secret value.

    Audit #23: match password-ish tokens as whole snake/camel/dotted parts
    rather than raw substrings, so `secretary`/`password_field_label` don't
    false-positive while `user_password`/`db_passwd`/`pw` still match.

    B6: an identifier whose LAST part is password-metadata (`..._label`,
    `..._field`, `..._prompt`, …) names the input's label/field, not the
    credential value, so it does not qualify — `password_field_label` and
    `secret_prompt` are not secret values.
    """
    ordered = [p for p in _TOKEN_SPLIT_RE.split(name.lower()) if p]
    if ordered and ordered[-1] in _PASSWORD_METADATA_SUFFIXES:
        return False
    parts = set(ordered)
    if parts & _PASSWORD_WORD_TOKENS:
        return True
    return any(tok in parts for tok in _PASSWORD_SUBSTR_TOKENS)


def _arg_subtree_looks_like_password(node: ast.AST) -> bool:
    """Return True if any Name/Attribute in the subtree has a password-y id."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and _looks_like_password_id(n.id):
            return True
        if isinstance(n, ast.Attribute) and _looks_like_password_id(n.attr):
            return True
    return False


# Attributes on the `request` object that carry user-controlled data across
# Flask, Django, FastAPI/Starlette. `headers` deliberately excluded — we have
# a dedicated header-trust check (`_is_request_header_trust`).
_REQUEST_INPUT_ATTRS: frozenset[str] = frozenset(
    {
        "GET",
        "POST",
        "args",
        "values",
        "form",
        "data",
        "json",
        "query_params",
        "path_params",
        "params",
        "body",
        "files",
        # audit #3/#4/#6: cookies (Flask + Django COOKIES), header values
        # (Django META too — the auth-trust `if` check is orthogonal), and
        # Django's uppercase FILES.
        "cookies",
        "COOKIES",
        "headers",
        "META",
        "FILES",
    }
)


def _ast_expr_text(node: ast.AST) -> str:
    """Return a short text representation of an AST expression.

    Uses ast.unparse on Python ≥3.9 (always available in our supported
    versions). Trims to a reasonable length so taint chains don't blow
    out report rendering or push the IPC pipeline past readFindings'
    1MiB-per-line cap.
    """
    try:
        text = ast.unparse(node)
    except Exception:  # noqa: BLE001 — unparse can hit unsupported nodes
        text = type(node).__name__
    text = text.strip()
    if len(text) > 200:
        text = text[:200] + "…"
    return text


# Method-call body accessors on the request object (Flask) — audit #5.
_REQUEST_INPUT_METHODS: frozenset[str] = frozenset({"get_json", "get_data"})


def _references_request_input(arg: ast.AST) -> bool:
    """Return True if the subtree references request.GET/POST/args/etc.

    Recognizes the global `request`, the handler-arg name `req`, and the
    method-call accessors request.get_json()/get_data() (audit #5).
    """
    for n in ast.walk(arg):
        # request.get_json() / request.get_data() — Flask body accessors.
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in _REQUEST_INPUT_METHODS
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in _REQUEST_NAMES
        ):
            return True
        if isinstance(n, ast.Attribute):
            if (
                isinstance(n.value, ast.Name)
                and n.value.id in _REQUEST_NAMES
                and n.attr in _REQUEST_INPUT_ATTRS
            ):
                return True
            # request.GET.get(...), request.args.get(...) — the .get is on
            # the inner attribute. Walk handles both via the outer iteration.
        if isinstance(n, ast.Subscript):
            value = n.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id in _REQUEST_NAMES
                and value.attr in _REQUEST_INPUT_ATTRS
            ):
                return True
    return False


# Datastore/retrieval read methods whose RESULTS are second-order (stored)
# untrusted input — RAG context, DB rows. Recognised ONLY as a source for the
# LLM_PROMPT sink (sink-gated), never for SQL/XSS/SSRF/path detectors.
_DATASTORE_READ_METHODS: frozenset[str] = frozenset(
    {
        # Elasticsearch
        "search",
        "get",
        "mget",
        "msearch",
        # SQLAlchemy / DB-API result accessors
        "fetchall",
        "fetchone",
        "fetchmany",
        "scalar",
        "scalars",
        "all",
        "first",
        "mappings",
        "one",
        "one_or_none",
    }
)
# Result-shaped keys that indicate retrieved content being indexed into.
_DATASTORE_RESULT_KEYS: frozenset[str] = frozenset(
    {
        "hits",
        "_source",
        "text",
        "summary",
        "content",
        "body",
        "documents",
        "rows",
    }
)


def _is_taint_source(expr: ast.AST, extra_source=None) -> bool:
    """True when `expr` is a source itself: request input, or what the sink's
    `extra_source` predicate (e.g. `_references_datastore_read`) accepts."""
    return _references_request_input(expr) or (
        extra_source is not None and extra_source(expr)
    )


def _references_datastore_read(arg: ast.AST) -> bool:
    """True if the subtree reads from a datastore/retrieval call — an ES
    .search()/.get() or a SQLAlchemy result accessor (.fetchall/.mappings/...),
    or a subscript into such a result (rows[0]['text'], hits['hits']...). This
    models second-order / RAG-retrieved untrusted input (Sanad A2). Used ONLY by
    the LLM_PROMPT sink via extra_source — kept out of every other detector."""
    for n in ast.walk(arg):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in _DATASTORE_READ_METHODS
        ):
            return True
        if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
            if n.slice.value in _DATASTORE_RESULT_KEYS:
                return True
    return False


# Common identifiers for the request object across Flask/Django/FastAPI.
# Conventional handler-arg names — `request` is the global/Django/FastAPI
# convention, `req` is the standard Flask handler-arg abbreviation.
_REQUEST_NAMES: frozenset[str] = frozenset({"request", "req"})


def _is_request_header_trust(test: ast.expr) -> bool:
    """Return True if an If-test reads a header for an auth decision.

    Matches:  if request.headers.get('X-Admin'):
              if request.headers.get('X-Role') == 'admin':
              if request.headers['X-Admin']:
              if req.headers.get('X-Admin'):    (handler-arg form)
    """
    # Compare(left=..., comparators=[...]) — unwrap to inspect left side.
    target: ast.expr = test
    if isinstance(test, ast.Compare):
        target = test.left

    # <req>.headers.get(...) call.
    if isinstance(target, ast.Call) and isinstance(target.func, ast.Attribute):
        if target.func.attr == "get":
            inner = target.func.value
            if (
                isinstance(inner, ast.Attribute)
                and inner.attr == "headers"
                and isinstance(inner.value, ast.Name)
                and inner.value.id in _REQUEST_NAMES
            ):
                return True

    # <req>.headers[...] subscript.
    if isinstance(target, ast.Subscript):
        value = target.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "headers"
            and isinstance(value.value, ast.Name)
            and value.value.id in _REQUEST_NAMES
        ):
            return True

    return False
