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
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Literal, Mapping

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
        # Task 3.8: a second pre-pass indexes the calls between the project's
        # modules, so a helper's parameter can be followed one hop to a caller
        # in another file. It parses each file once and hands the parse to
        # `_analyze_python`. Best-effort like the route index: on failure the
        # helper hop stays within each file.
        self._call_index = self._build_call_index(root, self._routes_by_func)

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
        # The index holds the callers' parsed trees; nothing reads it after
        # the walk.
        self._call_index = None

    def _build_route_index(self, root: Path):
        """Walk the tree once and merge every file's routes into one
        function-name → Route index. Keyed on the handler function's name so
        a Django urls.py route binds to its view defined elsewhere. Once every
        file is read, each Django route is pointed at the module that defines
        its view (`RouteTable.resolve_views`: one re-export hop, or a scanned
        module standing in for one the scan root sits inside), and a decorator
        route whose own file does not show its framework takes the project's
        dominant one (`RouteTable.resolve_frameworks`). Returns a RouteTable;
        on any import/IO failure returns an empty one (binding simply stays
        off)."""
        try:
            from analyzers.route_extractor import RouteTable, scan_module
        except Exception:  # noqa: BLE001 — binding is optional
            return None
        index = RouteTable()
        summaries = []
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
                    table, summary = scan_module(src, rel)
                except (RecursionError, Exception):  # noqa: BLE001 — binding is best-effort
                    # audit #18: one crafted/large file must not abort the
                    # route index (and thus the whole injection pass). Skip it.
                    continue
                for route in table.routes:
                    index.add(route)
                if summary is not None:
                    summaries.append(summary)
        try:
            index.resolve_views(summaries, root.resolve().parts)
            index.resolve_frameworks(summaries)
        except (RecursionError, Exception) as exc:  # noqa: BLE001 — binding is best-effort
            # The routes keep the modules their urlconf's imports resolved.
            print(
                f"[fendix-engine] ast_analyzer: route view resolution failed: {exc}",
                file=sys.stderr,
            )
        return index

    def _build_call_index(self, root: Path, route_table):
        """The project's `ProjectCallIndex` (analyzers/call_index.py), or None
        when it cannot be built. Imported here, not at module level: the
        index module imports this one."""
        try:
            from analyzers.call_index import ProjectCallIndex

            return ProjectCallIndex.build(root, route_table)
        except (RecursionError, Exception) as exc:  # noqa: BLE001 — the hop is optional
            print(
                f"[fendix-engine] ast_analyzer: project call index failed: {exc}",
                file=sys.stderr,
            )
            return None

    # ------------------------------------------------------------------
    # Python AST analysis
    # ------------------------------------------------------------------

    def _analyze_python(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Parse and analyze a Python file's AST. A file the project call
        index already parsed is analysed from that parse (Task 3.8)."""
        call_index = getattr(self, "_call_index", None)
        parsed = call_index.take_parsed(rel) if call_index is not None else None
        if parsed is not None:
            source, tree = parsed
        else:
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
        visitor = _file_visitor(
            source,
            rel,
            emit_fn,
            tree,
            route_table=getattr(self, "_routes_by_func", None),
            call_index=call_index,
        )
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


def _file_visitor(
    source: str,
    rel: str,
    emit_fn: Callable[[dict], None],
    tree: ast.Module,
    *,
    route_table=None,
    call_index=None,
    primed: bool = False,
) -> _PythonSecurityVisitor:
    """The visitor for one file: `_analyze_python` walks it, and the project
    call index (Task 3.8) asks a caller file's visitor questions without
    walking it. `tree` is the module root the 1-hop call-site index reads.
    `primed` sets up, without the walk, what the walk would have recorded
    that those questions read (`_PythonSecurityVisitor._prime`)."""
    visitor = _PythonSecurityVisitor(
        source.splitlines(),
        rel,
        emit_fn,
        route_table=route_table,
        call_index=call_index,
    )
    visitor._module_root = tree  # enable 1-hop interprocedural call-site index
    if primed:
        visitor._prime()
    return visitor


class _PythonSecurityVisitor(ast.NodeVisitor):
    """AST visitor that emits findings for dangerous Python patterns."""

    def __init__(
        self,
        source_lines: list[str],
        rel_path: str,
        emit_fn: Callable[[dict], None],
        route_table=None,
        call_index=None,
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
        # Task 3.4: local name → the module an `import` binds it to, which
        # `_import_origin` resolves dotted names through. Unlike the aliases
        # above, `import a.b` binds `a` to the top package `a`, not to `a.b`.
        self._imported_modules: dict[str, str] = {}
        # Task 3.4: while set, the taint trace does not enter the source of a
        # template built from a string (`_without_template_sources`).
        self._skip_template_sources = False
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
        # Task 3.8: the project's call index (call_index.ProjectCallIndex), for
        # a helper's callers in other files, and this file's dotted module,
        # the name those callers import it by. None: the hop stays in the
        # file.
        self._call_index = call_index
        self._module_dotted = (
            call_index.module_of(rel_path) if call_index is not None else ""
        )
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
        # Task 3.2: each call whose result an assignment binds to a single name
        # (`resp = make_response(...)`), recorded by visit_Assign before the
        # call is visited, so the HTML response sink can find a content type
        # assigned to the response afterwards; and the names the file defines
        # with def/class, collected on first need.
        self._call_targets: dict[ast.Call, tuple[str, ast.Assign]] = {}
        self._defined_names: frozenset[str] | None = None
        # Task 3.1: each def → the parameters that carry request data because
        # it is a route handler bound to this file (`_route_param_sources`),
        # and the module's `_ModuleFacts`, collected once, on first need.
        self._route_sources: dict[ast.AST, frozenset[str]] = {}
        self._module_facts: _ModuleFacts | None = None
        # Task 3.3: each def → whether it is a generator (a `yield` in its own
        # scope), whose `return` value is not a response body.
        self._generator_defs: dict[ast.AST, bool] = {}
        # Task 3.3: each module-level app/router name → the
        # `default_response_class=` its `FastAPI(...)`/`APIRouter(...)` sets
        # (None when it sets none), looked up once per name.
        self._default_response_classes: dict[str, ast.AST | None] = {}

    def _prime(self) -> None:
        """Record, without walking the file, the state the caller-side checks
        of the helper hop read (`_caller_arg_chain`): the scope parents
        (`_build_callsite_index`) and the file's imports, as the walk would
        leave them."""
        self._callsite_index = self._build_callsite_index()
        for node in ast.walk(self._module_root):
            if isinstance(node, ast.Import):
                self.visit_Import(node)
            elif isinstance(node, ast.ImportFrom):
                self.visit_ImportFrom(node)

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
        bind_route_in_other_file: bool = True,
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
            #
            # A bound route's file is the finding's file in its fingerprint
            # (models.Fingerprint, codeFile), and a Django route is declared in
            # the urlconf, not in the view. A rule whose findings were never
            # proven before passes bind_route_in_other_file=False, so proving
            # one does not re-file it under the urlconf.
            route = self._bound_route()
            if route is not None and (
                bind_route_in_other_file or self._route_is_in_this_file(route)
            ):
                finding["route"] = route.as_dict()
        self._emit(finding)

    def _route_is_in_this_file(self, route) -> bool:
        """True when `route` is declared in the file being visited: a
        decorator route on its handler, not a urlconf entry elsewhere."""
        return route.file.replace(os.sep, "/") == self._rel.replace(os.sep, "/")

    def _bound_route(self):
        """Return the Route whose handler is the innermost enclosing
        function, or None when there's no route table or no match."""
        if not self._func_stack:
            return None
        return self._route_for(self._func_stack[-1])

    def _route_for(self, func: ast.FunctionDef | ast.AsyncFunctionDef):
        """The first Route that points at `func` itself, or None."""
        routes = self._routes_for(func)
        return routes[0] if routes else None

    def _routes_for(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> list:
        """Every Route that points at `func` itself, first declared first.

        The route table is keyed on the bare function name, project-wide, so
        a name alone would make every same-named def a handler: an unrelated
        `def index(...)` in another file, a method sharing a view's name. A
        route binds only the def it was declared for (`_route_binds_here`)."""
        if self._route_table is None:
            return []
        return [
            route
            for route in self._route_table.routes_for_function(func.name)
            if self._route_binds_here(route, func)
        ]

    def _route_binds_here(self, route, func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """True when `route` dispatches to `func`, the def in this file.

        A urlconf route (Django) names its view as `module.func`: `func` must
        be a module-level def of a file one of the route's resolved
        `handler_modules` names. The route pass has already followed one
        re-export hop, and put a scanned module in place of one the scan root
        sits inside. A route with no module binds no def. A decorator route
        (Flask, FastAPI) is declared on the def itself: same file, and one of
        `func`'s decorators is the route's."""
        if getattr(route, "framework", "") == "django":
            modules = getattr(route, "handler_modules", ())
            return self._is_module_level_def(func) and any(
                _module_matches_file(m, self._rel) for m in modules
            )
        return route.file.replace(os.sep, "/") == self._rel.replace(
            os.sep, "/"
        ) and any(d.lineno == route.line for d in func.decorator_list)

    def _is_module_level_def(self, func: ast.AST) -> bool:
        """True when `func` is defined in the module's own scope (under an
        `if`/`try` at top level too), not in a class or another def."""
        if self._module_root is None:
            return True
        if self._callsite_index is None:
            self._callsite_index = self._build_callsite_index()
        return self._scope_parents.get(func) is self._module_root

    def _route_param_sources(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> frozenset[str]:
        """The parameters of `func` that are request sources:
        `route_param_sources` over the routes bound to `func` in this file
        (`_routes_for`; none, so no sources, unless it is a handler) and this
        module. Cached per def."""
        cached = self._route_sources.get(func)
        if cached is None:
            routes = self._routes_for(func)
            if routes and self._module_facts is None:
                self._module_facts = _module_facts(self._module_root)
            cached = _route_param_sources_with(func, routes, self._module_facts)
            self._route_sources[func] = cached
        return cached

    def _name_is_route_param_source(self, name: str) -> bool:
        """True when `name` is a request-carrying parameter of the route
        handler being visited: `self._bound_route() is not None and name in
        route_param_source_names(self._func_stack[-1])`, with the module and
        route rules `route_param_sources` adds."""
        return bool(self._func_stack) and name in self._route_param_sources(
            self._func_stack[-1]
        )

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
        if self._is_source(sink_arg, extra_source):
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
        function: a request source itself when the function is a route handler
        (`_name_is_route_param_source`), or one whose taint comes from a
        caller (audit recall gap; benchmark cmdi-interprocedural), which
        `_param_is_tainted_via_caller` tries one hop for.
        """
        return self._trace_names(
            expr,
            self._scope_binding,
            visited,
            depth,
            extra_source,
            self._unbound_name_source,
        )

    def _unbound_name_source(
        self, name: str, extra_source, depth: int
    ) -> list[dict] | None:
        """The chain prefix for a bare Name no binding in scope resolves.

        A request-carrying parameter of the route handler being visited is a
        source where it enters, at the `def` line, exactly as a `request.args`
        read would be at its assignment; sanitisers then apply to it as to
        any request value, because the sink predicates check the argument,
        not where it came from. Otherwise a same-file caller may taint the
        parameter (one hop)."""
        if self._name_is_route_param_source(name):
            return [self._link(self._func_stack[-1].lineno, name)]
        return self._param_is_tainted_via_caller(name, extra_source, depth)

    def _trace_in_bindings(
        self,
        expr: ast.AST,
        bindings: dict[str, ast.AST],
        visited: frozenset[str],
        depth: int,
        extra_source=None,
        on_unbound_name: Callable[..., list[dict] | None] | None = None,
    ) -> list[dict] | None:
        """`_trace_to_source` over a caller's ``bindings`` instead of the
        scopes being visited. A Name the bindings do not hold (a parameter of
        the caller, a global) ends the trace unless ``on_unbound_name``
        proves it: that is the single hop, and the caller's own callers are
        never searched."""
        return self._trace_names(
            expr, bindings.get, visited, depth, extra_source, on_unbound_name
        )

    def _scope_binding(self, key: str) -> ast.AST | None:
        """The value `key` is bound to in the scopes being visited, innermost
        first (audit #17), or None."""
        for scope in reversed(self._scopes):
            if key in scope:
                return scope[key]
        return None

    def _is_source(self, expr: ast.AST, extra_source=None) -> bool:
        """`_is_taint_source`, except that while `_skip_template_sources` is
        set, request input inside a template's source does not count."""
        if not self._skip_template_sources:
            return _is_taint_source(expr, extra_source)
        return any(
            _is_request_input_node(n) for n in self._walk_outside_template_sources(expr)
        ) or (extra_source is not None and extra_source(expr))

    def _taint_walk(self, expr: ast.AST) -> Iterator[ast.AST]:
        """The nodes the taint trace reads in ``expr``: `ast.walk`, without
        the template sources while `_skip_template_sources` is set."""
        if not self._skip_template_sources:
            return ast.walk(expr)
        return self._walk_outside_template_sources(expr)

    def _walk_outside_template_sources(self, expr: ast.AST) -> Iterator[ast.AST]:
        """`ast.walk(expr)` (the same breadth-first order) without the source
        argument of any template built from a string in it
        (`_template_construction`), nor anything inside that argument."""
        skipped: set[ast.AST] = set()
        todo = deque([expr])
        while todo:
            node = todo.popleft()
            if isinstance(node, ast.Call):
                built = self._template_construction(node)
                if built is not None and built[1] is not None:
                    skipped.add(built[1])
            todo.extend(c for c in ast.iter_child_nodes(node) if c not in skipped)
            yield node

    @contextmanager
    def _without_template_sources(self):
        """Trace taint for the HTML response sink (Task 3.2) without entering
        the source of a template built from a string. That source is the
        template-injection rule's (PY_SSTI, Task 3.4): the page an attacker's
        template renders is reported once, as SSTI, and an XSS finding on the
        same page is proven only by what its `.render(...)` is passed."""
        saved = self._skip_template_sources
        self._skip_template_sources = True
        try:
            yield
        finally:
            self._skip_template_sources = saved

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
        for n in self._taint_walk(expr):
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
                if self._is_source(assigned, extra_source):
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
        the keyword of that name (the only way to pass a keyword-only one). ``scope`` is where the call runs (see
        `_build_callsite_index`). Yields nothing once a hop is under way
        (`_interproc_depth`): one hop, never into the caller's callers.

        A method is never the callee of a bare-name call, which reaches a
        function of that name instead, so a method has no callers here."""
        if self._interproc_depth >= 1 or not self._func_stack:
            return
        func = self._func_stack[-1]
        idx = _param_position(func, param_name)
        if idx is None:
            return
        if self._callsite_index is None:
            self._callsite_index = self._build_callsite_index()
        if isinstance(self._scope_parents.get(func), ast.ClassDef):
            return
        for call, scope in self._callsite_index.get(func.name, []):
            arg = _call_argument(call, idx, param_name)
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
        same code written inline would not.

        When no caller in this file proves the parameter, the callers in other
        files are asked (`_cross_file_caller_link`, Task 3.8)."""
        for call, scope, arg in self._caller_args(param_name):
            self._interproc_depth += 1
            try:
                prefix = self._caller_arg_chain(call, scope, arg, extra_source, depth)
            finally:
                self._interproc_depth -= 1
            if prefix is not None:
                return prefix
        return self._cross_file_caller_link(param_name)

    def _cross_file_caller_link(self, param_name: str) -> list[dict] | None:
        """Task 3.8: the one-hop chain prefix a caller in ANOTHER file proves
        for parameter `param_name` of the innermost enclosing function, or
        None. The project call index (`self._call_index`) holds the calls that
        name this function through an import, and judges each in the caller's
        own file as `_caller_arg_chain` judges a same-file caller: request
        input or a request-carrying route parameter of the caller
        (`route_param_sources`), traced through the caller's assignments
        before the call, with the caller-side sanitiser union applied there
        (R-pf32, R-pf50 a). The prefix is that caller's one link, in the
        caller's file: the call, or the request expression passed inline.

        Only a module-level function is imported by name, so a method or a
        nested def has no callers here (R-pf50 c). A keyword-only parameter
        is matched by keyword alone (index -1). Single hop: never consulted
        while a hop is under way, and the callers' own parameters are not
        followed. The template-source rule of the trace under way
        (`_without_template_sources`) applies in the caller too."""
        if self._call_index is None or self._interproc_depth >= 1 or not self._func_stack:
            return None
        func = self._func_stack[-1]
        if not self._is_module_level_def(func):
            return None
        index = _param_position(func, param_name)
        if index is None:
            return None
        # The first proving caller is the one link the chain shows. The
        # caller is judged with this trace's template-source rule
        # (`_without_template_sources`), as a same-file caller is.
        links = self._call_index.tainted_args(
            self._module_dotted,
            func.name,
            index,
            param_name,
            first=True,
            skip_template_sources=self._skip_template_sources,
        )
        return [asdict(links[0])] if links else None

    def _caller_arg_chain(
        self, call: ast.Call, scope: ast.AST, arg: ast.AST, extra_source, depth: int
    ) -> list[dict] | None:
        """The chain prefix one caller's argument proves, or None: the
        argument as an inline source, or traced through the caller's bindings
        before the call (to a request expression, or to a request-carrying
        parameter of a caller that is a route handler) and followed by the
        call itself. None as well when a sanitiser accepts the argument in
        the caller."""
        if self._is_source(arg, extra_source):
            prefix = [self._link(call.lineno, _ast_expr_text(arg))]
        else:
            prefix = self._trace_in_bindings(
                arg,
                self._bindings_before(scope, call),
                frozenset(),
                depth + 1,
                extra_source,
                self._caller_route_param_source(scope),
            )
            if prefix is None:
                return None
            prefix = prefix + [self._link(call.lineno, _ast_expr_text(call))]
        if self._caller_arg_is_sanitised(scope, call, arg):
            return None
        return prefix

    def _caller_route_param_source(self, scope: ast.AST):
        """The `on_unbound_name` hook for a caller running in `scope`: a Name
        its bindings do not hold is a source when it is a request-carrying
        parameter of `scope`, a route handler (`_route_param_sources`), linked
        at the handler's `def` line. Only a def's own parameters: in a lambda,
        class or comprehension a name may be bound by that scope instead."""
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        sources = self._route_param_sources(scope)
        if not sources:
            return None

        def source(name: str, _extra_source, _depth: int) -> list[dict] | None:
            return [self._link(scope.lineno, name)] if name in sources else None

        return source

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

    def _is_escaped_call(
        self, expr: ast.AST, _resolving: frozenset[str] = frozenset()
    ) -> bool:
        """True if `expr` is a call to a recognized escaping/encoding function
        (html.escape, markupsafe.escape, bleach.clean, urllib.parse.quote,
        django escape/escapejs), or a Name bound to such a call (#24).

        ``_resolving`` holds the Names being followed, so a binding that reads
        its own name (``html = html``) ends instead of recursing until the
        file is skipped at the recursion limit."""
        if isinstance(expr, ast.Call):
            f = expr.func
            name = (
                f.attr
                if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else "")
            )
            return name in self._ESCAPE_FUNCS
        if isinstance(expr, ast.Name):
            if expr.id in _resolving:
                return False
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return self._is_escaped_call(
                        scope[expr.id], _resolving | {expr.id}
                    )
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

        A constant string repeated with ``*`` (``"&nbsp;" * depth``) is also
        inert: the result can only ever contain characters from the constant,
        whatever the multiplier evaluates to. A value repeated by a constant
        count (``name * 2``) is not: its text is the value's."""
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
            if isinstance(expr.op, ast.Mult) and any(
                isinstance(side, ast.Constant) and isinstance(side.value, str)
                for side in (expr.left, expr.right)
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
        may go where no sink is modelled (`os.remove`, `shutil.copy`), inline
        or returned to the caller, so the join can be the only place the flow
        is reported.
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
        self,
        arg: ast.AST,
        sink_line: int = 1_000_000,
        *,
        url_sink: bool = False,
        _resolving: frozenset[str] = frozenset(),
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

        ``_resolving`` holds the Names whose bindings are being followed. A
        binding can read its own name: ``x += "/p"`` on a parameter is bound to
        ``x + "/p"`` (visit_AugAssign). Following it again recursed without end,
        and the file was skipped at the recursion limit; such a Name is not
        sanitised.
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
            if arg.id in _resolving:
                return False
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
                    return self._arg_is_sanitised(
                        bound,
                        sink_line,
                        url_sink=url_sink,
                        _resolving=_resolving | {arg.id},
                    )
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
                        isinstance(v, ast.Constant)
                        or self._arg_is_sanitised(v, sink_line, _resolving=_resolving)
                        for v in values
                    )
                return False
            # Every non-Constant subexpression must itself be sanitised. Only
            # the leftmost operand of a `+` can still be the whole URL whose
            # host a URL-host guard fixed (`url + "/v1"`).
            left_url_sink = url_sink and isinstance(arg.op, ast.Add)
            return all(
                isinstance(sub, ast.Constant)
                or self._arg_is_sanitised(
                    sub, sink_line, url_sink=sub_url_sink, _resolving=_resolving
                )
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
        #
        # Task 3.9: the hashed value is traced to request input, so a password
        # read from the request is proven (reachable) and may block. The sink
        # is the evidence line on both paths: see the JWT branch below for why
        # a code finding needs that, and this `secrets` finding is keyed on
        # its rule and file alone (models.Fingerprint, secretIdentity).
        elif self._is_weak_password_hash(node):
            chain = self._collect_taint_chain(
                self._weak_password_hash_data(node), node.lineno, _ast_expr_text(node)
            )
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
                taint_chain=chain,
                sink=self._line_text(node.lineno),
            )

        # A redirect constructor with request-derived input (`_redirect_ctor`):
        # flask.redirect(request.args.get('url')), HttpResponseRedirect(
        # request.GET['next']), RedirectResponse(next_url) (Task 3.5).
        elif self._is_open_redirect(node):
            target = self._redirect_target(node)
            # Built once, OUTSIDE the chain attempt, so the operation is named
            # whether or not the flow can be proven — see _emit_finding's sink.
            # Every constructor names it `redirect(<target>)`.
            sink_expr = f"redirect({_ast_expr_text(target)})"
            chain = self._collect_taint_chain(target, node.lineno, sink_expr)
            self._emit_finding(
                "PY_OPEN_REDIRECT",
                _OPEN_REDIRECT_TITLE,
                _OPEN_REDIRECT_SEVERITY,
                _OPEN_REDIRECT_CONFIDENCE,
                _OPEN_REDIRECT_CWE,
                (
                    "Validate redirect targets against an allow-list of safe URLs/paths "
                    "before passing to redirect(). Reject anything outside your domain."
                ),
                node.lineno,
                taint_chain=chain,
                proven_title=_OPEN_REDIRECT_PROVEN_TITLE,
                sink=sink_expr,
            )

        # Server-side template injection (Task 3.4): a template compiled from a
        # string the request controls runs the attacker's template code on
        # the server (CWE-1336): `{{ cycler.__init__.__globals__.os.popen(...) }}`
        # in Jinja2, `${...}` in Mako. The sink is the construction, by
        # `_ssti_template_arg`: jinja2.Template, Environment(...).from_string
        # (sandboxed too), django.template.Template, engines[...].from_string
        # and mako.template.Template, resolved through the file's imports.
        # Flask's render_template_string keeps its own rule (PY_XSS_HTML_SINK,
        # below). Proven flows are CRITICAL; an unproven source stays HIGH.
        elif (ssti := self._ssti_sink(node)) is not None:
            template_name, template_src = ssti
            sink_expr = f"{template_name}({_ast_expr_text(template_src)})"
            chain = self._collect_taint_chain(template_src, node.lineno, sink_expr)
            self._emit_finding(
                "PY_SSTI",
                "Template built from a non-constant value (possible server-side template injection)",
                "HIGH",
                "HIGH",
                "CWE-1336",
                _SSTI_FIX,
                node.lineno,
                taint_chain=chain,
                proven_title="Template built from request input (server-side template injection)",
                proven_severity="CRITICAL",
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
        elif self._reports_html_sink(node):
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
                _XSS_HTML_SINK_TITLE,
                _XSS_HTML_SINK_SEVERITY,
                _XSS_HTML_SINK_CONFIDENCE,
                _XSS_HTML_SINK_CWE,
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

        # HTML response constructors (Task 3.2): Django HttpResponse, Flask
        # make_response / Response, Starlette and FastAPI HTMLResponse /
        # Response. The body reaches the browser as HTML unless the response
        # declares another content type, so request input written into it
        # unescaped is reflected XSS: the same weakness, so the same rule.
        elif self._is_html_response_sink(node):
            ctor = self._html_response_ctor(node)
            body = self._html_response_body(node, ctor)
            sink_expr = f"{ctor}({_ast_expr_text(body)})"
            with self._without_template_sources():
                chain = self._collect_taint_chain(body, node.lineno, sink_expr)
            self._emit_finding(
                "PY_XSS_HTML_SINK",
                _XSS_HTML_SINK_TITLE,
                _XSS_HTML_SINK_SEVERITY,
                _XSS_HTML_SINK_CONFIDENCE,
                _XSS_HTML_SINK_CWE,
                (
                    "Escape the value (html.escape, django.utils.html.escape or "
                    "markupsafe.escape) before writing it into the response, or "
                    "render it through an autoescaping template. A response that "
                    "is not HTML should declare its content type "
                    "(application/json, text/plain)."
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
        #   - starlette/fastapi FileResponse(x) (Task 3.6)
        #   - django.http.FileResponse(open(x, "rb"))  — caught via the
        #     inner open() match; Django's FileResponse takes an open file,
        #     so it is never a sink itself
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
            # The user-controlled arg is usually the FIRST positional
            # except for send_from_directory(safe_dir, x) and
            # os.path.join(base, x) where it's the second.
            # _path_traversal_target handles that.
            target = self._path_traversal_target(node)
            if target is not None:
                sink_expr = f"{sink_name}({_ast_expr_text(target)})"
                chain = self._collect_taint_chain(target, node.lineno, sink_expr)
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
        #
        # Task 3.9: the decoded token (the first argument, or `jwt=`) is traced
        # to request input, so a bearer token read from the request is proven
        # (reachable) and may block.
        #
        # Identity must not move with the proof. This is a code finding, and
        # models.Fingerprint names its operation by the sink, else the chain's
        # last link, else the evidence line. Before Task 3.9 it had neither, so
        # the evidence line was its identity: the sink is that line, on both
        # paths. A route declared in another file is not bound either (see
        # _emit_finding).
        elif self._is_jwt_misuse(node):
            token = _source_argument(node, "jwt")
            chain = (
                None
                if token is None
                else self._collect_taint_chain(token, node.lineno, _ast_expr_text(node))
            )
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
                taint_chain=chain,
                sink=self._line_text(node.lineno),
                bind_route_in_other_file=False,
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

        # A `Location` header on a framework response that redirects (Task
        # 3.5): `Response(status=302, headers={"Location": nxt})`. Checked
        # outside the chain above, so a response whose body is also an XSS
        # sink is reported for both.
        location = self._location_header_value(node)
        if location is not None and self._redirect_value_is_dynamic(location, node.lineno):
            self._report_location_redirect(location, node.lineno)

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

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        """Task 3.3: report a string a Flask view, or a FastAPI route whose
        response class is HTML, returns unescaped (`_report_view_return`), and
        Task 3.5: a ``Location`` header in a Flask view's returned
        ``(body, status, headers)`` tuple (`_returned_location`); then visit
        the returned expression."""
        if node.value is not None:
            response = self._view_return_response()
            if response is not None:
                self._report_view_return(node, *response)
            if response == ("make_response", "flask"):
                location = self._returned_location(node.value)
                if location is not None and self._redirect_value_is_dynamic(
                    location, node.lineno
                ):
                    self._report_location_redirect(location, node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """Record assignments so later sinks can resolve the bound value.

        Handles (audit #25-28): single Name, attribute (`self.q = ...`),
        subscript (`d['k'] = ...`), and tuple/list unpacking. For tuple
        unpacking from a tuple/list RHS we bind element-wise; otherwise each
        target is bound to the whole RHS (conservative — preserves taint)."""
        if (
            isinstance(node.value, ast.Call)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            self._call_targets[node.value] = (node.targets[0].id, node)
        # Task 3.5: `resp.headers["Location"] = x` / Django `resp["Location"] = x`.
        for target in node.targets:
            holder = _location_assignment_holder(target)
            if holder is not None:
                self._check_location_assignment(node, *holder)
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
            self._imported_modules[local_name] = alias.name if alias.asname else local_name
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
        return self._weak_password_hash_data(node) is not None

    def _weak_password_hash_data(self, node: ast.Call) -> ast.AST | None:
        """The hashed data of a hashlib.md5/sha1 call (`hashlib.new("md5" or
        "sha1", data)` too) when it looks like a password, else None."""
        if not isinstance(node.func, ast.Attribute):
            return None
        if not (
            isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib"
        ):
            return None
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
            return None
        # Find the data argument: arg[0] for md5/sha1, arg[1] for new(algo, data).
        data_arg = None
        if node.func.attr in {"md5", "sha1"} and node.args:
            data_arg = node.args[0]
        elif node.func.attr == "new" and len(node.args) >= 2:
            data_arg = node.args[1]
        if data_arg is None or not _arg_subtree_looks_like_password(data_arg):
            return None
        return data_arg

    def _is_open_redirect(self, node: ast.Call) -> bool:
        """Return True if a redirect constructor (`_redirect_ctor`) gets a
        non-literal target (`_redirect_value_is_dynamic`).

        Posture upgraded to match SSRF/XSS/path-traversal (surfaced by
        the accuracy corpus, 2026-05-13): emit on any non-literal arg,
        and let `_collect_taint_chain` decide reachability. Pre-upgrade
        only direct `redirect(request.args.get("x"))` was caught; the
        far more common `next_url = request.args.get("x"); return
        redirect(next_url)` pattern was silently missed because the
        first arg was a Name, not a request-access subtree.
        """
        if not self._redirect_ctor(node)[0]:
            return False
        target = self._redirect_target(node)
        return target is not None and self._redirect_value_is_dynamic(target, node.lineno)

    def _redirect_value_is_dynamic(self, value: ast.AST, sink_line: int) -> bool:
        """True when a redirect target (a constructor's argument or a
        ``Location`` header's value) is not provably a safe destination."""
        # Constant literal redirect target is safe.
        if isinstance(value, ast.Constant):
            return False
        # Name that resolves to a constant in scope is also safe.
        if isinstance(value, ast.Name):
            for scope in reversed(self._scopes):
                if value.id in scope:
                    if isinstance(scope[value.id], ast.Constant):
                        return False
                    break  # innermost binding wins (audit #17)
        # Whitelisted dict lookup / set-membership / URL-host allowlist guard
        # → sanitised.
        if self._arg_is_sanitised(value, sink_line, url_sink=True):
            return False
        # Framework URL builders produce safe internal URLs from a route NAME,
        # not user input: Flask url_for(...), Django reverse(...). A redirect to
        # one of these is not an open redirect (real-data FP on flask/django).
        if self._is_safe_url_builder(value):
            return False
        return True

    # ─── Redirect constructors and Location headers (Task 3.5) ───────
    #
    # A redirect is sent by a framework's redirect constructor (Flask's
    # `redirect`, Django's `HttpResponseRedirect`, Starlette's
    # `RedirectResponse`, ...) or by any framework response that carries a
    # `Location` header and a redirect status. Both are the PY_OPEN_REDIRECT
    # sink, judged by `_redirect_value_is_dynamic`.

    def _redirect_ctor(self, node: ast.Call) -> tuple[str, str]:
        """``(constructor, package)`` for a call to a redirect constructor
        (`_REDIRECT_CTOR_PACKAGES`), else ``("", "")``.

        An imported name resolves to the symbol it imports and must come from
        a framework that defines it: ``from fastapi.responses import
        RedirectResponse as Go; Go(x)`` is one, ``from app.utils import
        redirect`` is not, and neither is a name the file defines itself
        (``def redirect(...)``). A method on a module resolves the same way
        (``flask.redirect``, ``shortcuts.redirect``). A bare name the file
        neither imports nor defines (a star import), and a method on any other
        value (Tornado's ``self.redirect``), count by their name."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self._file_defined_names():
                return "", ""
            imported = func.id in self._from_imports
            module, name = self._from_imports.get(func.id, ("", func.id))
        elif isinstance(func, ast.Attribute):
            module, name = self._import_origin(func.value), func.attr
            imported = bool(module)
        else:
            return "", ""
        packages = _REDIRECT_CTOR_PACKAGES.get(name)
        if packages is None:
            return "", ""
        package = module.split(".")[0]
        if imported and package not in packages:
            return "", ""
        return name, package

    @staticmethod
    def _redirect_target(node: ast.Call) -> ast.AST | None:
        """The destination a redirect constructor is given: its first
        positional argument, else its ``location=`` (Flask, Werkzeug),
        ``to=`` (Django ``redirect``), ``redirect_to=`` (Django
        ``HttpResponseRedirect``) or ``url=`` (Starlette ``RedirectResponse``)
        keyword."""
        if node.args:
            return node.args[0]
        return next(
            (kw.value for kw in node.keywords if kw.arg in _REDIRECT_TARGET_KEYWORDS),
            None,
        )

    def _location_header_value(self, node: ast.Call) -> ast.AST | None:
        """The ``Location`` value a framework response constructor
        (`_resolve_html_response`) is given in its headers, when the response
        redirects (`_response_redirects`), else None:
        ``Response(status=302, headers={"Location": nxt})``. The headers are a
        literal dict or list of ``(name, value)`` pairs, or a name bound to
        one, passed by the ``headers=`` keyword or by position (Flask's
        ``make_response(body, status, headers)`` too); the key is compared
        case-insensitively. The last ``Location`` entry wins, as in a dict."""
        ctor, package = self._resolve_html_response(node)
        if not ctor:
            return None
        values = self._location_values(self._response_headers(node, ctor, package))
        if not values or not self._response_redirects(node, ctor, package):
            return None
        return values[-1]

    def _location_values(self, headers: list[ast.AST]) -> list[ast.AST]:
        """The ``Location`` values in each of ``headers``: a literal dict or
        list of pairs, or a Name bound to one in scope."""
        values: list[ast.AST] = []
        for h in headers:
            if isinstance(h, ast.Name):
                h = self._scope_binding(h.id) or h
            values.extend(_header_values(h, "location"))
        return values

    def _response_redirects(self, node: ast.Call, ctor: str, package: str) -> bool:
        """True when the response ``node`` builds may have a redirect status,
        which is what makes a browser follow its ``Location`` header.

        A status assigned to the bound response afterwards (``resp.status_code
        = 302``, found as `_late_content_type` finds a content type) decides by
        itself; otherwise the status given at construction, by keyword
        (``status``/``status_code``) or position (`_response_layout`). With no
        status the response sends the framework's default 200, which no
        browser follows. A 201 Created's ``Location`` names a new resource,
        so a status that is provably not a redirect is no sink
        (`_status_may_redirect`)."""
        late = self._late_assignment(node, _is_status_target)
        if late is not None:
            return self._status_may_redirect(late)
        args = self._response_args(node, ctor)
        status_index = self._response_layout(ctor, package)[0]
        statuses = [kw.value for kw in node.keywords if kw.arg in ("status", "status_code")]
        if status_index < len(args):
            statuses.append(args[status_index])
        return any(self._status_may_redirect(s) for s in statuses)

    def _status_may_redirect(self, value: ast.AST) -> bool:
        """False for a status that is provably not a redirect: a constant (or a
        Name bound to one) outside 301/302/303/307/308, ``None`` (the default
        200), a headers literal in a status position (Flask's
        ``make_response(body, headers)``), or a named status of a status module
        (`_STATUS_MODULES`) other than a redirect (``HTTPStatus.CREATED``,
        ``status.HTTP_201_CREATED``). Any other value may be a redirect."""
        if isinstance(value, ast.Name):
            bound = self._scope_binding(value.id)
            if isinstance(bound, ast.Constant):
                value = bound
        if isinstance(value, ast.Constant):
            status = value.value
            if isinstance(status, str):
                # Werkzeug also takes a status line: "302 FOUND".
                match = re.match(r"\s*(\d{3})", status)
                return match is not None and int(match.group(1)) in _REDIRECT_STATUSES
            return (
                isinstance(status, int)
                and not isinstance(status, bool)
                and status in _REDIRECT_STATUSES
            )
        if isinstance(value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            return False
        if self._is_redirect_status_constant(value):
            return True
        module = self._import_origin(value).rpartition(".")[0]
        return module not in _STATUS_MODULES

    def _returned_location(self, value: ast.AST) -> ast.AST | None:
        """The ``Location`` value of a Flask view's returned ``(body, status,
        headers)`` tuple when its status may be a redirect, else None. A
        ``(body, headers)`` tuple is sent with status 200."""
        if not (isinstance(value, ast.Tuple) and len(value.elts) == 3):
            return None
        _, status, headers = value.elts
        if not self._status_may_redirect(status):
            return None
        values = self._location_values([headers])
        return values[-1] if values else None

    def _check_location_assignment(
        self, node: ast.Assign, name: str, via_headers: bool
    ) -> None:
        """Report ``<name>.headers["Location"] = x`` (or Django's
        ``<name>["Location"] = x``) when ``name`` is bound to a framework
        response that redirects: a redirect constructor (`_redirect_ctor`), or
        a response constructor (`_resolve_html_response`) whose status may be
        a redirect (`_response_redirects`). The item form sets a header only on
        a Django response. A name bound to anything else (a plain dict, a
        parameter, a project's own class) is not a response this rule
        knows."""
        bound = self._scope_binding(name)
        if not isinstance(bound, ast.Call):
            return
        ctor, package = self._redirect_ctor(bound)
        if ctor:
            redirects = True
        else:
            ctor, package = self._resolve_html_response(bound)
            if not ctor:
                return
            redirects = self._response_redirects(bound, ctor, package)
        django = package == "django" or ctor in _DJANGO_RESPONSE_NAMES
        if not redirects or not (via_headers or django):
            return
        if self._redirect_value_is_dynamic(node.value, node.lineno):
            self._report_location_redirect(node.value, node.lineno)

    def _report_location_redirect(self, value: ast.AST, lineno: int) -> None:
        """Emit PY_OPEN_REDIRECT for a ``Location`` header set to ``value``.
        The sink is named ``Location: <value>`` in every form."""
        sink_expr = f"Location: {_ast_expr_text(value)}"
        chain = self._collect_taint_chain(value, lineno, sink_expr)
        self._emit_finding(
            "PY_OPEN_REDIRECT",
            _OPEN_REDIRECT_TITLE,
            _OPEN_REDIRECT_SEVERITY,
            _OPEN_REDIRECT_CONFIDENCE,
            _OPEN_REDIRECT_CWE,
            (
                "Validate redirect targets against an allow-list of safe URLs/paths "
                "before setting them as the Location header. Reject anything "
                "outside your domain."
            ),
            lineno,
            taint_chain=chain,
            proven_title=_OPEN_REDIRECT_PROVEN_TITLE,
            sink=sink_expr,
        )

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

    def _reports_html_sink(self, node: ast.Call) -> bool:
        """True when visit_Call's Markup/mark_safe/render_template_string
        branch reports ``node``: a known HTML-render sink whose argument is not
        fully escaped (B5). These sinks are released, so their findings are
        frozen (R-pf47): a template built from request input in the argument
        is reported by PY_SSTI beside them, never instead of them."""
        return self._is_xss_html_sink(node) and not (
            node.args and self._expr_is_fully_escaped(node.args[0])
        )

    # ─── HTML response constructors (Task 3.2) ──────────────────────
    #
    # `HttpResponse(f"<h1>{name}</h1>")` is the most common way request input
    # reaches a page unescaped: no template, so no autoescape. The sink is the
    # constructor's body, judged by `_is_html_response_sink`:
    #   1. the call is a framework's HTML response constructor
    #      (`_resolve_html_response`): imported from its framework, or called
    #      by a bare name the file neither imports nor defines;
    #   2. the response has a body the browser renders: not a 204/304 status,
    #      and no declared content type that is provably not markup, at
    #      construction or assigned afterwards (`_response_is_non_html`);
    #   3. the body is not constant, escaped or sanitised;
    #   4. some part of the body can carry text verbatim
    #      (`_html_body_carries_text`). The engine has no return values, so a
    #      body that is, as a whole, the result of a helper function is not
    #      claimed: the helper may have escaped or rendered it.

    def _is_html_response_sink(self, node: ast.Call) -> bool:
        """True when ``node`` builds an HTML response whose body can hold
        request text unescaped. The body's taint chain then decides whether the
        flow is proven, exactly as for Markup/mark_safe."""
        ctor, package = self._resolve_html_response(node)
        return bool(ctor) and self._html_sink_body(node, ctor, package) is not None

    def _html_sink_body(self, node: ast.Call, ctor: str, package: str) -> ast.AST | None:
        """Steps 2-4 above for a call to the constructor ``ctor`` of
        ``package``, already resolved: the body when the call is an HTML
        response sink, else None. A view's return value is judged here too, as
        the response its framework builds from it (`visit_Return`)."""
        body = self._html_response_body(node, ctor)
        if body is None or isinstance(body, ast.Constant):
            return None
        # Flask sends a dict or list as JSON and a response object as it is.
        if ctor == "make_response" and self._flask_body_is_not_text(body):
            return None
        if self._response_drops_body(node, ctor, package):
            return None
        if self._response_is_non_html(node, ctor, package):
            return None
        if self._expr_is_fully_escaped(body) or self._arg_is_sanitised(
            body, node.lineno
        ):
            return None
        if not self._html_body_carries_text(body, node.lineno):
            return None
        # One finding per flow: an HTML-render sink or an HTML response inside
        # the body (`make_response(Markup(x))`, `make_response(Response(x))`)
        # is reported by its own branch.
        if any(
            isinstance(sub, ast.Call)
            and (self._reports_html_sink(sub) or self._is_html_response_sink(sub))
            for sub in ast.walk(body)
        ):
            return None
        return body

    def _flask_body_is_not_text(
        self, body: ast.AST, _seen: frozenset[str] = frozenset(), _depth: int = 0
    ) -> bool:
        """True when Flask's ``make_response``, which Flask also applies to the
        value a view returns, does not send ``body`` as text:

        - a dict or list, which Flask sends as JSON: a literal, a
          comprehension, the request data Flask reads into one
          (`_is_flask_request_mapping`, and its ``.to_dict()``/``.getlist()``),
          or a ``.split()``/``.rsplit()``/``.splitlines()`` list;
        - a class instance (a capitalised callee): a response object Flask
          sends as it is (``Response(...)``, a project's response class), or a
          sink with a branch of its own (``Markup(...)``).

        Followed through both sides of a conditional or ``or``/``and``, and
        through a name the whole body is bound to: EVERY value the scope
        assigns that name (`_name_binding_values`) must be one of these, so a
        text value bound in any branch, before or after the others, keeps the
        body text. Never through an attribute or subscript read:
        ``form.name.data`` is text."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(body, (ast.Dict, ast.List, ast.DictComp, ast.ListComp)):
            return True
        if isinstance(body, ast.IfExp):
            return all(
                self._flask_body_is_not_text(b, _seen, _depth + 1)
                for b in (body.body, body.orelse)
            )
        if isinstance(body, ast.BoolOp):
            return all(self._flask_body_is_not_text(v, _seen, _depth + 1) for v in body.values)
        if isinstance(body, ast.Name):
            if body.id in _seen:
                return False
            values = self._name_binding_values(body.id)
            if values is None:
                return False
            if not values:
                bound = self._scope_binding(body.id)
                values = [bound] if bound is not None else []
            return bool(values) and all(
                self._flask_body_is_not_text(v, _seen | {body.id}, _depth + 1)
                for v in values
            )
        if _is_flask_request_mapping(body):
            return True
        if isinstance(body, ast.Call):
            func = body.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _FLASK_MAPPING_METHODS
                and _is_flask_request_mapping(func.value)
            ):
                return True
            if isinstance(func, ast.Attribute) and func.attr in _STR_LIST_METHODS:
                return True
            return _terminal_name(func)[:1].isupper()
        return False

    def _name_binding_values(self, name: str) -> list[ast.AST] | None:
        """Every value the scope being visited (the innermost def, else the
        module) assigns ``name`` by a plain ``name = value``, in any branch and
        before or after the point being visited. ``[]`` when the scope does
        not bind it; None when it binds it some other way (a parameter, a loop
        or ``with`` target, unpacking, ``+=``, a walrus), whose value is
        unknown."""
        scope = self._func_stack[-1] if self._func_stack else self._module_root
        if scope is None:
            return []
        values: list[ast.AST] = []
        stores = 0
        for n in _walk_own_scope(scope):
            if n is not scope and _binds_name(n, name):
                stores += 1
            if isinstance(n, ast.Assign):
                values.extend(
                    n.value for t in n.targets if isinstance(t, ast.Name) and t.id == name
                )
            elif (
                isinstance(n, ast.AnnAssign)
                and isinstance(n.target, ast.Name)
                and n.target.id == name
                and n.value is not None
            ):
                values.append(n.value)
        return values if stores == len(values) else None

    # ─── A view's return value (Task 3.3) ───────────────────────────
    #
    # Flask passes what a view returns to `make_response`, which sends a `str`
    # (or `bytes`) as text/html. `return f"<p>{name}</p>"` is therefore an HTML
    # response body exactly like `make_response(f"<p>{name}</p>")`, and it is
    # judged by the same body analysis (`_html_sink_body`): a
    # dict, list or response object is not text, a `(body, status, headers)`
    # tuple is checked on its body and its headers' content type, and the
    # sanitisers, opacity, value types and `json.dumps` rule are Task 3.2's.
    # Quart, which the route extractor counts as Flask, does the same. FastAPI
    # and Django Ninja send a returned `str` as JSON unless the route's
    # response class is HTML (`_fastapi_html_response`), and Django needs an
    # `HttpResponse`, so only those routes' returns are sinks.

    def _view_return_response(self) -> tuple[str, str] | None:
        """``(constructor, package)`` of the response the framework builds
        from what the view being visited returns, when that response is HTML:
        Flask's ``make_response`` for a Flask view, and the route's response
        class for a FastAPI route whose class is HTML. None for any other
        def: a generator (it streams what it yields), a return in a def,
        lambda or class nested in a view, a helper no route points at, and a
        route of another or an unknown framework."""
        route = self._bound_route()
        if route is None:
            return None
        func = self._func_stack[-1]
        if func not in self._generator_defs:
            self._generator_defs[func] = any(
                isinstance(n, (ast.Yield, ast.YieldFrom)) for n in _walk_own_scope(func)
            )
        if self._generator_defs[func]:
            return None
        framework = getattr(route, "framework", "")
        if framework == "flask":
            return "make_response", "flask"
        if framework == "fastapi":
            return self._fastapi_html_response(func, route)
        return None

    def _fastapi_html_response(self, func: ast.AST, route) -> tuple[str, str] | None:
        """``(constructor, package)`` of a FastAPI route's response class when
        it renders a returned ``str`` as HTML: ``HTMLResponse``, or Starlette's
        ``Response``, which sends no Content-Type for the browser to sniff.
        The class is the route decorator's ``response_class=``, else the
        ``default_response_class=`` of the ``FastAPI(...)``/``APIRouter(...)``
        the decorator is called on, bound once at module level in this file.
        None for any other class (``JSONResponse``, the default, or
        ``PlainTextResponse``)."""
        deco = next(
            (
                d
                for d in getattr(func, "decorator_list", [])
                if isinstance(d, ast.Call) and d.lineno == route.line
            ),
            None,
        )
        if deco is None:
            return None
        cls = next((kw.value for kw in deco.keywords if kw.arg == "response_class"), None)
        if cls is None and isinstance(deco.func, ast.Attribute) and isinstance(
            deco.func.value, ast.Name
        ):
            name = deco.func.value.id
            if name not in self._default_response_classes:
                owner = self._module_binding(name)
                self._default_response_classes[name] = (
                    next(
                        (kw.value for kw in owner.keywords if kw.arg == "default_response_class"),
                        None,
                    )
                    if isinstance(owner, ast.Call)
                    else None
                )
            cls = self._default_response_classes[name]
        if cls is None:
            return None
        ctor, package = self._resolve_html_response(ast.Call(func=cls, args=[], keywords=[]))
        if ctor == "HTMLResponse" or (ctor == "Response" and package in ("starlette", "fastapi")):
            return ctor, package
        return None

    def _report_view_return(self, node: ast.Return, ctor: str, package: str) -> None:
        """Emit PY_XSS_HTML_SINK for a view's ``return <value>`` when the
        response the framework builds from it, ``ctor(<value>)``, would be an
        HTML response sink and the body's text is proven to come from the
        request.

        A FastAPI route sends a returned response object as it is and cannot
        render a dict, list or tuple as HTML, so those are not its body.

        Only a proven flow is reported (R-pf44). Every view returns something,
        and a string built from a value the engine cannot trace to the request
        (a database read, an exception, a constant) is not a finding, not even
        an unproven one."""
        if ctor != "make_response" and (
            isinstance(node.value, ast.Tuple) or self._flask_body_is_not_text(node.value)
        ):
            return
        call = ast.copy_location(
            ast.Call(
                func=ast.Name(id=ctor, ctx=ast.Load()),
                args=[node.value],
                keywords=[],
            ),
            node,
        )
        body = self._html_sink_body(call, ctor, package)
        if body is None:
            return
        # The body alone names the sink: a status or headers added to the
        # returned tuple do not re-identify the finding.
        sink_expr = f"return {_ast_expr_text(body)}"
        with self._without_template_sources():
            chain = self._collect_taint_chain(body, node.lineno, sink_expr)
        if not chain:
            return
        self._emit_finding(
            "PY_XSS_HTML_SINK",
            _XSS_HTML_SINK_TITLE,
            _XSS_HTML_SINK_SEVERITY,
            _XSS_HTML_SINK_CONFIDENCE,
            _XSS_HTML_SINK_CWE,
            (
                "The framework sends this returned string as text/html. Escape "
                "the value (markupsafe.escape or html.escape) before returning "
                "it, or render it through an autoescaping template "
                "(render_template with an .html template). Data that is not a "
                "page should be returned as JSON (jsonify, a dict, or FastAPI's "
                "default response class) or with a non-HTML Content-Type."
            ),
            node.lineno,
            taint_chain=chain,
            sink=sink_expr,
        )

    def _html_response_ctor(self, node: ast.Call) -> str:
        """The name of the HTML response constructor ``node`` calls, or ""."""
        return self._resolve_html_response(node)[0]

    def _resolve_html_response(self, node: ast.Call) -> tuple[str, str]:
        """``(constructor, package)`` for a call to an HTML response
        constructor, else ``("", "")``.

        An imported name resolves to the symbol it imports, and must come from
        that constructor's framework (`_HTML_RESPONSE_PACKAGES`):
        ``from flask import make_response as mk; mk(x)`` is one,
        ``from .utils import make_response`` is not. A name the file defines
        itself (``def make_response(...)``) is never one, and neither is a
        method on ``self``/``cls``. A bare name that is neither imported nor
        defined, or a method on another value (Flask's ``app.make_response``),
        counts by its name, except ``Response``, which must be imported."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self._file_defined_names():
                return "", ""
            imported = func.id in self._from_imports
            module, name = self._from_imports.get(func.id, ("", func.id))
        elif isinstance(func, ast.Attribute):
            if _dotted(func.value) in _OWN_RECEIVERS:
                return "", ""
            module, name = self._import_origin(func.value), func.attr
            imported = bool(module)
        else:
            return "", ""
        if name not in _HTML_RESPONSE_CTORS:
            return "", ""
        package = module.split(".")[0]
        if (imported or name == "Response") and package not in _HTML_RESPONSE_PACKAGES[
            name
        ]:
            return "", ""
        return name, package

    def _file_defined_names(self) -> frozenset[str]:
        """Names the file binds with ``def`` or ``class``, methods excluded
        (a method never shadows a bare name)."""
        if self._defined_names is None:
            root = self._module_root
            nodes = list(ast.walk(root)) if root is not None else []
            methods = {
                id(child)
                for n in nodes
                if isinstance(n, ast.ClassDef)
                for child in n.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self._defined_names = frozenset(
                n.name
                for n in nodes
                if isinstance(n, ast.ClassDef)
                or (
                    isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and id(n) not in methods
                )
            )
        return self._defined_names

    def _import_origin(self, expr: ast.AST) -> str:
        """The dotted import path a Name/Attribute chain stands for, through the
        file's imports (``flask``, ``fastapi.responses``), or "" when its head
        is not an imported name, or is shadowed by a local binding
        (``import html`` then ``html = f"<p>{x}</p>"``). ``import a.b`` binds
        ``a``, so ``a.b.c`` is ``a.b.c``; ``import a.b as x`` binds ``x`` to
        ``a.b``."""
        head, _, rest = _dotted(expr).partition(".")
        if not head or self._scope_binding(head) is not None:
            return ""
        if head in self._imported_modules:
            base = self._imported_modules[head]
        elif head in self._from_imports:
            module, symbol = self._from_imports[head]
            base = f"{module}.{symbol}" if module else symbol
        else:
            return ""
        return f"{base}.{rest}" if rest else base

    @staticmethod
    def _response_args(node: ast.Call, ctor: str) -> list[ast.AST]:
        """The constructor's positional arguments. Flask's
        ``make_response((body, status, headers))`` passes them as one tuple."""
        args = list(node.args)
        if (
            ctor == "make_response"
            and len(args) == 1
            and isinstance(args[0], ast.Tuple)
            and args[0].elts
        ):
            return list(args[0].elts)
        return args

    def _html_response_body(self, node: ast.Call, ctor: str) -> ast.AST | None:
        """The body a response constructor sends: its first positional
        argument, else its ``content=``/``response=`` keyword."""
        args = self._response_args(node, ctor)
        if args:
            return None if isinstance(args[0], ast.Starred) else args[0]
        for kw in node.keywords:
            if kw.arg in _RESPONSE_BODY_KEYWORDS:
                return kw.value
        return None

    @staticmethod
    def _response_layout(ctor: str, package: str) -> tuple[int, int | None, tuple[int, ...]]:
        """Positions of the status, the headers and the content type among a
        constructor's positional arguments. Django
        ``HttpResponse(content, content_type, status, reason, charset, headers)``;
        Flask/Werkzeug ``Response(response, status, headers, mimetype,
        content_type)``; Starlette ``Response(content, status_code, headers,
        media_type, background)``; Flask ``make_response(body, status, headers)``,
        whose headers `_response_is_non_html` looks for in any position."""
        if ctor == "HttpResponse":
            return 2, 5, (1,)
        if ctor == "make_response":
            return 1, None, ()
        if package in ("flask", "werkzeug"):
            return 1, 2, (3, 4)
        return 1, 2, (3,)

    def _response_drops_body(self, node: ast.Call, ctor: str, package: str) -> bool:
        """True when the browser renders no body: a 204 No Content or 304 Not
        Modified response (Werkzeug drops the body), or a redirect (301, 302,
        303, 307 or 308) with a ``Location`` entry in a literal headers dict or
        list of pairs, which the browser follows instead of rendering it."""
        args = self._response_args(node, ctor)
        status_index = self._response_layout(ctor, package)[0]
        statuses = [kw.value for kw in node.keywords if kw.arg in ("status", "status_code")]
        if status_index < len(args):
            statuses.append(args[status_index])
        redirect = False
        for value in statuses:
            if isinstance(value, ast.Constant) and not isinstance(value.value, bool):
                if value.value in _BODYLESS_STATUSES:
                    return True
                redirect = redirect or value.value in _REDIRECT_STATUSES
            else:
                if _terminal_name(value).endswith(("NO_CONTENT", "NOT_MODIFIED")):
                    return True
                redirect = redirect or self._is_redirect_status_constant(value)
        return redirect and any(
            _header_values(h, "location") for h in self._response_headers(node, ctor, package)
        )

    def _is_redirect_status_constant(self, value: ast.AST) -> bool:
        """True for a redirect status named through an import: an
        ``HTTPStatus`` member (``HTTPStatus.FOUND``, ``http.HTTPStatus.SEE_OTHER``)
        or a constant of a status module (``http.client``, ``starlette.status``,
        ``fastapi.status``, ``rest_framework.status``: ``HTTP_302_FOUND``). A
        local name such as ``FOUND = 200`` is not one."""
        module, _, name = self._import_origin(value).rpartition(".")
        return module in _STATUS_MODULES and bool(_REDIRECT_STATUS_NAME.fullmatch(name))

    def _response_headers(self, node: ast.Call, ctor: str, package: str) -> list[ast.AST]:
        """The headers a constructor call passes: its ``headers=`` keyword,
        the headers argument at its position (`_response_layout`), and for
        Flask's ``make_response(body, status, headers)`` any argument after
        the body."""
        args = self._response_args(node, ctor)
        headers_index = self._response_layout(ctor, package)[1]
        headers = [kw.value for kw in node.keywords if kw.arg == "headers"]
        if ctor == "make_response":
            headers.extend(args[1:])
        elif headers_index is not None and headers_index < len(args):
            headers.append(args[headers_index])
        return headers

    def _response_is_non_html(self, node: ast.Call, ctor: str, package: str) -> bool:
        """True when the response's content type is provably not markup.

        A type assigned after construction (`_late_content_type`) decides by
        itself. Otherwise the construction decides: a type declared by the
        ``content_type``/``mimetype``/``media_type`` keyword, by its position
        (`_response_layout`), or by a ``Content-Type`` entry in a literal
        headers dict or list of pairs (``headers=``, or Flask's
        ``make_response(body, status, headers)``). Every declared type must be
        a non-markup constant (``None`` is a type not given). With none, the
        response is HTML: Django and Flask default to text/html, and a
        Starlette ``Response`` sends no Content-Type, so the browser sniffs the
        body. ``HTMLResponse`` is always HTML."""
        if ctor == "HTMLResponse":
            return False
        late = self._late_content_type(node)
        if late is not None:
            return self._is_non_markup_media_type(late)
        args = self._response_args(node, ctor)
        type_indexes = self._response_layout(ctor, package)[2]
        declared = [
            kw.value for kw in node.keywords if kw.arg in _RESPONSE_CONTENT_TYPE_KEYWORDS
        ]
        declared.extend(args[i] for i in type_indexes if i < len(args))
        for h in self._response_headers(node, ctor, package):
            declared.extend(_header_content_types(h))
        # `None` is a type not given (`Response(body, 200, None, None, "text/plain")`).
        declared = [
            v for v in declared if not (isinstance(v, ast.Constant) and v.value is None)
        ]
        return bool(declared) and all(self._is_non_markup_media_type(v) for v in declared)

    def _late_content_type(self, node: ast.Call) -> ast.AST | None:
        """The content type the response ``node`` builds ends up with after
        construction, or None when nothing later sets one.

        Only when ``node`` is bound to a name (``resp = ...``), and only in the
        statements that follow that binding in the same statement list:
        ``resp["Content-Type"] = v`` (Django), ``resp.headers["Content-Type"]
        = v`` (Flask, Starlette), and ``resp.mimetype``/``.content_type``/
        ``.media_type = v``. The last such assignment wins. The scan stops at
        a statement that rebinds the name, or that returns or yields (the
        response may leave before a later assignment runs). An assignment
        inside a nested branch, loop, ``with`` or ``try`` may not run, so it
        makes the type unknown, which is HTML."""
        return self._late_assignment(node, _is_content_type_target)

    def _late_assignment(
        self, node: ast.Call, is_target: Callable[[ast.AST, str], bool]
    ) -> ast.AST | None:
        """The value last assigned, after construction, to the part of the
        response ``node`` builds that ``is_target(target, name)`` recognises,
        scanned as `_late_content_type` describes; `_UNKNOWN_LATE_VALUE` when
        the last such assignment sits in a nested statement that may not run;
        None when nothing assigns it."""
        target = self._call_targets.get(node)
        scope = self._func_stack[-1] if self._func_stack else self._module_root
        if target is None or scope is None:
            return None
        name, binding = target
        stmts = _statement_list_holding(scope, binding)
        if stmts is None:
            return None
        found: ast.AST | None = None
        for stmt in stmts[_index_of(stmts, binding) + 1 :]:
            if _rebinds(stmt, name):
                break
            if isinstance(stmt, ast.Assign) and any(is_target(t, name) for t in stmt.targets):
                found = stmt.value
                continue
            if any(
                isinstance(n, ast.Assign) and any(is_target(t, name) for t in n.targets)
                for n in _walk_own_scope(stmt)
            ):
                found = _UNKNOWN_LATE_VALUE
            if any(isinstance(n, _LEAVING_NODES) for n in _walk_own_scope(stmt)):
                break
        return found

    def _is_non_markup_media_type(self, value: ast.AST) -> bool:
        """True for a constant media type (or a Name bound to one) that is not
        HTML, XML or SVG. ``None`` keeps the framework's default, which is HTML,
        and a value the engine cannot read might be text/html."""
        if isinstance(value, ast.Name):
            value = self._scope_binding(value.id) or value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return False
        media = value.value.split(";")[0].strip().lower()
        return bool(media) and not any(m in media for m in _MARKUP_MEDIA_TYPE_MARKERS)

    def _renderer_verdict(self, call: ast.Call) -> str:
        """``"safe"`` for a renderer that escapes what it renders (or Flask's
        ``jsonify``), called through an import from its framework
        (`_HTML_RESPONSE_SAFE_BODIES`), and for ``.render(...)`` on a Django
        template object (`_is_django_template`); ``"text"`` for Flask's
        ``render_template`` of a template whose constant name Flask does not
        autoescape (``"x.txt"``); "" for anything else, including ``.render``
        on a Jinja2 or Mako template and a same-file ``def render`` (R-pf40)."""
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "render"
            and self._is_django_template(func.value)
        ):
            return "safe"
        if isinstance(func, ast.Name):
            module, name = self._from_imports.get(func.id, ("", ""))
        elif isinstance(func, ast.Attribute):
            module, name = self._import_origin(func.value), func.attr
        else:
            return ""
        packages = _HTML_RESPONSE_SAFE_BODIES.get(name)
        if not packages or module.split(".")[0] not in packages:
            return ""
        if name == "render_template":
            template = call.args[0] if call.args else next(
                (kw.value for kw in call.keywords if kw.arg == "template_name_or_list"),
                None,
            )
            if (
                isinstance(template, ast.Constant)
                and isinstance(template.value, str)
                and not template.value.lower().endswith(_AUTOESCAPED_TEMPLATE_SUFFIXES)
            ):
                return "text"
        return "safe"

    def _is_django_template(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True when ``expr`` is, directly or through a binding, a Django
        template object, whose ``render`` autoescapes: the result of
        ``django.template.loader.get_template``/``select_template``, a
        ``django.template.Template(...)``, or ``engines[...]`` (Django's
        Jinja2 backend autoescapes too) or its ``from_string``/``get_template``
        result. Each name must resolve through the file's imports; a raw
        ``jinja2.Template`` or ``Environment`` is not one."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Name):
            bound = self._scope_binding(expr.id)
            return bound is not None and self._is_django_template(bound, _depth + 1)
        if isinstance(expr, ast.Subscript):
            return self._import_origin(expr.value) == "django.template.engines"
        if isinstance(expr, ast.Call):
            func = expr.func
            if self._import_origin(func) in _DJANGO_TEMPLATE_FACTORIES:
                return True
            return (
                isinstance(func, ast.Attribute)
                and func.attr in ("from_string", "get_template")
                and self._is_django_template(func.value, _depth + 1)
            )
        return False

    def _is_non_text_call(self, call: ast.Call) -> bool:
        """True for a call whose result holds no text from its argument: the
        builtins in `_NON_TEXT_FUNCS` (by bare name), and the value parsers in
        `_NON_TEXT_CALLS` (``UUID``, ``Decimal``, ``Fraction``, ``date``/
        ``datetime``/``time`` ``.fromisoformat``/``.strptime``), each resolved
        through the file's imports."""
        func = call.func
        if isinstance(func, ast.Name) and func.id in _NON_TEXT_FUNCS:
            return True
        return self._import_origin(func) in _NON_TEXT_CALLS

    def _request_get_value_type(self, call: ast.Call) -> ast.AST | None:
        """The ``type`` of a ``request.<data>.get(key, default, type)`` call
        (keyword or third positional argument) when it converts the value to
        one that holds no text: a builtin in `_NON_TEXT_FUNCS` (``int``,
        ``float``, ``bool``) or a value parser in `_NON_TEXT_CALLS`
        (``uuid.UUID``). Werkzeug's MultiDict returns the converted value."""
        func = call.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and _dotted(func).partition(".")[0] in _REQUEST_NAMES
        ):
            return None
        conv = next((kw.value for kw in call.keywords if kw.arg == "type"), None)
        if conv is None and len(call.args) > 2:
            conv = call.args[2]
        if conv is None:
            return None
        if isinstance(conv, ast.Name) and conv.id in _NON_TEXT_FUNCS:
            return conv
        return conv if self._import_origin(conv) in _NON_TEXT_CALLS else None

    def _is_request_rooted(
        self, expr: ast.AST, _seen: frozenset[str] = frozenset(), _depth: int = 0
    ) -> bool:
        """True when ``expr`` is read off the request: its receiver spine
        (attribute and subscript reads, method calls, ``await``) ends at a
        request name (`_REQUEST_NAMES`) or at a route handler's request
        parameter, directly or through the names it is bound to. Call
        arguments are not followed: ``storage.download(request.args["p"])`` is
        a helper's result, not request data."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        while True:
            if isinstance(expr, (ast.Attribute, ast.Subscript, ast.Await)):
                expr = expr.value
            elif isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
                expr = expr.func.value
            else:
                break
        if not isinstance(expr, ast.Name):
            return False
        if expr.id in _REQUEST_NAMES or self._name_is_route_param_source(expr.id):
            return True
        if expr.id in _seen:
            return False
        bound = self._scope_binding(expr.id)
        return bound is not None and self._is_request_rooted(
            bound, _seen | {expr.id}, _depth + 1
        )

    def _is_known_str(
        self, expr: ast.AST, _seen: frozenset[str] = frozenset(), _depth: int = 0
    ) -> bool:
        """True when ``expr`` is known to be a ``str``: a str literal, an
        f-string, ``str()``/``repr()``, the result of a str method that
        returns a str (`_STR_RESULT_METHODS`), a query or form value read off
        the request (``request.args``/``.form``/``.values``/``.GET``/``.POST``,
        by ``.get(...)`` or subscript; not files, JSON or the raw body), a
        route parameter that is a str (`_is_str_route_param`), or a name every
        plain assignment of which is one of these."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Constant):
            return isinstance(expr.value, str)
        if isinstance(expr, ast.JoinedStr):
            return True
        if isinstance(expr, ast.Subscript):
            return _is_request_query_mapping(expr.value)
        if isinstance(expr, ast.Call):
            func = expr.func
            if isinstance(func, ast.Name):
                return func.id in ("str", "repr") and func.id not in self._file_defined_names()
            if isinstance(func, ast.Attribute):
                if func.attr in _STR_RESULT_METHODS:
                    return True
                return (
                    func.attr == "get"
                    and _is_request_query_mapping(func.value)
                    and self._request_get_value_type(expr) is None
                )
            return False
        if not isinstance(expr, ast.Name):
            return False
        if self._is_str_route_param(expr.id):
            return True
        if expr.id in _seen:
            return False
        values = self._name_binding_values(expr.id)
        if values is None:
            return False
        if not values:
            bound = self._scope_binding(expr.id)
            values = [bound] if bound is not None else []
        return bool(values) and all(
            self._is_known_str(v, _seen | {expr.id}, _depth + 1) for v in values
        )

    def _is_str_route_param(self, name: str) -> bool:
        """True when ``name`` is a request parameter of the route handler
        being visited that arrives as a ``str``: a Flask or Django URL
        variable (their int, float and UUID converters are not sources), or a
        FastAPI parameter annotated ``str`` (bare, ``Optional``,
        ``X | None`` or ``Annotated``)."""
        if not self._name_is_route_param_source(name):
            return False
        route = self._bound_route()
        if getattr(route, "framework", "") in ("flask", "django"):
            return True
        func = self._func_stack[-1]
        params = [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
        arg = next((a for a in params if a.arg == name), None)
        types = _unwrap_annotation(arg.annotation)[0] if arg is not None else []
        return bool(types) and all(isinstance(t, ast.Name) and t.id == "str" for t in types)

    def _html_body_carries_text(
        self,
        expr: ast.AST,
        sink_line: int,
        whole: bool = True,
        _seen: frozenset[str] = frozenset(),
        _depth: int = 0,
    ) -> bool:
        """True when some part of a response body can hold text from outside
        the code verbatim: a parameter, a request read, or a value derived from
        one.

        False for constants, parts `_arg_is_sanitised` accepts (escaped,
        allowlisted, membership-guarded), `_renderer_verdict`'s safe renderers,
        `_is_non_text_call`, and, when it is the WHOLE body (``whole``), the
        result of a helper function or ``self``/``cls`` method (R-pf41). The
        engine cannot see what a function returns, and a function whose result
        is the whole page is a renderer: `HTMLResponse(content=
        email_data.html_content)` with `email_data =
        generate_reset_password_email(email=email)` renders a template. The
        whole body is followed through bindings, attribute and subscript
        reads, conditionals, the text methods of a value (`_TEXT_METHODS`) and
        `_TEXT_PASSTHROUGH_FUNCS`. Any other method on a value, as the whole
        body, is a helper too (`app.send_static_file(name)`).

        Inside an interpolated part (an f-string value, a ``+`` or ``%``
        operand, a ``.format``/``.join`` argument, a collection element) any
        call carries its arguments' text, as does a class constructor
        (``NameForm(request.POST)``) anywhere. A shape this does not model
        counts as carrying text."""
        if _depth >= _MAX_TAINT_HOPS:
            return True

        def same(sub: ast.AST) -> bool:
            return self._html_body_carries_text(sub, sink_line, whole, _seen, _depth + 1)

        def part(sub: ast.AST) -> bool:
            return self._html_body_carries_text(sub, sink_line, False, _seen, _depth + 1)

        if isinstance(expr, ast.Constant):
            return False
        # A comparison or a `not` is a bool.
        if isinstance(expr, ast.Compare) or (
            isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not)
        ):
            return False
        if isinstance(expr, ast.JoinedStr):
            return any(part(v.value) for v in expr.values if isinstance(v, ast.FormattedValue))
        if isinstance(expr, ast.BinOp):
            return part(expr.left) or part(expr.right)
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            return any(part(e) for e in expr.elts)
        if isinstance(expr, ast.Dict):
            return any(part(e) for e in (*expr.keys, *expr.values) if e is not None)
        if isinstance(expr, ast.IfExp):
            return same(expr.body) or same(expr.orelse)
        if isinstance(expr, ast.BoolOp):
            return any(same(v) for v in expr.values)
        if isinstance(expr, ast.Starred):
            return part(expr.value)
        if self._arg_is_sanitised(expr, sink_line):
            return False
        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript)):
            key = expr.id if isinstance(expr, ast.Name) else _binding_key(expr)
            if key is not None:
                if key in _seen:
                    # A rebinding that reads its own name (`html += ...` with
                    # no earlier value, `x = x.strip()`): the earlier value is
                    # out of sight.
                    return True
                bound = self._scope_binding(key)
                if bound is not None:
                    return self._html_body_carries_text(
                        bound, sink_line, whole, _seen | {key}, _depth + 1
                    )
            if isinstance(expr, ast.Name):
                return True  # a parameter or a global: whatever was passed in
            return same(expr.value)
        if isinstance(expr, ast.Call):
            built = self._template_construction(expr)
            if built is not None and built[1] is not None:
                # A template object built from a string. Its source is the
                # template-injection rule's (PY_SSTI, Task 3.4); the page it
                # renders carries what its `.render(...)` is passed. One with
                # no source argument (`Template(*args)`, Mako's
                # `Template(filename=...)`) is read like any other call.
                return False
            verdict = self._renderer_verdict(expr)
            if verdict == "safe":
                return False
            func = expr.func
            name = _terminal_name(func)
            args = [*expr.args, *(kw.value for kw in expr.keywords)]
            if verdict == "text":
                return any(part(a) for a in args)
            if (
                isinstance(func, ast.Attribute)
                and not self._import_origin(func.value)
                and (
                    func.attr in _BOOL_STR_METHODS
                    or (func.attr in _STR_INDEX_METHODS and self._is_known_str(func.value))
                )
            ):
                # q.isdigit(), x.startswith("a"); q.count("a") and q.find(":")
                # only on a str: an XML element's or a soup's find() is markup.
                return False
            typed = self._request_get_value_type(expr)
            if typed is not None:
                # request.args.get("page", 1, type=int): Werkzeug returns the
                # converted value, or the default when conversion fails.
                default = next((kw.value for kw in expr.keywords if kw.arg == "default"), None)
                if default is None and len(expr.args) > 1:
                    default = expr.args[1]
                return default is not None and part(default)
            if _dotted(func).partition(".")[0] in _REQUEST_NAMES:
                return True  # request.GET.get(...), request.get_json()
            if self._is_non_text_call(expr):
                return False
            if (
                isinstance(func, ast.Attribute)
                and not self._import_origin(func.value)
                and _dotted(func.value) not in _OWN_RECEIVERS
            ):
                # A method on a value ("<p>{}</p>".format(x), ", ".join(xs),
                # x.strip(), data.get("k")): its text is the receiver's and the
                # arguments'. `self.helper(...)` is a helper function instead,
                # and so, as the whole body, is a method that is not one of
                # `_TEXT_METHODS`: `app.send_static_file(name)` and
                # `storage.download(path)` return a response (R-pf41). A method
                # on the request's own data is not a helper:
                # `request.FILES["f"].read()` is the uploaded bytes.
                if (
                    whole
                    and func.attr not in _TEXT_METHODS
                    and not self._is_request_rooted(func.value)
                ):
                    return False
                return same(func.value) or any(part(a) for a in args)
            if name in _TEXT_PASSTHROUGH_FUNCS:
                return any(same(a) for a in (args[1:] if name == "map" else args))
            if not whole or name[:1].isupper():
                return any(part(a) for a in args)
            return False
        return True

    # ─── Server-side template injection (Task 3.4) ─────────────────────

    def _ssti_template_arg(self, node: ast.Call) -> ast.AST | None:
        """The template source of ``node`` when it compiles a template from a
        string (`_template_construction`) and that string may be the
        request's: not constant and not otherwise trusted
        (`_template_source_is_trusted`). None for any other call."""
        sink = self._ssti_sink(node)
        return None if sink is None else sink[1]

    def _ssti_sink(self, node: ast.Call) -> tuple[str, ast.AST] | None:
        """``(sink name, template source)`` for `_ssti_template_arg`, from a
        single `_template_construction` of ``node``."""
        built = self._template_construction(node)
        if built is None or built[1] is None:
            return None
        name, source = built
        if self._template_source_is_trusted(source, node.lineno):
            return None
        return name, source

    def _template_construction(self, node: ast.Call) -> tuple[str, ast.AST | None] | None:
        """``(sink name, source argument)`` when ``node`` compiles a template
        from a string, else None. The source is the first positional argument
        or the constructor's own keyword for it (``source=``,
        ``template_string=``, ``text=``, ``template_code=``); None when the
        call passes neither, as Mako's ``Template(filename=...)`` does.

        - ``jinja2.Template``, ``django.template.Template`` and
          ``mako.template.Template`` (`_TEMPLATE_CONSTRUCTORS`), the callee
          resolved through the file's imports (`_callee_origin`): a class the
          file defines, or one imported from anywhere else
          (``from .templating import Template``, ``string.Template``), is
          not one.
        - ``<env>.from_string(...)`` on a Jinja2 environment or a Django
          ``engines[...]`` backend (`_template_environment`).

        Loading a template by name (``get_template``, ``render_template``,
        ``TemplateLookup``) compiles the developer's file, so it is not one."""
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "from_string":
            env = self._template_environment(func.value)
            if not env:
                return None
            keyword = "template_code" if env == _DJANGO_ENGINES else "source"
            return f"{env}.from_string", _source_argument(node, keyword)
        if not isinstance(func, (ast.Name, ast.Attribute)):
            return None
        known = _TEMPLATE_CONSTRUCTORS.get(self._callee_origin(func))
        if known is None:
            return None
        name, keyword = known
        return name, _source_argument(node, keyword)

    def _callee_origin(self, func: ast.AST) -> str:
        """`_import_origin` of a callee, or "" for a bare name the file binds
        with ``def`` or ``class`` itself."""
        if isinstance(func, ast.Name) and func.id in self._file_defined_names():
            return ""
        return self._import_origin(func)

    def _template_environment(
        self, expr: ast.AST, _seen: frozenset[str] = frozenset(), _depth: int = 0
    ) -> str:
        """The name of the template environment ``expr`` is, directly or
        through the names it is bound to, or "": a Jinja2 ``Environment`` or
        one of its subclasses built by a call (`_TEMPLATE_ENVIRONMENTS`), or a
        Django ``engines[...]`` backend."""
        if _depth >= _MAX_TAINT_HOPS:
            return ""
        if isinstance(expr, ast.Name):
            if expr.id in _seen:
                return ""
            bound = self._scope_binding(expr.id)
            if bound is None:
                return ""
            return self._template_environment(bound, _seen | {expr.id}, _depth + 1)
        if isinstance(expr, ast.Subscript):
            return _DJANGO_ENGINES if self._import_origin(expr.value) == _DJANGO_ENGINES else ""
        if isinstance(expr, ast.Call):
            return _TEMPLATE_ENVIRONMENTS.get(self._callee_origin(expr.func), "")
        return ""

    def _template_source_is_trusted(
        self,
        expr: ast.AST,
        sink_line: int,
        _seen: frozenset[str] = frozenset(),
        _depth: int = 0,
    ) -> bool:
        """True when the template source ``expr`` cannot be text the request
        chose:

        - a constant (`_expr_folds_to_constant`): a literal, a name bound to
          one, or a concatenation, format, f-string or conditional of
          constants;
        - one of a literal collection of constant templates, picked by key
          (`_picks_constant_template`);
        - a name a dominating guard keeps inside a literal collection
          (`_name_is_membership_guarded`);
        - a file's or a package resource's content (`_is_file_read`);

        or a conditional, or a name bound to a value, that is one of these.
        Escaping is not a sanitiser here: ``html.escape`` leaves ``{{ }}``
        intact."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if (
            self._expr_folds_to_constant(expr)
            or self._picks_constant_template(expr)
            or self._is_file_read(expr)
        ):
            return True
        if isinstance(expr, ast.IfExp):
            return all(
                self._template_source_is_trusted(b, sink_line, _seen, _depth + 1)
                for b in (expr.body, expr.orelse)
            )
        if isinstance(expr, ast.Name) and expr.id not in _seen:
            if self._name_is_membership_guarded(expr.id, sink_line):
                return True
            bound = self._scope_binding(expr.id)
            return bound is not None and self._template_source_is_trusted(
                bound, sink_line, _seen | {expr.id}, _depth + 1
            )
        return False

    def _picks_constant_template(self, expr: ast.AST) -> bool:
        """True for ``<name>[key]`` or ``<name>.get(key[, default])`` where
        ``name`` is bound to a literal dict (or, by index, a list or tuple)
        whose every value is a constant, and so is the default: whatever the
        key, the result is one of the developer's templates."""
        default = None
        if isinstance(expr, ast.Subscript):
            holder = expr.value
        elif (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "get"
            and not expr.keywords
        ):
            holder = expr.func.value
            default = expr.args[1] if len(expr.args) > 1 else None
        else:
            return False
        if not isinstance(holder, ast.Name) or self._collection_is_mutated(holder.id):
            return False
        collection = self._scope_binding(holder.id)
        if isinstance(collection, ast.Dict) and None not in collection.keys:
            values = collection.values
        elif isinstance(collection, (ast.List, ast.Tuple)) and isinstance(expr, ast.Subscript):
            values = collection.elts
        else:
            return False
        return all(self._expr_folds_to_constant(v) for v in values) and (
            default is None or self._expr_folds_to_constant(default)
        )

    def _collection_is_mutated(self, name: str) -> bool:
        """True when the file changes the collection ``name`` in place
        anywhere: an item assignment or deletion (``name[k] = v``,
        ``name[k] += v``, ``del name[k]``) or a mutating method call
        (``name.update(...)``, ``.setdefault``, ``.append``, ...). A literal
        dict of constant templates then no longer holds only constants."""
        root = self._module_root
        if root is None:
            return False
        for n in ast.walk(root):
            if (
                isinstance(n, ast.Subscript)
                and isinstance(n.ctx, (ast.Store, ast.Del))
                and isinstance(n.value, ast.Name)
                and n.value.id == name
            ):
                return True
            if (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in _MUTATING_METHODS
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == name
            ):
                return True
        return False

    def _is_file_read(self, expr: ast.AST) -> bool:
        """True for a template read from the file system: ``.read()``,
        ``.read_text()`` or ``.read_bytes()`` (awaited or ``.decode()``d too)
        on a file-system handle (`_is_file_system_handle`), or a package
        resource read by a constant name (``pkgutil.get_data(pkg, "t.html")``,
        ``importlib.resources.read_text``). Which file is read is the
        path-traversal rule's concern; a resource name the request chooses is
        not trusted, since no rule reports it. Any other read (``urlopen``, a
        ``requests`` response, a zip archive, ``io.StringIO``) can return the
        request's text and is not trusted."""
        if isinstance(expr, ast.Await):
            expr = expr.value
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if isinstance(func, ast.Attribute):
            if func.attr == "decode":
                return self._is_file_read(func.value)
            if func.attr in _FILE_READ_METHODS and self._is_file_system_handle(func.value):
                return True
        if self._callee_origin(func) in _RESOURCE_READ_CALLS:
            return all(self._expr_folds_to_constant(a) for a in expr.args[1:]) and all(
                self._expr_folds_to_constant(kw.value)
                for kw in expr.keywords
                if kw.arg not in ("encoding", "errors")
            )
        return False

    def _is_file_system_handle(
        self, expr: ast.AST, _seen: frozenset[str] = frozenset(), _depth: int = 0
    ) -> bool:
        """True when ``expr`` is a file opened from, or a path on, the file
        system: a builtin ``open(...)``, ``io.open(...)`` or
        ``codecs.open(...)``; a pathlib path (`_is_pathlib_ctor_call`, ``/``,
        ``.parent``, ``.joinpath()`` and the other path-deriving methods); an
        ``importlib.resources.files(...)`` traversable; or a name bound to one
        of these (``with open(path) as fh``)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Name):
            if expr.id in _seen:
                return False
            bound = self._scope_binding(expr.id)
            return bound is not None and self._is_file_system_handle(
                bound, _seen | {expr.id}, _depth + 1
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return not self._is_request_segment(expr.right) and self._is_file_system_handle(
                expr.left, _seen, _depth + 1
            )
        if isinstance(expr, ast.Attribute) and expr.attr in _PATH_DERIVING_ATTRS:
            return self._is_file_system_handle(expr.value, _seen, _depth + 1)
        if not isinstance(expr, ast.Call):
            return False
        func = expr.func
        if self._is_builtin_open(func) or self._is_pathlib_ctor_call(expr):
            return True
        segments = [*expr.args, *(kw.value for kw in expr.keywords)]
        if isinstance(func, ast.Attribute) and func.attr in _PATH_DERIVING_METHODS:
            return not any(
                self._is_request_segment(seg) for seg in segments
            ) and self._is_file_system_handle(func.value, _seen, _depth + 1)
        origin = self._callee_origin(func)
        if origin in _RESOURCE_FILES_CALLS:
            return not any(self._is_request_segment(seg) for seg in segments)
        return origin in _FILE_OPEN_CALLS

    def _is_request_segment(self, segment: ast.AST) -> bool:
        """True when a segment a path derivation adds (``base / segment``,
        ``.joinpath(segment)``, ``.with_name(segment)``, the package of
        ``importlib.resources.files(segment)``) is proven request input
        (`_collect_taint_chain`). PY_PATH_TRAVERSAL models ``open(...)`` and
        ``Path(...)`` but not these joins, so a request-chosen segment makes
        the read the request's (R-pf48). A segment that is only a parameter no
        caller is proven to fill, as in the full-stack-fastapi-template email
        renderer, keeps the read trusted."""
        if isinstance(segment, ast.Constant):
            return False
        line = getattr(segment, "lineno", 0)
        return bool(self._collect_taint_chain(segment, line, _ast_expr_text(segment)))

    def _is_builtin_open(self, func: ast.AST) -> bool:
        """True for a bare ``open`` that is the builtin: not imported, not
        defined in the file and not bound in scope."""
        return (
            isinstance(func, ast.Name)
            and func.id == "open"
            and func.id not in self._from_imports
            and func.id not in self._module_aliases
            and func.id not in self._file_defined_names()
            and self._scope_binding(func.id) is None
        )

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
          - FileResponse(x) / FileResponse(path=x) — Starlette and FastAPI
            open and send the file at `x` (Task 3.6), resolved through the
            file's imports (`_is_file_response`). Given an `open(...)` call
            instead, the open() is the sink.

        A constant string arg is safe — `open("config.yaml")` is fine.
        Variable args (Name, Call, BinOp, JoinedStr) are the dangerous
        case; `_collect_taint_chain` decides whether the variable
        actually traces back to a request source.
        """
        sink_name = self._path_traversal_sink_name(node)
        if not sink_name:
            return False
        # A join resolved in place and checked by a containment guard before
        # any use is safe; the guard sits below the join's line, so it could
        # never dominate the join itself (`_resolved_join_is_guarded`).
        if sink_name == "os.path.join" and self._resolved_join_is_guarded(node):
            return False
        target = self._path_traversal_target(node)
        if target is None:
            return False
        # `FileResponse(open(path, "rb"))`: the inner open() is the sink and
        # reports the flow once.
        if (
            sink_name == "FileResponse"
            and isinstance(target, ast.Call)
            and _terminal_name(target.func) == "open"
        ):
            return False
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
        `os.path.abspath(x)`, `os.path.expanduser(x)`). `FileResponse` counts
        only when it resolves to Starlette's or FastAPI's
        (`_is_file_response`), under any alias.
        """
        if self._is_file_response(node.func):
            return "FileResponse"
        if isinstance(node.func, ast.Name):
            if node.func.id == "FileResponse":
                # Django's, a project's own, or one the file never imports.
                return ""
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

    def _path_traversal_target(self, node: ast.Call) -> ast.AST | None:
        """The path argument of a path-traversal sink: the positional argument
        at `_path_traversal_arg_index`, else, for `FileResponse`, its
        ``path=`` keyword; None when the call passes neither."""
        arg_idx = self._path_traversal_arg_index(node)
        if arg_idx < len(node.args):
            return node.args[arg_idx]
        if self._path_traversal_sink_name(node) == "FileResponse":
            return next((kw.value for kw in node.keywords if kw.arg == "path"), None)
        return None

    def _is_file_response(self, func: ast.AST) -> bool:
        """True when ``func`` is Starlette's or FastAPI's ``FileResponse``,
        through the file's imports: imported from ``starlette`` or
        ``fastapi`` (``from fastapi.responses import FileResponse as F``),
        or reached through such a module (``responses.FileResponse``). A name
        the file defines itself, one imported from elsewhere (Django's
        ``django.http.FileResponse``, a project's own class) and one the file
        never imports are not."""
        if isinstance(func, ast.Name):
            if func.id in self._file_defined_names():
                return False
            module, name = self._from_imports.get(func.id, ("", ""))
        elif isinstance(func, ast.Attribute):
            module, name = self._import_origin(func.value), func.attr
        else:
            return False
        return name == "FileResponse" and module.split(".")[0] in _FILE_RESPONSE_PACKAGES


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


# What both PY_XSS_HTML_SINK branches report: the Markup/mark_safe/
# render_template_string sinks and the HTML response constructors.
_XSS_HTML_SINK_TITLE = "Reflected XSS — user input passed to HTML render sink"
_XSS_HTML_SINK_SEVERITY = "HIGH"
_XSS_HTML_SINK_CONFIDENCE = "MEDIUM"
_XSS_HTML_SINK_CWE = "CWE-79"

_XSS_HTML_SINK_NAMES: frozenset[str] = frozenset(
    {
        "Markup",
        "mark_safe",
        "render_template_string",
    }
)


# HTML response constructors recognised by `_is_html_response_sink` (Task 3.2),
# each with the framework packages it must be imported from when the file
# imports it: Django `HttpResponse`, Flask `make_response`, Starlette and
# FastAPI `HTMLResponse`, and the Flask/Werkzeug and Starlette/FastAPI
# `Response`. Each sends its body to the browser, which renders it as HTML
# unless the response declares another content type. A `Response` must be
# imported, which keeps DRF's JSON `Response` and a project's own class out.
_HTML_RESPONSE_CTORS: frozenset[str] = frozenset(
    {"HttpResponse", "make_response", "Response", "HTMLResponse"}
)
_HTML_RESPONSE_PACKAGES: dict[str, frozenset[str]] = {
    "HttpResponse": frozenset({"django"}),
    "make_response": frozenset({"flask"}),
    "HTMLResponse": frozenset({"starlette", "fastapi"}),
    "Response": frozenset({"flask", "werkzeug", "starlette", "fastapi"}),
}
# Redirect constructors recognised by `_redirect_ctor` (Task 3.5), each with
# the framework packages it must be imported from when the file imports it:
# `redirect` from Flask, Werkzeug (where Flask's lives), Quart, Django
# (`django.shortcuts`), Bottle, Sanic, TurboGears (`tg`), Pylons, web.py
# (`web`), Morepath and Emmett; Django `HttpResponseRedirect` and
# `HttpResponsePermanentRedirect`; Starlette/FastAPI `RedirectResponse`. A
# same-named function or class of the project itself is not one.
_REDIRECT_CTOR_PACKAGES: dict[str, frozenset[str]] = {
    "redirect": frozenset(
        {
            "flask", "werkzeug", "quart", "django", "bottle", "sanic",
            "tg", "pylons", "web", "morepath", "emmett",
        }
    ),
    "HttpResponseRedirect": frozenset({"django"}),
    "HttpResponsePermanentRedirect": frozenset({"django"}),
    "RedirectResponse": frozenset({"starlette", "fastapi"}),
}
# The keywords a redirect constructor takes its target by (`_redirect_target`).
_REDIRECT_TARGET_KEYWORDS: frozenset[str] = frozenset({"location", "to", "redirect_to", "url"})
# Django response classes, whose headers are also set by item assignment
# (`resp["Location"] = url`).
_DJANGO_RESPONSE_NAMES: frozenset[str] = frozenset(
    {"HttpResponse", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}
)
# PY_OPEN_REDIRECT's presentation, shared by the redirect constructor and the
# Location header forms.
_OPEN_REDIRECT_TITLE = "Potential open redirect — dynamic redirect target"
_OPEN_REDIRECT_PROVEN_TITLE = "Open redirect — user-controlled redirect target"
_OPEN_REDIRECT_SEVERITY = "HIGH"
_OPEN_REDIRECT_CONFIDENCE = "MEDIUM"
_OPEN_REDIRECT_CWE = "CWE-601"
# Where a response constructor takes its body and its content type by keyword:
# `content` (Django, Starlette) or `response` (Flask) for the body;
# `content_type` (Django, Flask), `mimetype` (Flask) or `media_type`
# (Starlette) for the type.
_RESPONSE_BODY_KEYWORDS: tuple[str, ...] = ("content", "response")
_RESPONSE_CONTENT_TYPE_KEYWORDS: frozenset[str] = frozenset(
    {"content_type", "mimetype", "media_type"}
)
# Attributes a built response's content type is assigned through:
# `resp.mimetype` / `resp.content_type` (Flask), `resp.media_type` (Starlette).
_RESPONSE_CONTENT_TYPE_ATTRS: frozenset[str] = _RESPONSE_CONTENT_TYPE_KEYWORDS
# Statuses whose body the browser never renders: 204 No Content and 304 Not
# Modified (Werkzeug drops the body of both).
_BODYLESS_STATUSES: frozenset[int] = frozenset({204, 304})
# Redirect statuses whose body the browser does not render when the response
# carries a Location header: it follows the redirect instead.
_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
# Modules whose constants name HTTP statuses (`_is_redirect_status_constant`).
_STATUS_MODULES: frozenset[str] = frozenset(
    {"http.HTTPStatus", "http.client", "starlette.status", "fastapi.status", "rest_framework.status"}
)
_REDIRECT_STATUS_NAME = re.compile(
    r"HTTP_30[12378]_[A-Z_]+|MOVED_PERMANENTLY|FOUND|SEE_OTHER|TEMPORARY_REDIRECT|PERMANENT_REDIRECT"
)
# A declared media type containing one of these is rendered as a document that
# can run script: text/html, application/xhtml+xml, image/svg+xml, text/xml.
_MARKUP_MEDIA_TYPE_MARKERS: tuple[str, ...] = ("html", "xml")
# Renderers whose result is safe as a response body, each with the package it
# must be imported from (R-pf40): Django `render` and `render_to_string`
# (autoescaped templates), Flask `render_template` (autoescaped for the
# template names in _AUTOESCAPED_TEMPLATE_SUFFIXES, or a non-constant name) and
# Flask `jsonify` (JSON). A `<template>.render(...)` method is not one: Jinja2's
# `Template` and `Environment.from_string` do not autoescape by default.
_HTML_RESPONSE_SAFE_BODIES: dict[str, frozenset[str]] = {
    "render": frozenset({"django"}),
    "render_to_string": frozenset({"django"}),
    "render_template": frozenset({"flask"}),
    "jsonify": frozenset({"flask"}),
}
_AUTOESCAPED_TEMPLATE_SUFFIXES: tuple[str, ...] = (".html", ".htm", ".xml", ".xhtml", ".svg")
# Functions that hand their argument's text to their result unchanged, so
# request text in the argument is request text in a response body:
# `json.dumps` (it does not escape `<`; R-pf38), `json.loads`,
# `textwrap.dedent`, `urllib.parse.unquote`/`unquote_plus`, `html.unescape`,
# and `map` over its iterable.
_TEXT_PASSTHROUGH_FUNCS: frozenset[str] = frozenset(
    {
        "str",
        "repr",
        "format",
        "dumps",
        "loads",
        "dedent",
        "unquote",
        "unquote_plus",
        "unescape",
        "map",
    }
)
# Methods whose result is text from their receiver or arguments, so a whole
# response body (or returned value) built by one carries that text: str's own
# methods (and bytes' `decode`), a mapping's `get`/`pop`, and a raw template's
# `render` (Jinja2, Mako; R-pf40) or `substitute`. Any other method called as
# the whole body is a helper whose result the engine cannot see (R-pf41).
_TEXT_METHODS: frozenset[str] = frozenset(
    {
        "capitalize", "casefold", "center", "decode", "encode", "expandtabs",
        "format", "format_map", "get", "join", "ljust", "lower", "lstrip",
        "partition", "pop", "removeprefix", "removesuffix", "render",
        "render_unicode", "replace", "rjust", "rpartition", "rsplit", "rstrip",
        "safe_substitute", "split", "splitlines", "strip", "substitute",
        "swapcase", "title", "translate", "upper", "zfill",
    }
)
# str methods that return a list, which Flask sends as JSON.
_STR_LIST_METHODS: frozenset[str] = frozenset({"split", "rsplit", "splitlines"})
# str tests whose result is a bool, so it holds no text whatever the receiver.
_BOOL_STR_METHODS: frozenset[str] = frozenset(
    {
        "endswith", "isalnum", "isalpha", "isascii", "isdecimal", "isdigit",
        "isidentifier", "islower", "isnumeric", "isprintable", "isspace",
        "istitle", "isupper", "startswith",
    }
)
# str methods that return a number, but only on a str (`_is_known_str`): an
# XML element's or a BeautifulSoup tree's find() returns markup.
_STR_INDEX_METHODS: frozenset[str] = frozenset({"count", "find", "index", "rfind", "rindex"})
# str methods whose result is a str.
_STR_RESULT_METHODS: frozenset[str] = frozenset(
    {
        "capitalize", "casefold", "center", "decode", "expandtabs", "format",
        "format_map", "join", "ljust", "lower", "lstrip", "removeprefix",
        "removesuffix", "replace", "rjust", "rstrip", "safe_substitute", "strip",
        "substitute", "swapcase", "title", "translate", "upper", "zfill",
    }
)
# Request mappings whose values are query or form strings.
_REQUEST_QUERY_MAPPINGS: frozenset[str] = frozenset({"args", "form", "values", "GET", "POST"})
# Calls whose result holds no text from their argument: builtins (by bare
# name) and value parsers (by import path).
_NON_TEXT_FUNCS: frozenset[str] = frozenset(
    {"int", "float", "bool", "len", "round", "abs"}
)
_NON_TEXT_CALLS: frozenset[str] = frozenset(
    {
        "decimal.Decimal",
        "uuid.UUID",
        "fractions.Fraction",
        "datetime.date.fromisoformat",
        "datetime.datetime.fromisoformat",
        "datetime.time.fromisoformat",
        "datetime.datetime.strptime",
        "datetime.date.strptime",
        "datetime.time.strptime",
    }
)
# Django calls that return a template object whose `.render` autoescapes.
_DJANGO_TEMPLATE_FACTORIES: frozenset[str] = frozenset(
    {
        "django.template.loader.get_template",
        "django.template.loader.select_template",
        "django.template.Template",
        "django.template.base.Template",
    }
)
# Task 3.4: calls that compile a template from a string, by the import path
# they resolve to, each with the name the sink is reported under and the
# keyword its source may be passed by (`_template_construction`). A template
# the attacker writes runs on the server: Jinja2 and Mako evaluate Python
# expressions, and a Django template reads what its context exposes.
_TEMPLATE_CONSTRUCTORS: dict[str, tuple[str, str]] = {
    "jinja2.Template": ("jinja2.Template", "source"),
    "jinja2.environment.Template": ("jinja2.Template", "source"),
    "jinja2.nativetypes.NativeTemplate": ("jinja2.nativetypes.NativeTemplate", "source"),
    "django.template.Template": ("django.template.Template", "template_string"),
    "django.template.base.Template": ("django.template.Template", "template_string"),
    "mako.template.Template": ("mako.template.Template", "text"),
}
# Template environments whose `from_string(source)` compiles a template: a
# Jinja2 `Environment` and its subclasses, a sandboxed one too (the sandbox
# limits what a template can reach; an attacker's template still runs), and
# Django's `engines[...]` backends, whose argument is `template_code`.
_TEMPLATE_ENVIRONMENTS: dict[str, str] = {
    "jinja2.Environment": "jinja2.Environment",
    "jinja2.environment.Environment": "jinja2.Environment",
    "jinja2.sandbox.SandboxedEnvironment": "jinja2.sandbox.SandboxedEnvironment",
    "jinja2.sandbox.ImmutableSandboxedEnvironment": "jinja2.sandbox.ImmutableSandboxedEnvironment",
    "jinja2.nativetypes.NativeEnvironment": "jinja2.nativetypes.NativeEnvironment",
}
_DJANGO_ENGINES = "django.template.engines"
# What reads a template from the file system: a template loaded from a file is
# the developer's, like a template loaded by name (`_is_file_read`). The read
# methods count only on a file-system handle (`_is_file_system_handle`): a
# file opened with `open`, `io.open` or `codecs.open`, a pathlib path, or an
# `importlib.resources.files(...)` traversable.
_FILE_READ_METHODS: frozenset[str] = frozenset({"read", "read_text", "read_bytes"})
_FILE_OPEN_CALLS: frozenset[str] = frozenset({"io.open", "codecs.open"})
_RESOURCE_FILES_CALLS: frozenset[str] = frozenset(
    {"importlib.resources.files", "importlib_resources.files"}
)
# Methods and attributes that derive one path from another.
_PATH_DERIVING_METHODS: frozenset[str] = frozenset(
    {"joinpath", "resolve", "absolute", "expanduser", "with_name", "with_suffix", "with_stem"}
)
_PATH_DERIVING_ATTRS: frozenset[str] = frozenset({"parent"})
# Package-resource readers: trusted only for a constant resource name.
_RESOURCE_READ_CALLS: frozenset[str] = frozenset(
    {
        "pkgutil.get_data",
        "importlib.resources.read_text",
        "importlib.resources.read_binary",
        "importlib_resources.read_text",
        "importlib_resources.read_binary",
    }
)
# Methods that change a dict or list in place (`_collection_is_mutated`).
_MUTATING_METHODS: frozenset[str] = frozenset(
    {"update", "setdefault", "__setitem__", "append", "extend", "insert"}
)
_SSTI_FIX = (
    "Never compile a template from request input. Load templates by name from "
    "a trusted directory (render_template, get_template, a TemplateLookup) and "
    "pass request values only as render variables. A SandboxedEnvironment "
    "limits what a template can reach but does not make an attacker's "
    "template safe."
)
# A response's content type or status assigned in a branch that may not run
# (`_late_assignment`): unknown, so HTML, or a status that may redirect.
_UNKNOWN_LATE_VALUE: ast.AST = ast.Name(id="<set in a branch>")
# Statements through which a built response may leave the function.
_LEAVING_NODES = (ast.Return, ast.Yield, ast.YieldFrom)
# Receivers whose methods are the class's own helpers, not operations on a
# value: `self.render_page(name)` is opaque like `render_page(name)`.
_OWN_RECEIVERS: frozenset[str] = frozenset({"self", "cls"})
# Flask's request data that is a dict (or reads into one) as a whole, which
# Flask's make_response sends as JSON (`_flask_body_is_not_text`):
# `request.args`, `.form`, `.values`, `.files` and `.cookies` (MultiDicts),
# `request.headers`, the parsed `request.json`, and `request.get_json()`; and
# the methods that turn one into a dict or list.
_FLASK_REQUEST_MAPPINGS: frozenset[str] = frozenset(
    {"args", "form", "values", "files", "cookies", "headers", "json"}
)
_FLASK_MAPPING_METHODS: frozenset[str] = frozenset({"to_dict", "getlist"})


def _is_request_query_mapping(expr: ast.AST) -> bool:
    """True for ``request.args``/``.form``/``.values``/``.GET``/``.POST``,
    whose values are strings."""
    return (
        isinstance(expr, ast.Attribute)
        and expr.attr in _REQUEST_QUERY_MAPPINGS
        and isinstance(expr.value, ast.Name)
        and expr.value.id in _REQUEST_NAMES
    )


def _is_flask_request_mapping(expr: ast.AST) -> bool:
    """True for ``request.args``/``.form``/``.values``/``.files``/
    ``.cookies``/``.headers``/``.json`` and ``request.get_json(...)``, read as
    a whole (`_FLASK_REQUEST_MAPPINGS`)."""
    if isinstance(expr, ast.Call):
        func = expr.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "get_json"
            and isinstance(func.value, ast.Name)
            and func.value.id in _REQUEST_NAMES
        )
    return (
        isinstance(expr, ast.Attribute)
        and expr.attr in _FLASK_REQUEST_MAPPINGS
        and isinstance(expr.value, ast.Name)
        and expr.value.id in _REQUEST_NAMES
    )


def _header_content_types(headers: ast.AST) -> list[ast.AST]:
    """The values of the ``Content-Type`` entries (any case) in a literal
    headers dict or list/tuple of ``(name, value)`` pairs."""
    return _header_values(headers, "content-type")


def _header_values(headers: ast.AST, name: str) -> list[ast.AST]:
    """The values of the ``name`` entries (``name`` lower case, matched in
    any case) in a literal headers dict or list/tuple of ``(name, value)``
    pairs."""
    if isinstance(headers, ast.Dict):
        pairs = list(zip(headers.keys, headers.values))
    elif isinstance(headers, (ast.List, ast.Tuple)):
        pairs = [
            (e.elts[0], e.elts[1])
            for e in headers.elts
            if isinstance(e, (ast.Tuple, ast.List)) and len(e.elts) == 2
        ]
    else:
        return []
    return [
        value
        for key, value in pairs
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value.lower() == name
    ]


def _walk_own_scope(node: ast.AST):
    """``node`` and every node under it, without entering a nested function,
    lambda, class or comprehension."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(
            child
            for child in ast.iter_child_nodes(current)
            if not isinstance(child, _SCOPE_NODES)
        )


def _statement_list_holding(scope: ast.AST, stmt: ast.stmt) -> list[ast.stmt] | None:
    """The statement list (a ``body``, ``orelse``, ``finalbody`` or ``handlers``
    body) in ``scope`` that holds ``stmt`` itself."""
    for node in _walk_own_scope(scope):
        for attr in ("body", "orelse", "finalbody"):
            stmts = getattr(node, attr, None)
            if isinstance(stmts, list) and any(s is stmt for s in stmts):
                return stmts
    return None


def _index_of(stmts: list[ast.stmt], stmt: ast.stmt) -> int:
    return next(i for i, s in enumerate(stmts) if s is stmt)


def _rebinds(stmt: ast.stmt, name: str) -> bool:
    """True when ``stmt`` (at any depth in its own scope) binds ``name`` again."""
    for node in _walk_own_scope(stmt):
        if isinstance(node, ast.Name) and node.id == name and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            return True
    return False


def _is_content_type_target(target: ast.AST, name: str) -> bool:
    """True when an assignment target sets the content type of the response
    bound to ``name``: ``name["Content-Type"]``, ``name.headers["Content-Type"]``
    or ``name.mimetype``/``.content_type``/``.media_type``."""
    if isinstance(target, ast.Attribute):
        return (
            isinstance(target.value, ast.Name)
            and target.value.id == name
            and target.attr in _RESPONSE_CONTENT_TYPE_ATTRS
        )
    if isinstance(target, ast.Subscript):
        key = target.slice
        if not (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.lower() == "content-type"
        ):
            return False
        holder = target.value
        if isinstance(holder, ast.Attribute) and holder.attr == "headers":
            holder = holder.value
        return isinstance(holder, ast.Name) and holder.id == name
    return False


def _is_status_target(target: ast.AST, name: str) -> bool:
    """True when an assignment target sets the status of the response bound
    to ``name``: ``name.status_code`` (Django, Flask, Starlette) or
    ``name.status`` (Flask)."""
    return (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == name
        and target.attr in ("status_code", "status")
    )


def _location_assignment_holder(target: ast.AST) -> tuple[str, bool] | None:
    """``(name, via_headers)`` when an assignment target sets the
    ``Location`` header (any case) of the value bound to ``name``:
    ``name.headers["Location"]`` (via_headers) or ``name["Location"]``."""
    if not isinstance(target, ast.Subscript):
        return None
    key = target.slice
    if not (
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value.lower() == "location"
    ):
        return None
    holder = target.value
    via_headers = isinstance(holder, ast.Attribute) and holder.attr == "headers"
    if via_headers:
        holder = holder.value
    return (holder.id, via_headers) if isinstance(holder, ast.Name) else None


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
        # Starlette/FastAPI only, resolved through the imports
        # (`_is_file_response`); Django's takes an open file.
        "FileResponse",
    }
)
# The packages whose `FileResponse(path)` opens the file at `path` (Task 3.6).
_FILE_RESPONSE_PACKAGES: frozenset[str] = frozenset({"starlette", "fastapi"})

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


def _param_position(
    func: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> int | None:
    """Where a call passes `func`'s parameter `name`: its index among the
    positional parameters, -1 for a keyword-only one (after `*`, passed by
    keyword alone), None when `name` is neither (`*args`, `**kwargs`, not a
    parameter)."""
    positional = [a.arg for a in (*func.args.posonlyargs, *func.args.args)]
    if name in positional:
        return positional.index(name)
    if any(a.arg == name for a in func.args.kwonlyargs):
        return -1
    return None


def _call_argument(call: ast.Call, index: int, name: str) -> ast.AST | None:
    """The argument `call` passes for the parameter at positional `index`
    (-1: keyword-only) named `name`: the positional argument at that index as
    written, else the keyword of that name; None when it passes neither. The
    one rule the helper hop matches callers by, in the file and across
    files."""
    if 0 <= index < len(call.args):
        return call.args[index]
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every parameter name of `func`, `*args` and `**kwargs` included."""
    a = func.args
    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    params += [p for p in (a.vararg, a.kwarg) if p is not None]
    return {p.arg for p in params}


# ---------------------------------------------------------------------------
# Route-handler parameters as request sources (Task 3.1)
# ---------------------------------------------------------------------------

# Annotations naming a value the framework injects into a handler (FastAPI and
# Starlette request plumbing, a database session). Never client data.
_INJECTED_PARAM_TYPES: frozenset[str] = frozenset(
    {"Request", "Response", "BackgroundTasks", "WebSocket", "HTTPConnection", "Session"}
)
# Calls marking a FastAPI dependency: the server resolves the value, the client
# does not send it (Review Focus 2). As a default (`user = Depends(f)`) or in
# `Annotated[...]` metadata (ruling R-pf27).
_DEPENDENCY_MARKERS: frozenset[str] = frozenset({"Depends", "Security"})
# Ruling R-pf34: a type imported from a module with one of these path segments
# (`app.api.deps`, `app.dependencies.auth`, `.deps`) is a dependency alias.
_DEPENDENCY_MODULE_SEGMENTS: frozenset[str] = frozenset({"deps", "dependencies"})
# Rulings R-pf33 and R-pf36: types FastAPI and pydantic validate to a value that
# cannot carry free text before the handler runs. The pydantic constrained
# numbers include the float and decimal siblings of the ruled names.
_FIXED_VALUE_TYPES: frozenset[str] = frozenset(
    {
        "int",
        "float",
        "bool",
        "UUID",
        "datetime",
        "date",
        "time",
        "timedelta",
        "Decimal",
        "PositiveInt",
        "NegativeInt",
        "NonNegativeInt",
        "NonPositiveInt",
        "PositiveFloat",
        "NegativeFloat",
        "NonNegativeFloat",
        "NonPositiveFloat",
        "StrictInt",
        "StrictFloat",
        "StrictBool",
    }
)
# R-pf36: pydantic constrained-number factories used as an annotation
# (`n: conint(gt=0)`). `constr(pattern=...)` is a string and stays a source.
_FIXED_VALUE_FACTORIES: frozenset[str] = frozenset({"conint", "confloat", "condecimal"})
# R-pf36: a container of fixed-value types (`list[int]`, `set[UUID]`,
# `tuple[int, ...]`) holds no free text either.
_CONTAINER_TYPES: frozenset[str] = frozenset(
    {"list", "List", "set", "Set", "frozenset", "FrozenSet", "tuple", "Tuple", "Sequence"}
)
# R-pf36: a class with one of these bases is an Enum: FastAPI accepts only its
# members' values.
_ENUM_BASES: frozenset[str] = frozenset({"Enum", "IntEnum", "StrEnum"})
# Ruling R-pf33: Flask (`int`, `float`, `uuid`) and Django (`int`, `uuid`) URL
# converters that coerce the same way, read from the route pattern. Both
# frameworks write a URL variable `<name>` or `<converter:name>`; Flask's
# converter may take arguments (`<int(signed=True):n>`). A Django regex
# group `(?P<name>...)` matches too, as a text variable.
_COERCING_CONVERTERS: frozenset[str] = frozenset({"int", "float", "uuid"})
_URL_VARIABLE = re.compile(
    r"<\s*(?:([A-Za-z_]\w*)\s*(?:\([^)>]*\))?\s*:)?\s*([A-Za-z_]\w*)\s*>"
)
# How deep an annotation is unwrapped (`Optional[Annotated[list[int], ...]]`).
# Real annotations nest a handful of levels; the cap only bounds a crafted one.
_MAX_ANNOTATION_DEPTH = 16


def _terminal_name(node: ast.AST) -> str:
    """`Request` for `Request` and `fastapi.Request`; "" for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _dotted(node: ast.AST) -> str:
    """`a.b.c` for a Name/Attribute chain, else ""."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _is_dependency_call(node: ast.AST | None) -> bool:
    """`Depends(...)` / `Security(...)`, bare or module-qualified."""
    return isinstance(node, ast.Call) and _terminal_name(node.func) in _DEPENDENCY_MARKERS


def _unwrap_annotation(
    ann: ast.AST | None, _depth: int = 0
) -> tuple[list[ast.AST], list[ast.AST]]:
    """`(types, metadata)` of an annotation. `types` are the types it admits,
    with `Optional[...]`, `Union[...]`, `X | None` and the first argument of
    `Annotated[...]` unwrapped and `None` dropped; `metadata` holds the other
    `Annotated` arguments. A string annotation is parsed first. Anything else,
    `list[str]` included, is one type as written."""
    if ann is None or _depth >= _MAX_ANNOTATION_DEPTH:
        return [], []
    if isinstance(ann, ast.Constant):
        if ann.value is None:
            return [], []
        if isinstance(ann.value, str):
            try:
                parsed = ast.parse(ann.value.strip(), mode="eval").body
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return [ann], []
            return _unwrap_annotation(parsed, _depth + 1)
        return [ann], []
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        left_types, left_meta = _unwrap_annotation(ann.left, _depth + 1)
        right_types, right_meta = _unwrap_annotation(ann.right, _depth + 1)
        return left_types + right_types, left_meta + right_meta
    if isinstance(ann, ast.Subscript):
        head = _terminal_name(ann.value)
        args = _subscript_args(ann)
        if head in ("Optional", "Union") and args:
            types: list[ast.AST] = []
            meta: list[ast.AST] = []
            for arg in args if head == "Union" else args[:1]:
                arg_types, arg_meta = _unwrap_annotation(arg, _depth + 1)
                types += arg_types
                meta += arg_meta
            return types, meta
        if head == "Annotated" and args:
            types, meta = _unwrap_annotation(args[0], _depth + 1)
            return types, meta + args[1:]
    return [ann], []


def _subscript_args(node: ast.Subscript) -> list[ast.AST]:
    """The arguments of `X[a, b]` (`[a, b]`) or `X[a]` (`[a]`)."""
    return list(node.slice.elts) if isinstance(node.slice, ast.Tuple) else [node.slice]


def _is_fixed_value_annotation(
    ann: ast.AST | None, enums: frozenset[str], _depth: int = 0
) -> bool:
    """True when every type the annotation admits is a fixed-value type (R-pf33,
    R-pf36): a coerced scalar, a pydantic constrained number, a `Literal[...]`,
    an Enum class of this file, or a container of those."""
    if _depth >= _MAX_ANNOTATION_DEPTH:
        return False
    types = _unwrap_annotation(ann)[0]
    return bool(types) and all(_is_fixed_value_type(t, enums, _depth) for t in types)


def _is_fixed_value_type(t: ast.AST, enums: frozenset[str], _depth: int) -> bool:
    if _terminal_name(t) in _FIXED_VALUE_TYPES:
        return True
    if isinstance(t, ast.Name) and t.id in enums:
        return True
    if isinstance(t, ast.Call):
        return _terminal_name(t.func) in _FIXED_VALUE_FACTORIES
    if isinstance(t, ast.Subscript):
        head = _terminal_name(t.value)
        if head == "Literal":
            return True
        if head in _CONTAINER_TYPES:
            elements = [
                a
                for a in _subscript_args(t)
                if not (isinstance(a, ast.Constant) and a.value is Ellipsis)
            ]
            return bool(elements) and all(
                _is_fixed_value_annotation(a, enums, _depth + 1) for a in elements
            )
    return False


@dataclass(frozen=True)
class _ModuleFacts:
    """What the module around a handler says about its parameters' types.

    - ``enums``: classes of this file whose bases include Enum, IntEnum or
      StrEnum, directly or through another such class (R-pf36).
    - ``dependency_aliases``: module-level names bound in this file to an
      ``Annotated[..., Depends(...)]`` type, directly or through another such
      alias (R-pf27).
    - ``imports``: each name an import binds → the dotted path it imports,
      relative dots dropped (`from .deps import X` → ``deps.X``). It decides
      R-pf34: a type imported from a ``deps``/``dependencies`` module."""

    enums: frozenset[str] = frozenset()
    dependency_aliases: frozenset[str] = frozenset()
    imports: Mapping[str, str] = field(default_factory=dict)


def _module_facts(module: ast.AST | None) -> _ModuleFacts:
    """Collect `_ModuleFacts` from a module's top-level statements (under a
    top-level `if`/`try`/`with` too) and from every import in it."""
    if not isinstance(module, ast.Module):
        return _ModuleFacts()
    imports: dict[str, str] = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    top = alias.name.split(".", 1)[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    base = node.module or ""
                    imports[alias.asname or alias.name] = (
                        f"{base}.{alias.name}" if base else alias.name
                    )
    type_alias = getattr(ast, "TypeAlias", None)  # `type X = ...`, Python 3.12+
    enums: set[str] = set()
    aliases: set[str] = set()
    for stmt in _module_level_statements(module):
        if isinstance(stmt, ast.ClassDef):
            if any(
                _terminal_name(b) in _ENUM_BASES
                or (isinstance(b, ast.Name) and b.id in enums)
                for b in stmt.bases
            ):
                enums.add(stmt.name)
            continue
        target = value = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign):
            target, value = stmt.target, stmt.value
        elif type_alias is not None and isinstance(stmt, type_alias):
            target, value = stmt.name, stmt.value
        if not isinstance(target, ast.Name) or value is None:
            continue
        types, meta = _unwrap_annotation(value)
        if any(_is_dependency_call(m) for m in meta) or _names_any(types, aliases):
            aliases.add(target.id)
    return _ModuleFacts(frozenset(enums), frozenset(aliases), imports)


def _module_level_statements(module: ast.Module):
    """Yield the statements that run in the module's own scope: its body and
    the bodies of top-level `if`/`try`/`with` blocks, never a def or class
    body."""
    stack = list(reversed(module.body))
    while stack:
        stmt = stack.pop()
        yield stmt
        if isinstance(stmt, (ast.If, ast.Try, ast.With, ast.AsyncWith)) or (
            type(stmt).__name__ == "TryStar"
        ):
            blocks = [getattr(stmt, "body", []), getattr(stmt, "orelse", [])]
            blocks += [h.body for h in getattr(stmt, "handlers", [])]
            blocks.append(getattr(stmt, "finalbody", []))
            for block in reversed(blocks):
                stack.extend(reversed(block))


def _names_any(types: list[ast.AST], names: frozenset[str] | set[str]) -> bool:
    """True when one of `types` is a bare Name in `names`."""
    return any(isinstance(t, ast.Name) and t.id in names for t in types)


def _is_dependency_module(path: str) -> bool:
    """True when a dotted path has a `deps` or `dependencies` segment (R-pf34)."""
    return any(seg in _DEPENDENCY_MODULE_SEGMENTS for seg in path.split("."))


def _is_imported_dependency(t: ast.AST, imports: Mapping[str, str]) -> bool:
    """R-pf34: a bare Name imported from a `deps`/`dependencies` module
    (`from app.api.deps import CurrentUser`, `from .deps import X as Y`), or
    `<m>.<Name>` where `<m>` is an imported module with such a segment
    (`from app.api import deps` ... `deps.CurrentUser`)."""
    if isinstance(t, ast.Name):
        target = imports.get(t.id, "")
        return "." in target and _is_dependency_module(target.rpartition(".")[0])
    if isinstance(t, ast.Attribute):
        head, _, rest = _dotted(t.value).partition(".")
        if head not in imports:
            return False
        return _is_dependency_module(imports[head] + (f".{rest}" if rest else ""))
    return False


def _annotation_is_injected(ann: ast.AST | None, facts: _ModuleFacts) -> bool:
    """True when the annotation says the framework, not the client, supplies
    the value: `Annotated[..., Depends(...)]` metadata (R-pf27), an injected
    framework type (`Request`, ...), a same-file dependency alias (R-pf27), or
    a type imported from a `deps`/`dependencies` module (R-pf34)."""
    if ann is None:
        return False
    types, meta = _unwrap_annotation(ann)
    if any(_is_dependency_call(m) for m in meta):
        return True
    names = [_terminal_name(t) for t in types]
    if names and all(n in _INJECTED_PARAM_TYPES for n in names):
        return True
    return _names_any(types, facts.dependency_aliases) or any(
        _is_imported_dependency(t, facts.imports) for t in types
    )


def _signature_sources(
    func: ast.FunctionDef | ast.AsyncFunctionDef, facts: _ModuleFacts
) -> frozenset[str]:
    """The parameters of `func` its signature, read with `facts`, leaves as
    request sources. See `route_param_source_names` for the rules."""
    a = func.args
    positional = [*a.posonlyargs, *a.args]
    defaults: list[ast.AST | None] = [None] * (len(positional) - len(a.defaults))
    defaults += a.defaults
    params = [*zip(positional, defaults), *zip(a.kwonlyargs, a.kw_defaults)]
    first = next((p.arg for p in positional if p.arg != "self"), None)
    names = set()
    for param, default in params:
        name = param.arg
        if name == "self" or (name == first and name in _REQUEST_NAMES):
            continue
        if _is_dependency_call(default):
            continue
        if _annotation_is_injected(param.annotation, facts) or _is_fixed_value_annotation(
            param.annotation, facts.enums
        ):
            continue
        names.add(name)
    return frozenset(names)


def route_param_source_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    """The parameters of `func` that carry request data IF `func` is a route
    handler, judged from its signature alone. Every positional-only,
    positional and keyword-only parameter counts except:

    - ``self``;
    - the first positional parameter (after ``self``) named ``request`` or
      ``req``: the request object, whose attributes `_references_request_input`
      already treats as sources;
    - one annotated with a framework-injected type (`_INJECTED_PARAM_TYPES`),
      bare or under ``Optional``/``Union``/``| None``/``Annotated``;
    - one defaulted to ``Depends(...)``/``Security(...)``, or annotated
      ``Annotated[..., Depends(...)]`` (Review Focus 2, R-pf27);
    - one whose annotation admits only fixed values (R-pf33, R-pf36): a
      scalar FastAPI coerces to (``int``, ``Optional[UUID]``,
      ``Annotated[int, Query()]``), a pydantic constrained number
      (``conint(...)``, ``PositiveInt``), a ``Literal[...]``, or a container
      of those (``list[int]``, ``tuple[int, ...]``). ``str``, ``list[str]``,
      ``constr(...)``, a pydantic model and an unannotated parameter stay
      sources.

    Rules that need the module or the route (same-file Enum classes and
    dependency aliases, `deps` imports, Flask and Django URL patterns) are in
    `route_param_sources`, which applies the whole set."""
    return _signature_sources(func, _ModuleFacts())


def route_param_sources(
    func: ast.FunctionDef | ast.AsyncFunctionDef, routes, module: ast.AST | None
) -> frozenset[str]:
    """The parameters of `func` that are request sources, given the `routes`
    bound to it (empty: not a handler, no sources) and the `module` it is
    defined in. The whole rule set:

    - `route_param_source_names`'s signature rules, with the module's facts:
      an annotation naming an Enum class of this file (R-pf36), a same-file
      ``Annotated[..., Depends(...)]`` alias (R-pf27), or a type imported from
      a ``deps``/``dependencies`` module (R-pf34) is not a source either;
    - a Flask or Django route passes a parameter only when its URL pattern
      names it as text (R-pf36): ``<x>``, ``<path:x>``, ``(?P<x>...)``, or,
      for a Django regex with no named group, the unnamed groups in order
      after ``request``. A plain default (``def report(fmt="pdf")`` on
      ``/report``), a ``defaults=`` or urlconf extra-kwargs value, and a
      variable coerced by ``<int:x>``/``<float:x>``/``<uuid:x>`` (R-pf33)
      are developer-controlled or fixed;
    - a FastAPI route (or one whose framework is unknown) passes every
      parameter left.

    A parameter is a source when one of the routes passes it."""
    if not routes:
        return frozenset()
    return _route_param_sources_with(func, routes, _module_facts(module))


def _route_param_sources_with(
    func: ast.FunctionDef | ast.AsyncFunctionDef, routes, facts: _ModuleFacts
) -> frozenset[str]:
    """`route_param_sources` with the module's facts already collected (the
    visitor collects them once per file)."""
    if not routes:
        return frozenset()
    candidates = _signature_sources(func, facts)
    positional = [p.arg for p in (*func.args.posonlyargs, *func.args.args)]
    params = set(positional) | {p.arg for p in func.args.kwonlyargs}
    sources: set[str] = set()
    for route in routes:
        if getattr(route, "framework", "") in ("flask", "django"):
            sources |= candidates & _url_text_variables(route, positional, params)
        else:
            sources |= candidates
    return frozenset(sources)


def _url_text_variables(route, positional: list[str], params: set[str]) -> frozenset[str]:
    """The parameters a Flask-family or Django `route` fills from its URL as
    text: the variables its pattern names without a coercing converter, and,
    for a Django regex route with no named group, the positional parameters
    after the request that its unnamed groups fill.

    Flask, Quart and Django write `<converter:name>`; Sanic writes
    `<name:type>`. Of the two words, the one that is a parameter of the
    handler is the name (Flask's order when both or neither are)."""
    pattern = getattr(route, "pattern", "") or ""
    names = set()
    for first, second in _URL_VARIABLE.findall(pattern):
        name, converter = second, first
        if first and second not in params and first in params:
            name, converter = first, second
        if converter not in _COERCING_CONVERTERS:
            names.add(name)
    if getattr(route, "regex", False) and "(?P<" not in pattern:
        names.update(positional[1 : 1 + _unnamed_group_count(pattern)])
    return frozenset(names)


def _unnamed_group_count(pattern: str) -> int:
    """The number of unnamed capturing groups in a regex: `(` not followed by
    `?`, outside a character class and not escaped."""
    count = 0
    in_class = False
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(" and not pattern.startswith("?", i + 1):
            count += 1
        i += 1
    return count


def _module_matches_file(module: str, rel: str) -> bool:
    """True when dotted `module` names the file at `rel`: `app.views` is
    `app/views.py` or `app/views/__init__.py`, at the scan root or under a
    directory above the package (a `src/` layout, a scan of the repo root)."""
    if not module:
        return False
    rel = rel.replace(os.sep, "/")
    base = module.replace(".", "/")
    return any(
        rel == cand or rel.endswith("/" + cand)
        for cand in (f"{base}.py", f"{base}/__init__.py")
    )


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
    return any(_is_request_input_node(n) for n in ast.walk(arg))


def _is_request_input_node(n: ast.AST) -> bool:
    """The node-level test of `_references_request_input`: ``n`` itself reads
    request input."""
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
        # request.GET.get(...), request.args.get(...) — the .get is on the
        # inner attribute, which the walk reaches on its own.
        return (
            isinstance(n.value, ast.Name)
            and n.value.id in _REQUEST_NAMES
            and n.attr in _REQUEST_INPUT_ATTRS
        )
    if isinstance(n, ast.Subscript):
        value = n.value
        return (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id in _REQUEST_NAMES
            and value.attr in _REQUEST_INPUT_ATTRS
        )
    return False


def _source_argument(call: ast.Call, keyword: str) -> ast.AST | None:
    """The first positional argument of ``call``, else its ``keyword=``
    argument; None when neither is given or the first is ``*args``."""
    if call.args:
        first = call.args[0]
        return None if isinstance(first, ast.Starred) else first
    return next((kw.value for kw in call.keywords if kw.arg == keyword), None)


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
