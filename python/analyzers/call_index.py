"""Project call index: the one-hop helper check across files (Task 3.8).

The taint analyzer proves a sink in a helper function by following the
helper's parameter back to the calls of that helper (`_param_is_tainted_via_caller`).
Within one file it finds the calls itself. This index finds them in the rest
of the project: a view in `app/views.py` that does

    from app.services.q import find
    find(request.args["n"])

is a tainted caller of `find` in `app/services/q.py`.

`ProjectCallIndex.build(root, route_table)` reads every Python file once,
honouring the analyzer's own walk (`_SKIP_DIRS`, symlinked files,
`_MAX_FILE_BYTES`). Request input is a `request`/`req` name, so only a file
that names one, or that holds a route handler whose parameters are sources,
can pass request input to a call: those files are parsed, the rest are not.
It records two things per parsed file:

* **Imports.** Each local name an import binds, mapped to the dotted path it
  stands for (`from a.b import f` -> `a.b.f`, `from a.b import f as g`,
  `import a.b as m`, `import a.b`, relative imports resolved against the file's
  package; the route extractor's `_ImportScope`). A call `f(x)`, `m.f(x)` or
  `a.b.f(x)` whose head is such a name, and is not rebound in the calling
  function or module, names the function `f` of module `a.b`.
* **Call sites.** For each such call whose module is in the project, the
  caller's file, call node and scope, kept only when some argument may carry
  request input according to the caller's function summary: the names that
  are request sources there (`route_param_sources` for a route handler, the
  whole Task 3.1 rule set), plus every name assigned from request input or
  from an already tainted name, iterated to a fixpoint (at most
  `_MAX_TAINT_HOPS` rounds).

`tainted_args(module, function, index, name)` then answers for one parameter.
A call site counts when its argument for that parameter (positional at
`index`, or the keyword `name`; a negative `index` is a keyword-only
parameter, matched by keyword alone) passes the summary AND proves in the
caller exactly as a same-file caller would (`_caller_arg_chain` of a visitor
on the caller's file): the last assignment before the call decides, and the
caller-side sanitiser union of the same-file hop (R-pf32) runs with the
existing predicates in the caller's file and function (R-pf50 a). One link
per proven call site, in the caller's file.

One hop only: a caller's own parameters are not traced into its callers, and
the visitors this index runs on callers have no index of their own.

Module resolution assumes the scan root is the package parent. For a `src/`
layout or a root above the package, a query for module `src.app.q` also tries
each suffix of it that keeps at least two components (`app.q`), only while
exactly one scanned module has that suffix; otherwise it gives up.

Parses are cached for `ASTAnalyzer._analyze_python` to reuse
(`take_parsed`), so the index adds no parse for a file within the cache
budget (`_PARSE_CACHE_MAX_BYTES`), and at most one beyond it.
"""

from __future__ import annotations

import ast
import os
import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from analyzers.ast_analyzer import (
    _MAX_FILE_BYTES,
    _MAX_TAINT_HOPS,
    _REQUEST_NAMES,
    _SCOPE_NODES,
    _SKIP_DIRS,
    _dotted,
    _PythonSecurityVisitor,
    _references_request_input,
    _same_scope_nodes,
)
from analyzers.route_extractor import _ImportScope, _module_name

# Total source size of the parsed modules kept for `_analyze_python` to reuse.
# A parsed module takes about 30 times its source in memory, so 2 MiB of
# source (some 60k lines) holds about 60 MB of trees; past it, a file is
# parsed again when it is analysed. A caller's tree is kept regardless: its
# call sites point into it. Measured on a 217k-line tree, a larger budget
# bought no time (the collector walks the trees kept alive about as long as
# re-parsing takes) and cost about 30 MB per MiB.
_PARSE_CACHE_MAX_BYTES = 2 * 1_048_576

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)

# A file that never names the request object (`_REQUEST_NAMES` as a whole
# word) holds no request input.
_NAMES_THE_REQUEST = re.compile(
    r"\b(?:" + "|".join(sorted(map(re.escape, _REQUEST_NAMES))) + r")\b"
)


@dataclass(frozen=True)
class CallSiteLink:
    """The caller's end of a cross-file hop, as a taint-chain link: the call
    in the caller's file, or the request expression when that is passed
    inline (the same link the same-file hop ends its prefix with)."""

    file: str
    line: int
    expr: str


@dataclass(frozen=True)
class _CallSite:
    rel: str
    call: ast.Call
    # Where the call runs: the innermost def, lambda, class or comprehension
    # around it, else the module (`_PythonSecurityVisitor._build_callsite_index`).
    scope: ast.AST


def _discard(_finding: dict) -> None:
    """The caller visitors only answer questions; they never report."""


class ProjectCallIndex:
    """Calls into the project's own modules, by callee. See the module
    docstring."""

    def __init__(self, route_table=None) -> None:
        self._route_table = route_table
        # Dotted module of every scanned file, and for every dotted suffix of
        # one, how many scanned modules end with it.
        self._modules: set[str] = set()
        self._suffix_owners: dict[str, int] = {}
        # Every dotted prefix of a module a call can be keyed by: an import
        # whose target is not one, nor the parent of one, names no project
        # module.
        self._key_prefixes: set[str] = set()
        # (imported module, function name) -> the call sites naming it.
        self._sites: dict[tuple[str, str], list[_CallSite]] = {}
        # rel -> (source, tree) of every file holding a call site.
        self._callers: dict[str, tuple[str, ast.Module]] = {}
        # rel -> (source, tree) kept only for `take_parsed`.
        self._reusable: dict[str, tuple[str, ast.Module]] = {}
        self._reusable_bytes = 0
        self._visitors: dict[str, _PythonSecurityVisitor] = {}
        # Scope node of a caller -> the names its summary taints.
        self._summaries: dict[ast.AST, frozenset[str]] = {}
        self._answers: dict[tuple[str, str, int, str], tuple[CallSiteLink, ...]] = {}

    # -- building ---------------------------------------------------------

    @classmethod
    def build(cls, root: Path, route_table) -> ProjectCallIndex:
        """Read every Python file under `root` once, parse the ones that can
        pass request input to a call, and index the calls between the
        project's modules. `route_table` is the analyzer's project
        `RouteTable` (or None): it decides which callers are route handlers."""
        index = cls(route_table)
        files = list(_python_files(Path(root)))
        for _path, rel in files:
            index._learn_module(index.module_of(rel))
        index._learn_key_prefixes()
        handler_files = index._handler_files(rel for _path, rel in files)
        for path, rel in files:
            index._add_file(path, rel, rel in handler_files)
        return index

    @staticmethod
    def module_of(rel: str) -> str:
        """The dotted module of the file at `rel` under the scan root:
        `app/services/q.py` -> `app.services.q`, `app/services/__init__.py`
        -> `app.services`."""
        return _module_name(rel)[0]

    def _learn_module(self, module: str) -> None:
        if not module:
            return
        self._modules.add(module)
        parts = module.split(".")
        for k in range(len(parts)):
            suffix = ".".join(parts[k:])
            self._suffix_owners[suffix] = self._suffix_owners.get(suffix, 0) + 1

    def _learn_key_prefixes(self) -> None:
        keys = set(self._modules)
        keys.update(s for s, n in self._suffix_owners.items() if n == 1 and "." in s)
        for key in keys:
            parts = key.split(".")
            for k in range(1, len(parts) + 1):
                self._key_prefixes.add(".".join(parts[:k]))

    def _handler_files(self, rels) -> set[str]:
        """The files that may define a route handler, whose parameters can
        seed a summary: the file of a decorator route, and a file that is one
        of a Django route's view modules (`_module_matches_file`). Only these
        and files that name the request (`_REQUEST_NAMES`) can pass request
        input to a call (`_add_file`)."""
        if self._route_table is None:
            return set()
        decorated: set[str] = set()
        view_modules: set[str] = set()
        for routes in self._route_table.all_by_func.values():
            for route in routes:
                if getattr(route, "framework", "") == "django":
                    view_modules.update(getattr(route, "handler_modules", ()))
                else:
                    decorated.add(route.file.replace(os.sep, "/"))
        found = set()
        for rel in rels:
            if rel.replace(os.sep, "/") in decorated:
                found.add(rel)
                continue
            parts = self.module_of(rel).split(".")
            if any(".".join(parts[k:]) in view_modules for k in range(len(parts))):
                found.add(rel)
        return found

    def _is_project_module(self, module: str) -> bool:
        """True when a query can reach call sites keyed by `module`: a scanned
        module, or a suffix of exactly one with at least two components."""
        return module in self._modules or (
            "." in module and self._suffix_owners.get(module) == 1
        )

    def _add_file(self, path: Path, rel: str, holds_handlers: bool) -> None:
        """Index one file. Request input is a `request`/`req` name, so a file
        that names neither, and holds no route handler whose parameters
        could seed its summary, can pass none to a call: it is not parsed
        here at all, and `_analyze_python` parses it as before. A parsed file
        is kept for `take_parsed`."""
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if not holds_handlers and not _NAMES_THE_REQUEST.search(source):
            return
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return  # `_analyze_python` reads it again and decides, as before
        summaries: dict[ast.AST, frozenset[str]] = {}
        try:
            sites = self._call_sites(rel, source, tree, summaries)
        except (RecursionError, Exception):  # noqa: BLE001 — one file never aborts the index
            sites = []
        if sites:
            self._callers[rel] = (source, tree)
            self._summaries.update(summaries)
            for key, site in sites:
                self._sites.setdefault(key, []).append(site)
            return
        self._visitors.pop(rel, None)
        if self._reusable_bytes + len(source) <= _PARSE_CACHE_MAX_BYTES:
            self._reusable[rel] = (source, tree)
            self._reusable_bytes += len(source)

    def _call_sites(
        self,
        rel: str,
        source: str,
        tree: ast.Module,
        summaries: dict[ast.AST, frozenset[str]],
    ) -> list[tuple[tuple[str, str], _CallSite]]:
        """Every call in the file that names a function of a project module
        and passes an argument the caller's summary says may carry request
        input, keyed by `(module, function)` as the import names them.

        One walk collects the import statements and every call with the
        scope it runs in; the imports are then resolved by the route
        extractor's `_ImportScope`, given those statements alone."""
        import_nodes: list[ast.stmt] = []
        calls: list[tuple[ast.Call, ast.AST]] = []
        parents: dict[ast.AST, ast.AST] = {}
        queue = deque([(tree, tree)])
        while queue:
            node, scope = queue.popleft()
            if isinstance(node, ast.Call):
                calls.append((node, scope))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                import_nodes.append(node)
            if node is not tree and isinstance(node, _SCOPE_NODES):
                parents[node] = scope
                scope = node
            queue.extend((child, scope) for child in ast.iter_child_nodes(node))
        imports = {
            name: target
            for name, target in _ImportScope(
                ast.Module(body=import_nodes, type_ignores=[]), rel
            ).names.items()
            if target in self._key_prefixes
            or target.rpartition(".")[0] in self._key_prefixes
        }
        if not imports:
            return []
        found = []
        bound: dict[ast.AST, frozenset[str]] = {}
        for call, scope in calls:
            target = self._callee(call.func, imports)
            if target is None:
                continue
            key, head = target
            if not self._is_shadowed(head, scope, parents, bound) and any(
                self._may_carry_input(rel, source, tree, scope, arg, summaries)
                for arg in _argument_values(call)
            ):
                found.append((key, _CallSite(rel, call, scope)))
        return found

    def _callee(
        self, func: ast.AST, imports: dict[str, str]
    ) -> tuple[tuple[str, str], str] | None:
        """`((module, function), head)` for a call of `f`, `m.f` or `a.b.f`
        whose head an import binds and whose module is in the project; else
        None. `m.C.f` names module `m.C`, which is never a module of the
        project, so a class's method is not matched (R-pf50 c)."""
        dotted = _dotted(func)
        head, _, rest = dotted.partition(".")
        if not head or head not in imports:
            return None
        full = imports[head] + (f".{rest}" if rest else "")
        module, _, function = full.rpartition(".")
        if not module or not self._is_project_module(module):
            return None
        return (module, function), head

    @staticmethod
    def _is_shadowed(
        head: str,
        scope: ast.AST,
        parents: dict[ast.AST, ast.AST],
        bound: dict[ast.AST, frozenset[str]],
    ) -> bool:
        """True when `head` is bound by something other than an import in a
        scope the call reads it from: a parameter, an assignment, a def or a
        class of the calling function, of a function around it, or of the
        module. A class body's names are not visible in its methods."""
        node = scope
        while node is not None:
            if node is scope or not isinstance(node, ast.ClassDef):
                names = bound.get(node)
                if names is None:
                    names = bound[node] = _bound_names(node)
                if head in names:
                    return True
            node = parents.get(node)
        return False

    def _may_carry_input(
        self,
        rel: str,
        source: str,
        tree: ast.Module,
        scope: ast.AST,
        arg: ast.AST,
        summaries: dict[ast.AST, frozenset[str]],
    ) -> bool:
        """The summary test: `arg` reads request input, or, in a function or
        at module level, a name the scope's summary taints. In a lambda,
        class or comprehension only request input passed inline counts, as
        for a same-file caller."""
        if _references_request_input(arg):
            return True
        if not isinstance(scope, (ast.Module, *_DEFS)):
            return False
        tainted = summaries.get(scope)
        if tainted is None:
            tainted = summaries[scope] = self._summary(rel, source, tree, scope)
        return _reads_any(arg, tainted)

    def _summary(
        self, rel: str, source: str, tree: ast.Module, scope: ast.AST
    ) -> frozenset[str]:
        """The names a function (or the module) may hold request input in:
        its request-carrying route parameters (`route_param_sources`, via the
        caller visitor, which binds a route only to the def it was declared
        for), names assigned from request input, and names assigned from a
        tainted name, to a fixpoint capped at `_MAX_TAINT_HOPS` rounds."""
        tainted: set[str] = set()
        if (
            isinstance(scope, _DEFS)
            and self._route_table is not None
            and self._route_table.routes_for_function(scope.name)
        ):
            visitor = self._visitor(rel, source, tree)
            tainted |= visitor._route_param_sources(scope)
        flows = [
            (targets, value, _references_request_input(value))
            for targets, value in _assignments(scope)
            if targets
        ]
        tainted.update(n for targets, _value, direct in flows if direct for n in targets)
        for _round in range(_MAX_TAINT_HOPS):
            grew = False
            for targets, value, _direct in flows:
                if not targets <= tainted and _reads_any(value, tainted):
                    tainted |= targets
                    grew = True
            if not grew:
                break
        return frozenset(tainted)

    def _visitor(self, rel: str, source: str, tree: ast.Module) -> _PythonSecurityVisitor:
        """A visitor on the caller's file, set up as its own walk would leave
        it for the questions asked here: the module root, the scope parents
        (`_build_callsite_index`) and the file's imports."""
        visitor = self._visitors.get(rel)
        if visitor is None:
            visitor = _PythonSecurityVisitor(
                source.splitlines(), rel, _discard, route_table=self._route_table
            )
            visitor._module_root = tree
            visitor._callsite_index = visitor._build_callsite_index()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    visitor.visit_Import(node)
                elif isinstance(node, ast.ImportFrom):
                    visitor.visit_ImportFrom(node)
            self._visitors[rel] = visitor
        return visitor

    # -- queries ----------------------------------------------------------

    def take_parsed(self, rel: str) -> tuple[str, ast.Module] | None:
        """`(source, tree)` of the file at `rel` as the index parsed it, for
        `_analyze_python` to analyse instead of parsing it again; None when
        the index did not keep it. A tree no call site points into is
        released once taken."""
        entry = self._reusable.pop(rel, None)
        if entry is not None:
            self._reusable_bytes -= len(entry[0])
            return entry
        return self._callers.get(rel)

    def tainted_args(
        self, callee_module: str, callee_name: str, param_index: int, param_name: str
    ) -> list[CallSiteLink]:
        """One `CallSiteLink` per call site in the project that passes request
        input to parameter `param_name` (at position `param_index`; negative
        for a keyword-only parameter) of the module-level function
        `callee_name` of `callee_module`. Calls from the callee's own file
        are the same-file hop's and are never in this index's keys unless
        the file imports itself."""
        key = (callee_module, callee_name, param_index, param_name)
        answer = self._answers.get(key)
        if answer is None:
            answer = self._answers[key] = tuple(self._links(*key))
        return list(answer)

    def _links(
        self, callee_module: str, callee_name: str, param_index: int, param_name: str
    ) -> Iterator[CallSiteLink]:
        for module in self._names_for(callee_module):
            for site in self._sites.get((module, callee_name), ()):
                arg = _argument(site.call, param_index, param_name)
                if arg is None:
                    continue
                source, tree = self._callers[site.rel]
                if not self._may_carry_input(
                    site.rel, source, tree, site.scope, arg, self._summaries
                ):
                    continue
                link = self._prove(site, arg)
                if link is not None:
                    yield link

    def _names_for(self, module: str) -> Iterator[str]:
        """`module` itself, then each suffix of it with at least two
        components, while exactly one scanned module has that suffix."""
        yield module
        parts = module.split(".")
        for k in range(1, len(parts) - 1):
            suffix = ".".join(parts[k:])
            if self._suffix_owners.get(suffix) != 1:
                return
            yield suffix

    def _prove(self, site: _CallSite, arg: ast.AST) -> CallSiteLink | None:
        """The link the caller proves for `arg`, judged by a visitor on the
        caller's file exactly as a same-file caller is (`_caller_arg_chain`:
        the caller's bindings before the call, its route parameters, and the
        caller-side sanitiser union), or None. A failure inside the caller's
        file proves nothing; it never aborts the callee's analysis."""
        source, tree = self._callers[site.rel]
        try:
            visitor = self._visitor(site.rel, source, tree)
            prefix = visitor._caller_arg_chain(site.call, site.scope, arg, None, 0)
        except (RecursionError, Exception):  # noqa: BLE001 — best-effort proof
            return None
        if not prefix:
            return None
        last = prefix[-1]
        return CallSiteLink(file=last["file"], line=last["line"], expr=last["expr"])


# -- helpers ------------------------------------------------------------------


def _python_files(root: Path) -> Iterator[tuple[Path, str]]:
    """`(path, rel)` of every file the analyzer would analyse as Python: the
    same walk as `ASTAnalyzer.run`, without symlinked or oversized files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = Path(dirpath) / fname
            try:
                if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path, str(path.relative_to(root))


def _argument_values(call: ast.Call) -> Iterator[ast.AST]:
    for arg in call.args:
        yield arg.value if isinstance(arg, ast.Starred) else arg
    for kw in call.keywords:
        yield kw.value


def _argument(call: ast.Call, param_index: int, param_name: str) -> ast.AST | None:
    """The argument `call` passes for a parameter: positional at
    `param_index` when no `*args` comes at or before it, else the keyword of
    its name. A negative index is a keyword-only parameter."""
    if 0 <= param_index < len(call.args) and not any(
        isinstance(a, ast.Starred) for a in call.args[: param_index + 1]
    ):
        return call.args[param_index]
    for kw in call.keywords:
        if kw.arg == param_name:
            return kw.value
    return None


def _reads_any(expr: ast.AST, names: frozenset[str] | set[str]) -> bool:
    return bool(names) and any(
        isinstance(n, ast.Name) and n.id in names for n in ast.walk(expr)
    )


def _target_names(target: ast.AST) -> frozenset[str]:
    """The names an assignment target binds or writes through: `x`, and the
    `d` of `d[k]` or `d.k`, every one in a tuple."""
    if isinstance(target, ast.Name):
        return frozenset({target.id})
    if isinstance(target, (ast.Tuple, ast.List)):
        return frozenset().union(*(_target_names(e) for e in target.elts))
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, (ast.Attribute, ast.Subscript)):
        return _target_names(target.value)
    return frozenset()


def _assignments(scope: ast.AST) -> Iterator[tuple[frozenset[str], ast.AST]]:
    """`(target names, value)` for each assignment made in `scope`'s own
    body (`_same_scope_nodes`): plain, annotated, augmented and walrus
    assignments, `for` and `with ... as` targets."""
    for stmt in getattr(scope, "body", []):
        for n in _same_scope_nodes(stmt):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    yield _target_names(t), n.value
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                if n.value is not None:
                    yield _target_names(n.target), n.value
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                yield _target_names(n.target), n.iter
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    if item.optional_vars is not None:
                        yield _target_names(item.optional_vars), item.context_expr


def _bound_names(scope: ast.AST) -> frozenset[str]:
    """Names `scope` binds other than by import: parameters of a def or
    lambda, and the names its own statements store, define as a def or
    class, or (comprehension) iterate into."""
    names: set[str] = set()
    if isinstance(scope, (*_DEFS, ast.Lambda)):
        a = scope.args
        params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
        params += [p for p in (a.vararg, a.kwarg) if p is not None]
        names.update(p.arg for p in params)
    if isinstance(scope, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        for gen in scope.generators:
            names |= _target_names(gen.target)
        return frozenset(names)
    body = getattr(scope, "body", [])
    for stmt in body if isinstance(body, list) else []:
        for n in _same_scope_nodes(stmt):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                names.add(n.id)
            elif isinstance(n, (*_DEFS, ast.ClassDef)):
                names.add(n.name)
    return frozenset(names)
