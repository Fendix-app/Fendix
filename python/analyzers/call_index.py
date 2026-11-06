"""Project call index: the one-hop helper check across files (Task 3.8).

The taint analyzer proves a sink in a helper function by following the
helper's parameter back to the calls of that helper (`_param_is_tainted_via_caller`).
Within one file it finds the calls itself. This index finds them in the rest
of the project: a view in `app/views.py` that does

    from app.services.q import find
    find(request.args["n"])

is a tainted caller of `find` in `app/services/q.py`.

**Building.** `ProjectCallIndex.build(root, route_table)` reads every Python
file once, honouring the analyzer's own walk (`_SKIP_DIRS`, symlinked files,
`_MAX_FILE_BYTES`). Request input is a `request`/`req` name, so only a file
that names one, or that holds a route handler whose parameters are sources,
can pass request input to a call: those files are parsed, the rest are not.
Test and fixture code (`_is_test_path`) is never a caller. For each parsed
file the index records:

* **Imports, per scope.** Each local name an import binds, in the module or
  in the function (or class body) holding the import statement, mapped to
  the dotted path it stands for (`from a.b import f` -> `a.b.f`,
  `from a.b import f as g`, `import a.b as m`, `import a.b`, relative imports
  resolved against the file's package; the route extractor's `_ImportScope`).
  A call `f(x)`, `m.f(x)` or `a.b.f(x)` resolves its head through the scopes
  it reads names from, innermost first: an import there names the function
  `f` of module `a.b`; any other binding there (a parameter, an assignment, a
  def) means it is not an imported name.
* **Call sites.** For each call naming a function of a project module, a
  compact record: the caller's file, the call's source span, and which of its
  arguments may carry request input according to the caller's function
  summary. The summary is the names that are request sources there
  (`route_param_sources` for a route handler, the whole Task 3.1 rule set),
  plus every name assigned from request input or from an already tainted
  name, iterated to a fixpoint (at most `_MAX_TAINT_HOPS` rounds). A call
  none of whose arguments passes the summary is not recorded. No tree is kept
  for a record.

**Answering.** `tainted_args(module, function, index, name)` takes, for each
recorded call naming that function, the argument for the parameter (the one
rule the same-file hop uses, `_call_argument`: positional at `index` as
written, else the keyword `name`; a negative `index` is a keyword-only
parameter, matched by keyword alone). When the record says it may carry
request input, the call is proved in the caller's own file exactly as a
same-file caller is (`_caller_arg_chain` of a visitor on that file): the last
assignment before the call decides, and the caller-side sanitiser union of the
same-file hop (R-pf32) runs with the existing predicates in the caller's file
and function (R-pf50 a), under the template-source rule of the trace that
asks. One link per proven call, in the caller's file; `first=True` stops at
the first, which is all the taint chain shows. A caller's tree and visitor are
built on demand and kept in a least-recently-used cache capped at
`_CALLER_CACHE_MAX_BYTES` of source; a file evicted from it is parsed again
when it is next needed.

One hop only: a caller's own parameters are not traced into its callers, and
the visitors this index runs on callers have no index of their own.

Module resolution assumes the scan root is the package parent. For a `src/`
layout or a root above the package, a query for module `src.app.q` also tries
each suffix of it that keeps at least two components (`app.q`), only while
exactly one scanned module has that suffix; otherwise it gives up.

Parses made while building are kept, up to `_PARSE_CACHE_MAX_BYTES` of source,
for `ASTAnalyzer._analyze_python` to reuse (`take_parsed`): the index adds no
parse for a file within that budget and at most one beyond it, plus one for
each caller a proof needs that the caller cache no longer holds.
"""

from __future__ import annotations

import ast
import os
import re
from collections import OrderedDict, deque
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path

from analyzers.ast_analyzer import (
    _MAX_FILE_BYTES,
    _MAX_TAINT_HOPS,
    _REQUEST_NAMES,
    _SCOPE_NODES,
    _SKIP_DIRS,
    _call_argument,
    _dotted,
    _file_visitor,
    _is_test_path,
    _PythonSecurityVisitor,
    _references_request_input,
    _same_scope_nodes,
)
from analyzers.route_extractor import _ImportScope, _module_name

# Total source size of the parsed modules kept for `_analyze_python` to reuse;
# past it, a file is parsed again when it is analysed. A parsed module takes
# 30 to 90 times its source in memory (library code to dense generated
# views), so 256 KiB holds at most about 25 MB of trees. The first files kept
# are the first analysed, so the cache drains early in the walk. Measured,
# a larger budget bought no time (the collector walks the trees kept alive
# about as long as parsing them again takes) and cost memory.
_PARSE_CACHE_MAX_BYTES = 256 * 1024

# Total source size of the caller files whose tree and visitor a proof keeps
# for the next one, least recently used out first; the latest is always kept.
# A query stops at the first proving caller, so few are needed.
_CALLER_CACHE_MAX_BYTES = 256 * 1024

_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)

# A file that never names the request object (`_REQUEST_NAMES` as a whole
# word) holds no request input.
_NAMES_THE_REQUEST = re.compile(
    r"\b(?:" + "|".join(sorted(map(re.escape, _REQUEST_NAMES))) + r")\b"
)

Span = tuple[int, int, int, int]


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
    """One recorded call: the caller's file, the call's source span, and
    which arguments the caller's summary lets carry request input, by
    position (as written) and by keyword."""

    rel: str
    span: Span
    positional: tuple[bool, ...]
    keywords: frozenset[str]

    def may_carry(self, index: int, name: str) -> bool:
        """The summary's answer for the argument `_call_argument` takes for
        the parameter at `index` named `name`."""
        if 0 <= index < len(self.positional):
            return self.positional[index]
        return name in self.keywords


@dataclass
class _Caller:
    """A caller file ready for proofs: its visitor (primed, holding the tree)
    and the recorded calls in it, by span, each with the scope it runs in."""

    size: int
    visitor: _PythonSecurityVisitor
    calls: dict[Span, tuple[ast.Call, ast.AST]]


@dataclass
class _Walk:
    """One scope-tracking walk of a module (`_scoped_walk`)."""

    imports: dict[ast.AST, list[ast.stmt]]
    calls: list[tuple[ast.Call, ast.AST]]
    parents: dict[ast.AST, ast.AST]


def _discard(_finding: dict) -> None:
    """The caller visitors only answer questions; they never report."""


class ProjectCallIndex:
    """Calls into the project's own modules, by callee. See the module
    docstring."""

    def __init__(self, route_table=None, root: Path | None = None) -> None:
        self._route_table = route_table
        self._root = Path(root) if root is not None else Path(".")
        # Dotted module of every scanned file, and for every dotted suffix of
        # one, how many scanned modules end with it.
        self._modules: set[str] = set()
        self._suffix_owners: dict[str, int] = {}
        # Every dotted prefix of a module a call can be keyed by: an import
        # whose target is not one, nor the parent of one, names no project
        # module.
        self._key_prefixes: set[str] = set()
        # (imported module, function name) -> the calls naming it.
        self._sites: dict[tuple[str, str], list[_CallSite]] = {}
        # rel -> the spans of its recorded calls, and the path to re-read it.
        self._spans: dict[str, set[Span]] = {}
        self._paths: dict[str, Path] = {}
        # rel -> (source, tree) kept only for `take_parsed`.
        self._reusable: dict[str, tuple[str, ast.Module]] = {}
        self._reusable_bytes = 0
        # rel -> _Caller, least recently used first.
        self._callers: OrderedDict[str, _Caller] = OrderedDict()
        self._caller_bytes = 0
        self._answers: dict[tuple, tuple[CallSiteLink, ...]] = {}
        self._firsts: dict[tuple, CallSiteLink | None] = {}

    # -- building ---------------------------------------------------------

    @classmethod
    def build(cls, root: Path, route_table) -> ProjectCallIndex:
        """Read every Python file under `root` once, parse the ones that can
        pass request input to a call, and index the calls between the
        project's modules. `route_table` is the analyzer's project
        `RouteTable` (or None): it decides which callers are route handlers."""
        index = cls(route_table, root)
        files = list(_python_files(index._root))
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
        """Index one file. A test or fixture file is never a caller. Request
        input is a `request`/`req` name, so a file that names neither, and
        holds no route handler whose parameters could seed its summary, can
        pass none to a call: it is not parsed here at all, and
        `_analyze_python` parses it as before. A parsed file is kept for
        `take_parsed` within `_PARSE_CACHE_MAX_BYTES`."""
        if _is_test_path(rel):
            return
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
        try:
            sites = self._call_sites(rel, source, tree)
        except (RecursionError, Exception):  # noqa: BLE001 — one file never aborts the index
            sites = []
        for key, site in sites:
            self._sites.setdefault(key, []).append(site)
            self._spans.setdefault(rel, set()).add(site.span)
            self._paths[rel] = path
        if self._reusable_bytes + len(source) <= _PARSE_CACHE_MAX_BYTES:
            self._reusable[rel] = (source, tree)
            self._reusable_bytes += len(source)

    def _call_sites(
        self, rel: str, source: str, tree: ast.Module
    ) -> list[tuple[tuple[str, str], _CallSite]]:
        """Every call in the file that names a function of a project module
        through an import and passes an argument the caller's summary says
        may carry request input, keyed by `(module, function)` as the import
        names them."""
        walk = _scoped_walk(tree)
        imports = {
            scope: _ImportScope(ast.Module(body=nodes, type_ignores=[]), rel).names
            for scope, nodes in walk.imports.items()
        }
        # The names some import in the file binds to a project module or one
        # of its functions: a call whose head is none of them names nothing
        # of the project, whatever scope it resolves in.
        heads = {
            name
            for names in imports.values()
            for name, target in names.items()
            if target in self._key_prefixes
            or target.rpartition(".")[0] in self._key_prefixes
        }
        if not heads:
            return []
        found = []
        bound: dict[ast.AST, frozenset[str]] = {}
        summaries: dict[tuple[ast.AST, bool], frozenset[str]] = {}
        seeds = _RouteSeeds(self._route_table, source, rel, tree)
        for call, scope in walk.calls:
            if _dotted(call.func).partition(".")[0] not in heads:
                continue
            key = self._callee(call.func, scope, walk.parents, imports, bound)
            if key is None:
                continue

            def carries(arg: ast.AST, scope: ast.AST = scope) -> bool:
                return _may_carry_input(arg, scope, summaries, seeds)

            positional = tuple(carries(a) for a in call.args)
            keywords = frozenset(
                kw.arg for kw in call.keywords if kw.arg is not None and carries(kw.value)
            )
            if any(positional) or keywords:
                found.append((key, _CallSite(rel, _span(call), positional, keywords)))
        return found

    def _callee(
        self,
        func: ast.AST,
        scope: ast.AST,
        parents: dict[ast.AST, ast.AST],
        imports: dict[ast.AST, dict[str, str]],
        bound: dict[ast.AST, frozenset[str]],
    ) -> tuple[str, str] | None:
        """`(module, function)` for a call of `f`, `m.f` or `a.b.f` whose head
        resolves to an import (`_resolve_import`) and whose module is in the
        project; else None. `m.C.f` names module `m.C`, which is never a
        module of the project, so a class's method is not matched (R-pf50 c)."""
        dotted = _dotted(func)
        head, _, rest = dotted.partition(".")
        if not head:
            return None
        target = _resolve_import(head, scope, parents, imports, bound)
        if target is None:
            return None
        full = target + (f".{rest}" if rest else "")
        module, _, function = full.rpartition(".")
        if not module or not self._is_project_module(module):
            return None
        return module, function

    # -- queries ----------------------------------------------------------

    def take_parsed(self, rel: str) -> tuple[str, ast.Module] | None:
        """`(source, tree)` of the file at `rel` as the index parsed it, for
        `_analyze_python` to analyse instead of parsing it again; None when
        the index did not keep it. Released once taken."""
        entry = self._reusable.pop(rel, None)
        if entry is not None:
            self._reusable_bytes -= len(entry[0])
        return entry

    def tainted_args(
        self,
        callee_module: str,
        callee_name: str,
        param_index: int,
        param_name: str,
        *,
        first: bool = False,
        skip_template_sources: bool = False,
    ) -> list[CallSiteLink]:
        """One `CallSiteLink` per call in the project that passes request input
        to parameter `param_name` (at position `param_index`; negative for a
        keyword-only parameter) of the module-level function `callee_name`
        of `callee_module`, in the order the calls were indexed. `first`
        stops at the first proving call. `skip_template_sources` proves the
        caller as `_without_template_sources` does. Answers are cached per
        query, the flag included."""
        key = (callee_module, callee_name, param_index, param_name, skip_template_sources)
        answer = self._answers.get(key)
        if answer is not None:
            return list(answer[:1] if first else answer)
        if first:
            if key not in self._firsts:
                self._firsts[key] = next(self._links(*key), None)
            link = self._firsts[key]
            return [link] if link is not None else []
        answer = self._answers[key] = tuple(self._links(*key))
        return list(answer)

    def _links(
        self,
        callee_module: str,
        callee_name: str,
        param_index: int,
        param_name: str,
        skip_template_sources: bool,
    ) -> Iterator[CallSiteLink]:
        for module in self._names_for(callee_module):
            for site in self._sites.get((module, callee_name), ()):
                if not site.may_carry(param_index, param_name):
                    continue
                link = self._prove(site, param_index, param_name, skip_template_sources)
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

    def _prove(
        self, site: _CallSite, param_index: int, param_name: str, skip_template_sources: bool
    ) -> CallSiteLink | None:
        """The link the caller proves for the argument, judged by a visitor on
        the caller's file exactly as a same-file caller is
        (`_caller_arg_chain`: the caller's bindings before the call, its
        route parameters, and the caller-side sanitiser union), or None. Any
        failure, from re-reading the caller to the proof, proves nothing; it
        never aborts the callee's analysis."""
        try:
            caller = self._caller(site.rel)
            if caller is None or site.span not in caller.calls:
                return None
            call, scope = caller.calls[site.span]
            arg = _call_argument(call, param_index, param_name)
            if arg is None:
                return None
            visitor = caller.visitor
            rule = visitor._without_template_sources() if skip_template_sources else nullcontext()
            with rule:
                prefix = visitor._caller_arg_chain(call, scope, arg, None, 0)
        except (RecursionError, Exception):  # noqa: BLE001 — best-effort proof
            return None
        if not prefix:
            return None
        last = prefix[-1]
        return CallSiteLink(file=last["file"], line=last["line"], expr=last["expr"])

    def _caller(self, rel: str) -> _Caller | None:
        """The caller file at `rel`, from the cache or parsed again (its
        build-time parse when `_analyze_python` has not taken it yet), its
        recorded calls located by span. Inserting it evicts the least
        recently used callers beyond `_CALLER_CACHE_MAX_BYTES`, never itself."""
        caller = self._callers.get(rel)
        if caller is not None:
            self._callers.move_to_end(rel)
            return caller
        kept = self._reusable.get(rel)
        if kept is not None:
            source, tree = kept
        else:
            path = self._paths[rel]
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        wanted = self._spans.get(rel, set())
        calls = {
            _span(call): (call, scope)
            for call, scope in _scoped_walk(tree).calls
            if _span(call) in wanted
        }
        visitor = _file_visitor(
            source, rel, _discard, tree, route_table=self._route_table, primed=True
        )
        caller = self._callers[rel] = _Caller(len(source), visitor, calls)
        self._caller_bytes += caller.size
        while self._caller_bytes > _CALLER_CACHE_MAX_BYTES and len(self._callers) > 1:
            _rel, evicted = self._callers.popitem(last=False)
            self._caller_bytes -= evicted.size
        return caller


# -- helpers ------------------------------------------------------------------


class _RouteSeeds:
    """The request-carrying parameters of a caller def that is a route
    handler: `route_param_sources` over the routes bound to that def, through
    a visitor on the caller's file (which binds a route only to the def it
    was declared for). The visitor is made on the first handler asked about."""

    def __init__(self, route_table, source: str, rel: str, tree: ast.Module) -> None:
        self._route_table = route_table
        self._source, self._rel, self._tree = source, rel, tree
        self._visitor: _PythonSecurityVisitor | None = None

    def of(self, scope: ast.AST) -> frozenset[str]:
        if (
            not isinstance(scope, _DEFS)
            or self._route_table is None
            or not self._route_table.routes_for_function(scope.name)
        ):
            return frozenset()
        if self._visitor is None:
            self._visitor = _file_visitor(
                self._source, self._rel, _discard, self._tree, route_table=self._route_table
            )
        return self._visitor._route_param_sources(scope)


def _may_carry_input(
    arg: ast.AST,
    scope: ast.AST,
    summaries: dict[tuple[ast.AST, bool], frozenset[str]],
    seeds: _RouteSeeds,
) -> bool:
    """The summary test: `arg` reads request input, or, in a function or at
    module level, a name the scope's summary taints. In a lambda, class or
    comprehension only request input passed inline counts, as for a
    same-file caller. The route-parameter sources join the summary only when
    the request-input assignments alone do not reach `arg` (they need a
    look at the module, `route_param_sources`)."""
    if _references_request_input(arg):
        return True
    if not isinstance(scope, (ast.Module, *_DEFS)):
        return False
    for with_routes in (False, True):
        tainted = summaries.get((scope, with_routes))
        if tainted is None:
            route_sources = seeds.of(scope) if with_routes else frozenset()
            tainted = summaries[(scope, with_routes)] = _summary(scope, route_sources)
        if _reads_any(arg, tainted):
            return True
    return False


def _summary(scope: ast.AST, route_sources: frozenset[str]) -> frozenset[str]:
    """The names a function (or the module) may hold request input in: its
    request-carrying route parameters (`route_sources`, from
    `route_param_sources`), names assigned from request input, and names
    assigned from a tainted name, to a fixpoint capped at `_MAX_TAINT_HOPS`
    rounds."""
    tainted: set[str] = set(route_sources)
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


def _resolve_import(
    head: str,
    scope: ast.AST,
    parents: dict[ast.AST, ast.AST],
    imports: dict[ast.AST, dict[str, str]],
    bound: dict[ast.AST, frozenset[str]],
) -> str | None:
    """The dotted path an import binds `head` to, as seen from code in
    `scope`: the scopes the code reads names from, innermost first (a class
    body only for code directly in it). The first scope that binds `head`
    decides: through an import, its target; through anything else (a
    parameter, an assignment, a def or class), None. A scope that binds
    `head` both ways (`from svc import find` then `find = print`, or a later
    `def find`) gives None too: which binding a call reads depends on the order
    of the statements, so no call of it is taken to name the import."""
    node = scope
    while node is not None:
        if node is scope or not isinstance(node, ast.ClassDef):
            imported = imports.get(node)
            names = bound.get(node)
            if names is None:
                names = bound[node] = _bound_names(node)
            if head in names:
                return None
            if imported is not None and head in imported:
                return imported[head]
        node = parents.get(node)
    return None


def _scoped_walk(tree: ast.Module) -> _Walk:
    """One breadth-first walk of `tree`: the import statements of each scope,
    every call with the scope it runs in (the innermost def, lambda, class or
    comprehension, else the module, as `_build_callsite_index` has it), and
    each scope's parent scope."""
    walk = _Walk({}, [], {})
    queue = deque([(tree, tree)])
    while queue:
        node, scope = queue.popleft()
        if isinstance(node, ast.Call):
            walk.calls.append((node, scope))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            walk.imports.setdefault(scope, []).append(node)
        if node is not tree and isinstance(node, _SCOPE_NODES):
            walk.parents[node] = scope
            scope = node
        queue.extend((child, scope) for child in ast.iter_child_nodes(node))
    return walk


def _span(node: ast.AST) -> Span:
    return (node.lineno, node.col_offset, node.end_lineno or 0, node.end_col_offset or 0)


def _python_files(root: Path) -> Iterator[tuple[Path, str]]:
    """`(path, rel)` of every file the analyzer would analyse as Python: the
    same walk as `ASTAnalyzer.run`, without symlinked or oversized files.
    Sorted, so the first proving caller does not depend on the order the
    filesystem lists a directory in."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            path = Path(dirpath) / fname
            try:
                if path.is_symlink() or path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path, str(path.relative_to(root))


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
