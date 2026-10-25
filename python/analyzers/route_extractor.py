"""Route-table extraction for Proven Path v1 (90-day cut item 4).

Walks Python source for the route declarations that wire an HTTP path to a
view function, across the three frameworks that cover the 90-day ICP
(API-first Python/Django teams):

  * Django   — ``path("users/<int:id>", views.get_user)`` /
               ``re_path(r"^users/(?P<id>\\d+)$", get_user)`` in a
               ``urlpatterns`` list.
  * Flask    — ``@app.route("/users/<id>", methods=["GET"])`` /
               ``@bp.route(...)`` decorators on a view function.
  * FastAPI  — ``@app.get("/users/{id}")`` / ``@router.post(...)`` decorators.

The output is a list of :class:`Route` records. The taint analyzer binds a
finding to a route when the finding's sink sits inside a function that a
route points at (Flask/FastAPI: the decorated function; Django: the view
symbol named in ``path()``). That binding plus the existing source→sink
taint chain is the v1 "proof": route → handler → reachable sink.

Design notes:
  * Pure stdlib ``ast`` — no new dependency, mirrors ast_analyzer.py.
  * Best-effort: a route we can't statically resolve (a view built at
    runtime, an ``include()`` we don't follow) is simply not emitted —
    never guessed. Unbound findings keep working exactly as before.
  * This is metadata extraction only; it emits NO findings and cannot
    change detection, so it cannot move the heavy-eval F1 score.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


# Decorator method names that declare a route on a Flask/FastAPI app or
# router/blueprint object. ``route`` (Flask) takes methods= kwarg; the verb
# methods (FastAPI/Flask 2.x shortcuts) imply the method from the name.
_VERB_DECORATORS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "head": "HEAD",
    "options": "OPTIONS",
}
# Django URL-declaring callables inside a urlpatterns list.
_DJANGO_ROUTE_FUNCS = {"path", "re_path", "url"}


@dataclass
class Route:
    """One HTTP route bound to a handler symbol."""

    method: str  # "" = any/unknown (Flask route without methods=, Django)
    pattern: str
    handler: str  # the view symbol/function name the route dispatches to
    file: str
    line: int
    # Function names that ARE this handler (for binding a finding whose
    # enclosing function matches). For decorator routes this is the
    # decorated function; for Django it's the final component of the view
    # symbol, after the urlconf's imports resolve it (`from .views import
    # show as v; path("x", v)` binds `show`).
    handler_func: str = ""
    # Django only: the dotted modules (relative to the scan root) the view
    # symbol may be defined in, resolved through the urlconf's imports
    # (`from app.views import a; path("x", a.search)` -> "app.views.a").
    # A bare view the urlconf does not import is its own module's, or a
    # star import's. Empty for a decorator route, whose handler is the
    # decorated def in `file` itself. Not part of `as_dict`: it locates the
    # handler, it is not reported.
    handler_modules: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "pattern": self.pattern,
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class RouteTable:
    """All routes found in a file, indexed for cheap binding."""

    routes: list[Route] = field(default_factory=list)
    # function-name → Route, for binding a finding by its enclosing def.
    by_func: dict[str, Route] = field(default_factory=dict)
    # function-name → every Route with that handler name, in the order added.
    # Several views share a name across modules (`search` in two apps), so
    # the binding must pick the one whose handler is the def being visited.
    all_by_func: dict[str, list[Route]] = field(default_factory=dict)

    def add(self, route: Route) -> None:
        self.routes.append(route)
        if route.handler_func:
            # First declaration wins if a function is decorated twice; the
            # taint binding only needs *a* route, not all of them.
            self.by_func.setdefault(route.handler_func, route)
            self.all_by_func.setdefault(route.handler_func, []).append(route)

    def for_function(self, func_name: str) -> Route | None:
        return self.by_func.get(func_name)

    def routes_for_function(self, func_name: str) -> list[Route]:
        """Every route whose handler is named `func_name`, first added first.
        The name alone does not identify the def: the caller checks which
        route, if any, actually points at it."""
        return self.all_by_func.get(func_name, [])


def extract_routes(source: str, rel_path: str) -> RouteTable:
    """Parse `source` and return its RouteTable. Returns an empty table on
    syntax errors (a file we can't parse contributes no routes — the taint
    analyzer already guards parsing separately)."""
    table = RouteTable()
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError, ValueError):
        # audit #18: a file we can't parse (or that trips the recursion limit /
        # "too many nested" guard) contributes no routes — never aborts.
        return table

    try:
        _DecoratorRouteVisitor(table, rel_path).visit(tree)
        _DjangoUrlpatternsVisitor(table, rel_path, _ImportScope(tree, rel_path)).visit(tree)
    except RecursionError:
        return table
    return table


def _module_name(rel_path: str) -> tuple[str, str]:
    """`(module, package)` dotted names of a file at `rel_path` under the scan
    root: `app/urls.py` -> ("app.urls", "app"), `app/__init__.py` ->
    ("app", "app"), `urls.py` -> ("urls", "")."""
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    if not parts:
        return "", ""
    parts[-1] = parts[-1].removesuffix(".py")
    if parts[-1] == "__init__":
        parts = parts[:-1]
        return ".".join(parts), ".".join(parts)
    return ".".join(parts), ".".join(parts[:-1])


class _ImportScope:
    """What each imported name in one file refers to, as a dotted path from
    the scan root. Relative imports resolve against the file's own package;
    one that climbs above the scan root resolves to nothing."""

    def __init__(self, tree: ast.AST, rel_path: str) -> None:
        self.module, self.package = _module_name(rel_path)
        self.names: dict[str, str] = {}
        self.star_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.names[alias.asname] = alias.name
                    else:
                        # `import a.b` binds `a`, and `a.b.f` reads through it.
                        top = alias.name.split(".", 1)[0]
                        self.names[top] = top
            elif isinstance(node, ast.ImportFrom):
                base = self._from_base(node)
                if base is None:
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        self.star_modules.append(base)
                        continue
                    target = f"{base}.{alias.name}" if base else alias.name
                    self.names[alias.asname or alias.name] = target

    def _from_base(self, node: ast.ImportFrom) -> str | None:
        if not node.level:
            return node.module or None
        package = self.package.split(".") if self.package else []
        climb = node.level - 1
        if climb > len(package):
            return None
        base = package[: len(package) - climb]
        if node.module:
            base += node.module.split(".")
        return ".".join(base)

    def resolve_view(self, handler: str) -> tuple[str, tuple[str, ...]]:
        """`(function name, candidate modules)` for a view symbol written as
        `handler` in this file. An imported head resolves through its import;
        a dotted symbol with an unknown head is taken as written; a bare name
        nothing imports is defined here or comes from a star import."""
        head, _, rest = handler.partition(".")
        if head in self.names:
            full = self.names[head] + (f".{rest}" if rest else "")
        elif rest:
            full = handler
        else:
            return handler, (self.module, *self.star_modules)
        module, _, func = full.rpartition(".")
        return func, ((module,) if module else ())


def _str_const(node: ast.AST) -> str | None:
    """Return the string value of a literal node, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted name for an attribute/name expression
    (views.get_user → 'views.get_user', get_user → 'get_user')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class _DecoratorRouteVisitor(ast.NodeVisitor):
    """Binds Flask/FastAPI decorator routes to their decorated function."""

    def __init__(self, table: RouteTable, rel_path: str) -> None:
        self.table = table
        self.rel = rel_path

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._handle(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._handle(node)
        self.generic_visit(node)

    def _handle(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            if not isinstance(deco.func, ast.Attribute):
                continue
            attr = deco.func.attr  # e.g. "route", "get", "post"
            method = ""
            if attr in _VERB_DECORATORS:
                method = _VERB_DECORATORS[attr]
            elif attr != "route":
                continue  # not a routing decorator we recognise
            # First positional arg is the URL pattern.
            if not deco.args:
                continue
            pattern = _str_const(deco.args[0])
            if pattern is None:
                continue
            # Flask: methods=["POST", ...] kwarg overrides the default.
            if attr == "route":
                method = _flask_methods(deco) or method
            self.table.add(
                Route(
                    method=method,
                    pattern=pattern,
                    handler=node.name,
                    file=self.rel,
                    line=deco.lineno,
                    handler_func=node.name,
                )
            )


def _flask_methods(call: ast.Call) -> str:
    """Extract the first HTTP method from a Flask route's methods= kwarg,
    or '' when absent. We only surface one method for the binding label;
    the full set isn't needed for v1 proof."""
    for kw in call.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for elt in kw.value.elts:
                m = _str_const(elt)
                if m:
                    return m.upper()
    return ""


class _DjangoUrlpatternsVisitor(ast.NodeVisitor):
    """Extracts path()/re_path()/url() routes from Django urlconf files.

    Binds each to the *final component* of the view symbol (views.get_user
    → 'get_user'), which is what the taint finding's enclosing function name
    will match when the view lives in this project."""

    def __init__(self, table: RouteTable, rel_path: str, imports: _ImportScope) -> None:
        self.table = table
        self.rel = rel_path
        self.imports = imports

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        name = (
            func.id
            if isinstance(func, ast.Name)
            else (func.attr if isinstance(func, ast.Attribute) else "")
        )
        if name in _DJANGO_ROUTE_FUNCS and len(node.args) >= 2:
            pattern = _str_const(node.args[0])
            view = node.args[1]
            handler = _dotted_name(view)
            # Skip include() and class-based .as_view() — v1 binds plain
            # function views only (the common case for the ICP).
            if pattern is not None and handler and not _is_include(view):
                func_name, modules = self.imports.resolve_view(handler)
                # Strip a trailing .as_view for CBVs so the label is clean,
                # though we won't bind a finding to it (no matching def name).
                self.table.add(
                    Route(
                        method="",  # Django path() doesn't pin a method
                        pattern=pattern,
                        handler=handler,
                        file=self.rel,
                        line=node.lineno,
                        handler_func=func_name,
                        handler_modules=modules,
                    )
                )
        self.generic_visit(node)


def _is_include(node: ast.AST) -> bool:
    """True when the view arg is an include(...) call (nested urlconf) we
    don't follow in v1."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "include"
    )
