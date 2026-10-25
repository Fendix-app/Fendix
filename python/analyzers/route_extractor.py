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
from dataclasses import dataclass, field, replace


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
# Django callables whose pattern is a regular expression, not route syntax.
_DJANGO_REGEX_FUNCS = {"re_path", "url"}
# Import roots that say which framework a decorator route belongs to.
# Quart and Sanic share Flask's model: a handler receives only the URL
# variables its pattern names. Django Ninja reads parameters like FastAPI.
_FASTAPI_ROOTS = {"fastapi", "starlette", "ninja"}
_FLASK_ROOTS = {"flask", "quart", "sanic"}
# `@mock.patch("os.getenv")` looks like a PATCH route decorator: a receiver
# imported from one of these modules is never a route.
_MOCK_MODULES = {"mock", "unittest.mock"}


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
    # Which framework declared the route: "django" for a urlconf entry, and
    # "fastapi" or "flask" for a decorator route, from the file's imports,
    # then the pattern's syntax (`{x}` / `<x>`), then `.route(...)` (Flask),
    # then the project's dominant framework (`resolve_frameworks`). "" when
    # nothing tells. Flask and Django pass a handler only the URL variables
    # their pattern names; FastAPI passes query parameters too.
    framework: str = ""
    # Django only: the view symbol's head resolved through one of the
    # urlconf's imports, or is a bare name (defined in the urlconf or star
    # imported). False for a head nothing binds (`self.handler`, a local),
    # whose module is taken as written and is never widened by a fallback.
    handler_resolved: bool = False
    # Django only: the pattern is a regular expression (`re_path`, `url`).
    regex: bool = False

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

    def resolve_views(
        self, summaries: list[ModuleSummary], scan_root_parts: tuple[str, ...] = ()
    ) -> None:
        """Point each Django route at the module that defines its view, once
        every file of the project is summarised.

        - A resolved module that defines the view as a module-level def keeps
          it.
        - Otherwise ONE re-export hop is followed in that module's file (its
          ``__init__.py`` for a package): ``from .items import show`` (with
          ``as`` renaming) or ``from .items import *``. A renamed view is
          indexed under its real name too.
        - When no scanned file is the resolved module, the scan root may sit
          inside the package: `app.views` is then the scanned module `views`
          when the scan root is a directory named `app`. A proper trailing
          suffix of the module that is a scanned module stands in for it, but
          only when the prefix it drops is the directories the scan root sits
          in (`scan_root_parts`, the root's absolute path). Nothing stands in
          for a view whose head nothing imports (`self.handler`), or for a
          module of a package outside the scan (`django.views.static`): such a
          route binds no def.
        """
        # Every dotted suffix of each file's module -> the files it names, so
        # `app.views` finds `backend/app/views.py` (module `backend.app.views`)
        # as `_module_matches_file` would.
        by_suffix: dict[str, list[ModuleSummary]] = {}
        by_module: dict[str, list[ModuleSummary]] = {}
        for summary in summaries:
            parts = summary.module.split(".") if summary.module else []
            for i in range(len(parts)):
                by_suffix.setdefault(".".join(parts[i:]), []).append(summary)
            by_module.setdefault(summary.module, []).append(summary)
        for route in list(self.routes):
            if route.framework != "django" or not route.handler_modules:
                continue
            found = _match_modules(route, route.handler_modules, by_suffix)
            if found is None and route.handler_resolved:
                stand_ins = tuple(
                    suffix
                    for module in route.handler_modules
                    for suffix in _stand_in_modules(module, by_module, scan_root_parts)
                )
                if stand_ins:
                    route.handler_modules = stand_ins
                    found = _match_modules(route, stand_ins, by_module)
            if found is None:
                continue
            route.handler_modules = tuple(
                dict.fromkeys(found.pop(route.handler_func, route.handler_modules))
            )
            for func, modules in found.items():
                renamed = replace(route, handler_func=func, handler_modules=tuple(dict.fromkeys(modules)))
                self.all_by_func.setdefault(func, []).append(renamed)

    def resolve_frameworks(self, summaries: list[ModuleSummary]) -> None:
        """Give each decorator route whose framework its own file does not
        show the project's dominant framework: the one most scanned files
        import (`ModuleSummary.framework`). A tie, or a project that imports
        none, leaves it unknown (treated as FastAPI)."""
        counts: dict[str, int] = {}
        for summary in summaries:
            if summary.framework:
                counts[summary.framework] = counts.get(summary.framework, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
        if not ranked or (len(ranked) > 1 and ranked[0][1] == ranked[1][1]):
            return
        dominant = ranked[0][0]
        for route in self.routes:
            if not route.framework:
                route.framework = dominant


def _match_modules(
    route: Route, modules: tuple[str, ...], index: dict[str, list[ModuleSummary]]
) -> dict[str, list[str]] | None:
    """`{function: [modules]}` the route's view is found as in the files
    `index` maps `modules` to (one re-export hop), or None when no file is
    one of the modules."""
    matched = False
    targets: dict[str, list[str]] = {}
    for module in modules:
        for summary in index.get(module, []):
            matched = True
            found = _view_targets(summary, route.handler_func)
            for target_module, func in found or [(module, route.handler_func)]:
                targets.setdefault(func, []).append(target_module)
    return targets if matched else None


def _stand_in_modules(
    module: str, by_module: dict[str, list[ModuleSummary]], scan_root_parts: tuple[str, ...]
) -> list[str]:
    """The scanned modules that are a proper trailing suffix of `module` and
    whose dropped prefix is the trailing directories of the scan root."""
    parts = module.split(".")
    found = []
    for k in range(1, len(parts)):
        prefix, suffix = parts[:k], ".".join(parts[k:])
        if suffix in by_module and tuple(scan_root_parts[-k:]) == tuple(prefix):
            found.append(suffix)
    return found


@dataclass(frozen=True)
class ModuleSummary:
    """What `RouteTable.resolve_views` needs from one file: its dotted module
    (relative to the scan root), its module-level defs, and its imports."""

    module: str
    defs: frozenset[str]
    names: dict[str, str]
    star_modules: tuple[str, ...]
    # "fastapi", "flask" or "" from the file's imports, for
    # `RouteTable.resolve_frameworks`.
    framework: str = ""


def _view_targets(summary: ModuleSummary, func: str) -> list[tuple[str, str]]:
    """`(module, function)` pairs the view `func` of `summary`'s module may
    be: the module itself when it defines `func`, else one re-export hop."""
    if func in summary.defs:
        return [(summary.module, func)]
    found = []
    target = summary.names.get(func, "")
    if "." in target:
        module, _, real = target.rpartition(".")
        found.append((module, real))
    found += [(star, func) for star in summary.star_modules]
    return found


def extract_routes(source: str, rel_path: str) -> RouteTable:
    """Parse `source` and return its RouteTable. Returns an empty table on
    syntax errors (a file we can't parse contributes no routes — the taint
    analyzer already guards parsing separately)."""
    return scan_module(source, rel_path)[0]


def scan_module(source: str, rel_path: str) -> tuple[RouteTable, ModuleSummary | None]:
    """Parse `source` once: its RouteTable, and the ModuleSummary a project
    pass hands to `RouteTable.resolve_views` (None when it does not parse)."""
    table = RouteTable()
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError, ValueError):
        # audit #18: a file we can't parse (or that trips the recursion limit /
        # "too many nested" guard) contributes no routes — never aborts.
        return table, None

    try:
        imports = _ImportScope(tree, rel_path)
        _DecoratorRouteVisitor(table, rel_path, imports).visit(tree)
        _DjangoUrlpatternsVisitor(table, rel_path, imports).visit(tree)
        summary = ModuleSummary(
            module=imports.module,
            defs=frozenset(_module_level_defs(tree)),
            names=dict(imports.names),
            star_modules=tuple(imports.star_modules),
            framework=imports.framework(),
        )
    except RecursionError:
        return RouteTable(), None
    return table, summary


def _module_level_defs(tree: ast.AST):
    """Yield the names of the defs made in the module's own scope: its body
    and top-level `if`/`try`/`with` blocks, never a class or def body."""
    stack = list(getattr(tree, "body", []))
    while stack:
        stmt = stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield stmt.name
        elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.AsyncWith)) or (
            type(stmt).__name__ == "TryStar"
        ):
            stack += getattr(stmt, "body", []) + getattr(stmt, "orelse", [])
            stack += getattr(stmt, "finalbody", [])
            for handler in getattr(stmt, "handlers", []):
                stack += handler.body


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

    def resolve(self, dotted: str) -> str:
        """`dotted` with its head resolved through this file's imports
        (`mock.patch` -> `unittest.mock.patch`), or as written."""
        head, _, rest = dotted.partition(".")
        if head not in self.names:
            return dotted
        return self.names[head] + (f".{rest}" if rest else "")

    def roots(self) -> set[str]:
        """The top-level package of every module this file imports from."""
        return {t.split(".", 1)[0] for t in (*self.names.values(), *self.star_modules)}

    def framework(self) -> str:
        """"fastapi" or "flask" when this file imports from one of their
        families (`_FASTAPI_ROOTS`, `_FLASK_ROOTS`), else ""."""
        roots = self.roots()
        if roots & _FASTAPI_ROOTS:
            return "fastapi"
        return "flask" if roots & _FLASK_ROOTS else ""

    def resolve_view(self, handler: str) -> tuple[str, tuple[str, ...], bool]:
        """`(function name, candidate modules, resolved)` for a view symbol
        written as `handler` in this file. An imported head resolves through
        its import; a bare name nothing imports is defined here or comes from
        a star import. A dotted symbol whose head nothing binds
        (`self.handler`) is taken as written, and `resolved` is False."""
        head, _, rest = handler.partition(".")
        if head in self.names:
            full = self.names[head] + (f".{rest}" if rest else "")
        elif rest:
            module, _, func = handler.rpartition(".")
            return func, (module,), False
        else:
            return handler, (self.module, *self.star_modules), True
        module, _, func = full.rpartition(".")
        return func, ((module,) if module else ()), True


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

    def __init__(self, table: RouteTable, rel_path: str, imports: _ImportScope) -> None:
        self.table = table
        self.rel = rel_path
        self.imports = imports
        self.framework = imports.framework()

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
            # `@mock.patch("os.getenv")` is not a PATCH route.
            receiver = self.imports.resolve(_dotted_name(deco.func.value))
            if receiver in _MOCK_MODULES or receiver.startswith("unittest.mock."):
                continue
            # First positional arg is the URL pattern. Flask and Starlette
            # require it to start with "/"; FastAPI allows "" under a prefix.
            if not deco.args:
                continue
            pattern = _str_const(deco.args[0])
            if pattern is None or (pattern and not pattern.startswith("/")):
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
                    framework=self._framework(pattern, attr),
                )
            )

    def _framework(self, pattern: str, attr: str) -> str:
        """The file's framework from its imports; else `{x}` (Starlette) or
        `<x>` (Flask) in the pattern; else `.route(...)`, which is Flask's."""
        if self.framework:
            return self.framework
        if "{" in pattern:
            return "fastapi"
        if "<" in pattern or attr == "route":
            return "flask"
        return ""


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
                func_name, modules, resolved = self.imports.resolve_view(handler)
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
                        framework="django",
                        regex=name in _DJANGO_REGEX_FUNCS,
                        handler_resolved=resolved,
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
