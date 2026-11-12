"""Reaching definitions of one local name across one function body.

Why this exists (redteam3-py-01). A guard on a name is a statement about the
VALUE the name held when the guard ran::

    name = request.args["f"]
    if ".." in name or os.path.isabs(name):
        abort(400)
    name = unquote(name)          # a new value: the guard says nothing about it
    open(name)

The analyzer used to answer "is `name` guarded?" with per-guard rebind checks
(or none at all, which is how a decode or a concatenation after a traversal
guard hid a path traversal). This module replaces them with one rule:

    a guard protects a use only if every definition of the name that reaches
    the use also reached the guard.

`ReachingDefs(func, name)` runs a forward dataflow over the function's
statements and records, for every read (`ast.Name` with a Load context) of
`name`, the set of definitions that may supply its value. A definition is the
node that binds the name: an assignment, augmented assignment or annotated
assignment target, a `for` or `with` target, a walrus, an `except ... as`
name, an import alias, a `def` or `class`, a `match` capture, a `del`, or the
function entry (`ENTRY`: the parameter, or whatever the name held on entry).

The pass is conservative in the direction that matters for a security tool:
whenever control flow is uncertain it ADDS definitions to the set a use can
see (an exception can leave a `try` or a `with` at any point, a loop's body
may run again, a short-circuit operand may not run), which can only
invalidate a guard, never extend one. A name the function declares `global`
or `nonlocal`, anywhere, including in a nested def, is `volatile`: another
scope can change it at any time, so no guard on it is proven. So is a free name,
one the function neither takes as a parameter nor binds itself: a call between
the guard and the use can rebind a module global.

What it does not model: a call that rebinds the name through `exec`,
`globals()` or `locals()` (the same limit as every other check here), and a
nested def or lambda READING the name (those reads are not recorded; callers
fall back to the conservative "nothing binds the name after the guard" answer).
"""

from __future__ import annotations

import ast
from typing import Iterable, Optional

# The value the name holds when the function starts: the parameter's value, or
# the enclosing/module binding of a free name. One token per analysis.
ENTRY = ("entry",)

# Statements that end a block: nothing after them in the block runs.
_EMPTY: frozenset = frozenset()

# A loop body is re-run until the state at the loop head stops growing. Every
# definition is a node, so the lattice is finite and the iteration converges
# in a handful of rounds; the cap only guards a pathological nest, and hitting
# it marks the analysis `volatile` (no guard proven).
_MAX_LOOP_ROUNDS = 12


class _Loop:
    """Break and continue states collected for the innermost open loop."""

    __slots__ = ("breaks", "continues")

    def __init__(self) -> None:
        self.breaks: list[frozenset] = []
        self.continues: list[frozenset] = []


def _join(*states: frozenset) -> frozenset:
    out: frozenset = _EMPTY
    for s in states:
        out = out | s
    return out


class ReachingDefs:
    """Reaching definitions of `name` in `func` (a def; its body is walked,
    nested defs and lambdas are not).

    `defs_at(node)` is the frozenset of definitions that may supply the value
    of the Load `node` (a `ast.Name`), or None when `node` was not reached
    (it is not in this function's own scope, for instance). A definition is an
    AST node, or `ENTRY`.
    """

    def __init__(self, func: ast.AST, name: str) -> None:
        self.name = name
        self.func = func
        self._at: dict[int, frozenset] = {}
        # Every definition node of the name in the function body.
        self._positions: dict[object, tuple[int, int]] = {}
        self._exc: list[set] = []
        self._loops: list[_Loop] = []
        self._shadow = 0
        self.volatile = self._declared_shared(func, name)
        self._block(getattr(func, "body", []), frozenset({ENTRY}))
        if not self._positions and not self._is_parameter(func, name):
            # A free name (a module global, or a variable of an enclosing
            # function): any call between the guard and the use can rebind it
            # (`global` / `nonlocal` in another function), and nothing here can
            # see that.
            self.volatile = True

    # ---- queries ------------------------------------------------------

    def defs_at(self, node: ast.AST) -> Optional[frozenset]:
        """The definitions that may supply the value `node` reads, or None
        when this analysis never reached `node`."""
        return self._at.get(id(node))

    @property
    def definitions(self) -> list:
        """Every definition node of the name in the function body (ENTRY not
        included)."""
        return list(self._positions)

    # ---- set-up -------------------------------------------------------

    @staticmethod
    def _is_parameter(func: ast.AST, name: str) -> bool:
        args = getattr(func, "args", None)
        if args is None:
            return False
        every = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            every.append(args.vararg)
        if args.kwarg is not None:
            every.append(args.kwarg)
        return any(a.arg == name for a in every)

    @staticmethod
    def _declared_shared(func: ast.AST, name: str) -> bool:
        for node in ast.walk(func):
            if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
                return True
        return False

    # ---- definitions --------------------------------------------------

    def _define(self, node: ast.AST) -> frozenset:
        self._positions.setdefault(
            node,
            (getattr(node, "lineno", 0) or 0, getattr(node, "col_offset", 0) or 0),
        )
        new = frozenset({node})
        for acc in self._exc:
            acc.add(new)
        return new

    def _load(self, node: ast.Name, state: frozenset) -> None:
        key = id(node)
        self._at[key] = self._at.get(key, _EMPTY) | state

    # ---- expressions --------------------------------------------------

    def _expr(self, node: Optional[ast.AST], state: frozenset) -> frozenset:
        if node is None:
            return state
        if isinstance(node, ast.Name):
            if node.id == self.name and not self._shadow:
                if isinstance(node.ctx, ast.Load):
                    self._load(node, state)
                else:
                    return self._define(node)
            return state
        if isinstance(node, ast.NamedExpr):
            state = self._expr(node.value, state)
            # A walrus binds in the enclosing function even inside a
            # comprehension, so it is a definition whatever shadows the name.
            if isinstance(node.target, ast.Name) and node.target.id == self.name:
                return self._define(node.target)
            return state
        if isinstance(node, ast.BoolOp):
            outs = []
            for value in node.values:
                state = self._expr(value, state)
                outs.append(state)
            return _join(*outs)
        if isinstance(node, ast.IfExp):
            state = self._expr(node.test, state)
            return _join(self._expr(node.body, state), self._expr(node.orelse, state))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._comprehension(node, state)
        if isinstance(node, ast.Lambda):
            # The body runs later, in a scope of its own: not recorded. The
            # defaults run now.
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                state = self._expr(default, state)
            return state
        for child in ast.iter_child_nodes(node):
            state = self._expr(child, state)
        return state

    def _comprehension(self, node: ast.AST, state: frozenset) -> frozenset:
        """A comprehension may run its body zero times. If one of its `for`
        targets is the tracked name, reads inside it are that variable, not
        ours (a walrus inside still binds ours)."""
        binds = any(
            isinstance(n, ast.Name) and n.id == self.name and isinstance(n.ctx, ast.Store)
            for gen in node.generators
            for n in ast.walk(gen.target)
        )
        before = state
        generators = node.generators
        # The first iterable is evaluated in the enclosing scope.
        state = self._expr(generators[0].iter, state)
        if binds:
            self._shadow += 1
        try:
            for index, gen in enumerate(generators):
                if index:
                    state = self._expr(gen.iter, state)
                for cond in gen.ifs:
                    state = self._expr(cond, state)
            if isinstance(node, ast.DictComp):
                state = self._expr(node.key, state)
                state = self._expr(node.value, state)
            else:
                state = self._expr(node.elt, state)
        finally:
            if binds:
                self._shadow -= 1
        return _join(before, state)

    # ---- statements ---------------------------------------------------

    def _block(self, body: Iterable[ast.stmt], state: frozenset) -> frozenset:
        for stmt in body:
            state = self._stmt(stmt, state)
        return state

    def _stmt(self, node: ast.stmt, s: frozenset) -> frozenset:  # noqa: C901
        if isinstance(node, ast.Assign):
            s = self._expr(node.value, s)
            for target in node.targets:
                s = self._expr(target, s)
            return s
        if isinstance(node, ast.AugAssign):
            s = self._expr(node.value, s)
            return self._expr(node.target, s)
        if isinstance(node, ast.AnnAssign):
            if node.value is None:
                return s
            s = self._expr(node.value, s)
            return self._expr(node.target, s)
        if isinstance(node, ast.If):
            s = self._expr(node.test, s)
            return _join(self._block(node.body, s), self._block(node.orelse, s))
        if isinstance(node, (ast.For, ast.AsyncFor)):
            return self._for(node, s)
        if isinstance(node, ast.While):
            return self._while(node, s)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            return self._with(node, s)
        if isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            return self._try(node, s)
        if type(node).__name__ == "Match":
            return self._match(node, s)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                s = self._expr(dec, s)
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                s = self._expr(default, s)
            return self._define(node) if node.name == self.name else s
        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                s = self._expr(dec, s)
            for base in node.bases:
                s = self._expr(base, s)
            for kw in node.keywords:
                s = self._expr(kw.value, s)
            return self._define(node) if node.name == self.name else s
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == self.name:
                    return self._define(node)
            return s
        if isinstance(node, (ast.Return, ast.Raise)):
            for child in ast.iter_child_nodes(node):
                s = self._expr(child, s)
            return _EMPTY
        if isinstance(node, ast.Break):
            if self._loops:
                self._loops[-1].breaks.append(s)
            return _EMPTY
        if isinstance(node, ast.Continue):
            if self._loops:
                self._loops[-1].continues.append(s)
            return _EMPTY
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass)):
            return s
        # Expr, Assert, Delete and anything else: read children in order. A
        # `del name` target is a Name with a Del context, a definition.
        for child in ast.iter_child_nodes(node):
            s = self._expr(child, s)
        return s

    def _for(self, node, s: frozenset) -> frozenset:
        s = self._expr(node.iter, s)
        loop = _Loop()
        self._loops.append(loop)
        head = s
        for _ in range(_MAX_LOOP_ROUNDS):
            cur = self._expr(node.target, head)
            out = self._block(node.body, cur)
            new_head = _join(s, out, *loop.continues)
            if new_head == head:
                break
            head = new_head
        else:
            self.volatile = True
        self._loops.pop()
        # The iterator is exhausted at the head; the else branch runs then.
        return _join(self._block(node.orelse, head), *loop.breaks)

    def _while(self, node: ast.While, s: frozenset) -> frozenset:
        loop = _Loop()
        self._loops.append(loop)
        head = s
        tested = s
        for _ in range(_MAX_LOOP_ROUNDS):
            tested = self._expr(node.test, head)
            out = self._block(node.body, tested)
            new_head = _join(s, out, *loop.continues)
            if new_head == head:
                break
            head = new_head
        else:
            self.volatile = True
        self._loops.pop()
        forever = isinstance(node.test, ast.Constant) and bool(node.test.value)
        exits = self._block(node.orelse, tested) if not forever else _EMPTY
        return _join(exits, *loop.breaks)

    def _with(self, node, s: frozenset) -> frozenset:
        for item in node.items:
            s = self._expr(item.context_expr, s)
            if item.optional_vars is not None:
                s = self._expr(item.optional_vars, s)
        # A context manager may swallow an exception, so flow can continue
        # after the `with` from any point of its body.
        acc: set = {s}
        self._exc.append(acc)
        try:
            end = self._block(node.body, s)
        finally:
            self._exc.pop()
        return _join(end, *acc)

    def _try(self, node, s: frozenset) -> frozenset:
        body_acc: set = {s}
        self._exc.append(body_acc)
        try:
            body_end = self._block(node.body, s)
        finally:
            self._exc.pop()
        raised = _join(*body_acc)

        # Handlers and the else branch: an exception raised there goes to the
        # finally clause (or out), so their intermediate states feed it too.
        rest_acc: set = set()
        self._exc.append(rest_acc)
        try:
            outs = [self._block(node.orelse, body_end)]
            for handler in node.handlers:
                hs = self._expr(handler.type, raised)
                if handler.name == self.name:
                    hs = self._define(handler)
                outs.append(self._block(handler.body, hs))
        finally:
            self._exc.pop()
        merged = _join(*outs)
        if not node.finalbody:
            return merged
        # `finally` runs on the normal path and on every exceptional one.
        # Reads in it see both; the state that continues is the normal one.
        self._block(node.finalbody, _join(merged, raised, *rest_acc))
        return self._block(node.finalbody, merged)

    def _match(self, node, s: frozenset) -> frozenset:
        s = self._expr(node.subject, s)
        outs: list[frozenset] = []
        partial: list[frozenset] = []
        exhaustive = False
        for case in node.cases:
            cs = self._pattern(case.pattern, s)
            partial.append(cs)
            if case.guard is not None:
                cs = self._expr(case.guard, cs)
            outs.append(self._block(case.body, cs))
            if case.guard is None and self._irrefutable(case.pattern):
                exhaustive = True
        if not exhaustive:
            # No case matched: control continues, and a partly matched
            # pattern may already have bound its captures.
            outs.append(s)
            outs.extend(partial)
        return _join(*outs)

    def _pattern(self, pattern: ast.AST, s: frozenset) -> frozenset:
        for sub in ast.walk(pattern):
            kind = type(sub).__name__
            if kind in ("MatchAs", "MatchStar") and sub.name == self.name:
                s = self._define(sub)
            elif kind == "MatchMapping" and sub.rest == self.name:
                s = self._define(sub)
            elif kind == "MatchValue":
                s = self._expr(sub.value, s)
        return s

    @staticmethod
    def _irrefutable(pattern: ast.AST) -> bool:
        return type(pattern).__name__ == "MatchAs" and pattern.pattern is None
