"""AST analyzer — Python and JavaScript AST-based security analysis.

Performs deeper analysis than regex by parsing the abstract syntax tree
to detect security-relevant patterns like unsafe eval, exec, SQL construction,
and dangerous subprocess usage.

JavaScript analysis uses regex-backed heuristics since a full JS AST parser
is not a Python stdlib dependency.
"""

from __future__ import annotations

import ast
import bisect
import heapq
import os
import posixpath
import re
import sys
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Literal, Mapping

from analyzers import status_detail
from analyzers.interpreter import syntax_reason
from analyzers.reaching_defs import ENTRY, ReachingDefs
from analyzers.scope_evidence import (
    JS_ESCAPE_UNREADABLE,
    SYMLINK_REASON,
    NotRegularFile,
    SourceWalk,
    UndecodableSource,
    is_regular_file,
    js_identifier_escape,
    read_python_source,
    read_regular,
)

_MAX_FILE_BYTES = 1_048_576  # 1 MB

# What the analyzer leaves out of its scope (D5-2; `analyzers/scope_evidence.py`):
# a symlink, which is not followed and is said so (F-L12), and the Git metadata
# directory at the scan root when its layout is real. Nothing is left out for a
# file or directory name, a banner or header, minification or any other look of
# the code: every in-scope source file at or below the size cap is analysed, and
# one the analyzer could not read is recorded as lost evaluation with its reason.
# Compared in lower case (D6'): `APP.JS` and `Server.Py` are source files too; a
# file's letter case is a name, not evidence that it is not code.
_SOURCE_SUFFIXES_JS = frozenset({".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts", ".cts"})


def _read_python_source(path: Path) -> str:
    """The text of a Python source file as CPython runs it (R5-01, R6-E1, R6-E6):
    the shared PEP 263 predicate (`scope_evidence.python_source_encoding`) reads
    the cookie on line 1 or 2 with CPython's line model (\\r\\n, \\r, \\n; no byte
    limit; `python -x`), resolves the name through the generated codec table, and
    the file is decoded with the codec CPython applies. A UTF-8 byte-order mark is
    dropped (redteam2-py-01). A name only a run-time registration could supply, a
    cookie only `python -x` reads, or a foreign file that does not decode raises
    `UndecodableSource`, an OSError every caller records as lost evaluation: the
    old UTF-8 fallback analysed text that was not the program and read ok. No
    codec error ever escapes (a `# coding: idna` or `rot13` file used to abort
    the whole tree). Raises OSError when the file cannot be read."""
    return read_python_source(path)


def _os_error_reason(exc: OSError) -> str:
    """A short reason naming why a path could not be read."""
    if isinstance(exc, NotRegularFile):
        return _NOT_REGULAR_REASON
    if isinstance(exc, UndecodableSource):
        return exc.reason
    return f"unreadable: {type(exc).__name__}"

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

# C4B-23 bounds: how many names of one function are checked for a tainted path
# a last binding hides, and how many lost-evaluation notes one file lists.
_MAX_AMBIGUITY_NAMES = 200
_MAX_AMBIGUITY_NOTES = 20

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
        # The raw-text form, and the FLOOR of the rule (OR-88): every line it
        # matches is reported. `_analyze_js_heuristic` reads the file as tokens
        # (`_js_eval_lines`, E-1) only to decide the GRADE: a call a complete
        # reading puts in code keeps this HIGH/HIGH, every other match is reported
        # at `_JS_EVAL_UNCONFIRMED_GRADE`.
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
        # The opening backtick must not directly follow an identifier, `.`,
        # `)` or `]`: `sql`...${id}``, `prisma.$queryRaw`...${id}`` and
        # `Prisma.sql`...`` are TAGGED templates. The tag receives the strings
        # and the values apart and binds the values as parameters (postgres.js,
        # slonik, Prisma), so they are not string-built SQL.
        #
        # Linear on a long line: the lookahead finds the FIRST keyword in the
        # template and `\1` consumes it atomically, so a template with
        # thousands of keywords and no `${` is not retried at each one (a
        # keyword after the first cannot reach a `${` the first did not).
        re.compile(
            r"(?<![\w$.)\]])`(?=([^`]*?(?:SELECT|INSERT|UPDATE|DELETE)))\1[^`]*\$\{"
        ),
        "HIGH",
        "HIGH",
        "CWE-89",
    ),
]


# `${expr}` placeholders of one template literal.
_JS_TEMPLATE_EXPR = re.compile(r"\$\{([^}]*)\}")
_JS_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*\Z")


def _js_module_string_constants(source: str) -> set[str]:
    """Names declared at module level as ``const NAME = '<string literal>'``.

    Only a declaration that starts in column 0 counts (``export`` allowed, a
    ``: string`` annotation allowed): an indented ``const`` sits inside a
    function or block and may shadow, and ``let``/``var`` can be reassigned.
    """
    return {
        m.group(1)
        for m in re.finditer(
            r"^(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?="
            r"\s*(?:'[^'\\\n]*'|\"[^\"\\\n]*\"|`[^`$\\\n]*`)\s*;?\s*(?://.*)?$",
            source,
            re.MULTILINE,
        )
    }


def _js_template_only_constants(
    line: str, source: str, consts: set[str] | None = None
) -> bool:
    """True when every ``${...}`` of the SQL template on ``line`` is a bare
    identifier that ``source`` declares as a module-level constant string.

    Such a template cannot carry user input. A call, a member access, an
    expression, an undeclared name or a ``let``/``var`` keeps the finding.
    """
    if consts is None:
        consts = _js_module_string_constants(source)
    checked = False
    for match in re.finditer(r"(?<![\w$.)\]])`([^`]*)(?:`|$)", line):
        body = match.group(1)
        if not re.search(r"SELECT|INSERT|UPDATE|DELETE", body):
            continue
        for expr in _JS_TEMPLATE_EXPR.findall(body):
            name = expr.strip()
            if not _JS_IDENTIFIER.match(name) or name not in consts:
                return False
            checked = True
    return checked


# ---------------------------------------------------------------------------
# JS_EVAL: which `eval` sites are confirmed code (E-1, RC-9 (1a)+V2+E-1), and the
# floor under it (OR-88)
# ---------------------------------------------------------------------------
#
# The raw-text pattern in `_JS_PATTERNS` graded HIGH wherever `\beval\s*\(`
# appeared, and the collapse let that HIGH vouch for another rule's finding on
# the same line. `_js_eval_lines` reads the file as tokens instead, with the one
# lexer this analyzer has (there is no other JS comment/string lexer in
# `python/analyzers/`). It is a lexer, not a parser: it knows exactly enough to
# tell code from comment, string, template text and regex literal, and to read
# the few tokens around an `eval` identifier.
#
# THE FLOOR (OR-88, "the recognisers may lower a finding, never remove it"). The
# tokenizer decides only the GRADE of a site, never whether it is reported.
# Rounds 2 and 3 of independent verification each found shapes (an HTML-like
# comment, a hashbang ended by U+2028, a division after a function or class
# expression, a regex after `extends`, `default` or `for await`, `</`, JSX text
# with an apostrophe, a URL or a backtick) that made it read executed code as
# text and drop the call, where v3.7.0 reported every `eval(`. Shape-by-shape
# fixes were not converging, so the rule is structural:
#   * every line the v3.7.0 pattern `\beval\s*\(` matches is reported, always;
#   * a call a COMPLETE reading puts in code is reported at HIGH/HIGH, which can
#     corroborate textscan's finding on the same line (D20), exactly as before;
#   * every other match a complete reading puts outside code is reported at
#     `_JS_EVAL_UNCONFIRMED_GRADE` (MEDIUM/LOW): a WARN that earns no
#     deterministic-detection delta and lends no confidence to any other finding.
#     That covers a comment, a string, template or JSX text, a regex literal,
#     `$eval` and `x.eval`;
#   * when the tokenizer GIVES UP (no reading of the file completes, the readings
#     outgrow their budget, or it crashes) it has decided nothing: every raw match is
#     reported at HIGH/HIGH, as in rc.3 and v3.7.0. A budget an adversary can
#     exhaust must not be a way to lower a BLOCK (rc.4 brief, "no unsafe reduction
#     in BLOCK severity"), so a doubt reports.
# A fooled tokenizer therefore yields a WARN, never a clean scan. The accepted
# residual: crafted syntax that makes a COMPLETE reading wrong can lower a v3.7.0
# BLOCK to a WARN.
#
# What it confirms (the approved reading, additions above the floor):
#   * bare `eval(`, also `eval (x)`, `eval /* c */ (x)` and `eval` + newline + `(`;
#   * `window.eval(`, `globalThis.eval(`, `self.eval(` and `global.eval(` (Node's
#     global object; `global` is the one addition to the approved three, the
#     same indirect eval in the runtime that has no `window`);
#   * `eval?.(x)`;
#   * the indirect forms `(0, eval)(x)` and `(eval)(x)`, also on a global's
#     member: `(0, window.eval)(x)`;
#   * an identifier written with unicode escapes that spells the name
#     (`\u0065val(x)`), because the runtime reads it as `eval`.
# The forms the old pattern never matched (the indirect and the optional-call
# forms, a name split from its parenthesis, an escaped name) are reported only
# when their argument is not a single constant string: that exemption sits on top
# of the floor and never touches a site the old pattern matched.
# What it does not confirm: the word inside a comment, a string, the text of a
# template literal (code inside `${...}` IS code), a regex literal, the identifier
# `$eval`, or `.eval` on any other object. Those are the demoted sites.
#
# It reads a file the way a script is read where two readings exist. When the
# file cannot be read reliably (an unterminated comment or template, a closing
# bracket nothing opened, brackets left open at the end, or a run of unmatched
# `/` that would make the pass superlinear) the result is None and every match of
# the raw pattern is demoted. A construct with two readings that put code on
# different sides of a comment, string or regex (a `/` after `}`, `await`,
# `yield`, `of` or a postfix `!`; `<!--` and `-->`, which are comments in a script
# and code in a module) is followed both ways (`_js_eval_offsets`), and a call
# either reading puts in code is confirmed.

_JS_EVAL_GLOBALS = frozenset({"window", "globalThis", "self", "global"})
# After these keywords an expression starts, so a following `/` opens a regex.
_JS_EXPR_KEYWORDS = frozenset(
    {
        "return", "typeof", "instanceof", "in", "new", "delete", "void", "throw",
        "case", "do", "else", "yield", "await", "extends", "default",
    }
)  # fmt: skip
# `if (...)`, `while (...)`, `for (...)`: after the closing paren a statement
# starts, so a following `/` opens a regex, not a division.
_JS_CONTROL_KEYWORDS = frozenset({"if", "while", "for", "with", "switch", "catch"})
# A `{` after one of these opens a block (a function body, a class body, an
# `else` branch), not an object literal; so does a `{` after a plain name.
_JS_BLOCK_BEFORE = frozenset({")", "=>", ";", "{", "}", "", "else", "do", "try", "finally"})

# What ends a line, as `str.splitlines` counts it. Between `eval` and `(` the old
# per-line pattern could only match white space on the same line.
_JS_LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"

_JS_LEX = re.compile(
    r"(?P<ws>\s+)"
    r"|(?P<id>(?:[\w$]|\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]+\})+)"
    r"|(?P<lc>//[^\n\u2028\u2029]*)"
    r"|(?P<bc>/\*)"
    r"|(?P<sl>/)"
    # An unterminated string ends at the newline, as a syntax error would.
    r"|(?P<str>'(?:[^'\\\n]+|\\[\s\S])*'?|\"(?:[^\"\\\n]+|\\[\s\S])*\"?)"
    r"|(?P<tpl>`)"
    r"|(?P<op>\?\.(?!\d)|=>|\+\+|--|\.\.\.|[(){}\[\],;])"
    r"|(?P<other>[\s\S])"
)
# Text of a template literal up to its closing backtick or its next `${`.
_JS_TEMPLATE_TEXT = re.compile(r"(?:[^`\\$]+|\\[\s\S]|\$(?!\{))*")
# A regex literal: no newline, a `/` inside a character class does not end it.
# Single-character alternatives only, so a failed attempt backtracks linearly.
_JS_REGEX_LITERAL = re.compile(r"/(?:[^/\\\n\[]|\\[^\n]|\[(?:[^\]\\\n]|\\[^\n])*\])+/[A-Za-z]*")
_JS_ID_ESCAPE = re.compile(r"\\u(?:\{([0-9A-Fa-f]+)\}|([0-9A-Fa-f]{4}))")


def _js_unescape_identifier(text: str) -> str:
    def one(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(1) or m.group(2), 16))
        except (ValueError, OverflowError):
            return "\ufffd"

    return _JS_ID_ESCAPE.sub(one, text)


def _js_template_text_end(source: str, pos: int) -> tuple[int, bool] | None:
    """Past the text of a template literal that continues at `pos`: (index after
    the closing backtick, False), or (index after a `${`, True) when an
    expression starts. None when the template never ends."""
    end = _JS_TEMPLATE_TEXT.match(source, pos).end()
    if source.startswith("`", end):
        return end + 1, False
    if source.startswith("${", end):
        return end + 2, True
    return None


def _js_value_token(tok: str) -> bool:
    """True when the significant token `tok` (as `_js_eval_offsets` keeps it) ends
    a value: a name that is not an expression keyword, a number, a string, a
    template or regex literal, or a closing paren or bracket."""
    if tok in (")", "]", "0", '"', "`", "/re/"):
        return True
    return bool(tok) and (tok[0].isalnum() or tok[0] in "_$") and tok not in _JS_EXPR_KEYWORDS


class _JSLexState:
    """One reading of a file in progress (`_js_eval_offsets`): where it is, the
    paren and brace stacks, the three latest tokens, whether a `/` here starts a
    regex, the pending `eval` call and the offsets found so far. `force` is the
    reading to apply to the construct this state is stopped at."""

    __slots__ = (
        "i", "parens", "braces", "t1", "t2", "t3", "regex_ok", "pend", "pend_pos",
        "pend_end", "pend_prev", "pend_escaped", "hits", "force",
    )  # fmt: skip

    def __init__(self, i: int = 0) -> None:
        self.i = i
        self.parens: list[str] = []  # "g" group, "c" call or declaration, "k" control
        self.braces: list[str] = []  # "b" block, "e" object literal, "t" template expression
        # The three latest significant tokens; a literal is its marker, never text a
        # name could equal ('"', '`', '0', '/re/').
        self.t1 = self.t2 = self.t3 = ""
        self.regex_ok = True  # does a `/` here start a regex literal?
        # 1 eval reference seen, 2 after `?.`, 3 after `)` of a group; 4 after the
        # `(` of a call the old pattern did not match, 5 after that call's one string
        # literal
        self.pend = 0
        self.pend_pos = 0
        self.pend_end = 0
        self.pend_prev = ""
        self.pend_escaped = False
        self.hits: set[int] = set()
        self.force: str | None = None

    def fork(self, force: str) -> _JSLexState:
        other = _JSLexState(self.i)
        other.parens = list(self.parens)
        other.braces = list(self.braces)
        other.t1, other.t2, other.t3 = self.t1, self.t2, self.t3
        other.regex_ok = self.regex_ok
        other.pend, other.pend_pos, other.pend_end = self.pend, self.pend_pos, self.pend_end
        other.pend_prev, other.pend_escaped = self.pend_prev, self.pend_escaped
        other.hits = set(self.hits)
        other.force = force
        return other

    def key(self) -> tuple:
        return (
            self.i, tuple(self.parens), tuple(self.braces), self.t1, self.t2, self.t3,
            self.regex_ok, self.pend, self.pend_pos, self.pend_end, self.pend_prev,
            self.pend_escaped,
        )  # fmt: skip


def _js_line_end(source: str, pos: int) -> int:
    """The offset of the first line terminator at or after `pos` (U+2028 and
    U+2029 end a line as a line feed does), or the end of the source."""
    ends = [k for k in (source.find("\n", pos), source.find("\u2028", pos), source.find("\u2029", pos)) if k >= 0]
    return min(ends) if ends else len(source)


def _js_lex_run(source: str, st: _JSLexState, shared: list[int]) -> str:
    """Advance one reading to the end of the file ("done"), to a point it cannot
    be read past ("dead": an unterminated comment or template, a bracket nothing
    opened or left open), or to a construct with two readings ("fork": `st`
    stops before it, `st.force` is None). A state with `st.force` set reads that
    construct as told, then goes on."""
    n = len(source)
    match = _JS_LEX.match
    i = st.i
    parens, braces = st.parens, st.braces
    t1, t2, t3 = st.t1, st.t2, st.t3
    regex_ok = st.regex_ok
    pend, pend_pos, pend_end = st.pend, st.pend_pos, st.pend_end
    pend_prev, pend_escaped = st.pend_prev, st.pend_escaped
    hits = st.hits
    force, st.force = st.force, None

    def stop(at: int, outcome: str) -> str:
        st.i = at
        st.t1, st.t2, st.t3 = t1, t2, t3
        st.regex_ok = regex_ok
        st.pend, st.pend_pos, st.pend_end = pend, pend_pos, pend_end
        st.pend_prev, st.pend_escaped = pend_prev, pend_escaped
        return outcome

    while i < n:
        m = match(source, i)
        g = m.lastgroup
        j = m.end()
        if g == "ws" or g == "lc":
            i = j
            continue
        if g == "bc":
            close = source.find("*/", j)
            if close < 0:
                return stop(i, "dead")
            i = close + 2
            continue
        start = i
        i = j
        new_ref = False
        ref_prev = ""
        closed = ""
        escaped = False
        if g == "id":
            text = m.group()
            if "\\" in text:
                escaped = True
                text = _js_unescape_identifier(text)
            if text[0].isdigit():
                tok = "0"
                regex_ok = False
            else:
                tok = text
                prop = t1 == "." or t1 == "?."
                regex_ok = not prop and text in _JS_EXPR_KEYWORDS
                if text == "eval":
                    if not prop:
                        new_ref, ref_prev = True, t1
                    elif t2 in _JS_EVAL_GLOBALS and t3 != "." and t3 != "?.":
                        new_ref, ref_prev = True, t3
        elif g == "sl":
            tok = "/"
            regex_ok_next = True
            # Where this `/` could be a regex start or a division and the tokens
            # before it do not decide, both readings are followed (verifier A-1):
            # a wrong reading can turn the code after it into regex or string text,
            # and a real `eval(` into text. An offset is reported when either
            # reading puts it in code.
            #   * after `}`: a function, class or object expression is a value
            #     (division), a block after a statement, a label or a `case` is
            #     not (regex), and the token before it cannot tell which;
            #   * after `await`, `yield` or `of`: a keyword or a name;
            #   * after a postfix `!` (TypeScript's non-null assertion).
            if source[start - 1 : start] != "<" and (
                t1 == "}"
                or (t1 in ("await", "yield", "of") and t2 != "." and t2 != "?.")
                or (t1 == "!" and _js_value_token(t2))
            ):
                if force is None:
                    return stop(start, "fork")
                reading, force = force, None
                if reading == "re":
                    rx = _JS_REGEX_LITERAL.match(source, start)
                    if rx is None:
                        return stop(start, "dead")
                    i = rx.end()
                    tok = "/re/"
                    regex_ok_next = False
            # `</div>` and `</>`: a closing tag, not a regex.
            elif regex_ok and source[start - 1 : start] != "<":
                rx = _JS_REGEX_LITERAL.match(source, start)
                if rx is not None:
                    i = rx.end()
                    tok = "/re/"
                    regex_ok_next = False
                else:
                    nl = source.find("\n", start)
                    shared[0] -= (n if nl < 0 else nl) - start
                    if shared[0] < 0:
                        return stop(start, "dead")
            regex_ok = regex_ok_next
        elif g == "str":
            tok = '"'
            regex_ok = False
        elif g == "tpl":
            end = _js_template_text_end(source, j)
            if end is None:
                return stop(start, "dead")
            i, expr = end
            if expr:
                braces.append("t")
                tok = "${"
                regex_ok = True
            else:
                tok = "`"
                regex_ok = False
        elif g == "op":
            tok = m.group()
            if tok == "(":
                if t1 == ")" or t1 == "]":
                    kind = "c"
                elif t1[:1].isalnum() or t1[:1] == "_" or t1[:1] == "$":
                    named = t2 != "." and t2 != "?."
                    if named and t1 in _JS_CONTROL_KEYWORDS:
                        kind = "k"
                    elif named and t1 == "await" and t2 == "for":
                        kind = "k"  # `for await (...)`: a statement follows the paren
                    elif named and t1 in _JS_EXPR_KEYWORDS:
                        kind = "g"
                    else:
                        kind = "c"
                elif t1 in ('"', "`", "/re/"):
                    kind = "c"
                else:
                    kind = "g"
                parens.append(kind)
                regex_ok = True
            elif tok == ")":
                if not parens:
                    return stop(start, "dead")
                closed = parens.pop()
                regex_ok = closed == "k"
            elif tok == "{":
                after_name = (
                    (t1[:1].isalnum() or t1[:1] == "_" or t1[:1] == "$")
                    and t1 not in _JS_EXPR_KEYWORDS
                )
                braces.append("b" if t1 in _JS_BLOCK_BEFORE or after_name else "e")
                regex_ok = True
            elif tok == "}":
                if not braces:
                    return stop(start, "dead")
                kind = braces.pop()
                if kind == "t":
                    end = _js_template_text_end(source, j)
                    if end is None:
                        return stop(start, "dead")
                    i, expr = end
                    if expr:
                        braces.append("t")
                        tok = "${"
                        regex_ok = True
                    else:
                        tok = "`"
                        regex_ok = False
                else:
                    regex_ok = kind == "b"
            elif tok == "]":
                regex_ok = False
            elif tok == "--" and source.startswith(">", i):
                # `-->`: a line comment in a script, code in a module: both readings.
                if force is None:
                    return stop(start, "fork")
                reading, force = force, None
                if reading == "comment":
                    i = _js_line_end(source, start)
                    continue
            elif tok == "++" or tok == "--":
                pass  # postfix keeps "a value was just read"; prefix keeps "an operand is due"
            else:
                regex_ok = True
        else:
            tok = m.group()
            if tok == "<" and source.startswith("!--", i):
                # `<!--`: a line comment in a script, code in a module: both readings.
                if force is None:
                    return stop(start, "fork")
                reading, force = force, None
                if reading == "comment":
                    i = _js_line_end(source, start)
                    continue
            regex_ok = True
        if pend >= 4:
            # The argument list of a call the old pattern never matched: exactly
            # one string literal with no substitution is a constant, nothing
            # to inject; every other shape is reported.
            if pend == 4 and (tok == '"' or tok == "`"):
                pend = 5
            elif pend == 5 and tok == ")":
                pend = 0
            else:
                hits.add(pend_pos)
                pend = 0
        elif pend:
            if tok == "(":
                gap = source[pend_end:start]
                plain = not gap or (gap.isspace() and not any(c in gap for c in _JS_LINE_BREAKS))
                if pend == 1 and not pend_escaped and plain:
                    # `eval(` or `eval (` on one line, spelled plainly: what the
                    # old pattern matched, reported whatever its argument.
                    hits.add(pend_pos)
                    pend = 0
                else:
                    pend = 4
            elif tok == "?." and pend != 2:
                pend = 2
            elif tok == ")" and pend == 1 and closed == "g" and pend_prev in ("(", ","):
                pend = 3
            else:
                pend = 0
        if new_ref:
            pend = 1
            pend_pos = start
            pend_end = i
            pend_prev = ref_prev
            pend_escaped = escaped
        t3 = t2
        t2 = t1
        t1 = tok
    return stop(n, "dead" if parens or braces else "done")


# Most readings alive at once, most forks followed (the characters in the file
# bound them), and most characters read across all readings (as a multiple of the
# file's size) before the file is given up on: its sites are then all demoted.
_JS_MAX_READINGS = 256
_JS_MAX_FORKS_BASE = 4096  # forks followed: this many, plus one per 4 characters
_JS_MAX_WORK_FACTOR = 16


def _js_eval_offsets(source: str) -> list[int] | None:
    """Offsets of every real `eval` identifier in call position, in order, or
    None when no reading of the file is reliable (see the section comment).

    Where a construct has two readings that put code on different sides of a
    comment, string or regex (`_js_lex_run`), both are followed, as two states
    that continue side by side and merge when they meet in the same state. A
    reading that cannot be read to the end (an unbalanced bracket, an unterminated
    comment) is dropped: a valid program is read correctly by one of the readings.
    An offset found by any reading that completes is reported. When no reading
    completes, or the readings outgrow their budget, the result is None."""
    n = len(source)
    root = _JSLexState()
    if source.startswith("#!"):
        # A hashbang is a comment to the end of its line, and U+2028 and U+2029
        # end a line exactly as a line feed does (V8 reads them so).
        root.i = _js_line_end(source, 0)
    shared = [4 * n + 4096]  # work a failed regex attempt may cost in total
    work_left = _JS_MAX_WORK_FACTOR * n + 65536
    order = 0
    heap: list[tuple[int, int, _JSLexState, bool]] = [(root.i, order, root, False)]
    waiting: dict[tuple, _JSLexState] = {}
    survivors: set[int] = set()
    completed = False
    forks = 0
    while heap:
        _pos, _o, st, stopped = heapq.heappop(heap)
        if stopped:
            # Every reading behind this construct has run to it: follow both.
            forks += 1
            if forks > _JS_MAX_FORKS_BASE + n // 4:
                return None
            waiting.pop(st.key(), None)
            readings = ("comment", "code") if source.startswith(("<!--", "-->"), st.i) else ("div", "re")
            for reading in readings:
                if reading == "re" and _JS_REGEX_LITERAL.match(source, st.i) is None:
                    continue
                child = st.fork(reading)
                order += 1
                heapq.heappush(heap, (child.i, order, child, False))
            continue
        before = st.i
        outcome = _js_lex_run(source, st, shared)
        work_left -= max(st.i - before, 1)
        if work_left < 0 or shared[0] < 0 or len(heap) > _JS_MAX_READINGS:
            return None
        if outcome == "done":
            completed = True
            survivors |= st.hits
        elif outcome == "fork":
            key = st.key()
            twin = waiting.get(key)
            if twin is not None:
                twin.hits |= st.hits
            else:
                waiting[key] = st
                order += 1
                heapq.heappush(heap, (st.i, order, st, True))
    return sorted(survivors) if completed else None


def _js_eval_lines(source: str) -> set[int] | None:
    """The 1-based lines (as `str.splitlines` numbers them, which is how the
    analyzer walks a file) holding a real `eval` call, or None when the file
    could not be read reliably, in which case no site is confirmed (every match of
    the raw pattern is reported, demoted)."""
    # Without the word or a unicode escape (`\u0065val`) there is nothing to find.
    if "eval" not in source and "\\u" not in source:
        return set()
    offsets = _js_eval_offsets(source)
    if offsets is None:
        return None
    if not offsets:
        return set()
    starts: list[int] = []
    pos = 0
    for piece in source.splitlines(keepends=True):
        starts.append(pos)
        pos += len(piece)
    return {bisect.bisect_right(starts, offset) for offset in offsets}


class AnalysisIncomplete(RuntimeError):
    """Raised by `ASTAnalyzer.run` AFTER the whole tree was walked when the
    analysis of one or more files was cut short (redteam-py-01): the recursion
    limit, an out-of-memory parse, or any other exception mid-walk. Every
    finding already emitted stays emitted, and every other file was analysed.

    It exists so the lost evaluation reaches the coverage contract through
    the existing vocabulary: `engine.py`'s `_run_check` turns it into the
    injection check's `failed/execution_error` status line, which the Go side
    records as the `python-engine/injection` entry and the coverage contract
    counts as a gap. Before it, the per-file guard logged to stderr and the
    check reported `ok`, so a proven BLOCK in the rest of such a file vanished
    from a scan that said it was complete.

    An in-scope source file that was never analysed is lost evaluation too
    (D6, D5-2): one over the 1 MB size cap (`_MAX_FILE_BYTES`), whatever its
    header says, a file that is not a regular file, a file or directory that
    cannot be read, and a
    file the interpreter cannot parse (D1', DE-03). A SyntaxError is not "code
    the server does not run": a `match` statement under Python 3.9 is valid
    Python the interpreter is too old for, and dropping it hid a proven
    command injection. The reason says which it is (`analyzers/interpreter.py`).
    What the analyzer leaves out on purpose is not (`analyzers/scope_evidence.py`);
    it is listed by name instead.

    `status_detail` is the failed entry's detail, built by
    `analyzers/status_detail.py` within the Go side's 240-byte bound so that
    side never cuts it: the file count first, the first files named, then
    "and N more (see report metadata)", then what was declared out of scope
    in a segment starting "declared out of scope, not scanned:" (C1, C2).
    `str(exc)` is the same text."""

    def __init__(
        self,
        files: list[tuple[str, str]],
        declared: list[tuple[str, str]] | None = None,
    ) -> None:
        self.files = list(files)
        self.declared = list(declared or [])
        self.status_detail = status_detail.fit(loss=self.files, declared=self.declared)
        super().__init__(self.status_detail)


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
        # (rel, reason) for every file whose analysis was cut short during
        # `run`; non-empty makes `run` raise `AnalysisIncomplete` once the
        # walk is done (redteam-py-01).
        self.incomplete_files: list[tuple[str, str]] = []
        # (rel, why) for every path left out of scope on purpose during `run`:
        # symlinks that are not followed (`analyzers/scope_evidence.py`, D5-2).
        # Listed by `scope_note`.
        self.excluded: list[tuple[str, str]] = []
        # (path, rel) of every Python file the route pass read, for
        # `_ProjectMentions`.
        self._python_paths: list[tuple[Path, str]] = []

    def scope_note(self, budget: int = status_detail.DETAIL_BUDGET) -> str:
        """The segment naming what `run` left out of scope on purpose, "declared
        out of scope, not scanned: N paths: a/ (why), ... and K more (see
        report metadata)", fitted to `budget` bytes and never cut, or "" when
        there was nothing (D6', C1, C2)."""
        if not self.excluded:
            return ""
        return status_detail.fit(declared=self.excluded, budget=budget)

    def scope_payload(self) -> dict | None:
        """The complete lists of what was lost and what was declared, for the
        status line's additive `scope` field (C2)."""
        return status_detail.scope_payload(self.incomplete_files, self.excluded)

    def _record_incomplete(self, rel: str, reason: str) -> None:
        """Note that the analysis of `rel` was cut short (`AnalysisIncomplete`)."""
        entry = (rel, reason)
        if entry not in self.incomplete_files:
            self.incomplete_files.append(entry)

    def run(self, emit_fn: Callable[[dict], None]) -> None:
        """Walk code_path and emit findings for security patterns detected.

        Raises `AnalysisIncomplete` after the walk when any file's analysis
        was cut short, or an in-scope source file was skipped for size or
        could not be read (D6); the findings it emitted, and every other
        file's, are kept (redteam-py-01)."""
        self.incomplete_files = []
        self.excluded = []
        self._python_paths: list[tuple[Path, str]] = []
        root = Path(self.code_path)
        if not root.exists():
            return
        # One walk for every pass, so the route index, the call index and the
        # analysis agree on what is in scope (D6').
        walk = SourceWalk(root)

        # Proven Path v1: pre-pass builds a project-wide handler→route index
        # so a finding's sink can be bound to the route that reaches it —
        # even when the route is declared in urls.py and the view lives in a
        # different file (Django). Best-effort and metadata-only; a failure
        # here leaves binding off and never blocks the security pass.
        self._routes_by_func = self._build_route_index(root, walk)
        # Every Python file the route pass read, for an allowlist another
        # file may change (`_allowlist_shared`, redteam2-r001-01).
        self._project_mentions = _ProjectMentions(self._python_paths)
        # Task 3.8: a second pre-pass indexes the calls between the project's
        # modules, so a helper's parameter can be followed one hop to a caller
        # in another file. It parses each file once and hands the parse to
        # `_analyze_python`. Best-effort like the route index: on failure the
        # helper hop stays within each file.
        self._call_index = self._build_call_index(root, self._routes_by_func, walk)

        for dirpath, filenames in walk.walk(record=True):
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
                rel = str(fpath.relative_to(root))
                suffix = fpath.suffix.lower()
                source_file = suffix == ".py" or suffix in _SOURCE_SUFFIXES_JS
                try:
                    if fpath.is_symlink():
                        # Not followed, and said so (D6).
                        if source_file:
                            self.excluded.append((rel, SYMLINK_REASON))
                        continue
                except OSError as exc:
                    if source_file:
                        self._record_incomplete(rel, _os_error_reason(exc))
                    continue
                if source_file and not is_regular_file(fpath):
                    # A named pipe, socket or device with a source name: opening
                    # it can block the scan forever, and it holds no source the
                    # engine can read. In scope and never analysed (D5-2).
                    self._record_incomplete(rel, _NOT_REGULAR_REASON)
                    continue

                if suffix == ".py":
                    self.file_stats["python"] += 1
                    self._analyze_python(fpath, rel, emit_fn)
                elif suffix in _SOURCE_SUFFIXES_JS:
                    self.file_stats["javascript"] += 1
                    self._analyze_js_heuristic(fpath, rel, emit_fn)
        self.excluded = walk.declared + self.excluded
        for rel, reason in walk.lost:
            self._record_incomplete(rel, reason)
        # The index holds the callers' parsed trees; nothing reads it after
        # the walk. A caller it could not index or prove is lost evaluation
        # of a cross-file hop.
        for rel, reason in getattr(self._call_index, "incomplete", ()):
            self._record_incomplete(rel, reason)
        self._call_index = None
        if self.incomplete_files:
            raise AnalysisIncomplete(self.incomplete_files, self.excluded)

    def _build_route_index(self, root: Path, walk: SourceWalk | None = None):
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
        for dirpath, filenames in (walk or SourceWalk(root)).walk():
            for fname in filenames:
                if not fname.lower().endswith(".py"):
                    continue
                fpath = Path(dirpath) / fname
                rel = str(fpath.relative_to(root))
                try:
                    if not is_regular_file(fpath) or fpath.stat().st_size > _MAX_FILE_BYTES:
                        # A link, a named pipe, an oversized file: reported by
                        # the main walk (`run`, `_analyze_python`, D6).
                        continue
                    src = _read_python_source(fpath)
                except OSError as exc:
                    # Its routes are missing, so its handlers' route
                    # parameters are no request sources (D6).
                    self._record_incomplete(rel, f"route index: {_os_error_reason(exc)}")
                    continue
                self._python_paths.append((fpath, rel))
                errors: list[str] = []
                try:
                    table, summary = scan_module(src, rel, errors=errors)
                except (RecursionError, Exception) as exc:  # noqa: BLE001 — binding is best-effort
                    # audit #18: one crafted/large file must not abort the
                    # route index (and thus the whole injection pass). Skip
                    # it, but its handlers' route parameters are then no
                    # request sources: lost evaluation (redteam-py-01).
                    self._record_incomplete(rel, f"route index: {_exc_reason(exc)}")
                    continue
                for reason in errors:
                    self._record_incomplete(rel, f"route index: {reason}")
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

    def _build_call_index(self, root: Path, route_table, walk: SourceWalk | None = None):
        """The project's `ProjectCallIndex` (analyzers/call_index.py), or None
        when it cannot be built. Imported here, not at module level: the
        index module imports this one."""
        try:
            from analyzers.call_index import ProjectCallIndex

            return ProjectCallIndex.build(root, route_table, walk)
        except (RecursionError, Exception) as exc:  # noqa: BLE001 — the hop is optional
            print(
                f"[fendix-engine] ast_analyzer: project call index failed: {exc}",
                file=sys.stderr,
            )
            # Without the index no cross-file hop is proven anywhere: lost
            # evaluation (redteam-py-01).
            self._record_incomplete("(project call index)", _exc_reason(exc))
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
                size = filepath.stat().st_size
                if size > _MAX_FILE_BYTES:
                    # Too large to read: an in-scope source file that was never
                    # analysed, whatever its header says (D6, D5-2).
                    self._record_incomplete(rel, _size_reason(size))
                    return
                source = _read_python_source(filepath)
            except OSError as exc:
                # An in-scope source file that was never analysed (D6).
                self._record_incomplete(rel, _os_error_reason(exc))
                return
            try:
                tree = ast.parse(source, filename=str(filepath))
            except (SyntaxError, ValueError) as exc:
                # A file this interpreter cannot parse is lost evaluation, not
                # a clean result (D1', DE-03): the file is broken, or the
                # interpreter is older than its syntax; the reason says which.
                self._record_incomplete(rel, syntax_reason(exc, source))
                return
            except (RecursionError, MemoryError) as exc:
                # Valid source too deep or too large for the parser: the
                # file was never analysed (redteam-py-01).
                self._record_incomplete(rel, f"parse: {_exc_reason(exc)}")
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
            project_mentions=getattr(self, "_project_mentions", None),
        )
        #
        # The rest of the file is lost evaluation, not a clean result: it is
        # recorded, and `run` raises `AnalysisIncomplete` once every other
        # file is done, so the injection check is not reported `ok`
        # (redteam-py-01).
        try:
            visitor.visit(tree)
            for reason in visitor.lost_evaluation:
                self._record_incomplete(rel, reason)
        except RecursionError as exc:
            print(
                f"[fendix-engine] ast_analyzer: recursion limit hit on {rel}; "
                "skipping rest of file",
                file=sys.stderr,
            )
            self._record_incomplete(rel, _exc_reason(exc))
        except Exception as exc:  # noqa: BLE001 — never let one file abort the pass
            print(
                f"[fendix-engine] ast_analyzer: failed to analyze {rel}: {exc}",
                file=sys.stderr,
            )
            self._record_incomplete(rel, _exc_reason(exc))

    # ------------------------------------------------------------------
    # JavaScript heuristic analysis
    # ------------------------------------------------------------------

    def _analyze_js_heuristic(
        self, filepath: Path, rel: str, emit_fn: Callable[[dict], None]
    ) -> None:
        """Apply regex heuristics to a JavaScript/TypeScript file.

        Every in-scope file at or below the size cap is scanned, minified,
        vendored and generated code included: nothing in a file's name, banner,
        header or shape takes it out of scope, and no line is skipped for its
        length (D5-2). A file over the size cap, or one that cannot be read, is
        an in-scope source file that was never checked (D6)."""
        try:
            size = filepath.stat().st_size
            if size > _MAX_FILE_BYTES:
                self._record_incomplete(rel, _size_reason(size))
                return
            source = (
                read_regular(filepath)
                .decode("utf-8", errors="replace")
                .replace("\r\n", "\n")
                .replace("\r", "\n")
            )
        except OSError as exc:
            self._record_incomplete(rel, _os_error_reason(exc))
            return

        # R6-E7a: an identifier spelled with a unicode escape is read by the runtime as the
        # name it spells (an escaped eval is eval), but by every pattern below as written, so
        # the file is lost evaluation, whatever the patterns report in it.
        #
        # A lexer that raises is lost evaluation too (WS-C2's give-up audit): it never
        # aborts the file's analysis or the walk, and the file never reads as analysed.
        try:
            if js_identifier_escape(source, filepath.name).lost:
                self._record_incomplete(rel, JS_ESCAPE_UNREADABLE)
        except Exception as exc:  # noqa: BLE001 — never let one file abort the pass
            print(
                f"[fendix-engine] ast_analyzer: identifier-escape lexer failed on {rel}: "
                f"{type(exc).__name__}",
                file=sys.stderr,
            )
            self._record_incomplete(rel, _exc_reason(exc))

        lines = source.splitlines()
        # The module-level string constants of the file, read once: every
        # SQL-template line asks, and a megabyte of such lines (a minified or
        # generated file is scanned like any other, D5-2) would otherwise read
        # the whole file once per line.
        constants: set[str] | None = None
        # The GRADE of a JS_EVAL site is decided on tokens, not on the line's text
        # (E-1): the lines holding an `eval` call a complete reading puts in code,
        # or None when the file cannot be tokenised reliably. Whether the site is
        # reported is not: every line the raw pattern matches is (OR-88).
        try:
            eval_lines = _js_eval_lines(source)
        except Exception as exc:  # noqa: BLE001 — the same guard as the escape lexer above
            # No site is confirmed (every match of the raw pattern is reported,
            # demoted) and the file is lost evaluation: its indirect forms were not read.
            print(
                f"[fendix-engine] ast_analyzer: eval tokenizer failed on {rel}: "
                f"{type(exc).__name__}",
                file=sys.stderr,
            )
            self._record_incomplete(rel, _exc_reason(exc))
            eval_lines = None
        for lineno, line in enumerate(lines, start=1):
            for pat_id, title, pattern, severity, confidence, cwe in _JS_PATTERNS:
                fix = _JS_FIX.get(pat_id, "Review and sanitize this usage.")
                if pat_id == "JS_EVAL" and eval_lines is not None and lineno in eval_lines:
                    found = True  # a complete reading puts the call in code: HIGH/HIGH
                else:
                    found = pattern.search(line) is not None
                    if found and pat_id == "JS_EVAL" and eval_lines is not None:
                        # The v3.7.0 pattern matches this line and a complete reading
                        # of the file puts no call in code here (a comment, a string,
                        # `x.eval(`): reported all the same, demoted (OR-88). When the
                        # tokenizer gave up (`eval_lines` is None: no reading completes,
                        # the budget is spent, or it crashed) it decided nothing, so the
                        # match keeps the grade it always had, HIGH/HIGH: a doubt
                        # reports, and a budget an adversary can exhaust is no way to
                        # lower a BLOCK (rc.4 brief, "no unsafe reduction in BLOCK
                        # severity").
                        severity, confidence = _JS_EVAL_UNCONFIRMED_GRADE
                        fix = _JS_EVAL_UNCONFIRMED_FIX + fix
                if found:
                    if pat_id == "JS_SQL_TEMPLATE":
                        if constants is None:
                            constants = _js_module_string_constants(source)
                        if _js_template_only_constants(line, source, constants):
                            continue
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
                            "fix": fix,
                            "references": [cwe],
                            "confidence": confidence,
                            "line": f"{rel}:{lineno}",
                        }
                    )


# The `fix` prefix of a path-traversal finding LOWERED by a recognised containment
# guard (OR-88): the finding is reported at WARN with the guard named.
_PATH_GUARD_LOWERED = (
    "A path-containment guard ({guards}) covers this path, so it is reported at WARN "
    "rather than as a proven traversal: Fendix cannot show the guard holds on every "
    "path to the sink (a rebound or patched helper, a root that is a symlink or a "
    "parent of the base, or a check on a different value would defeat it). "
)

# Fixes for JS patterns
#
# `JS_EVAL` sites no complete reading of the file puts in code (a comment, a
# string, template or JSX text, a regex literal, `$eval`, `x.eval`, or a file the
# lexer could not read) are still reported (OR-88, "the recognisers may lower a
# finding, never remove it"), at MEDIUM severity and LOW confidence. LOW is the
# one confidence that WARNs under every `--fail-on` (the decision layer's
# `held_confidence_low`), that the collapse's `strongestClaim` can never copy onto
# another finding (it only adopts a HIGHER claim), and that cannot earn the
# deterministic-detection delta; textscan's own grade for the same call, HIGH
# severity at MEDIUM confidence, WARNs too but could lift a LOWER claim made by
# another analyzer on the same line. A call a complete reading does put in code
# keeps HIGH/HIGH and so still corroborates textscan's finding (D20). Id, rule_id,
# title, category and references are the confirmed finding's, so a baseline entry
# and a finding's identity do not move when a site changes grade.
_JS_EVAL_UNCONFIRMED_GRADE = ("MEDIUM", "LOW")
_JS_EVAL_UNCONFIRMED_FIX = (
    "Fendix could not confirm this `eval(` is executed code (it may be the word in a "
    "comment, a string, template or JSX text, or a regex literal, or the file could "
    "not be read reliably), so it is reported at reduced confidence and does not "
    "block on its own. "
)
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


class _ProjectMentions:
    """Which project files can reach a name of another module, read on demand
    and cached per name (redteam2-r001-01): a file that imports it
    (`from app import ALLOWED`, also inside a parenthesised import, or a
    star import with the name in the file), reads it as an attribute
    (`app.ALLOWED`) or names it in a string (`getattr(app, "ALLOWED")`).
    Text-level, so it can only over-count (a comment, an unrelated module's
    attribute of the same name), which makes an allowlist count less."""

    def __init__(self, files: list[tuple[Path, str]]) -> None:
        self._files = list(files)
        self._reached: dict[str, frozenset[str]] = {}

    def reached_from_outside(self, name: str, rel: str) -> bool:
        reached = self._reached.get(name)
        if reached is None:
            n = re.escape(name)
            word = re.compile(rf"\b{n}\b")
            reach = re.compile(
                rf"\.\s*{n}\b|\bimport\b[^\n]*\b{n}\b|\bimport\s*\([^)]*\b{n}\b|['\"]{n}['\"]"
            )
            star = re.compile(r"\bimport\s+\*")
            found = set()
            for path, other in self._files:
                try:
                    text = _read_python_source(path)
                except OSError:
                    found.add(other)  # unknown: may reach it
                    continue
                if not word.search(text):
                    continue
                if reach.search(text) or star.search(text):
                    found.add(other)
            reached = self._reached[name] = frozenset(found)
        return bool(reached - {rel})


_NOT_REGULAR_REASON = "unreadable: not a regular file"


def _size_reason(size: int) -> str:
    """The reason for an in-scope source file skipped for size (D6)."""
    return f"skipped: over the 1 MB size cap ({size} bytes)"


def _exc_reason(exc: BaseException) -> str:
    """A short reason for an aborted analysis (`AnalysisIncomplete`)."""
    if isinstance(exc, RecursionError):
        return "recursion limit"
    if isinstance(exc, MemoryError):
        return "out of memory"
    return f"internal error: {type(exc).__name__}"


def _file_visitor(
    source: str,
    rel: str,
    emit_fn: Callable[[dict], None],
    tree: ast.Module,
    *,
    route_table=None,
    call_index=None,
    primed: bool = False,
    project_mentions: _ProjectMentions | None = None,
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
    visitor._project_mentions = project_mentions
    if primed:
        visitor._prime()
    return visitor


class _Scope(dict):
    """The bindings of one scope (name -> the value last bound to it, in source
    order). It notes the keys that are read while a call is being checked
    (`_PythonSecurityVisitor.visit_Call`): a sink check that resolved a name
    consulted its binding, and C4B-23 asks whether that binding was the only one
    that could reach the sink."""

    __slots__ = ("_visitor",)

    def __init__(self, visitor: "_PythonSecurityVisitor") -> None:
        super().__init__()
        self._visitor = visitor

    def __getitem__(self, key):
        reads = self._visitor._binding_reads
        if reads is not None:
            reads.add(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        reads = self._visitor._binding_reads
        if reads is not None and key in self:
            reads.add(key)
        return super().get(key, default)


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
        self._scopes: list[dict[str, ast.AST]] = [_Scope(self)]
        # C4B-23: the names a call's own checks read from `_scopes` while it is
        # checked (None outside a call), the findings emitted so far, and the
        # lost evaluation the file's analysis records (`lost_evaluation`).
        self._binding_reads: set[str] | None = None
        self._emitted = 0
        self._lost_listed: list[str] = []
        self._lost_essential: list[str] = []
        self._definition_values_cache: dict[int, tuple[ast.AST, dict, dict, dict]] = {}
        # OR-88: the path-containment recognisers may LOWER a finding, never remove
        # it. `_guards_off` is non-zero while a sink is re-read as if no guard were
        # recognised; `_guard_trace` lists the guards the recognisers accepted since
        # `_path_traversal_report` last cleared it (`_note_guard`).
        self._guards_off = 0
        self._guard_trace: list[str] = []
        self._input_functions: dict[int, tuple[ast.AST, bool]] = {}
        self._ambiguity_names: dict[int, set[str]] = {}
        self._lost_overflow = 0
        # Stack of enclosing FunctionDef nodes — used by the whitelist-
        # sanitiser scan to find membership guards earlier in the same
        # function body. Top of stack is the innermost function being
        # visited.
        self._func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        # (function, name) -> its reaching definitions (`_guard_covers`). The
        # function is kept in the value so its id is never reused while cached.
        self._reaching_defs_cache: dict[tuple[int, str], tuple[ast.AST, ReachingDefs]] = {}
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
        # R-002: the class of the sink whose taint chain is being collected
        # (`_SINK_CLASSES`), and that sink's argument. The helper hop reads
        # both to apply only the caller-side sanitisers that neutralise THIS
        # sink class (`_caller_arg_is_sanitised`); "other" honours only the
        # sink-agnostic allowlist sanitisers.
        self._sink_class: str = "other"
        self._sink_arg: ast.AST | None = None
        # R-001: module-level allowlist names → bound once and never mutated
        # (`_allowlist_name_is_stable`), computed on first need.
        self._allowlist_stable: dict[str, bool] = {}
        # The project's other files, for a module-level allowlist another
        # file may change (`_allowlist_shared`); set by `_file_visitor`.
        self._project_mentions: _ProjectMentions | None = None
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
        # The leading-dot count of each `from <module> import <name>` (0 for an
        # absolute import), beside `_from_imports`, which keeps no level: the
        # containment-helper lookup resolves a relative import against this
        # file's package (`_g_absolute_module`).
        self._from_import_levels: dict[str, int] = {}
        # Every `from <module> import *` in the file, as the module written
        # (a relative one keeps its leading dots), collected once from the
        # whole module on first need (`_star_import_modules`).
        self._star_import_cache: tuple[str, ...] | None = None
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
        self._autoescape_switched_off: bool | None = None
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
        self._emitted += 1
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
        self,
        sink_arg: ast.AST,
        sink_lineno: int,
        sink_expr: str,
        extra_source=None,
        *,
        sink_class: str = "other",
    ) -> list[dict] | None:
        """Walk back from ``sink_arg`` through scope assignments to a request source.

        Returns an ordered chain (source first, sink last) when reachable,
        else None. The walker recurses through complex assignments — a
        chain like ``q = request.args.get('q'); sql = '...' + q;
        cursor.execute(sql)`` resolves via two hops: first ``sql`` ->
        BinOp containing Name ``q``, then ``q`` -> Call referencing
        ``request.args``.

        ``sink_class`` (one of `_SINK_CLASSES`) names what the sink is
        vulnerable to. The one-hop helper proof applies only the caller-side
        sanitisers of that class (R-002): an escaped value still proves a
        shell, SQL, path, SSRF or redirect sink in the helper.

        Each link is ``{"file": str, "line": int, "expr": str}``.
        """
        saved = self._sink_class, self._sink_arg
        self._sink_class, self._sink_arg = sink_class, sink_arg
        try:
            return self._collect_taint_chain_for(
                sink_arg, sink_lineno, sink_expr, extra_source
            )
        finally:
            self._sink_class, self._sink_arg = saved

    def _collect_taint_chain_for(
        self, sink_arg: ast.AST, sink_lineno: int, sink_expr: str, extra_source
    ) -> list[dict] | None:
        """`_collect_taint_chain` once the sink class is in force."""
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
        files are asked (`_cross_file_caller_link`, Task 3.8).

        The caller-side sanitisers are those of the helper's sink class
        (`_hop_sink_class`, R-002)."""
        hop_class = self._hop_sink_class(param_name)
        for call, scope, arg in self._caller_args(param_name):
            self._interproc_depth += 1
            try:
                prefix = self._caller_arg_chain(
                    call, scope, arg, extra_source, depth, sink_class=hop_class
                )
            finally:
                self._interproc_depth -= 1
            if prefix is not None:
                return prefix
        return self._cross_file_caller_link(param_name, hop_class)

    def _hop_sink_class(self, param_name: str) -> str:
        """The sink class the caller's argument for `param_name` is judged
        under: the class of the sink being traced, except that a URL sink
        whose argument does not START with the parameter (`requests.get(
        "https://" + url)`) is "url_part". The URL-host sanitisers (a netloc
        allowlist guard, a constant scheme and host) describe a whole URL
        string; embedded after other text it can name another host
        (`evil.com://api.example.com/x` has netloc api.example.com)."""
        if self._sink_class != "url":
            return self._sink_class
        if self._sink_arg is not None and self._expr_leads_with(
            self._sink_arg, param_name, frozenset()
        ):
            return "url"
        return "url_part"

    def _expr_leads_with(
        self, expr: ast.AST, name: str, seen: frozenset[str], _depth: int = 0
    ) -> bool:
        """True when the value of `expr` starts with the whole value of the
        Name `name`: the Name itself, a local bound to such an expression, the
        leftmost operand of a `+`, or the first part of an f-string."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Name):
            if expr.id == name:
                return True
            if expr.id in seen:
                return False
            bound = self._scope_binding(expr.id)
            return bound is not None and self._expr_leads_with(
                bound, name, seen | {expr.id}, _depth + 1
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return self._expr_leads_with(expr.left, name, seen, _depth + 1)
        if isinstance(expr, ast.JoinedStr) and expr.values:
            first = expr.values[0]
            return isinstance(first, ast.FormattedValue) and self._expr_leads_with(
                first.value, name, seen, _depth + 1
            )
        return False

    def _cross_file_caller_link(
        self, param_name: str, sink_class: str = "other"
    ) -> list[dict] | None:
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
            sink_class=sink_class,
        )
        return [asdict(links[0])] if links else None

    def _caller_arg_chain(
        self,
        call: ast.Call,
        scope: ast.AST,
        arg: ast.AST,
        extra_source,
        depth: int,
        *,
        sink_class: str = "other",
    ) -> list[dict] | None:
        """The chain prefix one caller's argument proves, or None: the
        argument as an inline source, or traced through the caller's bindings
        before the call (to a request expression, or to a request-carrying
        parameter of a caller that is a route handler) and followed by the
        call itself. None as well when a sanitiser of the helper's sink class
        (`sink_class`) accepts the argument in the caller."""
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
        if self._caller_arg_is_sanitised(scope, call, arg, sink_class):
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
        self, scope: ast.AST, call: ast.Call, arg: ast.AST, sink_class: str = "other"
    ) -> bool:
        """True when a sanitiser that neutralises the helper's sink class
        (`sink_class`, see `_SINK_CLASSES`) accepts `arg` where the caller
        passes it, exactly as the direct sink of that class would:

          * every class: a constant-collection lookup or a dominating
            membership guard (the value is one of a set of constants);
          * "html": an escaping call (`_is_escaped_call`), a safe URL builder,
            or a fully escaped expression (`_expr_is_fully_escaped`);
          * "url": a safe URL builder, a `urlparse(...).netloc` allowlist guard
            or a URL whose scheme and host are fixed
            (`_url_authority_is_constant`); "url_part" (the helper embeds the
            value after other text) only a safe URL builder;
          * "path" / "path_strict": path containment (`_path_is_contained`),
            basename-reduced values only for "path";
          * "shell": `shlex.quote` (`_is_shell_quoted`).

        R-002: the hop used to take the union of every sink's sanitisers, so
        `html.escape` or `basename` in the caller hid a command injection in
        the helper. Escaping neutralises markup only; `basename` and
        `secure_filename` remove directory structure only; URL-encoding does
        not fix a URL's host; `shlex.quote` protects a shell word only.

        Guards must dominate the call, exactly as they must dominate a sink."""
        with self._caller_context(scope, call):
            if sink_class == "url":
                return self._arg_is_sanitised(
                    arg, call.lineno, url_sink=True
                ) or self._url_authority_is_constant(arg)
            if sink_class == "html":
                return self._arg_is_sanitised(
                    arg, call.lineno, sink="html"
                ) or self._expr_is_fully_escaped(arg)
            if sink_class in ("path", "path_strict"):
                return self._arg_is_sanitised(
                    arg, call.lineno, sink="path"
                ) or self._path_is_contained(
                    arg, call.lineno, file_sink=sink_class == "path"
                )
            if sink_class == "shell":
                return self._arg_is_sanitised(
                    arg, call.lineno, sink="shell"
                ) or self._is_shell_quoted(arg)
            return self._arg_is_sanitised(arg, call.lineno, sink=sink_class)

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

    def _name_is_membership_guarded(
        self, name: str, sink_line: int, use: ast.AST | None = None
    ) -> bool:
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
            # R-001: members must be constants of an allowlist nothing
            # rebinds or mutates, and the guarded name must keep the value it
            # was checked with: no definition that reaches the use is one the
            # guard did not see (`_guard_covers`).
            if not self._allowlist_is_constant(collection):
                continue
            if not self._guard_covers(
                name, _loads_of(stmt.test, name), use, (stmt.lineno, stmt.col_offset)
            ):
                continue
            # The rejecting body must END control flow, proven (return, raise
            # or a call known never to return: `_body_ends_control_flow`), and
            # the sink must lie after it: a sink inside the guard's own body
            # runs exactly when the value is NOT in the allowlist
            # (redteam4-py-01).
            if (
                self._body_ends_control_flow(stmt.body)
                and stmt.body[-1].end_lineno < sink_line
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

    def _url_host_is_allowlisted(
        self, name: str, sink_line: int, use: ast.AST | None = None
    ) -> bool:
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

        R-001: the guard bounds the VALUE it parsed, not the name. It counts
        only for a use whose every reaching definition of `name` also reached
        the parse (`_guard_covers`: a rebind after the parse, a stale
        `p = urlparse(name)` with `name` re-read before the check, a rebind in
        a loop around the sink), when a bound parse `p` has one binding in the
        function, before the guard, and when every allowlist member is a
        non-empty string constant of an allowlist nothing rebinds or mutates
        (`_allowlist_is_constant`).
        """

        def covered(test: ast.AST) -> bool:
            parses: list[ast.Call] = []
            if not self._test_rejects_unlisted_host(test, name, parses):
                return False
            tested = [n for parse in parses for n in _loads_of(parse, name)]
            return self._guard_covers(name, tested, use, (test.lineno, test.col_offset))

        return self._has_dominating_exit_guard(sink_line, covered, before_sink="ends")

    def _test_rejects_unlisted_host(
        self, test: ast.AST, name: str, parses: list[ast.Call] | None = None
    ) -> bool:
        """True when `test` is True whenever `name`'s parsed netloc is outside
        a literal collection: the `not in` comparison itself, or an `or` with
        that comparison among its operands. Each `urlparse(name)` call it finds
        is appended to `parses`."""
        if isinstance(test, ast.BoolOp):
            return isinstance(test.op, ast.Or) and any(
                self._test_rejects_unlisted_host(v, name, parses) for v in test.values
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
        parse = self._url_parse_of(host.value, name, test)
        if parse is None:
            return False
        # Every member a non-empty string constant: an allowlist holding ""
        # admits every host-less URL, and one holding request data or any
        # other non-constant value bounds nothing (R-001).
        if not self._allowlist_is_constant(test.comparators[0], hosts=True):
            return False
        if parses is not None:
            parses.append(parse)
        return True

    def _url_parse_of(
        self, expr: ast.AST, name: str, test: ast.AST
    ) -> ast.Call | None:
        """The `urlparse(name)` / `urlsplit(name)` call the guard `test`
        checks: `expr` itself, or the value of the Name `expr` when that is
        its ONLY binding in the innermost function, a top-level assignment
        before the guard. The scope chain would give the binding live at the
        sink instead, which may be a later parse of another value."""
        if isinstance(expr, ast.Name):
            if not self._func_stack:
                return None
            binding = self._sole_top_level_assign(self._func_stack[-1], expr.id)
            if binding is None or binding.lineno >= test.lineno:
                return None
            expr = binding.value
        if not (isinstance(expr, ast.Call) and expr.args):
            return None
        fn = expr.func
        called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if called not in self._URL_PARSE_CALL_NAMES:
            return None
        first = expr.args[0]
        if isinstance(first, ast.Name) and first.id == name:
            return expr
        return None

    def _reaching_defs(self, name: str) -> ReachingDefs | None:
        """The reaching definitions of `name` in the innermost function (cached
        per function and name), or None outside a function."""
        if not self._func_stack:
            return None
        func = self._func_stack[-1]
        key = (id(func), name)
        cached = self._reaching_defs_cache.get(key)
        if cached is None:
            cached = (func, ReachingDefs(func, name))
            self._reaching_defs_cache[key] = cached
        return cached[1]

    def _guard_covers(
        self,
        name: str,
        tested: list[ast.Name],
        use: ast.AST | None,
        guard_pos: tuple[int, int],
        *,
        only: ast.AST | None = None,
    ) -> bool:
        """The one rule for every guard on a name (redteam3-py-01): a guard
        protects a use only if every definition of `name` that can supply the
        use's value also reached the guard.

        `tested` are the reads of `name` the guard checks (the operands of its
        test, or of the `urlparse(name)` it checks); the definitions that reach
        them are the values the guard actually tested. `use` is the read the
        sink consumes (or an alias chain's read). A reassignment, an augmented
        assignment, a decode, a concatenation, a loop or `with` target, a
        walrus, an `except ... as` or a `del` between the guard and the use
        puts a definition in the use's set that the guard never saw, and the
        guard no longer counts. See `analyzers/reaching_defs.py`.

        `only`, when given, is the one definition the guard must have tested
        (the assignment that resolved the path, for a containment guard).

        A name another scope can rebind (`global`/`nonlocal`) is never proven.
        When the analysis never reached `use` (a read in another scope, or no
        read given), the answer is the conservative one: nothing may bind the
        name after the guard, anywhere in the function.
        """
        rd = self._reaching_defs(name)
        if rd is None or rd.volatile or not tested:
            return False
        tested_defs: frozenset = frozenset()
        for node in tested:
            reached = rd.defs_at(node)
            if reached is None:
                return False
            tested_defs |= reached
        if not tested_defs or (only is not None and tested_defs != {only}):
            return False
        used = rd.defs_at(use) if use is not None else None
        if used is None:
            # A read in a scope the analysis does not enter (a lambda, a nested
            # def: where the name may be a parameter of its own), or none given.
            # Nested scopes count here, which can only over-count.
            for node in _stores_of(rd.func, name):
                pos = (getattr(node, "lineno", None), getattr(node, "col_offset", 0))
                if pos[0] is None or pos > guard_pos:
                    return False
            return True
        return used <= tested_defs

    # Methods that change a set, list or dict in place.
    # The methods that can put a new member into a set, list or dict.
    _COLLECTION_MUTATORS = frozenset(
        {
            "add",
            "update",
            "append",
            "extend",
            "insert",
            "setdefault",
            "__setitem__",
            "__ior__",
            "__iadd__",
            "__ixor__",
            "symmetric_difference_update",
        }
    )

    def _allowlist_is_constant(self, expr: ast.AST, *, hosts: bool = False) -> bool:
        """True when `expr` is a literal set, list, tuple or dict (its keys)
        whose every member is a constant, written inline or as a Name with ONE
        binding in the module that nothing mutates (`.add(...)`, `|=`,
        `ALLOWED[k] = ...`). With `hosts`, every member must be a non-empty
        string. Otherwise a member may also be a Name bound to a constant or
        a dotted attribute (`Color.RED`) that reads no request input.

        A literal holding request data (`{request.args["host"]}`), an
        allowlist extended at run time and one rebound anywhere bound
        nothing the analyzer can see (R-001)."""
        if isinstance(expr, ast.Name):
            if not self._allowlist_name_is_stable(expr.id):
                return False
            expr = self._resolve_binding(expr)
        if isinstance(expr, ast.Dict):
            if any(k is None for k in expr.keys):  # `**other`
                return False
            members = list(expr.keys)
        elif isinstance(expr, (ast.Set, ast.List, ast.Tuple)):
            members = list(expr.elts)
        else:
            return False
        return all(self._allowlist_member_is_constant(m, hosts) for m in members)

    def _allowlist_member_is_constant(self, member: ast.AST, hosts: bool) -> bool:
        if isinstance(member, ast.Constant):
            if hosts:
                return isinstance(member.value, str) and member.value != ""
            return True
        if hosts:
            return False
        if isinstance(member, ast.Name):
            return isinstance(self._resolve_binding(member), ast.Constant)
        if isinstance(member, ast.Attribute):
            node: ast.AST = member
            while isinstance(node, ast.Attribute):
                node = node.value
            if not isinstance(node, ast.Name) or _references_request_input(member):
                return False
            # `Color.RED` names a module-level class or module. An attribute
            # of a parameter or a local (`self.mode`) is run-time state.
            if self._func_stack:
                func = self._func_stack[-1]
                params = {a.arg for a in ast.walk(func.args) if isinstance(a, ast.arg)}
                if node.id in params or _stores_of(func, node.id):
                    return False
            return True
        return False

    def _allowlist_name_is_stable(self, name: str) -> bool:
        """True when the module binds `name` exactly once (counting every
        scope, which can only over-count), never mutates it in place, and,
        when it is bound to a mutable collection, never lets the collection
        escape under another name (`_allowlist_escapes`, redteam-r001-01)."""
        cache = self._allowlist_stable
        if name in cache:
            return cache[name]
        # An alias cycle (`A = B` read while judging B) is not stable.
        cache[name] = False
        root = self._module_root
        stable = False
        if root is not None:
            binds = 0
            mutated = False
            bound_value: ast.AST | None = None
            for node in ast.walk(root):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and any(
                    isinstance(t, ast.Name) and t.id == name
                    for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
                ):
                    bound_value = node.value
                if _binds_name(node, name):
                    binds += 1
                elif isinstance(node, ast.Call):
                    fn = node.func
                    mutated = mutated or (
                        isinstance(fn, ast.Attribute)
                        and fn.attr in self._COLLECTION_MUTATORS
                        and isinstance(fn.value, ast.Name)
                        and fn.value.id == name
                    )
                elif isinstance(node, ast.AugAssign):
                    mutated = mutated or (
                        isinstance(node.target, ast.Name) and node.target.id == name
                    )
                elif isinstance(node, ast.Subscript) and not isinstance(node.ctx, ast.Load):
                    mutated = mutated or (
                        isinstance(node.value, ast.Name) and node.value.id == name
                    )
            stable = binds == 1 and not mutated
            if stable and isinstance(bound_value, (ast.Set, ast.List, ast.Dict, ast.Name)):
                stable = not self._allowlist_escapes(name) and not self._allowlist_shared(name)
        cache[name] = stable
        return stable

    def _allowlist_shared(self, name: str) -> bool:
        """True when another project file may reach the module-level
        collection `name` and change it: it imports the name or reads it as
        an attribute (`from app import ALLOWED`, `app.ALLOWED.add(h)`), which
        this file's own analysis cannot see (redteam2-r001-01). Without the
        project's file list (`_ProjectMentions`) nothing is known, so the
        collection counts as shared."""
        mentions = self._project_mentions
        if mentions is None:
            return True
        return mentions.reached_from_outside(name, self._rel)

    # Calls that read a collection argument without keeping or changing it.
    _READ_ONLY_COLLECTION_CALLS = frozenset(
        {
            "len", "sorted", "list", "tuple", "set", "frozenset", "dict", "str", "repr",
            "print", "any", "all", "iter", "min", "max", "sum", "enumerate", "reversed",
            "isinstance", "bool", "hash", "format", "map", "filter", "zip",
        }
    )

    def _allowlist_escapes(self, name: str) -> bool:
        """True when a read of the module-level collection `name` hands the
        collection itself to code that can change it, which the
        name-based mutation check cannot see (redteam-r001-01): an alias
        that is mutated or escapes in turn (`A2 = ALLOWED; A2.add(x)`), an
        argument to a call that is not a known read-only builtin, a value
        stored into another object or container, returned or yielded.

        Reads that keep no reference are fine: a membership or other
        comparison, an attribute read (`ALLOWED.copy()`; the mutating
        methods are counted as mutation), a subscript read, iteration,
        truthiness, formatting, `", ".join(ALLOWED)`."""
        root = self._module_root
        if root is None:
            return True
        for node in ast.walk(root):
            if not (isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)):
                continue
            parent = self._parent_of(node)
            if isinstance(
                parent,
                (ast.Compare, ast.FormattedValue, ast.BoolOp, ast.UnaryOp, ast.Expr),
            ):
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                # A mutating method read without being called right away is a
                # bound method that changes the collection wherever it goes
                # (`f = ALLOWED.add; f(h)`, redteam2-r001-01). Called in
                # place, `_allowlist_name_is_stable` counts it as mutation.
                grand = self._parent_of(parent)
                if parent.attr in self._COLLECTION_MUTATORS and not (
                    isinstance(grand, ast.Call) and grand.func is parent
                ):
                    return True
                continue
            if isinstance(parent, ast.Subscript) and parent.value is node:
                continue
            if isinstance(parent, (ast.If, ast.While, ast.IfExp, ast.Assert)) and parent.test is node:
                continue
            if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)) and parent.iter is node:
                continue
            if isinstance(parent, ast.Call) and any(a is node for a in parent.args):
                fn = parent.func
                if (
                    isinstance(fn, ast.Name)
                    and fn.id in self._READ_ONLY_COLLECTION_CALLS
                    and fn.id not in self._file_defined_names()
                    and fn.id not in self._from_imports
                ):
                    continue
                if (
                    isinstance(fn, ast.Attribute)
                    and fn.attr == "join"
                    and isinstance(fn.value, ast.Constant)
                    and isinstance(fn.value.value, str)
                ):
                    continue
                return True
            if (
                isinstance(parent, ast.Assign)
                and parent.value is node
                and len(parent.targets) == 1
                and isinstance(parent.targets[0], ast.Name)
            ):
                if self._allowlist_name_is_stable(parent.targets[0].id):
                    continue
                return True
            return True
        return False

    # The sink classes a sanitiser is typed by (R-002 / R-058): what the sink
    # is vulnerable to. "url_part" is a URL sink whose argument embeds the
    # value after other text (see `_hop_sink_class`). "other" (SSTI, LLM
    # prompts, JWT, weak hashes, ...) honours only the sanitisers that bound a
    # value to constants.
    #
    # "path" is a path used as a FILE whose request value is the whole path
    # or the last, sole request-carrying part of a join: a basename-reduced
    # caller argument contains it. "path_strict" is every other path use (a
    # directory, a part followed by more parts, a use not known to reject a
    # directory): only `secure_filename` contains it, since `basename("..")`
    # is ".." (redteam-r006-01).
    _SINK_CLASSES = frozenset(
        {"html", "url", "url_part", "path", "path_strict", "shell", "sql", "other"}
    )

    # Escaping/encoding neutralizers that make a value safe to render (#24).
    # HTML sinks only (R-058): none of them fixes a URL's host or removes a
    # path's directory structure or a shell's metacharacters.
    #
    # Resolved through the file's imports (`_callee_qualname`), never on the
    # terminal name (redteam-r058-01): `shlex.quote`, `pipes.quote` and
    # `re.escape` leave `<` and `>` alone, and a project's own `escape()` or
    # `clean()` may return its argument unchanged. `urllib.parse.quote`
    # percent-encodes `<>"'&` unless its `safe=` set keeps them
    # (`_URL_QUOTE_ESCAPES`). `markupsafe.Markup(x)` marks a value safe
    # without escaping it, so it is not here.
    _HTML_ESCAPES = frozenset(
        {
            "html.escape",
            "cgi.escape",
            "markupsafe.escape",
            "markupsafe.escape_silent",
            "markupsafe.Markup.escape",
            "jinja2.escape",
            "jinja2.utils.escape",
            "jinja2.Markup.escape",
            "flask.escape",
            "werkzeug.escape",
            "werkzeug.utils.escape",
            "django.utils.html.escape",
            "django.utils.html.conditional_escape",
            "django.utils.html.escapejs",
            "django.template.defaultfilters.escape",
            "django.template.defaultfilters.force_escape",
            "django.template.defaultfilters.escapejs",
            "bleach.clean",
            "nh3.clean",
        }
    )
    _URL_QUOTE_ESCAPES = frozenset({"urllib.parse.quote", "urllib.parse.quote_plus"})
    # Escapes with a `quote` flag that decides whether `"` and `'` are
    # escaped, and the flag's default.
    _QUOTE_FLAG_ESCAPES: Mapping[str, bool] = {"html.escape": True, "cgi.escape": False}
    # The bleach sanitiser classes whose instances' `.clean(x)` escapes.
    _HTML_CLEANER_CLASSES = frozenset({"bleach.Cleaner", "bleach.sanitizer.Cleaner"})

    # Modules whose `quote` makes a value one shell word.
    _SHELL_QUOTE_MODULES = frozenset({"shlex", "pipes"})

    def _is_html_escape_call(self, call: ast.Call) -> bool:
        """True when `call` escapes markup (see `_HTML_ESCAPES`)."""
        name = self._callee_qualname(call.func)
        if name in self._QUOTE_FLAG_ESCAPES:
            # `html.escape(x, quote=False)` leaves `"` and `'` alone, so the
            # value breaks out of a quoted attribute (redteam2-r058-01);
            # `cgi.escape` does so by default. Only a literal true `quote`
            # (or html.escape's default) escapes for every HTML context.
            quote: ast.AST | None = call.args[1] if len(call.args) > 1 else None
            for kw in call.keywords:
                if kw.arg == "quote":
                    quote = kw.value
                elif kw.arg is None:  # `**opts` may carry `quote=`
                    return False
            if quote is None:
                return self._QUOTE_FLAG_ESCAPES[name]
            return isinstance(quote, ast.Constant) and quote.value is True
        if name in self._HTML_ESCAPES:
            return True
        if name in self._URL_QUOTE_ESCAPES:
            safe = call.args[1] if len(call.args) > 1 else None
            for kw in call.keywords:
                if kw.arg == "safe":
                    safe = kw.value
                elif kw.arg is None:  # `**opts` may carry `safe=`
                    return False
            if safe is None:
                return True
            if not isinstance(safe, ast.Constant) or not isinstance(safe.value, (str, bytes)):
                return False
            markup = "<>\"'&" if isinstance(safe.value, str) else b"<>\"'&"
            return not any(c in safe.value for c in markup)
        # `cleaner.clean(x)` on a `bleach.Cleaner(...)` instance.
        fn = call.func
        if isinstance(fn, ast.Attribute) and fn.attr == "clean":
            recv = self._resolve_binding(fn.value) if isinstance(fn.value, ast.Name) else fn.value
            return isinstance(recv, ast.Call) and (
                self._callee_qualname(recv.func) in self._HTML_CLEANER_CLASSES
            )
        return False

    def _is_shell_quoted(
        self, expr: ast.AST, _resolving: frozenset[str] = frozenset()
    ) -> bool:
        """True when `expr` is `shlex.quote(x)` (or `pipes.quote`), written
        through the module or as a bare `quote` imported from it, or a Name
        bound to such a call. `urllib.parse.quote` is not: matched on the
        module, never on the terminal name alone."""
        if isinstance(expr, ast.Call):
            fn = expr.func
            if isinstance(fn, ast.Attribute):
                return (
                    fn.attr == "quote"
                    and isinstance(fn.value, ast.Name)
                    and self._module_aliases.get(fn.value.id, fn.value.id)
                    in self._SHELL_QUOTE_MODULES
                    and not self._name_is_shadowed(fn.value.id, fn.value)
                )
            if isinstance(fn, ast.Name):
                origin = self._from_imports.get(fn.id)
                return (
                    origin is not None
                    and origin[0] in self._SHELL_QUOTE_MODULES
                    and origin[1] == "quote"
                    and not self._name_is_shadowed(fn.id, fn)
                )
            return False
        if isinstance(expr, ast.Name) and expr.id not in _resolving:
            for scope in reversed(self._scopes):
                if expr.id in scope:
                    return self._is_shell_quoted(scope[expr.id], _resolving | {expr.id})
        return False

    def _is_escaped_call(
        self, expr: ast.AST, _resolving: frozenset[str] = frozenset()
    ) -> bool:
        """True if `expr` is a call to a recognized HTML escaping function
        (`_HTML_ESCAPES`: html.escape, markupsafe.escape, django's escape,
        bleach.clean, ...; `urllib.parse.quote` with a safe set that keeps no
        markup character), resolved through the file's imports, or a Name
        bound to such a call (#24, redteam-r058-01).

        ``_resolving`` holds the Names being followed, so a binding that reads
        its own name (``html = html``) ends instead of recursing until the
        file is skipped at the recursion limit."""
        if isinstance(expr, ast.Call):
            return self._is_html_escape_call(expr)
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

    # Calls that reduce a value to a single path component, resolved through
    # the file's imports (`_callee_qualname`, redteam-r006-02): a project's
    # own `basename()` may return its argument unchanged.
    #
    #   * "secure": Werkzeug's `secure_filename()` strips separators and
    #     traversal sequences (`secure_filename("..")` is ""), so it contains
    #     a value anywhere in a path.
    #   * "basename": `os.path.basename()` (also `posixpath`/`ntpath`) and
    #     pathlib's `Path(x).name` drop the directories but KEEP `..`:
    #     `os.path.basename("..")` is "..". `ROOT/<basename>` is at worst
    #     `ROOT/..`, a directory, which a sink that reads or writes a FILE
    #     rejects; anywhere else (a directory sink, a part followed by more
    #     parts) it climbs out of ROOT (redteam-r006-01).
    _SECURE_FILENAME_CALLS = frozenset({"werkzeug.utils.secure_filename", "werkzeug.secure_filename"})
    _BASENAME_CALLS = frozenset({"os.path.basename", "posixpath.basename", "ntpath.basename"})
    _PATHLIB_CTORS = frozenset({"Path", "PurePath", "PurePosixPath", "PureWindowsPath"})

    def _containment_kind(self, expr: ast.AST) -> str | None:
        """"secure", "basename" or None for `expr` itself (see above)."""
        if isinstance(expr, ast.Call):
            name = self._callee_qualname(expr.func)
            if name in self._SECURE_FILENAME_CALLS:
                return "secure"
            if name in self._BASENAME_CALLS:
                return "basename"
            return None
        if (
            isinstance(expr, ast.Attribute)
            and expr.attr == "name"
            and isinstance(expr.value, ast.Call)
        ):
            # The RECEIVER must be a pathlib construction. Matching `.name` on
            # any receiver is wrong and was actively harmful: Django's
            # `request.FILES['f'].name` is the filename the UPLOADER chose.
            fn = expr.value.func
            if isinstance(fn, ast.Name) and fn.id in self._PATHLIB_CTORS:
                if fn.id in self._file_defined_names() or self._name_is_shadowed(fn.id, fn):
                    return None
                origin = self._from_imports.get(fn.id)
                if origin is None or origin == ("pathlib", fn.id):
                    return "basename"
                return None
            name = self._callee_qualname(fn)
            if name.startswith("pathlib.") and name.split(".", 1)[1] in self._PATHLIB_CTORS:
                return "basename"
        return None

    def _path_is_contained(
        self,
        arg: ast.AST,
        sink_line: int,
        *,
        aliases_are_sole: bool = True,
        file_sink: bool = True,
        _use: ast.AST | None = None,
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

        A join (`os.path.join(ROOT, basename(name))`, `Path(ROOT) /
        secure_filename(name)`) is contained when every part is a constant
        or trusted base or is reduced to one path component
        (`_path_join_uncontained_parts`, R-006).

        `file_sink` is True when the path goes to a sink that reads or writes
        a FILE (`open`, `send_file`, ...). Only then does a basename-reduced
        value count (`_containment_kind`): `basename("..")` is "..", which a
        directory sink climbs out with (redteam-r006-01).
        """
        if self._path_join_uncontained_parts(arg, sink_line, file_sink=file_sink) == []:
            return True
        kind = self._containment_kind(arg)
        if kind == "secure" or (kind == "basename" and file_sink):
            return True
        if isinstance(arg, ast.Name):
            if self._name_is_traversal_rejected(arg.id, sink_line, arg):
                return True
            if aliases_are_sole and self._path_containment_asserted(
                arg.id, sink_line, arg
            ):
                return True
            # RC-11 G: a recognised guard (a project helper, or an inline test,
            # anywhere that dominates the sink) checks this name. `_use` is the
            # name as the sink reads it, kept through the alias hops below.
            if aliases_are_sole and self._g_name_is_guarded(arg.id, _use or arg):
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
                        bound,
                        sink_line,
                        aliases_are_sole=sole,
                        file_sink=file_sink,
                        _use=_use or arg,
                    )
        return False

    # ─── joins whose request parts are one path component (R-006) ────
    #
    # `os.path.join(ROOT, os.path.basename(name))` cannot leave ROOT: the
    # joined part has no separator, and a part without one cannot be absolute
    # either, so the join does not restart at `/`. The same holds for
    # `secure_filename(name)` and `Path(name).name`, and for pathlib's
    # `Path(ROOT) / part` and `.joinpath(part)`. Every OTHER part must be a
    # constant or a trusted, unproven base: `join(request.args["d"],
    # basename(f))` is still traversal, through its directory.
    #
    # DELIBERATELY ABSENT as a contained part: a Name guarded by `".." in
    # name` and an asserted containment. Neither stops an absolute part, and
    # `join(ROOT, "/etc/passwd")` is `/etc/passwd`.

    def _path_join_parts(self, expr: ast.AST, _depth: int = 0) -> list[ast.AST] | None:
        """The parts of a path join, flattened: `os.path.join(a, b, ...)`,
        `<pathlib path> / b` and `<pathlib path>.joinpath(b, ...)`; None
        for anything else, or a join with a starred part or a keyword."""
        if _depth >= _MAX_TAINT_HOPS:
            return None
        if isinstance(expr, ast.Call):
            if self._is_os_path_call(expr, "join"):
                if len(expr.args) < 2 or expr.keywords:
                    return None
                if any(isinstance(a, ast.Starred) for a in expr.args):
                    return None
                return list(expr.args)
            fn = expr.func
            if (
                isinstance(fn, ast.Attribute)
                and fn.attr == "joinpath"
                and expr.args
                and not expr.keywords
                and not any(isinstance(a, ast.Starred) for a in expr.args)
                and self._is_pathlib_path(fn.value)
            ):
                head = self._path_join_parts(fn.value, _depth + 1) or [fn.value]
                return head + list(expr.args)
            return None
        if (
            isinstance(expr, ast.BinOp)
            and isinstance(expr.op, ast.Div)
            and self._is_pathlib_path(expr.left)
        ):
            head = self._path_join_parts(expr.left, _depth + 1) or [expr.left]
            return head + [expr.right]
        return None

    def _path_join_uncontained_parts(
        self, expr: ast.AST, sink_line: int, *, file_sink: bool = True
    ) -> list[ast.AST] | None:
        """For a path join (`_path_join_parts`), the parts that are not
        contained, in order; an empty list when the join is contained. None
        when `expr` is not a join. See `_join_part_statuses`."""
        parts = self._path_join_parts(expr)
        if parts is None:
            return None
        return [
            p
            for p, contained, _lenient in self._join_part_statuses(parts, sink_line, file_sink)
            if not contained
        ]

    def _join_part_statuses(
        self, parts: list[ast.AST], sink_line: int, file_sink: bool
    ) -> list[tuple[ast.AST, bool, bool]]:
        """`(part, contained, basename_ok)` for each part of a join.

        A part is contained when it is a constant or trusted base
        (`_join_part_is_trusted`) or `secure_filename`-reduced, or when it is
        basename-reduced and `basename_ok`: the join goes to a FILE sink
        (`file_sink`), the part is the LAST one, and every other part is a
        trusted base or `secure_filename`-reduced. `ROOT/a/b/..` then names a
        directory inside ROOT, which a file sink rejects. A basename part
        anywhere else (`join(ROOT, basename(t), name)`, a directory sink)
        climbs out of ROOT with `..` (redteam-r006-01)."""
        kinds = [self._single_component_kind(p) for p in parts]
        safe_other = [
            kind == "secure" or (kind is None and self._join_part_is_trusted(p, sink_line))
            for p, kind in zip(parts, kinds)
        ]
        out: list[tuple[ast.AST, bool, bool]] = []
        last = len(parts) - 1
        for i, (p, kind) in enumerate(zip(parts, kinds)):
            basename_ok = (
                file_sink
                and i == last
                and all(safe_other[j] for j in range(len(parts)) if j != i)
            )
            contained = safe_other[i] or (kind == "basename" and basename_ok)
            out.append((p, contained, basename_ok))
        return out

    def _single_component_kind(self, expr: ast.AST, _depth: int = 0) -> str | None:
        """The containment kind (`_containment_kind`) of `expr`, or of the
        value a Name's ONLY binding in the enclosing function gives it. A
        name bound on two branches (`safe = name` / `safe = basename(name)`)
        has none: the scope chain records one binding, and the other may be
        the raw value."""
        if _depth >= _MAX_TAINT_HOPS:
            return None
        if isinstance(expr, ast.Name):
            if not self._func_stack:
                return None
            binding = self._sole_top_level_assign(self._func_stack[-1], expr.id)
            if binding is None or binding.lineno >= getattr(expr, "lineno", 0):
                return None
            return self._single_component_kind(binding.value, _depth + 1)
        return self._containment_kind(expr)

    # ─── what a path value is used for (redteam-r006-01) ─────────────
    #
    # A basename-reduced part is contained only when the path is used as a
    # FILE. These calls read, write or remove the file at their path argument
    # and fail on a directory (`open("/srv/uploads/..")` is IsADirectoryError).
    # `.save(path)` is Werkzeug's `FileStorage.save` (and PIL's
    # `Image.save`), which open the path for writing.
    _FILE_PATH_CALLS = frozenset({"os.remove", "os.unlink"})
    # The `open` calls that open their path argument as a file and raise
    # IsADirectoryError on a directory. `os.open` is not one.
    _FILE_OPEN_CALLS = frozenset(
        {"io.open", "codecs.open", "gzip.open", "bz2.open", "lzma.open", "builtins.open"}
    )
    _FILE_PATH_METHODS = frozenset({"save"})
    # pathlib methods that open the file at the path.
    _PATHLIB_FILE_METHODS = frozenset(
        {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink"}
    )
    # Calls that hand their argument's path on unchanged in kind: the result
    # is judged by how IT is used.
    _PATH_PASS_THROUGH = frozenset({"os.path.realpath", "os.path.abspath", "os.path.normpath"})
    # Calls that only inspect a path; a use by one neither makes the path a
    # file nor a directory.
    _PATH_PREDICATES = frozenset(
        {
            "os.path.exists",
            "os.path.lexists",
            "os.path.isfile",
            "os.path.isdir",
            "os.path.islink",
            "os.path.getsize",
            "os.path.getmtime",
            "os.path.getctime",
            "os.path.getatime",
        }
    )

    def _enclosing_scope_of(self, node: ast.AST) -> ast.AST | None:
        """The def (or the module) whose body holds `node`."""
        current = self._parent_of(node)
        while current is not None and not isinstance(
            current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)
        ):
            current = self._parent_of(current)
        return current if current is not None else self._module_root

    def _same_file_def(self, func: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """The module-level def a bare-name call names, when the file defines
        that name exactly once, at top level, and nothing rebinds it."""
        root = self._module_root
        if not isinstance(func, ast.Name) or root is None:
            return None
        if func.id in self._from_imports or self._scope_binding(func.id) is not None:
            return None
        defs = [
            n
            for n in root.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func.id
        ]
        if len(defs) != 1 or len(_stores_of(root, func.id)) != 1:
            return None
        return defs[0]

    def _param_used_as_file(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, param: str, _depth: int
    ) -> bool:
        """True when every read of parameter `param` in `func` is a file use
        (`_use_is_file`), at least one of them is, and `func` never rebinds
        it."""
        if _stores_of(func, param):
            return False
        uses = [
            n
            for stmt in func.body
            for n in ast.walk(stmt)
            if isinstance(n, ast.Name) and n.id == param and isinstance(n.ctx, ast.Load)
        ]
        verdicts = [self._use_is_file(u, _depth + 1) for u in uses]
        return any(v is True for v in verdicts) and all(v is not False for v in verdicts)

    def _parent_of(self, node: ast.AST) -> ast.AST | None:
        """`node`'s parent in the module tree (built once per file)."""
        parents = getattr(self, "_parents", None)
        if parents is None:
            parents = {}
            if self._module_root is not None:
                for p in ast.walk(self._module_root):
                    for c in ast.iter_child_nodes(p):
                        parents[c] = p
            self._parents = parents
        return parents.get(node)

    def _path_feeds_file_sink(self, node: ast.AST, _depth: int = 0) -> bool:
        """True when the path value `node` (a join, a `Path(...)`, an
        `os.path.*` call) is used ONLY as a file: the path argument of a file
        sink (`_use_is_file`), directly, through a pass-through call
        (`realpath(...)`, `Path(...)`), or through a Name whose only binding
        in the function it is, every read of which is such a use or a mere
        predicate (`os.path.isfile(p)`). Anything else, a directory sink, a
        return or an unknown call included, is False: the use is not known
        to reject a directory (redteam-r006-01)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        parent = self._parent_of(node)
        if isinstance(parent, ast.Assign):
            if (
                parent.value is not node
                or len(parent.targets) != 1
                or not isinstance(parent.targets[0], ast.Name)
            ):
                return False
            name = parent.targets[0].id
            scope = self._enclosing_scope_of(parent)
            if scope is None or self._sole_top_level_assign(scope, name) is not parent:
                return False
            uses = [
                n
                for stmt in scope.body
                for n in ast.walk(stmt)
                if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
            ]
            verdicts = [self._use_is_file(u, _depth + 1) for u in uses]
            return any(v is True for v in verdicts) and all(v is not False for v in verdicts)
        return self._use_is_file(node, _depth) is True

    # Calls whose arguments are only logged or printed.
    _LOG_METHODS = frozenset(
        {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
    )

    def _use_is_file(self, node: ast.AST, _depth: int) -> bool | None:
        """True when the expression `node` is consumed as a file path, None
        when it is only inspected (`_PATH_PREDICATES`) or logged, False
        otherwise."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        parent = self._parent_of(node)
        if isinstance(parent, ast.FormattedValue):
            return None
        if isinstance(parent, ast.Call) and node is not parent.func:
            fn = parent.func
            if (isinstance(fn, ast.Attribute) and fn.attr in self._LOG_METHODS) or (
                isinstance(fn, ast.Name)
                and fn.id == "print"
                and fn.id not in self._file_defined_names()
            ):
                return None
        if isinstance(parent, ast.Attribute) and parent.value is node:
            grand = self._parent_of(parent)
            return (
                parent.attr in self._PATHLIB_FILE_METHODS
                and isinstance(grand, ast.Call)
                and grand.func is parent
                and self._is_pathlib_path(node)
            )
        if isinstance(parent, ast.keyword):
            call = self._parent_of(parent)
        elif isinstance(parent, ast.Call) and node is not parent.func:
            call = parent
        else:
            return False
        if not isinstance(call, ast.Call):
            return False
        positional = bool(call.args) and call.args[0] is node
        sink = self._path_traversal_sink_name(call)
        if sink in ("open", "send_file", "FileResponse"):
            # Only an `open` that opens a FILE: the builtin and the ones built
            # on it (`_FILE_OPEN_CALLS`). `os.open(dir, os.O_RDONLY)` opens a
            # directory, so `os.open(join(ROOT, basename("..")))` hands out
            # ROOT's parent (redteam2-r006-01).
            if sink == "open" and not self._opens_a_file(call.func):
                return False
            return positional or (
                isinstance(parent, ast.keyword)
                and parent.arg in ("file", "path", "path_or_file", "filename_or_fp")
            )
        if sink == "Path" and positional and len(call.args) == 1:
            return self._path_feeds_file_sink(call, _depth + 1)
        # A helper of this file: judged by what it does with the parameter
        # (`serve(join(ROOT, basename(n)))` where `serve(p)` sends `p`).
        helper = self._same_file_def(call.func)
        if helper is not None:
            params = [a.arg for a in helper.args.posonlyargs + helper.args.args]
            if isinstance(parent, ast.keyword):
                param = parent.arg
            else:
                index = next(i for i, a in enumerate(call.args) if a is node)
                param = params[index] if index < len(params) else None
            if param is None or any(isinstance(a, ast.Starred) for a in call.args):
                return False
            return self._param_used_as_file(helper, param, _depth)
        name = self._callee_qualname(call.func)
        if not positional:
            return False
        if name in self._PATH_PREDICATES:
            return None
        if name in self._PATH_PASS_THROUGH:
            return self._path_feeds_file_sink(call, _depth + 1)
        if name in self._FILE_PATH_CALLS:
            return True
        fn = call.func
        return isinstance(fn, ast.Attribute) and fn.attr in self._FILE_PATH_METHODS and not name

    def _join_part_is_trusted(self, expr: ast.AST, sink_line: int) -> bool:
        """True when a join part is a constant path, or a trusted
        non-request base (`_path_is_trusted_source`, or a framework config
        read such as `app.config["UPLOAD_FOLDER"]`) that no request flow
        reaches."""
        if self._expr_is_constant_path(expr):
            return True
        if _references_request_input(expr):
            return False
        # `Path(ROOT)`: a pathlib path built from trusted parts.
        if (
            self._is_pathlib_ctor_call(expr)
            and expr.args
            and not expr.keywords
            and all(self._join_part_is_trusted(a, sink_line) for a in expr.args)
        ):
            return True
        trusted = self._path_is_trusted_source(expr) or (
            isinstance(expr, ast.Subscript)
            and isinstance(expr.value, ast.Attribute)
            and expr.value.attr == "config"
            and isinstance(expr.slice, ast.Constant)
            and isinstance(expr.slice.value, str)
        )
        # A base is a directory: only `secure_filename` contains a caller's
        # value there (`path_strict`).
        return trusted and (
            self._collect_taint_chain(expr, sink_line, "", sink_class="path_strict") is None
        )

    def _name_is_traversal_rejected(
        self, name: str, sink_line: int, use: ast.AST | None = None
    ) -> bool:
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

        A '..' guard alone is not containment: `open("/etc/passwd")` has no
        '..' (redteam2-py-02). An ABSOLUTE path must be rejected too, by a
        dominating guard on the same name (`_rejects_absolute`), the same
        `if` (`if ".." in name or os.path.isabs(name):`) or another one.

        Each guard counts only for the value it tested (redteam3-py-01,
        `_guard_covers`): after `if ".." in name or os.path.isabs(name):
        abort()`, a `name = unquote(name)` or `name = "/" + name` before the
        sink is a new value the guards never saw, and the sink is reported.
        """

        def operands(test: ast.AST) -> list[ast.AST]:
            # `if A or B: <exit>` rejects A and B each.
            if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
                return list(test.values)
            return [test]

        def is_dotdot_test(test: ast.AST) -> bool:
            # `".." in name` — a traversal sequence being looked for.
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

        def covers(test: ast.AST) -> bool:
            return self._guard_covers(
                name, _loads_of(test, name), use, (test.lineno, test.col_offset)
            )

        def rejects_traversal(test: ast.AST) -> bool:
            return any(is_dotdot_test(t) for t in operands(test)) and covers(test)

        def rejects_absolute(test: ast.AST) -> bool:
            return any(
                self._is_absolute_path_test(t, name) for t in operands(test)
            ) and covers(test)

        return self._has_dominating_exit_guard(
            sink_line, rejects_traversal
        ) and self._has_dominating_exit_guard(sink_line, rejects_absolute)

    def _is_absolute_path_test(self, test: ast.AST, name: str) -> bool:
        """True when `test` is True for every absolute POSIX path in `name`:
        `os.path.isabs(name)` (or posixpath's), `name.startswith("/")` (a
        tuple holding "/", or `os.sep`), or `Path(name).is_absolute()`,
        each resolved through the file's imports (redteam2-py-02)."""
        if not isinstance(test, ast.Call):
            return False

        def is_name(node: ast.AST) -> bool:
            return isinstance(node, ast.Name) and node.id == name

        fn = test.func
        if self._callee_qualname(fn) in ("os.path.isabs", "posixpath.isabs"):
            return len(test.args) == 1 and is_name(test.args[0]) and not test.keywords
        if not isinstance(fn, ast.Attribute):
            return False
        if fn.attr == "startswith" and is_name(fn.value) and len(test.args) == 1:
            prefix = test.args[0]
            prefixes = prefix.elts if isinstance(prefix, ast.Tuple) else [prefix]
            return any(
                (isinstance(p, ast.Constant) and p.value == "/")
                or self._import_origin(p) in ("os.sep", "os.path.sep")
                for p in prefixes
            )
        if fn.attr == "is_absolute" and not test.args and isinstance(fn.value, ast.Call):
            ctor = fn.value
            return (
                self._is_pathlib_ctor_call(ctor)
                and len(ctor.args) == 1
                and is_name(ctor.args[0])
            )
        return False

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

    def _path_containment_asserted(
        self, name: str, sink_line: int, use: ast.AST | None = None
    ) -> bool:
        """Return True when `name` is a resolved path that a dominating guard
        asserts is under a fixed base directory, leaving the function when it
        is not (the accepted shapes are listed above).

        `name` must be resolved by a top-level
        `name = os.path.realpath(...)` or `name = <pathlib path>.resolve()`
        that comes before the guard, and it must be the only definition that
        reaches the guard. Any other definition that can supply the sink's
        value (on a branch, as a loop target, after the guard) could put an
        unresolved or unchecked value under the same name, so it disqualifies
        the guard (`_guard_covers`).

        Dominance follows `_has_dominating_exit_guard`. A sink inside the
        rejecting body is not covered. A sink in the guard's `else` is, since
        that branch runs only when the containment test passed. The `try`
        form must end before the sink.
        """
        return self._path_containment_guard(name, sink_line, use) is not None

    def _path_containment_guard(
        self, name: str, sink_line: int, use: ast.AST | None = None
    ) -> ast.stmt | None:
        """The first guard `_path_containment_asserted` accepts for `name`
        before `sink_line` (an `if` or a `try`), or None.

        The guard must have tested the resolved value and nothing else: the
        one definition of `name` that reaches it is the top-level
        `name = <resolved path>` (`_guard_covers(only=...)`), and every
        definition that reaches the use also reached the guard."""
        if self._guards_off or not self._func_stack:
            return None
        bound = self._resolve_binding(ast.Name(id=name, ctx=ast.Load()))
        if bound is None or not self._is_resolved_path(bound):
            return None
        binding = next(
            (
                stmt
                for stmt in self._func_stack[-1].body
                if isinstance(stmt, ast.Assign)
                and stmt.value is bound
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == name
            ),
            None,
        )
        if binding is None:
            return None
        after = binding.end_lineno
        resolved_def = binding.targets[0]

        def rejects_uncontained(test: ast.AST) -> bool:
            return (
                test.lineno > after
                and self._test_rejects_uncontained(test, name)
                and self._guard_covers(
                    name,
                    _loads_of(test, name),
                    use,
                    (test.lineno, test.col_offset),
                    only=resolved_def,
                )
            )

        def asserts_relative(stmt: ast.Try) -> bool:
            if not (stmt.lineno > after and self._try_asserts_relative(stmt, name)):
                return False
            tested = [
                n
                for s in stmt.body
                if self._is_relative_to_call(s, name, stmt.lineno)
                for n in _loads_of(s, name)
            ]
            return self._guard_covers(
                name, tested, use, (stmt.lineno, stmt.col_offset), only=resolved_def
            )

        guard = self._dominating_exit_guard(
            sink_line,
            rejects_uncontained,
            before_sink="body_ends",
            try_pred=asserts_relative,
        )
        # RC-11 G criterion 4 and the path-library check apply to this older
        # recogniser too (verifier A-1, C-8): the root it accepts must be the base
        # the path was joined from or one below it, never a parent or a sibling,
        # and a module that patches `os.sep` and the like is not trusted.
        if guard is not None and (self._g_patched() or not self._g_inline_root_ok(name, guard, bound)):
            return None
        if isinstance(guard, ast.If):
            self._note_guard(guard.test)
        elif guard is not None:
            self._note_guard(guard, f"`relative_to` check on `{name}`")
        return guard

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

    # ─── RC-11 G: containment guards read by what they do ───────────────
    #
    # See the section "RC-11 G" above `_TEST_PATH_RE`. These methods find the
    # guards that dominate a sink, read each one (a project helper's body, or an
    # inline test), and check that it covers the value the sink receives.

    def _g_reader(self, fn: ast.AST) -> _ContainmentReader:
        cache = self.__dict__.setdefault("_g_reader_cache", {})
        got = cache.get(id(fn))
        if got is None or got[0] is not fn:
            got = cache[id(fn)] = (fn, _ContainmentReader(self._callee_qualname, fn))
        return got[1]

    def _g_names(self) -> dict[str, str]:
        names = getattr(self, "_g_module_names_cache", None)
        if names is None:
            names = _g_module_names(self._module_root) if self._module_root is not None else {}
            self._g_module_names_cache = names
        return names

    def _g_patched(self) -> bool:
        """True when this module patches the path libraries (`_g_patches_path_library`)."""
        patched = getattr(self, "_g_patched_cache", None)
        if patched is None:
            patched = self._module_root is not None and _g_patches_path_library(
                self._module_root, self._g_names()
            )
            self._g_patched_cache = patched
        return patched

    def _g_name_bound_once(self, name: str) -> bool:
        """True when the module binds `name` exactly once anywhere (`_g_bindings`)
        and no `from m import *` could bind it again: a star import binds names no
        static read can list, wherever it sits (CL2-1, verifier x15)."""
        cache = self.__dict__.setdefault("_g_bindings_cache", {})
        if name not in cache:
            cache[name] = (
                self._module_root is not None
                and _g_bindings(self._module_root, name) == 1
                and not _g_has_star_import(self._module_root)
            )
        return cache[name]

    def _g_locally_bound(self, name: str) -> bool:
        """True when an enclosing function binds `name` (a parameter or a
        store), so it is not the module-level function of that name."""
        return any(
            name in _param_names(f) or bool(_stores_of(f, name)) for f in self._func_stack
        )

    def _g_absolute_module(self, module: str, level: int) -> str:
        """The dotted module an import names, resolved against this file's own
        package when it is relative."""
        if not level:
            return module
        package = self._module_dotted.split(".") if self._module_dotted else []
        if not self._rel.replace("\\", "/").endswith("__init__.py"):
            package = package[:-1]
        if level > 1:
            package = package[: max(len(package) - (level - 1), 0)]
        if not package:
            return module
        return ".".join([*package, *([module] if module else [])])

    def _g_function_of_call(
        self, func: ast.AST
    ) -> tuple[ast.FunctionDef, dict[str, str], bool] | None:
        """The project function a call names, with the import table of its
        module: a top-level def of this file, or one the call index finds in the
        project module the file imports it from. None for anything else (a
        library function, a method, a rebound name, a file that does not
        parse)."""
        root = self._module_root
        if root is None:
            return None
        if isinstance(func, ast.Name):
            name = func.id
            if self._g_locally_bound(name) or not self._g_name_bound_once(name):
                return None
            if name in self._file_defined_names():
                fdef = _g_unique_function(root, name)
                return (fdef, self._g_names(), self._g_patched()) if fdef is not None else None
            origin = self._from_imports.get(name)
            if origin is None or self._call_index is None:
                return None
            module, symbol = origin
            absolute = self._g_absolute_module(module, self._from_import_levels.get(name, 0))
            return self._call_index.function_def(absolute, symbol) if absolute else None
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and self._call_index is not None
        ):
            head = func.value.id
            if self._g_locally_bound(head) or not self._g_name_bound_once(head):
                return None
            module = self._imported_modules.get(head)
            if module is not None:
                return self._call_index.function_def(module, func.attr)
            origin = self._from_imports.get(head)
            if origin is not None:
                base = self._g_absolute_module(origin[0], self._from_import_levels.get(head, 0))
                return self._call_index.function_def(
                    f"{base}.{origin[1]}" if base else origin[1], func.attr
                )
        return None

    def _g_call_summary(self, call: ast.Call) -> tuple[str, int, int] | None:
        """("bool"|"raises", root_param, target_param) when `call` names a
        project helper whose body is a containment check, else None."""
        found = self._g_function_of_call(call.func)
        if found is None:
            return None
        fdef, names, patched = found
        if patched:
            return None  # the module holding the helper patches the path libraries
        cache = self.__dict__.setdefault("_g_summary_cache", {})
        got = cache.get(id(fdef))
        if got is None or got[0] is not fdef:
            got = cache[id(fdef)] = (fdef, _g_summarize_helper(fdef, names))
        return got[1]

    def _g_stmt_of(self, node: ast.AST) -> ast.stmt | None:
        cur: ast.AST | None = node
        while cur is not None and not isinstance(cur, ast.stmt):
            cur = self._parent_of(cur)
        return cur

    def _g_guard_forms(self, stmt: ast.stmt) -> list[tuple[str, ast.AST, ast.stmt]]:
        """The guards a statement can be: `if <test>: <exit>` with no `else`,
        or a bare call (a helper that raises). An `assert` is not one: it is
        gone under `python -O`."""
        if isinstance(stmt, ast.If) and not stmt.orelse and self._body_ends_control_flow(stmt.body):
            return [("if_exit", stmt.test, stmt)]
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return [("bare", stmt.value, stmt)]
        return []

    def _g_guards_before(
        self, stmt: ast.stmt, fn: ast.AST
    ) -> list[tuple[str, ast.AST, ast.stmt]]:
        """The guards that dominate `stmt` on every path to it: the statements
        before it in its block and in each enclosing block of the function, and
        every enclosing `if` whose positive test is the containment. A guard in
        a sibling branch, after the statement, or in a `try` body the statement
        is not part of is never listed; neither is anything before a handler
        or a `finally` block."""
        found: list[tuple[str, ast.AST, ast.stmt]] = []
        cur: ast.AST = stmt
        while cur is not fn:
            parent = self._parent_of(cur)
            if parent is None:
                return []
            field = None
            siblings: list | None = None
            for name in ("body", "orelse", "finalbody", "handlers"):
                lst = getattr(parent, name, None)
                if isinstance(lst, list) and any(cur is s for s in lst):
                    field, siblings = name, lst
                    break
            if siblings is not None and field in ("body", "orelse"):
                for s in siblings[: next(i for i, x in enumerate(siblings) if x is cur)]:
                    found.extend(self._g_guard_forms(s))
            if isinstance(parent, ast.If) and field == "body":
                found.append(("if_pos", parent.test, parent))
            elif isinstance(parent, ast.If) and field == "orelse":
                negated = _g_negated(parent.test)
                if negated is not None:
                    found.append(("if_pos", negated, parent))
            cur = parent
        return found

    def _g_const_part(self, expr: ast.AST, reader: _ContainmentReader) -> bool:
        """A join part that cannot leave the directory it is joined to: a
        relative string constant without `..`, or a module-level name bound once
        to one."""
        if isinstance(expr, ast.Name) and expr.id not in reader.params:
            if reader.stores_at_or_after(expr.id, 0):
                return False
            bound = self._module_binding(expr.id)
            expr = bound if bound is not None else expr
        return (
            isinstance(expr, ast.Constant)
            and isinstance(expr.value, str)
            and bool(expr.value)
            and not expr.value.startswith("/")
            and ".." not in expr.value
        )

    def _g_narrower_root(self, reader: _ContainmentReader, root: ast.AST, base: str) -> bool:
        """True when `root` is `join(<the base>, <relative constants>)`: a
        directory below the base the path was joined from, so containment in it
        implies containment in the base."""
        e = root
        for _ in range(3):
            if isinstance(e, ast.Name) and e.id not in reader.params:
                value = reader.sole(e.id)
                if value is None:
                    break
                e = value
            else:
                break
        inner = reader.strip_resolve(e)
        e = inner if inner is not None else e
        return (
            isinstance(e, ast.Call)
            and reader.qual(e.func) in ("os.path.join", "posixpath.join")
            and len(e.args) >= 2
            and not e.keywords
            and all(self._g_const_part(a, reader) for a in e.args[1:])
            and reader.canon(e.args[0]) == base
        )

    def _g_use_reads_local(self, name: str, use: ast.AST, fn: ast.AST) -> bool:
        """True when the read of `name` at `use` is the function's own local
        and not a name an inner lambda, def or comprehension rebinds (R-pf25b):
        `(lambda full: open(full))(x)` reads its argument, not the checked path."""
        cur = self._parent_of(use)
        while cur is not None and cur is not fn:
            if isinstance(cur, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
                if name in _param_names(cur):
                    return False
                if not isinstance(cur, ast.Lambda) and _stores_of(cur, name):
                    return False
            elif isinstance(cur, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                if any(
                    isinstance(n, ast.Name) and n.id == name
                    for g in cur.generators
                    for n in ast.walk(g.target)
                ):
                    return False
            cur = self._parent_of(cur)
        return cur is fn

    def _g_value_of_name(
        self, name: str, reader: _ContainmentReader, guard_line: int
    ) -> ast.AST | None:
        """The value a base `name` holds when the guard at `guard_line` runs: its
        one assignment in the function (before the guard), or, for a name the
        function never stores, the module's single binding of it. None for a
        parameter, a name an enclosing function binds, or a name stored any other
        way: the caller or another function may have chosen it."""
        if name in reader.params:
            return None
        if reader.stores_at_or_after(name, 0):
            value = reader.sole(name)
            if value is None or reader.stores_at_or_after(name, guard_line):
                return None
            return value
        for enclosing in self._func_stack:
            if name in _param_names(enclosing) or (
                enclosing is not reader.fn and _stores_of(enclosing, name)
            ):
                return None
        return self._module_binding(name)

    def _g_base_is_trusted(
        self, expr: ast.AST, reader: _ContainmentReader, guard_line: int, _depth: int = 0
    ) -> bool:
        """True when `expr` is a base directory the code fixes: a string constant
        narrower than the filesystem root, a configuration attribute of an
        imported object (`settings.MEDIA_ROOT`), a call of a project function (a
        per-tenant directory), or a join, resolution or `Path` of those with
        relative constants, through names bound once. A parameter, an
        environment read, a rebound or `global` name and anything else is not:
        containment in a directory the caller or the environment picks bounds
        nothing (RC-11 G keeps `_is_fixed_base`'s refusals)."""
        if _depth > 4:
            return False
        inner = reader.strip_resolve(expr)
        if inner is not None:
            return self._g_base_is_trusted(inner, reader, guard_line, _depth + 1)
        if isinstance(expr, ast.Constant):
            return isinstance(expr.value, str) and _is_bounding_dir(expr.value)
        if isinstance(expr, ast.Name):
            value = self._g_value_of_name(expr.id, reader, guard_line)
            return value is not None and self._g_base_is_trusted(
                value, reader, guard_line, _depth + 1
            )
        if isinstance(expr, ast.Attribute):
            parts = []
            head: ast.AST = expr
            while isinstance(head, ast.Attribute):
                parts.append(head.attr)
                head = head.value
            return (
                isinstance(head, ast.Name)
                and (head.id in self._imported_modules or head.id in self._from_imports)
                and not self._g_locally_bound(head.id)
                and all(part.isupper() for part in parts)
            )
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            return self._g_base_is_trusted(
                expr.left, reader, guard_line, _depth + 1
            ) and self._g_const_part(expr.right, reader)
        if isinstance(expr, ast.Call):
            qual = reader.qual(expr.func)
            if qual in ("os.path.join", "posixpath.join") and len(expr.args) >= 2 and not expr.keywords:
                return self._g_base_is_trusted(
                    expr.args[0], reader, guard_line, _depth + 1
                ) and all(self._g_const_part(a, reader) for a in expr.args[1:])
            if qual in _G_PATH_CTORS and len(expr.args) == 1 and not expr.keywords:
                return self._g_base_is_trusted(expr.args[0], reader, guard_line, _depth + 1)
            return self._g_function_of_call(expr.func) is not None
        return False

    def _g_const_str(
        self, expr: ast.AST, reader: _ContainmentReader, guard_line: int, _depth: int = 0
    ) -> str | None:
        """The string a constant path expression holds, through names bound once,
        resolvers and joins of constants; None when it is not one."""
        if _depth > 4:
            return None
        inner = reader.strip_resolve(expr)
        if inner is not None:
            return self._g_const_str(inner, reader, guard_line, _depth + 1)
        if isinstance(expr, ast.Constant):
            return expr.value if isinstance(expr.value, str) else None
        if isinstance(expr, ast.Name):
            value = self._g_value_of_name(expr.id, reader, guard_line)
            return None if value is None else self._g_const_str(value, reader, guard_line, _depth + 1)
        if (
            isinstance(expr, ast.Call)
            and reader.qual(expr.func) in ("os.path.join", "posixpath.join")
            and expr.args
            and not expr.keywords
        ):
            parts = [self._g_const_str(a, reader, guard_line, _depth + 1) for a in expr.args]
            return None if any(p is None for p in parts) else posixpath.join(*parts)
        if (
            isinstance(expr, ast.Call)
            and reader.qual(expr.func) in _G_PATH_CTORS
            and len(expr.args) == 1
            and not expr.keywords
        ):
            return self._g_const_str(expr.args[0], reader, guard_line, _depth + 1)
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
            left = self._g_const_str(expr.left, reader, guard_line, _depth + 1)
            right = self._g_const_str(expr.right, reader, guard_line, _depth + 1)
            return None if left is None or right is None else posixpath.join(left, right)
        return None

    def _g_root_within_base(
        self, reader: _ContainmentReader, root: ast.AST, base: ast.AST, guard_line: int
    ) -> bool:
        """Criterion 4: the root a guard checks against is the base the path was
        joined from, or a directory below it; never a parent or a sibling. Equal
        or narrower by expression, or, when both are constants, by value after
        normalisation (`/srv/uploads/` and `/srv/uploads/../uploads` are
        `/srv/uploads`; `/srv` and `/srv/uploads2` are not within it)."""
        base_canon = reader.canon(base)
        if reader.canon(root) == base_canon or self._g_narrower_root(reader, root, base_canon):
            return True
        root_s = self._g_const_str(root, reader, guard_line)
        base_s = self._g_const_str(base, reader, guard_line)
        if root_s is None or base_s is None or not root_s.startswith("/") or not base_s.startswith("/"):
            return False
        root_n, base_n = posixpath.normpath(root_s), posixpath.normpath(base_s)
        return root_n == base_n or root_n.startswith(base_n.rstrip("/") + "/")

    def _g_guard_root(self, guard: ast.stmt, name: str) -> ast.AST | None:
        """The root the guard `guard` (an `if` or a `try`) compares `name` with:
        the shapes `_test_rejects_uncontained` and `_try_asserts_relative` accept."""
        if isinstance(guard, ast.Try):
            for s in guard.body:
                if self._is_relative_to_call(s, name, guard.lineno):
                    return s.value.args[0]
            return None
        test = guard.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            call = test.operand
            if self._is_one_arg_method_call(call, name):
                if call.func.attr == "startswith":
                    return self._component_prefix_base(call.args[0])
                if call.func.attr == "is_relative_to":
                    return call.args[0]
            return None
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotEq):
            for common, base in ((test.left, test.comparators[0]), (test.comparators[0], test.left)):
                if self._is_commonpath_with(common, name, base):
                    return base
        return None

    def _g_inline_root_ok(self, name: str, guard: ast.stmt, bound: ast.AST) -> bool:
        """The inline recogniser's guard (`_path_containment_guard`) must check
        the root the resolved path `bound` was joined from, or one below it.
        A path with no join base, or a guard shape this cannot read, is left to
        the recogniser's own fixed-base rule."""
        if not self._func_stack:
            return True
        reader = self._g_reader(self._func_stack[-1])
        base = reader.join_base_node(bound)
        if base is None:
            return True
        root = self._g_guard_root(guard, name)
        if root is None:
            return True
        return self._g_root_within_base(reader, root, base, guard.lineno)

    def _g_match(
        self,
        reader: _ContainmentReader,
        root: ast.AST,
        target: ast.AST,
        guard: ast.stmt,
        sink_value: ast.AST,
    ) -> bool:
        """True when a containment test of (`root`, `target`) at `guard` covers
        `sink_value`: criteria 3, 4 and 5 of the "RC-11 G" section."""
        line = guard.lineno
        for expr in (root, target, sink_value):
            for n in ast.walk(expr):
                if isinstance(n, ast.Name) and reader.stores_at_or_after(n.id, line):
                    return False  # rebound at or after the guard: same text, another value
        if reader.canon(target) != reader.canon(sink_value):
            return False
        base = reader.join_base_node(sink_value)
        if base is None:
            return False
        if not self._g_root_within_base(reader, root, base, line):
            return False
        if not self._g_base_is_trusted(root, reader, line):
            return False
        if _references_request_input(root):
            return False
        return self._collect_taint_chain(root, line, "containment root", sink_class="path") is None

    def _note_guard(self, test: ast.AST, what: str = "") -> None:
        """Remember that a recogniser accepted the guard whose test is `test` (OR-88),
        so a sink it lets through can be reported at WARN, naming the guard."""
        text = _ast_expr_text(test)
        if len(text) > 100:
            text = text[:97] + "..."
        line = getattr(test, "lineno", 0)
        note = f"`{text}`, line {line}" if not what else f"{what}, line {line}"
        if note not in self._guard_trace:
            self._guard_trace.append(note)

    def _g_guard_covers(
        self,
        guard: tuple[str, ast.AST, ast.stmt],
        reader: _ContainmentReader,
        sink_value: ast.AST,
    ) -> bool:
        if self._guards_off:
            return False  # OR-88: the sink is being re-read as if no guard were recognised
        covers = self._g_guard_covers_value(guard, reader, sink_value)
        if covers:
            self._note_guard(guard[1])
        return covers

    def _g_guard_covers_value(
        self,
        guard: tuple[str, ast.AST, ast.stmt],
        reader: _ContainmentReader,
        sink_value: ast.AST,
    ) -> bool:
        if self._g_patched():
            return False  # this module patches the path libraries
        kind, test, stmt = guard
        inner = test
        if kind == "if_exit":
            negated = _g_negated(test)
            if negated is None:
                return False
            inner = negated
        if isinstance(inner, ast.Call):
            summary = self._g_call_summary(inner)
            if summary is not None:
                form, root_i, target_i = summary
                if form != ("raises" if kind == "bare" else "bool"):
                    return False  # the helper does not behave the way the call uses it
                if (
                    inner.keywords
                    or any(isinstance(a, ast.Starred) for a in inner.args)
                    or max(root_i, target_i) >= len(inner.args)
                ):
                    return False
                return self._g_match(
                    reader, inner.args[root_i], inner.args[target_i], stmt, sink_value
                )
        if kind == "bare":
            return False
        pair = reader.pair(inner)
        return pair is not None and self._g_match(reader, pair[0], pair[1], stmt, sink_value)

    def _g_name_is_guarded(self, name: str, use: ast.AST) -> bool:
        """True when a guard recognised by `_g_guard_covers` dominates `use`, a
        read of the local `name`, and checks `name`."""
        if not self._func_stack:
            return False
        fn = self._func_stack[-1]
        reader = self._g_reader(fn)
        if name in reader.params or reader.sole(name) is None:
            return False
        stmt = self._g_stmt_of(use)
        if stmt is None or not self._g_use_reads_local(name, use, fn):
            return False
        sink_value = ast.Name(id=name, ctx=ast.Load())
        return any(
            self._g_guard_covers(g, reader, sink_value) for g in self._g_guards_before(stmt, fn)
        )

    def _g_join_is_guarded(self, join: ast.Call) -> bool:
        """True when the `os.path.join(...)` sink `join` is bound to a local
        name and EVERY read of that name is behind a recognised guard (or is the
        guard's own test), with at least one such guard. The join itself builds
        a string; the traversal happens where the name is used, and a guard that
        dominates each use makes the join safe, however the guards are nested."""
        # `realpath(join(...))` and `Path(join(...)).resolve()` are the join's
        # value once resolved in place (`_resolved_joins`): the name is bound to that.
        value = self._resolved_joins.get(join, join)
        parent = self._parent_of(value)
        if not (
            isinstance(parent, ast.Assign)
            and parent.value is value
            and len(parent.targets) == 1
            and isinstance(parent.targets[0], ast.Name)
            and self._func_stack
        ):
            return False
        name = parent.targets[0].id
        fn = self._func_stack[-1]
        reader = self._g_reader(fn)
        if name in reader.params or reader.sole(name) is not value:
            return False
        sink_value = ast.Name(id=name, ctx=ast.Load())
        loads = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Name)
            and n.id == name
            and isinstance(n.ctx, ast.Load)
            and self._g_use_reads_local(name, n, fn)
        ]
        if not loads:
            return False
        for use in loads:
            stmt = self._g_stmt_of(use)
            if stmt is None:
                return False
            if any(
                self._g_guard_covers(g, reader, sink_value)
                for g in self._g_guards_before(stmt, fn)
            ):
                continue
            # A read inside the test of a covering guard is the check itself.
            cur: ast.AST | None = stmt
            inside = False
            while cur is not None and cur is not fn and not inside:
                if isinstance(cur, ast.stmt):
                    inside = any(
                        any(n is use for n in ast.walk(g[1]))
                        and self._g_guard_covers(g, reader, sink_value)
                        for g in self._g_guard_forms(cur)
                    )
                cur = self._parent_of(cur)
            if not inside:
                return False
        return True

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
            # A sink inside the guard's own rejecting body (or in a multi-line
            # test) runs when the value is exactly the one being rejected: the
            # guard never covers it, in every extent (redteam4-py-01). Only
            # code after the body, an `else` or `elif` included, can be covered.
            if stmt.body[-1].end_lineno >= sink_line:
                continue
            if test_pred(stmt.test) and self._body_ends_control_flow(stmt.body):
                return stmt
        return None

    def _body_ends_control_flow(
        self, body: list, _depth: int = 0, *, callee: bool = False
    ) -> bool:
        """True when a guard body provably leaves the function: a top-level
        `return` or `raise`, a call known never to return (`_call_never_returns`),
        or an `if`/`else` whose two branches both do.

        A guard that "ends control flow" by the NAME of what it calls protects
        nothing when the callee returns: a project's own `def abort(code):
        print(code)`, `log.exit()` on an object, a function that falls through.
        Termination is proven from the callee, never read from its name
        (redteam4-py-01).

        With `callee` (the body of a function being called, not a guard body) a
        `return` leaves only that function, so it never counts."""
        for s in body:
            if isinstance(s, ast.Raise) or (isinstance(s, ast.Return) and not callee):
                return True
            if (
                isinstance(s, ast.Expr)
                and isinstance(s.value, ast.Call)
                and self._call_never_returns(s.value, _depth)
            ):
                return True
            if (
                isinstance(s, ast.If)
                and s.orelse
                and self._body_ends_control_flow(s.body, _depth, callee=callee)
                and self._body_ends_control_flow(s.orelse, _depth, callee=callee)
            ):
                return True
        return False

    def _call_never_returns(self, call: ast.Call, _depth: int = 0) -> bool:
        """True when `call` is a call that never returns normally, proven from
        what the callee IS: a known raising or exiting function resolved
        through the file's imports (`sys.exit`, `flask.abort`, `os._exit`), the
        `exit` / `quit` builtins when nothing in the file rebinds them, or a
        function this file defines whose own body ends control flow on every
        path (`_local_function_never_returns`). A name that merely sounds
        terminal (`abort`, `exit`) and is not proven is not."""
        fn = call.func
        if self._callee_qualname(fn) in _NEVER_RETURNING_CALLS:
            return True
        if not isinstance(fn, ast.Name):
            return False
        if self._star_imported_never_returns(fn):
            return True
        if fn.id in ("exit", "quit"):
            return (
                fn.id not in self._file_defined_names()
                and fn.id not in self._from_imports
                and fn.id not in self._imported_modules
                and self._scope_binding(fn.id) is None
                and not self._name_is_shadowed(fn.id, fn)
            )
        if fn.id in self._file_defined_names() and _depth < 3:
            return self._local_function_never_returns(fn.id, _depth + 1)
        return False

    def _star_import_modules(self) -> tuple[str, ...]:
        """The module of every `from <module> import *` anywhere in the file,
        in the order written; a relative import keeps its dots (`.flask`), so
        it can never be mistaken for the installed module of that name. Read
        from the whole module, not from the imports the walk has reached: an
        import written below the view still runs before the view is called."""
        if self._star_import_cache is None:
            root = self._module_root
            found: list[tuple[int, int, str]] = []
            if root is not None:
                for n in ast.walk(root):
                    if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                        found.append(
                            (n.lineno, n.col_offset, "." * n.level + (n.module or ""))
                        )
            self._star_import_cache = tuple(m for _l, _c, m in sorted(found))
        return self._star_import_cache

    def _star_imported_never_returns(self, fn: ast.Name) -> bool:
        """True for a bare name that `from <module> import *` can only have
        supplied from a module whose function of that name never returns
        (`from flask import *` then `abort(400)`), when nothing else in the
        file defines or rebinds the name.

        Every star import binds the name, and the last one to run wins, so the
        proof needs every star import in the file to be of a module known to
        supply the never-returning function: a single such import, or several
        that all do. One import of a module the engine does not know (or of a
        project module, which any relative import is) may define a returning
        function of the same name (review item 3)."""
        modules = self._star_import_modules()
        if not modules or not all(
            f"{m}.{fn.id}" in _NEVER_RETURNING_CALLS for m in modules
        ):
            return False
        return (
            fn.id not in self._file_defined_names()
            and fn.id not in self._from_imports
            and self._scope_binding(fn.id) is None
            and not self._name_is_shadowed(fn.id, fn)
        )

    def _local_function_never_returns(self, name: str, depth: int) -> bool:
        """True when `name` is a plain top-level function of this file, defined
        once, undecorated, not a generator and not `async` (calling one runs
        no body), whose body ends control flow on every path."""
        root = self._module_root
        if root is None:
            return False
        defs = [
            n
            for n in ast.walk(root)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name == name
        ]
        if len(defs) != 1:
            return False
        fdef = defs[0]
        if (
            not isinstance(fdef, ast.FunctionDef)
            or fdef.decorator_list
            or not any(fdef is stmt for stmt in root.body)
            or any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(fdef))
        ):
            return False
        if any(isinstance(n, ast.Return) for n in ast.walk(fdef)):
            return False  # a path through it returns
        return self._body_ends_control_flow(fdef.body, depth, callee=True)

    def _arg_is_sanitised(
        self,
        arg: ast.AST,
        sink_line: int = 1_000_000,
        *,
        url_sink: bool = False,
        sink: str | None = None,
        _resolving: frozenset[str] = frozenset(),
    ) -> bool:
        """Composite check: dict-lookup whitelist OR membership-guarded Name.

        ``sink`` is the sink's class (`_SINK_CLASSES`; "url" when only
        ``url_sink`` is given, "other" when neither is). The sanitisers that
        bound a value to constants (a constant-collection lookup, a dominating
        membership guard) hold for every class. The others are typed
        (R-058): an escaping call only for "html"; a safe URL builder
        (`url_for` / `reverse`) for "html", "url" and "path".

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
        cls = sink if sink is not None else ("url" if url_sink else "other")
        if self._arg_is_whitelisted_lookup(arg):
            return True
        # audit #24; R-058: escaping is an HTML sanitiser only. `quote()` keeps
        # `//evil.com` and `html.escape()` keeps `../`, `;` and `$(...)`.
        if cls == "html" and self._is_escaped_call(arg):
            return True
        # Server-controlled internal URL builders (reverse/url_for) produce a
        # route string, not attacker input — safe to interpolate into an href.
        if cls in ("html", "url", "path") and self._is_safe_url_builder(arg):
            return True
        if isinstance(arg, ast.Name):
            if arg.id in _resolving:
                return False
            if self._name_is_membership_guarded(arg.id, sink_line, arg) or (
                url_sink and self._url_host_is_allowlisted(arg.id, sink_line, arg)
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
                        sink=cls,
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
                        or self._arg_is_sanitised(
                            v, sink_line, sink=cls, _resolving=_resolving
                        )
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
                    sub,
                    sink_line,
                    url_sink=sub_url_sink,
                    sink=cls,
                    _resolving=_resolving,
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
        """Check a call against every sink rule (`_check_call`) and visit what
        it contains. When the call's own checks read the binding of a name and
        reported nothing, ask whether a path the last binding hides would have
        made it a finding (`_note_ambiguous_bindings`, C4B-23)."""
        outer_reads = self._binding_reads
        before = self._emitted
        self._binding_reads = set()
        try:
            self._check_call(node)
        finally:
            reads, self._binding_reads = self._binding_reads, outer_reads
        if self._emitted == before and reads:
            self._note_ambiguous_bindings(node, reads)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call) -> None:
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
                    sink_class="shell",
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
                    sink_class="shell",
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
                    sink_class="shell",
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
                    sink_class="sql",
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
                    sink_class="sql",
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
            chain = self._collect_taint_chain(
                target, node.lineno, sink_expr, sink_class="url"
            )
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
                    sink_class="html",
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
                chain = self._collect_taint_chain(
                    body, node.lineno, sink_expr, sink_class="html"
                )
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
                    sink_class="url",
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
        elif (path_report := self._path_traversal_report(node)) is not None:
            sink_expr, chain, guard_notes = path_report
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
            #
            # OR-88: a sink a recognised containment guard covers is reported in
            # the unproven form (a WARN), with the guard named, never removed.
            fix = (
                "Validate the path against an allow-list of permitted filenames or a "
                "base directory. Use pathlib.Path.resolve() and confirm the resolved "
                "path is still under the intended root before opening. Reject any "
                "input containing '..' or absolute paths."
            )
            if guard_notes:
                fix = _PATH_GUARD_LOWERED.format(guards="; ".join(guard_notes[:3])) + fix
            self._emit_finding(
                "PY_PATH_TRAVERSAL",
                "Potential unsafe dynamic filesystem path",
                "MEDIUM",
                "MEDIUM",
                "CWE-22",
                fix,
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

    # ------------------------------------------------------------------
    # C4B-23: a name tainted on one path and rebound on another
    # ------------------------------------------------------------------

    def _definitions(self, func: ast.AST) -> tuple[dict, dict, dict]:
        """`(values, counts, by_name)` for the names `func` binds in its own
        scope.
        `values` maps a definition node (the nodes `ReachingDefs` returns) to
        the expression that supplies its value: the right side of an
        assignment, the iterable of a `for`, the context manager of a `with`,
        a walrus's value; a definition with no value of its own (an import, a
        `def`, an `except ... as`) is absent. `counts` maps a name to how many
        times the scope binds it, so a name bound once can be left out of the
        reaching-definition analysis, and `by_name` maps it to the values it is
        bound to. One pass, kept per function."""
        cached = self._definition_values_cache.get(id(func))
        if cached is not None and cached[0] is func:
            return cached[1], cached[2], cached[3]
        values: dict = {}
        counts: dict[str, int] = {}
        by_name: dict[str, list] = {}

        def bind(target: ast.AST, value: ast.AST) -> None:
            for n in ast.walk(target):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    values[id(n)] = value
                    by_name.setdefault(n.id, []).append(value)

        def count(name: str) -> None:
            counts[name] = counts.get(name, 0) + 1

        for stmt in getattr(func, "body", []):
            for n in _same_scope_nodes(stmt):
                if isinstance(n, ast.Name):
                    if not isinstance(n.ctx, ast.Load):
                        count(n.id)
                elif isinstance(n, ast.Assign):
                    for t in n.targets:
                        bind(t, n.value)
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    if n.value is not None:
                        bind(n.target, n.value)
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    bind(n.target, n.iter)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        if item.optional_vars is not None:
                            bind(item.optional_vars, item.context_expr)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    count(n.name)
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for alias in n.names:
                        count((alias.asname or alias.name.split(".")[0]))
                elif isinstance(n, ast.ExceptHandler) and n.name:
                    count(n.name)
                else:
                    # `match` captures (`MatchAs`, `MatchStar`, `MatchMapping`).
                    for attr in ("name", "rest"):
                        captured = getattr(n, attr, None)
                        if isinstance(captured, str) and type(n).__name__.startswith("Match"):
                            count(captured)
        self._definition_values_cache[id(func)] = (func, values, counts, by_name)
        return values, counts, by_name

    def _function_can_hold_input(self, func: ast.AST) -> bool:
        """False when `func` can hold no request input at all: it reads none
        (`_is_request_input_node`, anywhere in it) and takes none as a route
        parameter. Nothing in it is then tainted on any path, so there is nothing
        for a last binding to hide. Cached per function."""
        cached = self._input_functions.get(id(func))
        if cached is None or cached[0] is not func:
            holds = bool(self._route_param_sources(func)) or any(
                _is_request_input_node(n) for n in ast.walk(func)
            )
            cached = (func, holds)
            self._input_functions[id(func)] = cached
        return cached[1]

    def _carries_request_input(self, expr: ast.AST | None) -> bool:
        """True when `expr` is request input or traces back to it through the
        bindings in scope or to a request-carrying route parameter. The trace
        stays inside this function: no caller is searched, so a helper's
        parameter is not request input here (C4B-23 asks about what a
        definition in THIS function carries)."""
        if expr is None:
            return False
        if self._is_source(expr):
            return True

        def route_param(name: str, _extra, _depth: int) -> list[dict] | None:
            return [] if self._name_is_route_param_source(name) else None

        return (
            self._trace_names(expr, self._scope_binding, frozenset(), 0, None, route_param)
            is not None
        )

    def _reads_lazily(self, node: ast.AST, func: ast.AST) -> bool:
        """True when the read `node` runs when a lambda or generator expression
        is consumed, not where it is written: inside a lambda, or inside a
        generator expression other than its first iterable."""
        child, parent = node, self._parent_of(node)
        while parent is not None and parent is not func:
            if isinstance(parent, ast.Lambda):
                return True
            if isinstance(parent, ast.GeneratorExp) and not (
                parent.generators and child is parent.generators[0].iter
            ):
                return True
            child, parent = parent, self._parent_of(parent)
        return False

    def _would_report_with(self, call: ast.Call, name: str, alternative) -> bool:
        """True when `call` would be reported if `name` were bound to
        `alternative` (an expression; None for the value the function was
        entered with, which a route parameter takes from the request) where the
        checks read it. The sink rules run again with the findings collected, not
        emitted, and the binding put back."""
        scope = next((sc for sc in reversed(self._scopes) if dict.__contains__(sc, name)), None)
        if scope is None:
            return False
        held = dict.__getitem__(scope, name)
        saved = self._emit, self._emitted, self._binding_reads
        hits: list = []
        self._emit, self._binding_reads = hits.append, None
        try:
            if alternative is None:
                dict.__delitem__(scope, name)
            else:
                dict.__setitem__(scope, name, alternative)
            self._check_call(call)
        finally:
            dict.__setitem__(scope, name, held)
            self._emit, self._emitted, self._binding_reads = saved
        return bool(hits)

    def _note_ambiguous_bindings(self, call: ast.Call, reads: set[str]) -> None:
        """A call's checks resolved `reads` from the bindings in scope, and no
        finding was reported. The engine reads a name's last binding in source
        order, so a name that is request input on one path (an `if` arm, a
        `try` body, a parameter, a later rebind a lazy body sees) and rebound
        to something else on another is resolved to the one that hides the
        input. When a definition that reaches the use carries request input, the
        binding the checks used does not, and the call WOULD be reported with
        that definition in its place, the evaluation is lost: it is recorded
        (`lost_evaluation`; `_analyze_python` raises `AnalysisIncomplete`)
        instead of read as clean (C4B-23, and C4B-22 for a lazy body whose guard
        no longer holds).

        Bounded: a few hundred reads and four hops through the values."""
        if not self._func_stack:
            return
        func = self._func_stack[-1]
        if not self._function_can_hold_input(func):
            return
        values, counts, by_name = self._definitions(func)
        names = {r for r in reads if counts.get(r)}
        if not names:
            return
        todo: deque[tuple[ast.Name, int]] = deque(
            (n, 0)
            for n in ast.walk(call)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in names
        )
        seen: set[int] = set()
        budget = 300
        while todo and budget > 0:
            node, hops = todo.popleft()
            if id(node) in seen:
                continue
            seen.add(id(node))
            budget -= 1
            name = node.id
            bound = counts.get(name, 0)
            if bound == 0:
                continue
            lazy = self._reads_lazily(node, func)
            if bound == 1 and not lazy and not ReachingDefs._is_parameter(func, name):
                # Bound once and read where it is written: one definition
                # reaches it, so nothing here is ambiguous; follow its value.
                follow = by_name.get(name, ())
            else:
                analysed = self._ambiguity_names.setdefault(id(func), set())
                if name not in analysed:
                    if len(analysed) >= _MAX_AMBIGUITY_NAMES:
                        # Past the bound the reaching definitions are not
                        # computed: not read as clean either.
                        self._note_lost(
                            f"ambiguous bindings not analysed: over {_MAX_AMBIGUITY_NAMES} "
                            f"names (function at line {func.lineno})",
                            essential=True,
                        )
                        return
                    analysed.add(name)
                rd = self._reaching_defs(name)
                if rd is None or rd.volatile:
                    continue
                reaching = rd.defs_at(node)
                if reaching is None:
                    if not lazy:
                        continue
                    # Run when consumed: any definition of the name may reach it.
                    reaching = frozenset(rd.definitions) | {ENTRY}
                if len(reaching) > 1 and self._lost_to_last_binding(call, name, reaching, values):
                    self._note_lost(f"ambiguous binding: {name} (line {call.lineno})")
                    return
                follow = [values[id(d)] for d in reaching if d is not ENTRY and id(d) in values]
            if hops < 4:
                for value in follow:
                    todo.extend(
                        (n, hops + 1)
                        for n in ast.walk(value)
                        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                    )

    def _note_lost(self, reason: str, *, essential: bool = False) -> None:
        """Record one lost-evaluation reason for the file. At most
        `_MAX_AMBIGUITY_NOTES` are listed; the rest are counted in one more
        note, so a file of thousands of ambiguous bindings reports its size, not
        thousands of lines. An `essential` reason (the analysis ran out of its
        bound) is always kept."""
        if essential:
            if reason not in self._lost_essential:
                self._lost_essential.append(reason)
        elif reason in self._lost_listed:
            return
        elif len(self._lost_listed) < _MAX_AMBIGUITY_NOTES:
            self._lost_listed.append(reason)
        else:
            self._lost_overflow += 1

    @property
    def lost_evaluation(self) -> list[str]:
        """The lost-evaluation reasons this file's checks recorded
        (`_note_ambiguous_bindings`); `_analyze_python` raises
        `AnalysisIncomplete` for them."""
        more = (
            [f"ambiguous bindings: {self._lost_overflow} more not listed"]
            if self._lost_overflow
            else []
        )
        return [*self._lost_listed, *more, *self._lost_essential]

    def _lost_to_last_binding(
        self, call: ast.Call, name: str, reaching: frozenset, values: dict
    ) -> bool:
        """True when a definition of `name` in `reaching` carries request input,
        the binding the checks used (the last one in source order) does not, and
        `call` would be reported with that definition in its place."""
        tainted: list = []
        for d in reaching:
            if d is ENTRY:
                if self._name_is_route_param_source(name):
                    tainted.append(None)
            else:
                alternative = values.get(id(d))
                if alternative is not None and self._carries_request_input(alternative):
                    tainted.append(alternative)
        if not tainted:
            return False
        last = self._scope_binding(name)
        last_tainted = (
            self._name_is_route_param_source(name)
            if last is None
            else self._carries_request_input(last)
        )
        if last_tainted:
            return False
        return any(self._would_report_with(call, name, alt) for alt in tainted)

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
        self._scopes.append(_Scope(self))
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
            self._freeze_readers_of(target.id, scope)
            scope[target.id] = value
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            elts = target.elts
            if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(
                elts
            ):
                # A tuple assignment evaluates every right-hand element before
                # it binds any target: `name, other = other, name` gives
                # `name` the value `other` had BEFORE the statement. Binding
                # target by target made `name` read the NEW `other`, which
                # reads the guarded `name`, so a tainted value hid behind a
                # guard (DE4-08). An element that reads a name this statement
                # also assigns is taken at the binding in effect before it.
                assigned = {
                    n.id
                    for t in elts
                    for n in ast.walk(t)
                    if isinstance(n, ast.Name)
                }
                before = {k: scope[k] for k in assigned if k in scope}
                for t, v in zip(elts, value.elts):
                    if isinstance(v, ast.Name) and v.id in assigned:
                        if v.id in before:
                            v = before[v.id]
                        elif self._name_is_route_param_source(v.id):
                            v = _ENTRY_SOURCE
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

    def _name_is_guard_tested(self, name: str) -> bool:
        """True when a top-level `if` or `try` of the innermost function reads
        `name` in its test (a possible guard on it). Cached per function."""
        if not self._func_stack:
            return False
        func = self._func_stack[-1]
        cache = self.__dict__.setdefault("_tested_names_cache", {})
        tested = cache.get(id(func))
        if tested is None or tested[0] is not func:
            names: set[str] = set()
            for stmt in func.body:
                if isinstance(stmt, ast.If):
                    names.update(
                        n.id for n in ast.walk(stmt.test) if isinstance(n, ast.Name)
                    )
                elif isinstance(stmt, ast.Try):
                    names.update(
                        n.id
                        for s in stmt.body
                        for n in ast.walk(s)
                        if isinstance(n, ast.Name)
                    )
            tested = (func, names)
            cache[id(func)] = tested
        return name in tested[1]

    def _freeze_readers_of(self, key: str, scope: dict) -> None:
        """Before `key` is rebound in `scope`: every other binding that reads
        the name keeps the value the name held until now (alias-then-rebind:
        `base = name; name = "x"; open(base)` opens what `name` held, not "x").
        Without a prior binding (a parameter) there is nothing to substitute
        and the later binding stands. Bounded by `_FREEZE_MAX_NODES` per value
        and by the number of bindings in the scope."""
        if self._name_is_guard_tested(key):
            # A guard tests this name: the guard checks follow an alias by the
            # name and its reaching definitions (`_guard_covers`), which a
            # substituted value would lose. They already keep an alias on the
            # value it was guarded with.
            return
        prior = scope.get(key)
        if prior is None and self._name_is_route_param_source(key):
            # A request-carrying parameter has no binding, but it is a
            # source: readers keep it as request input, not as whatever the
            # name is rebound to.
            prior = _ENTRY_SOURCE
        if prior is None or len(scope) > 400:
            return
        for other, value in list(scope.items()):
            if other == key or not isinstance(value, ast.AST):
                continue
            if _reads_name(value, key) and not _reads_name(prior, key):
                scope[other] = _SubstituteName(key, prior).visit(value)

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
                if key in scope and isinstance(node.target, ast.Name):
                    self._freeze_readers_of(key, scope)
                scope[key] = ast.BinOp(left=prior, op=node.op, right=node.value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        """Push a scope for the class body so class-level assignments don't
        leak into module scope and falsely shadow handler-local names (#17)."""
        self._scopes.append(_Scope(self))
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
            self._from_import_levels[local_name] = node.level
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
        # A target that starts with a literal naming the destination: a fixed
        # scheme and host, or a same-origin path (`"/search?q=" + quote(q)`).
        # Escaping is no redirect sanitiser (R-058), so this is what keeps the
        # escaped query of a fixed path safe.
        if self._redirect_prefix_is_fixed(value):
            return False
        # Framework URL builders produce safe internal URLs from a route NAME,
        # not user input: Flask url_for(...), Django reverse(...). A redirect to
        # one of these is not an open redirect (real-data FP on flask/django).
        if self._is_safe_url_builder(value):
            return False
        return True

    def _redirect_prefix_is_fixed(self, value: ast.AST, _depth: int = 0) -> bool:
        """True when a redirect target is a `+` concatenation or an f-string
        whose LEADING part is a string literal that fixes where the browser
        goes: `http(s)://host/` (`_literal_url_fixes_host`), or a same-origin
        path, `/` followed by a letter, digit or one of `?#.-_~%`. `"/"`
        alone is not (`"/" + "/evil.com"` is protocol-relative), nor is
        `"/\\"`. Only a literal counts; a configured base may be `"/"`."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(value, ast.Name):
            bound = self._resolve_binding(value)
            return bound is not None and self._redirect_prefix_is_fixed(bound, _depth + 1)
        lead: ast.AST | None = None
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            lead = value.left
            while isinstance(lead, ast.BinOp) and isinstance(lead.op, ast.Add):
                lead = lead.left
        elif isinstance(value, ast.JoinedStr) and value.values:
            lead = value.values[0]
        if not (isinstance(lead, ast.Constant) and isinstance(lead.value, str)):
            return False
        s = lead.value
        if self._literal_url_fixes_host(s):
            return True
        return len(s) >= 2 and s[0] == "/" and (s[1].isalnum() or s[1] in "?#.-_~%")

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
        chain = self._collect_taint_chain(value, lineno, sink_expr, sink_class="url")
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
        if self._arg_is_sanitised(first, node.lineno, sink="html"):
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
            body, node.lineno, sink="html"
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
            chain = self._collect_taint_chain(
                body, node.lineno, sink_expr, sink_class="html"
            )
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

    def _callee_qualname(self, func: ast.AST, _depth: int = 0) -> str:
        """The dotted name a called expression stands for through the file's
        imports: ``html.escape`` for ``html.escape`` / ``from html import
        escape as e; e``, ``os.path.basename`` for ``osp.basename`` after
        ``import os.path as osp``. A bare name bound in scope to another
        callee (``e = html.escape``) resolves through that binding. "" when
        the name is defined in the file (``def escape(s)``), bound to
        anything else, or not imported: a function NAME alone says nothing
        about what the function does (redteam-r006-02, redteam-r058-01).

        An imported name is "" too where something else may stand for it
        (`_name_is_shadowed`): a class of that name, a parameter of an
        enclosing def or lambda (`def inner(basename=lambda p: p)`), or any
        other store of it in an enclosing scope (redteam2-r006-02)."""
        if _depth >= _MAX_TAINT_HOPS:
            return ""
        if isinstance(func, ast.Name):
            if func.id in self._file_defined_names():
                return ""
            bound = self._scope_binding(func.id)
            if bound is not None:
                if isinstance(bound, (ast.Name, ast.Attribute)) and bound is not func:
                    return self._callee_qualname(bound, _depth + 1)
                return ""
            origin = self._from_imports.get(func.id)
            if origin is None or self._name_is_shadowed(func.id, func):
                return ""
            module, symbol = origin
            return f"{module}.{symbol}" if module else symbol
        if isinstance(func, ast.Attribute):
            head = func
            while isinstance(head, ast.Attribute):
                head = head.value
            if isinstance(head, ast.Name) and self._name_is_shadowed(head.id, head):
                return ""
            base = self._import_origin(func.value)
            return f"{base}.{func.attr}" if base else ""
        return ""

    def _name_is_shadowed(self, name: str, at: ast.AST) -> bool:
        """True when the bare `name` read at `at` may not be an import of it
        (redteam2-r006-02). The scopes enclosing `at` are searched innermost
        first, as Python resolves the name: def or lambda (its parameters and
        its own stores), comprehension, class body, then the module. The
        first scope that binds `name` decides: shadowed unless every binding
        there is an import (a def or class of that name, a parameter, a
        default, an assignment or loop target, in any order, since a later
        store rebinds it for every call made after). A `global` declaration
        of it anywhere also shadows the module's import. Over-reporting only
        makes a sanitiser count less."""
        cache = self.__dict__.setdefault("_shadow_cache", {})

        def verdict(scope: ast.AST, params, nodes) -> bool | None:
            """None when `scope` does not bind `name`; else shadowed or not."""
            key = (id(scope), name)
            if key not in cache:
                binders = [x for x in params if x.arg == name]
                binders += [
                    n for stmt in nodes for n in _same_scope_nodes(stmt) if _binds_name(n, name)
                ]
                cache[key] = (
                    None if not binders else not all(isinstance(b, ast.alias) for b in binders)
                )
            return cache[key]

        node = at
        parent = self._parent_of(node)
        while parent is not None:
            found: bool | None = None
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inner = (
                    node is parent.body
                    if isinstance(parent, ast.Lambda)
                    else any(node is stmt for stmt in parent.body)
                )
                if inner:
                    a = parent.args
                    params = [*a.posonlyargs, *a.args, *a.kwonlyargs]
                    params += [x for x in (a.vararg, a.kwarg) if x is not None]
                    body = [parent.body] if isinstance(parent, ast.Lambda) else parent.body
                    found = verdict(parent, params, body)
            elif isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                if any(
                    _binds_name(n, name) for gen in parent.generators for n in ast.walk(gen.target)
                ):
                    found = True
            elif isinstance(parent, ast.ClassDef) and any(node is stmt for stmt in parent.body):
                found = verdict(parent, [], parent.body)
            if found is not None:
                return found
            node, parent = parent, self._parent_of(parent)
        root = self._module_root
        if root is None:
            return False
        key = (id(root), name, "global")
        if key not in cache:
            cache[key] = any(
                isinstance(n, ast.Global) and name in n.names for n in ast.walk(root)
            )
        if cache[key]:
            return True
        return bool(verdict(root, [], root.body))

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
            and (
                self._is_django_template(func.value)
                or self._is_autoescaping_jinja_template(func.value)
            )
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

    def _is_autoescaping_jinja_template(self, expr: ast.AST, _depth: int = 0) -> bool:
        """True when ``expr`` is, directly or through a binding, a template a
        Jinja2 environment that autoescapes loaded (``get_template``,
        ``select_template``, ``get_or_select_template``, ``from_string``), so
        its ``render`` escapes what it is passed. Honoured:

        - ``Environment(autoescape=True)`` and
          ``Environment(autoescape=select_autoescape(...))`` (also on a
          sandboxed or native environment), the setting read off the call that
          built the environment, directly or through the names it is bound to;
          ``select_autoescape`` only for a template name its extensions cover
          (default ``html``, ``htm``, ``xml``; a non-constant name is given the
          benefit of the doubt, as Flask's ``render_template`` is) and for
          ``from_string`` unless ``default_for_string=False``;
        - Flask's own ``<app>.jinja_env`` in a file that imports Flask, only
          for the templates Flask's ``select_jinja_autoescape`` escapes
          (``.html``, ``.htm``, ``.xml``, ``.xhtml``, ``.svg``, and
          ``from_string``); a template name that is not a string constant is
          not taken to be one of them.

        Not honoured: no ``autoescape`` argument (Jinja2's default is off),
        ``autoescape=False`` or any value this cannot read, an environment the
        file switches off later (``env.autoescape = False``), and a constant
        inline template that switches escaping off itself (``|safe``,
        ``{% autoescape false %}``)."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(expr, ast.Name):
            bound = self._scope_binding(expr.id)
            return bound is not None and self._is_autoescaping_jinja_template(bound, _depth + 1)
        if not (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in _JINJA_TEMPLATE_LOADERS
        ):
            return False
        if self._autoescape_is_switched_off():
            return False
        if expr.func.attr == "from_string" and self._inline_template_unescapes(expr):
            return False
        if self._is_flask_jinja_env(expr.func.value):
            return self._flask_autoescapes(expr)
        setting = self._environment_autoescape(expr.func.value)
        if setting is None:
            return False
        if isinstance(setting, ast.Constant):
            return setting.value is True
        if not isinstance(setting, ast.Call):
            return False
        if self._import_origin(setting.func) not in _SELECT_AUTOESCAPE:
            return False
        return self._select_autoescape_covers(setting, expr)

    def _is_flask_jinja_env(self, env: ast.AST, _depth: int = 0) -> bool:
        """True when ``env`` is, directly or through the names it is bound to,
        a ``<app>.jinja_env`` attribute in a file that imports Flask."""
        if _depth >= _MAX_TAINT_HOPS:
            return False
        if isinstance(env, ast.Name):
            bound = self._scope_binding(env.id)
            return bound is not None and self._is_flask_jinja_env(bound, _depth + 1)
        if isinstance(env, ast.Attribute) and env.attr == "jinja_env":
            return "flask" in self._imported_modules.values() or any(
                module.split(".")[0] == "flask" for module, _ in self._from_imports.values()
            )
        return False

    def _flask_autoescapes(self, load: ast.Call) -> bool:
        """True when Flask's ``select_jinja_autoescape`` escapes the template
        ``load`` (a call on ``jinja_env``) loads: any ``from_string`` template,
        and a named one only when the name is a string constant ending in one
        of `_FLASK_AUTOESCAPE_EXTENSIONS` (case-sensitive, as Flask matches it)."""
        assert isinstance(load.func, ast.Attribute)
        if load.func.attr == "from_string":
            return True
        name = load.args[0] if load.args else next(
            (kw.value for kw in load.keywords if kw.arg == "name"), None
        )
        return (
            isinstance(name, ast.Constant)
            and isinstance(name.value, str)
            and name.value.endswith(_FLASK_AUTOESCAPE_EXTENSIONS)
        )

    def _inline_template_unescapes(self, load: ast.Call) -> bool:
        """True when the text ``from_string`` is given is a string constant that
        switches escaping off itself (``|safe``, ``{% autoescape false %}``)."""
        text = load.args[0] if load.args else next(
            (kw.value for kw in load.keywords if kw.arg == "source"), None
        )
        return (
            isinstance(text, ast.Constant)
            and isinstance(text.value, str)
            and _TEMPLATE_UNESCAPES.search(text.value) is not None
        )

    def _environment_autoescape(
        self, env: ast.AST, _depth: int = 0
    ) -> ast.AST | None:
        """The ``autoescape`` setting of the Jinja2 environment ``env`` is,
        directly or through the names it is bound to: the ``autoescape``
        keyword of the call that built it (None when it has none). None for
        anything else (Flask's ``jinja_env`` is `_flask_autoescapes`)."""
        if _depth >= _MAX_TAINT_HOPS:
            return None
        if isinstance(env, ast.Name):
            bound = self._scope_binding(env.id)
            return None if bound is None else self._environment_autoescape(bound, _depth + 1)
        if isinstance(env, ast.Call) and self._callee_origin(env.func) in _TEMPLATE_ENVIRONMENTS:
            setting = next((kw.value for kw in env.keywords if kw.arg == "autoescape"), None)
            if isinstance(setting, ast.Name):
                setting = self._scope_binding(setting.id)
            return setting
        return None

    def _select_autoescape_covers(self, setting: ast.Call, load: ast.Call) -> bool:
        """True when ``select_autoescape(...)`` (`setting`) autoescapes the
        template ``load`` (a ``get_template``/``from_string`` call) loads."""

        def keyword(name: str, position: int) -> ast.AST | None:
            found = next((kw.value for kw in setting.keywords if kw.arg == name), None)
            if found is None and len(setting.args) > position:
                found = setting.args[position]
            return found

        def literal_strings(node: ast.AST | None) -> tuple[str, ...] | None:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return (node.value,)
            if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
            ):
                return tuple(e.value for e in node.elts)  # type: ignore[attr-defined]
            return None

        def is_false(node: ast.AST | None) -> bool:
            return isinstance(node, ast.Constant) and node.value is False

        assert isinstance(load.func, ast.Attribute)
        if load.func.attr == "from_string":
            return not is_false(keyword("default_for_string", 2))
        name = load.args[0] if load.args else next(
            (kw.value for kw in load.keywords if kw.arg == "name"), None
        )
        if not (isinstance(name, ast.Constant) and isinstance(name.value, str)):
            return True  # which template is not known: the benefit of the doubt
        given = keyword("enabled_extensions", 0)
        enabled = _SELECT_AUTOESCAPE_ENABLED if given is None else literal_strings(given)
        disabled = literal_strings(keyword("disabled_extensions", 1)) or ()
        if enabled is None:
            return True  # a computed list of extensions: the benefit of the doubt
        template = name.value.lower()
        if any(template.endswith("." + e.lower()) for e in disabled):
            return False
        if any(template.endswith("." + e.lower()) for e in enabled):
            return True
        default = keyword("default", 3)
        return isinstance(default, ast.Constant) and default.value is True

    def _autoescape_is_switched_off(self) -> bool:
        """True when the file assigns ``<anything>.autoescape`` something other
        than ``True`` (``env.autoescape = False``, ``app.jinja_env.autoescape =
        flag``). It does not follow which environment, so one such assignment
        turns the autoescape honouring off for the whole file."""
        if self._autoescape_switched_off is None:
            root = self._module_root
            self._autoescape_switched_off = root is not None and any(
                isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                and any(
                    isinstance(t, ast.Attribute) and t.attr == "autoescape"
                    for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
                )
                and not (
                    isinstance(n, (ast.Assign, ast.AnnAssign))
                    and isinstance(n.value, ast.Constant)
                    and n.value.value is True
                )
                for n in ast.walk(root)
            )
        return self._autoescape_switched_off

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
        if self._arg_is_sanitised(expr, sink_line, sink="html"):
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
            if self._name_is_membership_guarded(expr.id, sink_line, expr):
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
        return bool(
            self._collect_taint_chain(
                segment, line, _ast_expr_text(segment), sink_class="path"
            )
        )

    def _opens_a_file(self, func: ast.AST) -> bool:
        """True when the `open` that `func` names opens its path as a FILE and
        fails on a directory: the builtin (not shadowed in scope) or one of
        `_FILE_OPEN_CALLS`, never `os.open` (redteam2-r006-01)."""
        if self._is_builtin_open(func):
            return not self._name_is_shadowed("open", func)
        return self._callee_qualname(func) in self._FILE_OPEN_CALLS

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

    def _path_traversal_report(
        self, node: ast.Call
    ) -> tuple[str, list | None, list[str]] | None:
        """`(sink_expr, chain, guards)` for the path-traversal finding to emit at
        `node`, or None. `guards` is empty for a finding as the evidence stands, and
        names the recognised containment guards when the finding is LOWERED (OR-88,
        "the recognisers may lower a finding, never remove it"): a sink the
        recognisers let through is re-read as if no guard were recognised, and when
        that reading would report it, it is reported anyway, in the unproven form
        (no taint chain, MEDIUM/MEDIUM, a WARN), naming the guards."""
        self._guard_trace = []
        report = self._path_traversal_evidence(node)
        if report is not None:
            return report[0], report[1], []
        guards = list(self._guard_trace)
        if not guards:
            return None
        self._guards_off += 1
        try:
            reread = self._path_traversal_evidence(node)
        finally:
            self._guards_off -= 1
            self._guard_trace = guards
        if reread is None:
            return None
        return reread[0], None, guards

    def _path_traversal_evidence(self, node: ast.Call) -> tuple[str, list | None] | None:
        """`(sink_expr, chain)` when `node` is a path-traversal sink to report: the
        sink, the evidence that a request value reaches it (None when unproven), and
        for an `os.path.*` sink only when there is such a chain."""
        if not self._is_path_traversal_sink(node):
            return None
        chain = None
        sink_expr = ""
        sink_name = self._path_traversal_sink_name(node)
        # The user-controlled arg is usually the FIRST positional
        # except for os.path.join(base, x), where it's the second, and
        # send_from_directory(dir, name), where only the directory can
        # carry traversal (R-006). _path_traversal_target handles that.
        target = self._path_traversal_target(node)
        if target is not None:
            sink_expr = f"{sink_name}({_ast_expr_text(target)})"
            file_sink, target_lenient = self._path_sink_context(node, sink_name)
            # A join whose request-carrying parts are contained is proven
            # only through its other parts (R-006): `join(request.args["d"],
            # basename(f))` by the directory. Each part is traced under the
            # class its position allows: a basename-reduced caller value
            # contains only the last part of a file path (`path`), never a
            # directory or a middle part (`path_strict`, redteam-r006-01).
            parts = self._path_join_parts(target)
            if parts is None:
                chain = self._collect_taint_chain(
                    target,
                    node.lineno,
                    sink_expr,
                    sink_class="path" if target_lenient else "path_strict",
                )
            else:
                for part, contained, lenient in self._join_part_statuses(
                    parts, node.lineno, file_sink
                ):
                    if contained:
                        continue
                    chain = self._collect_taint_chain(
                        part,
                        node.lineno,
                        sink_expr,
                        sink_class="path" if lenient else "path_strict",
                    )
                    if chain is not None:
                        break
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
            return None
        return sink_expr, chain

    def _is_path_traversal_sink(self, node: ast.Call) -> bool:
        """Return True if node is a path-handling sink with a non-literal path arg.

        Recognises (TASK-134):
          - open(x[, mode]) — stdlib file open
          - Path(x) / pathlib.Path(x) — pathlib constructor (the resulting
            Path is typically opened or sent next; flagging the construct
            site lets the chain prove user-input flow regardless of where
            the actual filesystem access happens)
          - send_file(x) / flask.send_file(x) — Flask file response
          - send_from_directory(dir, x) / flask.send_from_directory —
            Flask file-by-name, judged on `dir` only: Werkzeug's safe_join
            contains `x` (R-006)
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
        if sink_name == "os.path.join" and (
            self._resolved_join_is_guarded(node) or self._g_join_is_guarded(node)
        ):
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
        # Whitelisted dict lookup / set-membership guard → sanitised. Escaping
        # is not a path sanitiser (R-058): `html.escape("../")` is `../`.
        if self._arg_is_sanitised(target, node.lineno, sink="path"):
            return False
        # Traversal-specific containment: basename-family normalisation, or a
        # dominating guard that rejects '..' outright. These neutralise
        # traversal specifically, which the generic sanitiser set above does
        # not model. A basename-reduced value counts only where the path is
        # used as a file (`_path_sink_context`, redteam-r006-01).
        file_sink, target_lenient = self._path_sink_context(node, sink_name)
        if self._path_is_contained(target, node.lineno, file_sink=target_lenient):
            return False
        # TwiScope FP-4: a path that provably comes from a NON-request source —
        # __file__-relative Path, os.getenv, tempfile.*.name, settings.*, a
        # BASE_DIR-style constant — is not user-controlled traversal. Never
        # suppress when the path references request input (recall guard).
        if not _references_request_input(target) and self._path_is_trusted_source(
            target
        ):
            chain = (
                self._collect_taint_chain(
                    target,
                    node.lineno,
                    "",
                    sink_class="path" if target_lenient else "path_strict",
                )
                if node.args
                else None
            )
            if chain is None:  # no proven request flow either → trusted, suppress
                return False
        return True

    def _path_sink_context(self, node: ast.Call, sink_name: str) -> tuple[bool, bool]:
        """`(file_sink, target_lenient)` for the path sink `node`.

        `file_sink`: the sink's path is used as a FILE. `open`, `send_file`
        and `FileResponse` read the file at their argument;
        `send_from_directory` is judged on its DIRECTORY and never is one; a
        `Path(...)`, an `os.path.join(...)` and the other `os.path.*` sinks
        are one only when every use of their value is (`_path_feeds_file_sink`).

        `target_lenient`: a basename-reduced value contains the TARGET
        argument itself. For most sinks that is `file_sink`. The
        `os.path.join` sink is judged on its second argument, which must also
        be the join's last part with every other part trusted or
        `secure_filename`-reduced (`_join_part_statuses`)."""
        if sink_name == "open" and not self._opens_a_file(node.func):
            # `os.open(path, os.O_RDONLY)` opens a directory as readily as a
            # file (redteam2-r006-01).
            return False, False
        if sink_name in ("open", "send_file", "FileResponse"):
            return True, True
        if sink_name == "send_from_directory":
            return False, False
        file_sink = self._path_feeds_file_sink(node)
        if sink_name == "os.path.join":
            statuses = self._join_part_statuses(list(node.args), node.lineno, file_sink)
            lenient = len(statuses) > 1 and statuses[1][2]
            return file_sink, lenient
        return file_sink, file_sink

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

        `os.path.join(base, x)` puts the user-controlled component at index 1;
        everything else at 0.

        `send_from_directory(directory, filename)` is judged on its DIRECTORY
        (index 0, R-006): Flask joins the filename with Werkzeug's
        `safe_join`, which refuses an absolute filename and any `..`
        component (404), so a request-chosen filename cannot leave the
        directory. A request-chosen directory can name any directory.
        """
        sink_name = self._path_traversal_sink_name(node)
        if sink_name == "os.path.join":
            return 1
        return 0

    def _path_traversal_target(self, node: ast.Call) -> ast.AST | None:
        """The path argument of a path-traversal sink: the positional argument
        at `_path_traversal_arg_index`, else, for `FileResponse`, its
        ``path=`` keyword and, for `send_from_directory`, its ``directory=``
        keyword; None when the call passes neither."""
        arg_idx = self._path_traversal_arg_index(node)
        if arg_idx < len(node.args):
            return node.args[arg_idx]
        keyword = {"FileResponse": "path", "send_from_directory": "directory"}.get(
            self._path_traversal_sink_name(node)
        )
        if keyword is not None:
            return next((kw.value for kw in node.keywords if kw.arg == keyword), None)
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
# What a Jinja2 environment calls to load a template, whose `render` then
# escapes when the environment autoescapes (`_is_autoescaping_jinja_template`).
_JINJA_TEMPLATE_LOADERS: frozenset[str] = frozenset(
    {"get_template", "select_template", "get_or_select_template", "from_string"}
)
_SELECT_AUTOESCAPE: frozenset[str] = frozenset(
    {"jinja2.select_autoescape", "jinja2.utils.select_autoescape"}
)
# What Flask's `select_jinja_autoescape` escapes by template name.
_FLASK_AUTOESCAPE_EXTENSIONS: tuple[str, ...] = (".html", ".htm", ".xml", ".xhtml", ".svg")
# What a constant inline template contains to switch escaping off itself: the
# `safe` filter, or an `{% autoescape false %}` block.
_TEMPLATE_UNESCAPES = re.compile(
    r"\|\s*safe\b|\{%-?\s*autoescape\s+(?:false|off)\b", re.IGNORECASE
)
# The extensions `select_autoescape()` enables when it is given none.
_SELECT_AUTOESCAPE_ENABLED: tuple[str, ...] = ("html", "htm", "xml")
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
# or `flask.send_file(x)` are also matched. send_from_directory is judged on
# its directory (the FIRST positional): its filename goes through Werkzeug's
# `safe_join` — see `_path_traversal_arg_index`.
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
    # The `match` statement's nodes exist from Python 3.10; the engine runs on 3.9.
    match_captures = tuple(
        cls for cls in (getattr(ast, "MatchAs", None), getattr(ast, "MatchStar", None)) if cls
    )
    if match_captures and isinstance(node, match_captures):
        return node.name == name
    match_mapping = getattr(ast, "MatchMapping", None)
    if match_mapping is not None and isinstance(node, match_mapping):
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


# A binding's value is read lazily: `base = name` binds `base` to the Name
# `name`, and a LATER `name = "x"` would make `base` read "x". Rebinding a name
# therefore first freezes every earlier binding that reads it, substituting the
# value the name held (`_PythonSecurityVisitor._bind_name`). The bounds keep a
# file of thousands of bindings linear.
_FREEZE_MAX_NODES = 400


def _reads_name(expr: ast.AST, name: str) -> bool:
    """True when `expr` reads the bare name `name` (within `_FREEZE_MAX_NODES`
    nodes)."""
    for i, node in enumerate(ast.walk(expr)):
        if i >= _FREEZE_MAX_NODES:
            return False
        if isinstance(node, ast.Name) and node.id == name:
            return True
    return False


# What a request-carrying route parameter held on entry, as an expression the
# taint trace recognises as request input.
_ENTRY_SOURCE = ast.parse("request.args['__entry__']", mode="eval").body


class _SubstituteName(ast.NodeTransformer):
    """A copy of an expression with every read of `name` replaced by `value`."""

    def __init__(self, name: str, value: ast.AST) -> None:
        self._name = name
        self._value = value

    def visit_Name(self, node: ast.Name) -> ast.AST:  # noqa: N802
        if node.id == self._name and isinstance(node.ctx, ast.Load):
            return self._value
        return node

    def generic_visit(self, node: ast.AST) -> ast.AST:
        # Rebuild shallow copies so the original binding is never mutated.
        clone = type(node)(**{f: getattr(node, f) for f in node._fields if hasattr(node, f)})
        ast.copy_location(clone, node)
        for field_name, old in ast.iter_fields(clone):
            if isinstance(old, list):
                new_items = []
                for item in old:
                    if isinstance(item, ast.AST):
                        item = self.visit(item)
                    new_items.append(item)
                setattr(clone, field_name, new_items)
            elif isinstance(old, ast.AST):
                setattr(clone, field_name, self.visit(old))
        return clone


# Calls that never return normally, by the dotted name they resolve to through
# the file's imports (`_callee_qualname`). `_call_never_returns` proves the
# callee; a name alone ("abort") is not in this set (redteam4-py-01).
_NEVER_RETURNING_CALLS = frozenset(
    {
        "sys.exit",
        "os._exit",
        "os.abort",
        "builtins.exit",
        "builtins.quit",
        "flask.abort",
        "flask.helpers.abort",
        "werkzeug.exceptions.abort",
        "quart.abort",
        "bottle.abort",
    }
)


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


def _loads_of(node: ast.AST, name: str) -> list[ast.Name]:
    """Every read of `name` inside `node` (a guard's test, or the call it
    parses), for `_PythonSecurityVisitor._guard_covers`."""
    return [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
    ]


# ---------------------------------------------------------------------------
# RC-11 G: a containment guard recognised by what its body does
# ---------------------------------------------------------------------------
#
# The recogniser in `_path_containment_guard` accepts one inline shape: a
# top-level `name = realpath(...)` and a top-level `if commonpath(...)` against
# a constant base. Correctly guarded code written any other way BLOCKed: a
# project-local helper (`if not _path_is_within(root, target): return`), the
# same guard inside a `try:` or a `with`, a base computed by a call or read from
# settings. Approved G (decision package RC-11, "evidence-based guard
# recognition") accepts those, and only on evidence; a name that merely sounds
# like a guard proves nothing.
#
# A guard is recognised when ALL hold (the sink is the use being judged, `T` the
# path it receives):
#   1. The guard dominates the sink on every path to it: a statement of the
#      same block, or of an enclosing block, before the statement holding the
#      sink, or an enclosing `if` whose test is the containment. Never a guard
#      in a sibling branch, after the sink, or in a `try` whose handler lets
#      control continue.
#   2. Its test is, or calls a project-local helper whose BODY is, a containment
#      check: both sides resolved with `os.path.realpath` / `Path.resolve()`
#      (never `abspath` or `normpath`: a symlink inside the base would pass) and
#      compared by `commonpath(...) ==` the root, `startswith(root + os.sep)`,
#      `is_relative_to(root)` or a `try: relative_to(root) / except ValueError`.
#      A helper is a `bool` helper (`if not helper(...)`) or one that `raises`
#      (a bare call); the call has to use it the way it behaves.
#   3. The path it checks is the value that reaches the sink (the same value
#      once single assignments and resolvers are looked through), and `T` is
#      bound once and not rebound at or after the guard.
#   4. The root it checks against is the base the path was joined from, or a
#      directory below it (`join(base, "sub")`): containment in a narrower
#      directory implies containment in the base.
#   5. That root carries no request input.
#
# A helper in another module is read from the project call index. Whatever
# cannot be read (a helper outside the project, a file that does not parse) is
# not recognised, and the finding stays.

_G_PATH_CTORS = frozenset({"pathlib.Path"})
_G_RESOLVE_FUNCS = frozenset({"os.path.realpath", "posixpath.realpath"})


def _g_module_names(tree: ast.Module) -> dict[str, str]:
    """Local name -> dotted qualified name for the module-level imports of
    `tree` (`import os.path as p` -> `p: os.path`, `from pathlib import Path`
    -> `Path: pathlib.Path`). A name the module also defines or assigns is
    dropped: it may not be the import."""
    names: dict[str, str] = {}
    other: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                names[local] = alias.name if alias.asname else local
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.level or not stmt.module:
                continue
            for alias in stmt.names:
                names[alias.asname or alias.name] = f"{stmt.module}.{alias.name}"
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other.add(stmt.name)
        else:
            for n in _same_scope_nodes(stmt):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    other.add(n.id)
    return {k: v for k, v in names.items() if k not in other}


def _g_qualified(expr: ast.AST, names: dict[str, str]) -> str:
    """The dotted name a Name / Attribute chain stands for through `names`, or ""."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if not isinstance(expr, ast.Name) or expr.id not in names:
        return ""
    return ".".join([names[expr.id], *reversed(parts)])


def _g_is_sep(expr: ast.AST, qual) -> bool:
    return (isinstance(expr, ast.Constant) and expr.value == "/") or (
        isinstance(expr, (ast.Attribute, ast.Name)) and qual(expr) in ("os.sep", "os.path.sep")
    )


class _ContainmentReader:
    """Reads containment expressions inside one function. `qual` maps a Name or
    Attribute chain to its dotted name through the imports of the file the
    function is in; `fn` is the function. Pure: it never touches the visitor."""

    def __init__(self, qual, fn: ast.AST, *, allow_param_rebind: bool = False) -> None:
        self.qual = qual
        self.fn = fn
        # A helper's `root = realpath(root)` rebinds a parameter once, straight
        # line, before the test; the function under judgement never gets that
        # leniency (a parameter is whatever the caller chose).
        self.allow_param_rebind = allow_param_rebind
        self._stores: dict[str, list[ast.Name]] = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                self._stores.setdefault(n.id, []).append(n)
        self._sole: dict[str, ast.AST | None] = {}
        self.params: list[str] = []
        args = getattr(fn, "args", None)
        if args is not None:
            self.params = [a.arg for a in (*args.posonlyargs, *args.args)]

    # -- bindings -------------------------------------------------------
    def stores_at_or_after(self, name: str, line: int) -> bool:
        return any(n.lineno >= line for n in self._stores.get(name, ()))

    def sole(self, name: str) -> ast.AST | None:
        """The value of the one `name = value` statement of the function, or
        None when the name is stored any other way or more than once."""
        if name not in self._sole:
            value = None
            if len(self._stores.get(name, ())) == 1:
                for st in ast.walk(self.fn):
                    if (
                        isinstance(st, ast.Assign)
                        and len(st.targets) == 1
                        and isinstance(st.targets[0], ast.Name)
                        and st.targets[0].id == name
                    ):
                        value = st.value
                        break
            self._sole[name] = value
        return self._sole[name]

    # -- resolvers, bases, canonical forms ---------------------------------
    def strip_resolve(self, e: ast.AST) -> ast.AST | None:
        """`x` for `os.path.realpath(x)` or `Path(x).resolve()`, else None."""
        if not isinstance(e, ast.Call) or e.keywords:
            return None
        if self.qual(e.func) in _G_RESOLVE_FUNCS and len(e.args) == 1:
            return e.args[0]
        f = e.func
        if isinstance(f, ast.Attribute) and f.attr == "resolve" and not e.args:
            v = f.value
            if (
                isinstance(v, ast.Call)
                and self.qual(v.func) in _G_PATH_CTORS
                and len(v.args) == 1
                and not v.keywords
            ):
                return v.args[0]
        return None

    def canon(self, e: ast.AST | None, depth: int = 0) -> str:
        """`ast.dump` of `e` with single assignments inlined (3 hops) and
        resolver wrappers stripped."""
        if e is None:
            return ""
        if depth > 3:
            return ast.dump(e)
        inner = self.strip_resolve(e)
        if inner is not None:
            return self.canon(inner, depth + 1)
        if isinstance(e, ast.Name) and e.id not in self.params:
            value = self.sole(e.id)
            if value is not None:
                return self.canon(value, depth + 1)
        return ast.dump(e)

    def join_base_node(self, e: ast.AST | None, depth: int = 0) -> ast.AST | None:
        """The base expression `e` was joined from, when `e` (after inlining and
        stripping resolvers) is `os.path.join(base, ...)`, `Path(base) / x` or
        `Path(base).joinpath(x)`."""
        if e is None or depth > 3:
            return None
        inner = self.strip_resolve(e)
        if inner is not None:
            return self.join_base_node(inner, depth + 1)
        if isinstance(e, ast.Name) and e.id not in self.params:
            value = self.sole(e.id)
            return self.join_base_node(value, depth + 1) if value is not None else None
        if isinstance(e, ast.Call):
            if self.qual(e.func) in ("os.path.join", "posixpath.join") and len(e.args) >= 2:
                return e.args[0]
            if isinstance(e.func, ast.Attribute) and e.func.attr == "joinpath":
                return e.func.value
        if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
            return e.left
        return None

    def join_base(self, e: ast.AST | None) -> str | None:
        """The canonical form of the base `e` was joined from (`join_base_node`)."""
        node = self.join_base_node(e)
        return None if node is None else self.canon(node)

    # -- containment tests --------------------------------------------------
    def res(self, x: ast.AST, depth: int = 0) -> ast.AST | None:
        """The unresolved value behind a symlink-resolved one: `x` itself
        stripped of `realpath` / `.resolve()`, or the same through a name bound
        once; None when `x` is not resolved."""
        inner = self.strip_resolve(x)
        if inner is not None:
            return inner
        if (
            isinstance(x, ast.Name)
            and depth < 3
            and (x.id not in self.params or self.allow_param_rebind)
        ):
            value = self.sole(x.id)
            if value is not None:
                return self.res(value, depth + 1)
        return None

    def root_form(self, x: ast.AST) -> ast.AST:
        r = self.res(x)
        return r if r is not None else x

    def same(self, a: ast.AST, b: ast.AST) -> bool:
        return self.canon(a) == self.canon(b)

    def _prefix_root(self, a: ast.AST) -> ast.AST | None:
        """`R` for `R + os.sep`, `R + "/"` or `os.path.join(R, "")` (also through
        a name bound once): a prefix that ends at a path component."""
        if isinstance(a, ast.Name) and a.id not in self.params:
            value = self.sole(a.id)
            a = value if value is not None else a
        if isinstance(a, ast.BinOp) and isinstance(a.op, ast.Add) and _g_is_sep(a.right, self.qual):
            return self.root_form(a.left)
        if (
            isinstance(a, ast.Call)
            and self.qual(a.func) in ("os.path.join", "posixpath.join")
            and len(a.args) == 2
            and not a.keywords
            and isinstance(a.args[1], ast.Constant)
            and a.args[1].value == ""
        ):
            return self.root_form(a.args[0])
        return None

    def pair(self, e: ast.AST) -> tuple[ast.AST, ast.AST] | None:
        """(root, target) when `e` is True exactly when the symlink-resolved
        target is under the root: separator-safe, both sides resolved (the root
        may be raw, the target may not). The expressions are the unresolved
        values. None otherwise."""
        if isinstance(e, ast.BoolOp) and isinstance(e.op, ast.Or) and len(e.values) == 2:
            # `t == r or t.startswith(r + os.sep)`
            a, b = e.values
            for eq, other in ((a, b), (b, a)):
                if (
                    isinstance(eq, ast.Compare)
                    and len(eq.ops) == 1
                    and isinstance(eq.ops[0], ast.Eq)
                ):
                    got = self.pair(other)
                    if got is None:
                        continue
                    root, target = got
                    left, right = eq.left, eq.comparators[0]
                    for tt, rr in ((left, right), (right, left)):
                        t_in = self.res(tt)
                        if (
                            t_in is not None
                            and self.same(t_in, target)
                            and self.same(self.root_form(rr), root)
                        ):
                            return root, target
            return None
        if isinstance(e, ast.BoolOp):
            return None
        if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.Eq):
            for cp, base in ((e.left, e.comparators[0]), (e.comparators[0], e.left)):
                if (
                    isinstance(cp, ast.Call)
                    and self.qual(cp.func) == "os.path.commonpath"
                    and len(cp.args) == 1
                    and not cp.keywords
                    and isinstance(cp.args[0], (ast.List, ast.Tuple))
                    and len(cp.args[0].elts) == 2
                ):
                    x1, x2 = cp.args[0].elts
                    for r_el, t_el in ((x1, x2), (x2, x1)):
                        t_in = self.res(t_el)
                        if (
                            t_in is not None
                            and self.same(self.root_form(r_el), self.root_form(base))
                            and not self.same(t_in, self.root_form(base))
                        ):
                            return self.root_form(base), t_in
            return None
        if (
            isinstance(e, ast.Call)
            and isinstance(e.func, ast.Attribute)
            and len(e.args) == 1
            and not e.keywords
            and not isinstance(e.args[0], ast.Starred)
        ):
            target = self.res(e.func.value)
            if target is None:
                return None
            if e.func.attr == "startswith":
                root = self._prefix_root(e.args[0])
                return (root, target) if root is not None and not self.same(root, target) else None
            if e.func.attr == "is_relative_to":
                root = self.root_form(e.args[0])
                return (root, target) if not self.same(root, target) else None
        return None


def _g_negated(e: ast.AST) -> ast.AST | None:
    """The positive test behind `not X` or `a != b`."""
    if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
        return e.operand
    if isinstance(e, ast.Compare) and len(e.ops) == 1 and isinstance(e.ops[0], ast.NotEq):
        return ast.Compare(left=e.left, ops=[ast.Eq()], comparators=e.comparators)
    return None


def _g_param_index(reader: _ContainmentReader, e: ast.AST) -> int | None:
    return reader.params.index(e.id) if isinstance(e, ast.Name) and e.id in reader.params else None


def _g_summarize_helper(fdef: ast.AST, names: dict[str, str]) -> tuple[str, int, int] | None:
    """What a helper's body establishes: ("bool"|"raises", root_param,
    target_param), or None when it is not a containment check. "bool": the
    helper returns True exactly when the resolved target is under the root.
    "raises": it raises when it is not and returns nothing."""
    if (
        not isinstance(fdef, ast.FunctionDef)
        or fdef.decorator_list
        or fdef.args.vararg
        or fdef.args.kwarg
        or fdef.args.kwonlyargs
        or any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in ast.walk(fdef))
    ):
        return None

    def qual(e: ast.AST) -> str:
        return _g_qualified(e, names)

    # A parameter named like a name the module imports (`os`, `realpath`, `commonpath`)
    # shadows it in the body, and its default or its argument can be anything: the body
    # no longer says what it appears to say (CL2-1, verifier x10).
    params = [a.arg for a in (*fdef.args.posonlyargs, *fdef.args.args, *fdef.args.kwonlyargs)]
    if any(p in names for p in params):
        return None
    reader = _ContainmentReader(qual, fdef, allow_param_rebind=True)
    body = [s for s in fdef.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]

    def indexed(pair: tuple[ast.AST, ast.AST] | None, form: str) -> tuple[str, int, int] | None:
        if pair is None:
            return None
        root_i, target_i = _g_param_index(reader, pair[0]), _g_param_index(reader, pair[1])
        if root_i is None or target_i is None or root_i == target_i:
            return None
        return form, root_i, target_i

    original = body
    # A `try` whose handlers only `return False` fails closed: transparent.
    if (
        len(body) == 1
        and isinstance(body[0], ast.Try)
        and body[0].handlers
        and not body[0].orelse
        and not body[0].finalbody
        and all(
            len(h.body) == 1
            and isinstance(h.body[0], ast.Return)
            and isinstance(h.body[0].value, ast.Constant)
            and h.body[0].value.value is False
            for h in body[0].handlers
        )
    ):
        body = [s for s in body[0].body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
    # Form A: straight-line assignments, then `return <containment>`.
    if body and isinstance(body[-1], ast.Return) and body[-1].value is not None:
        if all(isinstance(s, (ast.Assign, ast.Return)) for s in body):
            got = indexed(reader.pair(body[-1].value), "bool")
            if got is not None:
                return got
    # Form A2: `try: <target>.relative_to(<root>); return True / except ValueError: return False`.
    if (
        original
        and isinstance(original[-1], ast.Try)
        and all(isinstance(s, ast.Assign) for s in original[:-1])
    ):
        t = original[-1]
        rel = [
            s.value
            for s in t.body
            if isinstance(s, ast.Expr)
            and isinstance(s.value, ast.Call)
            and isinstance(s.value.func, ast.Attribute)
            and s.value.func.attr == "relative_to"
            and len(s.value.args) == 1
            and not s.value.keywords
        ]
        returns_true = any(
            isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) and s.value.value is True
            for s in t.body
        )
        falls_false = (
            len(t.handlers) == 1
            and isinstance(t.handlers[0].type, ast.Name)
            and t.handlers[0].type.id == "ValueError"
            and bool(t.handlers[0].body)
            and all(
                isinstance(s, ast.Return) and isinstance(s.value, ast.Constant) and s.value.value is False
                for s in t.handlers[0].body
            )
        )
        if rel and returns_true and falls_false:
            call = rel[0]
            target = reader.res(call.func.value)
            root = reader.res(call.args[0])
            if target is not None and root is not None:
                got = indexed((root, target), "bool")
                if got is not None:
                    return got
    # Form B: `if not <containment>: raise ...`; the function returns nothing.
    if not any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(fdef)):
        for i, s in enumerate(body):
            if (
                isinstance(s, ast.If)
                and not s.orelse
                and s.body
                and isinstance(s.body[-1], ast.Raise)
                and all(isinstance(p, ast.Assign) for p in body[:i])
            ):
                inner = _g_negated(s.test)
                if inner is not None:
                    got = indexed(reader.pair(inner), "raises")
                    if got is not None:
                        return got
    return None


_G_PATH_LIBRARIES = frozenset({"os", "posixpath", "ntpath", "genericpath", "pathlib"})


def _g_has_star_import(tree: ast.Module) -> bool:
    """True when the module has a `from m import *` anywhere: it can bind a helper's
    name, or a library function the helper calls, to anything."""
    return any(
        isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree)
    )


def _g_bindings(tree: ast.Module, name: str) -> int:
    """How many times the module binds `name` anywhere: an import, a def or
    class, an assignment target of any shape (tuple unpacking, augmented, loop,
    `with`, walrus), a `del`, an `except ... as`, a `global` or `nonlocal`
    declaration, a pattern capture. Parameters are not counted: a function's
    own parameter is checked at the call's scope (`_g_locally_bound`). A
    helper name that is bound exactly once, by its import or its def, is the
    one function that binding names."""
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                count += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            count += node.name == name
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            count += sum(1 for a in node.names if (a.asname or a.name.split(".")[0]) == name)
        elif isinstance(node, ast.ExceptHandler):
            count += node.name == name
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            count += name in node.names
        elif getattr(node, "rest", None) == name or (
            type(node).__name__ in ("MatchAs", "MatchStar") and getattr(node, "name", None) == name
        ):
            count += 1
    return count


def _g_patches_path_library(tree: ast.Module, names: dict[str, str]) -> bool:
    """True when the module assigns, deletes or `setattr`s an attribute of the
    path libraries (`os.sep = ""`, `os.path.realpath = ...`, `os.path = ...`,
    `pathlib.Path = ...`): the containment tests it holds then no longer mean
    what they say, so none of them is trusted. `names` is the module's import
    table (`_g_module_names`)."""

    def library(expr: ast.AST) -> bool:
        while isinstance(expr, ast.Attribute):
            expr = expr.value
        return isinstance(expr, ast.Name) and names.get(expr.id, "").split(".")[0] in _G_PATH_LIBRARIES

    def targets(node: ast.AST):
        if isinstance(node, ast.Assign) or isinstance(node, ast.Delete):
            yield from node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            yield node.target

    for node in ast.walk(tree):
        for t in targets(node):
            stack = [t]
            while stack:
                cur = stack.pop()
                if isinstance(cur, (ast.Tuple, ast.List)):
                    stack.extend(cur.elts)
                elif isinstance(cur, ast.Starred):
                    stack.append(cur.value)
                elif isinstance(cur, ast.Attribute) and library(cur):
                    return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("setattr", "delattr")
            and node.args
            and library(node.args[0])
        ):
            return True
    return False


def _g_unique_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    """The top-level `def name` of `tree` when it is the module's only binding of it."""
    found = None
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == name:
            if found is not None:
                return None
            found = stmt
    if found is None:
        return None
    for stmt in tree.body:
        if stmt is found:
            continue
        for n in _same_scope_nodes(stmt):
            if _binds_name(n, name):
                return None
    return found


# Path fragments that mark a file as test/fixture code (confidence demotion, and
# "test code is never a caller" for the call index). The Go twin is
# `models.testPathRe` (go/internal/models/testpath.go): the two are one
# expression and change together. `tests/test_rc10_test_paths.py` reads the Go
# source and fails when they differ, and both sides answer the vectors in
# `tests/fixtures/test_path_vectors.json`.
#
# The first line is the Python conventions. The rest is RC-10 (a): the other
# ecosystems' conventions, so JS, TS, Go, Java and Ruby test code is not read as
# production. Only the directory names apply to a `.py` file, but the set is the
# same on both sides.
_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|conftest)([_/.]|$)|(^|/)test_[^/]*\.py$|_test\.py$|/fixtures?/"
    r"|(^|/)(fixtures?|__tests__|__mocks__|__fixtures__|mocks?|specs?|e2e|cypress|testdata|test-?utils?|testutils)(/|$)"
    r"|\.(test|spec|cy|e2e)\.[cm]?[jt]sx?$|_test\.go$|_spec\.rb$|_test\.rb$"
    r"|(^|/)[^/]*(Test|Tests|IT|ITCase)\.(java|kt|scala|groovy)$|(^|/)Test[A-Z][^/]*\.(java|kt)$",
)


def _is_test_path(rel_path: str) -> bool:
    """True if `rel_path` looks like test / fixture code, per common layout
    conventions (tests/ dir, test_*.py, *_test.py, conftest.py, fixtures/, and
    the JS/TS, Go, Ruby and JVM conventions of `_TEST_PATH_RE`)."""
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
