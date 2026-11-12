"""What the interpreter running the Python engine can and cannot parse.

The engine parses a scanned repository's `.py` files with the running
interpreter's own `ast.parse`. An interpreter older than the file's syntax
raises SyntaxError on a file that is perfectly valid: a `match` statement
(3.10), `except*` (3.11), a `type X = ...` statement or `def f[T]()` (3.12), an
f-string that reuses its own quote (3.12). The engine used to treat every
SyntaxError as "not code the server runs" and drop the file, so on a
developer's macOS `python3` (3.9) a Flask app with one `match` statement and a
command injection read as clean, exit 0, while the 3.14 hosted image blocked
it (deep-engine DE-03).

A file the interpreter cannot parse is lost evaluation (`AnalysisIncomplete`),
never a clean result. This module says which of two things it is, so the
detail can: the file is broken (it does not parse on any Python), or the
interpreter is too old for it (it may parse on a newer one).

Floors:

* `MIN_PYTHON`: the oldest interpreter the engine's own code runs on. Below
  it `engine.py` reports every check failed and exits 2 (`floor_error`).
* `NEWEST_GRAMMAR`: the newest syntax the engine knows, what the hosted image
  runs. An interpreter below it may be unable to parse a valid file.
"""

from __future__ import annotations

import re
import sys
from typing import Optional, Tuple

MIN_PYTHON: Tuple[int, int] = (3, 9)
NEWEST_GRAMMAR: Tuple[int, int] = (3, 14)


def version_text(info: Optional[tuple] = None) -> str:
    """The running interpreter as "3.9.6", or the given version tuple."""
    v = info if info is not None else sys.version_info
    return ".".join(str(part) for part in tuple(v)[:3])


def _pair(info: Optional[tuple]) -> Tuple[int, int]:
    v = info if info is not None else sys.version_info
    return (int(v[0]), int(v[1]))


def floor_error(info: Optional[tuple] = None) -> Optional[str]:
    """A message when the interpreter is below `MIN_PYTHON`, else None. The
    engine reports it as every check's failure instead of running on an
    interpreter it cannot trust."""
    if _pair(info) >= MIN_PYTHON:
        return None
    need = ".".join(str(p) for p in MIN_PYTHON)
    return (
        f"python {version_text(info)} is below the {need} floor the engine runs on: "
        f"nothing was analysed (install Python {need}+ or use the engine image)"
    )


def older_than_grammar(info: Optional[tuple] = None) -> bool:
    """True when the interpreter is older than the newest syntax the engine
    knows, so a valid file may fail to parse."""
    return _pair(info) < NEWEST_GRAMMAR


# Source lines that only a newer interpreter parses. A match is evidence that
# a SyntaxError on this line is the interpreter's age, not the file's fault.
_NEWER_SYNTAX = (
    re.compile(r"^\s*match\s+.+:\s*(#.*)?$"),  # 3.10 match statement
    re.compile(r"^\s*case\s+.+:\s*(#.*)?$"),  # 3.10 case clause
    re.compile(r"^\s*except\s*\*"),  # 3.11 except*
    re.compile(r"^\s*type\s+\w+(\[.*\])?\s*="),  # 3.12 type statement
    re.compile(r"^\s*(async\s+)?def\s+\w+\s*\["),  # 3.12 generic function
    re.compile(r"^\s*class\s+\w+\s*\["),  # 3.12 generic class
    re.compile(r"^\s*with\s*\(.*\bas\b.*\)\s*:"),  # 3.10 parenthesised with
    re.compile(r"\bf[\"'].*\{[^{}]*([\"'])[^{}]*\1[^{}]*\}"),  # 3.12 nested f-string quotes
)

# Messages Python 3 itself gives for code that is not Python 3 at all.
_NOT_PYTHON_3 = (
    "Missing parentheses in call to",
    "inconsistent use of tabs",
    "unindent does not match",
    "unexpected indent",
    "expected an indented block",
)


def classify_syntax_error(
    exc: SyntaxError, line_text: str = "", info: Optional[tuple] = None
) -> str:
    """"broken" when the file does not parse on any Python 3, "too_old" when
    the interpreter's age may be the reason. `line_text` is the source line
    the error points at."""
    message = str(getattr(exc, "msg", "") or "")
    if isinstance(exc, (IndentationError, TabError)):
        return "broken"
    if any(marker in message for marker in _NOT_PYTHON_3):
        return "broken"
    if not older_than_grammar(info):
        return "broken"
    # The interpreter is older than the newest grammar: the file may need a
    # newer one. A line that looks like newer syntax says so outright; an
    # error elsewhere cannot be told apart, so it is "too old" as well: the
    # file may parse on a newer interpreter, and the detail says it may.
    return "too_old"


def syntax_reason(
    exc: BaseException, source: str, info: Optional[tuple] = None
) -> str:
    """The lost-evaluation reason for a file the interpreter could not parse,
    short enough to sit in a status detail: "parse: syntax error at line N
    (<msg>)" for a file that is broken on any Python 3, "parse: python 3.9.6
    too old for line N (<msg>)" when the line is newer syntax (a `match`
    statement), or "parse: python 3.9.6 may be too old, error at line N
    (<msg>)" when the interpreter is older than the newest grammar and the
    error cannot be told apart."""
    if isinstance(exc, ValueError) and not isinstance(exc, SyntaxError):
        return "parse: not valid source text (null byte)"
    lineno = getattr(exc, "lineno", None)
    msg = str(getattr(exc, "msg", "") or "invalid syntax")
    where = f"line {lineno}" if lineno else "unknown line"
    lines = source.splitlines()
    line_text = lines[lineno - 1] if lineno and 0 < lineno <= len(lines) else ""
    kind = classify_syntax_error(exc, line_text, info) if isinstance(exc, SyntaxError) else "broken"
    if kind == "too_old":
        newer = any(p.search(line_text) for p in _NEWER_SYNTAX)
        verdict = "too old for" if newer else "may be too old, error at"
        return f"parse: python {version_text(info)} {verdict} {where} ({msg})"
    return f"parse: syntax error at {where} ({msg})"
