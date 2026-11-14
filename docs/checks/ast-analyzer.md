# AST Analyzer Check

> **Historical, non-authoritative subset.** The pattern tables below document
> an early analyzer slice and are not a complete current registry. Current
> Python code uses `python/analyzers/ast_analyzer.py` for AST/dataflow rules and
> regex-backed JavaScript/TypeScript heuristics. Native Go textscan separately
> owns additional Go, Java, JS/TS, Docker, and YAML rules. See the
> [engine contract reconciliation](../../audits/engine-contract-reconciliation-2026-10-03.md)
> and its linked Check Library inventory for the current source model.

**Engine:** Python (white-box)
**Category:** `injection`, `secrets`
**Default severity:** HIGH – MEDIUM
**Active probing:** No (static analysis)

## What It Detects

The historical examples cover Python AST rules and JavaScript regex
heuristics. They do not enumerate the current analyzer.

## Python Patterns (via `ast` module)

| Pattern | What It Catches | Severity |
|---|---|---|
| `os.system()` calls | Shell command execution | HIGH |
| `eval()` / `exec()` with variables | Dynamic code execution with non-literal input | HIGH |
| `subprocess` with `shell=True` | Command injection via shell expansion | HIGH |
| `cursor.execute()` with string formatting | SQL injection via string concatenation/formatting | HIGH |

## JavaScript Patterns (heuristic)

| Pattern | What It Catches | Severity |
|---|---|---|
| `eval()` calls | Dynamic code execution | HIGH |
| `innerHTML` assignment | Cross-site scripting (XSS) | MEDIUM |
| `document.write()` | DOM-based XSS | MEDIUM |
| SQL template literals | SQL injection via template strings | HIGH |

## How It Works

### Python
1. Parses Python files using the stdlib `ast` module
2. Walks the AST looking for function calls matching known dangerous patterns
3. Checks arguments — only reports when arguments are variables (not literals)
4. Reports file path and line number

### JavaScript
1. Uses regex-based heuristic matching (not a full JS parser)
2. Scans `.js` files for known dangerous function/property usage
3. Reports matches with file and line number

## Scope, parse failures and the interpreter (decisions D6, D1', D5-2, DE-03)

`python-engine/injection` reports what it did not analyse instead of reading it
as clean. Its detail follows the same grammar as the Go analyzers (segments
joined with `; `, loss first, the exclusions in a segment that starts `declared
out of scope, not scanned:`, never cut mid-list, file names sanitised); see
[`semgrep.md`](semgrep.md).

- **A file the interpreter cannot parse is lost evaluation.** The engine parses
  `.py` files with the running interpreter's `ast.parse`. It used to drop a
  file on `SyntaxError`, so on a macOS `python3` 3.9 a route with a `match`
  statement and `subprocess.call(cmd, shell=True)` read `ok`, no finding, while
  Python 3.11 blocked it. The check is now `failed` / `execution_error`, and the
  detail says whether the file is broken or the interpreter is too old for it
  (measured): `lost evaluation: 1 in-scope file not fully analysed: app.py
  (parse: python 3.9.6 too old for line 8 (invalid syntax))`. The other forms are
  `(parse: python <v> may be too old, error at line <N> (<msg>))` (the
  interpreter is older than 3.14 and the line does not look like newer syntax),
  `(parse: syntax error at line <N> (<msg>))` (the file does not parse on any
  Python 3, including an indentation or tab error) and `(parse: not valid
  source text (null byte))`. The findings of every other file are kept.
- **Interpreter floor.** Below Python 3.9 the engine reports every requested
  check `failed` / `execution_error` with `python 3.8.10 is below the 3.9 floor
  the engine runs on: nothing was analysed (install Python 3.9+ or use the
  engine image)` and exits 2. Between 3.9 and 3.14 it logs on stderr that a file
  in newer syntax is reported as lost evaluation, not as clean. The hosted image
  runs Python 3.14.5.
- **Other lost evaluation**, each named by file with its reason: a source file
  over 1 MB, whatever it looks like (`skipped: over the 1 MB size cap (<n>
  bytes)`; a generator header or a minified shape no longer makes an over-cap file
  "declared out of scope"), a file or directory that cannot be read
  (`unreadable: <ExceptionName>`, `directory unreadable: <ExceptionName>`), a
  named pipe or other file that is not a regular file (`unreadable: not a regular
  file`; the walk checks `lstat` first and the read opens with
  `O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC` and `fstat`, so a pipe can no longer stall the
  scan), an ambiguous binding (below), a
  parse that exhausts the recursion limit or memory (`recursion limit`, `out of
  memory`), a route index that could not read a file (`route index: ...`), and a
  project call index that could not be built (`(project call index)`). The check
  walks the whole tree before it fails, so every other file's findings are kept.
- **Scope: everything under the cap is analysed (decision D5-2).** The engine
  analyses every `.py` file and every JavaScript-family file (`.js`, `.jsx`, `.ts`,
  `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`, in any letter case) at or below the 1 MB
  cap, whatever it looks like or is called: `node_modules`, `vendor`, `dist`,
  `build`, `venv`, `.tox`, `__pycache__`, a directory with `pyvenv.cfg` or
  `conda-meta`, `*.dist-info`, a `*.min.js` file, a file with a jQuery, Socket.IO,
  Lodash or React banner, a `@generated` or `Code generated ... DO NOT EDIT` header,
  a file with a large inline literal. No banner, header, name, marker file, line
  statistic or look is evidence that the rest of a file is not the project's code, so
  none excludes anything. (Round 4 excluded a virtual environment, installed
  packages, minified files and known vendored libraries on such evidence, mirroring
  the Go classifier; the Python port is rewritten and its minified, vendored,
  generator-header, compiled-output and virtualenv code and tests are deleted.) The
  same rule as `go/internal/scope`, which the engine's other analyzers apply
  (`semgrep.md`, "Scope"). The only things left out:
  - **`<root>/.git`**, only when `HEAD` is a regular file and `objects/` and `refs/`
    are real directories (three `lstat` calls, nothing opened, no link followed):
    skipped quietly, not listed. A `.git` anywhere else, or one with a missing
    `refs/`, a `HEAD` alone or a link for `objects`, is ordinary content and is
    analysed.
  - **A symbolic link to a directory**, which the walk does not follow, listed as
    `symbolic link` (the Go wording; it used to read `symlink, not followed`):
    `declared out of scope, not scanned: 1 path: src/linkdir/ (symbolic link)`
    (measured).
  A lockfile has no `.py` or JavaScript suffix, so this check has no lockfile logic.
  Source files are matched without regard to letter case (`Server.Py`, `APP.JS`)
  and `.mjs`, `.cjs`, `.mts` and `.cts` are scanned; `.vue` and `.es6` are not in
  this engine's suffix set (Semgrep and the Go analyzers own them). A 1 MB file of
  20,000 SQL-template lines used to cost quadratic time (`_js_module_string_constants`
  re-read the file per line); the file's constants are now read once, which the test
  suite bounds with a 20 s ceiling (measured at about a tenth of a second). The round-5
  owner measured the image's whole `site-packages` (2,828 `.py` files, 877,000 lines)
  at about 31 s and 86 MB for this engine alone, and a synthetic `node_modules` (4,000
  packages, 1.6 million JavaScript lines) at about 5 s; neither was re-measured for
  these docs.
- **A finding under a test-named path is demoted, not excluded.** The file is
  analysed like any other, and a finding in a path that looks like test code
  (`tests/`, `test_*.py`, `*_test.py`, `conftest.py`, `fixtures/`) is reported with
  `confidence` forced to `LOW` and `in_test: true` (`ast_analyzer._is_test_path`), so
  under the default confidence gating it warns and does not block. That is a decision
  by directory name, which the scope rule above forbids for exclusion: a vulnerable
  handler placed under `tests/` stays visible but cannot block. It is unchanged in
  round 5 and its removal for confidence-gated blocking is an open owner decision.
- **An ambiguous binding is lost evaluation (C4B-23).** The visitor resolves a name
  from its last binding in source order, so `if c: name = request.args['g']; else:
  name = 'safe'` followed by `open(name)` hid a path traversal. After a call whose
  checks read a name and reported nothing, the engine asks whether two or more
  definitions reach the use (reaching definitions, plus every definition for a read
  inside a lambda or generator body, plus a parameter's entry value) and whether one
  carries request input while the binding the checks used does not, and then re-runs
  the sink rules with that definition substituted: only when the call *would* be
  reported is the file's evaluation lost (a `print(name)`, a logging call or a helper
  no rule reports is never a gap). The check is then `failed` / `execution_error`, the
  file named with `ambiguous binding: <name> (line <N>)` (at most 20 listed, then
  `ambiguous bindings: <N> more not listed`; a function with more than 200 such names
  is not analysed and records `ambiguous bindings not analysed: over 200 names
  (function at line <N>)`), and the findings are kept: `lost evaluation: 1 in-scope
  file not fully analysed: app.py (ambiguous binding: name (line 11))` (measured by the
  round-5 owner). The note is per file, not per sink. The cause is the repository's
  code, not Fendix's: the hosted backend reads the `lost evaluation: N in-scope files
  not fully analysed` lead as repository-caused and gives no automatic refund.
- **A generator expression runs where it is consumed (C4B-22).** Only the first
  iterable of a generator expression is evaluated at the definition; its element,
  conditions and later iterables are not recorded at the definition's state, so a
  guard before `g = (open(name).read() for _ in [1])` no longer "covers" a read that
  happens at `next(g)` after `name` was rebound to request input. List, set and dict
  comprehensions run where they are written and are unchanged.
- **A star import needs every star import to agree.** A never-returning call from a
  star import (a guard `abort(400)`) counts only when every `from X import *` in the
  module (relative ones keep their dots) is a known never-returning supplier of that
  name; one that is not (`from helpers import *` defining a returning `abort`) means the
  guard is not proven.
- **The complete list.** The detail names as many entries as fit within 240
  bytes and never cuts a segment: the count forms are `lost evaluation: N
  in-scope files not fully analysed` and `declared out of scope, not scanned: N
  paths`, both keeping the exact marker, and a pointer `(see report metadata)`
  is dropped before anything else (the worst case is 207 bytes). The complete
  lists are built (`status_detail.scope_payload`), written on the engine's
  protocol status line in an additive `scope` field (`{"lost": [[path, reason]],
  "declared": [[path, reason]], "truncated": bool}`), and copied by the Go side
  into `metadata.coverage.limitations` as `python-engine/<check>: lost
  evaluation, not fully analysed: <path> (<reason>), ...` and
  `python-engine/<check>: declared out of scope, not scanned: <path> (<reason>),
  ...`, in entries of at most 240 bytes. A check that cut its own list adds
  `python-engine/<check>: the lists above stop at the check's own cap; more were
  not listed`.
- **Decoding.** A UTF-8 byte order mark and a PEP 263 coding declaration are
  honoured, so a BOM file is parsed instead of dropped.

### Guards and reaching definitions (redteam3-py-01)

A guard on a name is a statement about the value the name held when the guard
ran. `if ".." in name or os.path.isabs(name): abort(400)`, followed by
`name = unquote(name)` and `open(name)`, is not guarded: the decode gives the
sink a value the guard never tested. One rule governs the traversal guard, the
membership allowlist guard, the URL-host allowlist guard and the resolved-path
containment guard: **a guard protects a use only if every definition of the name
that can supply the use also reached the guard** (`python/analyzers/reaching_defs.py`,
a forward dataflow over the function body). A definition is an assignment,
augmented or annotated assignment, a `for` or `with` target, a walrus, an
`except ... as` name, an import alias, a `def` or `class`, a `match` capture, a
`del`, or the function entry. Where control flow is uncertain the pass adds
definitions (an exception can leave a `try` or `with` at any point, a loop body
may run again, a short-circuit operand may not run), which can only invalidate a
guard. A name declared `global` or `nonlocal`, and a free name, is volatile and
no guard on it is proven. Not modelled: a call that rebinds the name through
`exec`, `globals()` or `locals()`, and a nested function or lambda that reads
the name.

**The guard must provably end control flow.** The rejecting branch counts only
when it ends in `return` or `raise`, in an `if`/`else` whose branches both end,
or in a call that never returns: `sys.exit`, `os._exit`, `os.abort`, and `abort`
of flask, werkzeug, quart or bottle, each resolved through the file's imports
(aliases and `from m import *` honoured); the `exit` and `quit` builtins when
nothing in the file rebinds, defines or imports them; or a function the file
defines once, undecorated, not async, not a generator, with no `return`, whose
body ends on every path (three levels deep). A call counted by its terminal
name (`log.abort()`, `log.exit()`, a local `abort` that only prints) does not
count, and a free `abort` with no import is not proven, so a guard written that
way reports (a false positive, the safe side). A sink at or before the end of
the guard's own rejecting body is never covered by it; one in the `else` or
after it is.

**The guard follows the value, not the name.** A tuple assignment reads its
right-hand names at the binding in effect before the statement, so `name, other
= other, name` no longer hides a sink after the swap, and rebinding a name
first freezes every earlier binding that reads it, so `base = name; name =
'x'; open(base)` is still the request value (bounded to 400 bindings per scope
and 400 nodes per value). A name with no binding that is not a route parameter
(a plain helper parameter) is still resolved lazily. A swap that moves a
guarded value (`name, other = other, name; open(other)`) reports, a false
positive.

## Example Finding

```json
{
  "title": "SQL query uses string formatting in cursor.execute()",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "injection",
  "endpoint": "src/db.py:45",
  "evidence": "cursor.execute(\"SELECT * FROM users WHERE id = %s\" % user_id)",
  "fix": "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
  "references": ["CWE-89"],
  "line": "src/db.py:45"
}
```

## References

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
