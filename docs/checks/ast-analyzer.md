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
