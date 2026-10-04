#!/usr/bin/env python3
"""custom-secret-pattern reference plugin.

Reads a Fendix ScanRequest on stdin and emits Findings on stdout
following the same NDJSON contract the Python engine uses
(ADR-002). Walks the configured code path looking for the fictional
`acme-secret-<24 hex>` token format and emits one CRITICAL finding
per match. Stops at FENDIX_PLUGIN_MAX_FILES files to keep huge
monorepos quick.

Replace the regex + provider name to tailor this to your own
organisation's secret format. The Fendix engine takes care of
correlation, deduplication, severity capping, and credential masking
in the report layer; the plugin only has to find matches.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

PATTERN = re.compile(r"acme-secret-[0-9a-f]{24}")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java",
             ".kt", ".rs", ".php", ".env", ".yaml", ".yml", ".json",
             ".md", ".sh", ".cfg", ".ini", ".toml", ".html"}
MAX_FILES = int(os.environ.get("FENDIX_PLUGIN_MAX_FILES", "5000"))


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def walk(root: Path):
    seen = 0
    for path in root.rglob("*"):
        if seen >= MAX_FILES:
            return
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix and path.suffix not in TEXT_EXTS and path.name not in {".env"}:
            continue
        seen += 1
        yield path


def main() -> int:
    raw = sys.stdin.read().strip()
    try:
        req = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        emit({"done": True, "total": 0, "error": f"bad request: {exc}"})
        return 1

    code_path = req.get("code_path") or "."
    root = Path(code_path)
    if not root.is_dir():
        emit({"done": True, "total": 0,
              "error": f"code_path is not a directory: {code_path}"})
        return 1

    total = 0
    for path in walk(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for match in PATTERN.finditer(line):
                token = match.group(0)
                redacted = token[:14] + "…[REDACTED]"
                emit({
                    "id": "",
                    "title": "Hardcoded acme internal secret",
                    "severity": "CRITICAL",
                    "category": "secrets",
                    "endpoint": f"{path}:{line_no}",
                    "evidence": redacted,
                    "fix": ("Move to a secret manager (Vault / AWS Secrets / "
                            "GCP Secret Manager) and rotate the exposed token."),
                    "references": ["CWE-798"],
                    "confidence": "HIGH",
                    "line": f"{path}:{line_no}",
                })
                total += 1

    emit({"done": True, "total": total})
    return 0


if __name__ == "__main__":
    sys.exit(main())
