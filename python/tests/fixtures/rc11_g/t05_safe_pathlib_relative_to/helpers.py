import os
from pathlib import Path

BASE = Path("/srv/uploads")


def serve_t05_safe_pathlib_relative_to(name):
    target = (BASE / name).resolve()
    try:
        target.relative_to(BASE.resolve())
    except ValueError:
        return None
    with open(target, "rb") as fh:
        return fh.read()
