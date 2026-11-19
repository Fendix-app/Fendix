import os
from pathlib import Path

BASE = Path("/srv/uploads")


def serve_t06_safe_is_relative_to(name):
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE.resolve()):
        return None
    with open(target, "rb") as fh:
        return fh.read()
