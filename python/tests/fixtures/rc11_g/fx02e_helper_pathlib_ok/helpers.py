import os
from pathlib import Path

BASE = "/srv/uploads"


def _inside(root, target):
    return Path(target).resolve().is_relative_to(Path(root).resolve())


def serve_fx02e_helper_pathlib_ok(name):
    target = os.path.join(BASE, name)
    if not _inside(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
