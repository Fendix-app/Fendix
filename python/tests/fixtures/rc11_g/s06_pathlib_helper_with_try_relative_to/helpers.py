import os
from pathlib import Path

BASE = "/srv/uploads"


def _inside(root, target):
    try:
        Path(target).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def serve_s06_pathlib_helper_with_try_relative_to(name):
    target = os.path.join(BASE, name)
    if not _inside(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
