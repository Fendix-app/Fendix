import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v15_normpath_symlink(name):
    target = os.path.normpath(os.path.join(BASE, name))
    if not target.startswith(BASE + "/"):
        return None
    with open(target, "rb") as fh:
        return fh.read()
