import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_h13_guard_against_the_filesystem_root(name):
    target = os.path.join(BASE, name)
    if not is_within("/", target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
