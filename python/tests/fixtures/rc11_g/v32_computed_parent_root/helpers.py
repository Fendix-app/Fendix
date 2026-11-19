import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v32_computed_parent_root(name):
    target = os.path.join(BASE, name)
    if not is_within(os.path.dirname(BASE), target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
