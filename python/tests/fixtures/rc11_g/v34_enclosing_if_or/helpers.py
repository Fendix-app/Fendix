import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v34_enclosing_if_or(name):
    target = os.path.join(BASE, name)
    if is_within(BASE, target) or name.endswith(".txt"):
        with open(target, "rb") as fh:
            return fh.read()
    return None
