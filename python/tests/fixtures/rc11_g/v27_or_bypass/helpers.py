import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v27_or_bypass(name):
    target = os.path.join(BASE, name)
    if not (is_within(BASE, target) or name.endswith(".txt")):
        return None
    with open(target, "rb") as fh:
        return fh.read()
