import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_t07_safe_helper_raises(name):
    target = os.path.join(BASE, name)
    ensure_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
