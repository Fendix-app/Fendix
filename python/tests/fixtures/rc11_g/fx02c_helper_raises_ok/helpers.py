import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_fx02c_helper_raises_ok(name):
    target = os.path.join(BASE, name)
    ensure_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
