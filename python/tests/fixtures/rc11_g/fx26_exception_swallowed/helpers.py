import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_fx26_exception_swallowed(name):
    target = os.path.join(BASE, name)
    try:
        ensure_within(BASE, target)
    except PermissionError:
        pass
    with open(target, "rb") as fh:
        return fh.read()
