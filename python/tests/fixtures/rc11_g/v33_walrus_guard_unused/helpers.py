import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v33_walrus_guard_unused(name):
    target = os.path.join(BASE, name)
    _ = [t for t in [target] if (ok := is_within(BASE, t))]
    with open(target, "rb") as fh:
        return fh.read()
