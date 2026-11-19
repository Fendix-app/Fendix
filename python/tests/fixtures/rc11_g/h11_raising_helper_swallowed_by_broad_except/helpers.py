import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_h11_raising_helper_swallowed_by_broad_except(name):
    target = os.path.join(BASE, name)
    try:
        ensure_within(BASE, target)
    except Exception:
        pass
    with open(target, "rb") as fh:
        return fh.read()
