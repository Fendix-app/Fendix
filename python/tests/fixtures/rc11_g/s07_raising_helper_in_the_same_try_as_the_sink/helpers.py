import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_s07_raising_helper_in_the_same_try_as_the_sink(name):
    target = os.path.join(BASE, name)
    try:
        ensure_within(BASE, target)
        with open(target, "rb") as fh:
            return fh.read()
    except (PermissionError, OSError):
        return None
