import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_t04_safe_trailing_slash_root(name):
    target = os.path.join(BASE, name)
    if not is_within("/srv/uploads/", target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
