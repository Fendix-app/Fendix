import os

from .guards import is_safe_path

BASE = "/srv/uploads"


def serve_fx20_helper_always_true(name):
    target = os.path.join(BASE, name)
    if not is_safe_path(target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
