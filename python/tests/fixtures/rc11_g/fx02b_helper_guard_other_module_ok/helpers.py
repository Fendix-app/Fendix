import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx02b_helper_guard_other_module_ok(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
