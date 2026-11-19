import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_t08_safe_other_module_helper(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
