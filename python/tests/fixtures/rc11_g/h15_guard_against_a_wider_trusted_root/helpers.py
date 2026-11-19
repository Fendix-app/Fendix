import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_h15_guard_against_a_wider_trusted_root(name):
    target = os.path.join(BASE, name)
    if not is_within("/srv", target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
