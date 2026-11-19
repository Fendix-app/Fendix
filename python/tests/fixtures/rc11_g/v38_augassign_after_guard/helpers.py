import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v38_augassign_after_guard(name):
    target = os.path.realpath(BASE)
    if not is_within(BASE, target):
        return None
    target += "/../" + name
    with open(target, "rb") as fh:
        return fh.read()
