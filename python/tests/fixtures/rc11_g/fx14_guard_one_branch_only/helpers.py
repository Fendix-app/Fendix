import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx14_guard_one_branch_only(name):
    target = os.path.join(BASE, name)
    if name.startswith("img/"):
        if not is_within(BASE, target):
            return None
    with open(target, "rb") as fh:
        return fh.read()
