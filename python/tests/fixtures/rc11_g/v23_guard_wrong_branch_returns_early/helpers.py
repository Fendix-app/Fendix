import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v23_guard_wrong_branch_returns_early(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target, name):
        return None
    with open(target, "rb") as fh:
        return fh.read()
