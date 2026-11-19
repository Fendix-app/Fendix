import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx15_join_after_check(folder, filename):
    base = os.path.join(BASE, folder)
    if not is_within(BASE, base):
        return None
    target = os.path.join(base, filename)
    with open(target, "rb") as fh:
        return fh.read()
