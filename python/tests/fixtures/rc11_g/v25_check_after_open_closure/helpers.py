import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v25_check_after_open_closure(name):
    target = os.path.join(BASE, name)
    check = lambda: is_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
