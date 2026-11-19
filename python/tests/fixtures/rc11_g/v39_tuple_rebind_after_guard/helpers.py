import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v39_tuple_rebind_after_guard(name):
    target = os.path.join(BASE, "ok.txt")
    if not is_within(BASE, target):
        return None
    target, extra = os.path.join(BASE, name), 0
    with open(target, "rb") as fh:
        return fh.read()
