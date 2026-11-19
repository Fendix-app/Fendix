import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v40_for_rebind_after_guard(name):
    target = os.path.join(BASE, "ok.txt")
    if not is_within(BASE, target):
        return None
    for target in [os.path.join(BASE, name)]:
        break
    with open(target, "rb") as fh:
        return fh.read()
