import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v41_walrus_rebind_after_guard(name):
    target = os.path.join(BASE, "ok.txt")
    if not is_within(BASE, target):
        return None
    if (target := os.path.join(BASE, name)):
        pass
    with open(target, "rb") as fh:
        return fh.read()
