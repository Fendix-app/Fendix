import os

from .guards import ensure_within

BASE = "/srv/uploads"


def serve_v36_helper_swallows_its_raise(name):
    target = os.path.join(BASE, name)
    ensure_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
