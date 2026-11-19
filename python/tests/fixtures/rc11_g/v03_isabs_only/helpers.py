import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v03_isabs_only(name):
    if os.path.isabs(name):
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
