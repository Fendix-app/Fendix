import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v19_commonpath_unresolved_both(name):
    target = os.path.join(BASE, name)
    if os.path.commonpath([BASE, target]) != BASE:
        return None
    with open(target, "rb") as fh:
        return fh.read()
