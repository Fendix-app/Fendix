import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx10_startswith_no_sep(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
