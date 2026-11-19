import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v02_wrong_root(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath("/srv") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
