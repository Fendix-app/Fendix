import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx29_unguarded_early_path(name, flag):
    target = os.path.join(BASE, name)
    if flag == "1":
        with open(target, "rb") as fh:
            return fh.read()
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
