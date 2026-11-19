import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx13_return_value_ignored(name):
    target = os.path.join(BASE, name)
    is_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
