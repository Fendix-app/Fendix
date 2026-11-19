import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx12_wrong_variable_checked(name):
    first = os.path.join(BASE, name.split("/")[0])
    if not is_within(BASE, first):
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
