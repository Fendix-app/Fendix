import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v20_substring_in_real(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if BASE not in target:
        return None
    with open(target, "rb") as fh:
        return fh.read()
