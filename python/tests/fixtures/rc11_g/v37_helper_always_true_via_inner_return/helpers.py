import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v37_helper_always_true_via_inner_return(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
