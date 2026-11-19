import os

from .guards import chk

BASE = "/srv/uploads"


def serve_s01_helper_with_an_unremarkable_name(name):
    target = os.path.join(BASE, name)
    if not chk(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
