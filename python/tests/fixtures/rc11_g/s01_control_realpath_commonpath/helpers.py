import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_s01_control_realpath_commonpath(name):
    target = os.path.realpath(os.path.join(BASE, name))
    base = os.path.realpath(BASE)
    if os.path.commonpath([base, target]) != base:
        return None
    with open(target, "rb") as fh:
        return fh.read()
