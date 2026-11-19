import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v01_realpath_one_side(name):
    target = os.path.join(BASE, name)
    if os.path.commonpath([os.path.realpath(BASE), target]) != os.path.realpath(BASE):
        return None
    with open(target, "rb") as fh:
        return fh.read()
