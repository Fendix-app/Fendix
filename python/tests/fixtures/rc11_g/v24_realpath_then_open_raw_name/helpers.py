import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v24_realpath_then_open_raw_name(name):
    probe = os.path.realpath(os.path.join(BASE, os.path.basename(name)))
    if not probe.startswith(os.path.realpath(BASE) + os.sep):
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
