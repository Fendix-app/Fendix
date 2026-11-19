import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_s02_control_startswith_sep_resolved(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath(BASE) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
