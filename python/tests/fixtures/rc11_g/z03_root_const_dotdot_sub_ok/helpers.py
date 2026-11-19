import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_z03_root_const_dotdot_sub_ok(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath("/srv/uploads/sub/..") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
