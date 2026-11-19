import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_z01_root_const_dotdot_after_symlink(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath("/srv/uploads/link/..") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
