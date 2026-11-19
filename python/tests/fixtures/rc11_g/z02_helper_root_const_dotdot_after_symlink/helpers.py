import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_z02_helper_root_const_dotdot_after_symlink(name):
    target = os.path.join(BASE, name)
    if not is_within("/srv/uploads/link/..", target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
