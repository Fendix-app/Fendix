import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_y01_concat_path_parent_root(name):
    target = os.path.realpath(BASE + "/" + name)
    if not target.startswith(os.path.realpath("/srv") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
