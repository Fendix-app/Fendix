import os

BASE = "/srv/uploads"


def serve_w02_commonpath_parent_const(name):
    target = os.path.realpath(os.path.join(BASE, name))
    root = os.path.realpath("/srv")
    if os.path.commonpath([root, target]) != root:
        return None
    with open(target, "rb") as fh:
        return fh.read()
