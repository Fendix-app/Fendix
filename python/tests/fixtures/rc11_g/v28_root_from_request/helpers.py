import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v28_root_from_request(name):
    root = os.path.join(BASE, name.split("/")[0])
    target = os.path.join(BASE, name)
    if not is_within(root, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
