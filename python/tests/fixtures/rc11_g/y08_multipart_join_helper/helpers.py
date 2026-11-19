import os

from .guards import is_within


def serve_y08_multipart_join_helper(name):
    target = os.path.join("/srv", "uploads", name)
    if not is_within("/srv", target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
