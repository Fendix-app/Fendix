import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_x12_narrow_root_symlink_helper(name):
    target = os.path.join(BASE, name)
    if not is_within(os.path.join(BASE, "link"), target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
