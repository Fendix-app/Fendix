import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_x05_init_patches_guards_attr(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
