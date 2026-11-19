import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_x06_third_module_patches(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
