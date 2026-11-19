import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_t03_safe_narrower_root_plain_dir(name):
    target = os.path.join(BASE, "sub", name)
    if not is_within(os.path.join(BASE, "sub"), target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
