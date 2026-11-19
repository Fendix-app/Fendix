import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_x07_os_path_realpath_patched_elsewhere(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
