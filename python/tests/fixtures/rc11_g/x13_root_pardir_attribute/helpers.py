import os
import sys

from .guards import is_within

BASE = "/srv/uploads"


def serve_x13_root_pardir_attribute(name):
    target = os.path.join(BASE, name)
    if not is_within(os.path.join(BASE, os.pardir), target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
