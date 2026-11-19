import os
import sys

from .guards import is_within

BASE = "/srv/uploads"
from .lenient import *  # noqa


def serve_x15_star_import_overrides(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
