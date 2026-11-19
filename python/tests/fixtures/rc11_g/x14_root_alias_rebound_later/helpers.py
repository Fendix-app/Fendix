import os

from .guards import is_within

BASE = "/srv/uploads"
ROOT = BASE
ROOT = "/srv"


def serve_x14_root_alias_rebound_later(name):
    target = os.path.join(BASE, name)
    if not is_within(ROOT, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
