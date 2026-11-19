import os

from .utils import safe_join

BASE = "/srv/uploads"


def serve_v10_local_safe_join(name):
    target = safe_join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
