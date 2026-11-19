import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v18_lstrip_slash_only(name):
    name = name.lstrip("/")
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
