import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v08_dotdot_substring_only(name):
    if ".." in name:
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
