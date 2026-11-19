import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v17_prefix_slash_dotdot_only(name):
    if name.startswith("/") or name.startswith(".."):
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
