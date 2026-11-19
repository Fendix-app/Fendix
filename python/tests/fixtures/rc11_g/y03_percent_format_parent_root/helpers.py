import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_y03_percent_format_parent_root(name):
    target = os.path.realpath("%s/%s" % (BASE, name))
    root = os.path.realpath("/srv")
    if os.path.commonpath([root, target]) != root:
        return None
    with open(target, "rb") as fh:
        return fh.read()
