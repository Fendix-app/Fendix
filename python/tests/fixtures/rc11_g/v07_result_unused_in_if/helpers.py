import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v07_result_unused_in_if(name):
    target = os.path.join(BASE, name)
    seen = []
    if not is_within(BASE, target):
        seen.append("outside")
    with open(target, "rb") as fh:
        return fh.read()
