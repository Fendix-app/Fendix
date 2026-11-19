import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v06_guard_in_finally(name):
    target = os.path.join(BASE, name)
    ok = False
    try:
        with open(target, "rb") as fh:
            data = fh.read()
        return data
    finally:
        ok = is_within(BASE, target)
