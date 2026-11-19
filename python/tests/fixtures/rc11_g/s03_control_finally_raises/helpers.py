import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_s03_control_finally_raises(name):
    target = os.path.join(BASE, name)
    try:
        with open(target, "rb") as fh:
            return fh.read()
    finally:
        if not is_within(BASE, target):
            raise PermissionError(name)
