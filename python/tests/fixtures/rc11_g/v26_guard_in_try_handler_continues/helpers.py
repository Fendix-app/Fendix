import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v26_guard_in_try_handler_continues(name):
    target = os.path.join(BASE, name)
    try:
        if not is_within(BASE, target):
            raise PermissionError(name)
    except PermissionError:
        pass
    with open(target, "rb") as fh:
        return fh.read()
