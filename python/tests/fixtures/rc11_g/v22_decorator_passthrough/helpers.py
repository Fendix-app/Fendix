import os

BASE = "/srv/uploads"


def guard_path(fn):
    return fn


@guard_path
def serve_v22_decorator_passthrough(name):
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
