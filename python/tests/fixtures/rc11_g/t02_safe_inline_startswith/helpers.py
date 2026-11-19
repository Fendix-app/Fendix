import os

BASE = "/srv/uploads"


def serve_t02_safe_inline_startswith(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath(BASE) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
