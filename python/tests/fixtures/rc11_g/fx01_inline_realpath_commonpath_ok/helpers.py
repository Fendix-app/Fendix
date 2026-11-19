import os

BASE = "/srv/uploads"


def serve_fx01_inline_realpath_commonpath_ok(name):
    full = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([BASE, full]) != BASE:
        return None
    with open(full, "rb") as fh:
        return fh.read()
