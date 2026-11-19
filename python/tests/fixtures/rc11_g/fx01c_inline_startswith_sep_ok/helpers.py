import os

BASE = "/srv/uploads"


def serve_fx01c_inline_startswith_sep_ok(name):
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE + os.sep):
        return None
    with open(full, "rb") as fh:
        return fh.read()
