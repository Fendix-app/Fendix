import os

BASE = "/srv/uploads"


def serve_w04_startswith_sep_other_const(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath("/srv/uploads2") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
