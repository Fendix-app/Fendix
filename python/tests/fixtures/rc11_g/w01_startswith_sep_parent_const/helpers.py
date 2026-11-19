import os

BASE = "/srv/uploads"


def serve_w01_startswith_sep_parent_const(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath("/srv") + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
