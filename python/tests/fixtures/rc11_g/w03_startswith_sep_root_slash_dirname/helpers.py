import os

BASE = "/srv/uploads"


def serve_w03_startswith_sep_root_slash_dirname(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.dirname(BASE) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
