import os

os.sep = ""

BASE = "/srv/uploads"


def serve_v04_sep_monkeypatched(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(BASE + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
