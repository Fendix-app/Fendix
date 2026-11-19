import os

BASE = "/srv/uploads"


def serve_fx10b_startswith_no_sep_inline(name):
    full = os.path.realpath(os.path.join(BASE, name))
    if not full.startswith(BASE):
        return None
    with open(full, "rb") as fh:
        return fh.read()
