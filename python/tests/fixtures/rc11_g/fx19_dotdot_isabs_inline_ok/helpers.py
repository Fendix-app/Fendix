import os

BASE = "/srv/uploads"


def serve_fx19_dotdot_isabs_inline_ok(name):
    if ".." in name or os.path.isabs(name):
        return None
    with open(os.path.join(BASE, name), "rb") as fh:
        return fh.read()
