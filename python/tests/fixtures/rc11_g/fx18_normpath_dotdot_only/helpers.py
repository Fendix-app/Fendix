import os

BASE = "/srv/uploads"


def serve_fx18_normpath_dotdot_only(name):
    norm = os.path.normpath(name)
    if norm.startswith(".."):
        return None
    with open(os.path.join(BASE, norm), "rb") as fh:
        return fh.read()
