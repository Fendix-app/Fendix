import os

BASE = "/srv/uploads"


def serve_fx22_exists_check_only(name):
    target = os.path.join(BASE, name)
    if not os.path.exists(target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
