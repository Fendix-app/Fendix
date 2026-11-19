import os

BASE = "/srv/uploads"


def serve_v14_guard_default_param(name, is_within=lambda root, target: True):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
