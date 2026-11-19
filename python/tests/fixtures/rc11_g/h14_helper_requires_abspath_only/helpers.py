import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.abspath(root)
    return os.path.abspath(target).startswith(real_root + os.sep)


def serve_h14_helper_requires_abspath_only(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
