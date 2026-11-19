import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    return os.path.commonpath([root, target]) == root


def serve_h06_commonpath_without_normalisation(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
