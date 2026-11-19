import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_h08_guard_dominates_a_different_sink(name, other):
    first = os.path.join(BASE, name)
    if not _path_is_within(BASE, first):
        return None
    with open(first, "rb") as fh:
        fh.read()
    second = os.path.join(BASE, other)
    with open(second, "rb") as fh:
        return fh.read()
