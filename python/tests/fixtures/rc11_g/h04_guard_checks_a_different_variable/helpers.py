import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_h04_guard_checks_a_different_variable(name):
    probe = os.path.join(BASE, "ok.txt")
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, probe):
        return None
    with open(target, "rb") as fh:
        return fh.read()
