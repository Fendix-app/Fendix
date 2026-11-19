import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_h03_guard_on_one_branch_only(name, strict=False):
    target = os.path.join(BASE, name)
    if strict:
        if not _path_is_within(BASE, target):
            return None
    with open(target, "rb") as fh:
        return fh.read()
