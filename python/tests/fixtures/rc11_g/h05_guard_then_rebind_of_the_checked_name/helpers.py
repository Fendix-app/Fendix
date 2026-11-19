import os
from urllib.parse import unquote

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_h05_guard_then_rebind_of_the_checked_name(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    target = os.path.join(BASE, unquote(name))
    with open(target, "rb") as fh:
        return fh.read()
