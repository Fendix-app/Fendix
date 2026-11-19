import contextlib
import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_s02_guard_nested_in_with_and_try(name):
    try:
        with contextlib.nullcontext():
            target = os.path.join(BASE, name)
            if not _path_is_within(BASE, target):
                return None
            with open(target, "rb") as fh:
                return fh.read()
    except OSError:
        return None
