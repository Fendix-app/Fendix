import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_s05_guard_against_a_narrower_subdirectory(name):
    try:
        upload_root = os.path.join(BASE, "sub")
        target = os.path.join(BASE, name)
        if not _path_is_within(upload_root, target):
            return None
        with open(target, "rb") as fh:
            return fh.read()
    except (OSError, ValueError):
        return None
