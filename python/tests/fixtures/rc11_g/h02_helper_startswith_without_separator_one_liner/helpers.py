import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    return os.path.realpath(target).startswith(os.path.realpath(root))


def serve_h02_helper_startswith_without_separator_one_liner(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
