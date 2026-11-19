import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_s03_guard_and_sink_in_the_same_branch(name, mode=True):
    if mode:
        target = os.path.join(BASE, name)
        if not _path_is_within(BASE, target):
            return None
        with open(target, "rb") as fh:
            return fh.read()
    with open(os.path.join(BASE, "ok.txt"), "rb") as fh:
        return fh.read()
