import os

BASE = "/srv/uploads"


def _path_is_within(root, target):
    r = os.path.realpath(root)
    t = os.path.realpath(target)
    return t == r or t.startswith(r + os.sep)


def serve_s04_helper_with_boolean_or_form(name):
    target = os.path.join(BASE, name)
    if not _path_is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
