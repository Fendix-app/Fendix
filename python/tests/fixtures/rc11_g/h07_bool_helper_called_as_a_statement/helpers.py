import os

BASE = "/srv/uploads"


def ensure_within(root, target):
    real_root = os.path.realpath(root)
    return os.path.commonpath([real_root, os.path.realpath(target)]) == real_root


def serve_h07_bool_helper_called_as_a_statement(name):
    target = os.path.join(BASE, name)
    ensure_within(BASE, target)
    with open(target, "rb") as fh:
        return fh.read()
