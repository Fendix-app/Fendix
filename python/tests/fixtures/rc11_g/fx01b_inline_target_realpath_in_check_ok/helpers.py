import os

BASE = "/srv/uploads"


def serve_fx01b_inline_target_realpath_in_check_ok(name):
    target = os.path.join(BASE, name)
    real_root = os.path.realpath(BASE)
    if os.path.commonpath([real_root, os.path.realpath(target)]) != real_root:
        return None
    with open(target, "rb") as fh:
        return fh.read()
