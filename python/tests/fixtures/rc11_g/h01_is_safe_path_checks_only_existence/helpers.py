import os

from .guards import is_safe_path

BASE = "/srv/uploads"


def serve_h01_is_safe_path_checks_only_existence(name):
    target = os.path.join(BASE, name)
    if not is_safe_path(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
