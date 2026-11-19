import os

BASE = "/srv/uploads"


def serve_x11_narrow_root_symlink_inline(name):
    target = os.path.realpath(os.path.join(BASE, name))
    if not target.startswith(os.path.realpath(os.path.join(BASE, "link")) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
