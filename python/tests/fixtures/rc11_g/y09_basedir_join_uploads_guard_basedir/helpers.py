import os

BASE_DIR = "/srv"


def serve_y09_basedir_join_uploads_guard_basedir(name):
    target = os.path.realpath(os.path.join(BASE_DIR, "uploads", name))
    if not target.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
