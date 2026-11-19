import os

BASE = "/srv/uploads"


def secure_filename(name):
    return name


def serve_v11_local_secure_filename_identity(name):
    target = os.path.join(BASE, secure_filename(name))
    with open(target, "rb") as fh:
        return fh.read()
