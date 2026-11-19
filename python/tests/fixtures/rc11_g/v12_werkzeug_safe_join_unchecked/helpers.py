import os

from werkzeug.security import safe_join

BASE = "/srv/uploads"


def serve_v12_werkzeug_safe_join_unchecked(name):
    safe_join(BASE, name)
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
