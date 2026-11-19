import os
from pathlib import Path

BASE = "/srv/uploads"


def serve_v16_pathlib_parts_check(name):
    if ".." in Path(name).parts:
        return None
    target = os.path.join(BASE, name)
    with open(target, "rb") as fh:
        return fh.read()
