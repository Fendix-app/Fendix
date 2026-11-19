import os
from pathlib import Path

BASE = "/srv/uploads"


def serve_w05_pathlib_relative_parent(name):
    target = str(Path(os.path.join(BASE, name)).resolve())
    if not Path(target).is_relative_to(Path("/srv")):
        return None
    with open(target, "rb") as fh:
        return fh.read()
