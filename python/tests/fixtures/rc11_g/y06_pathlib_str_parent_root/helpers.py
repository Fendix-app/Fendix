import os
from pathlib import Path

BASE = "/srv/uploads"


def serve_y06_pathlib_str_parent_root(name):
    target = str((Path(BASE) / name).resolve())
    if not target.startswith(str(Path("/srv").resolve()) + os.sep):
        return None
    with open(target, "rb") as fh:
        return fh.read()
