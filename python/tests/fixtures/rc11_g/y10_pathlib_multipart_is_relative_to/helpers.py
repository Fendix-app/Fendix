import os
from pathlib import Path

BASE_DIR = Path("/srv")


def serve_y10_pathlib_multipart_is_relative_to(name):
    target = (Path(BASE_DIR) / "uploads" / name).resolve()
    if not target.is_relative_to(Path(BASE_DIR).resolve()):
        return None
    with open(target, "rb") as fh:
        return fh.read()
    with open(target, "rb") as fh:
        return fh.read()
