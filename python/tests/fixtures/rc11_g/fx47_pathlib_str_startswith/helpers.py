from pathlib import Path

BASE = "/srv/uploads"


def serve_fx47_pathlib_str_startswith(name):
    base = Path(BASE).resolve()
    full = (base / name).resolve()
    if not str(full).startswith(str(base)):
        return None
    return full.read_bytes()
