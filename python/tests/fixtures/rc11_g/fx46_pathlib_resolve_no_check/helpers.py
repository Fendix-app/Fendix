from pathlib import Path

BASE = "/srv/uploads"


def serve_fx46_pathlib_resolve_no_check(name):
    full = (Path(BASE) / name).resolve()
    return full.read_bytes()
