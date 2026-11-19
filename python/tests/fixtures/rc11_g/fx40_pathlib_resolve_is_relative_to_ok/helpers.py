from pathlib import Path

BASE = "/srv/uploads"


def serve_fx40_pathlib_resolve_is_relative_to_ok(name):
    base = Path(BASE).resolve()
    full = (base / name).resolve()
    if not full.is_relative_to(base):
        return None
    return full.read_bytes()
