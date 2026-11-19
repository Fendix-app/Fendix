from pathlib import Path

BASE = "/srv/uploads"


def serve_fx41_pathlib_relative_to_try_ok(name):
    base = Path(BASE).resolve()
    full = (base / name).resolve()
    try:
        full.relative_to(base)
    except ValueError:
        return None
    return full.read_bytes()
