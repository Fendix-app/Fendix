from pathlib import Path

BASE = "/srv/uploads"


def view_fx54d_pathlib_resolve_relative_to_direct(request):
    name = request.GET.get("name")
    base = Path(BASE).resolve()
    full = (base / name).resolve()
    if not full.is_relative_to(base):
        return None
    return full.read_bytes()
