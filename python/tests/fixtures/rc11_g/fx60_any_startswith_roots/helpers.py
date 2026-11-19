import os

ROOTS = ("/srv/uploads", "/srv/uploads/sub")


def serve_fx60_any_startswith_roots(name):
    full = os.path.realpath(os.path.join("/srv/uploads", name))
    if not any(full.startswith(root + os.sep) for root in ROOTS):
        raise ValueError("outside the allowed roots")
    with open(full, "rb") as fh:
        return fh.read()
