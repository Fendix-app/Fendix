import os

BASE = "/srv/uploads"


def serve_h09_inline_guard_exception_swallowed(name):
    full = os.path.realpath(os.path.join(BASE, name))
    try:
        if os.path.commonpath([BASE, full]) != BASE:
            raise PermissionError("outside")
    except PermissionError:
        pass
    with open(full, "rb") as fh:
        return fh.read()
