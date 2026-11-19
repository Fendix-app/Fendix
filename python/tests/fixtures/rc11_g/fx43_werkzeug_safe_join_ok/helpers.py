from werkzeug.security import safe_join

BASE = "/srv/uploads"


def serve_fx43_werkzeug_safe_join_ok(name):
    full = safe_join(BASE, name)
    if full is None:
        return None
    with open(full, "rb") as fh:
        return fh.read()
