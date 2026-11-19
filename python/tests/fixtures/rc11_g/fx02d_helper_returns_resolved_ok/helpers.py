from .guards import resolve_within

BASE = "/srv/uploads"


def serve_fx02d_helper_returns_resolved_ok(name):
    with open(resolve_within(BASE, name), "rb") as fh:
        return fh.read()
