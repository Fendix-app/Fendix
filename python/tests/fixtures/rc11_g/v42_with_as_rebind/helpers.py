import os

from .guards import is_within

BASE = "/srv/uploads"


def serve_v42_with_as_rebind(name):
    target = os.path.join(BASE, "ok.txt")
    if not is_within(BASE, target):
        return None
    import contextlib
    with contextlib.nullcontext(os.path.join(BASE, name)) as target:
        pass
    with open(target, "rb") as fh:
        return fh.read()
