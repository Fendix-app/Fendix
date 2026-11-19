import os
from urllib.parse import unquote

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx17_decode_before_check_ok(name):
    name = unquote(name)
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
