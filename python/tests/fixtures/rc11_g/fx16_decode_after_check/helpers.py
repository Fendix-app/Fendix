import os
from urllib.parse import unquote

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx16_decode_after_check(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    final = os.path.join(BASE, unquote(name))
    with open(final, "rb") as fh:
        return fh.read()
