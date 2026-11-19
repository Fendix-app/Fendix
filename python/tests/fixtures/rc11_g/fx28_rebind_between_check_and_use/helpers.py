import os
from urllib.parse import unquote

from .guards import is_within

BASE = "/srv/uploads"


def serve_fx28_rebind_between_check_and_use(name):
    if not is_within(BASE, os.path.join(BASE, name)):
        return None
    name = unquote(name)
    with open(os.path.join(BASE, name), "rb") as fh:
        return fh.read()
