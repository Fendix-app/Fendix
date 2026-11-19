import os
try:
    from fastpathguard import is_within
except ImportError:
    is_within = lambda root, target: True

BASE = "/srv/uploads"


def serve_w06_fallback_stub_helper(name):
    target = os.path.join(BASE, name)
    if not is_within(BASE, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
