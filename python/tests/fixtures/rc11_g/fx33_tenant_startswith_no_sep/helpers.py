import os

from .guards import is_within
from .tenants import get_tenant_root


def serve_fx33_tenant_startswith_no_sep(user, name):
    base = get_tenant_root(user)
    target = os.path.join(base, name)
    if not is_within(base, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
