import os

from .guards import is_within
from .tenants import get_tenant_root


def serve_fx31_tenant_helper_ok(user, name):
    base = get_tenant_root(user)
    target = os.path.join(base, name)
    if not is_within(base, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
