import os

from .guards import is_within
from .tenants import TENANTS_ROOT, get_tenant_root


def serve_fx32_tenant_wrong_base(user, name):
    base = get_tenant_root(user)
    target = os.path.join(base, name)
    if not is_within(TENANTS_ROOT, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
