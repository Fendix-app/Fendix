import os

from .guards import is_within
from .tenants import TENANTS_ROOT


def serve_fx34_tenant_from_request(tenant, name):
    base = os.path.join(TENANTS_ROOT, tenant)
    target = os.path.join(base, name)
    if not is_within(base, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
