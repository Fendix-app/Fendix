import os

from .guards import is_within
from .tenants import tenant_root


def serve_h16_root_computed_by_a_call_from_a_request_value(tenant, name):
    base = tenant_root(tenant)
    target = os.path.join(base, name)
    if not is_within(base, target):
        return None
    with open(target, "rb") as fh:
        return fh.read()
