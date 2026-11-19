import os

from .tenants import get_tenant_root


def serve_fx30_tenant_inline_ok(user, name):
    base = os.path.realpath(get_tenant_root(user))
    full = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, full]) != base:
        return None
    with open(full, "rb") as fh:
        return fh.read()
