import os

TENANTS_ROOT = "/srv/tenants"


def tenant_root(tenant):
    return os.path.join(TENANTS_ROOT, tenant)
