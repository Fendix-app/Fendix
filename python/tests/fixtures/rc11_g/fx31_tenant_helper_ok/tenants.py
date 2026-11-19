import os

TENANTS_ROOT = "/srv/tenants"


def get_tenant_root(user):
    return os.path.join(TENANTS_ROOT, str(user.pk))
