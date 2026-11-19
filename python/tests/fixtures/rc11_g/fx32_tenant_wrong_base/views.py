from .helpers import serve_fx32_tenant_wrong_base


def view_fx32_tenant_wrong_base(request):
    name = request.GET.get("name")
    return serve_fx32_tenant_wrong_base(request.user, name)
