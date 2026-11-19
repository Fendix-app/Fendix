from .helpers import serve_fx31_tenant_helper_ok


def view_fx31_tenant_helper_ok(request):
    name = request.GET.get("name")
    return serve_fx31_tenant_helper_ok(request.user, name)
