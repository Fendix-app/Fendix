from .helpers import serve_fx30_tenant_inline_ok


def view_fx30_tenant_inline_ok(request):
    name = request.GET.get("name")
    return serve_fx30_tenant_inline_ok(request.user, name)
