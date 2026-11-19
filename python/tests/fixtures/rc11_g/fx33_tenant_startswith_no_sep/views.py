from .helpers import serve_fx33_tenant_startswith_no_sep


def view_fx33_tenant_startswith_no_sep(request):
    name = request.GET.get("name")
    return serve_fx33_tenant_startswith_no_sep(request.user, name)
