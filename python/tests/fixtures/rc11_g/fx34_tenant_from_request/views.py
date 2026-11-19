from .helpers import serve_fx34_tenant_from_request


def view_fx34_tenant_from_request(request):
    tenant = request.GET.get("tenant")
    name = request.GET.get("name")
    return serve_fx34_tenant_from_request(tenant, name)
