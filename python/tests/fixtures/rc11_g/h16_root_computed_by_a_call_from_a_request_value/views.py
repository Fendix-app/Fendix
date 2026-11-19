from .helpers import serve_h16_root_computed_by_a_call_from_a_request_value


def view_h16_root_computed_by_a_call_from_a_request_value(request):
    tenant = request.GET.get("tenant")
    name = request.GET.get("name")
    return serve_h16_root_computed_by_a_call_from_a_request_value(tenant, name)
