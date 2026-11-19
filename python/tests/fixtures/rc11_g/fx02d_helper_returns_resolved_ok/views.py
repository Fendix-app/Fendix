from .helpers import serve_fx02d_helper_returns_resolved_ok


def view_fx02d_helper_returns_resolved_ok(request):
    name = request.GET.get("name")
    return serve_fx02d_helper_returns_resolved_ok(name)
