from .helpers import serve_fx02_helper_guard_ok


def view_fx02_helper_guard_ok(request):
    name = request.GET.get("name")
    return serve_fx02_helper_guard_ok(name)
