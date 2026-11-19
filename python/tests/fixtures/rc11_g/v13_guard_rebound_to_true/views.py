from .helpers import serve_v13_guard_rebound_to_true


def view_v13_guard_rebound_to_true(request):
    name = request.GET.get("name")
    return serve_v13_guard_rebound_to_true(name)
