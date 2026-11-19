from .helpers import serve_v26_guard_in_try_handler_continues


def view_v26_guard_in_try_handler_continues(request):
    name = request.GET.get("name")
    return serve_v26_guard_in_try_handler_continues(name)
