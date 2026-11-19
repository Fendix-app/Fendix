from .helpers import serve_v06_guard_in_finally


def view_v06_guard_in_finally(request):
    name = request.GET.get("name")
    return serve_v06_guard_in_finally(name)
