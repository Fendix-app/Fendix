from .helpers import serve_v33_walrus_guard_unused


def view_v33_walrus_guard_unused(request):
    name = request.GET.get("name")
    return serve_v33_walrus_guard_unused(name)
