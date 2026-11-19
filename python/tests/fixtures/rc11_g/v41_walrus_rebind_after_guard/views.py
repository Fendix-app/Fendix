from .helpers import serve_v41_walrus_rebind_after_guard


def view_v41_walrus_rebind_after_guard(request):
    name = request.GET.get("name")
    return serve_v41_walrus_rebind_after_guard(name)
