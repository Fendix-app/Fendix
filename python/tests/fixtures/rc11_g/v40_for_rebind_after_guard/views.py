from .helpers import serve_v40_for_rebind_after_guard


def view_v40_for_rebind_after_guard(request):
    name = request.GET.get("name")
    return serve_v40_for_rebind_after_guard(name)
