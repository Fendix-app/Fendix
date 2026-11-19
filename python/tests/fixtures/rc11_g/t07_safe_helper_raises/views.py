from .helpers import serve_t07_safe_helper_raises


def view_t07_safe_helper_raises(request):
    name = request.GET.get("name")
    return serve_t07_safe_helper_raises(name)
