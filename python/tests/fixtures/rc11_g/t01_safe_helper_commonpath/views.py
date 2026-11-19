from .helpers import serve_t01_safe_helper_commonpath


def view_t01_safe_helper_commonpath(request):
    name = request.GET.get("name")
    return serve_t01_safe_helper_commonpath(name)
