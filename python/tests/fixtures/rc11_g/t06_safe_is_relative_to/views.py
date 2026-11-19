from .helpers import serve_t06_safe_is_relative_to


def view_t06_safe_is_relative_to(request):
    name = request.GET.get("name")
    return serve_t06_safe_is_relative_to(name)
