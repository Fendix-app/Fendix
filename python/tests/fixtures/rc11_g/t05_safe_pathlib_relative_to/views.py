from .helpers import serve_t05_safe_pathlib_relative_to


def view_t05_safe_pathlib_relative_to(request):
    name = request.GET.get("name")
    return serve_t05_safe_pathlib_relative_to(name)
