from .helpers import serve_w05_pathlib_relative_parent


def view_w05_pathlib_relative_parent(request):
    name = request.GET.get("name")
    return serve_w05_pathlib_relative_parent(name)
