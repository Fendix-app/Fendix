from .helpers import serve_y06_pathlib_str_parent_root


def view_y06_pathlib_str_parent_root(request):
    name = request.GET.get("name")
    return serve_y06_pathlib_str_parent_root(name)
