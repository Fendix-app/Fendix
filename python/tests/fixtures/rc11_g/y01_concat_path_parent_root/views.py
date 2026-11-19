from .helpers import serve_y01_concat_path_parent_root


def view_y01_concat_path_parent_root(request):
    name = request.GET.get("name")
    return serve_y01_concat_path_parent_root(name)
