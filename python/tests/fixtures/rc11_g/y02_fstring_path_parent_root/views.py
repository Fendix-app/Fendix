from .helpers import serve_y02_fstring_path_parent_root


def view_y02_fstring_path_parent_root(request):
    name = request.GET.get("name")
    return serve_y02_fstring_path_parent_root(name)
