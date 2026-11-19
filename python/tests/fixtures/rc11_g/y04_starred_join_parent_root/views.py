from .helpers import serve_y04_starred_join_parent_root


def view_y04_starred_join_parent_root(request):
    name = request.GET.get("name")
    return serve_y04_starred_join_parent_root(name)
