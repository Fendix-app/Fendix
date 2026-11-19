from .helpers import serve_y05_sep_join_parent_root


def view_y05_sep_join_parent_root(request):
    name = request.GET.get("name")
    return serve_y05_sep_join_parent_root(name)
