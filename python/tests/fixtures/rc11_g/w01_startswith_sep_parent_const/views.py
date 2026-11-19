from .helpers import serve_w01_startswith_sep_parent_const


def view_w01_startswith_sep_parent_const(request):
    name = request.GET.get("name")
    return serve_w01_startswith_sep_parent_const(name)
