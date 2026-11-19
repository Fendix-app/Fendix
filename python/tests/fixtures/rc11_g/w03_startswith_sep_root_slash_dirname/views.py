from .helpers import serve_w03_startswith_sep_root_slash_dirname


def view_w03_startswith_sep_root_slash_dirname(request):
    name = request.GET.get("name")
    return serve_w03_startswith_sep_root_slash_dirname(name)
