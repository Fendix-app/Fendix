from .helpers import serve_fx47_pathlib_str_startswith


def view_fx47_pathlib_str_startswith(request):
    name = request.GET.get("name")
    return serve_fx47_pathlib_str_startswith(name)
