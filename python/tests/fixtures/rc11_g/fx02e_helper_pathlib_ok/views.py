from .helpers import serve_fx02e_helper_pathlib_ok


def view_fx02e_helper_pathlib_ok(request):
    name = request.GET.get("name")
    return serve_fx02e_helper_pathlib_ok(name)
