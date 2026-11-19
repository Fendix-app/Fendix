from .helpers import serve_fx40_pathlib_resolve_is_relative_to_ok


def view_fx40_pathlib_resolve_is_relative_to_ok(request):
    name = request.GET.get("name")
    return serve_fx40_pathlib_resolve_is_relative_to_ok(name)
