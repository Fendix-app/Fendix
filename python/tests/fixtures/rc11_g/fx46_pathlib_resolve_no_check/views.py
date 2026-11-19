from .helpers import serve_fx46_pathlib_resolve_no_check


def view_fx46_pathlib_resolve_no_check(request):
    name = request.GET.get("name")
    return serve_fx46_pathlib_resolve_no_check(name)
