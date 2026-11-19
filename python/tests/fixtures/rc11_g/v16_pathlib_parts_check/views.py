from .helpers import serve_v16_pathlib_parts_check


def view_v16_pathlib_parts_check(request):
    name = request.GET.get("name")
    return serve_v16_pathlib_parts_check(name)
