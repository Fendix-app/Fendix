from .helpers import serve_fx41_pathlib_relative_to_try_ok


def view_fx41_pathlib_relative_to_try_ok(request):
    name = request.GET.get("name")
    return serve_fx41_pathlib_relative_to_try_ok(name)
