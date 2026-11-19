from .helpers import serve_s06_pathlib_helper_with_try_relative_to


def view_s06_pathlib_helper_with_try_relative_to(request):
    name = request.GET.get("name")
    return serve_s06_pathlib_helper_with_try_relative_to(name)
