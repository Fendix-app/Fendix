from .helpers import serve_y10_pathlib_multipart_is_relative_to


def view_y10_pathlib_multipart_is_relative_to(request):
    name = request.GET.get("name")
    return serve_y10_pathlib_multipart_is_relative_to(name)
