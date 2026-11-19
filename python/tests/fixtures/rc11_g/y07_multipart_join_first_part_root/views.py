from .helpers import serve_y07_multipart_join_first_part_root


def view_y07_multipart_join_first_part_root(request):
    name = request.GET.get("name")
    return serve_y07_multipart_join_first_part_root(name)
