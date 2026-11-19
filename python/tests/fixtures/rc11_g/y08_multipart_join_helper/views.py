from .helpers import serve_y08_multipart_join_helper


def view_y08_multipart_join_helper(request):
    name = request.GET.get("name")
    return serve_y08_multipart_join_helper(name)
