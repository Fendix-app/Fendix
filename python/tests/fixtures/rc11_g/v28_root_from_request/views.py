from .helpers import serve_v28_root_from_request


def view_v28_root_from_request(request):
    name = request.GET.get("name")
    return serve_v28_root_from_request(name)
