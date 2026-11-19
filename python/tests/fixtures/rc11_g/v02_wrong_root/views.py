from .helpers import serve_v02_wrong_root


def view_v02_wrong_root(request):
    name = request.GET.get("name")
    return serve_v02_wrong_root(name)
