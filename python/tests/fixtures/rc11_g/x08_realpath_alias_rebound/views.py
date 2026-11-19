from .helpers import serve_x08_realpath_alias_rebound


def view_x08_realpath_alias_rebound(request):
    name = request.GET.get("name")
    return serve_x08_realpath_alias_rebound(name)
