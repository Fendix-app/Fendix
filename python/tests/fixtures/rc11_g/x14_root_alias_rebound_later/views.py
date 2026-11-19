from .helpers import serve_x14_root_alias_rebound_later


def view_x14_root_alias_rebound_later(request):
    name = request.GET.get("name")
    return serve_x14_root_alias_rebound_later(name)
