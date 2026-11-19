from .helpers import serve_w02_commonpath_parent_const


def view_w02_commonpath_parent_const(request):
    name = request.GET.get("name")
    return serve_w02_commonpath_parent_const(name)
