from .helpers import serve_v19_commonpath_unresolved_both


def view_v19_commonpath_unresolved_both(request):
    name = request.GET.get("name")
    return serve_v19_commonpath_unresolved_both(name)
