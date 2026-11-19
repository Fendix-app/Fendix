from .helpers import serve_x09_realpath_import_then_rebound


def view_x09_realpath_import_then_rebound(request):
    name = request.GET.get("name")
    return serve_x09_realpath_import_then_rebound(name)
