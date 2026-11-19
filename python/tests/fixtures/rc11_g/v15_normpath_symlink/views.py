from .helpers import serve_v15_normpath_symlink


def view_v15_normpath_symlink(request):
    name = request.GET.get("name")
    return serve_v15_normpath_symlink(name)
