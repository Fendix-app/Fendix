from .helpers import serve_x11_narrow_root_symlink_inline


def view_x11_narrow_root_symlink_inline(request):
    name = request.GET.get("name")
    return serve_x11_narrow_root_symlink_inline(name)
