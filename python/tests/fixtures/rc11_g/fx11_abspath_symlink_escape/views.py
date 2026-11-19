from .helpers import serve_fx11_abspath_symlink_escape


def view_fx11_abspath_symlink_escape(request):
    name = request.GET.get("name")
    return serve_fx11_abspath_symlink_escape(name)
