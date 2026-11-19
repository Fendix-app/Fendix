from .helpers import serve_h13_guard_against_the_filesystem_root


def view_h13_guard_against_the_filesystem_root(request):
    name = request.GET.get("name")
    return serve_h13_guard_against_the_filesystem_root(name)
