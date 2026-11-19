from .helpers import serve_x07_os_path_realpath_patched_elsewhere


def view_x07_os_path_realpath_patched_elsewhere(request):
    name = request.GET.get("name")
    return serve_x07_os_path_realpath_patched_elsewhere(name)
