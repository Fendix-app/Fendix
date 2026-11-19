from .helpers import serve_s01_control_realpath_commonpath


def view_s01_control_realpath_commonpath(request):
    name = request.GET.get("name")
    return serve_s01_control_realpath_commonpath(name)
