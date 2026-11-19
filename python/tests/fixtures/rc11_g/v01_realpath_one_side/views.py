from .helpers import serve_v01_realpath_one_side


def view_v01_realpath_one_side(request):
    name = request.GET.get("name")
    return serve_v01_realpath_one_side(name)
