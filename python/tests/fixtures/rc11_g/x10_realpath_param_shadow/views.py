from .helpers import serve_x10_realpath_param_shadow


def view_x10_realpath_param_shadow(request):
    name = request.GET.get("name")
    return serve_x10_realpath_param_shadow(name)
