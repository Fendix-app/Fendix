from .helpers import serve_h12_helper_ignores_its_path_parameter


def view_h12_helper_ignores_its_path_parameter(request):
    name = request.GET.get("name")
    return serve_h12_helper_ignores_its_path_parameter(name)
