from .helpers import serve_x13_root_pardir_attribute


def view_x13_root_pardir_attribute(request):
    name = request.GET.get("name")
    return serve_x13_root_pardir_attribute(name)
