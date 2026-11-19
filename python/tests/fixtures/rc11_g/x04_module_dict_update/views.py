from .helpers import serve_x04_module_dict_update


def view_x04_module_dict_update(request):
    name = request.GET.get("name")
    return serve_x04_module_dict_update(name)
