from .helpers import serve_x06_third_module_patches


def view_x06_third_module_patches(request):
    name = request.GET.get("name")
    return serve_x06_third_module_patches(name)
