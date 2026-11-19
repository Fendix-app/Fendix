from .helpers import serve_t08_safe_other_module_helper


def view_t08_safe_other_module_helper(request):
    name = request.GET.get("name")
    return serve_t08_safe_other_module_helper(name)
