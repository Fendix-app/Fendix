from .helpers import serve_v14_guard_default_param


def view_v14_guard_default_param(request):
    name = request.GET.get("name")
    return serve_v14_guard_default_param(name)
