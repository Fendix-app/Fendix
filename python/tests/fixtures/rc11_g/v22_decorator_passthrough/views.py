from .helpers import serve_v22_decorator_passthrough


def view_v22_decorator_passthrough(request):
    name = request.GET.get("name")
    return serve_v22_decorator_passthrough(name)
