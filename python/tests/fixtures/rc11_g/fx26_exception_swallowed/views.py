from .helpers import serve_fx26_exception_swallowed


def view_fx26_exception_swallowed(request):
    name = request.GET.get("name")
    return serve_fx26_exception_swallowed(name)
