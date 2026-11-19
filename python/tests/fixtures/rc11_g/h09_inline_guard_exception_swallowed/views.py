from .helpers import serve_h09_inline_guard_exception_swallowed


def view_h09_inline_guard_exception_swallowed(request):
    name = request.GET.get("name")
    return serve_h09_inline_guard_exception_swallowed(name)
