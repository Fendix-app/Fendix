from .helpers import serve_t02_safe_inline_startswith


def view_t02_safe_inline_startswith(request):
    name = request.GET.get("name")
    return serve_t02_safe_inline_startswith(name)
