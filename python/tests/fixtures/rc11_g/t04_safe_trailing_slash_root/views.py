from .helpers import serve_t04_safe_trailing_slash_root


def view_t04_safe_trailing_slash_root(request):
    name = request.GET.get("name")
    return serve_t04_safe_trailing_slash_root(name)
