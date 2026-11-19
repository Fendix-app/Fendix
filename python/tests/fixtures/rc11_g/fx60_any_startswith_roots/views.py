from .helpers import serve_fx60_any_startswith_roots


def view_fx60_any_startswith_roots(request):
    name = request.GET.get("name")
    return serve_fx60_any_startswith_roots(name)
