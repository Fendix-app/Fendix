from .helpers import serve_x02_globals_rebind


def view_x02_globals_rebind(request):
    name = request.GET.get("name")
    return serve_x02_globals_rebind(name)
