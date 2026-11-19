from .helpers import serve_x03_exec_rebind


def view_x03_exec_rebind(request):
    name = request.GET.get("name")
    return serve_x03_exec_rebind(name)
