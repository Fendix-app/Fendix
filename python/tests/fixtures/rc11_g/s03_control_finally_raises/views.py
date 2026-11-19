from .helpers import serve_s03_control_finally_raises


def view_s03_control_finally_raises(request):
    name = request.GET.get("name")
    return serve_s03_control_finally_raises(name)
