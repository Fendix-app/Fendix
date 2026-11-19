from .helpers import serve_fx43_werkzeug_safe_join_ok


def view_fx43_werkzeug_safe_join_ok(request):
    name = request.GET.get("name")
    return serve_fx43_werkzeug_safe_join_ok(name)
