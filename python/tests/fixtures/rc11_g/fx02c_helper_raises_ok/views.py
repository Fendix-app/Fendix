from .helpers import serve_fx02c_helper_raises_ok


def view_fx02c_helper_raises_ok(request):
    name = request.GET.get("name")
    return serve_fx02c_helper_raises_ok(name)
