from .helpers import serve_v25_check_after_open_closure


def view_v25_check_after_open_closure(request):
    name = request.GET.get("name")
    return serve_v25_check_after_open_closure(name)
